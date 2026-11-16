package reconcile_test

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

var host7 = []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")}

// The epoch moves for each call that can remove an entry or replace the
// ruleset, also for a call that fails. It does not move for a read or an
// add.
func TestGuardEpochCountsTheCallsThatCanRemove(t *testing.T) {
	rs := reconcile.NewRuleset([]byte("table web\n"))
	tests := []struct {
		name string
		call func(context.Context, reconcile.Backend) error
		want uint64
	}{
		{"Read", func(ctx context.Context, b reconcile.Backend) error { _, err := b.Read(ctx); return err }, 0},
		{"LoadedID", func(ctx context.Context, b reconcile.Backend) error { _, err := b.LoadedID(ctx); return err }, 0},
		{"AddEntries", func(ctx context.Context, b reconcile.Backend) error { return b.AddEntries(ctx, "web", host7) }, 0},
		{"Load", func(ctx context.Context, b reconcile.Backend) error { return b.Load(ctx, rs) }, 1},
		{"RemoveEntries", func(ctx context.Context, b reconcile.Backend) error { return b.RemoveEntries(ctx, "web", host7) }, 1},
		{"DropTable", func(ctx context.Context, b reconcile.Backend) error { return b.DropTable(ctx, "web") }, 1},
	}
	for _, fail := range []bool{false, true} {
		for _, tt := range tests {
			w := reconciletest.NewWorld()
			if fail {
				w.SetBeforeWrite(func(int) error { return reconciletest.ErrInjected })
			}
			g := reconcile.NewGuard(w.Backend())
			got := g.Exclusive(func(b reconcile.Backend) { _ = tt.call(t.Context(), b) }) //nolint:errcheck // the test checks the epoch, not the result
			if got != tt.want {
				t.Errorf("%s (fail %v): epoch = %d, want %d", tt.name, fail, got, tt.want)
			}
		}
	}
}

// The Backend of an Exclusive call cannot write after the call returned:
// it would write without the lock and without a move of the epoch.
func TestGuardBackendAfterExclusivePanics(t *testing.T) {
	g := reconcile.NewGuard(reconciletest.NewWorld().Backend())
	var kept reconcile.Backend
	g.Exclusive(func(b reconcile.Backend) { kept = b })
	defer func() {
		if recover() == nil {
			t.Error("DropTable after Exclusive returned did not panic")
		}
	}()
	_ = kept.DropTable(t.Context(), "web") //nolint:errcheck // the call must panic
}

// blockingAdder holds AddEntries until the test releases it.
type blockingAdder struct {
	reconcile.Backend
	entered, release chan struct{}
}

func (b blockingAdder) AddEntries(ctx context.Context, table policy.Name, entries []netip.Prefix) error {
	close(b.entered)
	<-b.release
	return b.Backend.AddEntries(ctx, table, entries)
}

// events is a log of the steps of concurrent sections.
type events struct {
	mu  sync.Mutex
	log []string
}

func (e *events) add(s string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.log = append(e.log, s)
}

func (e *events) get() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.log)
}

// An Exclusive call that starts while a Shared section runs waits for its
// end. The test cannot see that Exclusive is blocked on the lock, so it
// checks the order of the log: a missing exclusion can only add the
// exclusive step before the end of the shared one.
func TestGuardExclusiveWaitsForShared(t *testing.T) {
	b := blockingAdder{Backend: reconciletest.NewWorld().Backend(), entered: make(chan struct{}), release: make(chan struct{})}
	g := reconcile.NewGuard(b)
	var ev events
	var wg sync.WaitGroup
	wg.Go(func() {
		_ = g.Shared(func(a reconcile.Adder) error { //nolint:errcheck // the test checks the order
			ev.add("shared in")
			err := a.AddEntries(t.Context(), "web", host7)
			ev.add("shared out")
			return err
		})
	})
	<-b.entered
	wg.Go(func() { g.Exclusive(func(reconcile.Backend) { ev.add("exclusive") }) })
	close(b.release)
	wg.Wait()
	if got, want := ev.get(), []string{"shared in", "shared out", "exclusive"}; !slices.Equal(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
}

// A Shared call that starts while an Exclusive section runs waits for its
// end. The test checks the order as above.
func TestGuardSharedWaitsForExclusive(t *testing.T) {
	g := reconcile.NewGuard(reconciletest.NewWorld().Backend())
	entered, release := make(chan struct{}), make(chan struct{})
	var ev events
	var wg sync.WaitGroup
	wg.Go(func() {
		g.Exclusive(func(reconcile.Backend) {
			ev.add("exclusive in")
			close(entered)
			<-release
			ev.add("exclusive out")
		})
	})
	<-entered
	wg.Go(func() {
		_ = g.Shared(func(reconcile.Adder) error { ev.add("shared"); return nil }) //nolint:errcheck // f returns nil
	})
	close(release)
	wg.Wait()
	if got, want := ev.get(), []string{"exclusive in", "exclusive out", "shared"}; !slices.Equal(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
}

// Shared sections run at the same time: the second one starts while the
// first one waits for it.
func TestGuardSharedSectionsOverlap(t *testing.T) {
	g := reconcile.NewGuard(reconciletest.NewWorld().Backend())
	second := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		_ = g.Shared(func(reconcile.Adder) error { <-second; return nil }) //nolint:errcheck // f returns nil
	})
	wg.Go(func() {
		_ = g.Shared(func(reconcile.Adder) error { close(second); return nil }) //nolint:errcheck // f returns nil
	})
	wg.Wait()
}

// Converge returns the epoch after its Backend part. A pass that only
// reads and Adoptable leave it as it is.
func TestConvergeReturnsTheEpoch(t *testing.T) {
	f := newFixture(t, configV1)
	_, first, err := f.rec.Converge(t.Context(), f.inputs())
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if first == 0 {
		t.Fatalf("epoch after the first Converge = 0, want > 0: it loaded a ruleset")
	}
	if _, err := f.rec.Adoptable(t.Context(), f.cfg.Policies); err != nil {
		t.Fatalf("Adoptable: %v", err)
	}
	_, again, err := f.rec.Converge(t.Context(), f.inputs())
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if again != first {
		t.Errorf("epoch after a pass without writes = %d, want %d", again, first)
	}
	f.world.FlushAll()
	_, last, err := f.rec.Converge(t.Context(), f.inputs())
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if last <= first {
		t.Errorf("epoch after a repair pass = %d, want > %d", last, first)
	}
}
