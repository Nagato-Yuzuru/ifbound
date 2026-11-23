package reconcile_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

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
		{"Digest", func(ctx context.Context, b reconcile.Backend) error { _, err := b.Digest(ctx); return err }, 0},
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
		_ = g.Shared(t.Context(), func(a reconcile.Adder) error { //nolint:errcheck // the test checks the order
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
		_ = g.Shared(t.Context(), func(reconcile.Adder) error { ev.add("shared"); return nil }) //nolint:errcheck // f returns nil
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
		_ = g.Shared(t.Context(), func(reconcile.Adder) error { <-second; return nil }) //nolint:errcheck // f returns nil
	})
	wg.Go(func() {
		_ = g.Shared(t.Context(), func(reconcile.Adder) error { close(second); return nil }) //nolint:errcheck // f returns nil
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

// In a synctest bubble, a convergence that waits for a report must not
// stop the fake clock: the report sleeps in its shared section, and the
// sleep must end. A Guard on a sync.RWMutex fails here, because a
// goroutine that waits on a mutex is not durably blocked.
func TestGuardWaitKeepsTheFakeClock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := reconcile.NewGuard(reconciletest.NewWorld().Backend())
		in := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			_ = g.Shared(t.Context(), func(reconcile.Adder) error { //nolint:errcheck // f returns nil
				close(in)
				time.Sleep(time.Minute) // in the bubble: moves the fake clock
				return nil
			})
		})
		<-in
		wg.Go(func() { g.Exclusive(func(reconcile.Backend) {}) })
		wg.Wait()
	})
}

// changed calls g.Changed and fails the test on an error.
func changed(t *testing.T, g *reconcile.Guard) bool {
	t.Helper()
	c, err := g.Changed(t.Context())
	if err != nil {
		t.Fatalf("Changed: %v", err)
	}
	return c
}

// The writes of an Exclusive call do not look like a change. A change
// that another program makes looks like one, once.
func TestGuardChangedSkipsOwnWrites(t *testing.T) {
	rs := reconcile.NewRuleset([]byte("table web\n"))
	for _, tt := range []struct {
		name     string
		external func(w *reconciletest.World)
	}{
		{"FlushAll", (*reconciletest.World).FlushAll},
		{"DisableFirewall", (*reconciletest.World).DisableFirewall},
		{"ExternalLoad", func(w *reconciletest.World) { w.ExternalLoad([]byte("other\n")) }},
	} {
		w := reconciletest.NewWorld()
		g := reconcile.NewGuard(w.Backend())
		g.Exclusive(func(b reconcile.Backend) { _ = b.Load(t.Context(), rs) }) //nolint:errcheck // the World does not fail
		if changed(t, g) {
			t.Errorf("%s: Changed after an own Load = true, want false", tt.name)
		}
		tt.external(w)
		if !changed(t, g) {
			t.Errorf("%s: Changed after the external change = false, want true", tt.name)
		}
		if changed(t, g) {
			t.Errorf("%s: second Changed after the external change = true, want false: one change is reported once", tt.name)
		}
	}
}

// digestFails is a Backend whose Digest fails while fail is set.
type digestFails struct {
	reconcile.Backend
	fail *atomic.Bool
}

func (b digestFails) Digest(ctx context.Context) (reconcile.Digest, error) {
	if b.fail.Load() {
		return reconcile.Digest{}, reconciletest.ErrInjected
	}
	return b.Backend.Digest(ctx)
}

// A failed read in Changed returns the error and keeps the expected
// digest. A failed read after a write of an Exclusive call makes the
// expected digest unknown, so the next Changed reports a change.
func TestGuardChangedAfterDigestErrors(t *testing.T) {
	var fail atomic.Bool
	g := reconcile.NewGuard(digestFails{Backend: reconciletest.NewWorld().Backend(), fail: &fail})
	if !changed(t, g) {
		t.Error("first Changed of a new Guard = false, want true: the expected digest is unknown")
	}
	fail.Store(true)
	if _, err := g.Changed(t.Context()); !errors.Is(err, reconciletest.ErrInjected) {
		t.Errorf("Changed with a failing Digest = %v, want ErrInjected", err)
	}
	fail.Store(false)
	if changed(t, g) {
		t.Error("Changed after a failed Changed = true, want false: the failure kept the expected digest")
	}
	rs := reconcile.NewRuleset([]byte("table web\n"))
	fail.Store(true)
	g.Exclusive(func(b reconcile.Backend) { _ = b.Load(t.Context(), rs) }) //nolint:errcheck // the World does not fail
	fail.Store(false)
	if !changed(t, g) {
		t.Error("Changed after an Exclusive call whose read failed = false, want true")
	}
}

// insideDigests records, for each call of Digest, whether an Exclusive
// section of the test was in f at the time.
type insideDigests struct {
	reconcile.Backend
	inside *atomic.Bool
	ev     *events
}

func (b insideDigests) Digest(ctx context.Context) (reconcile.Digest, error) {
	if b.inside.Load() {
		b.ev.add("digest inside f")
	} else {
		b.ev.add("digest")
	}
	return b.Backend.Digest(ctx)
}

// Changed never reads the Digest while an Exclusive section runs. The
// test holds f open after a write, and synctest.Wait proves that Changed
// is blocked before its read: the Guard waits on channels, so a blocked
// Changed is durably blocked. The only read in f is the read after the
// write.
func TestGuardChangedWaitsForExclusive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var inside atomic.Bool
		var ev events
		g := reconcile.NewGuard(insideDigests{Backend: reconciletest.NewWorld().Backend(), inside: &inside, ev: &ev})
		rs := reconcile.NewRuleset([]byte("table web\n"))
		entered, release := make(chan struct{}), make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			g.Exclusive(func(b reconcile.Backend) {
				inside.Store(true)
				_ = b.Load(t.Context(), rs) //nolint:errcheck // the World does not fail
				close(entered)
				<-release
				inside.Store(false)
			})
		})
		<-entered
		result := make(chan bool, 1)
		wg.Go(func() {
			c, err := g.Changed(t.Context())
			if err != nil {
				t.Errorf("Changed: %v", err)
			}
			result <- c
		})
		synctest.Wait()
		if got, want := ev.get(), []string{"digest inside f"}; !slices.Equal(got, want) {
			t.Fatalf("Digest calls while f runs = %v, want %v: only the read after the write", got, want)
		}
		close(release)
		wg.Wait()
		if got, want := ev.get(), []string{"digest inside f", "digest"}; !slices.Equal(got, want) {
			t.Errorf("Digest calls = %v, want %v: the read after the write, then the read of Changed", got, want)
		}
		if <-result {
			t.Error("Changed after the Exclusive call = true, want false")
		}
	})
}

// A change by another program after a write of ifbound, while the same
// Exclusive call goes on, shows to Changed: the Guard reads the expected
// digest right after the write, not at the end of the call.
func TestGuardChangedSeesAChangeLaterInTheSameSection(t *testing.T) {
	w := reconciletest.NewWorld()
	g := reconcile.NewGuard(w.Backend())
	rs := reconcile.NewRuleset([]byte("table web\n"))
	g.Exclusive(func(b reconcile.Backend) {
		_ = b.Load(t.Context(), rs) //nolint:errcheck // the World does not fail
		w.FlushAll()
		if _, err := b.Read(t.Context()); err != nil {
			t.Errorf("read: %v", err)
		}
	})
	if !changed(t, g) {
		t.Error("Changed after a flush that came after the own Load = false, want true")
	}
}
