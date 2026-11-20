package reconcile_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

var errCommit = errors.New("commit failed")

// fakeLedger records its calls. Commit fails with err, and it calls
// onCommit first when that is set.
type fakeLedger struct {
	mu       sync.Mutex
	calls    []string
	err      error
	onCommit func()
}

func (l *fakeLedger) note(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, s)
}

func (l *fakeLedger) Touch([]policy.Name, []blockable.Addr, time.Duration, time.Time) (addrstore.Pending, error) {
	l.note("touch")
	return addrstore.Pending{}, nil
}

func (l *fakeLedger) Commit(context.Context, addrstore.Pending) error {
	if l.onCommit != nil {
		l.onCommit()
	}
	l.note("commit")
	return l.err
}

func (l *fakeLedger) got() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.calls)
}

// loaded returns a Guard on a World with rs loaded, and the epoch after
// the load.
func loaded(t *testing.T, w *reconciletest.World, rs reconcile.Ruleset) (*reconcile.Guard, uint64) {
	t.Helper()
	g := reconcile.NewGuard(w.Backend())
	var err error
	epoch := g.Exclusive(func(b reconcile.Backend) { err = b.Load(t.Context(), rs) })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return g, epoch
}

var (
	recordRS   = reconcile.NewRuleset([]byte("table web\n"))
	addr7      = learned("203.0.113.7")
	sightingOf = func(epoch uint64, addrs []blockable.Addr) reconcile.Sighting {
		return reconcile.Sighting{Names: []policy.Name{"web"}, Addrs: addrs, TTL: time.Minute, At: time.Unix(0, 0), Epoch: epoch}
	}
)

// A report that succeeds puts its addresses in the table and the book,
// in this order, and proves the epoch and the loaded ruleset.
func TestRecordAddsCommitsAndChecks(t *testing.T) {
	w := reconciletest.NewWorld()
	g, epoch := loaded(t, w, recordRS)
	l := &fakeLedger{}
	c, err := reconcile.Record(t.Context(), g, l, sightingOf(epoch, addr7))
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if !c.Proves(epoch, recordRS.ID()) {
		t.Errorf("Checked does not prove epoch %d and %q", epoch, recordRS.ID())
	}
	if c.Proves(epoch+1, recordRS.ID()) || c.Proves(epoch, "other") {
		t.Error("Checked proves another epoch or another ruleset")
	}
	if got := w.Tables()["web"]; !slices.Contains(got, host7[0]) {
		t.Errorf("table web = %v, want %v", got, host7[0])
	}
	if got, want := l.got(), []string{"touch", "commit"}; !slices.Equal(got, want) {
		t.Errorf("ledger calls = %v, want %v", got, want)
	}
}

// A report without an address writes nothing, but it still checks.
func TestRecordWithoutAddressOnlyChecks(t *testing.T) {
	w := reconciletest.NewWorld()
	g, epoch := loaded(t, w, recordRS)
	before := w.Writes()
	l := &fakeLedger{}
	c, err := reconcile.Record(t.Context(), g, l, sightingOf(epoch, nil))
	if err != nil || !c.Proves(epoch, recordRS.ID()) {
		t.Fatalf("Record = %v; want a check of epoch %d", err, epoch)
	}
	if len(l.got()) != 0 || w.Writes() != before {
		t.Errorf("ledger calls %v, Backend writes %d; want none", l.got(), w.Writes()-before)
	}
}

// The zero Checked proves nothing, also for the zero epoch and the
// empty ruleset ID.
func TestZeroCheckedProvesNothing(t *testing.T) {
	var c reconcile.Checked
	if c.Proves(0, "") || c.Mismatch(0, "") {
		t.Error("the zero Checked proves a check")
	}
}

// A failure at a step gives a *ReportError with that step, and a zero
// Checked. A failed add does not commit.
func TestRecordFailsAtEachStep(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(w *reconciletest.World, l *fakeLedger)
		step  reconcile.ReportStep
		calls []string
	}{
		{"table add", func(w *reconciletest.World, _ *fakeLedger) {
			w.SetBeforeWrite(func(int) error { return reconciletest.ErrInjected })
		}, reconcile.StepTableAdd, []string{"touch"}},
		{"commit", func(_ *reconciletest.World, l *fakeLedger) { l.err = errCommit }, reconcile.StepCommit, []string{"touch", "commit"}},
	} {
		w := reconciletest.NewWorld()
		g, epoch := loaded(t, w, recordRS)
		l := &fakeLedger{}
		c.setup(w, l)
		got, err := reconcile.Record(t.Context(), g, l, sightingOf(epoch, addr7))
		re, ok := errors.AsType[*reconcile.ReportError](err)
		if !ok || re.Step != c.step {
			t.Errorf("%s: Record = %v, want a ReportError at step %d", c.name, err, c.step)
		}
		if got != (reconcile.Checked{}) {
			t.Errorf("%s: Checked = %+v, want the zero Checked", c.name, got)
		}
		if calls := l.got(); !slices.Equal(calls, c.calls) {
			t.Errorf("%s: ledger calls = %v, want %v", c.name, calls, c.calls)
		}
	}
}

// failingLoadedID fails each LoadedID.
type failingLoadedID struct{ reconcile.Backend }

func (failingLoadedID) LoadedID(context.Context) (string, error) {
	return "", reconciletest.ErrInjected
}

func TestRecordFailsAtTheLoadedID(t *testing.T) {
	g := reconcile.NewGuard(failingLoadedID{reconciletest.NewWorld().Backend()})
	_, err := reconcile.Record(t.Context(), g, &fakeLedger{}, sightingOf(0, nil))
	if re, ok := errors.AsType[*reconcile.ReportError](err); !ok || re.Step != reconcile.StepLoadedID {
		t.Errorf("Record = %v, want a ReportError at StepLoadedID", err)
	}
}

// A write that can remove an entry between the read of the gate and
// Record makes the report stale: Record writes nothing and checks
// nothing.
func TestRecordRefusesAStaleEpoch(t *testing.T) {
	w := reconciletest.NewWorld()
	g, epoch := loaded(t, w, recordRS)
	g.Exclusive(func(b reconcile.Backend) { _ = b.RemoveEntries(t.Context(), "web", host7) }) //nolint:errcheck // only the move of the epoch matters
	before := w.Writes()
	l := &fakeLedger{}
	c, err := reconcile.Record(t.Context(), g, l, sightingOf(epoch, addr7))
	if !errors.Is(err, reconcile.ErrStale) || c != (reconcile.Checked{}) {
		t.Errorf("Record = (%+v, %v), want ErrStale and the zero Checked", c, err)
	}
	if len(l.got()) != 0 || w.Writes() != before {
		t.Errorf("ledger calls %v, Backend writes %d; want none", l.got(), w.Writes()-before)
	}
}

// A convergence cannot run between the add and the check of a report:
// an Exclusive call that starts while the report commits runs after
// Record returned. The order of the log shows it, as in
// TestGuardExclusiveWaitsForShared.
func TestRecordHoldsOffAConvergenceUntilTheCheck(t *testing.T) {
	w := reconciletest.NewWorld()
	g, epoch := loaded(t, w, recordRS)
	var ev events
	committing, release := make(chan struct{}), make(chan struct{})
	l := &fakeLedger{onCommit: func() {
		close(committing)
		<-release
	}}
	var wg sync.WaitGroup
	wg.Go(func() {
		_, err := reconcile.Record(t.Context(), g, l, sightingOf(epoch, addr7))
		ev.add("record done")
		if err != nil {
			t.Errorf("Record: %v", err)
		}
	})
	<-committing
	wg.Go(func() {
		g.Exclusive(func(b reconcile.Backend) {
			ev.add("exclusive")
			_ = b.RemoveEntries(t.Context(), "web", host7) //nolint:errcheck // the test checks the order
		})
	})
	close(release)
	wg.Wait()
	if got, want := ev.get(), []string{"record done", "exclusive"}; !slices.Equal(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
}
