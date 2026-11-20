package core

import (
	"errors"
	"slices"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// The zero Answer refuses: a missing answer never acks.
func TestZeroAnswerRefuses(t *testing.T) {
	var a Answer
	if a.Protected() || !errors.Is(a.Err(), ErrUnenforced) {
		t.Errorf("zero Answer: protected %v, err %v; want a refusal with ErrUnenforced", a.Protected(), a.Err())
	}
	if step, err, ok := a.Failure(); ok {
		t.Errorf("the zero Answer tells a report failure at step %d: %v", step, err)
	}
}

func TestAdmit(t *testing.T) {
	open := GateOf(ready(t, shell{}))
	o, ok := open.State.(Open)
	if !ok {
		t.Fatalf("gate of ready = %#v, want open", open.State)
	}
	closed := Gate{Matcher: open.Matcher, State: Closed{Err: ErrNotReady}}

	if _, _, a, decided := Admit(closed, "www.example.net"); !decided || !errors.Is(a.Err(), ErrNotReady) {
		t.Errorf("closed gate: decided %v, err %v; want a refusal with ErrNotReady", decided, a.Err())
	}
	if _, _, a, decided := Admit(open, "a..example.net"); !decided || a.Err() == nil {
		t.Errorf("malformed name: decided %v, err %v; want a refusal", decided, a.Err())
	}
	if _, _, a, decided := Admit(open, "nomatch.org"); !decided || a.Err() != nil || a.Protected() {
		t.Errorf("no match: decided %v, protected %v, err %v; want an unprotected ack", decided, a.Protected(), a.Err())
	}
	names, epoch, _, decided := Admit(open, "www.example.net")
	if decided || !slices.Equal(names, []policy.Name{"web"}) || epoch != o.Epoch {
		t.Errorf("match: decided %v, names %v, epoch %d; want the report path for [web] at epoch %d", decided, names, epoch, o.Epoch)
	}
}

// check runs reconcile.Record for a report without an address on a
// World with rs loaded. It returns the Checked and the epoch of the
// check.
func check(t *testing.T, rs reconcile.Ruleset) (reconcile.Checked, uint64) {
	t.Helper()
	g := reconcile.NewGuard(reconciletest.NewWorld().Backend())
	var err error
	epoch := g.Exclusive(func(b reconcile.Backend) { err = b.Load(t.Context(), rs) })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	c, err := reconcile.Record(t.Context(), g, nil, reconcile.Sighting{Names: []policy.Name{"web"}, Epoch: epoch})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	return c, epoch
}

// Only a check of the epoch and the installed ruleset of the gate after
// Record gives a protected ack.
func TestAckAfterCheck(t *testing.T) {
	rs := reconcile.NewRuleset([]byte("table web\n"))
	c, epoch := check(t, rs)
	openAt := func(e uint64, installed string) Gate { return Gate{State: Open{Epoch: e, Installed: installed}} }
	addErr := &reconcile.ReportError{Step: reconcile.StepTableAdd, Err: reconciletest.ErrInjected}
	for _, tc := range []struct {
		name      string
		gate      Gate
		c         reconcile.Checked
		err       error
		protected bool
		wantErr   error
		step      reconcile.ReportStep
	}{
		{"proved", openAt(epoch, rs.ID()), c, nil, true, nil, 0},
		{"zero Checked", openAt(epoch, rs.ID()), reconcile.Checked{}, nil, false, reconcile.ErrStale, 0},
		{"gate of a later convergence", openAt(epoch+1, rs.ID()), c, nil, false, reconcile.ErrStale, 0},
		{"another loaded ruleset", openAt(epoch, "other"), c, nil, false, ErrUnenforced, reconcile.StepRuleset},
		{"closed gate", Gate{State: Closed{Err: ErrUnenforced}}, c, nil, false, ErrUnenforced, 0},
		{"failed step", openAt(epoch, rs.ID()), reconcile.Checked{}, addErr, false, reconciletest.ErrInjected, reconcile.StepTableAdd},
		{"stale", openAt(epoch, rs.ID()), reconcile.Checked{}, reconcile.ErrStale, false, reconcile.ErrStale, 0},
	} {
		a := AckAfterCheck(tc.gate, tc.c, tc.err)
		if a.Protected() != tc.protected {
			t.Errorf("%s: protected = %v, want %v", tc.name, a.Protected(), tc.protected)
		}
		if got := a.Err(); (tc.wantErr == nil) != (got == nil) || (tc.wantErr != nil && !errors.Is(got, tc.wantErr)) {
			t.Errorf("%s: err = %v, want %v", tc.name, got, tc.wantErr)
		}
		step, ferr, ok := a.Failure()
		if ok != (tc.step != 0) || step != tc.step || (ok && !errors.Is(ferr, tc.wantErr)) {
			t.Errorf("%s: failure = (%d, %v, %v), want step %d with %v", tc.name, step, ferr, ok, tc.step, tc.wantErr)
		}
	}
}
