package core

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
)

// planned returns the waits of the RepairPlanned effects.
func planned(effects []Effect) []time.Duration {
	var out []time.Duration
	for _, e := range effects {
		if p, ok := e.(RepairPlanned); ok {
			out = append(out, p.Wait)
		}
	}
	return out
}

// repairOnce gives Step a firewall change at the time at, and runs its
// repair: at once, or at the wake time that the change sets. It returns
// the state after the repair, the wait before it, and the time of it.
func repairOnce(t *testing.T, s State, at time.Time) (State, time.Duration, time.Time) {
	t.Helper()
	s, effects := Step(s, FirewallChanged{At: at})
	waits := planned(effects)
	if len(waits) != 1 {
		t.Fatalf("change at %v: RepairPlanned waits = %v, want one", at.Sub(t0), waits)
	}
	if got := triggers(effects); waits[0] == 0 {
		if !slices.Equal(got, []string{logattr.TriggerFirewallChanged}) {
			t.Fatalf("change at %v with no wait: triggers = %v, want %s", at.Sub(t0), got, logattr.TriggerFirewallChanged)
		}
		return s, 0, at
	} else if len(got) != 0 {
		t.Fatalf("change at %v with wait %v: triggers = %v, want none before the wait", at.Sub(t0), waits[0], got)
	}
	wake, ok := NextWake(s)
	if !ok || wake != at.Add(waits[0]) {
		t.Fatalf("change at %v: NextWake = %v %v, want the end of the wait %v", at.Sub(t0), wake.Sub(t0), ok, waits[0])
	}
	if _, early := Step(s, Tick{At: wake.Add(-time.Nanosecond)}); len(triggers(early)) != 0 {
		t.Fatalf("change at %v: a convergence before the end of the wait", at.Sub(t0))
	}
	s, effects = Step(s, Tick{At: wake})
	if got := triggers(effects); !slices.Equal(got, []string{logattr.TriggerFirewallChanged}) {
		t.Fatalf("tick at the end of the wait: triggers = %v, want %s", got, logattr.TriggerFirewallChanged)
	}
	return s, waits[0], wake
}

// A firewall change soon after the last repair waits 1 s, and the wait
// doubles for each further quick change, up to 30 s. A quiet time of
// RepairQuiet after the last repair makes the next repair come at once
// again.
func TestFirewallChangeRepairBacksOff(t *testing.T) {
	s := ready(t, shell{})
	at := t0.Add(time.Minute)
	var waits []time.Duration
	var wait time.Duration
	for range 9 {
		s, wait, at = repairOnce(t, s, at)
		waits = append(waits, wait)
		// The other program breaks the entry again at once, and the next
		// poll finds it.
		at = at.Add(time.Second)
	}
	want := []time.Duration{0, 1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second}
	if !slices.Equal(waits, want) {
		t.Errorf("waits = %v, want %v", waits, want)
	}

	// The last repair was 1 s before at. A change RepairQuiet after it
	// comes at once, and the next quick one waits RepairBackoffMin again.
	at = at.Add(RepairQuiet - time.Second)
	waits = waits[:0]
	for range 2 {
		s, wait, at = repairOnce(t, s, at)
		waits = append(waits, wait)
		at = at.Add(time.Second)
	}
	if want := []time.Duration{0, RepairBackoffMin}; !slices.Equal(waits, want) {
		t.Errorf("waits after a quiet time = %v, want %v", waits, want)
	}
}

// A change while a repair waits joins that repair: it does not move the
// time of the repair, and it does not double the wait.
func TestFirewallChangeJoinsTheWaitingRepair(t *testing.T) {
	s := ready(t, shell{})
	s, _, at := repairOnce(t, s, t0.Add(time.Minute))
	s, _ = Step(s, FirewallChanged{At: at.Add(time.Second)})
	wake, _ := NextWake(s)
	s, effects := Step(s, FirewallChanged{At: at.Add(1500 * time.Millisecond)})
	if got := triggers(effects); len(got) != 0 {
		t.Errorf("change during the wait: triggers = %v, want none", got)
	}
	if got := planned(effects); !slices.Equal(got, []time.Duration{500 * time.Millisecond}) {
		t.Errorf("change during the wait: RepairPlanned waits = %v, want the rest of the wait, 500ms", got)
	}
	if again, _ := NextWake(s); again != wake {
		t.Errorf("NextWake after a change during the wait = %v, want %v", again.Sub(t0), wake.Sub(t0))
	}
	s, _ = Step(s, Tick{At: wake})
	if _, wait, _ := repairOnce(t, s, wake.Add(time.Second)); wait != 2*RepairBackoffMin {
		t.Errorf("wait after a joined change = %v, want %v", wait, 2*RepairBackoffMin)
	}
}

// Without a configuration no convergence can repair, so a firewall
// change does nothing.
func TestFirewallChangeWithoutConfig(t *testing.T) {
	s, effects := Step(State{}, FirewallChanged{At: t0})
	if len(effects) != 0 {
		t.Errorf("effects = %v, want none", effects)
	}
	if _, ok := NextWake(s); ok {
		t.Error("NextWake reports a wake, want none")
	}
}

var errWatch = errors.New("ioctl failed")

// A failed poll makes the phase Degraded until a good poll. The log
// gets the first failure of a series only. A firewall change is a good
// poll too.
func TestWatchFailureDegrades(t *testing.T) {
	for _, good := range []Event{WatchSucceeded{At: t0}, FirewallChanged{At: t0}} {
		s := ready(t, shell{})
		var logged int
		for range 3 {
			var effects []Effect
			s, effects = Step(s, WatchFailed{At: t0, Err: errWatch})
			logged += countOf[WatchFailing](effects)
			if len(triggers(effects)) != 0 {
				t.Errorf("WatchFailed asked for a convergence")
			}
		}
		if logged != 1 {
			t.Errorf("WatchFailing effects = %d, want 1", logged)
		}
		p := PhaseOf(s)
		want := "the watch of the firewall failed: " + errWatch.Error()
		if p.Lifecycle != Degraded || !slices.ContainsFunc(p.Reasons, func(r string) bool { return strings.Contains(r, want) }) {
			t.Errorf("phase = %v %q, want Degraded with %q", p.Lifecycle, p.Reasons, want)
		}
		if !p.Acks() {
			t.Error("the phase does not ack: a failed poll must not void the enforcement")
		}
		s, _ = Step(s, good)
		if p := PhaseOf(s); p.Lifecycle != Ready {
			t.Errorf("phase after %T = %v %q, want Ready", good, p.Lifecycle, p.Reasons)
		}
		if _, effects := Step(s, WatchFailed{At: t0, Err: errWatch}); countOf[WatchFailing](effects) != 1 {
			t.Errorf("a failure after %T is not logged", good)
		}
	}
}
