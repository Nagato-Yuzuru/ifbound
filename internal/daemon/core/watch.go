package core

import (
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

const (
	// RepairBackoffMin is the wait before the repair of a firewall change
	// that comes less than RepairQuiet after the last repair that a
	// firewall change started. Without the wait, another program that
	// breaks the entry to the anchor again at once makes one convergence
	// for each poll of the watcher.
	RepairBackoffMin = 1 * time.Second
	// RepairBackoffMax is the longest wait before such a repair. Each
	// further quick change doubles the wait up to this value. The wait
	// has no limit of tries: ifbound never stops the repair, because no
	// count of tries tells that the other program stopped.
	RepairBackoffMax = 30 * time.Second
	// RepairQuiet is the time after the last repair that a firewall
	// change started, after which the next change is repaired at once
	// again. It is RepairBackoffMax: a program that changes the firewall
	// less often than this gets no more repairs than the longest wait
	// permits, so a longer quiet time saves no convergence.
	RepairQuiet = RepairBackoffMax
)

// FirewallChanged tells that the watcher found a change of the firewall
// that ifbound did not make (see reconcile.Guard.Changed). The change
// can break the entry to the anchor, or it can be harmless, for example
// a new main ruleset that still calls the anchor. Only a convergence
// reads which one it is. So Step does not close the gate: the check of
// each report already refuses an ack while the ruleset is not in effect.
type FirewallChanged struct{ At time.Time }

// WatchFailed tells that a poll of the watcher failed.
type WatchFailed struct {
	At  time.Time
	Err error
}

// WatchSucceeded tells that a poll of the watcher succeeded after a
// WatchFailed. The shell sends it only then.
type WatchSucceeded struct{ At time.Time }

func (e FirewallChanged) at() time.Time { return e.At }
func (e WatchFailed) at() time.Time     { return e.At }
func (e WatchSucceeded) at() time.Time  { return e.At }

// RepairPlanned tells the log of a firewall change that Step accepted.
// Wait is the time until the convergence that repairs it, or zero when
// the convergence comes at once.
type RepairPlanned struct{ Wait time.Duration }

// WatchFailing tells the log that the polls of the watcher started to
// fail. A failure that repeats is not logged again until a poll
// succeeds.
type WatchFailing struct{ Err error }

func (RepairPlanned) isEffect() {}
func (RepairPlanned) isOut()    {}
func (WatchFailing) isEffect()  {}
func (WatchFailing) isOut()     {}

// watch is what Step knows of the watcher.
type watch struct {
	// failure is the last failed poll, or nil after a good poll.
	failure *WatchFailed
	// repairAt is the time of the convergence for a firewall change that
	// waits, or zero when no change waits.
	repairAt time.Time
	// repaired is the time of the last convergence that a firewall change
	// started, or zero for none.
	repaired time.Time
	// wait is the wait of the last delayed repair, or zero when the last
	// repair came at once.
	wait time.Duration
}

// applyFirewallChanged plans the repair of a firewall change. It returns
// the trigger of a convergence at once, or "" when the convergence
// waits. A change that comes less than RepairQuiet after the last
// repair waits, and the wait doubles for each such change in a row. A
// change while a repair waits joins that repair.
//
// Other convergences, such as the self-heal, can repair the change
// before the wait ends. The convergence at the end of the wait then
// finds nothing to do, and it still counts as a repair for the backoff.
// Without a configuration no convergence can repair, so it ignores the
// event then.
func (s State) applyFirewallChanged(out []Effect) (State, []Effect, string) {
	w := &s.watch
	// The poll that found the change succeeded.
	w.failure = nil
	if _, ok := s.Config().(Configured); !ok {
		return s, out, ""
	}
	if !w.repairAt.IsZero() {
		return s, append(out, RepairPlanned{Wait: w.repairAt.Sub(s.now)}), ""
	}
	if w.repaired.IsZero() || s.now.Sub(w.repaired) >= RepairQuiet {
		w.repaired, w.wait = s.now, 0
		return s, append(out, RepairPlanned{}), logattr.TriggerFirewallChanged
	}
	// The same shape as the accept backoff of ipc.Server.
	w.wait = min(max(w.wait*2, RepairBackoffMin), RepairBackoffMax)
	w.repairAt = s.now.Add(w.wait)
	return s, append(out, RepairPlanned{Wait: w.wait}), ""
}

// fireRepair starts the repair that waits when s.now reached its time.
// It returns the trigger of its convergence, or "". Only a configured
// state plans a repair, and a drive never takes the configuration away,
// so the state is configured here.
func (s State) fireRepair() (State, string) {
	w := &s.watch
	if w.repairAt.IsZero() || s.now.Before(w.repairAt) {
		return s, ""
	}
	w.repairAt, w.repaired = time.Time{}, s.now
	return s, logattr.TriggerFirewallChanged
}

// applyWatchFailed keeps the failure. It logs the first failure of a
// series.
func (s State) applyWatchFailed(ev WatchFailed, out []Effect) (State, []Effect) {
	if s.watch.failure == nil {
		out = append(out, WatchFailing{Err: ev.Err})
	}
	s.watch.failure = &ev
	return s, out
}

// watchProblem returns the Problem of a failed poll, if there is one.
// It does not void the enforcement: the check of each report and the
// self-heal still find a ruleset that is not in effect. Only the repair
// is slower.
func watchProblem(s State) (reconcile.Problem, bool) {
	f := s.watch.failure
	if f == nil {
		return reconcile.Problem{}, false
	}
	return reconcile.Problem{Text: "the watch of the firewall failed: " + f.Err.Error()}, true
}
