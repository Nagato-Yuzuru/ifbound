// Package core is the decision function of ifboundd. Step takes the
// state and one event, and returns the next state and the effects to
// run. It does no I/O, reads no clock, and starts no goroutine: the time
// comes with each event. The shell in package daemon runs the effects and
// gives their results back to Step as events.
package core

import (
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// State is what Step knows. Only Step changes it. The zero State is the
// state at start: no read started and no read ended.
type State struct {
	// now is the latest time of an event.
	now time.Time
	// nextID is the ID of the last read that Step started.
	nextID ReqID

	accounts accountReads
	// scope is the names that the last AccountsWanted gave. A pending
	// read uses them.
	scope accountNames

	hosts Observed[HostFile]
	// kernelHosts is the learned-looking kernel entries. They count as
	// host addresses until a read of hosts is good.
	kernelHosts Observed[map[policy.Name][]blockable.Addr]
}

// accountNames is the user names and the group names that the scopes of
// the configuration list.
type accountNames struct{ users, groups []string }

// Event is one input of Step.
//
//sumtype:decl
type Event interface{ at() time.Time }

// Tick comes when the time of NextWake is reached.
type Tick struct{ At time.Time }

func (e Tick) at() time.Time { return e.At }

// Effect is one output of Step. Each effect is in exactly one of the sub
// sums SyncEffect, AsyncEffect, and OutEffect.
//
//sumtype:decl
type Effect interface{ isEffect() }

// SyncEffect runs on the loop. The shell runs it before it takes the next
// outside event, and gives its result back to Step before it runs the
// next effect.
//
//sumtype:decl
type SyncEffect interface {
	Effect
	isSync()
}

// AsyncEffect starts work outside the loop. Its result comes back later
// as an event.
//
//sumtype:decl
type AsyncEffect interface {
	Effect
	isAsync()
}

// OutEffect tells the outside of a decision, for example in the log. It
// has no result.
//
//sumtype:decl
type OutEffect interface {
	Effect
	isOut()
}

// Converge asks for one convergence with a trigger, a value of
// logattr.ConvergeTrigger. The shell does not start the pass in the
// middle of the effects: it starts it after the current outside event,
// so a pass never runs inside another pass.
type Converge struct{ Trigger string }

func (Converge) isEffect() {}
func (Converge) isSync()   {}

// Step returns the state and the effects that follow ev. A time in ev
// that is older than the latest one does not move the time back. Step
// asks for at most one convergence for each event, and Converge is then
// the last effect.
func Step(s State, ev Event) (State, []Effect) {
	wasOverdue := s.accounts.overdue(s.now)
	if t := ev.at(); t.After(s.now) {
		s.now = t
	}
	var out []Effect
	converge := false
	if !wasOverdue && s.accounts.overdue(s.now) {
		out, converge = s.accountsOverdue(out), true
	}
	switch ev := ev.(type) {
	case Tick:
	case AccountsWanted:
		s.scope = accountNames{users: ev.Users, groups: ev.Groups}
		s, out = s.readAccounts(out)
	case AccountsRead:
		var changed bool
		s, out, changed = s.applyAccounts(ev, out)
		converge = converge || changed
	case HostsWanted:
		s, out = s.readHosts(out)
	case HostsRead:
		s, out = s.applyHosts(ev, out)
	case KernelRead:
		s, out = s.applyKernelHosts(ev, out)
	}
	if converge {
		out = append(out, Converge{Trigger: logattr.TriggerAccounts})
	}
	return s, out
}

// NextWake returns the time at which the shell gives Step a Tick. It
// reports false when nothing is due.
func NextWake(s State) (time.Time, bool) {
	if _, ok := s.accounts.InFlight(); ok && s.now.Before(s.accounts.deadline) {
		return s.accounts.deadline, true
	}
	return time.Time{}, false
}
