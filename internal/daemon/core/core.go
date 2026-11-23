// Package core is the decision function of ifboundd. Step takes the
// state and one event, and returns the next state and the effects to
// run. It does no I/O, reads no clock, and starts no goroutine: the time
// comes with each event. The shell in package daemon runs the effects and
// gives their results back to Step as events.
package core

import (
	"cmp"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

const (
	// SelfHealInterval is the period of the convergence that repairs
	// external changes, such as a flushed table.
	SelfHealInterval = 5 * time.Second
	// InterfaceDebounce is the delay from the first interface change to
	// the convergence. Changes inside the delay share that convergence.
	InterfaceDebounce = 500 * time.Millisecond
)

// State is what Step knows. Only Step changes it. New returns the state
// at start. The zero State is a state at start with an account reader
// and with no self-heal.
type State struct {
	// now is the latest time of an event.
	now time.Time
	// nextID is the ID of the last read that Step started.
	nextID ReqID

	// noAccountReader is true when the shell has no account reader: the
	// account snapshot then stays zero.
	noAccountReader bool
	accounts        accountReads

	hosts Observed[HostFile]
	// kernelHosts is the learned-looking kernel entries. They count as
	// host addresses until a read of hosts is good.
	kernelHosts Observed[map[policy.Name][]blockable.Addr]

	// config is nil before the first ConfigRead: Config returns
	// Unconfigured then.
	config Config
	// gen counts the good configuration reads.
	gen uint64
	// retain is the retain of the first good configuration. It is the
	// retain of the book for the life of the daemon.
	retain   time.Duration
	enf      enforcement
	reports  reports
	selfTest selfTest
	watch    watch

	// healAt is the time of the next self-heal, or zero for none.
	healAt time.Time
	// debounceAt is the time of the convergence for the interface
	// changes that wait, or zero when no change waits.
	debounceAt time.Time
}

// New returns the state at start, at the time at. The self-heals come
// at each SelfHealInterval after at. accountReader is false when the
// shell has no account reader: Step then starts no account read.
func New(at time.Time, accountReader bool) State {
	return State{now: at, noAccountReader: !accountReader, healAt: at.Add(SelfHealInterval)}
}

// Event is one input of Step.
//
//sumtype:decl
type Event interface{ at() time.Time }

// Tick comes when the time of NextWake is reached.
type Tick struct{ At time.Time }

// InterfacesChanged tells that the network interfaces changed. The
// convergence comes InterfaceDebounce after the first change that waits.
type InterfacesChanged struct{ At time.Time }

// PassStarted tells that the shell starts a convergence pass. Step
// reads the host file first: adoption and the tables must know the host
// addresses. While the book is not loaded, it then loads the book: it
// opens the book when the shell does not hold it, and adopts again when
// an adoption is still owed. The pass ends with Converged.
type PassStarted struct{ At time.Time }

func (e Tick) at() time.Time              { return e.At }
func (e InterfacesChanged) at() time.Time { return e.At }
func (e PassStarted) at() time.Time       { return e.At }

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
// so a pass never runs inside another pass. A pass covers each Converge
// that came before its PassStarted drain ended.
type Converge struct{ Trigger string }

func (Converge) isEffect() {}
func (Converge) isSync()   {}

// Step returns the state and the effects that follow ev. A time in ev
// that is older than the latest one does not move the time back. A timer
// whose time the event reaches fires first. Step asks for at most one
// convergence for each event, and Converge is then the last effect. The
// trigger of the event comes before the trigger of a timer.
func Step(s State, ev Event) (State, []Effect) {
	wasOverdue := s.accounts.overdue(s.now)
	if t := ev.at(); t.After(s.now) {
		s.now = t
	}
	var out []Effect
	var timer, trigger string
	if !wasOverdue && s.accounts.overdue(s.now) {
		out, timer = s.accountsOverdue(out), logattr.TriggerAccounts
	}
	var t string
	s, out, t = s.fireTimers(out)
	timer = cmp.Or(timer, t)
	switch ev := ev.(type) {
	case Tick:
	case InterfacesChanged:
		if s.debounceAt.IsZero() {
			s.debounceAt = s.now.Add(InterfaceDebounce)
		}
	case PassStarted:
		s, out = s.readHosts(out)
		s, out = s.wantBook(out)
	case ConfigRead:
		s, out, trigger = s.applyConfig(ev, out)
	case Converged:
		s, out = s.applyConverged(ev, out)
	case ReportFailed:
		s, out, trigger = s.applyReportFailed(ev, out)
	case ReportSucceeded:
		s = s.applyReportSucceeded()
	case SelfTestResult:
		s, trigger = s.applySelfTest(ev)
	case AccountsRead:
		var changed bool
		if s, out, changed = s.applyAccounts(ev, out); changed {
			trigger = logattr.TriggerAccounts
		}
	case HostsRead:
		s, out = s.applyHosts(ev, out)
	case KernelRead:
		s, out = s.applyKernelHosts(ev, out)
	case BookOpened:
		s, out = s.applyBookOpened(ev, out)
	case BookAdopted:
		s, out = s.applyBookAdopted(ev, out)
	case BookExpired:
		var loaded bool
		if s, loaded = s.setFacts(ev.Facts); loaded && ev.Removed > 0 {
			trigger = logattr.TriggerExpiry
		}
	case BookChanged:
		s, _ = s.setFacts(ev.Facts)
	case FirewallChanged:
		s, out, trigger = s.applyFirewallChanged(out)
	case WatchFailed:
		s, out = s.applyWatchFailed(ev, out)
	case WatchSucceeded:
		s.watch.failure = nil
	}
	if trigger = cmp.Or(trigger, timer); trigger != "" {
		out = append(out, Converge{Trigger: trigger})
	}
	return s, out
}

// fireTimers runs each timer whose time s.now reached: the self-heal,
// the interface debounce, the repair of a firewall change, and the
// expiry of the book. It returns the trigger of the convergence that a
// timer wants, or "".
func (s State) fireTimers(out []Effect) (State, []Effect, string) {
	_, configured := s.Config().(Configured)
	var trigger string
	if !s.healAt.IsZero() && !s.now.Before(s.healAt) {
		// As a ticker, the next self-heal stays on the grid of New.
		s.healAt = s.healAt.Add((s.now.Sub(s.healAt)/SelfHealInterval + 1) * SelfHealInterval)
		if configured {
			s, out = s.readAccounts(out)
			trigger = logattr.TriggerSelfHeal
		}
	}
	if !s.debounceAt.IsZero() && !s.now.Before(s.debounceAt) {
		s.debounceAt = time.Time{}
		if configured {
			trigger = cmp.Or(trigger, logattr.TriggerInterfaces)
		}
	}
	var repair string
	s, repair = s.fireRepair()
	trigger = cmp.Or(trigger, repair)
	if b, ok := s.loadedBook(); ok {
		if next, due := b.expiry(); due && !s.now.Before(next) {
			b.expired = s.now
			s = s.withBook(b)
			out = append(out, ExpireBook{At: s.now})
		}
	}
	return s, out, trigger
}

// NextWake returns the time at which the shell gives Step a Tick. It
// reports false when nothing is due.
func NextWake(s State) (time.Time, bool) {
	var next time.Time
	add := func(t time.Time) {
		if !t.IsZero() && (next.IsZero() || t.Before(next)) {
			next = t
		}
	}
	if _, ok := s.accounts.InFlight(); ok && s.now.Before(s.accounts.deadline) {
		add(s.accounts.deadline)
	}
	add(s.healAt)
	add(s.debounceAt)
	add(s.watch.repairAt)
	if b, ok := s.loadedBook(); ok {
		if t, due := b.expiry(); due {
			add(t)
		}
	}
	return next, !next.IsZero()
}
