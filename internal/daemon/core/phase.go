package core

import (
	"errors"
	"slices"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/matcher"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// ReasonNotLoaded is the reason of Starting before the first open of the
// address book.
const ReasonNotLoaded = "the address book is not loaded yet"

// reasonNotUsed is the reason of Starting from the load of the book to
// the end of the convergence of its pass.
const reasonNotUsed = "the address book is loaded, and no convergence used it yet"

// reasonAdopting is the reason of Starting while the first adoption of
// the kernel entries runs.
const reasonAdopting = "the kernel entries are not adopted into the address book yet"

// Errors of a closed Gate.
var (
	// ErrNotReady rejects a report while the daemon is in Starting.
	ErrNotReady = errors.New("daemon: not ready")
	// ErrUnenforced rejects a report while the installed enforcement is
	// missing or void: in Unenforced, or when the loaded ruleset is not
	// the installed one.
	ErrUnenforced = errors.New("daemon: enforcement not installed")
)

// Lifecycle is the lifecycle state of the daemon.
//
// Starting goes to Ready, Degraded, or Unenforced. These three go to each
// other. Only Ready and Degraded acknowledge reports. A daemon that
// starts without a stored configuration is in Unenforced; when Apply then
// gives it a configuration and the address book does not load, it goes
// to Starting.
type Lifecycle uint8

// The lifecycle states. The zero Lifecycle is Starting.
const (
	// Starting: the address book is not loaded. The daemon acknowledges
	// no report. With a configuration, it loads the ruleset and adds the
	// entries that need no address book, but it removes no table entry
	// that blockable.New accepts.
	Starting Lifecycle = iota
	// Ready: the ruleset for the current configuration and interfaces is
	// installed, and nothing reports a problem.
	Ready
	// Degraded: the ruleset is installed, but a problem that does not
	// void enforcement exists, such as a resolver conflict or a failed
	// resolver write. Reports are acknowledged.
	Degraded
	// Unenforced: the ruleset for the current configuration and
	// interfaces is not installed, or a problem voids it, such as a
	// disabled firewall, or the daemon has no configuration. No report is
	// acknowledged.
	Unenforced
)

// String returns the lower-case state name: the value of the log
// attribute logattr.EnforcementState.
func (l Lifecycle) String() string {
	switch l {
	case Starting:
		return logattr.StateStarting
	case Ready:
		return logattr.StateReady
	case Degraded:
		return logattr.StateDegraded
	case Unenforced:
		return logattr.StateUnenforced
	default:
		return logattr.StateUnknown
	}
}

// Phase is the lifecycle state together with the facts it rests on.
// Only PhaseOf makes one, so the facts cannot disagree: Installed is set
// exactly in Ready and Degraded.
type Phase struct {
	Lifecycle Lifecycle
	// Installed is the ruleset ID that the last convergence installed for
	// the current configuration and interfaces. A report is acknowledged
	// only while the Backend still has this ruleset loaded.
	Installed string
	// Reasons explains every state but Ready, where it is empty.
	Reasons []string
}

// Acks reports whether the phase acknowledges reports.
func (p Phase) Acks() bool { return p.Installed != "" }

// Converged is the result of one convergence pass: its report, its
// error, and the epoch of the Guard after its Backend part. The pass ran
// under the configuration and the book state of the State that it read,
// because the pass runs inside one drain.
type Converged struct {
	At     time.Time
	Report reconcile.Report
	Err    error
	Epoch  uint64
}

func (e Converged) at() time.Time { return e.At }

// enforcement is what Step knows of the enforcement on the platform.
type enforcement struct {
	// last is the outcome of the latest convergence, or nil before the
	// first one.
	last *outcome
}

// outcome is one convergence and the state that it ran under.
type outcome struct {
	// gen is the configuration generation of the pass.
	gen uint64
	// epoch is the epoch of the Guard after the pass.
	epoch   uint64
	addOnly bool
	report  reconcile.Report
	err     error
}

// applyConverged keeps the outcome of the pass. When the pass installed
// the ruleset with the loaded book, no loaded rule refers to a removed
// policy, and its table is gone: Step then prunes the book. Until this
// point a revert of the configuration must still find its addresses.
func (s State) applyConverged(ev Converged, out []Effect) (State, []Effect) {
	c, ok := s.Config().(Configured)
	if !ok {
		return s, out
	}
	_, loaded := c.Book.(BookLoaded)
	s.enf.last = &outcome{gen: c.Active.Gen, epoch: ev.Epoch, addOnly: !loaded, report: ev.Report, err: ev.Err}
	s = s.clearReports()
	if ev.Report.Installed != "" && loaded {
		out = append(out, PruneBook{Keep: policyNames(c.Active.Config.Policies)})
	}
	return s, out
}

func policyNames(policies []policy.Policy) []policy.Name {
	names := make([]policy.Name, len(policies))
	for i, p := range policies {
		names[i] = p.Name
	}
	return names
}

// PhaseOf returns the phase of s. It is the only source of the phase.
func PhaseOf(s State) Phase {
	switch c := s.Config().(type) {
	case Unconfigured:
		if c.Err == nil {
			return Phase{Lifecycle: Starting, Reasons: []string{ReasonNotLoaded}}
		}
		return Phase{Lifecycle: Unenforced, Reasons: []string{"the stored configuration did not load: " + c.Err.Error()}}
	case Configured:
		return s.configuredPhase(c)
	default:
		return Phase{Lifecycle: Unenforced, Reasons: []string{"unknown configuration state"}}
	}
}

// configuredPhase is the phase of a configured state. Only a
// convergence of the active configuration can install a ruleset, and a
// later report that finds another loaded ruleset voids it. The problems
// of the inputs do not void enforcement. While the book is not loaded,
// the phase acknowledges nothing, also when the ruleset is installed:
// without the book, the daemon cannot record an address.
func (s State) configuredPhase(c Configured) Phase {
	o := s.enf.last
	switch {
	case o == nil || o.gen != c.Active.Gen:
		return Phase{Lifecycle: Unenforced, Reasons: []string{"the new configuration is not installed yet"}}
	}
	if reason, ok := rulesetReason(s); ok {
		return Phase{Lifecycle: Unenforced, Reasons: []string{reason}}
	}
	problems := slices.Clone(o.report.Problems)
	if p, ok := hostsProblem(s); ok {
		problems = append(problems, p)
	}
	if p, ok := accountsProblem(s); ok {
		problems = append(problems, p)
	}
	if p, ok := reportProblem(s); ok {
		problems = append(problems, p)
	}
	if p, ok := watchProblem(s); ok {
		problems = append(problems, p)
	}
	b, loaded := c.Book.(BookLoaded)
	if p, ok := bookProblem(b); loaded && ok {
		problems = append(problems, p)
	}
	if c.Active.Upstream != nil {
		// Only the stored file at start can fail the check: Apply refuses
		// such a configuration. The check protects only DNS, so the
		// daemon enforces the file.
		problems = append(problems, reconcile.Problem{Text: "the configuration fails the upstream check: " + c.Active.Upstream.Error()})
	}
	switch b := c.Book.(type) {
	case BookLoaded:
		if o.addOnly {
			// The pass that loaded the book did not converge yet. An
			// add-only convergence can keep a table entry that the book
			// would remove.
			return Phase{Lifecycle: Starting, Reasons: reasonsOf(slices.Insert(problems, 0, reconcile.Problem{Text: reasonNotUsed}), o.err)}
		}
		p := loadedPhase(problems, o.report.Installed, o.err)
		if st, ok := s.selfTestProblem(); ok && p.Acks() {
			// The warm-up, and so the self-test, runs only while the phase
			// acks. In another phase the reason would only repeat that.
			p = loadedPhase(append(problems, st), o.report.Installed, o.err)
		}
		return p
	case BookUnloadable:
		return Phase{Lifecycle: Starting, Reasons: reasonsOf(slices.Insert(problems, 0, reconcile.Problem{Text: b.Err.Error()}), o.err)}
	case BookAdopting:
		text := reasonAdopting
		if b.Err != nil {
			text = b.Err.Error()
		}
		return Phase{Lifecycle: Starting, Reasons: reasonsOf(slices.Insert(problems, 0, reconcile.Problem{Text: text}), o.err)}
	case BookLoading:
		return Phase{Lifecycle: Starting, Reasons: reasonsOf(slices.Insert(problems, 0, reconcile.Problem{Text: ReasonNotLoaded}), o.err)}
	default:
		return Phase{Lifecycle: Unenforced, Reasons: []string{"unknown book state"}}
	}
}

// loadedPhase is the phase of a convergence with the loaded book.
func loadedPhase(problems []reconcile.Problem, installed string, err error) Phase {
	reasons := reasonsOf(problems, err)
	switch {
	case installed == "" || slices.ContainsFunc(problems, func(p reconcile.Problem) bool { return p.Voids }):
		return Phase{Lifecycle: Unenforced, Reasons: reasons}
	case len(reasons) > 0:
		return Phase{Lifecycle: Degraded, Installed: installed, Reasons: reasons}
	default:
		return Phase{Lifecycle: Ready, Installed: installed}
	}
}

func reasonsOf(problems []reconcile.Problem, err error) []string {
	var reasons []string
	for _, p := range problems {
		reasons = append(reasons, p.Text)
	}
	if err != nil {
		reasons = append(reasons, "convergence failed: "+err.Error())
	}
	return reasons
}

// Gate is what the report path needs of the State: the matcher of the
// active configuration, and whether reports get an ack. GateOf makes it,
// and the shell takes a new one after each Step.
type Gate struct {
	// Matcher is nil without a configuration.
	Matcher *matcher.Matcher
	State   GateState
}

// GateState is exactly one of Open and Closed.
//
//sumtype:decl
type GateState interface{ isGateState() }

// Open: reports get an ack while the Backend has the ruleset Installed
// loaded and the Guard still has Epoch. Epoch is the epoch of the Guard
// after the convergence that opened the gate. A later write that can
// remove an entry or replace the ruleset moves the epoch of the Guard.
type Open struct {
	Epoch     uint64
	Installed string
}

// Closed: no report gets an ack. Err is ErrNotReady in Starting and
// ErrUnenforced in the other phases.
type Closed struct{ Err error }

func (Open) isGateState()   {}
func (Closed) isGateState() {}

// GateOf returns the gate of s. It is open exactly when PhaseOf acks.
func GateOf(s State) Gate {
	var g Gate
	if c, ok := s.Config().(Configured); ok {
		g.Matcher = c.Active.Matcher
	}
	switch p := PhaseOf(s); {
	case p.Acks():
		g.State = Open{Epoch: s.enf.last.epoch, Installed: p.Installed}
	case p.Lifecycle == Starting:
		g.State = Closed{Err: ErrNotReady}
	default:
		g.State = Closed{Err: ErrUnenforced}
	}
	return g
}
