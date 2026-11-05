package daemon

import (
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrbook"
	"github.com/Nagato-Yuzuru/ifbound/internal/configstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/matcher"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// State is the lifecycle state of the daemon.
//
// Starting goes to Ready, Degraded, or Unenforced. These three go to each
// other. Only Ready and Degraded acknowledge reports. A daemon that
// starts without a stored configuration is in Unenforced; when Apply then
// gives it a configuration and the snapshot does not load, it goes to
// Starting.
type State uint8

// The lifecycle states. The zero State is StateStarting.
const (
	// StateStarting: the snapshot is not loaded. The daemon writes
	// nothing to the platform and acknowledges no report.
	StateStarting State = iota
	// StateReady: the ruleset for the current configuration and
	// interfaces is installed, and nothing reports a problem.
	StateReady
	// StateDegraded: the ruleset is installed, but a problem that does
	// not void enforcement exists, such as a resolver conflict or a
	// failed resolver write. Reports are acknowledged.
	StateDegraded
	// StateUnenforced: the ruleset for the current configuration and
	// interfaces is not installed, or a problem voids it, such as a
	// disabled firewall, or the daemon has no configuration. No report is
	// acknowledged.
	StateUnenforced
)

// String returns the lower-case state name: the value of the log
// attribute logattr.EnforcementState.
func (s State) String() string {
	switch s {
	case StateStarting:
		return logattr.StateStarting
	case StateReady:
		return logattr.StateReady
	case StateDegraded:
		return logattr.StateDegraded
	case StateUnenforced:
		return logattr.StateUnenforced
	default:
		return logattr.StateUnknown
	}
}

// Status is a read-only copy of the daemon state for a client such as
// the CLI.
type Status struct {
	State State
	// Reasons explains every state but StateReady, where it is empty.
	Reasons []string
	// Policies is the number of configured policies.
	Policies int
	// Addrs is the number of learned addresses of the configured policies.
	Addrs int
	// RetainRestart is true when the configured retain differs from the
	// retain of the running address book. Only a restart applies it.
	RetainRestart bool
	// Config is the digest of the stored configuration that the daemon
	// runs. It is zero when the daemon has no configuration.
	Config configstore.Digest
	// Warnings are the warnings of the upstream check for the running
	// configuration.
	Warnings []policy.Warning
}

// phase is the lifecycle state together with the facts it rests on. It
// is one value, built only by the functions below, so the facts cannot
// disagree: installed is set exactly in StateReady and StateDegraded.
type phase struct {
	state State
	// installed is the ruleset ID that the last convergence installed for
	// the current configuration and interfaces. A report is acknowledged
	// only while the Backend still has this ruleset loaded.
	installed string
	reasons   []string
}

// waitPhase is a phase that does not acknowledge reports: it has no
// installed ruleset. It is the phase of a mode without a book.
type waitPhase struct {
	state   State
	reasons []string
}

// asPhase returns w as a phase without an installed ruleset.
func (w waitPhase) asPhase() phase { return phase{state: w.state, reasons: w.reasons} }

func startingPhase(reason string) waitPhase {
	return waitPhase{state: StateStarting, reasons: []string{reason}}
}

// unconfiguredPhase is the phase of a daemon that has no configuration.
// It does not converge, so it keeps the platform state that it found.
func unconfiguredPhase(reason string) waitPhase {
	return waitPhase{state: StateUnenforced, reasons: []string{reason}}
}

func unenforcedPhase(reason string) waitPhase {
	return waitPhase{state: StateUnenforced, reasons: []string{reason}}
}

// convergedPhase is the phase after a convergence attempt.
func convergedPhase(rep reconcile.Report, err error) phase {
	var reasons []string
	voids := false
	for _, p := range rep.Problems {
		reasons = append(reasons, p.Text)
		voids = voids || p.Voids
	}
	if err != nil {
		reasons = append(reasons, "convergence failed: "+err.Error())
	}
	switch {
	case rep.Installed == "" || voids:
		return phase{state: StateUnenforced, reasons: reasons}
	case len(reasons) > 0:
		return phase{state: StateDegraded, installed: rep.Installed, reasons: reasons}
	default:
		return phase{state: StateReady, installed: rep.Installed}
	}
}

// acks reports whether the phase acknowledges reports.
func (p phase) acks() bool { return p.installed != "" }

// mode is the lifecycle of the loop: exactly one of unconfiguredMode,
// loadingMode, and runningMode. Only runningMode has a book, and only its
// phase can have an installed ruleset.
//
//sumtype:decl
type mode interface{ isMode() }

// unconfiguredMode: the daemon has no configuration. It does not
// converge, so it keeps the platform state that it found.
type unconfiguredMode struct{ phase waitPhase }

// loadingMode: the daemon has a configuration, but no load of the
// snapshot succeeded yet. It does not converge: an empty book would
// remove every learned address.
type loadingMode struct {
	conf activeConfig
	// retain is the retain of the book to load. The first configuration
	// fixes it for the life of the daemon.
	retain time.Duration
	phase  waitPhase
}

// runningMode: the daemon has a configuration and the book of the
// loaded snapshot. It converges, and its phase can acknowledge reports.
type runningMode struct {
	conf activeConfig
	// retain is the retain of book.
	retain time.Duration
	book   *addrbook.AddrBook
	phase  phase
}

func (unconfiguredMode) isMode() {}
func (loadingMode) isMode()      {}
func (runningMode) isMode()      {}

// activeConfig is the configuration that the daemon uses, with what the
// daemon derives from it. newActiveConfig builds it, and a new
// configuration replaces it as a whole.
type activeConfig struct {
	cfg policy.Config
	// digest is the digest of the stored file of cfg, or zero.
	digest  configstore.Digest
	matcher *matcher.Matcher
	apexes  []policy.Domain
	// upstream is the error of the upstream check for cfg, or nil.
	upstream error
	warnings []policy.Warning
	// gen counts the configurations. A warm-up runs only under the
	// configuration that it started with.
	gen uint64
}

func newActiveConfig(cfg policy.Config, digest configstore.Digest, gen uint64) activeConfig {
	m := matcher.New(cfg.Policies)
	return activeConfig{
		cfg:      cfg,
		digest:   digest,
		matcher:  m,
		apexes:   m.Apexes(),
		upstream: cfg.CheckUpstreams(),
		warnings: cfg.Warnings(),
		gen:      gen,
	}
}
