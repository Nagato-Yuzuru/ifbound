package daemon

import (
	"github.com/Nagato-Yuzuru/ifbound/internal/configstore"
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

// String returns the lower-case state name.
func (s State) String() string {
	switch s {
	case StateStarting:
		return "starting"
	case StateReady:
		return "ready"
	case StateDegraded:
		return "degraded"
	case StateUnenforced:
		return "unenforced"
	default:
		return "unknown"
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

func startingPhase(reason string) phase {
	return phase{state: StateStarting, reasons: []string{reason}}
}

// unconfiguredPhase is the phase of a daemon that has no configuration.
// It does not converge, so it keeps the platform state that it found.
func unconfiguredPhase(reason string) phase {
	return phase{state: StateUnenforced, reasons: []string{reason}}
}

func unenforcedPhase(reason string) phase {
	return phase{state: StateUnenforced, reasons: []string{reason}}
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
