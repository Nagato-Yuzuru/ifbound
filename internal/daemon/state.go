package daemon

import (
	"slices"

	"github.com/Nagato-Yuzuru/ifbound/internal/configstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/daemon/core"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// State is the lifecycle state of the daemon. See core.Lifecycle for the
// states and their moves.
type State = core.Lifecycle

// The lifecycle states. The zero State is StateStarting.
const (
	StateStarting   = core.Starting
	StateReady      = core.Ready
	StateDegraded   = core.Degraded
	StateUnenforced = core.Unenforced
)

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

// statusOf returns the status of s. It costs one map lookup per policy,
// so the loop can publish it at each pass.
func statusOf(s core.State) Status {
	p := core.PhaseOf(s)
	st := Status{State: p.Lifecycle, Reasons: slices.Clone(p.Reasons)}
	c, ok := s.Config().(core.Configured)
	if !ok {
		return st
	}
	st.Policies = len(c.Active.Config.Policies)
	st.RetainRestart = c.Active.Config.AddrBook.Retain != s.Retain()
	st.Config = c.Active.Digest
	st.Warnings = slices.Clone(c.Active.Warnings)
	if b, ok := c.Book.(core.BookLoaded); ok {
		for _, pol := range c.Active.Config.Policies {
			st.Addrs += b.Facts.Counts[pol.Name]
		}
	}
	return st
}
