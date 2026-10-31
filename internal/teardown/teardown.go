// Package teardown removes the enforcement of ifbound from the host: the
// rules and the tables of the pf anchor, the pf references of ifbound,
// and the resolver entries. Uninstall runs it after the daemons stop.
//
// Each step reads the state that the steps before it left, so a second
// run after a stop at any step finishes the teardown. A stop fails
// closed: the resolver entries go last, so while the pf part is not
// complete, they send the protected names to the stopped DNS server, and
// the names do not resolve.
package teardown

import (
	"context"
	"fmt"

	"github.com/Nagato-Yuzuru/ifbound/internal/enforcementlock"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// Backend removes the firewall part of the enforcement.
// *pfbackend.Backend implements it.
type Backend interface {
	// Unload reads the firewall references of ifbound from the kernel,
	// gives them back, then removes the rules and the tables. It is
	// idempotent, and it finishes also when ctx is canceled.
	Unload(ctx context.Context) error
}

// Teardown holds the platform parts. All fields are required.
type Teardown struct {
	// Lock is the path of the writer lock: layout.EnforcementLock on the
	// host.
	Lock     string
	Backend  Backend
	Resolver reconcile.SysResolver
}

// Run takes the writer lock, unloads the Backend, and then converges the
// resolver entries to the empty state, which removes all of them. It
// loads no ruleset: a load adds nothing before the unload, and it would
// enable a firewall that the user disabled. When the unload fails, Run
// keeps the resolver entries.
//
// When another process holds the writer lock, Run returns an error that
// wraps enforcementlock.ErrHeld at once and changes nothing.
func (t Teardown) Run(ctx context.Context) error {
	l, err := enforcementlock.Acquire(t.Lock)
	if err != nil {
		return err
	}
	defer l.Close() //nolint:errcheck // the close releases the lock; a failure cannot change what Run did
	if err := t.Backend.Unload(ctx); err != nil {
		return fmt.Errorf("unloading the enforcement: %w", err)
	}
	r := reconcile.Reconciler{Resolver: t.Resolver}
	if _, err := r.ConvergeResolver(ctx, reconcile.Inputs{}); err != nil {
		return fmt.Errorf("removing the resolver entries: %w", err)
	}
	return nil
}
