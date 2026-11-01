package daemon

import (
	"context"

	"github.com/Nagato-Yuzuru/ifbound/internal/configstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// Reconfigure runs the convergence path of Apply without the store, for
// the tests that inject faults into a configuration change. Its error is
// that of the convergence. Status.Config becomes zero, because no stored
// file holds cfg. See call for ctx.Err() and ErrStopped.
func (d *Daemon) Reconfigure(ctx context.Context, cfg policy.Config) error {
	err, cerr := call(ctx, d, func(ctx context.Context, l *loop) error {
		return l.reconfigure(ctx, cfg, configstore.Digest{})
	})
	if cerr != nil {
		return cerr
	}
	return err
}

// SetStore replaces configstore.Store for Apply. Call it before Run.
func (d *Daemon) SetStore(f func(path string, data []byte, gid int) (policy.Config, configstore.Digest, error)) {
	d.store = f
}
