package daemon

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrstore"
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

// ErrInjectedBook is the error of a book write that SetBookFault fails.
var ErrInjectedBook = errors.New("daemon test: injected book write fault")

// SetBookFault makes the writes of the address book fail while fail is
// set: Commit of a Pending that is not empty, and Adopt with an address.
// A failed write changes nothing, as a failed commit of the store
// does. Expire and Prune still run. Call it before Run.
func (d *Daemon) SetBookFault(fail *atomic.Bool) {
	open := d.openBook
	d.openBook = func(path, legacy string, retain time.Duration) (addrBook, error) {
		b, err := open(path, legacy, retain)
		if err != nil {
			return nil, err
		}
		return faultyBook{addrBook: b, fail: fail}, nil
	}
}

type faultyBook struct {
	addrBook
	fail *atomic.Bool
}

func (b faultyBook) Commit(ctx context.Context, p addrstore.Pending) error {
	if b.fail.Load() && !p.Empty() {
		return ErrInjectedBook
	}
	return b.addrBook.Commit(ctx, p)
}

func (b faultyBook) Apply(ctx context.Context, op addrstore.Op) (int, error) {
	if !b.fail.Load() {
		return b.addrBook.Apply(ctx, op)
	}
	switch op := op.(type) {
	case addrstore.Adopt:
		for _, addrs := range op.Found {
			if len(addrs) > 0 {
				return 0, ErrInjectedBook
			}
		}
	case addrstore.Expire, addrstore.Prune:
	}
	return b.addrBook.Apply(ctx, op)
}
