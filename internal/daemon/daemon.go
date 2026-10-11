// Package daemon runs the ifboundd event loop.
//
// One goroutine, started by Run, owns the address book and drives the
// platform through a reconcile.Reconciler. Every event goes to it: a DNS
// report, an interface change, the self-heal and expiry timers, and a
// configuration change. Other goroutines talk to it only through requests
// with a reply channel, so its state needs no lock.
//
// Every event that can change the desired state ends in the same
// convergence. Crash recovery, an external flush, and a configuration
// change therefore all take one path. Shutdown removes no rule and no
// resolver entry: enforcement stays in place while the daemon is down.
//
// An acknowledgement of a report means: the addresses are in the tables
// of the matching policies, in the saved snapshot, and the ruleset that
// the last convergence installed for the current configuration and
// interfaces is still loaded. See State for when the daemon acknowledges.
package daemon

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

const (
	// SelfHealInterval is the period of the convergence that repairs
	// external changes, such as a flushed table.
	SelfHealInterval = 5 * time.Second
	// InterfaceDebounce is the delay from the first interface change to
	// the convergence. Changes inside the delay share that convergence.
	InterfaceDebounce = 500 * time.Millisecond
)

// Errors of the request methods.
var (
	// ErrNotReady rejects a report while the daemon is in StateStarting.
	ErrNotReady = errors.New("daemon: not ready")
	// ErrUnenforced rejects a report while the installed enforcement is
	// missing or void: in StateUnenforced, or when the loaded ruleset is
	// not the installed one.
	ErrUnenforced = errors.New("daemon: enforcement not installed")
	// ErrStopped means Run has returned.
	ErrStopped = errors.New("daemon: stopped")
	// ErrAlreadyRunning is the error of a second Run call.
	ErrAlreadyRunning = errors.New("daemon: Run already called")
)

// Config holds what the daemon needs at start.
type Config struct {
	// Policy is the initial configuration. Its retain is fixed for the
	// life of the daemon.
	Policy policy.Config
	// Snapshot is the path of the address book snapshot.
	Snapshot string
	// Platform converges the platform state. All its fields are required.
	Platform reconcile.Reconciler
	// Logger receives state changes and enforcement changes. Nil discards
	// them.
	Logger *slog.Logger
}

// request runs on the loop goroutine with the loop context.
type request func(ctx context.Context, l *loop)

// Daemon is the ifboundd core. Create it with New and start it with Run.
// Its methods are safe for concurrent use. It implements ipc.Handler.
//
// The daemon learns of a problem that voids enforcement, such as a
// disabled firewall, only at a convergence: for up to SelfHealInterval
// after it appears, reports are still acknowledged, and addresses that
// were acknowledged earlier are exposed in the same window.
type Daemon struct {
	cfg      Config
	requests chan request
	done     chan struct{}
	started  atomic.Bool
}

var _ ipc.Handler = (*Daemon)(nil)

// New returns a daemon in StateStarting. It does no I/O; Run does.
func New(cfg Config) *Daemon {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Daemon{cfg: cfg, requests: make(chan request), done: make(chan struct{})}
}

// Run is the event loop. It loads the snapshot, converges, and then
// serves events until ctx ends. It returns nil when ctx ends, and
// ErrAlreadyRunning when called a second time.
//
// A snapshot that does not load keeps the daemon in StateStarting. A
// snapshot without entries, such as a missing file, makes the daemon
// adopt the learned-looking kernel entries and save them before it
// leaves StateStarting. The self-heal timer retries the load and the
// convergence until both succeed.
func (d *Daemon) Run(ctx context.Context) error {
	if !d.started.CompareAndSwap(false, true) {
		return ErrAlreadyRunning
	}
	defer close(d.done)

	l := newLoop(d.cfg)
	heal := time.NewTicker(SelfHealInterval)
	defer heal.Stop()
	expiry := time.NewTimer(0) // armExpiry sets it before the first select
	defer expiry.Stop()
	var debounce <-chan time.Time
	changes := d.cfg.Platform.Inventory.Changes()

	_ = l.reconcile(ctx, "start") // the phase holds the outcome
	for {
		l.armExpiry(expiry)
		select {
		case <-ctx.Done():
			return nil
		case req := <-d.requests:
			req(ctx, l)
			if l.recheck {
				l.recheck = false
				_ = l.reconcile(ctx, "ruleset changed") // the phase holds the outcome
			}
		case <-changes:
			if debounce == nil {
				debounce = time.After(InterfaceDebounce)
			}
		case <-debounce:
			debounce = nil
			_ = l.reconcile(ctx, "interfaces") // the phase holds the outcome
		case <-heal.C:
			_ = l.reconcile(ctx, "self-heal") // the phase holds the outcome
		case <-expiry.C:
			l.expire(ctx)
		}
	}
}

// Observe implements ipc.Handler. It returns nil, the acknowledgement,
// only when every address is in the table of each matching policy, in
// the saved snapshot, and the installed ruleset is still loaded. A name
// that matches no policy is acknowledged and not stored. It returns
// ErrNotReady in StateStarting, ErrUnenforced when enforcement is not
// installed, an error that wraps matcher.ErrMalformedName for a name that
// cannot be classified, and the platform error otherwise. See call for
// ctx.Err() and ErrStopped.
func (d *Daemon) Observe(ctx context.Context, o ipc.Observation) error {
	err, cerr := call(ctx, d, func(ctx context.Context, l *loop) error {
		return l.observe(ctx, o)
	})
	if cerr != nil {
		return cerr
	}
	return err
}

// Reconfigure replaces the configuration and converges. The new
// configuration applies also when the convergence fails: the error is
// that of the convergence, the daemon acknowledges no report until a
// convergence succeeds, and the self-heal timer retries it. A new retain
// applies only after a restart; see Status.RetainRestart. See call for
// ctx.Err() and ErrStopped: with either, the configuration did not apply.
func (d *Daemon) Reconfigure(ctx context.Context, cfg policy.Config) error {
	err, cerr := call(ctx, d, func(ctx context.Context, l *loop) error {
		return l.reconfigure(ctx, cfg)
	})
	if cerr != nil {
		return cerr
	}
	return err
}

// Status returns a copy of the daemon state.
func (d *Daemon) Status(ctx context.Context) (Status, error) {
	return call(ctx, d, func(_ context.Context, l *loop) Status { return l.status() })
}

// call runs f on the loop goroutine and returns its result. Its error is
// ctx.Err() when ctx ends before the loop takes the request, and
// ErrStopped when Run has returned; f then did not run. Once the loop
// takes the request, call waits for the result and ignores ctx, so the
// caller always learns the outcome of what ran. The wait is bounded: the
// platform calls that f makes finish in bounded time.
func call[R any](ctx context.Context, d *Daemon, f func(context.Context, *loop) R) (R, error) {
	reply := make(chan R, 1)
	req := func(loopCtx context.Context, l *loop) { reply <- f(loopCtx, l) }
	var zero R
	select {
	case d.requests <- req:
	case <-ctx.Done():
		return zero, ctx.Err()
	case <-d.done:
		return zero, ErrStopped
	}
	return <-reply, nil
}
