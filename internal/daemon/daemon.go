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
//
// A report can carry aliases: names that the answer points the client
// to. The client then asks for each alias (A, AAAA, HTTPS), and those
// answers must also be blocked. So each alias gets a resolver entry that
// sends its queries to ifbound-dns, and the daemon acks a report with an
// alias only after a probe proves that the system applies that entry:
// the follow-up queries then come to ifbound-dns and are reported like
// any other query. See Daemon.Observe.
//
// When the daemon starts to ack reports, and after each configuration
// change, it warms up: it resolves the listed names through the system
// resolver, so that their addresses are blocked before an
// application asks. A probe first proves that the lookups go to
// ifbound-dns, and their reports take the normal path. See Daemon.Run.
package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
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
	// ProbeInterval is the time between two probes of one alias.
	ProbeInterval = 50 * time.Millisecond
	// AckReserve is the part of the time budget of a report that the
	// probe leaves for the rest of the report: the loop can run a
	// convergence first, and then it checks the tables and the ruleset.
	// With the 5 s budget of ifbound-dns, the probe gets 4 s, more than
	// twice the longest apply time of a new resolver entry measured on
	// macOS (1.55 s).
	AckReserve = time.Second
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
	// ErrAliasEntry rejects a report with an alias that has no resolver
	// entry of ifbound: the alias cannot get one (it is malformed, it
	// does not obey the domain rules of the configuration, or it is a
	// public suffix), or the write of its entry failed. A later query
	// for the alias would go around ifbound-dns.
	ErrAliasEntry = errors.New("daemon: alias has no resolver entry")
	// ErrAliasProbe rejects a report when no probe proved in the time
	// budget that the system applies the resolver entry of an alias, when
	// the entry or an entry above it changed while the probe ran, or when
	// the system resolver reported a new problem meanwhile.
	ErrAliasProbe = errors.New("daemon: resolver entry of an alias not proven")
	// ErrConfigChanged rejects a report when the configuration changed
	// while its probe ran.
	ErrConfigChanged = errors.New("daemon: configuration changed during the probe")
)

// SystemResolver resolves a name through the system resolver, as an
// application does. syslookup.Resolver implements it. The daemon uses it
// to send probe names (see ipc.ProbePrefix) and the names of the
// warm-up. It ignores the addresses: only the report from ifbound-dns
// counts. The warm-up logs the error, and it treats an error that wraps
// syslookup.ErrNotFound as normal. The deadline of ctx is the budget of
// the call.
type SystemResolver interface {
	Resolve(ctx context.Context, name string) ([]netip.Addr, error)
}

// Config holds what the daemon needs at start.
type Config struct {
	// Policy is the initial configuration. Its retain is fixed for the
	// life of the daemon.
	Policy policy.Config
	// Snapshot is the path of the address book snapshot.
	Snapshot string
	// Platform converges the platform state. All its fields are required.
	Platform reconcile.Reconciler
	// Lookup sends the probe names and the warm-up names through the
	// system resolver. It is required.
	Lookup SystemResolver
	// Logger receives state changes and enforcement changes. Nil discards
	// them.
	Logger *slog.Logger
}

// request runs on the loop goroutine with the loop context.
type request func(ctx context.Context, l *loop)

// Daemon is the ifboundd core. Create it with New and start it with Run.
// Its methods are safe for concurrent use. It implements ipc.Handler and
// ipc.ProbeHandler.
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

	// probes are the probe names that a probe waits for. The probe
	// reports do not go through the loop: a report that waits for its
	// probe holds no loop time, but a probe report must never wait for
	// anything.
	probesMu sync.Mutex
	probes   map[string]*probeWait
}

var (
	_ ipc.Handler      = (*Daemon)(nil)
	_ ipc.ProbeHandler = (*Daemon)(nil)
)

// New returns a daemon in StateStarting. It does no I/O; Run does.
func New(cfg Config) *Daemon {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Daemon{
		cfg:      cfg,
		requests: make(chan request),
		done:     make(chan struct{}),
		probes:   make(map[string]*probeWait),
	}
}

// Run is the event loop. It loads the snapshot, converges, and then
// serves events until ctx ends. It returns nil when ctx ends, and
// ErrAlreadyRunning when called a second time.
//
// A snapshot that does not load keeps the daemon in StateStarting. A
// snapshot without an address of a configured policy, such as a missing
// file or a file with aliases only, makes the daemon adopt the
// learned-looking kernel entries and save them before it leaves
// StateStarting. The self-heal timer retries the load and the
// convergence until both succeed.
//
// In StateReady and StateDegraded, Run resolves the names that the
// configuration lists through Config.Lookup: each exact destination and
// the domain of each suffix destination. Before the lookup of a name, a
// probe below the name must prove that its queries go to ifbound-dns. A
// name whose probe fails gets another try after SelfHealInterval. At
// most WarmUpConcurrency names are in work at one time, outside the
// loop. The probe and the lookup of a name get WarmUpTimeout each. A
// failed lookup is logged and skipped. The warm-up stops when the state
// leaves these two states or the configuration changes, and then starts
// again under the new state or configuration. Its lookups that already
// started run to their end. Run returns after every lookup has returned.
func (d *Daemon) Run(ctx context.Context) error {
	if !d.started.CompareAndSwap(false, true) {
		return ErrAlreadyRunning
	}
	warm := newWarmUp(d.cfg.Lookup, d.probe, d.cfg.Logger)
	// The warm-up ends with ctx. Run waits for its lookups after done
	// closes: a lookup can wait for its report, and that report then
	// ends with ErrStopped.
	defer warm.wait()
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
		warm.sync(ctx, l)
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
// that matches no policy is acknowledged and not stored.
//
// A report matches the policies that match its name and the policies
// that learned its name as an alias. For a matching report, each alias
// must also have a resolver entry of ifbound that a probe proved: the
// system sends the queries for the alias to ifbound-dns. The daemon
// remembers a proof until the entry changes. To prove an entry, Observe
// resolves a probe name below the alias through Config.Lookup, every
// ProbeInterval, until ifbound-dns reports one of these names
// (ProbeSeen). The probe runs on the goroutine of the caller, so the loop
// serves other events meanwhile. It gets the deadline of ctx less
// AckReserve, or ipc.DefaultTimeout less AckReserve when ctx has no
// deadline.
//
// It returns ErrNotReady in StateStarting, ErrUnenforced when
// enforcement is not installed, an error that wraps
// matcher.ErrMalformedName for a name that cannot be classified,
// ErrAliasEntry, ErrAliasProbe, ErrConfigChanged, and the
// platform error otherwise. See call for ctx.Err() and ErrStopped.
func (d *Daemon) Observe(ctx context.Context, o ipc.Observation) error {
	res, cerr := call(ctx, d, func(ctx context.Context, l *loop) observed {
		pq, err := l.observe(ctx, o)
		return observed{pq: pq, err: err}
	})
	switch {
	case cerr != nil:
		return cerr
	case res.err != nil || res.pq == nil:
		return res.err
	}
	perr := d.prove(ctx, res.pq.aliases)
	// finish runs also when ctx has ended, so the caller learns the
	// outcome of the probe.
	err, cerr := call(context.WithoutCancel(ctx), d, func(ctx context.Context, l *loop) error {
		return l.finish(ctx, res.pq, perr)
	})
	if cerr != nil {
		return cerr
	}
	return err
}

// observed is the result of the first part of Observe. A non-nil pq
// means: no error, and the aliases of pq need a probe before the ack.
type observed struct {
	pq  *pending
	err error
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
