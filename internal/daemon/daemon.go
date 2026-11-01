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
// macOS answers a name from the host file before it asks DNS. Each
// convergence first reads the host file again if it changed, and the
// addresses of its entries for protected names go into the tables. See
// Daemon.Run.
//
// When the daemon starts to ack reports, and after each configuration
// change, it warms up: it resolves the listed names through the system
// resolver, so that their addresses are blocked before an
// application asks. A probe first proves that the lookups go to
// ifbound-dns, and their reports take the normal path. See Daemon.Run.
//
// The configuration comes from the stored file of configstore. Run loads
// it at start, and only Apply replaces it. See Daemon.Run and
// Daemon.Apply.
//
// The ruleset limits a scoped policy to its users and groups by their
// ids. The daemon reads these ids outside the loop, after the first
// convergence, after each configuration change, and at each self-heal.
// See Daemon.Run.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/configstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
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
	// ErrBadConfig is the error of Run when a field of Config is not
	// valid.
	ErrBadConfig = errors.New("daemon: bad Config")
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
	// ConfigPath is the path of the stored configuration (see
	// configstore). Run loads it at start, and Apply replaces it. The
	// retain of the first configuration that the daemon gets is fixed
	// for the life of the daemon. It must be absolute and clean.
	ConfigPath string
	// ConfigGID is the group that Apply gives the stored configuration:
	// the group of ifbound-dns (layout.Group), so that ifbound-dns can
	// read it. Zero is not valid: the group of ifbound-dns is never
	// wheel, so a zero is a field that the caller did not set. A
	// negative value keeps the group of the new file, for tests.
	ConfigGID int
	// Snapshot is the path of the address book snapshot.
	Snapshot string
	// HostsFile is the path of the host file. Empty means the host file
	// of layout.Default.
	HostsFile string
	// Platform converges the platform state. All its fields are required.
	Platform reconcile.Reconciler
	// Lookup sends the probe names and the warm-up names through the
	// system resolver. It is required.
	Lookup SystemResolver
	// Accounts looks up the ids of the users and groups of each scope.
	// Nil means no reader: the daemon knows no account, so each scoped
	// policy loses its scope and applies to all traffic (fail closed),
	// and the state is StateDegraded.
	Accounts AccountReader
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
	// status is the Status that the loop published last. The loop
	// publishes after each request and at the end of each pass, so
	// Status never waits for the loop.
	status atomic.Pointer[Status]
	// store is configstore.Store. A test can replace it before Run.
	store storeFunc

	// probes are the probe names that a probe waits for. The probe
	// reports do not go through the loop: a probe report must never wait
	// for anything.
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
	d := &Daemon{
		cfg:      cfg,
		store:    configstore.Store,
		requests: make(chan request),
		done:     make(chan struct{}),
		probes:   make(map[string]*probeWait),
	}
	d.status.Store(&Status{State: StateStarting, Reasons: []string{reasonNotLoaded}})
	return d
}

// check returns an error that wraps ErrBadConfig when a field of c is
// not valid.
func (c Config) check() error {
	switch {
	case !filepath.IsAbs(c.ConfigPath) || filepath.Clean(c.ConfigPath) != c.ConfigPath:
		return fmt.Errorf("%w: ConfigPath %q is not an absolute clean path", ErrBadConfig, c.ConfigPath)
	case c.ConfigGID == 0:
		return fmt.Errorf("%w: ConfigGID is zero", ErrBadConfig)
	default:
		return nil
	}
}

// Run is the event loop. It loads the stored configuration and the
// snapshot, converges, and then serves events until ctx ends. It returns
// nil when ctx ends, ErrAlreadyRunning when called a second time, and
// an error that wraps ErrBadConfig when a field of Config is not valid.
//
// A stored configuration that does not load, such as a missing or a
// damaged file, puts the daemon in StateUnenforced with the load error
// as the reason. The daemon then converges nothing, so it keeps the
// platform state that it finds, and it acknowledges no report. It does
// not read the file again: only Apply gives it a configuration. A stored
// configuration that fails policy.Config.CheckUpstreams still applies;
// the failure makes the state StateDegraded.
//
// A snapshot that does not load keeps the daemon in StateStarting. A
// snapshot without an address of a configured policy, such as a missing
// file, makes the daemon adopt the learned-looking kernel entries and
// save them before it leaves StateStarting. The self-heal timer retries
// the load and the convergence until both succeed.
//
// Each convergence first checks the modification time and the size of
// the host file, and reads it again when they changed. While the file
// has an entry for a name that matches a policy, the table of the policy
// holds the address of the entry; when the entry goes away, the next
// convergence removes the address. A missing file has no entries. A
// file that exists but cannot be read keeps the addresses of the last
// good read and makes the state StateDegraded until a read succeeds. A
// change takes effect at the next convergence, so for up to
// SelfHealInterval a new host entry is not blocked.
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
//
// Run reads the users and groups that the scopes name through
// Config.Accounts after the first convergence, after each configuration
// change, and at each self-heal. So a changed id takes up to
// SelfHealInterval and the time of one read to apply. The read runs
// outside the loop, and at most one read is in work. When it ends, a
// convergence applies a changed snapshot. The first convergence uses no
// accounts, so each scope is dropped until the first read ends. A name
// that the host does not know drops the scope of its policy, so that
// policy applies to all traffic. A name whose lookup fails keeps the id
// of its last good lookup; without one, its scope is dropped. Each of
// these makes the state StateDegraded, and so does a read that takes
// longer than AccountReadTimeout. Run does not wait for a lookup that
// hangs: the lookup goes on after Run returns, until its system call
// returns, and its result is dropped.
//
// The probes of the warm-up are also the self-test of ifbound-dns. Under
// each configuration, the state is StateDegraded with the reason
// "ifbound-dns not connected" until a probe reaches ifbound-dns. The
// warm-up tries the names again after SelfHealInterval. The first probe
// that reaches ifbound-dns removes the reason until the configuration
// changes. A configuration without names has no warm-up, so it has no
// self-test and no reason.
func (d *Daemon) Run(ctx context.Context) error {
	if err := d.cfg.check(); err != nil {
		return err
	}
	if !d.started.CompareAndSwap(false, true) {
		return ErrAlreadyRunning
	}
	warm := newWarmUp(d.cfg.Lookup, d.probe, d.cfg.Logger)
	// The warm-up ends with ctx. Run waits for its lookups after done
	// closes: a lookup can wait for its report, and that report then
	// ends with ErrStopped.
	defer warm.wait()
	defer close(d.done)

	l := newLoop(d.cfg, d.store, &d.status)
	l.loadStored(ctx)
	heal := time.NewTicker(SelfHealInterval)
	defer heal.Stop()
	expiry := time.NewTimer(0) // armExpiry sets it before the first select
	defer expiry.Stop()
	var debounce <-chan time.Time
	changes := d.cfg.Platform.Inventory.Changes()

	_ = l.reconcile(ctx, "start") //nolint:errcheck // the phase holds the outcome
	l.readAccounts(ctx)
	for {
		l.armExpiry(expiry)
		warm.sync(ctx, l)
		l.publish()
		select {
		case <-ctx.Done():
			return nil
		case req := <-d.requests:
			req(ctx, l)
			if l.recheck {
				l.recheck = false
				_ = l.reconcile(ctx, "ruleset changed") //nolint:errcheck // the phase holds the outcome
			}
		case <-changes:
			if debounce == nil {
				debounce = time.After(InterfaceDebounce)
			}
		case <-debounce:
			debounce = nil
			_ = l.reconcile(ctx, "interfaces") //nolint:errcheck // the phase holds the outcome
		case <-heal.C:
			l.readAccounts(ctx)
			_ = l.reconcile(ctx, "self-heal") //nolint:errcheck // the phase holds the outcome
		case <-expiry.C:
			l.expire(ctx)
		case r := <-l.accounts.results:
			if l.applyAccounts(ctx, r) {
				_ = l.reconcile(ctx, "accounts") //nolint:errcheck // the phase holds the outcome
			}
		case <-l.accounts.timeout:
			l.accountsOverdue(ctx)
			_ = l.reconcile(ctx, "accounts") //nolint:errcheck // the phase holds the outcome
		case <-warm.results:
			if l.selfTestResult(warm.result()) {
				_ = l.reconcile(ctx, "self-test") //nolint:errcheck // the phase holds the outcome
			}
		}
	}
}

// Observe implements ipc.Handler. It returns a nil error, the
// acknowledgement, only when every address is in the table of each
// matching policy, in the saved snapshot, and the installed ruleset is
// still loaded. The ack is protected when the name matches at least one
// policy. A name that matches no policy is acknowledged as not protected
// and not stored. It returns ErrNotReady in StateStarting, ErrUnenforced
// when enforcement is not installed, an error that wraps
// matcher.ErrMalformedName for a name that cannot be classified, and the
// platform error otherwise. See call for ctx.Err() and ErrStopped.
func (d *Daemon) Observe(ctx context.Context, o ipc.Observation) (ipc.Ack, error) {
	type result struct {
		ack ipc.Ack
		err error
	}
	r, cerr := call(ctx, d, func(ctx context.Context, l *loop) result {
		ack, err := l.observe(ctx, o)
		return result{ack, err}
	})
	if cerr != nil {
		return ipc.Ack{}, cerr
	}
	return r.ack, r.err
}

// Apply checks, stores, and applies the configuration in data. It runs
// configstore.Store on Config.ConfigPath, and then converges. The new
// configuration applies also when the convergence fails: the daemon then
// acknowledges no report until a convergence succeeds, and the self-heal
// timer retries it. A new retain applies only after a restart; see
// Status.RetainRestart.
//
// Apply returns the status after the convergence, with the digest of the
// stored file. A failed convergence does not make an error: the status
// tells the outcome. Status shows the new digest from the rename of the
// stored file, also while the convergence runs.
//
// A refused data, such as one that fails policy.Parse or
// policy.Config.CheckUpstreams, and a failed store change nothing: not
// the stored file, not the running configuration. The error then comes
// from configstore.Store, and an invalid data wraps a
// *policy.FieldError. Apply does not start the store after ctx ends: the
// error then wraps ctx.Err(). See call for ErrStopped. An error that
// wraps configstore.ErrNotDurable comes with the status of the applied
// configuration: the new file is in place, but a crash can bring back
// the old one.
//
// The store runs on the loop, so reports wait for it. This serializes
// each Apply with the configuration that runs.
func (d *Daemon) Apply(ctx context.Context, data []byte) (Status, error) {
	type result struct {
		st  Status
		err error
	}
	r, cerr := call(ctx, d, func(loopCtx context.Context, l *loop) result {
		st, err := l.apply(loopCtx, ctx, data)
		return result{st, err}
	})
	if cerr != nil {
		return Status{}, cerr
	}
	return r.st, r.err
}

// Status returns a copy of the daemon state that the loop published
// last. It does not wait for the loop, so it answers also during a slow
// convergence. The copy is never older than the last request that
// returned, and than the last loop pass that ended. Before Run starts,
// it is the status of StateStarting. It returns ErrStopped when Run has
// returned. ctx is not used: Status does not block.
func (d *Daemon) Status(context.Context) (Status, error) {
	select {
	case <-d.done:
		return Status{}, ErrStopped
	default:
	}
	st := *d.status.Load()
	st.Reasons = slices.Clone(st.Reasons)
	st.Warnings = slices.Clone(st.Warnings)
	return st, nil
}

// call runs f on the loop goroutine and returns its result. The loop
// publishes its status before the reply, so a Status call after call
// returns sees the effect of f. Its error is
// ctx.Err() when ctx ends before the loop takes the request, and
// ErrStopped when Run has returned; f then did not run. Once the loop
// takes the request, call waits for the result and ignores ctx, so the
// caller always learns the outcome of what ran. The wait is bounded: the
// platform calls that f makes finish in bounded time.
func call[R any](ctx context.Context, d *Daemon, f func(context.Context, *loop) R) (R, error) {
	reply := make(chan R, 1)
	req := func(loopCtx context.Context, l *loop) {
		r := f(loopCtx, l)
		l.publish()
		reply <- r
	}
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
