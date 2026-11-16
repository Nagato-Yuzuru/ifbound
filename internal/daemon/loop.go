package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync/atomic"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/configstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/daemon/core"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// errNoConfig is the error of a convergence while the daemon has no
// configuration.
var errNoConfig = errors.New("daemon: no configuration")

// storeFunc stores a configuration as configstore.Store does.
type storeFunc func(path string, data []byte, gid int) (policy.Config, configstore.Digest, error)

// loop is the state that only the Run goroutine touches.
type loop struct {
	rec reconcile.Reconciler
	// addrStore is the path of the address book, and snapshot the path
	// of the JSON snapshot that each open of the book merges.
	addrStore string
	snapshot  string
	openBook  openBookFunc
	// book is the open address book. It is not nil exactly while core
	// is core.BookAdopting or core.BookLoaded. facts are the latest facts
	// that it sent.
	book     addrBook
	facts    addrstore.BookFacts
	store    string // the path of the stored configuration
	storeGID int
	storeFn  storeFunc
	log      *slog.Logger
	// pub receives the status that Daemon.Status returns.
	pub *atomic.Pointer[Status]

	// core is the state that core.Step decides on. Only drive changes it.
	core core.State
	// gate is core.GateOf(core) after the last Step.
	gate core.Gate
	// logged is the phase of the last state changed event, or of the
	// start.
	logged core.Phase
	// hostsReader reads the host file. mapped is the last mapping of a
	// good read of it.
	hostsReader HostsReader
	mapped      mappedHosts
	// accountReader is nil when there is no reader: the account
	// snapshot then stays zero.
	accountReader AccountReader
	// accountResults receives the result of the account read in flight.
	// It has room for one result, and core starts at most one read at a
	// time.
	accountResults chan core.AccountsRead

	// pending is the trigger of the convergence that Run starts after the
	// current request or event, or "" when there is none. A Converge
	// effect of core sets it. A second trigger before the pass does not
	// replace the first. Each pass clears it (see converge).
	pending string
	// reportFailed is true after a report failure that core got, until a
	// report succeeds. Only then does a success go to core.
	reportFailed bool

	// failed is the error.type and the error text of the last
	// convergence, or "" when it succeeded. A failure that repeats is
	// logged at debug.
	failed string
}

func newLoop(c Config, store storeFunc, openBook openBookFunc, pub *atomic.Pointer[Status]) *loop {
	s := core.New(time.Now(), c.Accounts != nil)
	return &loop{
		rec:       c.Platform,
		addrStore: c.AddrStore,
		snapshot:  c.Snapshot,
		openBook:  openBook,
		store:     c.ConfigPath,
		storeGID:  c.ConfigGID,
		storeFn:   store,
		log:       c.Logger,
		pub:       pub,
		core:      s,
		gate:      core.GateOf(s),
		logged:    core.PhaseOf(s),

		hostsReader:    c.Hosts,
		accountReader:  c.Accounts,
		accountResults: make(chan core.AccountsRead, 1),
	}
}

// publish makes the current status the one that Daemon.Status returns,
// and logs a change of the phase.
func (l *loop) publish(ctx context.Context) {
	l.notePhase(ctx)
	st := statusOf(l.core)
	l.pub.Store(&st)
}

// notePhase logs a change of the phase since the last call. The loop
// calls it where a step of the daemon ends: at the end of each pass, and
// at each publish. A phase between them is not logged.
func (l *loop) notePhase(ctx context.Context) {
	p := core.PhaseOf(l.core)
	old := l.logged
	if p.Lifecycle == old.Lifecycle && p.Installed == old.Installed && slices.Equal(p.Reasons, old.Reasons) {
		return
	}
	l.logged = p
	level := slog.LevelWarn
	if p.Lifecycle == StateReady {
		level = slog.LevelInfo
	}
	l.log.LogAttrs(ctx, level, "state changed",
		slog.String(logattr.EnforcementState, p.Lifecycle.String()), slog.Any(logattr.EnforcementReasons, p.Reasons))
}

// loadStored loads the stored configuration at start. A configuration
// that does not load leaves the daemon without one: it then keeps the
// platform state that it finds and acknowledges nothing, until Apply
// gives it a configuration. It does not try the load again: only Apply
// changes the stored file.
func (l *loop) loadStored(ctx context.Context) {
	cfg, digest, err := configstore.Load(l.store)
	l.drive(ctx, core.ConfigRead{At: time.Now(), Config: cfg, Digest: digest, Err: err})
}

// active returns the active configuration. It reports false when the
// daemon has no configuration.
func (l *loop) active() (core.Active, bool) {
	c, ok := l.core.Config().(core.Configured)
	return c.Active, ok
}

// policies returns the policies of the active configuration. It
// returns nil when the daemon has no configuration.
func (l *loop) policies() []policy.Policy {
	a, _ := l.active()
	return a.Config.Policies
}

// converge is the one path to the desired state. While the address book
// is not loaded, the convergence is add-only (see
// reconcile.Inputs.AddOnly) with no learned address: the ruleset, the IP
// and CIDR destinations, and the host addresses need no book, but a
// removal would unblock every learned address. Without a configuration,
// it does nothing.
//
// The PassStarted drive reads the host file and loads the book first:
// adoption must know which kernel entries are host addresses.
//
// A pass covers each pending convergence: it converges the whole desired
// state from the inputs that it reads, and the trigger only names the
// cause in the log. A Converge of core is pending only when its change is
// in core, and the PassStarted drive is the last change to core before
// Converge, so the pass clears the pending trigger after it.
//
// Each pass that it starts writes one convergence event (see
// logConverge), and one more event when it ended pf states.
func (l *loop) converge(ctx context.Context, trigger string) error {
	if _, ok := l.core.Config().(core.Configured); !ok {
		l.pending = ""
		return errNoConfig
	}
	began := time.Now()
	l.drive(ctx, core.PassStarted{At: began})
	l.pending = ""
	// A drive never takes the configuration away. The book state is the
	// one of the pass. Only a loaded book is a source: before its
	// adoption and its first expire, the book can hold entries that
	// expired while the daemon was down.
	c, _ := l.core.Config().(core.Configured)
	var src reconcile.AddrSource = emptyBook{}
	_, loaded := c.Book.(core.BookLoaded)
	if loaded {
		src = l.book
	}
	rep, epoch, err := l.rec.Converge(ctx, reconcile.Inputs{
		Policies: c.Active.Config.Policies,
		Book:     src,
		Hosts:    l.hostAddrs(ctx, c.Active),
		Apexes:   c.Active.Apexes,
		Listen:   c.Active.Config.DNS.Listen,
		Accounts: l.core.AccountIDs(),
		AddOnly:  !loaded,
	})
	l.drive(ctx, core.Converged{At: time.Now(), Report: rep, Err: err, Epoch: epoch})
	l.logStatesEnded(ctx, logattr.StatesCauseNarrowed, rep.Narrowed)
	l.notePhase(ctx)
	errType := logattr.ErrorTypePlatform
	if bookErr := bookError(c.Book); bookErr != nil {
		if err == nil {
			errType = logattr.ErrorTypeSnapshot
		}
		err = errors.Join(bookErr, err)
	}
	l.logConverge(ctx, trigger, time.Since(began), rep, errType, err)
	return err
}

// logConverge writes the event of one convergence pass, after the pass
// set the phase. A failure is a warning when it starts or changes, and
// debug while the same failure repeats: the self-heal starts one pass
// every SelfHealInterval, and the state changed event shows the
// recovery. A pass that wrote to the kernel is info, and a pass that
// found nothing to do is debug. errType is the error.type of a non-nil
// err.
func (l *loop) logConverge(ctx context.Context, trigger string, took time.Duration, rep reconcile.Report, errType string, err error) {
	attrs := []slog.Attr{
		slog.String(logattr.ConvergeTrigger, trigger),
		slog.Int(logattr.ConvergeWrites, rep.Writes),
		slog.Int64(logattr.ConvergeDurationMS, took.Milliseconds()),
		slog.String(logattr.EnforcementState, core.PhaseOf(l.core).Lifecycle.String()),
	}
	level := slog.LevelDebug
	failed := ""
	switch {
	case err != nil:
		failed = errType + ": " + err.Error()
		if failed != l.failed {
			level = slog.LevelWarn
		}
		attrs = append(attrs, slog.String(logattr.ErrorType, errType), slog.String(logattr.ExceptionMessage, err.Error()))
	case rep.Writes > 0:
		level = slog.LevelInfo
	}
	l.failed = failed
	l.log.LogAttrs(ctx, level, "convergence", attrs...)
}

// logStatesEnded writes one event for the policies whose pf connection
// states a convergence ended for cause. It writes nothing when policies
// is empty. An end of states cannot be undone, so the event is info.
func (l *loop) logStatesEnded(ctx context.Context, cause string, policies []policy.Name) {
	if len(policies) == 0 {
		return
	}
	names := make([]string, len(policies))
	for i, p := range policies {
		names[i] = string(p)
	}
	l.log.LogAttrs(ctx, slog.LevelInfo, "pf states ended",
		slog.String(logattr.StatesCause, cause), slog.Any(logattr.PolicyNames, names))
}

// reconfigure applies cfg. Until a convergence installs the ruleset of
// cfg, the phase acknowledges nothing. It publishes this phase with the
// new digest before the convergence, so that Status tells the
// configuration of the stored file also while the convergence runs. The
// book keeps the entries of removed policies until then; the
// convergence prunes them.
func (l *loop) reconfigure(ctx context.Context, cfg policy.Config, digest configstore.Digest) error {
	l.drive(ctx, core.ConfigRead{At: time.Now(), Config: cfg, Digest: digest})
	l.publish(ctx)
	return l.converge(ctx, l.pending)
}

// apply stores data and then reconfigures. It does not start the store
// after caller ends. configstore.Store has no step between its
// temporary file and its rename for the check, so the check runs just
// before the store. A refused or failed store changes nothing and
// returns a zero Status. A store whose directory sync failed is in
// place, so it applies, and its error wraps configstore.ErrNotDurable.
// Each call writes one apply event.
func (l *loop) apply(ctx, caller context.Context, data []byte) (Status, error) {
	before, hadConfig := l.active()
	previous := before.Digest
	if err := caller.Err(); err != nil {
		err = fmt.Errorf("apply not started: %w", err)
		l.logApply(ctx, previous, hadConfig, logattr.ErrorTypeCanceled, err)
		return Status{}, err
	}
	cfg, digest, err := l.storeFn(l.store, data, l.storeGID)
	if err != nil && !errors.Is(err, configstore.ErrNotDurable) {
		l.logApply(ctx, previous, hadConfig, storeErrType(err), err)
		return Status{}, err
	}
	_ = l.reconfigure(ctx, cfg, digest) //nolint:errcheck // the phase holds the outcome, and Status reports it
	l.logApply(ctx, previous, hadConfig, logattr.ErrorTypeConfigNotDurable, err)
	return statusOf(l.core), err
}

// storeErrType returns the error.type of an error of configstore.Store
// that changed nothing.
func storeErrType(err error) string {
	if _, ok := errors.AsType[*policy.FieldError](err); ok {
		return logattr.ErrorTypeConfigInvalid
	}
	return logattr.ErrorTypeConfigFile
}

// logApply writes the event of one Apply. The digest is the one of the
// configuration that runs after the Apply: after a refused store, it is
// the one that still runs. previous is the digest of the configuration
// that ran before, when hadConfig. errType is the error.type of a non-nil
// err. A caller that left before the start is info: nothing is degraded.
func (l *loop) logApply(ctx context.Context, previous configstore.Digest, hadConfig bool, errType string, err error) {
	attrs := []slog.Attr{slog.String(logattr.EnforcementState, core.PhaseOf(l.core).Lifecycle.String())}
	if a, ok := l.active(); ok {
		attrs = append(attrs, slog.String(logattr.ConfigDigest, a.Digest.String()))
	}
	if hadConfig {
		attrs = append(attrs, slog.String(logattr.ConfigPreviousDigest, previous.String()))
	}
	level := slog.LevelInfo
	if err != nil {
		if errType != logattr.ErrorTypeCanceled {
			level = slog.LevelWarn
		}
		attrs = append(attrs, slog.String(logattr.ErrorType, errType), slog.String(logattr.ExceptionMessage, err.Error()))
	}
	l.log.LogAttrs(ctx, level, "apply", attrs...)
}

// observe handles one DNS report. The report is untrusted: only the
// policies that match its name get its addresses.
//
// A name that matches no policy gets an unprotected ack, with no check.
// For a name that matches a policy, the order is: record the addresses,
// check that the installed ruleset is loaded, and only then ack as
// protected. A report without an address skips record but not the check.
// The check costs one LoadedID read per report that matches a policy.
// ifbound-dns removes the aliases from the reply when the ack is
// protected.
func (l *loop) observe(ctx context.Context, o ipc.Observation) (ipc.Ack, error) {
	if c, ok := l.gate.State.(core.Closed); ok {
		return ipc.Ack{}, c.Err
	}
	names, err := l.gate.Matcher.Match(o.QName)
	if err != nil {
		return ipc.Ack{}, fmt.Errorf("classifying qname: %w", err)
	}
	if len(names) == 0 {
		return ipc.Ack{}, nil
	}
	if len(o.Addrs) > 0 {
		if err := l.record(ctx, names, o); err != nil {
			return ipc.Ack{}, err
		}
	}
	if err := l.checkInstalled(ctx); err != nil {
		return ipc.Ack{}, err
	}
	if l.reportFailed {
		l.reportFailed = false
		l.drive(ctx, core.ReportSucceeded{At: time.Now()})
	}
	return ipc.Ack{Protected: true}, nil
}

// reportFailure gives a failure of the report path to core, and returns
// err.
func (l *loop) reportFailure(ctx context.Context, step reconcile.ReportStep, err error) error {
	l.reportFailed = true
	l.drive(ctx, core.ReportFailed{At: time.Now(), Step: step, Err: err})
	return err
}

// record puts the addresses of o in the tables and the book of each
// policy in names, in this order. It skips the addresses that
// blockable.New refuses, so the book does not keep them either. The same
// slice goes to the book and to the tables, so a table entry and its
// book key cannot differ. An address is in the book only after its
// commit: after a failure, the book does not have the new addresses, and
// the report is not acknowledged. The gate is open, so the loop holds
// the book.
func (l *loop) record(ctx context.Context, names []policy.Name, o ipc.Observation) error {
	addrs := blockable.Filter(o.Addrs)
	p, err := l.book.Touch(names, addrs, o.TTL, time.Now())
	if err != nil {
		return fmt.Errorf("recording addresses: %w", err)
	}
	err = l.rec.Guard.Shared(func(a reconcile.Adder) error {
		for _, name := range names {
			if err := reconcile.AddObserved(ctx, a, name, addrs); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return l.reportFailure(ctx, reconcile.StepTableAdd, err)
	}
	if err := l.book.Commit(ctx, p); err != nil {
		return l.reportFailure(ctx, reconcile.StepCommit, fmt.Errorf("saving the address book: %w", err))
	}
	if !p.Empty() {
		l.drive(ctx, core.BookChanged{At: time.Now(), Facts: l.latestFacts()})
	}
	return nil
}

// checkInstalled returns nil when the Backend has the installed ruleset
// of the gate loaded. It reads the gate after the read of the Backend,
// so it never trusts an older gate. When the gate is closed, it returns
// the error of the gate. When another ruleset is loaded, something
// outside ifbound changed it: the phase then stops acknowledging, Run
// converges right after this request, and it returns ErrUnenforced.
func (l *loop) checkInstalled(ctx context.Context) error {
	var id string
	err := l.rec.Guard.Shared(func(a reconcile.Adder) (err error) {
		id, err = a.LoadedID(ctx)
		return err
	})
	if err != nil {
		return l.reportFailure(ctx, reconcile.StepLoadedID, fmt.Errorf("reading the loaded ruleset: %w", err))
	}
	switch g := l.gate.State.(type) {
	case core.Closed:
		return g.Err
	case core.Open:
		if id != g.Installed {
			return l.reportFailure(ctx, reconcile.StepRuleset, ErrUnenforced)
		}
		return nil
	default:
		panic(fmt.Sprintf("daemon: unknown gate state %T", g))
	}
}
