package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrbook"
	"github.com/Nagato-Yuzuru/ifbound/internal/configstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// errNoConfig is the error of a convergence while the daemon has no
// configuration.
var errNoConfig = errors.New("daemon: no configuration")

// reasonNotLoaded is the reason of StateStarting before the first load of
// the snapshot.
const reasonNotLoaded = "the snapshot is not loaded yet"

// storeFunc stores a configuration as configstore.Store does.
type storeFunc func(path string, data []byte, gid int) (policy.Config, configstore.Digest, error)

// selfTest is the state of the self-test for one configuration.
type selfTest uint8

const (
	// selfTestNone: the configuration lists no name, so no query goes
	// to ifbound-dns, and there is nothing to test.
	selfTestNone selfTest = iota
	// selfTestNotRun: no warm-up pass under the configuration has ended,
	// and no probe reached ifbound-dns.
	selfTestNotRun
	// selfTestFailed: a warm-up pass ended, and no probe reached
	// ifbound-dns.
	selfTestFailed
	// selfTestPassed: a probe reached ifbound-dns under the
	// configuration.
	selfTestPassed
)

// loop is the state that only the Run goroutine touches.
type loop struct {
	rec      reconcile.Reconciler
	snapshot string
	store    string // the path of the stored configuration
	storeGID int
	storeFn  storeFunc
	log      *slog.Logger
	// pub receives the status that Daemon.Status returns.
	pub *atomic.Pointer[Status]

	// mode is the lifecycle of the daemon.
	mode mode

	// selfTest is the self-test of the running configuration. A new
	// configuration resets it.
	selfTest selfTest

	hosts    hostsState
	accounts accountsState

	// recheck asks Run for a convergence after the current request. A
	// report sets it when it finds a loaded ruleset that is not the
	// installed one.
	recheck bool
}

func newLoop(c Config, store storeFunc, pub *atomic.Pointer[Status]) *loop {
	l := &loop{
		rec:      c.Platform,
		snapshot: c.Snapshot,
		store:    c.ConfigPath,
		storeGID: c.ConfigGID,
		storeFn:  store,
		log:      c.Logger,
		pub:      pub,
		mode:     unconfiguredMode{phase: startingPhase(reasonNotLoaded)},
		hosts:    hostsState{reader: c.Hosts},
		accounts: newAccountsState(c.Accounts),
	}
	return l
}

// publish makes the current status the one that Daemon.Status returns.
func (l *loop) publish() {
	st := l.status()
	l.pub.Store(&st)
}

// loadStored loads the stored configuration at start. A configuration
// that does not load leaves the daemon without one: it then keeps the
// platform state that it finds and acknowledges nothing, until Apply
// gives it a configuration. It does not try the load again: only Apply
// changes the stored file.
func (l *loop) loadStored(ctx context.Context) {
	cfg, digest, err := configstore.Load(l.store)
	if err != nil {
		l.setPhase(ctx, unconfiguredPhase("the stored configuration did not load: "+err.Error()))
		return
	}
	l.setConfig(cfg, digest)
}

// setConfig makes cfg the running configuration. digest is the digest of
// its stored file, or zero when it is not stored. The phase does not
// change. A daemon without a configuration goes to loadingMode. The
// first configuration fixes the retain. A runningMode keeps its book: the
// book keeps the entries of removed policies until reconcile prunes them.
func (l *loop) setConfig(cfg policy.Config, digest configstore.Digest) {
	switch m := l.mode.(type) {
	case unconfiguredMode:
		l.mode = loadingMode{run: newRunning(cfg, digest, 1, cfg.AddrBook.Retain), phase: m.phase}
	case loadingMode:
		l.mode = loadingMode{run: newRunning(cfg, digest, m.run.gen+1, m.run.retain), phase: m.phase}
	case runningMode:
		l.mode = runningMode{run: newRunning(cfg, digest, m.run.gen+1, m.run.retain), book: m.book, phase: m.phase}
	}
	l.selfTest = selfTestNone
	if len(warmUpNames(cfg)) > 0 {
		l.selfTest = selfTestNotRun
	}
}

// policies returns the policies of the running configuration. It
// returns nil when the daemon has no configuration.
func (l *loop) policies() []policy.Policy {
	switch m := l.mode.(type) {
	case unconfiguredMode:
		return nil
	case loadingMode:
		return m.run.cfg.Policies
	case runningMode:
		return m.run.cfg.Policies
	}
	return nil
}

func policyNames(cfg policy.Config) []policy.Name {
	names := make([]policy.Name, len(cfg.Policies))
	for i, p := range cfg.Policies {
		names[i] = p.Name
	}
	return names
}

// reconcile is the one path to the desired state. It never converges
// before the snapshot is loaded: an empty book would remove every learned
// address.
//
// The host file comes first: adoption must know which kernel entries are
// host addresses. Without a configuration, it does nothing.
func (l *loop) reconcile(ctx context.Context, trigger string) error {
	var (
		run  running
		book *addrbook.AddrBook
	)
	switch m := l.mode.(type) {
	case unconfiguredMode:
		return errNoConfig
	case loadingMode:
		run = m.run
		l.refreshHosts(ctx, run)
		b, err := l.loadBook(ctx, run)
		if err != nil {
			l.setPhase(ctx, startingPhase(err.Error()))
			return err
		}
		book = b
	case runningMode:
		run, book = m.run, m.book
		l.refreshHosts(ctx, run)
	}
	rep, err := l.rec.Converge(ctx, reconcile.Inputs{
		Policies: run.cfg.Policies,
		Book:     book,
		Hosts:    l.hosts.addrs,
		Apexes:   run.apexes,
		Listen:   run.cfg.DNS.Listen,
		Accounts: l.accounts.snap,
	})
	if rep.Installed != "" {
		// No loaded rule refers to a removed policy now, and its table is
		// gone. Until this point a revert of the configuration must still
		// find its addresses.
		book.Prune(policyNames(run.cfg))
	}
	if rep.Writes > 0 {
		l.log.InfoContext(ctx, "enforcement changed",
			slog.String("trigger", trigger), slog.Int("writes", rep.Writes), slog.Bool("complete", err == nil))
	}
	if p, ok := l.hosts.problem(); ok {
		rep.Problems = append(rep.Problems, p)
	}
	if p, ok := l.accountsProblem(); ok {
		rep.Problems = append(rep.Problems, p)
	}
	if run.upstream != nil {
		// Only the stored file at start can fail the check: Apply refuses
		// such a configuration. The check protects only DNS, so the
		// daemon enforces the file.
		rep.Problems = append(rep.Problems, reconcile.Problem{Text: "the configuration fails the upstream check: " + run.upstream.Error()})
	}
	p := convergedPhase(rep, err)
	if st, ok := l.selfTestProblem(); ok && p.acks() {
		// The warm-up, and so the self-test, runs only while the phase
		// acks. In another phase the reason would only repeat that.
		rep.Problems = append(rep.Problems, st)
		p = convergedPhase(rep, err)
	}
	// The book is loaded, so the daemon runs from now on, also when the
	// convergence failed.
	l.setMode(ctx, runningMode{run: run, book: book, phase: p})
	return err
}

// loadBook builds a book from the snapshot. A snapshot without addresses
// of the configured policies (most often a missing file) makes it adopt
// the learned-looking entries of the kernel tables and save them first:
// a lost snapshot then keeps addresses blocked for one retain period
// instead of unblocking them.
//
// The trigger looks at the configured policies only, so it also adopts
// when the snapshot holds addresses only of policies that the
// configuration removed. Adoption reads every table, also the table of a
// removed policy: its removal may not be installed yet, and a revert must
// find its addresses. reconcile prunes them after the install. This is broader than "the snapshot is empty", and it fails
// closed: adoption adds entries that the tables already hold, and each
// one expires after one retain period. After a good read of the host
// file, its addresses are not adopted: they leave the tables with their
// host entries. Before a good read, they are adopted. Entries that expired while the
// daemon was down leave the book here.
func (l *loop) loadBook(ctx context.Context, run running) (*addrbook.AddrBook, error) {
	book := addrbook.New(run.retain, time.Now)
	if err := book.Load(l.snapshot); err != nil {
		return nil, fmt.Errorf("loading snapshot: %w", err)
	}
	if !slices.ContainsFunc(policyNames(run.cfg), func(n policy.Name) bool { return len(book.Addrs(n)) > 0 }) {
		if err := l.adopt(ctx, book, run.cfg.Policies); err != nil {
			return nil, err
		}
	}
	book.Expire()
	return book, nil
}

func (l *loop) adopt(ctx context.Context, book *addrbook.AddrBook, policies []policy.Policy) error {
	found, err := l.rec.Adoptable(ctx, policies)
	if err != nil {
		return fmt.Errorf("adopting kernel entries: %w", err)
	}
	if len(found) == 0 {
		return nil
	}
	for name, addrs := range found {
		if l.hosts.read {
			// The host file is their source of truth, not the snapshot.
			hosts := l.hosts.addrs[name] // sorted
			addrs = slices.DeleteFunc(addrs, func(a netip.Addr) bool {
				_, found := slices.BinarySearchFunc(hosts, a, netip.Addr.Compare)
				return found
			})
		}
		if len(addrs) == 0 {
			continue
		}
		// TTL 0: the entry gets a fresh retain period.
		if _, err := book.Observe(name, addrs, 0); err != nil {
			return fmt.Errorf("adopting kernel entries: %w", err)
		}
	}
	if err := book.Save(l.snapshot); err != nil {
		return fmt.Errorf("saving adopted entries: %w", err)
	}
	return nil
}

// phase returns the phase of the current mode.
func (l *loop) phase() phase {
	switch m := l.mode.(type) {
	case unconfiguredMode:
		return m.phase
	case loadingMode:
		return m.phase
	case runningMode:
		return m.phase
	}
	return phase{}
}

// setPhase gives the current mode the phase p.
func (l *loop) setPhase(ctx context.Context, p phase) {
	switch m := l.mode.(type) {
	case unconfiguredMode:
		m.phase = p
		l.setMode(ctx, m)
	case loadingMode:
		m.phase = p
		l.setMode(ctx, m)
	case runningMode:
		m.phase = p
		l.setMode(ctx, m)
	}
}

// setMode makes m the current mode, and logs a change of the phase.
func (l *loop) setMode(ctx context.Context, m mode) {
	old := l.phase()
	l.mode = m
	p := l.phase()
	if p.state == old.state && p.installed == old.installed && slices.Equal(p.reasons, old.reasons) {
		return
	}
	level := slog.LevelWarn
	if p.state == StateReady {
		level = slog.LevelInfo
	}
	l.log.LogAttrs(ctx, level, "state changed",
		slog.String("state", p.state.String()), slog.Any("reasons", p.reasons))
}

func (l *loop) armExpiry(t *time.Timer) {
	m, ok := l.mode.(runningMode)
	if !ok {
		t.Stop()
		return
	}
	next, ok := m.book.NextExpiry()
	if !ok {
		t.Stop()
		return
	}
	t.Reset(time.Until(next))
}

func (l *loop) expire(ctx context.Context) {
	if m, ok := l.mode.(runningMode); ok && len(m.book.Expire()) > 0 {
		_ = l.reconcile(ctx, "expiry") //nolint:errcheck // the phase holds the outcome
	}
}

// reconfigure applies cfg. Until a convergence installs the ruleset of
// cfg, the phase acknowledges nothing. It publishes this phase with the
// new digest before the convergence, so that Status tells the
// configuration of the stored file also while the convergence runs. The
// book keeps the entries of removed policies until then; reconcile
// prunes them.
func (l *loop) reconfigure(ctx context.Context, cfg policy.Config, digest configstore.Digest) error {
	l.setConfig(cfg, digest)
	l.setPhase(ctx, unenforcedPhase("the new configuration is not installed yet"))
	l.publish()
	l.readAccounts(ctx)
	return l.reconcile(ctx, "config")
}

// apply stores data and then reconfigures. It does not start the store
// after caller ends. configstore.Store has no step between its
// temporary file and its rename for the check, so the check runs just
// before the store. A refused or failed store changes nothing and
// returns a zero Status. A store whose directory sync failed is in
// place, so it applies, and its error wraps configstore.ErrNotDurable.
func (l *loop) apply(ctx, caller context.Context, data []byte) (Status, error) {
	if err := caller.Err(); err != nil {
		return Status{}, fmt.Errorf("apply not started: %w", err)
	}
	cfg, digest, err := l.storeFn(l.store, data, l.storeGID)
	if err != nil && !errors.Is(err, configstore.ErrNotDurable) {
		return Status{}, err
	}
	if err != nil {
		l.log.WarnContext(ctx, "the applied configuration is not durable", slog.Any("error", err))
	}
	_ = l.reconfigure(ctx, cfg, digest) //nolint:errcheck // the phase holds the outcome, and Status reports it
	return l.status(), err
}

// selfTestResult takes the latest results of the warm-up. Only a result
// for the running configuration counts, and a pass is final for it. It
// reports whether the self-test changed.
func (l *loop) selfTestResult(r warmResult) bool {
	var gen uint64
	switch m := l.mode.(type) {
	case unconfiguredMode:
		return false
	case loadingMode:
		gen = m.run.gen
	case runningMode:
		gen = m.run.gen
	}
	before := l.selfTest
	switch {
	case l.selfTest == selfTestNone || l.selfTest == selfTestPassed:
	case r.proved == gen:
		l.selfTest = selfTestPassed
	case r.missed == gen:
		l.selfTest = selfTestFailed
	}
	return l.selfTest != before
}

// selfTestProblem returns the Problem of the self-test, if there is one.
// It does not void enforcement: without ifbound-dns, a protected name
// does not resolve.
func (l *loop) selfTestProblem() (reconcile.Problem, bool) {
	switch l.selfTest {
	case selfTestNotRun:
		return reconcile.Problem{Text: "ifbound-dns not connected: no probe reached it yet"}, true
	case selfTestFailed:
		return reconcile.Problem{Text: "ifbound-dns not connected: no probe reached it; the self-test tries again at each self-heal"}, true
	case selfTestNone, selfTestPassed:
		return reconcile.Problem{}, false
	default:
		return reconcile.Problem{Text: "unknown self-test state"}, true
	}
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
	m, isRunning := l.mode.(runningMode)
	switch {
	case l.phase().state == StateStarting:
		return ipc.Ack{}, ErrNotReady
	case !isRunning || !m.phase.acks():
		return ipc.Ack{}, ErrUnenforced
	}
	names, err := m.run.matcher.Match(o.QName)
	if err != nil {
		return ipc.Ack{}, fmt.Errorf("classifying qname: %w", err)
	}
	if len(names) == 0 {
		return ipc.Ack{}, nil
	}
	if len(o.Addrs) > 0 {
		if err := l.record(ctx, m.book, names, o); err != nil {
			return ipc.Ack{}, err
		}
	}
	if err := l.checkInstalled(ctx, m.phase.installed); err != nil {
		return ipc.Ack{}, err
	}
	return ipc.Ack{Protected: true}, nil
}

// record puts the addresses of o in the book, the tables, and the
// snapshot of each policy in names, in this order. After a failure, the
// book keeps the addresses. The next report or convergence completes the
// work.
func (l *loop) record(ctx context.Context, book *addrbook.AddrBook, names []policy.Name, o ipc.Observation) error {
	addrs := canonical(o.Addrs)
	needSave := false
	for _, name := range names {
		ns, err := book.Observe(name, addrs, o.TTL)
		if err != nil {
			return fmt.Errorf("recording addresses: %w", err)
		}
		needSave = needSave || ns
	}
	for _, name := range names {
		if err := l.rec.AddObserved(ctx, name, addrs); err != nil {
			return err
		}
	}
	if needSave {
		if err := book.Save(l.snapshot); err != nil {
			return fmt.Errorf("saving snapshot: %w", err)
		}
	}
	return nil
}

// checkInstalled returns nil when the Backend has the ruleset installed
// loaded. installed is the ruleset ID of the current phase. Otherwise
// something outside ifbound changed it. The phase then stops
// acknowledging, and Run converges right after this request. It returns
// ErrUnenforced in this case.
func (l *loop) checkInstalled(ctx context.Context, installed string) error {
	id, err := l.rec.Backend.LoadedID(ctx)
	if err != nil {
		return fmt.Errorf("reading the loaded ruleset: %w", err)
	}
	if id != installed {
		l.setPhase(ctx, unenforcedPhase("the loaded ruleset changed outside ifbound"))
		l.recheck = true
		return ErrUnenforced
	}
	return nil
}

// canonical returns the addresses in the form that the AddrBook keys
// them by: IPv4-mapped IPv6 unmapped. The same slice goes to the book and
// to the tables, so a table entry and its book key cannot differ.
func canonical(addrs []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, len(addrs))
	for i, a := range addrs {
		out[i] = a.Unmap()
	}
	return out
}

// status costs one map lookup per policy, so the loop can publish it at
// each pass.
func (l *loop) status() Status {
	p := l.phase()
	st := Status{State: p.state, Reasons: slices.Clone(p.reasons)}
	withRun := func(run running) {
		st.Policies = len(run.cfg.Policies)
		st.RetainRestart = run.cfg.AddrBook.Retain != run.retain
		st.Config = run.digest
		st.Warnings = slices.Clone(run.warnings)
	}
	switch m := l.mode.(type) {
	case unconfiguredMode:
	case loadingMode:
		withRun(m.run)
	case runningMode:
		withRun(m.run)
		for _, pol := range m.run.cfg.Policies {
			st.Addrs += m.book.Len(pol.Name)
		}
	}
	return st
}
