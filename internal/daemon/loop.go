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
	"github.com/Nagato-Yuzuru/ifbound/internal/layout"
	"github.com/Nagato-Yuzuru/ifbound/internal/matcher"
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
	// retain is the retain of every book. The first configuration fixes
	// it.
	retain time.Duration

	// book is nil until the first complete load of the snapshot. The
	// daemon never converges without it: an empty book would remove every
	// learned address.
	book *addrbook.AddrBook

	// configured is false until the daemon has a configuration. Until
	// then it does not converge.
	configured bool
	cfg        policy.Config
	digest     configstore.Digest
	matcher    *matcher.Matcher
	apexes     []policy.Domain
	// upstream is the error of the upstream check for cfg, or nil.
	upstream error
	warnings []policy.Warning
	// gen counts the configuration changes. A warm-up runs only under
	// the configuration that it started with.
	gen uint64

	// selfTest is the self-test of cfg.
	selfTest selfTest

	hosts    hostsState
	accounts accountsState

	phase phase
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
		phase:    startingPhase(reasonNotLoaded),
		hosts:    hostsState{path: c.HostsFile},
		accounts: newAccountsState(c.Accounts),
		matcher:  matcher.New(nil),
	}
	if l.hosts.path == "" {
		l.hosts.path = layout.Default().HostsFile
	}
	return l
}

// publish makes the current status the one that Daemon.Status returns.
func (l *loop) publish() {
	st := l.status()
	l.pub.Store(&st)
}

func (l *loop) newBook() *addrbook.AddrBook { return addrbook.New(l.retain, time.Now) }

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
// its stored file, or zero when it is not stored.
func (l *loop) setConfig(cfg policy.Config, digest configstore.Digest) {
	if !l.configured {
		l.configured = true
		l.retain = cfg.AddrBook.Retain
	}
	l.cfg, l.digest = cfg, digest
	l.gen++
	l.matcher = matcher.New(cfg.Policies)
	l.apexes = l.matcher.Apexes()
	l.upstream = cfg.CheckUpstreams()
	l.warnings = cfg.Warnings()
	l.selfTest = selfTestNone
	if len(warmUpNames(cfg)) > 0 {
		l.selfTest = selfTestNotRun
	}
}

func (l *loop) policyNames() []policy.Name {
	names := make([]policy.Name, len(l.cfg.Policies))
	for i, p := range l.cfg.Policies {
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
	if !l.configured {
		return errNoConfig
	}
	l.refreshHosts(ctx)
	if l.book == nil {
		book, err := l.loadBook(ctx)
		if err != nil {
			l.setPhase(ctx, startingPhase(err.Error()))
			return err
		}
		l.book = book
	}
	rep, err := l.rec.Converge(ctx, reconcile.Inputs{
		Policies: l.cfg.Policies,
		Book:     l.book,
		Hosts:    l.hosts.addrs,
		Apexes:   l.apexes,
		Listen:   l.cfg.DNS.Listen,
		Accounts: l.accounts.snap,
	})
	if rep.Installed != "" {
		// No loaded rule refers to a removed policy now, and its table is
		// gone. Until this point a revert of the configuration must still
		// find its addresses.
		l.book.Prune(l.policyNames())
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
	if l.upstream != nil {
		// Only the stored file at start can fail the check: Apply refuses
		// such a configuration. The check protects only DNS, so the
		// daemon enforces the file.
		rep.Problems = append(rep.Problems, reconcile.Problem{Text: "the configuration fails the upstream check: " + l.upstream.Error()})
	}
	p := convergedPhase(rep, err)
	if st, ok := l.selfTestProblem(); ok && p.acks() {
		// The warm-up, and so the self-test, runs only while the phase
		// acks. In another phase the reason would only repeat that.
		rep.Problems = append(rep.Problems, st)
		p = convergedPhase(rep, err)
	}
	l.setPhase(ctx, p)
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
func (l *loop) loadBook(ctx context.Context) (*addrbook.AddrBook, error) {
	book := l.newBook()
	if err := book.Load(l.snapshot); err != nil {
		return nil, fmt.Errorf("loading snapshot: %w", err)
	}
	if !slices.ContainsFunc(l.policyNames(), func(n policy.Name) bool { return len(book.Addrs(n)) > 0 }) {
		if err := l.adopt(ctx, book); err != nil {
			return nil, err
		}
	}
	book.Expire()
	return book, nil
}

func (l *loop) adopt(ctx context.Context, book *addrbook.AddrBook) error {
	found, err := l.rec.Adoptable(ctx, l.cfg.Policies)
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

func (l *loop) setPhase(ctx context.Context, p phase) {
	if p.state == l.phase.state && p.installed == l.phase.installed && slices.Equal(p.reasons, l.phase.reasons) {
		return
	}
	l.phase = p
	level := slog.LevelWarn
	if p.state == StateReady {
		level = slog.LevelInfo
	}
	l.log.LogAttrs(ctx, level, "state changed",
		slog.String("state", p.state.String()), slog.Any("reasons", p.reasons))
}

func (l *loop) armExpiry(t *time.Timer) {
	if l.book == nil {
		t.Stop()
		return
	}
	next, ok := l.book.NextExpiry()
	if !ok {
		t.Stop()
		return
	}
	t.Reset(time.Until(next))
}

func (l *loop) expire(ctx context.Context) {
	if l.book != nil && len(l.book.Expire()) > 0 {
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
	before := l.selfTest
	switch {
	case l.selfTest == selfTestNone || l.selfTest == selfTestPassed:
	case r.proved == l.gen:
		l.selfTest = selfTestPassed
	case r.missed == l.gen:
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
// policies that match its name get its addresses. The order keeps the
// acknowledgement honest: book, tables, snapshot, a check that the
// installed ruleset is still loaded, and only then nil. The check costs
// one LoadedID read per report that matches a policy. After a failure the
// book keeps the addresses, so the next report or convergence completes
// the work.
//
// The ack is protected when the name matches a policy: ifbound-dns then
// removes the aliases from the reply. A report without an address only
// asks for that flag. The ack promises nothing about addresses then, so
// it needs no platform call; the phase checks still apply.
func (l *loop) observe(ctx context.Context, o ipc.Observation) (ipc.Ack, error) {
	switch {
	case l.phase.state == StateStarting:
		return ipc.Ack{}, ErrNotReady
	case !l.phase.acks():
		return ipc.Ack{}, ErrUnenforced
	}
	names, err := l.matcher.Match(o.QName)
	if err != nil {
		return ipc.Ack{}, fmt.Errorf("classifying qname: %w", err)
	}
	if len(names) == 0 || len(o.Addrs) == 0 {
		return ipc.Ack{Protected: len(names) > 0}, nil
	}
	if err := l.record(ctx, names, o); err != nil {
		return ipc.Ack{}, err
	}
	return ipc.Ack{Protected: true}, nil
}

// record puts the addresses of o in the book, the tables, and the
// snapshot of each policy in names.
func (l *loop) record(ctx context.Context, names []policy.Name, o ipc.Observation) error {
	addrs := canonical(o.Addrs)
	needSave := false
	for _, name := range names {
		ns, err := l.book.Observe(name, addrs, o.TTL)
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
		if err := l.book.Save(l.snapshot); err != nil {
			return fmt.Errorf("saving snapshot: %w", err)
		}
	}
	return l.checkInstalled(ctx)
}

// checkInstalled confirms that the Backend still has the installed
// ruleset loaded. If not, something outside ifbound changed it: the phase
// stops acknowledging, and Run converges right after this request.
func (l *loop) checkInstalled(ctx context.Context) error {
	id, err := l.rec.Backend.LoadedID(ctx)
	if err != nil {
		return fmt.Errorf("reading the loaded ruleset: %w", err)
	}
	if id != l.phase.installed {
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
	n := 0
	for _, p := range l.cfg.Policies {
		if l.book != nil {
			n += l.book.Len(p.Name)
		}
	}
	return Status{
		State:         l.phase.state,
		Reasons:       slices.Clone(l.phase.reasons),
		Policies:      len(l.cfg.Policies),
		Addrs:         n,
		RetainRestart: l.cfg.AddrBook.Retain != l.retain,
		Config:        l.digest,
		Warnings:      slices.Clone(l.warnings),
	}
}
