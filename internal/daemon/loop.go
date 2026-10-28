package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrbook"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/matcher"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// loop is the state that only the Run goroutine touches.
type loop struct {
	rec      reconcile.Reconciler
	snapshot string
	log      *slog.Logger
	retain   time.Duration // the retain of every book, fixed at creation

	// book is empty in StateStarting. A complete load replaces it.
	book *addrbook.AddrBook

	cfg     policy.Config
	matcher *matcher.Matcher
	apexes  []policy.Domain
	// gen counts the configuration changes. A warm-up runs only under
	// the configuration that it started with.
	gen uint64

	hosts hostsState

	phase phase
	// recheck asks Run for a convergence after the current request. A
	// report sets it when it finds a loaded ruleset that is not the
	// installed one.
	recheck bool
}

func newLoop(c Config) *loop {
	l := &loop{
		rec:      c.Platform,
		snapshot: c.Snapshot,
		log:      c.Logger,
		retain:   c.Policy.AddrBook.Retain,
		phase:    startingPhase("the snapshot is not loaded yet"),
		hosts:    hostsState{path: c.HostsFile},
	}
	if l.hosts.path == "" {
		l.hosts.path = DefaultHostsFile
	}
	l.book = l.newBook()
	l.setConfig(c.Policy)
	return l
}

func (l *loop) newBook() *addrbook.AddrBook { return addrbook.New(l.retain, time.Now) }

func (l *loop) setConfig(cfg policy.Config) {
	l.cfg = cfg
	l.gen++
	l.matcher = matcher.New(cfg.Policies)
	l.apexes = l.matcher.Apexes()
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
// host addresses.
func (l *loop) reconcile(ctx context.Context, trigger string) error {
	l.refreshHosts(ctx)
	if !l.phase.loaded() {
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
	l.setPhase(ctx, convergedPhase(rep, err))
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
	next, ok := l.book.NextExpiry()
	if !ok {
		t.Stop()
		return
	}
	t.Reset(time.Until(next))
}

func (l *loop) expire(ctx context.Context) {
	if len(l.book.Expire()) > 0 {
		_ = l.reconcile(ctx, "expiry") //nolint:errcheck // the phase holds the outcome
	}
}

// reconfigure applies cfg. Until a convergence installs the ruleset of
// cfg, the phase acknowledges nothing. The book keeps the entries of
// removed policies until then; reconcile prunes them.
func (l *loop) reconfigure(ctx context.Context, cfg policy.Config) error {
	l.setConfig(cfg)
	return l.reconcile(ctx, "config")
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
	case !l.phase.loaded():
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

func (l *loop) status() Status {
	n := 0
	for _, name := range l.policyNames() {
		n += len(l.book.Addrs(name))
	}
	return Status{
		State:         l.phase.state,
		Reasons:       slices.Clone(l.phase.reasons),
		Policies:      len(l.cfg.Policies),
		Addrs:         n,
		RetainRestart: l.cfg.AddrBook.Retain != l.retain,
	}
}
