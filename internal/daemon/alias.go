package daemon

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// alias is one alias of a report, checked.
type alias struct {
	name dnsname.Name
	// domain is the domain of the resolver entry of the alias.
	domain policy.Domain
	ttl    time.Duration
}

// parseAliases checks the aliases of a report. Each alias must be able
// to get a resolver entry: the Reconciler writes an entry only for an
// alias that reconcile.AliasEntry accepts, and without an entry a later
// query for the alias goes around ifbound-dns. Names that differ only in
// spelling merge, with the largest TTL.
func parseAliases(in []ipc.Alias) ([]alias, error) {
	out := make([]alias, 0, len(in))
	for _, a := range in {
		n, err := dnsname.Parse(a.Name)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrAliasEntry, a.Name, err)
		}
		d, err := reconcile.AliasEntry(n)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrAliasEntry, err)
		}
		if i := slices.IndexFunc(out, func(b alias) bool { return b.name == n }); i >= 0 {
			out[i].ttl = max(out[i].ttl, a.TTL)
			continue
		}
		out = append(out, alias{name: n, domain: d, ttl: a.TTL})
	}
	return out, nil
}

// needProof returns the aliases whose resolver entry has no proof now,
// and the view of the last read. Each alias must have an entry that
// sends its queries to ifbound-dns.
//
// An alias without an entry gets one through a convergence first. The
// probe must come after the write: until the system applies the entry,
// the probe cannot reach ifbound-dns. When the last write of a missing
// entry failed, the report fails at once and starts no convergence: the
// self-heal timer retries the write, and a convergence per report would
// load the loop.
func (l *loop) needProof(ctx context.Context, aliases []alias) ([]alias, resolverView, error) {
	if len(aliases) == 0 {
		return nil, resolverView{}, nil
	}
	view, err := l.aliasEntries(ctx)
	if err != nil {
		return nil, view, err
	}
	missing := false
	for _, a := range aliases {
		switch {
		case view.present[a.domain]:
		case l.resolver.failed[a.domain]:
			return nil, view, fmt.Errorf("%w: %s: its last write failed", ErrAliasEntry, a.name)
		default:
			missing = true
		}
	}
	if missing {
		_ = l.reconcile(ctx, "alias learned") // the phase holds the outcome
		if !l.phase.acks() {
			return nil, view, ErrUnenforced
		}
		if view, err = l.aliasEntries(ctx); err != nil {
			return nil, view, err
		}
	}
	var out []alias
	for _, a := range aliases {
		switch {
		case !view.present[a.domain]:
			return nil, view, fmt.Errorf("%w: %s", ErrAliasEntry, a.name)
		case !l.resolver.isProven(a.domain):
			out = append(out, a)
		}
	}
	return out, view, nil
}

// resolverView is what one read tells about the resolver entries of
// ifbound.
type resolverView struct {
	// present holds the entries that send queries to ifbound-dns.
	present map[policy.Domain]bool
	// version holds the Version of each present entry.
	version map[policy.Domain]string
	// problems are the texts of the problems that the SysResolver
	// reports.
	problems []string
}

// aliasEntries reads the resolver entries of ifbound. The read also
// forgets proofs (see resolverWatch.Read).
func (l *loop) aliasEntries(ctx context.Context) (resolverView, error) {
	st, err := l.rec.Resolver.Read(ctx)
	if err != nil {
		return resolverView{}, fmt.Errorf("reading resolver entries: %w", err)
	}
	v := resolverView{
		present: make(map[policy.Domain]bool, len(st.Entries)),
		version: make(map[policy.Domain]string, len(st.Entries)),
	}
	for _, e := range st.Entries {
		if e.Server == l.cfg.DNS.Listen {
			v.present[e.Domain] = true
			v.version[e.Domain] = e.Version
		}
	}
	for _, p := range st.Problems {
		v.problems = append(v.problems, p.Text)
	}
	return v, nil
}

// pending is the work of a report between observe and finish.
type pending struct {
	names   []policy.Name // the policies that the report matched
	addrs   []netip.Addr  // the addresses of the report
	aliases []alias       // the aliases to prove
	// proven are the other aliases of the report: their proofs held at
	// the start, and they must still hold at the ack.
	proven []alias
	// stamps holds resolverWatch.stamp of each alias at the start, and
	// covers its covering entries. A probe proves only the entries that
	// it started with.
	stamps []uint64
	covers []cover
	// problems are the problems that the SysResolver reported at the
	// start.
	problems []string
	gen      uint64
}

// finish completes a report after its probe. It acks only when the
// configuration is the one that the report started with, the phase still
// acks, no new SysResolver problem appeared, each proved entry and each
// entry above it is unchanged since the probe started (no write of
// ifbound, and the same Version), each proved entry is still present,
// and the installed ruleset is still loaded. A probe can be reported
// late, so a write by another process after the probe makes its report
// tell nothing about the new entry. The other aliases of the report must
// still have their entries and their proofs. A new
// problem can be a conflicting entry that takes the queries of an alias,
// and a problem does not tell which domain it is about, so any new
// problem stops the ack. The addresses of the report go into the tables
// again: an external flush can have removed them meanwhile.
//
// The proof is kept only when the SysResolver reports no problem, and
// with the version of the entry; see resolverWatch.
func (l *loop) finish(ctx context.Context, pq *pending, perr error) error {
	switch {
	case perr != nil:
		return perr
	case pq.gen != l.gen:
		return ErrConfigChanged
	case !l.phase.acks():
		return ErrUnenforced
	}
	view, err := l.aliasEntries(ctx)
	if err != nil {
		return err
	}
	if i := slices.IndexFunc(view.problems, func(p string) bool { return !slices.Contains(pq.problems, p) }); i >= 0 {
		return fmt.Errorf("%w: the system resolver reports a new problem: %s", ErrAliasProbe, view.problems[i])
	}
	for _, a := range pq.proven {
		switch {
		case !view.present[a.domain]:
			return fmt.Errorf("%w: %s: removed during the probe", ErrAliasEntry, a.name)
		case !l.resolver.isProven(a.domain):
			return fmt.Errorf("%w: %s: its proof ended during the probe", ErrAliasProbe, a.name)
		}
	}
	for i, a := range pq.aliases {
		switch {
		case !view.present[a.domain]:
			return fmt.Errorf("%w: %s: removed during the probe", ErrAliasEntry, a.name)
		case l.resolver.stamp(a.domain) != pq.stamps[i] || !maps.Equal(view.cover(a.domain), pq.covers[i]):
			return fmt.Errorf("%w: %s: changed during the probe", ErrAliasProbe, a.name)
		}
	}
	if len(view.problems) == 0 {
		for _, a := range pq.aliases {
			l.resolver.proven[a.domain] = view.cover(a.domain)
		}
	}
	if err := l.enforce(ctx, pq.names, pq.addrs, false); err != nil {
		return err
	}
	return l.checkInstalled(ctx)
}

// resolverWatch wraps the SysResolver of the platform, so the loop sees
// each write, removal, and read of a resolver entry. It keeps what the
// loop knows about the entries. Only the loop goroutine uses it.
type resolverWatch struct {
	reconcile.SysResolver
	listen netip.AddrPort
	// proven holds the entries that a probe proved and that did not
	// change since, each with its covering entries at the proof.
	//
	// A probe below an alias can reach ifbound-dns through the entry of a
	// parent domain, so a proof rests on every covering entry. A write or
	// a removal of ifbound forgets the proofs of the entries at or below
	// it. A read forgets a proof when a covering entry is gone, has
	// another server than listen, or has another Version: another process
	// wrote the entry again, and the new entry can fail to apply. A
	// platform without versions ("") cannot show such a write; there a
	// covering entry must be active, and a read that shows it not active
	// forgets the proof. That rule misses a write by another process that
	// applies between two reads. A read with a problem forgets every
	// proof: a conflicting entry can take the queries, and a problem does
	// not tell which domain it is about.
	proven map[policy.Domain]cover
	// gen counts the writes and removals of each entry.
	gen map[policy.Domain]uint64
	// failed holds the entries whose last write failed.
	failed map[policy.Domain]bool
}

func newResolverWatch(r reconcile.SysResolver) *resolverWatch {
	return &resolverWatch{
		SysResolver: r,
		proven:      make(map[policy.Domain]cover),
		gen:         make(map[policy.Domain]uint64),
		failed:      make(map[policy.Domain]bool),
	}
}

func (w *resolverWatch) isProven(d policy.Domain) bool {
	_, ok := w.proven[d]
	return ok
}

func (w *resolverWatch) changed(d policy.Domain) {
	w.gen[d]++
	for p := range w.proven {
		if atOrBelow(p.String(), d.String()) {
			delete(w.proven, p)
		}
	}
}

// stamp sums the generations of d and of each domain above it. Each
// generation only grows, so an equal stamp means that none of these
// entries was written or removed in between.
func (w *resolverWatch) stamp(d policy.Domain) uint64 {
	var sum uint64
	for _, p := range atOrAbove(d) {
		sum += w.gen[p]
	}
	return sum
}

// atOrAbove returns d and each domain above it that obeys the domain
// rules.
func atOrAbove(d policy.Domain) []policy.Domain {
	var out []policy.Domain
	for name := d.String(); ; {
		if p, err := policy.ParseDomain(name); err == nil {
			out = append(out, p)
		}
		_, rest, ok := strings.Cut(name, ".")
		if !ok {
			return out
		}
		name = rest
	}
}

// cover holds the covering entries of an alias: its own entry and each
// entry of ifbound above it, with their Versions.
type cover map[policy.Domain]string

// cover returns the covering entries of d in the view.
func (v resolverView) cover(d policy.Domain) cover {
	c := make(cover)
	for _, p := range atOrAbove(d) {
		if v.present[p] {
			c[p] = v.version[p]
		}
	}
	return c
}

// atOrBelow reports whether name is equal to domain or below it, by whole
// labels.
func atOrBelow(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

// Write implements reconcile.SysResolver.
func (w *resolverWatch) Write(ctx context.Context, e reconcile.ResolverEntry) error {
	w.changed(e.Domain)
	err := w.SysResolver.Write(ctx, e)
	if err != nil {
		w.failed[e.Domain] = true
	} else {
		delete(w.failed, e.Domain)
	}
	return err
}

// Remove implements reconcile.SysResolver.
func (w *resolverWatch) Remove(ctx context.Context, d policy.Domain) error {
	w.changed(d)
	delete(w.failed, d)
	return w.SysResolver.Remove(ctx, d)
}

// Read implements reconcile.SysResolver.
func (w *resolverWatch) Read(ctx context.Context) (reconcile.ResolverState, error) {
	st, err := w.SysResolver.Read(ctx)
	if err != nil {
		return st, err
	}
	// When the SysResolver also reports the entries that another
	// configuration shadows, forget only their proofs here.
	if len(st.Problems) > 0 {
		clear(w.proven)
		return st, nil
	}
	for d, c := range w.proven {
		for p, version := range c {
			if !slices.ContainsFunc(st.Entries, func(e reconcile.ManagedEntry) bool {
				return e.Domain == p && e.Server == w.listen && e.Version == version && (version != "" || e.Active)
			}) {
				delete(w.proven, d)
				break
			}
		}
	}
	return st, nil
}
