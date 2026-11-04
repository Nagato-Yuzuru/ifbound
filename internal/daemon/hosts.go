package daemon

import (
	"context"
	"iter"
	"log/slog"
	"net/netip"
	"slices"
	"strings"

	"github.com/Nagato-Yuzuru/ifbound/internal/hostsfile"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// hostsState is what the daemon knows of the host file. macOS answers a
// name from the host file before it asks DNS, so a host entry for a
// protected name never reaches ifbound-dns. Its address goes into the
// table of each matching policy instead. The file is the source of truth
// for these addresses: they do not expire and are not in the snapshot.
type hostsState struct {
	reader HostsReader
	// good is the content of the last good read. A missing file is a good
	// read with no entries.
	good hostsfile.Hosts
	// read is true after the first good read.
	read bool
	// version identifies the file of the last good read.
	version hostsfile.Version
	// err is the error of the last read, or nil.
	err error
	// addrs are the host addresses of each policy, sorted, without
	// duplicates. Before the first good
	// read, they are the learned-looking kernel entries: the last run can
	// have put host addresses there.
	addrs map[policy.Name][]netip.Addr
	// gen is the configuration generation that addrs was made for.
	gen uint64
	// dirty is true when good changed after addrs was made.
	dirty bool
}

// HostsReader reads the host file. hostsfs.Reader implements it.
type HostsReader interface {
	// Version returns a cheap identity of the file, without a read of its
	// content. Two calls return equal Versions while the file does not
	// change, and different Versions after a change. A missing file gives
	// the zero Version and no error. An error means that the reader
	// cannot tell the state of the file. The file can exist or not: a
	// loop of links, a parent that is not a directory, or a denied
	// parent gives an error too.
	Version() (hostsfile.Version, error)
	// Read returns the content of the file that Version found as v. A
	// Version of a missing file gives no entries. Read cannot check that
	// v is still current: the daemon calls Version again after the read
	// and drops the content when the Version moved. Read takes v so that
	// it does not open a file that Version found missing.
	Read(v hostsfile.Version) (hostsfile.Hosts, error)
}

// refreshHosts reads the host file again when it changed or the last
// read failed, and maps its entries again when the content or the
// configuration changed. run is the running configuration. A file that
// exists but cannot be read keeps the addresses of the last good read:
// other readers can still read it, so its entries can be in use.
func (l *loop) refreshHosts(ctx context.Context, run running) {
	h := &l.hosts
	if v, err := h.reader.Version(); err != nil {
		h.fail(ctx, l.log, err)
	} else if !h.read || h.err != nil || v != h.version {
		l.readHosts(ctx, v)
	}
	switch {
	case !h.read:
		l.keepKernelHosts(ctx, run.cfg.Policies)
	case h.dirty || h.gen != run.gen:
		h.addrs = l.mapHosts(ctx, run)
		h.gen, h.dirty = run.gen, false
	}
}

// readHosts reads the file that Version found as v. The file must have
// the same version after the read: a writer that is not done can leave a
// part of the file or no file, and the next pass reads again.
func (l *loop) readHosts(ctx context.Context, v hostsfile.Version) {
	h := &l.hosts
	content, err := h.reader.Read(v)
	if err != nil {
		h.fail(ctx, l.log, err)
		return
	}
	if after, err := h.reader.Version(); err != nil || after != v {
		return
	}
	if !v.Exists {
		l.log.DebugContext(ctx, "host file is missing")
	}
	h.good, h.version, h.err, h.read, h.dirty = content, v, nil, true, true
}

// keepKernelHosts runs while no read of the host file has succeeded. The
// last run can have put host addresses in the tables, and the file can
// still have their entries. So the learned-looking kernel entries count
// as host addresses until a read succeeds. A failed kernel read keeps
// the earlier ones.
func (l *loop) keepKernelHosts(ctx context.Context, policies []policy.Policy) {
	found, err := l.rec.Adoptable(ctx, policies)
	if err != nil {
		l.log.WarnContext(ctx, "reading the kernel entries for the host file failed", slog.Any("error", err))
		return
	}
	l.hosts.addrs = found
}

func (h *hostsState) fail(ctx context.Context, log *slog.Logger, err error) {
	if h.err == nil {
		log.WarnContext(ctx, "host file read failed", slog.Any("error", err))
	}
	h.err = err
}

// problem returns the Problem of a failed read, if there is one. It does
// not void enforcement: the tables keep the host addresses that they
// have.
func (h *hostsState) problem() (reconcile.Problem, bool) {
	if h.err == nil {
		return reconcile.Problem{}, false
	}
	return reconcile.Problem{Text: "the host file cannot be read, so changes to its entries for protected names are not applied: " + h.err.Error()}, true
}

// mapHosts gives the addresses of the host file to the policies that
// match a name of an entry. mDNSResponder answers an alias of an entry
// as a CNAME to the first name, and it follows that CNAME across all
// lines, also when the first name is an alias of another line. So a
// matching name takes the addresses of each first name that its CNAME
// chain reaches.
//
// A loopback or unspecified address is not a host address: traffic to it
// does not leave the host, and a block of it would stop local services,
// ifbound-dns too.
//
// It also logs each line with a name that the entries cannot show, when
// the name is at or below an apex. Such a line can hold a protected
// address that no table has.
func (l *loop) mapHosts(ctx context.Context, run running) map[policy.Name][]netip.Addr {
	g := newHostGraph(l.hosts.good.Entries)
	out := make(map[policy.Name][]netip.Addr)
	for name := range g.names() {
		policies, err := run.matcher.Match(name)
		if err != nil {
			// A name that dnsname built always splits.
			l.log.ErrorContext(ctx, "host file name does not split", slog.String("name", name), slog.Any("error", err))
			continue
		}
		if len(policies) == 0 {
			continue
		}
		addrs := g.resolve(name)
		for _, p := range policies {
			out[p] = append(out[p], addrs...)
		}
	}
	for p, addrs := range out {
		slices.SortFunc(addrs, netip.Addr.Compare)
		out[p] = slices.Compact(addrs)
	}
	for _, line := range l.hosts.good.Unrepresentable {
		if names := belowApex(run.apexes, line.Names); len(names) > 0 {
			l.log.WarnContext(ctx, "host file line has a protected name that ifbound cannot read",
				slog.Int("line", line.Number), slog.Any("names", names))
		}
	}
	return out
}

// hostGraph holds the names of the host file. A first name has
// addresses; an alias points to the first name of its entry.
type hostGraph struct {
	addrs   map[string][]netip.Addr
	targets map[string][]string
}

func newHostGraph(entries []hostsfile.Entry) hostGraph {
	g := hostGraph{addrs: make(map[string][]netip.Addr), targets: make(map[string][]string)}
	for _, e := range entries {
		first := e.Name.String()
		if !e.Addr.IsLoopback() && !e.Addr.IsUnspecified() {
			g.addrs[first] = append(g.addrs[first], e.Addr)
		} else if _, ok := g.addrs[first]; !ok {
			g.addrs[first] = nil // the name is still in the file
		}
		for _, a := range e.Aliases {
			g.targets[a.String()] = append(g.targets[a.String()], first)
		}
	}
	return g
}

// names yields each name of the file once.
func (g hostGraph) names() iter.Seq[string] {
	return func(yield func(string) bool) {
		for n := range g.addrs {
			if !yield(n) {
				return
			}
		}
		for n := range g.targets {
			if _, ok := g.addrs[n]; ok {
				continue
			}
			if !yield(n) {
				return
			}
		}
	}
}

// resolve returns the addresses of name and of each name that its CNAME
// chain reaches. A cycle ends the chain.
func (g hostGraph) resolve(name string) []netip.Addr {
	seen := map[string]bool{name: true}
	queue := []string{name}
	var out []netip.Addr
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		out = append(out, g.addrs[n]...)
		for _, t := range g.targets[n] {
			if !seen[t] {
				seen[t] = true
				queue = append(queue, t)
			}
		}
	}
	return out
}

// belowApex returns the fields that are at or below an apex, compared as
// text without ASCII case and without one final dot.
func belowApex(apexes []policy.Domain, fields []string) []string {
	var out []string
	for _, f := range fields {
		t := lowerASCII(strings.TrimSuffix(f, "."))
		for _, apex := range apexes {
			a := apex.String()
			if t == a || strings.HasSuffix(t, "."+a) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
