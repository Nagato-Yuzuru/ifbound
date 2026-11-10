package daemon

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/daemon/core"
	"github.com/Nagato-Yuzuru/ifbound/internal/hostsfile"
	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// mappedHosts is the host addresses of each policy that the shell mapped
// from a good read of the host file, sorted, without duplicates.
type mappedHosts struct {
	// file is the ID of the read, and gen is the configuration
	// generation.
	file  core.ReqID
	gen   uint64
	addrs map[policy.Name][]blockable.Addr
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

// readHosts runs the host file read of e. The file must have the same
// version after the read: a writer that is not done can leave a part of
// the file or no file, and the next read reads again.
func (l *loop) readHosts(ctx context.Context, e core.ReadHosts) core.HostsRead {
	r := l.hostsReader
	res := core.HostsRead{ID: e.ID}
	v, err := r.Version()
	switch {
	case err != nil:
		res.Err = err
	case e.Known && v == e.Last:
	default:
		content, err := r.Read(v)
		if err != nil {
			res.Err = err
			break
		}
		if after, err := r.Version(); err != nil || after != v {
			break
		}
		if !v.Exists {
			l.log.DebugContext(ctx, "host file is missing")
		}
		res.New, res.Version, res.Hosts = true, v, content
	}
	res.At = time.Now()
	return res
}

// readKernelHosts reads the learned-looking kernel entries of the
// configured policies.
func (l *loop) readKernelHosts(ctx context.Context, e core.ReadKernelHosts) core.KernelRead {
	found, err := l.rec.Adoptable(ctx, l.policies())
	return core.KernelRead{At: time.Now(), ID: e.ID, Addrs: found, Err: err}
}

// hostAddrs returns the host addresses of each policy for a convergence
// under conf. Before the first good read of the host file, they are the
// kernel host entries. It maps the file again only when the read or the
// configuration changed, so the warnings of mapHosts do not repeat.
func (l *loop) hostAddrs(ctx context.Context, conf activeConfig) map[policy.Name][]blockable.Addr {
	file, read := l.core.HostFile()
	if !read {
		return l.core.KernelHosts()
	}
	if m := l.mapped; m.file != file.ID || m.gen != conf.gen {
		l.mapped = mappedHosts{file: file.ID, gen: conf.gen, addrs: l.mapHosts(ctx, conf, file.Hosts)}
	}
	return l.mapped.addrs
}

// mapHosts gives the addresses of the host file to the policies that
// match a name of an entry. mDNSResponder answers an alias of an entry
// as a CNAME to the first name, and it follows that CNAME across all
// lines, also when the first name is an alias of another line. So a
// matching name takes the addresses of each first name that its CNAME
// chain reaches. It skips the addresses that blockable.New refuses.
//
// It also logs, in one event, the lines with a name that the entries
// cannot show, when the name is at or below an apex. Such a line can hold
// a protected address that no table has.
func (l *loop) mapHosts(ctx context.Context, conf activeConfig, hosts hostsfile.Hosts) map[policy.Name][]blockable.Addr {
	g := newHostGraph(hosts.Entries)
	out := make(map[policy.Name][]blockable.Addr)
	var bad []string
	var badErrs []error
	for name := range g.names() {
		policies, err := conf.matcher.Match(name)
		if err != nil {
			bad, badErrs = append(bad, name), append(badErrs, err)
			continue
		}
		if len(policies) == 0 {
			continue
		}
		addrs := blockable.Filter(g.resolve(name))
		for _, p := range policies {
			out[p] = append(out[p], addrs...)
		}
	}
	for p, addrs := range out {
		slices.SortFunc(addrs, blockable.Addr.Compare)
		out[p] = slices.Compact(addrs)
	}
	if len(bad) > 0 {
		// A name that dnsname built always splits.
		l.log.ErrorContext(ctx, "host file names do not split", slog.Any(logattr.HostsNames, bad),
			slog.String(logattr.ErrorType, logattr.ErrorTypeInvariant), slog.String(logattr.ExceptionMessage, errors.Join(badErrs...).Error()))
	}
	var lines []string
	for _, line := range hosts.Unrepresentable {
		if below := belowApex(conf.apexes, line.Names); len(below) > 0 {
			lines = append(lines, fmt.Sprintf("line %d: %s", line.Number, strings.Join(below, " ")))
		}
	}
	if len(lines) > 0 {
		l.log.WarnContext(ctx, "host file lines have a protected name that ifbound cannot read",
			slog.Any(logattr.HostsLines, lines))
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
		g.addrs[first] = append(g.addrs[first], e.Addr)
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
