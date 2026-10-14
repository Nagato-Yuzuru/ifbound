package macresolver

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// ConfigSource reads the resolver configuration of the system.
type ConfigSource interface {
	// Resolvers returns the resolvers for unscoped queries.
	Resolvers(ctx context.Context) ([]ConfigEntry, error)
}

// ConfigEntry is one resolver of the system resolver configuration.
type ConfigEntry struct {
	// Domain is in lower case without a final dot. It is empty for a
	// default resolver.
	Domain string
	// Servers holds the zero Addr for a server that the source cannot
	// read. The zero Addr is never the server of an ifbound entry.
	Servers []netip.Addr
	// Port is the server port. It is 53 when the configuration gives no
	// port, and 0 when the source cannot read it. Port 0 is never the port
	// of an ifbound entry.
	Port uint16
	// Supplemental is true for a resolver that a network service or a VPN
	// client added, not a file.
	Supplemental bool
}

// findings is what the resolver configuration tells about the entries.
type findings struct {
	// texts are the problem texts, sorted, without duplicates.
	texts []string
	// shadowed are the domains of the resolvers that ifbound does not
	// manage at or below an entry, most specific first.
	shadowed []policy.Domain
}

// examine compares the configuration with the entries. A resolver is the
// file of an entry only when it has the domain, the single server, and
// the port of the entry and is not supplemental. Each other resolver at
// or below an entry is a finding: macOS can send the queries for names of
// the entry to that resolver.
func examine(entries []reconcile.ResolverEntry, conf []ConfigEntry) findings {
	var f findings
	for _, c := range conf {
		e, ok := covering(entries, c.Domain)
		if !ok || isFileOf(c, e) {
			continue
		}
		f.texts = append(f.texts, fmt.Sprintf(
			"a resolver that ifbound does not manage takes %s (servers %s, port %d), which is at or below the ifbound entry %s",
			c.Domain, serversText(c.Servers), c.Port, e.Domain))
		if d, err := policy.ParseDomain(c.Domain); err == nil {
			f.shadowed = append(f.shadowed, d)
		}
	}
	slices.Sort(f.texts)
	f.texts = slices.Compact(f.texts)
	slices.SortFunc(f.shadowed, moreSpecificFirst)
	f.shadowed = slices.Compact(f.shadowed)
	return f
}

// covering returns the most specific entry at or above d.
func covering(entries []reconcile.ResolverEntry, d string) (reconcile.ResolverEntry, bool) {
	var best reconcile.ResolverEntry
	found := false
	for _, e := range entries {
		if d != "" && atOrBelow(d, e.Domain.String()) && (!found || len(e.Domain.String()) > len(best.Domain.String())) {
			best, found = e, true
		}
	}
	return best, found
}

// isFileOf reports whether c is the resolver that the file of e gives.
func isFileOf(c ConfigEntry, e reconcile.ResolverEntry) bool {
	return c.Domain == e.Domain.String() && !c.Supplemental && e.Server.IsValid() &&
		len(c.Servers) == 1 && c.Servers[0] == e.Server.Addr() && c.Port == e.Server.Port()
}

// atOrBelow reports whether d equals apex or is below it, by whole labels.
func atOrBelow(d, apex string) bool {
	return d == apex || strings.HasSuffix(d, "."+apex)
}

// moreSpecificFirst orders domains by label count, most labels first,
// then by name.
func moreSpecificFirst(a, b policy.Domain) int {
	as, bs := a.String(), b.String()
	return cmp.Or(cmp.Compare(strings.Count(bs, "."), strings.Count(as, ".")), strings.Compare(as, bs))
}

func serversText(servers []netip.Addr) string {
	parts := make([]string, len(servers))
	for i, s := range servers {
		if s.IsValid() {
			parts[i] = s.String()
		} else {
			parts[i] = "unreadable"
		}
	}
	return "[" + strings.Join(parts, " ") + "]"
}
