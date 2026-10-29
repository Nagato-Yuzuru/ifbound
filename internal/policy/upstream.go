package policy

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Warning reports a configuration that is valid but can be a mistake.
// Field is the path in the file, as in FieldError.
type Warning struct {
	Field string
	Msg   string
}

func (w Warning) String() string {
	// The same quoting as FieldError, so a key cannot forge log lines.
	return strconv.Quote(w.Field) + ": " + w.Msg
}

// CheckUpstreams returns a *FieldError when an upstream address is inside
// an IP or CIDR destination of a policy that allows no interface.
// ifbound-dns can then never reach that upstream.
//
// Parse does not run this check. The check protects only the
// availability of DNS, not the enforcement. "ifbound apply" runs it
// before it stores a configuration. A later version can make the check
// stricter, and the daemon must still load a configuration that an
// earlier version stored.
func (c Config) CheckUpstreams() error {
	faults, _ := c.upstreamFindings()
	if len(faults) == 0 {
		return nil
	}
	return faults[0]
}

// Warnings returns the upstream settings that are valid but can be a
// mistake:
//
//   - an upstream address inside an IP or CIDR destination of a policy
//     that allows some interfaces. ifbound-dns then reaches the upstream
//     only through these interfaces. This is correct for "DNS only
//     through the VPN".
//   - an upstream server name at or below a domain destination of any
//     policy. A lookup of that name can add the upstream address to the
//     policy, with the same effect as an address destination.
func (c Config) Warnings() []Warning {
	_, warnings := c.upstreamFindings()
	return warnings
}

// upstreamHit is one upstream inside one policy destination.
type upstreamHit struct {
	policy   int    // index in Config.Policies
	upstream int    // index in DNS.Upstream
	dest     string // the destination in canonical form
	byName   bool   // the server name, not the address, is inside dest
}

// upstreamFindings puts each upstream inside a policy destination into
// one of two lists. An address inside a policy that allows no interface
// is a fault. Every other hit is a warning. Two destinations with the
// same canonical form, such as "9.9.9.9" and "9.9.9.9/32", give one
// finding.
func (c Config) upstreamFindings() (faults []error, warnings []Warning) {
	seen := map[upstreamHit]struct{}{}
	for i, p := range c.Policies {
		blocked := alwaysBlocked(p.Constraint)
		for _, d := range p.To {
			for j, u := range c.DNS.Upstream {
				h, ok := matchUpstream(d, u)
				if !ok {
					continue
				}
				h.policy, h.upstream = i, j
				if _, dup := seen[h]; dup {
					continue
				}
				seen[h] = struct{}{}
				where := h.describe(c)
				switch {
				case !h.byName && blocked:
					faults = append(faults, &FieldError{Field: h.field(), Err: fmt.Errorf("%w: %s, which allows no interface", errUnreachable, where)})
				case !h.byName:
					warnings = append(warnings, Warning{h.field(), where + ": ifbound-dns reaches this upstream only through the interfaces that the policy allows"})
				case blocked:
					warnings = append(warnings, Warning{h.field(), where + ", which allows no interface: a lookup of this name can block the upstream address, and ifbound-dns then cannot reach this upstream"})
				default:
					warnings = append(warnings, Warning{h.field(), where + ": a lookup of this name can add the upstream address to the policy, and ifbound-dns then reaches this upstream only through the interfaces that the policy allows"})
				}
			}
		}
	}
	return faults, warnings
}

// matchUpstream reports whether u is inside d: its address for an IP or
// CIDR destination, its server name for a domain destination. The
// returned hit has only dest and byName set.
func matchUpstream(d Destination, u Upstream) (upstreamHit, bool) {
	addr, name := u.Addr.Addr(), u.ServerName.String()
	switch d := d.(type) {
	case IPAddr:
		return upstreamHit{dest: netip.PrefixFrom(d.addr, d.addr.BitLen()).String()}, d.addr == addr
	case CIDR:
		return upstreamHit{dest: d.prefix.String()}, d.prefix.Contains(addr)
	case ExactDomain:
		return upstreamHit{dest: d.domain.String(), byName: true}, d.domain == u.ServerName
	case DomainSuffix:
		root := d.domain.String()
		return upstreamHit{dest: "*." + root, byName: true}, name == root || strings.HasSuffix(name, "."+root)
	}
	return upstreamHit{}, false
}

// field is the path of the destination list. It has no index: Parse
// removes duplicate destinations, so the index in Policy.To can differ
// from the index in the file.
func (h upstreamHit) field() string { return fmt.Sprintf("policy[%d].to", h.policy) }

func (h upstreamHit) describe(c Config) string {
	u := c.DNS.Upstream[h.upstream]
	subject := fmt.Sprintf("upstream %s", u.Addr.Addr())
	if h.byName {
		subject = fmt.Sprintf("server name %s of upstream %s", u.ServerName, u.Addr.Addr())
	}
	return fmt.Sprintf("%s (dns.upstream[%d]) is inside destination %s of policy %q",
		subject, h.upstream, h.dest, c.Policies[h.policy].Name)
}

// alwaysBlocked reports whether c allows no interface.
func alwaysBlocked(c Constraint) bool {
	o, ok := c.(OnlyVia)
	return ok && len(o.selectors) == 0
}
