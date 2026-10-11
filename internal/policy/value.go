package policy

import (
	"fmt"
	"net/netip"
	"path"
	"strings"
)

const (
	maxDomainLen    = 253
	maxLabelLen     = 63
	maxIfaceNameLen = 15 // IFNAMSIZ - 1
	maxPolicyName   = 24
)

// Domain is a valid DNS name in lower case, without a trailing dot.
// The zero Domain is not valid. Only ParseDomain builds one, so every
// other package can trust a Domain value.
type Domain struct{ s string }

// ParseDomain checks and normalizes a domain name. It lower-cases the
// name and removes one trailing dot. Each label has 1 to 63 characters
// from [a-z0-9_-], and does not start or end with "-". A name whose last
// label is all digits is an address form, not a domain, so it fails.
// Non-ASCII names fail: write the punycode form.
func ParseDomain(s string) (Domain, error) {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return Domain{}, fmt.Errorf("%w: %q", errNonASCII, s)
		}
	}
	name := strings.TrimSuffix(strings.ToLower(s), ".")
	if name == "" || len(name) > maxDomainLen {
		return Domain{}, fmt.Errorf("%w: %q", errBadDomain, s)
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if !validLabel(l) {
			return Domain{}, fmt.Errorf("%w: %q", errBadDomain, s)
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return Domain{}, fmt.Errorf("%w: %q", errBadDomain, s)
	}
	return Domain{s: name}, nil
}

func validLabel(l string) bool {
	if l == "" || len(l) > maxLabelLen || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := range len(l) {
		c := l[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// String returns the normalized name.
func (d Domain) String() string { return d.s }

// ParseDestination parses a policy destination: a domain, a domain
// suffix pattern ("*.x"), an IP address, or a CIDR prefix.
func ParseDestination(s string) (Destination, error) {
	if strings.Contains(s, "/") {
		p, err := parsePrefix(s)
		if err != nil {
			return nil, err
		}
		return CIDR{prefix: p}, nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a, err = normalizeAddr(a)
		if err != nil {
			return nil, fmt.Errorf("%w: %q", err, s)
		}
		return IPAddr{addr: a}, nil
	}
	rest, suffix := strings.CutPrefix(s, "*.")
	d, err := ParseDomain(rest)
	if err != nil {
		return nil, err
	}
	if suffix {
		return DomainSuffix{domain: d}, nil
	}
	return ExactDomain{domain: d}, nil
}

// normalizeAddr rejects a zoned address and unmaps IPv4-mapped IPv6.
func normalizeAddr(a netip.Addr) (netip.Addr, error) {
	if a.Zone() != "" {
		return netip.Addr{}, errZoned
	}
	return a.Unmap(), nil
}

// parsePrefix returns a masked prefix. An IPv4-mapped IPv6 prefix of 96
// bits or more becomes an IPv4 prefix. A shorter one has no IPv4 form.
func parsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: %q", errBadDestination, s)
	}
	if p.Addr().Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("%w: %q", errZoned, s)
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("%w: %q", errMappedPrefix, s)
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}

// ParseInterfaceSelector parses "@class", a glob, or an interface name.
// A name has at most 15 bytes from [A-Za-z0-9_.-] and does not start with
// "-". A glob also allows "*", "?", "[" and "]".
func ParseInterfaceSelector(s string) (InterfaceSelector, error) {
	if name, ok := strings.CutPrefix(s, "@"); ok {
		for _, c := range []Class{ClassHardware, ClassTunnel} {
			if c.String() == name {
				return InterfaceClass{class: c}, nil
			}
		}
		return nil, fmt.Errorf("%w: %q", errUnknownClass, s)
	}
	glob := strings.ContainsAny(s, "*?[]")
	if !validIfaceChars(s, glob) {
		return nil, fmt.Errorf("%w: %q", errBadSelector, s)
	}
	if !glob {
		return InterfaceName{name: s}, nil
	}
	if _, err := path.Match(s, ""); err != nil {
		return nil, fmt.Errorf("%w: %q", errBadSelector, s)
	}
	return InterfaceGlob{pattern: s}, nil
}

func validIfaceChars(s string, glob bool) bool {
	if s == "" || len(s) > maxIfaceNameLen || s[0] == '-' {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '.', c == '-':
		case glob && strings.IndexByte("*?[]", c) >= 0:
		default:
			return false
		}
	}
	return true
}

func parseName(s string) (Name, error) {
	if s == "" || len(s) > maxPolicyName || s[0] == '-' || s[0] == '_' {
		return "", fmt.Errorf("%w: %q", errBadName, s)
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return "", fmt.Errorf("%w: %q", errBadName, s)
		}
	}
	return Name(s), nil
}
