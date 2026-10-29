package policy

import (
	"errors"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// domainRE is the domain allowlist, written out independently of
// ParseDomain: lower-case labels of [a-z0-9_-], 1 to 63 bytes, no leading
// or trailing "-".
var (
	domainRE  = regexp.MustCompile(`^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$`)
	nameRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	accountRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
)

func checkInvariants(t *testing.T, cfg Config) {
	t.Helper()
	checkAddrPort(t, "listen", cfg.DNS.Listen)
	if l := cfg.DNS.Listen.Addr(); !l.IsLoopback() {
		t.Errorf("listen %v is not loopback", l)
	}
	if len(cfg.DNS.Upstream) == 0 {
		t.Error("no upstream")
	}
	for _, u := range cfg.DNS.Upstream {
		checkAddrPort(t, "upstream", u.Addr)
		checkDomain(t, "server name", u.ServerName)
	}
	if cfg.AddrBook.Retain <= 0 {
		t.Errorf("retain %v", cfg.AddrBook.Retain)
	}
	names := map[Name]bool{}
	for _, p := range cfg.Policies {
		if !nameRE.MatchString(string(p.Name)) || len(p.Name) > 24 || names[p.Name] {
			t.Errorf("name %q breaks the name contract", p.Name)
		}
		names[p.Name] = true
		checkTo(t, p)
		checkConstraint(t, p)
		checkScope(t, p)
	}
	checkUpstreamCheck(t, cfg)
	// Round trip: render the config back to TOML; it must parse to the
	// same value.
	again, err := ParseBytes([]byte(render(cfg)))
	if err != nil {
		t.Errorf("rendered config does not re-validate: %v\n%s", err, render(cfg))
		return
	}
	if !reflect.DeepEqual(cfg, again) {
		t.Errorf("round trip changed the config\n got %#v\nwant %#v", again, cfg)
	}
}

// checkUpstreamCheck checks CheckUpstreams against an independent
// oracle: it fails exactly when a policy that allows no interface holds
// an upstream address. So a config that passes the apply check has no
// unreachable upstream.
func checkUpstreamCheck(t *testing.T, cfg Config) {
	t.Helper()
	var blocked []string
	for _, p := range cfg.Policies {
		if c, ok := p.Constraint.(OnlyVia); !ok || len(c.Selectors()) > 0 {
			continue
		}
		for _, d := range p.To {
			for _, u := range cfg.DNS.Upstream {
				a := u.Addr.Addr()
				ip, isIP := d.(IPAddr)
				c, isCIDR := d.(CIDR)
				if isIP && ip.Addr() == a || isCIDR && c.Prefix().Contains(a) {
					blocked = append(blocked, string(p.Name)+" blocks "+a.String())
				}
			}
		}
	}
	if err := cfg.CheckUpstreams(); (err != nil) != (len(blocked) > 0) {
		t.Errorf("CheckUpstreams = %v, but the oracle finds %q", err, blocked)
	}
}

func checkAddrPort(t *testing.T, what string, ap netip.AddrPort) {
	t.Helper()
	if !ap.IsValid() || ap.Port() == 0 || ap.Addr().Zone() != "" || ap.Addr().Is4In6() {
		t.Errorf("%s %v breaks the address contract", what, ap)
	}
}

func checkDomain(t *testing.T, what string, d Domain) {
	t.Helper()
	s := d.String()
	if !domainRE.MatchString(s) || len(s) > 253 || strings.Trim(s[strings.LastIndexByte(s, '.')+1:], "0123456789") == "" {
		t.Errorf("%s %q breaks the domain allowlist", what, s)
	}
	if d2, err := ParseDomain(s); err != nil || d2 != d {
		t.Errorf("%s %q does not re-validate: %v", what, s, err)
	}
}

func checkTo(t *testing.T, p Policy) {
	t.Helper()
	if len(p.To) == 0 {
		t.Errorf("policy %s has no destination", p.Name)
	}
	seen := map[Destination]bool{}
	for _, d := range p.To {
		if seen[d] {
			t.Errorf("policy %s has duplicate %#v", p.Name, d)
		}
		seen[d] = true
		checkDestination(t, d)
	}
}

func checkDestination(t *testing.T, d Destination) {
	t.Helper()
	switch d := d.(type) {
	case ExactDomain:
		checkDomain(t, "exact", d.Domain())
	case DomainSuffix:
		checkDomain(t, "suffix", d.Domain())
	case IPAddr:
		a := d.Addr()
		if !a.IsValid() || a.Zone() != "" || a.Is4In6() {
			t.Errorf("address %v breaks the address contract", a)
		}
	case CIDR:
		pr := d.Prefix()
		if !pr.IsValid() || pr != pr.Masked() || pr.Addr().Zone() != "" || pr.Addr().Is4In6() {
			t.Errorf("prefix %v breaks the prefix contract", pr)
		}
	default:
		t.Errorf("unknown destination %T", d)
	}
}

func checkConstraint(t *testing.T, p Policy) {
	t.Helper()
	var sels []InterfaceSelector
	switch c := p.Constraint.(type) {
	case OnlyVia:
		sels = c.Selectors()
	case DenyVia:
		sels = c.Selectors()
		if len(sels) == 0 {
			t.Errorf("policy %s has an empty deny_via", p.Name)
		}
	default:
		t.Errorf("policy %s has constraint %T", p.Name, p.Constraint)
	}
	for _, s := range sels {
		back, err := ParseInterfaceSelector(selString(s))
		if err != nil || back != s {
			t.Errorf("selector %#v does not re-validate: %v", s, err)
		}
	}
}

func checkScope(t *testing.T, p Policy) {
	t.Helper()
	users, groups := p.Scope.Users(), p.Scope.Groups()
	if p.Scope.Limited() != (len(users)+len(groups) > 0) {
		t.Errorf("policy %s: Limited() disagrees with the lists", p.Name)
	}
	for _, a := range append(users, groups...) {
		if !accountRE.MatchString(a.String()) || len(a.String()) > 32 {
			t.Errorf("policy %s: account %q breaks the account contract", p.Name, a)
		}
	}
}

func selString(s InterfaceSelector) string {
	switch s := s.(type) {
	case InterfaceName:
		return s.Name()
	case InterfaceGlob:
		return s.Pattern()
	case InterfaceClass:
		return "@" + s.Class().String()
	default:
		return "\x00unknown"
	}
}

func render(cfg Config) string {
	q := func(s string) string { return `"` + s + `"` }
	var b strings.Builder
	b.WriteString("[dns]\nlisten = " + q(cfg.DNS.Listen.String()) + "\nupstream = [")
	for i, u := range cfg.DNS.Upstream {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(q("tls://" + u.Addr.String() + "@" + u.ServerName.String()))
	}
	b.WriteString("]\n[addrbook]\nretain = " + q(cfg.AddrBook.Retain.String()) + "\n")
	for _, p := range cfg.Policies {
		b.WriteString("[[policy]]\nname = " + q(string(p.Name)) + "\nto = [")
		for i, d := range p.To {
			if i > 0 {
				b.WriteString(", ")
			}
			switch d := d.(type) {
			case ExactDomain:
				b.WriteString(q(d.Domain().String()))
			case DomainSuffix:
				b.WriteString(q("*." + d.Domain().String()))
			case IPAddr:
				b.WriteString(q(d.Addr().String()))
			case CIDR:
				b.WriteString(q(d.Prefix().String()))
			default:
				b.WriteString(q("\x00unknown"))
			}
		}
		key, sels := "only_via", []InterfaceSelector(nil)
		switch c := p.Constraint.(type) {
		case OnlyVia:
			sels = c.Selectors()
		case DenyVia:
			key, sels = "deny_via", c.Selectors()
		default:
			key = "\x00unknown"
		}
		b.WriteString("]\n" + key + " = [")
		for i, s := range sels {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(q(selString(s)))
		}
		b.WriteString("]\n" + renderScope(p.Scope))
	}
	return b.String()
}

func renderScope(s Scope) string {
	if !s.Limited() {
		return ""
	}
	return "scope = { users = " + accountList(s.Users()) + ", groups = " + accountList(s.Groups()) + " }\n"
}

func accountList(as []Account) string {
	parts := make([]string, len(as))
	for i, a := range as {
		parts[i] = `"` + a.String() + `"`
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// TestOracleInvariantsOnAccepts runs the fuzz property over every accept

// fuzzSeeds are documents that reach the interesting branches. A plain
// `go test` runs each one through FuzzParse, so the invariants hold on
// every run, not only under -fuzz.
func fuzzSeeds() []string {
	return []string{
		dnsTable,
		// The upstream is IPv6, so the mapped prefix ::ffff:0:0/96 (all of
		// IPv4) does not hold it, and the seed passes the apply check.
		"[dns]\nupstream = [\"tls://[2001:db8::53]@a.b\"]\n" +
			policyDoc(`"a.com", "A.COM.", "*.a.com", "::ffff:1.2.3.4", "1.2.3.4", "::ffff:0:0/96", "0x7f000001"`, "only_via = []\n")[len(dnsTable):],
		policyDoc(`"1.1.1.0/24"`, "only_via = []\n"), // fails the apply check
		policyDoc(`"a.com"`, "only_via = [\"en0\", \"en0\", \"utun*\", \"@tunnel\"]\n"),
		policyDoc(`"203.0.113.77/24", "fe80::/10"`, "deny_via = [\"@hardware\"]\n"),
		policyDoc(`"a.com"`, "deny_via = [\"en0\"]\nscope = { users = [\"_a\", \"_a\"], groups = [\"staff\"] }\n"),
		dnsTable + "[addrbook]\nretain = \"+7d\"\n",
		"[dns]\nlisten = \"[::ffff:127.0.0.1]:53\"\nupstream = [\"tls://[::ffff:1.1.1.1]:0853@A.B.\"]\n",
		policyDoc(`"a.com"`, "only_via = []\n") + policyDoc(`"b.com"`, "only_via = []\n")[len(dnsTable):],
		dnsTable + "[[POLICY]]\nname = \"c\"\n",
		"policy = [1]\n" + dnsTable,
		"[dns\n",
		"",
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, doc string) {
		cfg, err := ParseBytes([]byte(doc))
		if err != nil {
			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("error is not a *FieldError: %v", err)
			}
			return
		}
		checkInvariants(t, cfg)
	})
}
