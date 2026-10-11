package policy

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

const dnsTable = "[dns]\nupstream = [\"tls://1.1.1.1@a.b\"]\n"

// policyDoc returns a config with one policy. Extra lines follow the
// name and to keys.
func policyDoc(to, extra string) string {
	return dnsTable + "[[policy]]\nname = \"p\"\nto = [" + to + "]\n" + extra
}

func mustDest(t *testing.T, s string) Destination {
	t.Helper()
	d, err := ParseDestination(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mustSel(t *testing.T, s string) InterfaceSelector {
	t.Helper()
	d, err := ParseInterfaceSelector(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mustDomain(t *testing.T, s string) Domain {
	t.Helper()
	d, err := ParseDomain(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestParseExample parses the RFC example without its third policy's
// scope key. Scope is out of scope for this ticket: see
// TestParseRejectsRFCScope. The third policy keeps its deny_via.
func TestParseExample(t *testing.T) {
	const doc = `
[dns]
listen   = "127.0.0.1:53553"
upstream = ["tls://1.1.1.1@cloudflare-dns.com", "tls://1.0.0.1@cloudflare-dns.com"]

[addrbook]
retain = "7d"

[[policy]]
name     = "bing"
to       = ["*.bing.com", "203.0.113.0/24"]
only_via = ["@tunnel"]

[[policy]]
name     = "doh-servers"
to       = ["1.1.1.1/32", "8.8.8.8/32"]
only_via = []            # no allowed interface: always blocked

[[policy]]
name     = "build-bot"
to       = ["*.example.com"]
deny_via = ["@hardware"]
`
	got, err := ParseBytes([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	// The expected values are literals, so that a fault in the parser
	// cannot also change the expectation.
	hw := InterfaceClass{class: ClassHardware}
	tun := InterfaceClass{class: ClassTunnel}
	want := Config{
		DNS: DNS{
			Listen: netip.MustParseAddrPort("127.0.0.1:53553"),
			Upstream: []Upstream{
				{Addr: netip.MustParseAddrPort("1.1.1.1:853"), ServerName: Domain{s: "cloudflare-dns.com"}},
				{Addr: netip.MustParseAddrPort("1.0.0.1:853"), ServerName: Domain{s: "cloudflare-dns.com"}},
			},
		},
		AddrBook: AddrBook{Retain: 7 * 24 * time.Hour},
		Policies: []Policy{
			{
				Name: "bing",
				To: []Destination{
					DomainSuffix{domain: Domain{s: "bing.com"}},
					CIDR{prefix: netip.MustParsePrefix("203.0.113.0/24")},
				},
				Constraint: OnlyVia{selectors: []InterfaceSelector{tun}},
			},
			{
				Name: "doh-servers",
				To: []Destination{
					CIDR{prefix: netip.MustParsePrefix("1.1.1.1/32")},
					CIDR{prefix: netip.MustParsePrefix("8.8.8.8/32")},
				},
				Constraint: OnlyVia{},
			},
			{
				Name:       "build-bot",
				To:         []Destination{DomainSuffix{domain: Domain{s: "example.com"}}},
				Constraint: DenyVia{selectors: []InterfaceSelector{hw}},
			},
		},
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("config mismatch\nwant %#v\n got %#v", want, got)
	}
	if !got.Policies[1].Constraint.Equal(NewOnlyVia()) || got.Policies[1].Constraint.Equal(want.Policies[2].Constraint) {
		t.Error("Equal gives a wrong answer")
	}
}

// TestParseRejectsRFCScope uses the RFC example verbatim, with scope.
func TestParseRejectsRFCScope(t *testing.T) {
	const doc = dnsTable + `
[[policy]]
name     = "build-bot"
to       = ["*.example.com"]
deny_via = ["@hardware"]
scope    = { users = ["_buildbot"] }
`
	assertFieldErr(t, doc, "policy[0].scope", errUnknownKey)
}

func TestParseDefaults(t *testing.T) {
	cfg, err := ParseBytes([]byte("[dns]\nupstream = [\"tls://[2606:4700:4700::1111]@one.one.one.one\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Literals, not the constants: the test pins the documented defaults.
	if cfg.DNS.Listen != netip.MustParseAddrPort("127.0.0.1:53553") {
		t.Errorf("listen = %v", cfg.DNS.Listen)
	}
	if cfg.AddrBook.Retain != 168*time.Hour {
		t.Errorf("retain = %v", cfg.AddrBook.Retain)
	}
	if want := netip.MustParseAddrPort("[2606:4700:4700::1111]:853"); cfg.DNS.Upstream[0].Addr != want {
		t.Errorf("upstream addr = %v", cfg.DNS.Upstream[0].Addr)
	}
}

func TestParseUpstreamPort(t *testing.T) {
	cfg, err := ParseBytes([]byte("[dns]\nupstream = [\"tls://9.9.9.9:8853@dns.quad9.net\", \"tls://[::1]:1853@local\", \"tls://[::1]@local\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []uint16{8853, 1853, 853} {
		if got := cfg.DNS.Upstream[i].Addr.Port(); got != want {
			t.Errorf("upstream[%d] port = %d, want %d", i, got, want)
		}
	}
}

func TestParseRetain(t *testing.T) {
	tests := map[string]time.Duration{
		"1d": 24 * time.Hour, "36h": 36 * time.Hour, "90m": 90 * time.Minute,
		"106751d": 106751 * 24 * time.Hour, // the largest whole-day count
	}
	for in, want := range tests {
		cfg, err := ParseBytes([]byte(dnsTable + "[addrbook]\nretain = \"" + in + "\"\n"))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if cfg.AddrBook.Retain != want {
			t.Errorf("%s: got %v, want %v", in, cfg.AddrBook.Retain, want)
		}
	}
}

func TestParseNormalizes(t *testing.T) {
	cfg, err := ParseBytes([]byte(policyDoc(
		`"A.COM.", "a.com", "*.A.com", "203.0.113.77/24", "::ffff:1.2.3.4", "::ffff:1.2.3.0/120", "1.2.3.4"`,
		"only_via = []\n")))
	if err != nil {
		t.Fatal(err)
	}
	want := []Destination{
		mustDest(t, "a.com"), mustDest(t, "*.a.com"),
		CIDR{prefix: netip.MustParsePrefix("203.0.113.0/24")},
		IPAddr{addr: netip.MustParseAddr("1.2.3.4")},
		CIDR{prefix: netip.MustParsePrefix("1.2.3.0/24")},
	}
	// "1.2.3.4" duplicates the unmapped "::ffff:1.2.3.4" and drops out.
	if got := cfg.Policies[0].To; !reflect.DeepEqual(got, want) {
		t.Errorf("destinations\nwant %#v\n got %#v", want, got)
	}
}

func TestParseDenyViaWithoutScope(t *testing.T) {
	cfg, err := ParseBytes([]byte(policyDoc(`"x.example"`, "deny_via = [\"@hardware\"]\n")))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Policies[0].Constraint.(DenyVia); !ok {
		t.Errorf("constraint = %T", cfg.Policies[0].Constraint)
	}
}

// assertFieldErr checks that Parse fails with a *FieldError at exactly
// field and wrapping reason.
func assertFieldErr(t *testing.T, doc, field string, reason error) {
	t.Helper()
	_, err := ParseBytes([]byte(doc))
	if err == nil {
		t.Fatal("want error, got nil")
	}
	var fe *FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("error %q is not a *FieldError", err)
	}
	if fe.Field != field {
		t.Errorf("field = %q, want %q (error: %v)", fe.Field, field, err)
	}
	if !errors.Is(err, reason) {
		t.Errorf("error %q does not wrap %q", err, reason)
	}
}

func TestParseRejects(t *testing.T) {
	const viaOK = "only_via = []\n"
	pol := func(to, extra string) string { return policyDoc(to, extra) }
	tests := []struct {
		name   string
		input  string
		field  string
		reason error
	}{
		// Unknown keys and key spelling.
		{"unknown key in dns", dnsTable + "bogus = 1\n", "dns.bogus", errUnknownKey},
		{"unknown key in addrbook", dnsTable + "[addrbook]\nkeep = 1\n", "addrbook.keep", errUnknownKey},
		{"unknown key in policy", pol(`"a.com"`, viaOK+"bogus = 1\n"), "policy[0].bogus", errUnknownKey},
		{"unknown top-level table", dnsTable + "[foo]\nx = 1\n", "foo", errUnknownKey},
		{"unknown dns subtable", dnsTable + "[dns.extra]\nx = 1\n", "dns.extra", errUnknownKey},
		{"scope subtable", pol(`"a.com"`, viaOK+"[policy.scope]\nusers = [\"x\"]\n"), "policy[0].scope", errUnknownKey},
		{"quoted spelling of scope", pol(`"a.com"`, viaOK+"\"sc\\u006fpe\" = 1\n"), "policy[0].scope", errUnknownKey},
		{"upper-case table", "[DNS]\nupstream = [\"tls://1.1.1.1@a.b\"]\n", "DNS", errUnknownKey},
		{"upper-case dns key", "[dns]\nUPSTREAM = [\"tls://1.1.1.1@a.b\"]\n", "dns.UPSTREAM", errUnknownKey},
		{"second dns table by case", dnsTable + "[DNS]\nupstream = [\"tls://9.9.9.9@evil.example\"]\n", "DNS", errUnknownKey},
		{"case-variant policy table", pol(`"a.com"`, viaOK) + "[[POLICY]]\nname = \"c\"\nto = [\"c.com\"]\nonly_via = []\n", "POLICY", errUnknownKey},
		{"case-variant to key", pol(`"a.com"`, viaOK+"TO = [\"b.com\"]\n"), "policy[0].TO", errUnknownKey},
		{"case-variant name key", pol(`"a.com"`, viaOK+"NAME = \"q\"\n"), "policy[0].NAME", errUnknownKey},
		{"case-variant deny_via key", pol(`"a.com"`, "deny_via = [\"en0\"]\nDeny_Via = [\"en1\"]\n"), "policy[0].Deny_Via", errUnknownKey},
		{"single policy table", dnsTable + "[policy]\nname = \"p\"\nto = [\"a.com\"]\nonly_via = []\n", "policy", errPolicyShape},
		{"policy is a string", "policy = \"x\"\n" + dnsTable, "policy", errPolicyShape},
		{"inline unknown key", "policy = [{name=\"p\", to=[\"a.com\"], only_via=[], scope=1}]\n" + dnsTable, "policy[0].scope", errUnknownKey},
		// Types and syntax.
		{"wrong type", dnsTable + "[addrbook]\nretain = 5\n", "addrbook.retain", errSyntax},
		{"syntax error", "[dns\n", "", errSyntax},
		// [dns].
		{"no upstream", "[dns]\n", "dns.upstream", errUpstreamEmpty},
		{"non-tls upstream", "[dns]\nupstream = [\"udp://1.1.1.1@a.b\"]\n", "dns.upstream[0]", errUpstreamForm},
		{"upstream without server name", "[dns]\nupstream = [\"tls://1.1.1.1\"]\n", "dns.upstream[0]", errUpstreamForm},
		{"upstream hostname", "[dns]\nupstream = [\"tls://dns.example@a.b\"]\n", "dns.upstream[0]", errBadAddress},
		{"upstream bare ipv6", "[dns]\nupstream = [\"tls://::1@a.b\"]\n", "dns.upstream[0]", errBadAddress},
		{"upstream bracketed ipv4", "[dns]\nupstream = [\"tls://[1.1.1.1]@a.b\"]\n", "dns.upstream[0]", errBadAddress},
		{"upstream double bracket", "[dns]\nupstream = [\"tls://[[::1]]@a.b\"]\n", "dns.upstream[0]", errBadAddress},
		{"upstream stray bracket", "[dns]\nupstream = [\"tls://1.1.1.1]@a.b\"]\n", "dns.upstream[0]", errBadAddress},
		{"upstream port zero", "[dns]\nupstream = [\"tls://1.1.1.1:0@a.b\"]\n", "dns.upstream[0]", errPortZero},
		{"upstream zoned", "[dns]\nupstream = [\"tls://[fe80::1%en0]@a.b\"]\n", "dns.upstream[0]", errZoned},
		{"upstream wildcard name", "[dns]\nupstream = [\"tls://1.1.1.1@*.a.b\"]\n", "dns.upstream[0]", errBadDomain},
		{"upstream name with brace", "[dns]\nupstream = [\"tls://1.1.1.1@a.b}\"]\n", "dns.upstream[0]", errBadDomain},
		{"upstream name with port", "[dns]\nupstream = [\"tls://1.1.1.1@a.b:853\"]\n", "dns.upstream[0]", errBadDomain},
		{"upstream name is an address", "[dns]\nupstream = [\"tls://1.1.1.1@1.1.1.1\"]\n", "dns.upstream[0]", errBadDomain},
		{"bad listen", "[dns]\nlisten = \"nope\"\nupstream = [\"tls://1.1.1.1@a.b\"]\n", "dns.listen", errBadAddress},
		{"listen port zero", "[dns]\nlisten = \"127.0.0.1:0\"\nupstream = [\"tls://1.1.1.1@a.b\"]\n", "dns.listen", errPortZero},
		{"listen zoned", "[dns]\nlisten = \"[fe80::1%en0]:53\"\nupstream = [\"tls://1.1.1.1@a.b\"]\n", "dns.listen", errZoned},
		// [addrbook].
		{"bad retain", dnsTable + "[addrbook]\nretain = \"soon\"\n", "addrbook.retain", errBadDuration},
		{"zero retain", dnsTable + "[addrbook]\nretain = \"0s\"\n", "addrbook.retain", errNotPositive},
		{"negative retain", dnsTable + "[addrbook]\nretain = \"-1d\"\n", "addrbook.retain", errNotPositive},
		{"retain day overflow", dnsTable + "[addrbook]\nretain = \"106752d\"\n", "addrbook.retain", errBadDuration},
		{"retain leading space", dnsTable + "[addrbook]\nretain = \" 7d\"\n", "addrbook.retain", errBadDuration},
		{"retain inner space", dnsTable + "[addrbook]\nretain = \"7 d\"\n", "addrbook.retain", errBadDuration},
		{"retain fraction of day", dnsTable + "[addrbook]\nretain = \"1.5d\"\n", "addrbook.retain", errBadDuration},
		// Duplicate keys: the full path comes from the token stream.
		{"duplicate to", dnsTable + "[[policy]]\nname = \"p\"\nto = [\"a.com\"]\nto = [\"b.com\"]\nonly_via = []\n", "policy[0].to", errSyntax},
		{"duplicate to in second policy", pol(`"a.com"`, viaOK) + "[[policy]]\nname = \"q\"\nto = [\"b.com\"]\nto = [\"c.com\"]\nonly_via = []\n", "policy[1].to", errSyntax},
		{"duplicate listen", "[dns]\nlisten = \"127.0.0.1:1\"\nlisten = \"127.0.0.1:2\"\nupstream = [\"tls://1.1.1.1@a.b\"]\n", "dns.listen", errSyntax},
		// Value types: the path has the array indices.
		{"to mixes string and int", pol(`"a.com"`, viaOK) + "[[policy]]\nname = \"q\"\nto = [\"b.com\", 1]\nonly_via = []\n", "policy[1].to[1]", errSyntax},
		{"name is an int", dnsTable + "[[policy]]\nname = 1\nto = [\"a.com\"]\nonly_via = []\n", "policy[0].name", errSyntax},
		{"name is an int in second policy", pol(`"a.com"`, viaOK) + "[[policy]]\nname = 1\nto = [\"b.com\"]\nonly_via = []\n", "policy[1].name", errSyntax},
		{"to is a string", dnsTable + "[[policy]]\nname = \"p\"\nto = \"a.com\"\nonly_via = []\n", "policy[0].to", errSyntax},
		{"only_via holds a table", pol(`"a.com"`, "only_via = [{}]\n"), "policy[0].only_via[0]", errSyntax},
		{"only_via is a table", dnsTable + "[[policy]]\nname = \"p\"\nto = [\"a.com\"]\n[policy.only_via]\n", "policy[0].only_via", errSyntax},
		{"policy array holds an int", "policy = [1]\n" + dnsTable, "policy[0]", errSyntax},
		{"policy array mixes table and int", "policy = [{name=\"p\", to=[\"a.com\"], only_via=[]}, 1]\n" + dnsTable, "policy[1]", errSyntax},
		{"listen is an int", "[dns]\nlisten = 53\nupstream = [\"tls://1.1.1.1@a.b\"]\n", "dns.listen", errSyntax},
		{"upstream holds an int", "[dns]\nupstream = [\"tls://1.1.1.1@a.b\", 1]\n", "dns.upstream[1]", errSyntax},
		{"dns is not a table", "dns = 1\n", "dns", errSyntax},
		// Unknown keys, more shapes.
		{"unknown key in inline addrbook", "addrbook = { RETAIN = \"1d\" }\n" + dnsTable, "addrbook.RETAIN", errUnknownKey},
		{"three unknown keys: first in order", "[dns]\nzz = 1\naa = 1\nmm = 1\nupstream = [\"tls://1.1.1.1@a.b\"]\n", "dns.aa", errUnknownKey},
		{"second upstream bad", "[dns]\nupstream = [\"tls://1.1.1.1@a.b\", \"tls://x@a.b\"]\n", "dns.upstream[1]", errBadAddress},
		// Domains: names with look-alike or non-ASCII characters.
		{"Kelvin sign", pol(`"\u212Aey.com"`, viaOK), "policy[0].to[0]", errNonASCII},
		{"dotted capital I", pol(`"a.com\u0130"`, viaOK), "policy[0].to[0]", errNonASCII},
		{"digit last label", pol(`"a.123"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"name with dot", dnsTable + "[[policy]]\nname = \"a.b\"\nto = [\"a.com\"]\nonly_via = []\n", "policy[0].name", errBadName},
		{"name leading underscore", dnsTable + "[[policy]]\nname = \"_p\"\nto = [\"a.com\"]\nonly_via = []\n", "policy[0].name", errBadName},
		{"domain of 254 bytes", pol(`"`+longDomain(254)+`"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"retain below the day bound", dnsTable + "[addrbook]\nretain = \"-106752d\"\n", "addrbook.retain", errBadDuration},
		{"retain hex", dnsTable + "[addrbook]\nretain = \"0x7d\"\n", "addrbook.retain", errBadDuration},
		{"retain underscore", dnsTable + "[addrbook]\nretain = \"1_0d\"\n", "addrbook.retain", errBadDuration},
		// Policy shape.
		{"both via", pol(`"a.com"`, "only_via = []\ndeny_via = [\"en0\"]\n"), "policy[0].only_via/deny_via", errViaConflict},
		{"neither via", pol(`"a.com"`, ""), "policy[0].only_via/deny_via", errViaConflict},
		{"empty deny_via", pol(`"a.com"`, "deny_via = []\n"), "policy[0].deny_via", errDenyEmpty},
		{"empty name", dnsTable + "[[policy]]\nname = \"\"\nto = [\"a.com\"]\nonly_via = []\n", "policy[0].name", errBadName},
		{"missing name", dnsTable + "[[policy]]\nto = [\"a.com\"]\nonly_via = []\n", "policy[0].name", errBadName},
		{"upper-case name", dnsTable + "[[policy]]\nname = \"P\"\nto = [\"a.com\"]\nonly_via = []\n", "policy[0].name", errBadName},
		{"name with quote", dnsTable + "[[policy]]\nname = \"x\\\" { pass all }\"\nto = [\"a.com\"]\nonly_via = []\n", "policy[0].name", errBadName},
		{"name with newline", dnsTable + "[[policy]]\nname = \"p\\nq\"\nto = [\"a.com\"]\nonly_via = []\n", "policy[0].name", errBadName},
		{"name leading dash", dnsTable + "[[policy]]\nname = \"-p\"\nto = [\"a.com\"]\nonly_via = []\n", "policy[0].name", errBadName},
		{"name too long", dnsTable + "[[policy]]\nname = \"" + strings.Repeat("a", 25) + "\"\nto = [\"a.com\"]\nonly_via = []\n", "policy[0].name", errBadName},
		{"duplicate name", pol(`"a.com"`, viaOK) + pol(`"a.com"`, viaOK)[len(dnsTable):], "policy[1].name", errNameDuplicate},
		{"empty to", pol(``, viaOK), "policy[0].to", errToEmpty},
		// Destinations.
		{"non-ASCII domain", pol(`"bücher.de"`, viaOK), "policy[0].to[0]", errNonASCII},
		{"wildcard in the middle", pol(`"a.*.com"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"bare wildcard", pol(`"*"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"wildcard only suffix marker", pol(`"*."`, viaOK), "policy[0].to[0]", errBadDomain},
		{"double wildcard", pol(`"*.*.com"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"two trailing dots", pol(`"example.com.."`, viaOK), "policy[0].to[0]", errBadDomain},
		{"double dot inside", pol(`"a..com"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"leading dot", pol(`".x.com"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"digit tld with dot", pol(`"1.2.3.4."`, viaOK), "policy[0].to[0]", errBadDomain},
		{"leading-zero address", pol(`"1.1.1.01"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"short dotted number", pol(`"1.2.3"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"bracketed v6", pol(`"[2001:db8::1]"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"address with port", pol(`"1.2.3.4:443"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"control char", pol(`"a\u0000b.com"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"del char", pol(`"a\u007fb.com"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"newline", pol(`"a.com\n"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"question mark", pol(`"a?.com"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"space", pol(`"a b.com"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"leading dash label", pol(`"-a.com"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"trailing dash label", pol(`"a-.com"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"long label", pol(`"`+strings.Repeat("a", 64)+`.com"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"long name", pol(`"`+strings.Repeat("a.", 127)+`com"`, viaOK), "policy[0].to[0]", errBadDomain},
		{"bad prefix", pol(`"1.2.3.4/99"`, viaOK), "policy[0].to[0]", errBadDestination},
		{"zoned address", pol(`"fe80::1%en0"`, viaOK), "policy[0].to[0]", errZoned},
		{"zoned prefix", pol(`"fe80::1%en0/64"`, viaOK), "policy[0].to[0]", errBadDestination},
		{"short mapped prefix", pol(`"::ffff:0:0/80"`, viaOK), "policy[0].to[0]", errMappedPrefix},
		{"second destination bad", pol(`"a.com", "b?.com"`, viaOK), "policy[0].to[1]", errBadDomain},
		// Selectors.
		{"unknown class", pol(`"a.com"`, "only_via = [\"@foo\"]\n"), "policy[0].only_via[0]", errUnknownClass},
		{"upper-case class", pol(`"a.com"`, "only_via = [\"@Tunnel\"]\n"), "policy[0].only_via[0]", errUnknownClass},
		{"empty selector", pol(`"a.com"`, "only_via = [\"\"]\n"), "policy[0].only_via[0]", errBadSelector},
		{"bad glob", pol(`"a.com"`, "only_via = [\"utun[\"]\n"), "policy[0].only_via[0]", errBadSelector},
		{"negated name", pol(`"a.com"`, "deny_via = [\"en0\", \"!en0\"]\n"), "policy[0].deny_via[1]", errBadSelector},
		{"parenthesized name", pol(`"a.com"`, "only_via = [\"(en0)\"]\n"), "policy[0].only_via[0]", errBadSelector},
		{"colon name", pol(`"a.com"`, "only_via = [\"en0:network\"]\n"), "policy[0].only_via[0]", errBadSelector},
		{"trailing space name", pol(`"a.com"`, "only_via = [\"en0 \"]\n"), "policy[0].only_via[0]", errBadSelector},
		{"slash name", pol(`"a.com"`, "only_via = [\"a/b\"]\n"), "policy[0].only_via[0]", errBadSelector},
		{"leading dash name", pol(`"a.com"`, "only_via = [\"-en0\"]\n"), "policy[0].only_via[0]", errBadSelector},
		{"long name", pol(`"a.com"`, "only_via = [\""+strings.Repeat("e", 16)+"\"]\n"), "policy[0].only_via[0]", errBadSelector},
		{"glob with brace", pol(`"a.com"`, "only_via = [\"{en0}*\"]\n"), "policy[0].only_via[0]", errBadSelector},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { assertFieldErr(t, tt.input, tt.field, tt.reason) })
	}
}

func TestParseAcceptsBoundaries(t *testing.T) {
	long := strings.Repeat("e", 15)
	label := strings.Repeat("a", 63)
	doc := policyDoc(`"`+label+`.com", "a_b.example", "2001:db8::1", "fe80::/10"`,
		"only_via = [\""+long+"\", \"utun*\", \"en[0-9]\", \"bridge0.1\"]\n")
	if _, err := ParseBytes([]byte(doc)); err != nil {
		t.Fatal(err)
	}
	nameDoc := dnsTable + "[[policy]]\nname = \"" + strings.Repeat("a", 24) + "\"\nto = [\"a.com\"]\nonly_via = []\n"
	if _, err := ParseBytes([]byte(nameDoc)); err != nil {
		t.Fatal(err)
	}
}

func TestParseCaseVariantsDoNotReplace(t *testing.T) {
	// The decoder alone would drop policies a and b and keep c.
	pol := func(hdr, n string) string {
		return hdr + "\nname = \"" + n + "\"\nto = [\"" + n + ".com\"]\nonly_via = [\"@tunnel\"]\n"
	}
	doc := dnsTable + pol("[[policy]]", "a") + pol("[[policy]]", "b") + pol("[[POLICY]]", "c")
	assertFieldErr(t, doc, "POLICY", errUnknownKey)
}

func TestParseReadError(t *testing.T) {
	boom := errors.New("boom")
	_, err := Parse(iotest.ErrReader(boom))
	if !errors.Is(err, boom) {
		t.Fatalf("error %v does not wrap the read error", err)
	}
	var fe *FieldError
	if errors.As(err, &fe) {
		t.Errorf("a read error must not be a FieldError: %v", err)
	}
}

func TestFieldErrorMessage(t *testing.T) {
	_, err := ParseBytes([]byte("[dns\n"))
	if err == nil || strings.HasPrefix(err.Error(), ":") {
		t.Errorf("message has an empty field prefix: %v", err)
	}
}

// longDomain returns a valid-looking domain of exactly n bytes, built
// from labels of at most 63 bytes. The last label has a letter.
func longDomain(n int) string {
	var parts []string
	for n > 0 {
		l := min(63, n)
		if n-l == 1 { // a label of one byte must follow a dot, not stand alone
			l--
		}
		parts = append(parts, strings.Repeat("a", l))
		n -= l + 1
	}
	return strings.Join(parts, ".")
}

func TestParseDomainLengths(t *testing.T) {
	for _, s := range []string{longDomain(253), longDomain(253) + ".", "Key.com", "1.2.3.a"} {
		if _, err := ParseDomain(s); err != nil {
			t.Errorf("ParseDomain(%.20q...) = %v", s, err)
		}
	}
	if got := len(longDomain(253)); got != 253 {
		t.Fatalf("test helper builds %d bytes, want 253", got)
	}
}

func TestParseSelectorLiterals(t *testing.T) {
	cfg, err := ParseBytes([]byte(policyDoc(`"a.com"`, "only_via = [\"@tunnel\", \"@hardware\", \"en0\", \"utun*\", \"en0\"]\n")))
	if err != nil {
		t.Fatal(err)
	}
	// Literals: swapping the two classes must fail this test. The second
	// "en0" is a duplicate and drops out.
	want := OnlyVia{selectors: []InterfaceSelector{
		InterfaceClass{class: ClassTunnel},
		InterfaceClass{class: ClassHardware},
		InterfaceName{name: "en0"},
		InterfaceGlob{pattern: "utun*"},
	}}
	if !reflect.DeepEqual(cfg.Policies[0].Constraint, want) {
		t.Errorf("constraint\nwant %#v\n got %#v", want, cfg.Policies[0].Constraint)
	}
}

func TestParseMappedZeroPrefix(t *testing.T) {
	d, err := ParseDestination("::ffff:0:0/96")
	if err != nil {
		t.Fatal(err)
	}
	if want := (CIDR{prefix: netip.MustParsePrefix("0.0.0.0/0")}); d != want {
		t.Errorf("got %#v, want %#v", d, want)
	}
}

func TestFieldErrorQuotesPath(t *testing.T) {
	_, err := ParseBytes([]byte("\"a\\nb\" = 1\n" + dnsTable))
	if err == nil {
		t.Fatal("want error")
	}
	if strings.ContainsAny(err.Error(), "\n\x00") {
		t.Errorf("message holds a raw control byte: %q", err.Error())
	}
}

func TestConstraintAliasing(t *testing.T) {
	in := []InterfaceSelector{mustSel(t, "en0")}
	c := NewOnlyVia(in...)
	in[0] = mustSel(t, "en1")
	got := c.Selectors()
	got[0] = mustSel(t, "en2")
	if !c.Equal(NewOnlyVia(mustSel(t, "en0"))) {
		t.Error("a caller changed the constraint through a slice")
	}
	d, err := NewDenyVia(mustSel(t, "en0"))
	if err != nil {
		t.Fatal(err)
	}
	d.Selectors()[0] = mustSel(t, "en1")
	if want, _ := NewDenyVia(mustSel(t, "en0")); !d.Equal(want) {
		t.Error("a caller changed the deny constraint through Selectors")
	}
}

func TestConstraintEqual(t *testing.T) {
	a, b := mustSel(t, "en0"), mustSel(t, "en1")
	deny, err := NewDenyVia(a, b)
	if err != nil {
		t.Fatal(err)
	}
	denyRev, _ := NewDenyVia(b, a)
	tests := []struct {
		name string
		x, y Constraint
		want bool
	}{
		{"same only", NewOnlyVia(a, b), NewOnlyVia(a, b), true},
		{"other order", NewOnlyVia(a, b), NewOnlyVia(b, a), false},
		{"other length", NewOnlyVia(a), NewOnlyVia(a, b), false},
		{"only and deny", NewOnlyVia(a, b), deny, false},
		{"deny and only", deny, NewOnlyVia(a, b), false},
		{"same deny", deny, deny, true},
		{"deny other order", deny, denyRev, false},
		{"empty only", NewOnlyVia(), OnlyVia{}, true},
	}
	for _, tt := range tests {
		if got := tt.x.Equal(tt.y); got != tt.want {
			t.Errorf("%s: Equal = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestConstraintConstructors(t *testing.T) {
	if _, err := NewDenyVia(); !errors.Is(err, errDenyEmpty) {
		t.Errorf("NewDenyVia() error = %v", err)
	}
	// Equal replaces ==, which panics on a Constraint that holds slices.
	a, b := NewOnlyVia(mustSel(t, "en0")), NewOnlyVia(mustSel(t, "en0"))
	if !a.Equal(b) || a.Equal(NewOnlyVia(mustSel(t, "en1"))) {
		t.Error("Equal gives a wrong answer")
	}
}
