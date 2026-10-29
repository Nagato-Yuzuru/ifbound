package policy

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// upstreamDoc returns a config with one upstream and one policy.
func upstreamDoc(upstream, to, via string) string {
	return "[dns]\nupstream = [\"" + upstream + "\"]\n[[policy]]\nname = \"p\"\nto = [" + to + "]\n" + via + "\n"
}

// mustParse parses doc and fails the test on an error.
func mustParse(t *testing.T, doc string) Config {
	t.Helper()
	cfg, err := ParseBytes([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// assertUnreachable checks that Parse accepts doc and that CheckUpstreams
// rejects it at field. It returns the error text.
func assertUnreachable(t *testing.T, doc, field string) string {
	t.Helper()
	err := mustParse(t, doc).CheckUpstreams()
	var fe *FieldError
	if !errors.As(err, &fe) || fe.Field != field || !errors.Is(err, errUnreachable) {
		t.Fatalf("CheckUpstreams = %v, want a *FieldError at %q that wraps %q", err, field, errUnreachable)
	}
	return err.Error()
}

func TestUpstreamInBlockedPolicyIsAnError(t *testing.T) {
	tests := []struct {
		name     string
		upstream string
		to       string
	}{
		{"ipv4 in cidr", "tls://9.9.9.9@dns.quad9.net", `"9.9.9.0/24"`},
		{"ipv4 equals address", "tls://9.9.9.9@dns.quad9.net", `"9.9.9.9"`},
		{"ipv6 in cidr", "tls://[2620:fe::fe]@dns.quad9.net", `"2620:fe::/32"`},
		{"ipv6 equals address", "tls://[2620:fe::fe]:853@dns.quad9.net", `"2620:fe::fe"`},
		{"mapped ipv4 upstream in ipv4 cidr", "tls://[::ffff:9.9.9.9]@dns.quad9.net", `"9.0.0.0/8"`},
		{"second destination", "tls://9.9.9.9@dns.quad9.net", `"a.com", "9.9.9.9/32"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := upstreamDoc(tt.upstream, tt.to, "only_via = []")
			assertUnreachable(t, doc, "policy[0].to")
			if w := mustParse(t, doc).Warnings(); len(w) != 0 {
				t.Errorf("warnings = %v, want none: the fault is an error", w)
			}
		})
	}
}

func TestUpstreamInAllowingPolicyIsAWarning(t *testing.T) {
	tests := []struct {
		name     string
		upstream string
		to       string
		via      string
	}{
		{"only_via glob", "tls://9.9.9.9@dns.quad9.net", `"9.9.9.0/24"`, `only_via = ["utun*"]`},
		{"deny_via", "tls://9.9.9.9@dns.quad9.net", `"9.9.9.9"`, `deny_via = ["@hardware"]`},
		{"ipv6", "tls://[2620:fe::fe]@dns.quad9.net", `"2620:fe::/32"`, `only_via = ["utun*"]`},
		{"same prefix twice", "tls://9.9.9.9@dns.quad9.net", `"9.9.9.9", "9.9.9.9/32"`, `only_via = ["utun*"]`},
		{"exact server name, blocked", "tls://9.9.9.9@dns.quad9.net", `"dns.quad9.net"`, `only_via = []`},
		{"suffix of server name, blocked", "tls://9.9.9.9@dns.quad9.net", `"*.quad9.net"`, `only_via = []`},
		{"suffix at server name", "tls://9.9.9.9@dns.quad9.net", `"*.dns.quad9.net"`, `only_via = ["utun*"]`},
		{"server name in deny_via", "tls://9.9.9.9@dns.quad9.net", `"*.quad9.net"`, `deny_via = ["en0"]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := mustParse(t, upstreamDoc(tt.upstream, tt.to, tt.via))
			if err := cfg.CheckUpstreams(); err != nil {
				t.Errorf("CheckUpstreams = %v, want nil", err)
			}
			w := cfg.Warnings()
			if len(w) != 1 || w[0].Field != "policy[0].to" || !strings.Contains(w[0].Msg, `policy "p"`) {
				t.Errorf("warnings = %v, want one on policy[0].to that names policy \"p\"", w)
			}
		})
	}
}

func TestUpstreamOutsideDestinations(t *testing.T) {
	tests := []struct {
		name     string
		upstream string
		to       string
	}{
		{"other ipv4 prefix", "tls://9.9.9.9@dns.quad9.net", `"9.9.8.0/24", "9.9.9.10"`},
		{"ipv6 address next to the upstream", "tls://[2620:fe::fe]@dns.quad9.net", `"2620:fe::ff", "2620:fe::fd/128"`},
		{"ipv6 next to ipv4", "tls://[2620:fe::fe]@dns.quad9.net", `"0.0.0.0/0"`},
		{"ipv4 next to ipv6", "tls://9.9.9.9@dns.quad9.net", `"::/0"`},
		{"other domain", "tls://9.9.9.9@dns.quad9.net", `"quad9.net", "*.xdns.quad9.net", "*.ad9.net"`},
	}
	for _, tt := range tests {
		for _, via := range []string{"only_via = []", `only_via = ["utun*"]`} {
			t.Run(tt.name+"/"+via, func(t *testing.T) {
				cfg := mustParse(t, upstreamDoc(tt.upstream, tt.to, via))
				if err := cfg.CheckUpstreams(); err != nil {
					t.Errorf("CheckUpstreams = %v, want nil", err)
				}
				if w := cfg.Warnings(); len(w) != 0 {
					t.Errorf("warnings = %v, want none", w)
				}
			})
		}
	}
}

// TestUpstreamExampleWithBlockedUpstream changes the upstream of the RFC
// example to an address of the always-blocked policy "doh-servers". Parse
// accepts it: only the apply check rejects it.
func TestUpstreamExampleWithBlockedUpstream(t *testing.T) {
	const doc = `
[dns]
listen   = "127.0.0.1:10053"
upstream = ["tls://1.1.1.1@cloudflare-dns.com"]
[addrbook]
retain = "7d"
[[policy]]
name     = "bing"
to       = ["*.bing.com", "203.0.113.0/24"]
only_via = ["@tunnel"]
[[policy]]
name     = "doh-servers"
to       = ["1.1.1.1/32", "8.8.8.8/32"]
only_via = []
[[policy]]
name     = "build-bot"
to       = ["*.example.com"]
deny_via = ["@hardware"]
scope    = { users = ["_buildbot"] }
`
	got := assertUnreachable(t, doc, "policy[1].to")
	const want = `"policy[1].to": ifbound-dns can never reach an upstream: upstream 1.1.1.1 (dns.upstream[0]) is inside destination 1.1.1.1/32 of policy "doh-servers", which allows no interface`
	if got != want {
		t.Errorf("error\n got %s\nwant %s", got, want)
	}
}

// TestUnreachableNamesTheUpstream checks that with two upstreams, the
// error names the one that ifbound-dns cannot reach.
func TestUnreachableNamesTheUpstream(t *testing.T) {
	const doc = `
[dns]
upstream = ["tls://9.9.9.9@dns.quad9.net", "tls://149.112.112.112@dns.quad9.net"]
[[policy]]
name     = "p"
to       = ["149.112.112.112"]
only_via = []
`
	got := assertUnreachable(t, doc, "policy[0].to")
	if !strings.Contains(got, "upstream 149.112.112.112 (dns.upstream[1])") || strings.Contains(got, "9.9.9.9") {
		t.Errorf("error %s does not name only dns.upstream[1]", got)
	}
}

// TestWarningsInFileOrder checks the text and the order of the warnings.
func TestWarningsInFileOrder(t *testing.T) {
	const doc = `
[dns]
upstream = ["tls://9.9.9.9@dns.quad9.net", "tls://149.112.112.112@dns.quad9.net"]
[[policy]]
name     = "a"
to       = ["9.0.0.0/8", "149.112.0.0/16"]
only_via = ["@tunnel"]
[[policy]]
name     = "b"
to       = ["9.9.9.9", "9.9.9.9/32"]
deny_via = ["en0"]
[[policy]]
name     = "c"
to       = ["dns.quad9.net"]
only_via = []
[[policy]]
name     = "d"
to       = ["*.quad9.net"]
only_via = ["utun*"]
`
	var got []string
	for _, w := range mustParse(t, doc).Warnings() {
		got = append(got, w.String())
	}
	const allowed = "ifbound-dns reaches this upstream only through the interfaces that the policy allows"
	want := []string{
		`"policy[0].to": upstream 9.9.9.9 (dns.upstream[0]) is inside destination 9.0.0.0/8 of policy "a": ` + allowed,
		`"policy[0].to": upstream 149.112.112.112 (dns.upstream[1]) is inside destination 149.112.0.0/16 of policy "a": ` + allowed,
		`"policy[1].to": upstream 9.9.9.9 (dns.upstream[0]) is inside destination 9.9.9.9/32 of policy "b": ` + allowed,
		`"policy[2].to": server name dns.quad9.net of upstream 9.9.9.9 (dns.upstream[0]) is inside destination dns.quad9.net of policy "c", which allows no interface: a lookup of this name can block the upstream address, and ifbound-dns then cannot reach this upstream`,
		`"policy[2].to": server name dns.quad9.net of upstream 149.112.112.112 (dns.upstream[1]) is inside destination dns.quad9.net of policy "c", which allows no interface: a lookup of this name can block the upstream address, and ifbound-dns then cannot reach this upstream`,
		`"policy[3].to": server name dns.quad9.net of upstream 9.9.9.9 (dns.upstream[0]) is inside destination *.quad9.net of policy "d": a lookup of this name can add the upstream address to the policy, and ifbound-dns then reaches this upstream only through the interfaces that the policy allows`,
		`"policy[3].to": server name dns.quad9.net of upstream 149.112.112.112 (dns.upstream[1]) is inside destination *.quad9.net of policy "d": a lookup of this name can add the upstream address to the policy, and ifbound-dns then reaches this upstream only through the interfaces that the policy allows`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("warnings\n got %q\nwant %q", got, want)
	}
}

// TestUpstreamScopeAndComposition pins two choices. A scoped policy that
// allows no interface is still an error: a scope user that does not exist
// makes the policy apply to all traffic. Two policies that together allow
// no interface give only warnings: the check looks at one policy at a time.
func TestUpstreamScopeAndComposition(t *testing.T) {
	scoped := upstreamDoc("tls://9.9.9.9@dns.quad9.net", `"9.9.9.9"`, "only_via = []\nscope = { users = [\"_buildbot\"] }")
	assertUnreachable(t, scoped, "policy[0].to")

	const composed = `
[dns]
upstream = ["tls://9.9.9.9@dns.quad9.net"]
[[policy]]
name     = "a"
to       = ["9.9.9.9"]
only_via = ["en0"]
[[policy]]
name     = "b"
to       = ["9.9.9.9"]
deny_via = ["en0"]
`
	cfg := mustParse(t, composed)
	if err := cfg.CheckUpstreams(); err != nil {
		t.Errorf("CheckUpstreams = %v, want nil", err)
	}
	if w := cfg.Warnings(); len(w) != 2 {
		t.Errorf("warnings = %v, want two", w)
	}
}
