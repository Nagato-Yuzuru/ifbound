package pfbackend

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// The outputs below are captured from pfctl on macOS 27.0 (26A428) in a
// tart guest.

// capturedRuleset is "pfctl -a com.apple/000.ifbound/* -sr" after a load
// of a pfrules ruleset with a sentinel. The kernel expands the interface
// list, removes the quotes, and reorders the quick blocks.
const capturedRuleset = `anchor "tag.bing" out on utun4 from any to <bing> tag ifbound.bing {
}
anchor "tag.bing" out on utun5 from any to <bing> tag ifbound.bing {
}
block return-icmp(port-unr, port-unr) out quick from any to <doh>
block return-icmp(port-unr, port-unr) out quick from any to <doh> user = 299
block return-icmp(port-unr, port-unr) out quick from any to <bing> ! tagged ifbound.bing
block drop out quick all label "ifbound-ruleset:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" tagged ifbound-id
block drop out quick all label "ifbound-token:13772037947654164677.1793350000" tagged ifbound-id
`

// capturedForeign is the same anchor after another tool loaded rules into
// a sub-anchor, also a nested one.
const capturedForeign = `anchor "tag.bing" out on utun4 from any to <bing> tag ifbound.bing {
  anchor "z" all {
    pass out quick all no state
  }
}
block drop out quick all label "ifbound-ruleset:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" tagged ifbound-id
`

const zeroID = "0000000000000000000000000000000000000000000000000000000000000000"

func TestParseRuleset(t *testing.T) {
	other := "ifbound-ruleset:" + strings.Repeat("_", 43)
	tests := []struct {
		name string
		out  string
		want string
	}{
		{"captured", capturedRuleset, zeroID},
		{"rule in a sub-anchor", capturedForeign, ""},
		{"pass rule at the top level", "pass out quick all no state\n" + capturedRuleset, ""},
		{"block rule at the top level", "block drop out quick from any to 192.0.2.77\n" + capturedRuleset, zeroID},
		{"no sentinel", "block drop out quick all\n", ""},
		{"empty anchor", "", ""},
		{"two sentinels", capturedRuleset + `block drop out quick all label "` + other + `"` + "\n", ""},
		{"label too short", `block drop out quick all label "ifbound-ruleset:AAAA"` + "\n", ""},
		{"label not base64url", `block drop out quick all label "ifbound-ruleset:` + strings.Repeat("+", 43) + `"` + "\n", ""},
		{"label without end quote", `block drop out quick all label "ifbound-ruleset:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` + "\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := parseRuleset([]byte(tt.out)); got != tt.want {
				t.Errorf("parseRuleset = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSentinelRoundTrip(t *testing.T) {
	id := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	s, err := sentinel(id)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, `tagged "ifbound-id"`) {
		t.Errorf("sentinel %q does not match on the sentinel tag only", s)
	}
	label, _, _ := strings.Cut(strings.SplitN(s, `label "`, 2)[1], `"`)
	if len(label) > 63 {
		t.Errorf("label %q has %d bytes, pf takes at most 63", label, len(label))
	}
	if got, _ := parseRuleset([]byte(s)); got != id {
		t.Errorf("ID read back from %q = %q, want %q", s, got, id)
	}
	for _, bad := range []string{"", "xyz", id[:62], id + "00"} {
		if _, err := sentinel(bad); !errors.Is(err, errRulesetID) {
			t.Errorf("sentinel(%q) error = %v, want errRulesetID", bad, err)
		}
	}
}

func TestTokenRoundTrip(t *testing.T) {
	tok := token{value: "18446744073709551615", created: 9999999999}
	r := tokenRule(tok)
	if label, _, _ := strings.Cut(strings.SplitN(r, `label "`, 2)[1], `"`); len(label) > 63 {
		t.Errorf("label %q has %d bytes, pf takes at most 63", label, len(label))
	}
	if _, got := parseRuleset([]byte(r)); !slices.Equal(got, []token{tok}) {
		t.Errorf("tokens read back from %q = %v, want %v", r, got, tok)
	}
	want := []token{{value: "13772037947654164677", created: 1793350000}}
	if _, got := parseRuleset([]byte(capturedRuleset)); !slices.Equal(got, want) {
		t.Errorf("tokens read back from the captured ruleset = %v, want %v", got, want)
	}
	two := capturedRuleset + `block drop out quick all label "ifbound-token:1.2" tagged ifbound-id` + "\n"
	if _, got := parseRuleset([]byte(two)); len(got) != 2 {
		t.Errorf("tokens read back from two token rules = %v, want two", got)
	}
	for _, out := range []string{
		"",
		`block drop out quick all label "ifbound-token:13772037947654164677" tagged ifbound-id` + "\n",
		`block drop out quick all label "ifbound-token:12x.5" tagged ifbound-id` + "\n",
		`block drop out quick all label "ifbound-token:12.x" tagged ifbound-id` + "\n",
		`block drop out quick all label "ifbound-token:.5" tagged ifbound-id` + "\n",
		`block drop out quick all label "ifbound-token:" tagged ifbound-id` + "\n",
	} {
		if _, got := parseRuleset([]byte(out)); len(got) != 0 {
			t.Errorf("tokens read back from %q = %v, want none", out, got)
		}
	}
}

// capturedReferences is "pfctl -s References" with two references, 8 s
// after the first "pfctl -E".
const capturedReferences = `TOKENS:
PID      Process Name                 TOKEN                    TIMESTAMP
796      pfctl                        3634474195142116324      0 days 00:00:05
792      pfctl                        9418272877687921726      0 days 00:00:08
`

func TestParseReferences(t *testing.T) {
	now := time.Unix(1793350000, 0)
	want := []token{
		{value: "3634474195142116324", created: 1793350000 - 5},
		{value: "9418272877687921726", created: 1793350000 - 8},
	}
	if got := parseReferences([]byte(capturedReferences), now); !slices.Equal(got, want) {
		t.Errorf("parseReferences = %v, want %v", got, want)
	}
	long := "801      Some VPN Helper              42                       2 days 03:04:05\n"
	if got := parseReferences([]byte(long), now); !slices.Equal(got, []token{{value: "42", created: 1793350000 - (2*86400 + 3*3600 + 4*60 + 5)}}) {
		t.Errorf("parseReferences with a name with spaces = %v", got)
	}
	for _, out := range []string{"No pf starter references held\n", "TOKENS:\nPID Process Name TOKEN TIMESTAMP\n"} {
		if got := parseReferences([]byte(out), now); len(got) != 0 {
			t.Errorf("parseReferences(%q) = %v, want none", out, got)
		}
	}
}

func TestTokenSame(t *testing.T) {
	tok := token{value: "7", created: 100}
	for _, tt := range []struct {
		r    token
		want bool
	}{
		{token{value: "7", created: 100}, true},
		{token{value: "7", created: 100 + tokenSkew}, true},
		{token{value: "7", created: 100 - tokenSkew}, true},
		{token{value: "7", created: 100 + tokenSkew + 1}, false},
		{token{value: "8", created: 100}, false},
	} {
		if got := tok.same(tt.r); got != tt.want {
			t.Errorf("%v.same(%v) = %v, want %v", tok, tt.r, got, tt.want)
		}
	}
}

// capturedStates is "pfctl -s state" with a NAT state and an IPv6 state.
const capturedStates = `ALL udp 192.168.64.14:57829 -> 192.0.2.10:9       SINGLE:NO_TRAFFIC
ALL tcp 192.168.64.14:51121 -> 192.0.2.10:443       SYN_SENT:CLOSED
ALL udp 192.168.64.14:59130 -> 192.168.64.200:38457 -> 192.0.2.11:9       SINGLE:NO_TRAFFIC
ALL udp ::1[63006] -> ::1[9999]       SINGLE:NO_TRAFFIC
`

func TestParseStates(t *testing.T) {
	got, ok := parseStates([]byte(capturedStates))
	want := []string{"192.168.64.14", "192.0.2.10", "192.168.64.14", "192.0.2.10", "192.168.64.14", "192.168.64.200", "192.0.2.11", "::1", "::1"}
	if !ok || len(got) != len(want) {
		t.Fatalf("parseStates = (%v, %v), want %v", got, ok, want)
	}
	for i, a := range got {
		if a.String() != want[i] {
			t.Errorf("address %d = %v, want %s", i, a, want[i])
		}
	}
	if got, ok := parseStates(nil); !ok || len(got) != 0 {
		t.Errorf("parseStates(empty) = (%v, %v), want no address", got, ok)
	}
	if _, ok := parseStates([]byte(capturedStates + "ALL gre host.example -> other.example\n")); ok {
		t.Errorf("parseStates accepts a line without an address")
	}
}

func TestNatPass(t *testing.T) {
	tests := []struct {
		rule string
		want bool
	}{
		{"nat pass on en0 inet from any to 192.0.2.11 -> (en0) round-robin", true},
		{"binat pass on en0 from 192.168.64.14 to any -> 192.168.64.99", true},
		{"nat on en0 inet from any to 192.0.2.11 -> (en0) round-robin", false},
		{"rdr pass on en0 proto tcp from any to any port 80 -> 127.0.0.1 port 8080", false},
		{`nat-anchor "com.apple/*" all`, false},
		{"", false},
	}
	for _, tt := range tests {
		if got := natPass(tt.rule); got != tt.want {
			t.Errorf("natPass(%q) = %v, want %v", tt.rule, got, tt.want)
		}
	}
}

func TestRefersToApple(t *testing.T) {
	tests := []struct {
		rule string
		want bool
	}{
		{`anchor "com.apple/*" all`, true},
		{`anchor "com.apple/*"`, true},
		{`anchor "com.apple/*" in all`, false},
		{`anchor "com.apple/*" on lo0 all`, false},
		{`anchor "com.apple/x" all`, false},
		{`scrub-anchor "com.apple/*" all fragment reassemble`, false},
	}
	for _, tt := range tests {
		if got := refersToApple(tt.rule); got != tt.want {
			t.Errorf("refersToApple(%q) = %v, want %v", tt.rule, got, tt.want)
		}
	}
}

func TestParseStatus(t *testing.T) {
	tests := []struct {
		out     string
		want    bool
		wantErr bool
	}{
		{"Status: Enabled for 0 days 00:00:01           Debug: Urgent\n", true, false},
		{"No ALTQ support in kernel\nStatus: Disabled for 0 days 00:00:01          Debug: Urgent\n\nState Table\n", false, false},
		{"Status: Unknown\n", false, true},
		{"", false, true},
	}
	for _, tt := range tests {
		got, err := parseStatus([]byte(tt.out))
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("parseStatus(%q) = (%v, %v), want (%v, error %v)", tt.out, got, err, tt.want, tt.wantErr)
		}
		if err != nil && !errors.Is(err, errOutput) {
			t.Errorf("parseStatus(%q) error = %v, want errOutput", tt.out, err)
		}
	}
}

func TestParseEntries(t *testing.T) {
	captured := "   10.0.0.0/8\n   198.18.1.1\n  !198.18.1.20\n  !::1\n   2001:db8::1\n"
	entries, negated, err := parseEntries([]byte(captured))
	if err != nil {
		t.Fatal(err)
	}
	wantEntries := prefixes("10.0.0.0/8", "198.18.1.1/32", "2001:db8::1/128")
	wantNegated := prefixes("198.18.1.20/32", "::1/128")
	if !slices.Equal(entries, wantEntries) || !slices.Equal(negated, wantNegated) {
		t.Errorf("parseEntries = (%v, %v), want (%v, %v)", entries, negated, wantEntries, wantNegated)
	}
	if e, n, err := parseEntries(nil); err != nil || e != nil || n != nil {
		t.Errorf("parseEntries(empty) = (%v, %v, %v), want no entries", e, n, err)
	}
	for _, bad := range []string{"   example.com\n", "   10.0.0.0/33\n"} {
		if _, _, err := parseEntries([]byte(bad)); !errors.Is(err, errOutput) {
			t.Errorf("parseEntries(%q) error = %v, want errOutput", bad, err)
		}
	}
}

func TestParseConflicts(t *testing.T) {
	captured := "Y  198.18.1.20\nA  198.18.1.21\nA  10.0.0.0/8\n"
	got, err := parseConflicts([]byte(captured))
	if err != nil {
		t.Fatal(err)
	}
	if want := prefixes("198.18.1.20/32"); !slices.Equal(got, want) {
		t.Errorf("parseConflicts = %v, want %v", got, want)
	}
	for _, bad := range []string{"Y198.18.1.20\n", "Y  \n", "Y x198.18.1.20\n", "Y  host.example\n"} {
		if _, err := parseConflicts([]byte(bad)); !errors.Is(err, errOutput) {
			t.Errorf("parseConflicts(%q) error = %v, want errOutput", bad, err)
		}
	}
}

func TestParseToken(t *testing.T) {
	tok, err := parseToken([]byte("No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : 5568675831746034285\n"))
	if err != nil || tok != "5568675831746034285" {
		t.Errorf("parseToken = (%q, %v), want 5568675831746034285", tok, err)
	}
	if _, err := parseToken([]byte("pf enabled\n")); !errors.Is(err, errOutput) {
		t.Errorf("parseToken without a token: error = %v, want errOutput", err)
	}
}

func TestParseSkipped(t *testing.T) {
	got := parseSkipped([]byte("ALL\nXHC17\nen0 (skip)\nen1\nlo0 (skip)\n"))
	if want := []string{"en0", "lo0"}; !slices.Equal(got, want) {
		t.Errorf("parseSkipped = %v, want %v", got, want)
	}
}

func TestPassQuick(t *testing.T) {
	tests := []struct {
		rule string
		want bool
	}{
		{"pass out quick on en0 all flags S/SA keep state", true},
		{"pass quick on lo0 all", true},
		{"pass out on en0 inet all flags any keep state", false},
		{"block return out quick all", false},
		{`anchor "com.apple/*" all`, false},
		{"", false},
	}
	for _, tt := range tests {
		if got := passQuick(tt.rule); got != tt.want {
			t.Errorf("passQuick(%q) = %v, want %v", tt.rule, got, tt.want)
		}
	}
}

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}
