package pfbackend

import (
	"errors"
	"math"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/pf"
)

// The outputs below are captured from pfctl on macOS 27.0 (26A428) in a
// tart guest.

// loadedRules are the filter rules of the anchor after a load of a
// pfrules ruleset with a sentinel, as Handle.Rules returns them: two
// anchor rules, three block rules, the sentinel rule, and a token rule.
// pf keeps a "block return" rule with the action drop.
var loadedRules = []pf.Rule{
	{Action: pf.ActionPass, AnchorCall: "tag.bing"},
	{Action: pf.ActionPass, AnchorCall: "tag.bing"},
	{Action: pf.ActionDrop},
	{Action: pf.ActionDrop},
	{Action: pf.ActionDrop},
	{Action: pf.ActionDrop, Label: "ifbound-ruleset:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	{Action: pf.ActionDrop, Label: "ifbound-token:13772037947654164677.1793350000.412"},
}

const zeroID = "0000000000000000000000000000000000000000000000000000000000000000"

func TestParseRules(t *testing.T) {
	other := pf.Rule{Action: pf.ActionDrop, Label: "ifbound-ruleset:" + strings.Repeat("_", 43)}
	label := func(l string) pf.Rule { return pf.Rule{Action: pf.ActionDrop, Label: l} }
	tests := []struct {
		name        string
		rules       []pf.Rule
		want        string
		wantForeign bool
	}{
		{"loaded", loadedRules, zeroID, false},
		{"pass rule at the top level", append([]pf.Rule{{Action: pf.ActionPass}}, loadedRules...), zeroID, true},
		{"NAT action at the top level", append([]pf.Rule{{Action: pf.ActionNAT}}, loadedRules...), zeroID, true},
		{"block rule at the top level", append([]pf.Rule{{Action: pf.ActionDrop}}, loadedRules...), zeroID, false},
		{"absolute anchor call", append([]pf.Rule{{Action: pf.ActionPass, AnchorCall: "/vpn"}}, loadedRules...), zeroID, true},
		{"anchor call out of the anchor", append([]pf.Rule{{Action: pf.ActionPass, AnchorCall: "../vpn"}}, loadedRules...), zeroID, true},
		{"wildcard call below a sub-anchor", append([]pf.Rule{{Action: pf.ActionPass, AnchorCall: "tag.bing/*"}}, loadedRules...), zeroID, true},
		{"wildcard call of the sub-anchors", append([]pf.Rule{{Action: pf.ActionPass, AnchorCall: "*"}}, loadedRules...), zeroID, true},
		{"no sentinel", []pf.Rule{{Action: pf.ActionDrop}}, "", false},
		{"empty anchor", nil, "", false},
		{"two sentinels", append(slices.Clone(loadedRules), other), "", false},
		{"label too short", []pf.Rule{label("ifbound-ruleset:AAAA")}, "", false},
		{"label not base64url", []pf.Rule{label("ifbound-ruleset:" + strings.Repeat("+", 43))}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, foreign := parseRules(tt.rules)
			if got != tt.want || foreign != tt.wantForeign {
				t.Errorf("parseRules = (%q, foreign %v), want (%q, foreign %v)", got, foreign, tt.want, tt.wantForeign)
			}
		})
	}
}

// ruleLabel returns the label of a rule that the Backend writes.
func ruleLabel(t *testing.T, rule string) string {
	t.Helper()
	_, rest, ok := strings.Cut(rule, `label "`)
	if !ok {
		t.Fatalf("rule %q has no label", rule)
	}
	label, _, _ := strings.Cut(rest, `"`)
	if len(label) > 63 {
		t.Errorf("label %q has %d bytes, pf takes at most 63", label, len(label))
	}
	return label
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
	if got, ok := labelID(ruleLabel(t, s)); !ok || got != id {
		t.Errorf("ID read back from %q = %q, want %q", s, got, id)
	}
	for _, bad := range []string{"", "xyz", id[:62], id + "00"} {
		if _, err := sentinel(bad); !errors.Is(err, errRulesetID) {
			t.Errorf("sentinel(%q) error = %v, want errRulesetID", bad, err)
		}
	}
}

func TestTokenRoundTrip(t *testing.T) {
	// The longest label: the largest token value and pid, and the
	// largest creation time that the comment on the label budget names.
	tok := token{value: math.MaxUint64, created: 1e17 - 1, pid: math.MaxInt32}
	r := tokenRule(tok)
	if got, ok := labelToken(ruleLabel(t, r)); !ok || got != tok {
		t.Errorf("token read back from %q = %v, want %v", r, got, tok)
	}
	want := []token{{value: 13772037947654164677, created: 1793350000, pid: 412}}
	if _, got, _ := parseRules(loadedRules); !slices.Equal(got, want) {
		t.Errorf("tokens read back from the loaded rules = %v, want %v", got, want)
	}
	two := append(slices.Clone(loadedRules), pf.Rule{Action: pf.ActionDrop, Label: "ifbound-token:1.2.3"})
	if _, got, _ := parseRules(two); len(got) != 2 {
		t.Errorf("tokens read back from two token rules = %v, want two", got)
	}
	for _, label := range []string{
		"13772037947654164677",
		"13772037947654164677.1793350000",
		"13772037947654164677.1793350000.412.5",
		"12x.5.1",
		"12.x.1",
		"12.5.x",
		"12.5.-1",
		"12.5.",
		".5.1",
		"18446744073709551616.5.1",
		"12.5.2147483648",
		"",
	} {
		if got, ok := labelToken(tokenPrefix + label); ok {
			t.Errorf("token read back from label %q = %v, want none", tokenPrefix+label, got)
		}
	}
	if _, got, _ := parseRules(nil); len(got) != 0 {
		t.Errorf("tokens read back from no rules = %v, want none", got)
	}
}

// A token is its reference only when the value, the creation time, and
// the pid all match.
func TestTokenIs(t *testing.T) {
	tok := token{value: 7, created: 100, pid: 412}
	for _, tt := range []struct {
		r    pf.Ref
		want bool
	}{
		{pf.Ref{Token: 7, Created: time.Unix(100, 0), PID: 412}, true},
		{pf.Ref{Token: 8, Created: time.Unix(100, 0), PID: 412}, false},
		{pf.Ref{Token: 7, Created: time.Unix(101, 0), PID: 412}, false},
		{pf.Ref{Token: 7, Created: time.Unix(99, 0), PID: 412}, false},
		{pf.Ref{Token: 7, Created: time.Unix(100, 0), PID: 413}, false},
	} {
		if got := tok.is(tt.r); got != tt.want {
			t.Errorf("%v.is(%+v) = %v, want %v", tok, tt.r, got, tt.want)
		}
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
		{`pass out on en0 all no state label "keep quick dns"`, false},
		{`pass out on en0 all no state label "a\" quick "`, false},
		{`pass out quick on en0 all no state label "a b"`, true},
		{`anchor "com.apple/*" all`, false},
		{"", false},
	}
	for _, tt := range tests {
		if got := passQuick(ruleWords(tt.rule)); got != tt.want {
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
