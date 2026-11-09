package pfbackend

import (
	"errors"
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
	{Action: pf.ActionDrop, Label: "ifbound-token:13772037947654164677.1793350000"},
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
	tok := token{value: "18446744073709551615", created: 9999999999}
	r := tokenRule(tok)
	if got, ok := labelToken(ruleLabel(t, r)); !ok || got != tok {
		t.Errorf("token read back from %q = %v, want %v", r, got, tok)
	}
	want := []token{{value: "13772037947654164677", created: 1793350000}}
	if _, got, _ := parseRules(loadedRules); !slices.Equal(got, want) {
		t.Errorf("tokens read back from the loaded rules = %v, want %v", got, want)
	}
	two := append(slices.Clone(loadedRules), pf.Rule{Action: pf.ActionDrop, Label: "ifbound-token:1.2"})
	if _, got, _ := parseRules(two); len(got) != 2 {
		t.Errorf("tokens read back from two token rules = %v, want two", got)
	}
	for _, label := range []string{
		"",
		"ifbound-token:13772037947654164677",
		"ifbound-token:12x.5",
		"ifbound-token:12.x",
		"ifbound-token:.5",
		"ifbound-token:",
	} {
		if got, ok := labelToken(label); ok {
			t.Errorf("token read back from label %q = %v, want none", label, got)
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
