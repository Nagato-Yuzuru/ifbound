package pfrules_test

import (
	"fmt"
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/pfrules"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// The pools of TestSelectedMatchesRuleText. They differ from the pools
// of property_test.go on purpose.
var (
	selIfacePool    = []string{"en0", "en1", "en5", "utun0", "utun4", "utun12", "ppp0", "bridge0", "gif0"}
	selSelectorPool = []string{"en0", "en1", "utun4", "ppp0", "utun*", "en?", "*0", "ppp*", "[eu]*", "@tunnel", "@hardware"}
	// anchorLine is the rule of only_via that lists the allowed
	// interfaces.
	anchorLine = regexp.MustCompile(`^anchor "tag\.([^"]+)" out on \{ ([^}]*) \} to <"([^"]+)"> tag `)
	// denyLine is a block rule of deny_via that lists the denied
	// interfaces.
	denyLine = regexp.MustCompile(`^block return-icmp\([^)]*\) out quick on \{ ([^}]*) \} to <"([^"]+)">`)
	// blockAll is a block rule of only_via.
	blockAll = regexp.MustCompile(`^block return-icmp\([^)]*\) out quick to <"([^"]+)">`)
)

// listNames returns the names in a pf list body, sorted and once each.
func listNames(list string) []string {
	var out []string
	for f := range strings.FieldsSeq(list) {
		out = append(out, strings.Trim(f, `"`))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func randomSelIfaces(r *rand.Rand) []reconcile.Interface {
	var out []reconcile.Interface
	for _, n := range selIfacePool {
		if r.IntN(2) == 0 {
			continue
		}
		switch r.IntN(4) {
		case 0:
			out = append(out, reconcile.Interface{Name: n, Class: policy.ClassHardware})
		case 1:
			out = append(out, reconcile.Interface{Name: n, Class: policy.ClassTunnel})
		case 2:
			out = append(out, reconcile.Uncertain(n, policy.ClassTunnel))
		default:
			out = append(out, reconcile.Uncertain(n, policy.ClassHardware, policy.ClassTunnel))
		}
	}
	return out
}

// randomSelConfig returns one to four policies. Some have a scope, so
// the rules of a policy can come in more than one line.
func randomSelConfig(r *rand.Rand) string {
	var b strings.Builder
	b.WriteString("[dns]\nupstream = [\"tls://1.1.1.1@a.example\"]\n")
	for i := range 1 + r.IntN(4) {
		key := "only_via"
		n := r.IntN(4)
		if r.IntN(2) == 0 {
			key = "deny_via"
			n++
		}
		var sels []string
		for range n {
			sels = append(sels, `"`+selSelectorPool[r.IntN(len(selSelectorPool))]+`"`)
		}
		fmt.Fprintf(&b, "[[policy]]\nname = \"p%d\"\nto = [\"192.0.2.%d\"]\n%s = [%s]\n", i, i+1, key, strings.Join(sels, ", "))
		if r.IntN(3) == 0 {
			b.WriteString("scope = { users = [\"_a\"] }\n")
		}
	}
	return b.String()
}

// ruleLists returns, for each table, the interfaces that the rules list,
// and the tables that a block rule without "on" refers to.
func ruleLists(body []byte) (map[string][]string, map[string]bool, error) {
	listed := map[string][]string{}
	blocksAll := map[string]bool{}
	for line := range strings.SplitSeq(string(body), "\n") {
		if m := anchorLine.FindStringSubmatch(line); m != nil {
			if m[1] != m[3] {
				return nil, nil, fmt.Errorf("the anchor rule of %s refers to table %s", m[1], m[3])
			}
			listed[m[1]] = append(listed[m[1]], listNames(m[2])...)
		}
		if m := denyLine.FindStringSubmatch(line); m != nil {
			listed[m[2]] = append(listed[m[2]], listNames(m[1])...)
		}
		if m := blockAll.FindStringSubmatch(line); m != nil {
			blocksAll[m[1]] = true
		}
	}
	return listed, blocksAll, nil
}

// compileRandom compiles a random configuration on random interfaces,
// with or without the account of the scope.
func compileRandom(t *testing.T, seed uint64) (policy.Config, []reconcile.Interface, reconcile.Ruleset) {
	t.Helper()
	r := rand.New(rand.NewPCG(seed, 7))
	text := randomSelConfig(r)
	cfg, err := policy.ParseBytes([]byte(text))
	if err != nil {
		t.Fatalf("seed %d: %v\n%s", seed, err, text)
	}
	ifaces := randomSelIfaces(r)
	accounts := reconcile.Accounts{}
	if r.IntN(2) == 0 {
		accounts.Users = map[string]uint32{"_a": 501}
	}
	rs, err := pfrules.Compiler{}.Compile(cfg.Policies, ifaces, accounts)
	if err != nil {
		t.Fatalf("seed %d: Compile: %v\n%s", seed, err, text)
	}
	return cfg, ifaces, rs
}

// TestSelectedMatchesRuleText reads the interface lists from the compiled
// pf text and compares them with Ruleset.Selected. It uses no code of the
// Compiler and not the model of property_test.go.
func TestSelectedMatchesRuleText(t *testing.T) {
	for seed := range uint64(3000) {
		cfg, ifaces, rs := compileRandom(t, seed)
		listed, blocksAll, err := ruleLists(rs.Body())
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		for _, p := range cfg.Policies {
			name := string(p.Name)
			sel, ok := rs.Selected(p.Name)
			if !ok {
				t.Fatalf("seed %d: no selection for %s", seed, name)
			}
			slices.Sort(sel)
			want := slices.Sorted(slices.Values(listed[name]))
			want = slices.Compact(want)
			if !slices.Equal(sel, want) {
				t.Fatalf("seed %d: policy %s: Selected = %v, the rules list %v\nifaces %v\n%s", seed, name, sel, want, ifaces, rs.Body())
			}
			// Without a block rule, the list of only_via above would not
			// be the whole verdict.
			if _, only := p.Constraint.(policy.OnlyVia); only && !blocksAll[name] {
				t.Fatalf("seed %d: only_via policy %s has no block rule", seed, name)
			}
		}
	}
}
