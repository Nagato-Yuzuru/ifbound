package pfrules_test

import (
	"errors"
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
	selIfacePool    = []string{"en0", "en1", "en5", "utun0", "utun4", "utun12", "ppp0", "bridge0", "gif0", "lo0"}
	selSelectorPool = []string{"en0", "en1", "utun4", "ppp0", "utun*", "en?", "*0", "ppp*", "[eu]*", "@tunnel", "@hardware"}
	// anchorLine is the rule of only_via that lists the allowed
	// interfaces.
	anchorLine = regexp.MustCompile(`^anchor "tag\.([^"]+)" out on \{ ([^}]*) \} to <"([^"]+)"> tag `)
	// denyLine is a block rule that lists the denied interfaces: of
	// deny_via, or the first rule of only_via.
	denyLine = regexp.MustCompile(`^block return-icmp\([^)]*\) out quick on \{ ([^}]*) \} to <"([^"]+)">`)
	// blockAll is the block rule of only_via for each interface except
	// lo0.
	blockAll = regexp.MustCompile(`^block return-icmp\([^)]*\) out quick on ! lo0 to <"([^"]+)">`)
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

// lists holds, for each table, the interfaces that the anchor rules
// list, the interfaces that the block rules list, and whether a block
// rule on each interface except lo0 refers to the table.
type lists struct {
	tagged, denied map[string][]string
	blocksAll      map[string]bool
}

// ruleLists reads the lists of the rules in body.
func ruleLists(body []byte) (lists, error) {
	tagged := map[string][]string{}
	denied := map[string][]string{}
	blocksAll := map[string]bool{}
	for line := range strings.SplitSeq(string(body), "\n") {
		if m := anchorLine.FindStringSubmatch(line); m != nil {
			if m[1] != m[3] {
				return lists{}, fmt.Errorf("the anchor rule of %s refers to table %s", m[1], m[3])
			}
			tagged[m[1]] = append(tagged[m[1]], listNames(m[2])...)
		}
		if m := denyLine.FindStringSubmatch(line); m != nil {
			denied[m[2]] = append(denied[m[2]], listNames(m[1])...)
		}
		if m := blockAll.FindStringSubmatch(line); m != nil {
			blocksAll[m[1]] = true
		}
	}
	return lists{tagged, denied, blocksAll}, nil
}

// sortedOnce returns the names sorted and once each.
func sortedOnce(names []string) []string {
	return slices.Compact(slices.Sorted(slices.Values(names)))
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
// pf text and compares them with Ruleset.Selected: the anchor rule lists
// the selection of only_via, and the block rule lists the selection of
// deny_via. The block rule of only_via lists each other interface of the
// inventory, also one with an uncertain class, except lo0. It uses no
// code of the Compiler and not the model of property_test.go.
func TestSelectedMatchesRuleText(t *testing.T) {
	for seed := range uint64(3000) {
		cfg, ifaces, rs := compileRandom(t, seed)
		l, err := ruleLists(rs.Body())
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		for _, p := range cfg.Policies {
			if err := l.check(p, rs, ifaces); err != nil {
				t.Fatalf("seed %d: policy %s: %v\nifaces %v\n%s", seed, p.Name, err, ifaces, rs.Body())
			}
		}
	}
}

// check compares the lists of the policy p with the selection in rs.
func (l lists) check(p policy.Policy, rs reconcile.Ruleset, ifaces []reconcile.Interface) error {
	name := string(p.Name)
	sel, ok := rs.Selected(p.Name)
	if !ok {
		return errors.New("no selection")
	}
	slices.Sort(sel)
	_, only := p.Constraint.(policy.OnlyVia)
	want := sortedOnce(l.denied[name])
	if only {
		want = sortedOnce(l.tagged[name])
	}
	if !slices.Equal(sel, want) {
		return fmt.Errorf("Selected = %v, the rules list %v", sel, want)
	}
	if !only {
		return nil
	}
	// Without a block rule, the list of only_via above would not be the
	// whole verdict.
	if !l.blocksAll[name] {
		return errors.New("only_via without a block rule")
	}
	if got, want := sortedOnce(l.denied[name]), deniedByOnlyVia(sel, ifaces); !slices.Equal(got, want) {
		return fmt.Errorf("the block rule lists %v, want %v", got, want)
	}
	return nil
}

// deniedByOnlyVia returns the interfaces that the block rule of an
// only_via policy with the selection sel lists: each interface of ifaces
// that sel does not hold, except lo0. With no allowed interface, the
// block rule on each interface except lo0 is the only rule.
func deniedByOnlyVia(sel []string, ifaces []reconcile.Interface) []string {
	var out []string
	for _, i := range ifaces {
		if len(sel) > 0 && i.Name != "lo0" && !slices.Contains(sel, i.Name) {
			out = append(out, i.Name)
		}
	}
	return sortedOnce(out)
}
