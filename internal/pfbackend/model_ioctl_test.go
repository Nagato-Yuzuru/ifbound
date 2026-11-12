package pfbackend

import (
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/Nagato-Yuzuru/ifbound/pf"
)

// This file holds the ioctl semantics that both models of pf share:
// fakePF in fakepf_test.go and kernel in kernel_test.go. The models keep
// rules as the lines that pfctl prints, and tables as maps from an entry
// to its negation.

// The kernel model of the external test package uses these.
var (
	RulesOf    = rulesOf
	Children   = children
	AddAddrs   = addAddrs
	DelAddrs   = deleteAddrs
	AddrsOf    = addrsOf
	AddrArgs   = addrArgs
	RuleKindOf = ruleKind
	CallTarget = callTarget
)

// ruleKind returns the ruleset of pf that holds a rule line.
func ruleKind(line string) pf.RulesetKind {
	f := strings.Fields(line)
	if len(f) > 1 && f[0] == "no" {
		f = f[1:]
	}
	if len(f) == 0 {
		return pf.RulesetFilter
	}
	switch strings.TrimSuffix(f[0], "-anchor") {
	case "scrub":
		return pf.RulesetScrub
	case "nat":
		return pf.RulesetNAT
	case "binat":
		return pf.RulesetBINAT
	case "rdr":
		return pf.RulesetRDR
	case "dummynet":
		return pf.RulesetDummynet
	}
	return pf.RulesetFilter
}

// rulesOf returns the rules of the kind in lines, as Handle.Rules returns
// them. pf keeps a block rule with the action drop, and an anchor rule
// with the action pass.
func rulesOf(lines []string, kind pf.RulesetKind) []pf.Rule {
	var rules []pf.Rule
	for _, line := range lines {
		if ruleKind(line) != kind {
			continue
		}
		r := pf.Rule{Action: pf.ActionPass}
		if strings.HasPrefix(line, "block ") {
			r.Action = pf.ActionDrop
		}
		if name, _, ok := anchorRule(ruleWords(line)); ok && kind == pf.RulesetFilter {
			r.AnchorCall = name
		}
		if _, rest, ok := strings.Cut(line, `label "`); ok {
			r.Label, _, _ = strings.Cut(rest, `"`)
		}
		rules = append(rules, r)
	}
	return rules
}

// children returns the names of the anchors directly below anchor, from
// the paths of all anchors. pf holds the parents of each anchor.
func children(paths []string, anchor string) []string {
	prefix := anchor + "/"
	if anchor == "" {
		prefix = ""
	}
	var names []string
	for _, p := range paths {
		rest, ok := strings.CutPrefix(p, prefix)
		if !ok || rest == "" {
			continue
		}
		name, _, _ := strings.Cut(rest, "/")
		names = append(names, name)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// addAddrs adds addrs to the table as DIOCRADDADDRS does with feedback.
func addAddrs(t map[netip.Prefix]bool, addrs []pf.Addr) []pf.Feedback {
	fb := make([]pf.Feedback, len(addrs))
	seen := map[netip.Prefix]bool{}
	for i, a := range addrs {
		neg, present := t[a.Prefix]
		switch {
		case seen[a.Prefix]:
			fb[i] = pf.FeedbackDuplicate
		case present && neg != a.Negated:
			fb[i] = pf.FeedbackConflict
		case present:
			fb[i] = pf.FeedbackNone
		default:
			t[a.Prefix] = a.Negated
			fb[i] = pf.FeedbackAdded
		}
		seen[a.Prefix] = true
	}
	return fb
}

// deleteAddrs deletes addrs from the table as DIOCRDELADDRS does with
// feedback. An entry for which keep returns true stays, as if pf did not
// delete it.
func deleteAddrs(t map[netip.Prefix]bool, addrs []pf.Addr, keep func(pf.Addr) bool) []pf.Feedback {
	fb := make([]pf.Feedback, len(addrs))
	for i, a := range addrs {
		neg, present := t[a.Prefix]
		switch {
		case !present:
			fb[i] = pf.FeedbackNone
		case neg != a.Negated:
			fb[i] = pf.FeedbackConflict
		case keep != nil && keep(a):
			fb[i] = pf.FeedbackNone
		default:
			delete(t, a.Prefix)
			fb[i] = pf.FeedbackDeleted
		}
	}
	return fb
}

// addrsOf returns the entries of the table in order.
func addrsOf(t map[netip.Prefix]bool) []pf.Addr {
	var addrs []pf.Addr
	for _, p := range slices.SortedFunc(maps.Keys(t), netip.Prefix.Compare) {
		addrs = append(addrs, pf.Addr{Prefix: p, Negated: t[p]})
	}
	return addrs
}

// addrArgs are the arguments of a table call in the call log: the anchor,
// the table, and each address, with "!" for a negated one.
func addrArgs(t pf.Table, addrs []pf.Addr) []string {
	args := []string{t.Anchor, t.Name}
	for _, a := range addrs {
		mark := ""
		if a.Negated {
			mark = "!"
		}
		args = append(args, mark+a.Prefix.String())
	}
	return args
}
