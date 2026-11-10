package pfbackend

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/pf"
)

// anchorStack is the size of the anchor stack of pf (pf.c,
// pf_anchor_stack). pf does not evaluate an anchor rule when the stack is
// full.
const anchorStack = 64

// problems returns the faults that void the ifbound rules:
//
//   - pf is disabled;
//   - no rule of the main ruleset refers to `anchor "com.apple/*"` for
//     all packets, so pf does not evaluate the ifbound anchor (a rule
//     with parameters, such as `anchor "com.apple/*" in all`, evaluates
//     it only for the packets that it matches);
//   - a filter rule decides packets before the ifbound rules: a rule that
//     passes packets quick, or a quick anchor rule that calls an anchor
//     with a pass rule or a wildcard call, or that is a wildcard call;
//   - a filter rule routes packets to an interface (route-to, dup-to,
//     fastroute) and keeps state, before or after the ifbound anchor;
//   - a NAT rule passes the packets that it translates ("nat pass",
//     "binat pass"), so pf evaluates no filter rule for them;
//   - "set skip" covers an interface other than a loopback interface, so
//     pf evaluates no rule for its packets;
//   - a negated entry exempts addresses from an entry of its table.
//
// The check of the filter rules follows the anchor calls of pf (see
// walk), so it does not report a rule in an anchor that no rule calls. It
// reads only the rule text: it does not evaluate the direction, the
// interfaces, or the addresses of a rule, and it follows an anchor rule
// with parameters as if it had none. The check of the NAT rules reads
// every anchor. So Read can report a rule that pf does not apply to a
// protected packet, which is the safe direction.
//
// A negated entry that is inside no entry of its table exempts nothing,
// so it is not a Problem. AddEntries deletes it when it adds a prefix
// that holds it. Read leaves each entry that holds a negated entry out of
// Tables, so the Reconciler calls AddEntries for it.
func (b *Backend) problems(ctx context.Context, enabled bool, tables, negated map[policy.Name][]netip.Prefix) ([]reconcile.Problem, error) {
	var ps []reconcile.Problem
	if !enabled {
		ps = append(ps, voids("pf is disabled, so no ifbound rule is in effect"))
	}
	rules, err := b.ruleProblems(ctx)
	if err != nil {
		return nil, err
	}
	ps = append(ps, rules...)
	nat, err := b.natProblems(ctx)
	if err != nil {
		return nil, err
	}
	ps = append(ps, nat...)
	ifaces, err := b.pfctl(ctx, nil, "-sI", "-v")
	if err != nil {
		return nil, err
	}
	for _, name := range parseSkipped(ifaces.Stdout) {
		if !strings.HasPrefix(name, "lo") {
			ps = append(ps, voids(fmt.Sprintf("pf skips the interface %s (set skip), so no ifbound rule applies to its packets", name)))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(negated)) {
		for _, n := range negated[name] {
			if slices.ContainsFunc(tables[name], func(e netip.Prefix) bool { return inside(n, e) }) {
				ps = append(ps, voids(fmt.Sprintf("the table %s of the ifbound anchor holds the negated entry !%s, which exempts these addresses", name, n)))
			}
		}
	}
	return ps, nil
}

// ruleProblems checks the filter rules that pf can evaluate. It follows
// the anchor calls in the order in which pf evaluates them: the rules of
// the main ruleset, and in each anchor rule the anchors that it calls.
func (b *Backend) ruleProblems(ctx context.Context) ([]reconcile.Problem, error) {
	out, err := b.pfctl(ctx, nil, "-sr")
	if err != nil {
		return nil, err
	}
	rules := lines(out.Stdout)
	if !slices.ContainsFunc(rules, refersToApple) {
		return []reconcile.Problem{voids(`the main pf ruleset has no rule anchor "com.apple/*" for all packets, so pf does not evaluate the ifbound anchor`)}, nil
	}
	w := walk{b: b, before: true, canPass: make(map[string]bool)}
	for _, r := range rules {
		if _, err := w.rule(ctx, "", r, 0); err != nil {
			return nil, err
		}
	}
	return w.ps, nil
}

// walk follows the anchor calls of pf through the rules that pfctl
// prints. It reports these rules:
//
//   - before the ifbound anchor, a rule that passes packets quick;
//   - before the ifbound anchor, a quick anchor rule that can end the
//     evaluation: an anchor that it calls holds a pass rule, or the rule
//     or an anchor that it calls makes a wildcard call. pf ends the
//     evaluation at the quick anchor rule when the match flag of the
//     called anchor is set (pf.c: pf_step_out_of_anchor). A wildcard
//     call sets that flag from the flag of each anchor below, and pf
//     keeps the flag of an anchor across packets. So an earlier packet
//     can end the evaluation, also when no rule matches this packet;
//   - at each position, a rule that routes packets (route-to, dup-to,
//     fastroute) and keeps state. pf creates the state before it routes
//     the packet, and on the new interface the floating state passes the
//     packet without the rules (pf.c: pf_test_rule, pf_route,
//     pf_find_state). Without state, pf evaluates the rules again on the
//     new interface, and the ifbound rules block the packet there. This
//     also reports a rule that routes inbound packets only, or that routes
//     to an interface that each policy allows, which is the safe
//     direction.
//
// The walk reads each anchor one time. It does not go into the ifbound
// anchor: Read checks its rules through the ruleset ID, and parseRules
// does not accept a call out of the ifbound anchor.
type walk struct {
	b  *Backend
	ps []reconcile.Problem
	// before is true until the walk comes to the position of the ifbound
	// anchor: in the first rule of the main ruleset that refers to the
	// anchors below com.apple for all packets, the first anchor whose path
	// is the path of the ifbound anchor or comes after it in byte order.
	// The walk reads the rules in the order in which pf evaluates them, so
	// a rule that it reads while before is true comes before the ifbound
	// rules.
	before bool
	// canPass maps each anchor that the walk read to whether a quick
	// anchor rule that calls it can end the evaluation (see walk). An
	// anchor that the walk reads at the moment can: a call back into it
	// is a loop, and the safe answer is yes.
	canPass map[string]bool
}

// rule checks one rule of the ruleset at path, at the given depth of the
// anchor stack. It reports whether the rule is a pass rule, or an anchor
// rule that can end the evaluation when it is quick.
func (w *walk) rule(ctx context.Context, path, rule string, depth int) (bool, error) {
	before := w.before
	where := "the main pf ruleset"
	if path != "" {
		where = "the anchor " + path
	}
	words := ruleWords(rule)
	if routesWithState(words) {
		w.ps = append(w.ps, voids(fmt.Sprintf("the rule %q in %s routes packets to an interface and keeps state; pf passes a routed packet on that state and evaluates no ifbound rule for it", rule, where)))
	}
	if before && passQuick(words) {
		w.ps = append(w.ps, voids(fmt.Sprintf("the rule %q in %s comes before the ifbound anchor and passes packets quick", rule, where)))
	}
	if len(words) == 0 || words[0] != "anchor" {
		return len(words) > 0 && words[0] == "pass", nil
	}
	canPass, problem, err := w.call(ctx, path, rule, words, depth)
	if err != nil {
		return false, err
	}
	if problem != "" {
		w.ps = append(w.ps, voids(fmt.Sprintf("cannot follow the anchor rule %q in %s: %s", rule, where, problem)))
		return true, nil
	}
	if _, quick, _ := anchorRule(words); before && quick && canPass {
		w.ps = append(w.ps, voids(fmt.Sprintf("the rule %q in %s comes before the ifbound anchor; it is a quick anchor rule, and a pass rule or a wildcard call in its calls can end the evaluation and pass packets", rule, where)))
	}
	return canPass, nil
}

// call checks the anchors that an anchor rule of the ruleset at path
// calls; words are the words of the rule. It reports whether the rule can
// end the evaluation when it is quick, or why the walk cannot follow the
// call.
func (w *walk) call(ctx context.Context, path, rule string, words []string, depth int) (canPass bool, problem string, err error) {
	call, _, ok := anchorRule(words)
	if !ok {
		return false, "pfctl does not print the name of the anchor", nil
	}
	if depth >= anchorStack {
		return false, fmt.Sprintf("the anchor calls are deeper than %d", anchorStack), nil
	}
	target, wildcard := callTarget(path, call)
	targets := []string{target}
	if wildcard {
		targets, err = w.below(target)
		if errors.Is(err, pf.ErrNotFound) {
			return false, "the anchor " + target + " does not exist", nil
		}
		if err != nil {
			return false, "", err
		}
	}
	apple := w.before && path == "" && refersToApple(rule)
	canPass = wildcard
	for _, t := range targets {
		if apple && t >= Anchor {
			w.before = false
		}
		p, err := w.ruleset(ctx, t, depth+1)
		if err != nil {
			return false, "", err
		}
		canPass = canPass || p
	}
	if apple {
		w.before = false
	}
	return canPass, "", nil
}

// ruleset checks the rules of the anchor at path. It reports whether a
// quick anchor rule that calls the anchor can end the evaluation.
func (w *walk) ruleset(ctx context.Context, path string, depth int) (bool, error) {
	if path == Anchor || strings.HasPrefix(path, Anchor+"/") {
		return false, nil
	}
	if canPass, ok := w.canPass[path]; ok {
		return canPass, nil
	}
	w.canPass[path] = true
	out, err := w.b.pfctl(ctx, nil, "-a", path, "-sr")
	if err != nil {
		return false, err
	}
	if complained(out.Stderr) {
		where := "which comes before the ifbound anchor"
		if !w.before {
			where = "so Read cannot look for route rules in it"
		}
		w.ps = append(w.ps, voids(fmt.Sprintf("cannot read the rules of the anchor %s, %s: %s", path, where, stderrText(out.Stderr))))
		return true, nil
	}
	canPass := false
	for _, r := range lines(out.Stdout) {
		p, err := w.rule(ctx, path, r, depth)
		if err != nil {
			return false, err
		}
		canPass = canPass || p
	}
	w.canPass[path] = canPass
	return canPass, nil
}

// below returns the paths of the anchors directly below the anchor at
// path, in the order in which a wildcard call evaluates them. The error
// wraps pf.ErrNotFound when the anchor does not exist.
func (w *walk) below(path string) ([]string, error) {
	names, err := w.b.dev.Anchors(path)
	if err != nil {
		return nil, fmt.Errorf("listing the anchors below %s: %w", path, err)
	}
	paths := make([]string, len(names))
	for i, n := range names {
		paths[i] = path + "/" + n
	}
	slices.Sort(paths)
	return paths, nil
}

// natProblems reports each NAT rule that passes packets, in the main
// ruleset and in every anchor. An "rdr pass" rule passes inbound packets
// only. The ifbound rules filter outbound packets, so it is not reported.
func (b *Backend) natProblems(ctx context.Context) ([]reconcile.Problem, error) {
	anchors, err := b.pfctl(ctx, nil, "-sA", "-v")
	if err != nil {
		return nil, err
	}
	var ps []reconcile.Problem
	for _, a := range append([]string{""}, parseNames(anchors.Stdout)...) {
		args, where := []string{"-sn"}, "the main pf ruleset"
		if a != "" {
			args, where = []string{"-a", a, "-sn"}, "the anchor "+a
		}
		out, err := b.pfctl(ctx, nil, args...)
		if err != nil {
			return nil, err
		}
		if complained(out.Stderr) {
			ps = append(ps, voids(fmt.Sprintf("cannot read the NAT rules of %s: %s", where, stderrText(out.Stderr))))
			continue
		}
		for _, r := range lines(out.Stdout) {
			if natPass(r) {
				ps = append(ps, voids(fmt.Sprintf("the NAT rule %q in %s passes the packets that it translates, so pf does not evaluate the ifbound rules for them", r, where)))
			}
		}
	}
	return ps, nil
}

func voids(text string) reconcile.Problem { return reconcile.Problem{Text: text, Voids: true} }

// lines returns the lines of out that are not empty.
func lines(out []byte) []string {
	var ls []string
	for l := range strings.Lines(string(out)) {
		if l = strings.TrimRight(l, "\r\n"); l != "" {
			ls = append(ls, l)
		}
	}
	return ls
}
