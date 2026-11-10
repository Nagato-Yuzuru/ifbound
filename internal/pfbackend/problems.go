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
//     with a pass rule;
//   - a filter rule routes packets to an interface (route-to, reply-to,
//     dup-to, fastroute), before or after the ifbound anchor;
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
// The rules before the anchor rule that refers to the anchors below
// com.apple come before the ifbound anchor, and in that anchor rule the
// anchors whose name comes before the name of the ifbound anchor in byte
// order. The rest comes after it.
func (b *Backend) ruleProblems(ctx context.Context) ([]reconcile.Problem, error) {
	out, err := b.pfctl(ctx, nil, "-sr")
	if err != nil {
		return nil, err
	}
	rules := lines(out.Stdout)
	ref := slices.IndexFunc(rules, refersToApple)
	if ref < 0 {
		return []reconcile.Problem{voids(`the main pf ruleset has no rule anchor "com.apple/*" for all packets, so pf does not evaluate the ifbound anchor`)}, nil
	}
	w := walk{b: b, held: make(map[string]bool)}
	for i, r := range rules {
		if i != ref {
			if _, err := w.rule(ctx, "", r, i < ref, 0); err != nil {
				return nil, err
			}
			continue
		}
		apple, err := w.below(appleAnchor)
		if err != nil {
			return nil, err
		}
		for _, a := range apple {
			if _, err := w.ruleset(ctx, a, a < Anchor, 1); err != nil {
				return nil, err
			}
		}
	}
	return w.ps, nil
}

// walk follows the anchor calls of pf through the rules that pfctl
// prints. It reports these rules:
//
//   - before the ifbound anchor, a rule that passes packets quick;
//   - before the ifbound anchor, a quick anchor rule that calls an anchor
//     with a pass rule. When a rule in the anchors that it calls matches,
//     pf ends the evaluation (pf.c: pf_step_out_of_anchor gives the quick
//     flag of the anchor rule);
//   - at each position, a rule that routes packets (route-to, reply-to,
//     dup-to, fastroute). pf evaluates a routed packet again on the new
//     interface, and the packet keeps the tag that the ifbound rules gave
//     it on the first interface (pf.c: pf_route). This also reports a
//     rule that routes inbound packets only, which is the safe direction.
//
// The walk reads each anchor one time. It does not go into the ifbound
// anchor: Read checks its rules through the ruleset ID.
type walk struct {
	b  *Backend
	ps []reconcile.Problem
	// held maps each anchor that the walk read to whether it, or an
	// anchor that it calls, holds a pass rule. An anchor that the walk
	// reads at the moment holds one: a call back into it is a loop, and
	// the safe answer is yes.
	held map[string]bool
}

// rule checks one rule of the ruleset at path, at the given depth of the
// anchor stack. It reports whether the rule is a pass rule, or an anchor
// rule that calls an anchor with a pass rule.
func (w *walk) rule(ctx context.Context, path, rule string, before bool, depth int) (bool, error) {
	where := "the main pf ruleset"
	if path != "" {
		where = "the anchor " + path
	}
	if routes(rule) {
		w.ps = append(w.ps, voids(fmt.Sprintf("the rule %q in %s routes packets to an interface; pf evaluates them again there and they keep their tags, so they can go around the ifbound rules", rule, where)))
	}
	if before && passQuick(rule) {
		w.ps = append(w.ps, voids(fmt.Sprintf("the rule %q in %s comes before the ifbound anchor and passes packets quick", rule, where)))
	}
	f := strings.Fields(rule)
	if len(f) == 0 || f[0] != "anchor" {
		return len(f) > 0 && f[0] == "pass", nil
	}
	call, quick, ok := anchorRule(rule)
	if !ok {
		w.ps = append(w.ps, voids(fmt.Sprintf("cannot follow the anchor rule %q in %s: pfctl does not print the name of the anchor", rule, where)))
		return true, nil
	}
	if depth >= anchorStack {
		w.ps = append(w.ps, voids(fmt.Sprintf("cannot follow the anchor rule %q in %s: the anchor calls are deeper than %d", rule, where, anchorStack)))
		return true, nil
	}
	target, wildcard := callTarget(path, call)
	targets := []string{target}
	if wildcard {
		var err error
		if targets, err = w.below(target); err != nil {
			return false, err
		}
	}
	held := false
	for _, t := range targets {
		h, err := w.ruleset(ctx, t, before, depth+1)
		if err != nil {
			return false, err
		}
		held = held || h
	}
	if before && quick && held {
		w.ps = append(w.ps, voids(fmt.Sprintf("the rule %q in %s comes before the ifbound anchor; it is a quick anchor rule, so a pass rule in the anchors that it calls passes packets quick", rule, where)))
	}
	return held, nil
}

// ruleset checks the rules of the anchor at path. It reports whether the
// anchor, or an anchor that it calls, holds a pass rule.
func (w *walk) ruleset(ctx context.Context, path string, before bool, depth int) (bool, error) {
	if path == Anchor || strings.HasPrefix(path, Anchor+"/") {
		return false, nil
	}
	if held, ok := w.held[path]; ok {
		return held, nil
	}
	w.held[path] = true
	out, err := w.b.pfctl(ctx, nil, "-a", path, "-sr")
	if err != nil {
		return false, err
	}
	if complained(out.Stderr) {
		where := "which comes before the ifbound anchor"
		if !before {
			where = "so Read cannot look for route rules in it"
		}
		w.ps = append(w.ps, voids(fmt.Sprintf("cannot read the rules of the anchor %s, %s: %s", path, where, stderrText(out.Stderr))))
		return true, nil
	}
	held := false
	for _, r := range lines(out.Stdout) {
		h, err := w.rule(ctx, path, r, before, depth)
		if err != nil {
			return false, err
		}
		held = held || h
	}
	w.held[path] = held
	return held, nil
}

// below returns the paths of the anchors directly below the anchor at
// path, in the order in which a wildcard call evaluates them. An anchor
// that does not exist has none.
func (w *walk) below(path string) ([]string, error) {
	names, err := w.b.dev.Anchors(path)
	if errors.Is(err, pf.ErrNotFound) {
		return nil, nil
	}
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
