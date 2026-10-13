package pfbackend

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// problems returns the faults that void the ifbound rules:
//
//   - pf is disabled;
//   - no rule of the main ruleset refers to `anchor "com.apple/*"` for
//     all packets, so pf does not evaluate the ifbound anchor (a rule
//     with parameters, such as `anchor "com.apple/*" in all`, evaluates
//     it only for the packets that it matches);
//   - a rule that passes packets quick comes first: in the main ruleset
//     before that anchor rule, in an anchor that such an earlier anchor
//     rule refers to, or in an anchor below com.apple whose name comes
//     before the name of the ifbound anchor in byte order;
//   - a NAT rule passes the packets that it translates ("nat pass",
//     "binat pass"), so pf evaluates no filter rule for them;
//   - "set skip" covers an interface other than a loopback interface, so
//     pf evaluates no rule for its packets;
//   - a negated entry exempts addresses from an entry of its table.
//
// The check of an earlier anchor also reads its sub-anchors, also the ones
// that no rule refers to, and the check of the NAT rules reads every
// anchor. That can report a rule that pf does not evaluate, which is the
// safe direction.
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
	main, err := b.mainProblems(ctx)
	if err != nil {
		return nil, err
	}
	ps = append(ps, main...)
	earlier, err := b.earlierAnchors(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range earlier {
		more, err := b.treeProblems(ctx, a)
		if err != nil {
			return nil, err
		}
		ps = append(ps, more...)
	}
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

// mainProblems checks the main ruleset up to the rule that refers to the
// anchors below com.apple, and the anchors that the rules before it
// refer to.
func (b *Backend) mainProblems(ctx context.Context) ([]reconcile.Problem, error) {
	out, err := b.pfctl(ctx, nil, "-sr")
	if err != nil {
		return nil, err
	}
	rules := lines(out.Stdout)
	ref := slices.IndexFunc(rules, refersToApple)
	if ref < 0 {
		return []reconcile.Problem{voids(`the main pf ruleset has no rule anchor "com.apple/*" for all packets, so pf does not evaluate the ifbound anchor`)}, nil
	}
	var ps []reconcile.Problem
	for _, r := range rules[:ref] {
		if passQuick(r) {
			ps = append(ps, voids(fmt.Sprintf("the rule %q in the main pf ruleset comes before the ifbound anchor and passes packets quick", r)))
		}
		if name, ok := anchorRule(r); ok {
			more, err := b.treeProblems(ctx, name)
			if err != nil {
				return nil, err
			}
			ps = append(ps, more...)
		}
	}
	return ps, nil
}

// earlierAnchors returns the anchors below com.apple that pf evaluates
// before the ifbound anchor.
func (b *Backend) earlierAnchors(ctx context.Context) ([]string, error) {
	out, err := b.pfctl(ctx, nil, "-a", appleAnchor, "-sA")
	if err != nil {
		return nil, err
	}
	var earlier []string
	for _, a := range parseNames(out.Stdout) {
		if a < Anchor && !strings.HasPrefix(a, Anchor+"/") {
			earlier = append(earlier, a)
		}
	}
	return earlier, nil
}

// treeProblems reports each rule that passes packets quick in the anchor
// root and in every anchor below it.
func (b *Backend) treeProblems(ctx context.Context, root string) ([]reconcile.Problem, error) {
	subs, err := b.pfctl(ctx, nil, "-a", root, "-sA", "-v")
	if err != nil {
		return nil, err
	}
	var ps []reconcile.Problem
	for _, a := range append([]string{root}, parseNames(subs.Stdout)...) {
		out, err := b.pfctl(ctx, nil, "-a", a, "-sr")
		if err != nil {
			return nil, err
		}
		if complained(out.Stderr) {
			ps = append(ps, voids(fmt.Sprintf("cannot read the rules of the anchor %s, which comes before the ifbound anchor: %s", a, stderrText(out.Stderr))))
			continue
		}
		for _, r := range lines(out.Stdout) {
			if passQuick(r) {
				ps = append(ps, voids(fmt.Sprintf("the rule %q in the anchor %s comes before the ifbound anchor and passes packets quick", r, a)))
			}
		}
	}
	return ps, nil
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
