package reconcile

import (
	"slices"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// verdict maps the name of each current interface to true when a policy
// allows its traffic on that interface.
type verdict map[string]bool

// verdicts returns the verdict of each policy on ifaces. It takes the
// selection of each policy from rs, so the verdict follows the rules
// that the Compiler wrote. A policy without a selection denies every
// interface.
func verdicts(policies []policy.Policy, ifaces []Interface, rs Ruleset) map[policy.Name]verdict {
	out := make(map[policy.Name]verdict, len(policies))
	for _, p := range policies {
		sel, ok := rs.Selected(p.Name)
		deny := false
		switch p.Constraint.(type) {
		case policy.OnlyVia:
		case policy.DenyVia:
			deny = true
		}
		v := make(verdict, len(ifaces))
		for _, i := range ifaces {
			v[i.Name] = ok && slices.Contains(sel, i.Name) != deny
		}
		out[p.Name] = v
	}
	return out
}

// narrowedBy reports whether a state that started under v can continue
// on an interface that next denies: next denies an interface that v did
// not deny (it was absent or allowed), or next denies an interface and an
// interface that v allows is absent or denied in next. When next denies
// no interface, no state can leak now; a denied interface that appears
// later is new in the verdict then. A nil v (no earlier verdict) thus
// is narrowed by each next that denies an interface.
func (v verdict) narrowedBy(next verdict) bool {
	denies := false
	for name, allowed := range next {
		if allowed {
			continue
		}
		if was, ok := v[name]; !ok || was {
			return true
		}
		denies = true
	}
	if !denies {
		return false
	}
	for name, allowed := range v {
		if allowed && !next[name] {
			return true
		}
	}
	return false
}
