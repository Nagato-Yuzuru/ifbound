// Package pfrules compiles policies, interfaces, and accounts into the pf
// ruleset of the ifbound anchor on macOS.
//
// The ruleset declares one table per policy, and the table has the name
// of the policy, as the paired Backend expects. Each table is declared
// "persist" and without addresses, so a reload of the anchor keeps the
// entries that the Backend added. The rules come after the tables, one
// policy after the other in name order. Each policy gets these rules:
//
//   - only_via: an anchor rule that only tags the packets on the allowed
//     interfaces, then a quick block for the packets without that tag.
//     When no interface is allowed, the block rule only.
//   - deny_via: a quick block on the denied interfaces. When no current
//     interface is denied, no rule.
//
// An interface with an uncertain class (reconcile.Uncertain) is in each
// deny_via class that it can have, and in no only_via class. A name or a
// glob selects it as any other interface.
//
// The anchor rule refers to an empty sub-anchor "tag.<policy>" below the
// ifbound anchor. pfctl does not accept an empty inline anchor ("{ }"),
// so the ruleset only refers to the sub-anchor, and the kernel creates it
// empty when it adds the rule. A matching anchor rule sets its tag but
// does not decide the packet, so a rule before it in another ruleset and
// a rule after it still decide. A packet carries one tag only: the tag of
// a policy is set and tested before the next policy sets its own, so the
// policies combine with AND. No rule is a quick pass and no rule keeps
// state.
//
// A policy with a scope gets one block rule for its users and one for its
// groups, with numeric IDs from the account snapshot. pfctl takes no ID
// above maxID as a number, so an account with such an ID (for example
// nobody, -2) becomes the range "> maxID". The range also matches the
// other IDs in it, which is stricter than the scope. When the snapshot
// does not know a name, the policy loses its scope: it then applies to
// all traffic (fail closed), and the ruleset reports it as a problem. pf
// finds the socket owner of TCP and UDP packets only, so a
// scoped policy does not apply to other protocols, such as ICMP, and not
// to VM traffic through kernel NAT.
//
// pf does not tag fragments: every packet with "more fragments" set or a
// nonzero fragment offset, the first fragment too, goes through the
// fragment path of pf, which sets no tag and does not check the owner. A
// fragment to an only_via destination is blocked also on an allowed
// interface. This fails closed.
//
// The package is pure. It runs no command and reads no file.
package pfrules

import (
	"cmp"
	"errors"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// blockOut starts every block rule. It holds the reject method: ICMP port
// unreachable for IPv4 and ICMPv6 port unreachable for IPv6. Measured on
// macOS 27, only this method makes a local connect fail at once in both
// families. With one code, pf uses code 3 for IPv6, so both codes are
// written. A later guest did not repeat the fast failure for IPv4 TCP, so
// the method can change after more measurements.
const blockOut = "block return-icmp(port-unr, port-unr) out quick"

const (
	tagPrefix       = "ifbound."
	subAnchorPrefix = "tag."
	maxTableName    = 31 // PF_TABLE_NAME_SIZE - 1; it also keeps the tag and sub-anchor names short
	maxTagName      = 63 // PF_TAG_NAME_SIZE - 1
	maxIfaceName    = 15 // IFNAMSIZ - 1
	// maxID is the largest uid and gid that pfctl accepts as a number:
	// it refuses UID_MAX (2^31 - 1) and above, for example nobody (-2).
	// A larger ID goes into a rule as the range "> maxID".
	maxID = 1<<31 - 2
)

var (
	errName       = errors.New("policy name does not fit a pf table name and tag name")
	errDuplicate  = errors.New("duplicate policy name")
	errConstraint = errors.New("constraint cannot be compiled")
	errSelector   = errors.New("interface selector cannot be compiled")
	errInterface  = errors.New("interface name cannot be written in a pf rule")
)

// Compiler compiles policies into the ruleset of the ifbound anchor. The
// zero value is ready to use.
type Compiler struct{}

var _ reconcile.Compiler = Compiler{}

// Compile returns the ruleset for policies on the interfaces ifaces, with
// the scope names resolved in accounts. The order of policies and of
// ifaces has no effect on the result.
//
// An interface name in a selector goes into the rules as it is, also when
// the interface does not exist yet. A glob or a class selects only the
// interfaces in ifaces.
//
// Compile fails when a policy cannot be written as pf rules that make it
// hold: a policy name that is not a valid pf table name or does not fit
// the pf limits, two policies with one name, a nil or empty constraint, a
// selector that is not valid, or a selected interface whose name pf
// cannot take. A scope that the accounts cannot resolve is not an error:
// see the package documentation.
func (Compiler) Compile(policies []policy.Policy, ifaces []reconcile.Interface, accounts reconcile.Accounts) (reconcile.Ruleset, error) {
	sorted := slices.Clone(policies)
	slices.SortFunc(sorted, func(a, b policy.Policy) int { return cmp.Compare(a.Name, b.Name) })
	var tables, rules strings.Builder
	var problems []reconcile.Problem
	for i, p := range sorted {
		if i > 0 && sorted[i-1].Name == p.Name {
			return reconcile.Ruleset{}, fmt.Errorf("%w: %q", errDuplicate, p.Name)
		}
		lines, problem, err := policyRules(p, ifaces, accounts)
		if err != nil {
			return reconcile.Ruleset{}, fmt.Errorf("policy %q: %w", p.Name, err)
		}
		if problem != "" {
			problems = append(problems, reconcile.Problem{Text: problem})
		}
		tables.WriteString("table " + table(p.Name) + " persist\n")
		for _, l := range lines {
			rules.WriteString(l + "\n")
		}
	}
	return reconcile.NewRuleset([]byte(tables.String()+rules.String()), problems...), nil
}

// policyRules returns the rules of one policy, in evaluation order, and
// a problem text when the policy lost its scope.
func policyRules(p policy.Policy, ifaces []reconcile.Interface, accounts reconcile.Accounts) ([]string, string, error) {
	if !validName(p.Name) {
		return nil, "", errName
	}
	owners, unresolved := ownerMatches(p.Scope, accounts)
	var problem string
	if len(unresolved) > 0 {
		problem = fmt.Sprintf("policy %s applies to all traffic: its scope is dropped, because these accounts are unknown: %s",
			p.Name, strings.Join(unresolved, ", "))
	}
	to := " to " + table(p.Name)
	var rules []string
	switch c := p.Constraint.(type) {
	case policy.OnlyVia:
		allowed, err := resolve(c.Selectors(), ifaces, hasClass)
		if err != nil {
			return nil, "", err
		}
		match := to
		if len(allowed) > 0 {
			tag := quote(tagPrefix + string(p.Name))
			sub := quote(subAnchorPrefix + string(p.Name))
			rules = append(rules, "anchor "+sub+" out on "+list(allowed)+to+" tag "+tag)
			match += " ! tagged " + tag
		}
		for _, o := range owners {
			rules = append(rules, blockOut+match+o)
		}
	case policy.DenyVia:
		sels := c.Selectors()
		if len(sels) == 0 {
			return nil, "", fmt.Errorf("%w: deny_via without an interface", errConstraint)
		}
		denied, err := resolve(sels, ifaces, mayHaveClass)
		if err != nil {
			return nil, "", err
		}
		// With no denied interface now, there is nothing to block. The
		// next convergence adds the rule when such an interface appears.
		if len(denied) == 0 {
			return nil, problem, nil
		}
		for _, o := range owners {
			rules = append(rules, blockOut+" on "+list(denied)+to+o)
		}
	default:
		return nil, "", fmt.Errorf("%w: %T", errConstraint, p.Constraint)
	}
	return rules, problem, nil
}

// ownerMatches returns the socket-owner part of each block rule of a
// policy. An unlimited scope gives one empty part. A limited scope gives
// one part for its users and one for its groups, so a socket is in the
// scope when its owner or the primary group of its owner is listed.
//
// When the accounts do not know a name, ownerMatches returns one empty
// part, as for an unlimited scope, and the unknown names, sorted.
func ownerMatches(s policy.Scope, accounts reconcile.Accounts) ([]string, []string) {
	if !s.Limited() {
		return []string{""}, nil
	}
	var parts, unresolved []string
	for _, kind := range []struct {
		keyword string
		names   []policy.Account
		ids     map[string]uint32
	}{{"user", s.Users(), accounts.Users}, {"group", s.Groups(), accounts.Groups}} {
		var ids []uint32
		for _, a := range kind.names {
			id, ok := kind.ids[a.String()]
			if !ok {
				unresolved = append(unresolved, fmt.Sprintf("%s %q", kind.keyword, a))
				continue
			}
			ids = append(ids, id)
		}
		if len(ids) > 0 {
			parts = append(parts, " "+kind.keyword+" "+idList(ids))
		}
	}
	if len(unresolved) > 0 {
		slices.Sort(unresolved)
		return []string{""}, unresolved
	}
	return parts, nil
}

// resolve returns the sorted names of the interfaces that sels select.
// A class selector selects the interfaces for which inClass is true.
func resolve(sels []policy.InterfaceSelector, ifaces []reconcile.Interface, inClass classTest) ([]string, error) {
	var names []string
	for _, sel := range sels {
		n, err := selected(sel, ifaces, inClass)
		if err != nil {
			return nil, err
		}
		names = append(names, n...)
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

// classTest reports whether a class selector selects an interface.
type classTest func(reconcile.Interface, policy.Class) bool

// hasClass is the classTest of only_via: an interface with an uncertain
// class is not allowed.
func hasClass(i reconcile.Interface, c policy.Class) bool { return i.Class == c }

// mayHaveClass is the classTest of deny_via: an interface that can have
// the class is denied.
func mayHaveClass(i reconcile.Interface, c policy.Class) bool {
	return i.Class == c || slices.Contains(i.Possible(), c)
}

// selected returns the names of the interfaces that one selector selects.
// A name selects itself. A glob or a class selects only from ifaces, and
// it fails when it selects an interface whose name pf cannot take. A
// class selects the interfaces for which inClass is true.
func selected(sel policy.InterfaceSelector, ifaces []reconcile.Interface, inClass classTest) ([]string, error) {
	var match func(reconcile.Interface) bool
	switch s := sel.(type) {
	case policy.InterfaceName:
		if !validIface(s.Name()) {
			return nil, fmt.Errorf("%w: name %q", errSelector, s.Name())
		}
		return []string{s.Name()}, nil
	case policy.InterfaceGlob:
		if _, err := path.Match(s.Pattern(), ""); err != nil || s.Pattern() == "" {
			return nil, fmt.Errorf("%w: glob %q", errSelector, s.Pattern())
		}
		match = func(i reconcile.Interface) bool {
			ok, _ := path.Match(s.Pattern(), i.Name) //nolint:errcheck // the pattern is valid: checked above
			return ok
		}
	case policy.InterfaceClass:
		switch s.Class() {
		case policy.ClassHardware, policy.ClassTunnel:
		default:
			return nil, fmt.Errorf("%w: class %d", errSelector, s.Class())
		}
		match = func(i reconcile.Interface) bool { return inClass(i, s.Class()) }
	default:
		return nil, fmt.Errorf("%w: %T", errSelector, sel)
	}
	var names []string
	for _, i := range ifaces {
		if !match(i) {
			continue
		}
		if !validIface(i.Name) {
			return nil, fmt.Errorf("%w: %q", errInterface, i.Name)
		}
		names = append(names, i.Name)
	}
	return names, nil
}

func table(n policy.Name) string { return "<" + quote(string(n)) + ">" }

// quote puts a name in double quotes, so that pf never reads it as a
// keyword such as "any". The callers allow only safe bytes in the name.
func quote(s string) string { return `"` + s + `"` }

func list(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = quote(n)
	}
	return "{ " + strings.Join(q, " ") + " }"
}

// idList writes sorted, unique IDs. Two names can share one ID. The IDs
// above maxID become one range item "> maxID".
func idList(ids []uint32) string {
	slices.Sort(ids)
	ids = slices.Compact(ids)
	var s []string
	for _, id := range ids {
		if id > maxID {
			s = append(s, "> "+strconv.Itoa(maxID))
			break
		}
		s = append(s, strconv.FormatUint(uint64(id), 10))
	}
	return "{ " + strings.Join(s, " ") + " }"
}

func validName(n policy.Name) bool {
	return safe(string(n)) && len(n) <= maxTableName && len(tagPrefix)+len(n) <= maxTagName
}

func validIface(name string) bool { return safe(name) && len(name) <= maxIfaceName }

// safe reports whether s is not empty and holds only bytes from
// [A-Za-z0-9_.-]. Such a name cannot end a quoted pf string or a line.
func safe(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '.' && c != '-' {
			return false
		}
	}
	return true
}
