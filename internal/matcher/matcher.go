// Package matcher maps a DNS name to the policies that name it.
//
// A Matcher is a tree of labels, read from the right. A lookup costs time
// in proportion to the number of labels in the name, not the number of
// policies. IP and CIDR destinations take no part in name matching.
package matcher

import (
	"errors"
	"slices"
	"strings"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// ErrMalformedName means that a qname cannot be split into labels.
var ErrMalformedName = errors.New("malformed DNS name")

const (
	maxLabelLen = 63
	maxWireLen  = 255
)

// Matcher answers name lookups for one set of policies. It is immutable,
// so many goroutines may share it. Build a new one when the configuration
// changes. The zero Matcher is valid and matches nothing.
type Matcher struct {
	root  node
	names []policy.Name // policy names in file order
}

// node is one label in the tree. The int values index Matcher.names. Both
// slices are ascending.
type node struct {
	children map[string]*node
	exact    []int         // policies with the exact name that this node spells
	suffix   []int         // policies with "*." plus the name that this node spells
	domain   policy.Domain // the name of this node, valid when it has an entry
}

func (n *node) hasEntry() bool { return len(n.exact) > 0 || len(n.suffix) > 0 }

// New builds a Matcher from the policies of a parsed Config.
func New(policies []policy.Policy) *Matcher {
	m := &Matcher{names: make([]policy.Name, len(policies))}
	for i, p := range policies {
		m.names[i] = p.Name
		for _, dest := range p.To {
			switch d := dest.(type) {
			case policy.ExactDomain:
				n := m.root.descend(d.Domain())
				n.exact = append(n.exact, i)
			case policy.DomainSuffix:
				n := m.root.descend(d.Domain())
				n.suffix = append(n.suffix, i)
			case policy.IPAddr, policy.CIDR:
				// Not a name: the firewall layer handles these.
			}
		}
	}
	return m
}

// descend returns the node that spells d. It creates missing nodes.
func (n *node) descend(d policy.Domain) *node {
	labels := strings.Split(d.String(), ".")
	for _, l := range slices.Backward(labels) {
		if n.children == nil {
			n.children = make(map[string]*node)
		}
		child, ok := n.children[l]
		if !ok {
			child = &node{}
			n.children[l] = child
		}
		n = child
	}
	n.domain = d
	return n
}

// Match returns the names of all policies that match qname, in file order,
// without duplicates. It has three outcomes:
//
//   - names and a nil error: the name matches these policies.
//   - no names and a nil error: the name is well formed but no policy
//     matches it. The root name "." is such a name, because a
//     configuration cannot name the root.
//   - ErrMalformedName: the name cannot be split into labels. The caller
//     must not treat this as "no match". The daemon must not acknowledge
//     the report.
//
// qname is in DNS presentation form, as a resolver library prints it. "\X"
// stands for the byte X, "\DDD" (three digits, at most 255) for one byte,
// and an unescaped "." ends a label. One final unescaped dot is optional.
//
// Match does not check the characters of a label. A real resolver answers
// names that the configuration syntax forbids, such as "a*b.bing.com",
// and a policy for "*.bing.com" must still cover them. A label that is not
// in the tree simply ends the walk. Comparison folds ASCII case only.
func (m *Matcher) Match(qname string) ([]policy.Name, error) {
	labels, err := splitName(qname)
	if err != nil {
		return nil, err
	}
	var hits []int
	n := &m.root
	for i, l := range slices.Backward(labels) {
		n = n.children[l]
		if n == nil {
			break
		}
		hits = append(hits, n.suffix...)
		if i == 0 {
			hits = append(hits, n.exact...)
		}
	}
	if len(hits) == 0 {
		return nil, nil
	}
	slices.Sort(hits)
	hits = slices.Compact(hits)
	out := make([]policy.Name, len(hits))
	for i, h := range hits {
		out[i] = m.names[h]
	}
	return out, nil
}

// Apexes returns the smallest set of domains that covers every domain
// destination: each one is equal to, or below, an apex. The list is sorted
// and has no duplicates. The caller owns the returned slice.
func (m *Matcher) Apexes() []policy.Domain {
	var out []policy.Domain
	m.root.collectApexes(&out)
	slices.SortFunc(out, func(a, b policy.Domain) int {
		return strings.Compare(a.String(), b.String())
	})
	return out
}

// collectApexes stops at the first node on each path that holds an entry.
// Every name below that node is already covered.
func (n *node) collectApexes(out *[]policy.Domain) {
	if n.hasEntry() {
		*out = append(*out, n.domain)
		return
	}
	for _, c := range n.children {
		c.collectApexes(out)
	}
}

// splitName splits a presentation-form name into labels, left to right. It
// folds ASCII case. The root name "." gives no labels.
func splitName(s string) ([]string, error) {
	if s == "" {
		return nil, ErrMalformedName
	}
	if s == "." {
		return nil, nil
	}
	var (
		labels []string
		cur    []byte
		wire   = 1 // the root label
	)
	push := func() error {
		if len(cur) == 0 || len(cur) > maxLabelLen {
			return ErrMalformedName
		}
		wire += len(cur) + 1
		labels = append(labels, string(cur))
		cur = cur[:0]
		return nil
	}
	for i := 0; i < len(s); {
		switch c := s[i]; c {
		case '.':
			if err := push(); err != nil {
				return nil, err
			}
			i++
		case '\\':
			b, size, ok := unescape(s[i+1:])
			if !ok {
				return nil, ErrMalformedName
			}
			cur = append(cur, foldASCII(b))
			i += 1 + size
		default:
			cur = append(cur, foldASCII(c))
			i++
		}
	}
	// A name without a final dot ends in a label. A name with one ends in
	// the dot, and cur is empty.
	if len(cur) > 0 {
		if err := push(); err != nil {
			return nil, err
		}
	}
	if wire > maxWireLen {
		return nil, ErrMalformedName
	}
	return labels, nil
}

// unescape reads the text after a backslash. It returns the byte and the
// number of input bytes used.
func unescape(s string) (b byte, size int, ok bool) {
	if s == "" {
		return 0, 0, false
	}
	if !isDigit(s[0]) {
		return s[0], 1, true
	}
	if len(s) < 3 || !isDigit(s[1]) || !isDigit(s[2]) {
		return 0, 0, false
	}
	v := int(s[0]-'0')*100 + int(s[1]-'0')*10 + int(s[2]-'0')
	if v > 255 {
		return 0, 0, false
	}
	return byte(v), 3, true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func foldASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
