package matcher_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/matcher"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// refDest is a domain destination as the reference sees it: a label list
// that the test reads from the destination text, not from the matcher.
type refDest struct {
	labels []string
	suffix bool
}

type refPolicy struct {
	name  policy.Name
	dests []refDest
}

// parseSpec builds policies from spec: policies split by ";" and
// destinations split by ",". Text that does not parse is skipped. It
// returns the reference form beside the real one.
func parseSpec(spec string) ([]policy.Policy, []refPolicy) {
	var (
		policies []policy.Policy
		refs     []refPolicy
	)
	for i, ps := range strings.Split(spec, ";") {
		p := policy.Policy{
			Name:       policy.Name("p" + string(rune('a'+i%26)) + string(rune('a'+i/26%26))),
			Constraint: policy.NewOnlyVia(),
		}
		r := refPolicy{name: p.Name}
		for ds := range strings.SplitSeq(ps, ",") {
			dest, err := policy.ParseDestination(ds)
			if err != nil {
				continue
			}
			p.To = append(p.To, dest)
			if _, ok := domainOf(dest); ok {
				rest, suffix := strings.CutPrefix(ds, "*.")
				rest = strings.TrimSuffix(strings.ToLower(rest), ".")
				r.dests = append(r.dests, refDest{labels: strings.Split(rest, "."), suffix: suffix})
			}
		}
		if len(p.To) > 0 {
			policies = append(policies, p)
			refs = append(refs, r)
		}
	}
	return policies, refs
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// refMatch is the brute-force oracle: it loops over every destination and
// compares label lists. It uses no code from the matcher or the parser.
func refMatch(refs []refPolicy, q []string) []policy.Name {
	var out []policy.Name
	for _, p := range refs {
		for _, d := range p.dests {
			n := len(d.labels)
			ok := len(q) == n || (d.suffix && len(q) > n)
			if ok && slices.Equal(q[len(q)-n:], d.labels) {
				out = append(out, p.name)
				break
			}
		}
	}
	return out
}

// queryLabels reads labels from data. A length byte gives the label
// length (0 to 7), and the next bytes are the label. Any byte can occur.
func queryLabels(data []byte) []string {
	var labels []string
	for len(data) > 0 && len(labels) < 20 { // 20 short labels stay under the wire limit
		n := int(data[0]%7) + 1
		data = data[1:]
		n = min(n, len(data))
		if n == 0 {
			break
		}
		labels = append(labels, string(data[:n]))
		data = data[n:]
	}
	return labels
}

// spell writes one label byte. ch picks one of the equivalent spellings.
func spell(sb *strings.Builder, c, ch byte) {
	special := c == '.' || c == '\\'
	printable := c > ' ' && c < 0x7f
	digit := c >= '0' && c <= '9'
	switch {
	case digit && ch%2 == 0, printable && !special && !digit && ch%3 == 0:
		sb.WriteByte(c)
	case printable && !digit && ch%3 == 1:
		sb.WriteByte('\\')
		sb.WriteByte(c)
	default:
		sb.WriteByte('\\')
		sb.WriteByte('0' + c/100)
		sb.WriteByte('0' + c/10%10)
		sb.WriteByte('0' + c%10)
	}
}

// encode writes labels in presentation form. Each byte of enc picks the
// spelling of one label byte, and the first byte decides the final dot.
func encode(labels []string, enc []byte) string {
	if len(labels) == 0 {
		return "."
	}
	k := 0
	var sb strings.Builder
	for i, l := range labels {
		if i > 0 {
			sb.WriteByte('.')
		}
		for j := range len(l) {
			var ch byte
			if len(enc) > 0 {
				k++
				ch = enc[k%len(enc)]
			}
			spell(&sb, l[j], ch)
		}
	}
	if len(enc) > 0 && enc[0]%2 == 0 {
		sb.WriteByte('.')
	}
	return sb.String()
}

func domainOf(dest policy.Destination) (string, bool) {
	switch x := dest.(type) {
	case policy.ExactDomain:
		return x.Domain().String(), true
	case policy.DomainSuffix:
		return x.Domain().String(), true
	case policy.IPAddr, policy.CIDR:
	}
	return "", false
}

func below(name, ancestor string) bool { return strings.HasSuffix(name, "."+ancestor) }

// checkApexes asserts that the apexes are sorted, unique, free of nesting,
// and cover every domain destination.
func checkApexes(t *testing.T, m *matcher.Matcher, policies []policy.Policy) {
	t.Helper()
	var apexes []string
	for _, a := range m.Apexes() {
		apexes = append(apexes, a.String())
	}
	if !slices.IsSorted(apexes) || len(slices.Compact(slices.Clone(apexes))) != len(apexes) {
		t.Fatalf("Apexes not sorted and unique: %v", apexes)
	}
	for i, a := range apexes {
		for j, b := range apexes {
			if i != j && below(a, b) {
				t.Fatalf("apex %q is below apex %q", a, b)
			}
		}
	}
	for _, p := range policies {
		for _, dest := range p.To {
			d, ok := domainOf(dest)
			if !ok {
				continue
			}
			if !slices.ContainsFunc(apexes, func(a string) bool { return d == a || below(d, a) }) {
				t.Fatalf("domain %q not covered by %v", d, apexes)
			}
		}
	}
}

// FuzzMatch compares the tree with a label-list oracle. The query is a
// list of arbitrary bytes that the test encodes in a random spelling.
func FuzzMatch(f *testing.F) {
	f.Add("*.bing.com,www.bing.com;a.bing.com", []byte("\x03bing\x03com"), []byte{0, 1, 2})
	f.Add("*.a.b;a.b,*.b", []byte("\x01A\x01b"), []byte{2})
	f.Add("a;*.a;1.2.3.4,10.0.0.0/8", []byte("\x01b\x01a"), []byte{1, 0})
	f.Add("a.b.c.com;c.com", []byte("\x01x\x01c\x03com"), []byte{})
	f.Add("*.a", []byte("\x03.\\\xff\x01a"), []byte{1, 1, 1, 2})
	f.Add("*.a", []byte("\x01a"), []byte{})
	f.Fuzz(func(t *testing.T, spec string, qdata, enc []byte) {
		policies, refs := parseSpec(spec)
		m := matcher.New(policies)
		labels := queryLabels(qdata)
		q := encode(labels, enc)
		folded := make([]string, len(labels))
		for i, l := range labels {
			folded[i] = lowerASCII(l)
		}
		got, err := m.Match(q)
		if err != nil {
			t.Fatalf("Match(%q) error: %v", q, err)
		}
		if want := refMatch(refs, folded); !slices.Equal(got, want) {
			t.Fatalf("Match(%q) = %v, oracle = %v (labels %q)", q, got, want, labels)
		}
		checkApexes(t, m, policies)
	})
}

// FuzzMatchRaw feeds arbitrary strings. Match must not panic, and its
// outcome must be names or ErrMalformedName.
func FuzzMatchRaw(f *testing.F) {
	for _, s := range []string{"", ".", "a..b", `\`, `\9`, `\256`, "a.com.", `a\.b`, "\xff\x00"} {
		f.Add(s)
	}
	m := matcher.New(nil)
	f.Fuzz(func(t *testing.T, s string) {
		got, err := m.Match(s)
		if err != nil && (!errors.Is(err, matcher.ErrMalformedName) || got != nil) {
			t.Fatalf("Match(%q) = %v, %v", s, got, err)
		}
	})
}
