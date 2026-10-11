package matcher_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/matcher"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// build makes policies named p0, p1, ... from lists of destination text.
func build(tb testing.TB, specs [][]string) []policy.Policy {
	tb.Helper()
	var out []policy.Policy
	for i, spec := range specs {
		p := policy.Policy{
			Name:       policy.Name("p" + string(rune('0'+i))),
			Constraint: policy.NewOnlyVia(),
		}
		for _, s := range spec {
			d, err := policy.ParseDestination(s)
			if err != nil {
				tb.Fatalf("ParseDestination(%q): %v", s, err)
			}
			p.To = append(p.To, d)
		}
		out = append(out, p)
	}
	return out
}

func names(ns []policy.Name) []string {
	var out []string
	for _, n := range ns {
		out = append(out, string(n))
	}
	return out
}

func TestMatch(t *testing.T) {
	t.Parallel()
	m := matcher.New(build(t, [][]string{
		{"www.bing.com"},                 // p0 exact
		{"*.bing.com"},                   // p1 suffix
		{"*.bing.com", "a.bing.com"},     // p2 two matching destinations
		{"10.0.0.0/8", "1.2.3.4", "x.y"}, // p3 IP and CIDR are ignored
	}))
	tests := []struct {
		name  string
		qname string
		want  []string
	}{
		{"exact matches itself and the suffix policies", "www.bing.com", []string{"p0", "p1", "p2"}},
		{"exact does not match a child", "a.www.bing.com", []string{"p1", "p2"}},
		{"suffix includes the apex", "bing.com", []string{"p1", "p2"}},
		{"label boundary", "notbing.com", nil},
		{"unrelated tld", "bing.org", nil},
		{"parent of the suffix", "com", nil},
		{"upper case", "WWW.Bing.COM", []string{"p0", "p1", "p2"}},
		{"trailing dot", "www.bing.com.", []string{"p0", "p1", "p2"}},
		{"escaped letter", `\119ww.bing.com`, []string{"p0", "p1", "p2"}},
		{"escaped upper case letter", `\087ww.bing.com`, []string{"p0", "p1", "p2"}},
		{"two destinations of one policy give one entry", "a.bing.com", []string{"p1", "p2"}},
		{"other exact", "x.y", []string{"p3"}},
		{"root", ".", nil},
		{"escaped dot joins a label", `www\.bing.com.`, nil},
		{"decimal dot joins a label", `www\046bing.com.`, nil},
		{"escaped dot ends the last label", `bing.com\.`, nil},
		{"escaped backslash then separator", `a\\.bing.com.`, []string{"p1", "p2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := m.Match(tt.qname)
			if err != nil {
				t.Fatalf("Match(%q) error: %v", tt.qname, err)
			}
			if !slices.Equal(names(got), tt.want) {
				t.Errorf("Match(%q) = %v, want %v", tt.qname, got, tt.want)
			}
		})
	}
}

// TestMatchOddLabels pins the fail-open fix: a resolver answers these
// names through a wildcard, so they must match the suffix policy.
func TestMatchOddLabels(t *testing.T) {
	t.Parallel()
	m := matcher.New(build(t, [][]string{{"*.bing.com"}, {"www.bing.com"}}))
	qnames := []string{
		"x.bing.com.", "-x.bing.com.", "x-.bing.com.", "a*b.bing.com.", "*.bing.com.",
		`a\032b.bing.com.`, `a\ b.bing.com.`, `a\.b.bing.com.`, "a/b.bing.com.",
		"a+b.bing.com.", "a~b.bing.com.", "a=b.bing.com.", "a:b.bing.com.",
		"[x].bing.com.", "a,b.bing.com.", `\195\175.bing.com.`, "\xc3\xaf.bing.com.",
		strings.Repeat("a", 63) + ".bing.com.", `\(x\).bing.com.`, `a\"b.bing.com.`,
		`a\@b.bing.com.`, `a\;b.bing.com.`, `a\\b.bing.com.`, `a\\.bing.com.`,
		`\000.bing.com.`, `\255.bing.com.`, `a\.b\.c.bing.com`,
	}
	for _, q := range qnames {
		got, err := m.Match(q)
		if err != nil || !slices.Equal(names(got), []string{"p0"}) {
			t.Errorf("Match(%q) = %v, %v; want [p0], nil", q, got, err)
		}
	}
}

func TestMatchMalformed(t *testing.T) {
	t.Parallel()
	m := matcher.New(build(t, [][]string{{"*.bing.com"}}))
	label := func(n int) string { return strings.Repeat("a", n) }
	qnames := map[string]string{
		"empty":                               "",
		"empty interior label":                "a..bing.com",
		"two trailing dots":                   "bing.com..",
		"empty label after escaped backslash": `a\\..bing.com`,
		"leading dot":                         ".bing.com",
		"dangling backslash":                  `bing.com\`,
		"one digit":                           `a\9.bing.com`,
		"two digits":                          `a\99.bing.com`,
		"digit then letters":                  `a\9x.bing.com`,
		"non-digit in the middle":             `a\0:0.bing.com`,
		"256":                                 `a\256.bing.com`,
		"999":                                 `a\999.bing.com`,
		"label of 64":                         label(64) + ".bing.com",
		"label of 64 by escape":               strings.Repeat(`\097`, 64) + ".bing.com",
		"wire length 256":                     label(63) + "." + label(63) + "." + label(63) + "." + label(62),
	}
	for name, q := range qnames {
		got, err := m.Match(q)
		if !errors.Is(err, matcher.ErrMalformedName) || got != nil {
			t.Errorf("%s: Match(%q) = %v, %v; want ErrMalformedName", name, q, got, err)
		}
	}
	// The longest valid name has a wire length of 255.
	long := label(63) + "." + label(63) + "." + label(63) + "." + label(61)
	if _, err := m.Match(long); err != nil {
		t.Errorf("Match(255-byte name) error: %v", err)
	}
}

func TestZeroMatcher(t *testing.T) {
	t.Parallel()
	var m matcher.Matcher
	if got, err := m.Match("a.com"); got != nil || err != nil {
		t.Errorf("Match = %v, %v; want nil, nil", got, err)
	}
	if got := m.Apexes(); len(got) != 0 {
		t.Errorf("Apexes = %v, want none", got)
	}
}

func TestMatchEmpty(t *testing.T) {
	t.Parallel()
	m := matcher.New(nil)
	if got, err := m.Match("a.com"); got != nil || err != nil {
		t.Errorf("Match = %v, %v; want nil, nil", got, err)
	}
	if got := m.Apexes(); len(got) != 0 {
		t.Errorf("Apexes = %v, want none", got)
	}
}

func TestApexes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		specs [][]string
		want  []string
	}{
		{"suffix and exact below it", [][]string{{"*.bing.com", "www.bing.com"}}, []string{"bing.com"}},
		{"exact above suffix", [][]string{{"bing.com", "*.www.bing.com"}}, []string{"bing.com"}},
		{"deep chain", [][]string{{"a.b.c.com", "b.c.com", "c.com"}}, []string{"c.com"}},
		{"gap in the chain", [][]string{{"a.b.c.com", "c.com"}}, []string{"c.com"}},
		{"across policies, sorted", [][]string{{"z.com"}, {"a.com", "x.a.com"}}, []string{"a.com", "z.com"}},
		{"duplicates across policies", [][]string{{"a.com"}, {"*.a.com"}}, []string{"a.com"}},
		{"siblings stay", [][]string{{"a.b.com", "c.b.com"}}, []string{"a.b.com", "c.b.com"}},
		{"label boundary", [][]string{{"notbing.com", "bing.com"}}, []string{"bing.com", "notbing.com"}},
		{"ip and cidr excluded", [][]string{{"1.2.3.4", "10.0.0.0/8", "::1"}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got []string
			for _, d := range matcher.New(build(t, tt.specs)).Apexes() {
				got = append(got, d.String())
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Apexes = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResultsAreCopies(t *testing.T) {
	t.Parallel()
	m := matcher.New(build(t, [][]string{{"a.com"}, {"b.com"}}))
	ap := m.Apexes()
	ap[0] = ap[1]
	if got := m.Apexes()[0].String(); got != "a.com" {
		t.Errorf("Apexes()[0] = %q after caller write, want a.com", got)
	}
}

func TestFoldEveryLetter(t *testing.T) {
	t.Parallel()
	for l := 'a'; l <= 'z'; l++ {
		lower := string(l)
		upper := strings.ToUpper(lower)
		m := matcher.New(build(t, [][]string{{"*." + lower + lower + ".com"}}))
		decimal := fmt.Sprintf(`\%03d`, upper[0])
		for _, q := range []string{
			upper + upper + ".COM", upper + upper + ".com.",
			decimal + decimal + ".com", decimal + upper + ".com.",
		} {
			got, err := m.Match(q)
			if err != nil || !slices.Equal(names(got), []string{"p0"}) {
				t.Errorf("Match(%q) = %v, %v; want [p0]", q, got, err)
			}
		}
	}
}

// TestFoldASCIIOnly pins that Unicode case folding never applies.
func TestFoldASCIIOnly(t *testing.T) {
	t.Parallel()
	m := matcher.New(build(t, [][]string{{"k.com", "i.com", "*.s.com"}}))
	qnames := []string{
		`\226\132\170.com.`, // KELVIN SIGN, looks like K
		"K.com.",            // the same, raw UTF-8
		"İ.com.",            // I with dot above
		"x.İ.com.",
		"ſ.s.com.x", // long s
		"ſ.com.",
	}
	for _, q := range qnames {
		if got, err := m.Match(q); err != nil || got != nil {
			t.Errorf("Match(%q) = %v, %v; want no match", q, got, err)
		}
	}
}

// TestMatchOrder pins file order when the tree walk meets a later policy
// first: the walk reaches "com" before "www".
func TestMatchOrder(t *testing.T) {
	t.Parallel()
	m := matcher.New(build(t, [][]string{
		{"www.bing.com"},
		{"*.bing.com", "*.www.bing.com", "www.bing.com"},
		{"*.com"},
	}))
	tests := []struct {
		qname string
		want  []string
	}{
		{"www.bing.com.", []string{"p0", "p1", "p2"}},
		{"x.www.bing.com.", []string{"p1", "p2"}},
		{"bing.com", []string{"p1", "p2"}},
	}
	for _, tt := range tests {
		got, err := m.Match(tt.qname)
		if err != nil || !slices.Equal(names(got), tt.want) {
			t.Errorf("Match(%q) = %v, %v; want %v", tt.qname, got, err, tt.want)
		}
	}
}
