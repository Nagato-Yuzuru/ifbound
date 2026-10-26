package dnsname_test

// Differential test of the canonical form. The reference is the wire
// form that miekg/dns packs from the same presentation text. Two names
// share a key exactly when their wire labels are equal after ASCII case
// folding.

import (
	"errors"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
)

type refVerdict int

const (
	refOK refVerdict = iota
	refRoot
	refMalformed
)

// badEscape reports an escape that RFC 1035 section 5.1 does not define:
// a backslash at the end, or a backslash and a digit that do not start
// three digits of a value up to 255. miekg/dns reads these leniently (it
// wraps "\256" to 0 and reads "\9" as "9"), so the reference decides them
// by the RFC rule.
func badEscape(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			continue
		}
		if i+1 == len(s) {
			return true
		}
		if !isDigit(s[i+1]) {
			i++
			continue
		}
		if i+3 >= len(s) || !isDigit(s[i+2]) || !isDigit(s[i+3]) {
			return true
		}
		if v, _ := strconv.Atoi(s[i+1 : i+4]); v > 255 { //nolint:errcheck // isDigit checked all three bytes above, so Atoi cannot fail
			return true
		}
		i += 3
	}
	return false
}

// asciiText respells each octet from 0x80 up as "\DDD". dns.IsFqdn, which
// PackDomainName also calls, counts the backslashes before a final dot by
// rune index, so a multi-byte rune before "\\." or "\." flips its answer.
// The respelling names the same octets (RFC 1035 section 5.1) and keeps
// miekg/dns on ASCII. The caller has already refused bad escapes.
func asciiText(s string) string {
	var b strings.Builder
	octet := func(c byte) {
		if c >= 0x80 {
			b.WriteString(`\` + leftPad(int(c)))
			return
		}
		b.WriteByte(c)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && isDigit(s[i+1]):
			b.WriteString(s[i : i+4])
			i += 3
		case c == '\\':
			if s[i+1] >= 0x80 {
				octet(s[i+1])
			} else {
				b.WriteString(s[i : i+2])
			}
			i++
		default:
			octet(c)
		}
	}
	return b.String()
}

// endsInDot reports a final dot that no backslash escapes.
func endsInDot(s string) bool {
	if s == "" || s[len(s)-1] != '.' {
		return false
	}
	n := 0
	for i := len(s) - 2; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n%2 == 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func foldASCII(b []byte) string {
	out := []byte(string(b))
	for i, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + 'a' - 'A'
		}
	}
	return string(out)
}

// refLabels returns the labels of s, folded, as miekg/dns packs them into
// a buffer of 255 octets, the wire limit.
func refLabels(s string) ([]string, refVerdict) {
	if s == "" || badEscape(s) {
		return nil, refMalformed
	}
	fq := asciiText(s)
	if !endsInDot(fq) {
		fq += "."
	}
	buf := make([]byte, 255)
	off, err := dns.PackDomainName(fq, buf, 0, nil, false)
	if err != nil {
		return nil, refMalformed
	}
	var labels []string
	for i := 0; i < off; {
		n := int(buf[i])
		if n == 0 {
			break
		}
		labels = append(labels, foldASCII(buf[i+1:i+1+n]))
		i += 1 + n
	}
	if len(labels) == 0 {
		return nil, refRoot
	}
	return labels, refOK
}

// checkAgainstWire checks one input against the reference and returns the
// reference labels when the input is a valid non-root name.
func checkAgainstWire(t *testing.T, s string) ([]string, bool) {
	t.Helper()
	want, verdict := refLabels(s)
	got, serr := dnsname.Split(s)
	n, perr := dnsname.Parse(s)
	switch verdict {
	case refMalformed:
		if !errors.Is(serr, dnsname.ErrMalformedName) || !errors.Is(perr, dnsname.ErrMalformedName) || n != (dnsname.Name{}) {
			t.Fatalf("%q: reference malformed; Split err %v, Parse = %q, %v", s, serr, n, perr)
		}
		return nil, false
	case refRoot:
		if serr != nil || len(got) != 0 || !errors.Is(perr, dnsname.ErrRootName) {
			t.Fatalf("%q: reference root; Split = %q, %v; Parse err %v", s, got, serr, perr)
		}
		return nil, false
	case refOK:
	}
	if serr != nil || perr != nil {
		t.Fatalf("%q: reference labels %q; Split err %v, Parse err %v", s, want, serr, perr)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%q: Split = %q, reference %q", s, got, want)
	}
	checkKey(t, s, n, want)
	return want, true
}

// checkKey checks the key of a valid name with the reference labels want.
func checkKey(t *testing.T, s string, n dnsname.Name, want []string) {
	t.Helper()
	// The String is a presentation form of the same labels. Each letter
	// in it, escaped or not, stands for itself, so it holds no upper case.
	back, v := refLabels(n.String())
	if v != refOK || !slices.Equal(back, want) {
		t.Fatalf("%q: String %q reads as %q (%v) in miekg/dns, want %q", s, n.String(), back, v, want)
	}
	if strings.ContainsFunc(n.String(), func(r rune) bool { return r >= 'A' && r <= 'Z' }) {
		t.Fatalf("%q: String %q holds upper case", s, n.String())
	}
	if again, err := dnsname.Parse(n.String()); err != nil || again != n {
		t.Fatalf("%q: Parse(String %q) = %q, %v", s, n.String(), again, err)
	}
	// Every spelling of the labels gives the same key.
	for _, sp := range []string{spellDDD(want, true), spellDDD(want, false)} {
		if m, err := dnsname.Parse(sp); err != nil || m != n {
			t.Fatalf("%q: spelling %q gives %q, %v; want %q", s, sp, m, err, n)
		}
	}
}

// spellDDD spells every octet as "\DDD" (the longest text), with or
// without the final dot.
func spellDDD(labels []string, final bool) string {
	var b strings.Builder
	for i, l := range labels {
		if i > 0 {
			b.WriteByte('.')
		}
		for j := range len(l) {
			b.WriteString(`\` + leftPad(int(l[j])))
		}
	}
	if final {
		b.WriteByte('.')
	}
	return b.String()
}

func leftPad(v int) string {
	s := strconv.Itoa(v)
	return strings.Repeat("0", 3-len(s)) + s
}

// spellRandom spells labels with a random mix of raw bytes (letters in
// random case), "\X" and "\DDD".
func spellRandom(r *rand.Rand, labels []string) string {
	var b strings.Builder
	for i, l := range labels {
		if i > 0 {
			b.WriteByte('.')
		}
		for j := range len(l) {
			c := l[j]
			switch k := r.IntN(4); {
			case k == 0:
				b.WriteString(`\` + leftPad(int(c)))
			case k == 1 && !isDigit(c):
				b.WriteByte('\\')
				b.WriteByte(upperMaybe(r, c))
			case c == '.' || c == '\\':
				b.WriteByte('\\')
				b.WriteByte(c)
			default:
				b.WriteByte(upperMaybe(r, c))
			}
		}
	}
	if r.IntN(2) == 0 {
		b.WriteByte('.')
	}
	return b.String()
}

func upperMaybe(r *rand.Rand, c byte) byte {
	if c >= 'a' && c <= 'z' && r.IntN(2) == 0 {
		return c - 'a' + 'A'
	}
	return c
}

// lookAlikeBytes holds the bytes that make texts look alike: dots,
// backslashes, digits, case pairs, space, controls and high octets.
var lookAlikeBytes = []byte{'a', 'A', 'b', 'z', 'Z', '0', '9', '.', '\\', ' ', 0, 9, 10, 31, 127, 128, 200, 255, '*', '"', ';', '(', '@', '$'}

func randomLabels(r *rand.Rand) []string {
	n := 1 + r.IntN(4)
	if r.IntN(50) == 0 {
		n = 1 + r.IntN(127)
	}
	labels := make([]string, n)
	for i := range labels {
		size := 1 + r.IntN(4)
		switch r.IntN(40) {
		case 0:
			size = 63
		case 1:
			size = 64
		}
		l := make([]byte, size)
		for j := range l {
			l[j] = lookAlikeBytes[r.IntN(len(lookAlikeBytes))]
		}
		labels[i] = string(l)
	}
	return labels
}

// randomText builds raw text from presentation fragments, valid or not.
func randomText(r *rand.Rand) string {
	frags := []string{"a", "B", ".", "..", `\`, `\.`, `\\`, `\0`, `\00`, `\000`, `\065`, `\255`, `\256`, `\999`, `\9`, `\a`, `\A`, "0", " ", "\x00", "\xff", `\046`, `\092`}
	var b strings.Builder
	for range r.IntN(12) {
		b.WriteString(frags[r.IntN(len(frags))])
	}
	return b.String()
}

// Spellings of one label list give one key; different label lists never
// share a key.
func TestCanonicalVsWire(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewPCG(117, 1))
	keyOf := map[dnsname.Name]string{} // key -> joined reference labels
	join := func(ls []string) string { return strconv.Quote(strings.Join(ls, "\x00|")) }
	record := func(s string) {
		labels, ok := checkAgainstWire(t, s)
		if !ok {
			return
		}
		n, _ := dnsname.Parse(s) //nolint:errcheck // checkAgainstWire already failed the test on any Parse error
		j := join(labels)
		if prev, seen := keyOf[n]; seen && prev != j {
			t.Fatalf("key %q is shared by labels %s and %s", n, prev, j)
		}
		keyOf[n] = j
	}
	// The count bounds the run to well under a second.
	for range 12000 {
		labels := randomLabels(r)
		record(spellRandom(r, labels))
		record(spellDDD(labels, r.IntN(2) == 0))
		record(randomText(r))
	}
	// Equal labels after folding share one key.
	byLabels := map[string]dnsname.Name{}
	for n, j := range keyOf {
		if other, dup := byLabels[j]; dup && other != n {
			t.Fatalf("labels %s have keys %q and %q", j, other, n)
		}
		byLabels[j] = n
	}
	t.Logf("%d distinct keys checked", len(keyOf))
}

// Exact limits: a 63-octet label, a 255-octet wire form and the
// 1004-byte longest text are valid; one octet more is not.
func TestCanonicalLimits(t *testing.T) {
	t.Parallel()
	lbl := func(n int) string { return strings.Repeat("a", n) }
	cases := []string{
		lbl(63), lbl(64), lbl(63) + ".", lbl(64) + ".",
		spellDDD([]string{lbl(63), lbl(63), lbl(63), lbl(61)}, true),  // 255 octets, 1004 bytes
		spellDDD([]string{lbl(63), lbl(63), lbl(63), lbl(61)}, false), // 1003 bytes
		spellDDD([]string{lbl(63), lbl(63), lbl(63), lbl(62)}, true),  // 256 octets
		spellDDD([]string{lbl(63), lbl(63), lbl(63), lbl(61)}, true) + "a",
		strings.Repeat("a.", 127), strings.Repeat("a.", 128), strings.Repeat("a.", 126) + "aa",
		`\.`, `\\`, `\..`, `\\.`, `.`, `..`, `.a`, `a\`, `a\\`, `a\0`, `a\00`, `a\255`, `a\256`,
	}
	valid := 0
	for _, s := range cases {
		if _, ok := checkAgainstWire(t, s); ok {
			valid++
		}
	}
	if valid != 11 {
		t.Fatalf("%d valid limit cases, want 11", valid)
	}
}

// FuzzCanonicalPair explores pairs: equal keys exactly when the
// folded wire labels are equal.
func FuzzCanonicalPair(f *testing.F) {
	f.Add("a.b", `a\.b`)
	f.Add(`\0099`, `c`)
	f.Add(`a\\.b`, `a\.b`)
	f.Add("A.B.", `\097.b`)
	f.Add(`\032`, ` `)
	f.Fuzz(func(t *testing.T, a, b string) {
		la, oka := checkAgainstWire(t, a)
		lb, okb := checkAgainstWire(t, b)
		if !oka || !okb {
			return
		}
		na, _ := dnsname.Parse(a) //nolint:errcheck // checkAgainstWire already failed the test on any Parse error
		nb, _ := dnsname.Parse(b) //nolint:errcheck // checkAgainstWire already failed the test on any Parse error
		if (na == nb) != slices.Equal(la, lb) {
			t.Fatalf("Parse(%q) = %q, Parse(%q) = %q; labels %q vs %q", a, na, b, nb, la, lb)
		}
	})
}
