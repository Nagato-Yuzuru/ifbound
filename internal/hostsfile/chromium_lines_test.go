// The reference parser in this file is a port of HostsParser and
// ParseHostsWithCommaMode in the Chromium file net/dns/dns_hosts.cc
// (commit 2600dc0efdc944b3214d54302514fc3c1aa1522b), Copyright 2012 The
// Chromium Authors, under the BSD 3-Clause license; the full text is in
// LICENSES/BSD-3-Clause-Chromium.txt at the root of the repository, and
// NOTICE lists it.

package hostsfile

import (
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
)

// refHostsParser is HostsParser of dns_hosts.cc:27-130 with
// PARSE_HOSTS_COMMA_IS_WHITESPACE, written for the test apart from
// dialect.go. It walks the whole file, as Chromium does.
type refHostsParser struct {
	text      string
	pos       int // -1 is std::string::npos
	token     string
	tokenIsIP bool
}

// find returns the first position from pos with a byte in set (in true)
// or not in set (in false), or -1.
func (p *refHostsParser) find(set string, in bool) int {
	for i := p.pos; i < len(p.text); i++ {
		if (strings.IndexByte(set, p.text[i]) >= 0) == in {
			return i
		}
	}
	return -1
}

// advance is HostsParser::Advance (dns_hosts.cc:40-82).
func (p *refHostsParser) advance() bool {
	nextIsIP := p.pos == 0
	for p.pos != -1 && p.pos < len(p.text) {
		switch p.text[p.pos] {
		case ' ', '\t', ',':
			p.pos = p.find(" ,\t", false)
		case '\r', '\n':
			nextIsIP = true
			p.pos++
		case '#':
			p.skipRestOfLine()
		default:
			start := p.pos
			p.pos = p.find(" ,\t\n\r#", true)
			end := p.pos
			if end == -1 {
				end = len(p.text)
			}
			p.token, p.tokenIsIP = p.text[start:end], nextIsIP
			return true
		}
	}
	return false
}

// skipRestOfLine is HostsParser::SkipRestOfLine (dns_hosts.cc:87): it
// goes to the next LF, not to a CR.
func (p *refHostsParser) skipRestOfLine() {
	if p.pos == -1 {
		return
	}
	if i := strings.IndexByte(p.text[p.pos:], '\n'); i >= 0 {
		p.pos += i
	} else {
		p.pos = -1
	}
}

type refPair struct {
	addr netip.Addr
	name dnsname.Name
}

// refChromium is ParseHostsWithCommaMode (dns_hosts.cc:132-176). It uses
// the field readers of chromium.go, which chromium_test.go checks against
// Chrome.
func refChromium(text string) []refPair {
	p := &refHostsParser{text: text}
	var (
		ipText string
		ip     netip.Addr
		out    []refPair
	)
	for p.advance() {
		if p.tokenIsIP {
			if p.token != ipText {
				if a, ok := chromiumAddr(p.token); ok {
					ipText, ip = p.token, a
				} else {
					p.skipRestOfLine()
				}
			}
			continue
		}
		if n, use := chromiumName(p.token); use == nameUsed {
			out = append(out, refPair{ip, n})
		}
	}
	return out
}

// Every pair that Chromium maps must have an entry with the address and
// the name, on generated host files.
func TestParseMatchesChromiumLines(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(20261013, 3))
	var files []string
	for range 2000 {
		files = append(files, chromiumStructured(rng), chromiumNoise(rng))
	}
	pairs := 0
	for _, f := range files {
		h, err := Parse(strings.NewReader(f))
		if err != nil {
			t.Fatal(err)
		}
		for _, rp := range refChromium(f) {
			pairs++
			if !hasName(h, rp.addr, rp.name) {
				t.Errorf("file %q: Chromium %v %q, Parse %q", f, rp.addr, rp.name, render(h))
			}
		}
	}
	if pairs < 1000 {
		t.Fatalf("only %d pairs", pairs)
	}
}

// chromiumStructured makes a file of lines of an address and names, with
// the separators, comments, and line ends that Chromium treats in its own
// way.
func chromiumStructured(rng *rand.Rand) string {
	addrs := []string{"1.2.3.4", "10.0.0.1", "010.0.0.1", "0177.0.0.1", "1.2.3.4.", "0x7f.1", "127.1", "::1",
		"::ffff:010.0.0.1", "fd00::10", "bad", "1.2.3.4#x", "#1.2.3.4", "fe80::1%en0", "192.168.001.010",
		"08.1.1.1", "4294967295", "1.2.3.256", "\ufeff1.2.3.4", "1.2.3.4\x00"}
	names := []string{"protected.example", "Protected.Example", "PROTECTED.EXAMPLE.", "bücher.example",
		"%70rotected.example", "a#b.example", "x\x00y.example", "1.2.3.4", "a..b", "ｐrotected.example",
		"_s.example", "-a.example", "a.example", "nas.lan", "*.example", "a.123", "xn--bcher-kva.example",
		"exämple.com", strings.Repeat("a", 63) + ".example", strings.Repeat("a", 64) + ".example",
		"%zz.example", "مثال.example", "⒈.example"}
	seps := []string{" ", "\t", ",", " , ", ",,", "\t "}
	// A line of only separators between CRs is a line end too.
	ends := []string{"\n", "\r\n", "\r", "\n\r", "\r\r\n", "\n\n", "\r,\r", "\r , \t\r\n"}
	pick := func(s []string) string { return s[rng.IntN(len(s))] }
	line := func() string {
		if rng.Float64() < 0.06 {
			return "#" + pick([]string{"", " ", "x"}) + pick([]string{"comment", " 1.2.3.4 protected.example"})
		}
		s := pick([]string{"", "", "", " ", "\t", ",", " ,"}) + pick(addrs)
		for range []int{0, 1, 1, 2, 3, 5}[rng.IntN(6)] {
			s += pick(seps) + pick(names)
		}
		if rng.Float64() < 0.12 {
			s += pick([]string{"#", " #", "# ", "#x "}) + pick([]string{"", "protected.example", " 5.6.7.8 protected.example"})
		}
		if rng.Float64() < 0.03 {
			i := rng.IntN(len(s) + 1)
			s = s[:i] + "\x00" + s[i:]
		}
		if rng.Float64() < 0.05 {
			s += pick(seps)
		}
		return s
	}
	var b strings.Builder
	for range 1 + rng.IntN(8) {
		b.WriteString(line() + pick(ends))
	}
	if rng.Float64() < 0.3 {
		return strings.TrimRight(b.String(), "\r\n")
	}
	return b.String()
}

// chromiumNoise makes a file of random pieces.
func chromiumNoise(rng *rand.Rand) string {
	pieces := []string{"1.2.3.4", " ", "\t", ",", "\r", "\n", "#", "protected.example", "010.0.0.1", "\x00",
		"a", "%70", "ü", "::1", ".", "0x7f.1", "5.6.7.8", "\r\n", "b.example", "1.2.3.4.", "0", "x"}
	weights := []int{6, 6, 3, 3, 3, 4, 2, 6, 2, 1, 3, 1, 1, 1, 2, 1, 3, 2, 3, 1, 1, 1}
	total := 0
	for _, w := range weights {
		total += w
	}
	target := []int{30, 100, 300, 1100}[rng.IntN(4)]
	var b strings.Builder
	for b.Len() < target {
		r := rng.IntN(total)
		for i, w := range weights {
			if r < w {
				b.WriteString(pieces[i])
				break
			}
			r -= w
		}
	}
	return b.String()
}
