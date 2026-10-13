// Parts of this file are ports of Chromium code at commit
// 2600dc0efdc944b3214d54302514fc3c1aa1522b:
//
//   - url/url_canon_ip.h, url/url_canon_host.cc, url/url_idna_icu.cc,
//     url/url_canon_internal.h, net/base/url_util.cc:
//     Copyright 2013 The Chromium Authors.
//   - net/base/ip_address.h: Copyright 2015 The Chromium Authors.
//   - net/dns/dns_hosts.cc: Copyright 2012 The Chromium Authors.
//
// Chromium is under the BSD 3-Clause license; the full text is in
// LICENSES/BSD-3-Clause-Chromium.txt at the root of the repository, and
// NOTICE lists it.

package hostsfile

import (
	"math"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
	"golang.org/x/net/idna"
)

// Electron apps use the same Chromium code as Chrome.

// chromiumAddr reads an address field as Chromium does
// (IPAddress::AssignFromIPLiteral, net/base/ip_address.h:135-160). A field
// with a colon is an IPv6 address, any other field an IPv4 address in the
// URL form: a part with a leading "0" is octal, and a final dot is
// ignored. A zone is not accepted.
func chromiumAddr(field string) (netip.Addr, bool) {
	if strings.IndexByte(field, ':') >= 0 {
		b, ok := urlIPv6(field)
		return netip.AddrFrom16(b).Unmap(), ok
	}
	b, _, fam := urlIPv4(field)
	if fam != urlIPv4Family {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4(b), true
}

// urlFamily is url::CanonHostInfo::Family, restricted to the values that
// the IPv4 parser returns.
type urlFamily int

const (
	// urlNeutral means that the text is not an IPv4 address. It can be a
	// host name.
	urlNeutral urlFamily = iota
	// urlIPv4Family means that the text is an IPv4 address.
	urlIPv4Family
	// urlBroken means that the text looks like an IPv4 address but is
	// not valid. It is neither an address nor a host name.
	urlBroken
)

// urlIPv4 is DoIPv4AddressToNumber (url/url_canon_ip.h:136-233). It
// returns the address and the number of parts.
func urlIPv4(s string) (addr [4]byte, parts int, fam urlFamily) {
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return addr, 0, urlNeutral
	}
	// The parts are read from the right: a last part that is not a number
	// makes a host name, any other part that is not a number makes the
	// text broken.
	var values [4]uint32
	for end := len(s); ; {
		start := strings.LastIndexByte(s[:end], '.') + 1
		v, f := urlIPv4Part(s[start:end])
		if f == urlNeutral && parts == 0 {
			return addr, 0, urlNeutral
		}
		if f != urlIPv4Family {
			return addr, 0, urlBroken
		}
		values[parts] = v
		parts++
		if start == 0 {
			break
		}
		if parts == len(values) {
			return addr, 0, urlBroken
		}
		end = start - 1
	}
	// values[0] is the last part. It fills the bytes that the other parts
	// leave. Each other part is one byte.
	for i := parts - 1; i > 0; i-- {
		if values[i] > math.MaxUint8 {
			return addr, 0, urlBroken
		}
		addr[parts-1-i] = byte(values[i])
	}
	last := values[0]
	for i := 4; i >= parts; i-- {
		addr[i-1] = byte(last)
		last >>= 8
	}
	if last != 0 {
		return addr, 0, urlBroken
	}
	return addr, parts, urlIPv4Family
}

// urlIPv4Part is IPv4ComponentToNumber (url/url_canon_ip.h:48-132). "0x"
// starts a hex number, another leading "0" an octal number. "0x" alone
// is zero. A decimal digit that is not valid in the base makes the part
// broken. A value over 32 bits is broken.
func urlIPv4Part(c string) (uint32, urlFamily) {
	if c == "" {
		return 0, urlNeutral
	}
	base, i := uint64(10), 0
	if c[0] == '0' && len(c) > 1 {
		if c[1] == 'x' || c[1] == 'X' {
			base, i = 16, 2
		} else {
			base, i = 8, 1
		}
	}
	for i < len(c) && c[i] == '0' {
		i++
	}
	const maxDigits = 16 // kMaxComponentLen: more digits always overflow
	var (
		num         uint64
		digits      int
		brokenOctal bool
	)
	for ; i < len(c); i++ {
		d, ok := digitIn(c[i], base)
		switch {
		case ok:
		case isDigit(c[i]):
			brokenOctal = true
			continue
		default:
			return 0, urlNeutral
		}
		if digits < maxDigits {
			num = num*base + d
			digits++
		}
	}
	if brokenOctal || num > math.MaxUint32 {
		return 0, urlBroken
	}
	return uint32(num), urlIPv4Family
}

// digitIn returns the value of c as a digit in base 8, 10, or 16.
func digitIn(c byte, base uint64) (uint64, bool) {
	var d uint64
	switch {
	case isDigit(c):
		d = uint64(c - '0')
	case 'a' <= c|0x20 && c|0x20 <= 'f':
		d = uint64(c|0x20-'a') + 10
	default:
		return 0, false
	}
	return d, d < base
}

// urlIPv6 is DoIPv6AddressToNumber (url/url_canon_ip.h:457-529) on the
// text inside the brackets. A group has at most four hex digits. An
// embedded IPv4 address has four parts in the URL form, so "010" in it
// is octal, and no final dot.
func urlIPv6(s string) (addr [16]byte, ok bool) {
	p, ok := splitIPv6(s)
	if !ok {
		return addr, false
	}
	// CheckIPv6ComponentsSize (url_canon_ip.h:403-430): a contraction
	// stands for at least one group.
	size := 2 * len(p.groups)
	if p.ipv4 != "" {
		size += 4
	}
	zeros := 0
	if p.contraction != -1 {
		zeros = max(16-size, 2)
	}
	if size+zeros != 16 {
		return addr, false
	}
	at := 0
	for i := 0; i <= len(p.groups); i++ {
		if i == p.contraction {
			at += zeros
		}
		if i < len(p.groups) {
			var v uint64
			for _, c := range []byte(p.groups[i]) {
				d, _ := digitIn(c, 16)
				v = v<<4 | d
			}
			addr[at], addr[at+1] = byte(v>>8), byte(v)
			at += 2
		}
	}
	if p.ipv4 != "" {
		v4, parts, fam := urlIPv4(p.ipv4)
		if fam != urlIPv4Family || parts != 4 || strings.HasSuffix(p.ipv4, ".") {
			return addr, false
		}
		copy(addr[at:], v4[:])
	}
	return addr, true
}

// ipv6Parts is IPv6Parsed (url/url_canon_ip.h:272-294).
type ipv6Parts struct {
	groups []string
	// contraction is the index of the group that "::" comes before, or
	// -1.
	contraction int
	// ipv4 is the embedded IPv4 address, or "".
	ipv4 string
}

// splitIPv6 is DoParseIPv6 (url/url_canon_ip.h:300-395). A character that
// is not a hex digit but can be in an IPv4 address starts the embedded
// IPv4 address, which goes to the end.
func splitIPv6(s string) (ipv6Parts, bool) {
	p := ipv6Parts{contraction: -1}
	if s == "" {
		return p, false
	}
	begin := 0
	for i := 0; ; i++ {
		colon := i < len(s) && s[i] == ':'
		double := colon && i < len(s)-1 && s[i+1] == ':'
		if (colon || i == len(s)) && !p.endGroup(s[begin:i], double && i == 0, i == len(s)) {
			return p, false
		}
		switch {
		case i == len(s):
			return p, true
		case double:
			if p.contraction != -1 {
				return p, false
			}
			p.contraction = len(p.groups)
			i++
			begin = i + 1
		case colon:
			begin = i + 1
		case s[i] == '.' || s[i] == 'x' || s[i] == 'X':
			p.ipv4 = s[begin:]
			return p, true
		default:
			if _, hex := digitIn(s[i], 16); !hex {
				return p, false
			}
		}
	}
}

// endGroup adds the group g that ends at a colon or at the end of the
// text. An empty group is valid only before a leading "::" or after a
// final "::".
func (p *ipv6Parts) endGroup(g string, leadingContraction, atEnd bool) bool {
	switch {
	case len(g) > 4:
		return false
	case g == "":
		return leadingContraction || atEnd && p.contraction == len(p.groups)
	case len(p.groups) == 8:
		return false
	}
	p.groups = append(p.groups, g)
	return true
}

// chromiumName reads a host name as Chromium does (ParseHostsWithCommaMode,
// net/dns/dns_hosts.cc:157-173): it canonicalizes the name as a URL host,
// skips a name that is an IPv4 address or broken, and skips a name that is
// not compliant. A name that chromiumIDNA refuses can still be valid in
// Chromium, so it is nameUnrepresentable.
func chromiumName(field string) (dnsname.Name, nameUse) {
	host, use := urlCanonHost(field)
	if use != nameUsed {
		return dnsname.Name{}, use
	}
	if _, _, fam := urlIPv4(host); fam != urlNeutral || !hostCompliant(host) {
		return dnsname.Name{}, nameRefused
	}
	if n, err := dnsname.Parse(host); err == nil {
		return n, nameUsed
	}
	return dnsname.Name{}, nameUnrepresentable // a compliant host always parses
}

// urlCanonHost is DoHostSubstring and DoComplexHost
// (url/url_canon_host.cc:240-470): percent-decoding, IDNA for a name that
// is not ASCII, and ASCII lower case. It returns nameRefused when
// Chromium marks the host broken, and nameUnrepresentable when
// chromiumIDNA refuses a name.
func urlCanonHost(s string) (string, nameUse) {
	host, ok, nonASCII := simpleHost(s)
	if !nonASCII {
		return host, useIf(ok)
	}
	// The decoded text goes to UTS #46 as UTF-16. Chromium decodes "%"
	// escapes once more on that text, as code points (DoIdnHost,
	// url_canon_host.cc:294-299).
	if !utf8.ValidString(host) || !ok {
		return "", nameRefused
	}
	ascii, err := chromiumIDNA().ToASCII(simpleHostRunes(host))
	if err != nil {
		return "", nameUnrepresentable
	}
	out, ok, nonASCII := simpleHost(ascii)
	return out, useIf(ok && !nonASCII && ascii != "")
}

func useIf(ok bool) nameUse {
	if ok {
		return nameUsed
	}
	return nameRefused
}

// chromiumIDNA is the UTS #46 profile of Chromium (CreateIDNA,
// url/url_idna_icu.cc:22-27, and the errors that IDNToASCII ignores,
// :56-71): nontransitional, without the STD3 rules, without the hyphen
// and length checks. Chromium also checks the Bidi and ContextJ rules;
// this profile does not, so it accepts more names, never fewer.
func chromiumIDNA() *idna.Profile {
	return idna.New(
		idna.MapForLookup(),
		idna.Transitional(false),
		idna.StrictDomainName(false),
		idna.CheckHyphens(false),
		idna.CheckJoiners(false),
		idna.VerifyDNSLength(false),
	)
}

// hostEscape marks a byte that DoSimpleHost writes as a "%" escape but
// accepts (kEsc, url_canon_host.cc:23).
const hostEscape = 0xff

// hostChar is kHostCharLookup (url/url_canon_host.cc:25-41): the
// canonical form of each ASCII byte in a host, 0 for a byte that makes
// the host broken, hostEscape for a byte that is escaped.
func hostChar(c byte) byte {
	switch {
	case 'A' <= c && c <= 'Z':
		return c + 'a' - 'A'
	case 'a' <= c && c <= 'z', isDigit(c):
		return c
	case c == ' ' || c == '*':
		return hostEscape
	case strings.IndexByte("!\"$&'()+,-.:;=[]_`{}~", c) >= 0:
		return c
	default:
		return 0
	}
}

// simpleHost is DoSimpleHost (url/url_canon_host.cc:240-288) on bytes.
// It decodes "%XX" escapes, maps ASCII bytes with hostChar, and keeps
// other bytes. It reports whether the host is valid and whether the
// result has a byte that is not ASCII.
func simpleHost(s string) (out string, ok, nonASCII bool) {
	canonical := true
	for i := range len(s) {
		if c := s[i]; c == '%' || c >= utf8.RuneSelf || hostChar(c) != c {
			canonical = false
			break
		}
	}
	if canonical {
		return s, true, false
	}
	var b strings.Builder
	b.Grow(len(s))
	ok = true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' {
			v, valid := decodeEscape(s[i+1:])
			if !valid {
				b.WriteString("%25")
				ok = false
				continue
			}
			c = v
			i += 2
		}
		if c >= utf8.RuneSelf {
			b.WriteByte(c)
			nonASCII = true
			continue
		}
		switch r := hostChar(c); r {
		case 0:
			writeEscape(&b, c)
			ok = false
		case hostEscape:
			writeEscape(&b, c)
			if c == ' ' {
				ok = false
			}
		default:
			b.WriteByte(r)
		}
	}
	return b.String(), ok, nonASCII
}

// simpleHostRunes is DoSimpleHost on UTF-16 text (DoIdnHost,
// url_canon_host.cc:299). An escape stands for the code point of its
// value, and the result of the call is not used.
func simpleHostRunes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == '%' {
			if v, valid := decodeEscape(s[i+1:]); valid {
				r, size = rune(v), 3
			} else {
				b.WriteString("%25")
				i += size
				continue
			}
		}
		i += size
		if r >= utf8.RuneSelf {
			b.WriteRune(r)
			continue
		}
		switch c := hostChar(byte(r)); c {
		case 0, hostEscape:
			writeEscape(&b, byte(r))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// decodeEscape reads the two hex digits after "%" (DecodeEscaped,
// url/url_canon_internal.h:420-442).
func decodeEscape(s string) (byte, bool) {
	if len(s) < 2 {
		return 0, false
	}
	hi, ok1 := digitIn(s[0], 16)
	lo, ok2 := digitIn(s[1], 16)
	return byte(hi<<4 | lo), ok1 && ok2
}

func writeEscape(b *strings.Builder, c byte) {
	const hex = "0123456789ABCDEF"
	b.WriteByte('%')
	b.WriteByte(hex[c>>4])
	b.WriteByte(hex[c&0xf])
}

// hostCompliant is IsCanonicalizedHostCompliant (net/base/url_util.cc:377-415):
// labels of letters, digits, "-", and "_", each of 1 to 63 bytes, at most
// 253 bytes without a final dot, and a last label that starts with a
// letter or digit.
func hostCompliant(host string) bool {
	if host == "" || len(host) > 254 || (len(host) == 254 && host[len(host)-1] != '.') {
		return false
	}
	inLabel, alnumStart, size := false, false, 0
	for i := range len(host) {
		c := host[i]
		alnum := 'a' <= c && c <= 'z' || isDigit(c)
		size++
		switch {
		case !inLabel:
			alnumStart = alnum
			if !alnum && c != '-' && c != '_' {
				return false
			}
			inLabel = true
		case c == '.':
			if size > 64 || size == 1 {
				return false
			}
			inLabel, size = false, 0
		case !alnum && c != '-' && c != '_':
			return false
		}
	}
	return size <= 63 && alnumStart
}
