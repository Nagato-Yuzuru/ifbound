package hostsfile

import (
	"net/netip"
	"strings"
)

// mdnsAddr reads an address field as mDNSResponder does, and reports
// whether it accepts it.
//
// mDNSResponder ends the address at "%" and reads the rest as an
// interface name (mDNSMacOSX.c:5773-5776). mdnsAddr removes the zone in
// the same way, for IPv4 and IPv6. Then it accepts what getaddrinfo with
// AI_NUMERICHOST accepts (mDNSMacOSX.c:5787): inet_pton for IPv4, then the
// strict inet_aton forms, then inet_pton for IPv6 (_gai_numerichost,
// Libinfo-600 si_getaddrinfo.c:775-806). The macOS inet_pton accepts
// leading zeros and reads them as decimal.
//
// An IPv4-mapped IPv6 address is returned as the IPv4 address.
func mdnsAddr(field string) (netip.Addr, bool) {
	field, _, _ = strings.Cut(field, "%")
	if a, ok := parsePton4(field); ok {
		return a, true
	}
	if a, ok := parseAton(field); ok {
		return a, true
	}
	a, ok := parsePton6(field)
	return a.Unmap(), ok
}

// libinfoAddr reads an address field as Libinfo does: inet_pton for IPv4,
// then for IPv6 (file_module.c:1321-1328). The macOS inet_pton for IPv6
// accepts a zone after "%" that has no other "%". For a link-local
// address with an interface name, it puts the interface index into the
// second group of the result (fe80:e::1 for fe80::1%en0). libinfoAddr
// returns the address without the index, as it goes on the wire.
func libinfoAddr(field string) (netip.Addr, bool) {
	if a, ok := parsePton4(field); ok {
		return a, true
	}
	field, zone, _ := strings.Cut(field, "%")
	if strings.IndexByte(zone, '%') >= 0 {
		return netip.Addr{}, false
	}
	a, ok := parsePton6(field)
	return a.Unmap(), ok
}

// parsePton4 reads four decimal parts of at most 255, separated by dots.
// A part can have any number of leading zeros.
func parsePton4(s string) (netip.Addr, bool) {
	var b [4]byte
	for i := range b {
		part, rest, dot := strings.Cut(s, ".")
		if dot != (i < len(b)-1) || part == "" {
			return netip.Addr{}, false
		}
		v := 0
		for _, c := range []byte(strings.TrimLeft(part, "0")) {
			if !isDigit(c) || v > 25 {
				return netip.Addr{}, false
			}
			v = v*10 + int(c-'0')
		}
		if v > 255 {
			return netip.Addr{}, false
		}
		b[i] = byte(v)
		s = rest
	}
	return netip.AddrFrom4(b), true
}

// parseAton reads the strict inet_aton forms: one to four parts separated
// by dots. A part is decimal, octal after a leading "0", or hex after
// "0x". The last part fills the bytes that the parts before it leave, and
// each part before it is one byte. The arithmetic wraps at 64 bits, as
// the unsigned long of the C function does, and the value of a single
// part is cut to 32 bits. Strict means that no text, not even white
// space, can follow the address.
func parseAton(s string) (netip.Addr, bool) {
	var (
		parts []uint64
		val   uint64
	)
	for {
		var (
			next  int
			digit bool
			ok    bool
		)
		val, next, digit, ok = atonPart(s)
		if !ok {
			return netip.Addr{}, false
		}
		s = s[next:]
		if s == "" {
			if !digit {
				return netip.Addr{}, false // "0x" without a hex digit
			}
			break
		}
		if s[0] != '.' || len(parts) == 3 || val > 0xff {
			return netip.Addr{}, false
		}
		parts = append(parts, val)
		s = s[1:]
	}
	if limit := uint64(1)<<(8*(4-len(parts))) - 1; len(parts) > 0 && val > limit {
		return netip.Addr{}, false
	}
	v := uint32(val) // the C function also cuts the value to 32 bits
	for i, p := range parts {
		v |= uint32(p) << (24 - 8*i)
	}
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true
}

// atonPart reads one inet_aton part at the start of s. It returns the
// value, the number of bytes read, and whether the part has a digit
// after its prefix.
func atonPart(s string) (val uint64, n int, digit, ok bool) {
	if s == "" || !isDigit(s[0]) {
		return 0, 0, false, false
	}
	base := uint64(10)
	if s[0] == '0' {
		n = 1
		if len(s) > 1 && (s[1] == 'x' || s[1] == 'X') {
			base, n = 16, 2
		} else {
			base, digit = 8, true
		}
	}
	for ; n < len(s); n++ {
		c := s[n]
		var d uint64
		switch {
		case isDigit(c):
			if base == 8 && c >= '8' {
				return 0, 0, false, false
			}
			d = uint64(c - '0')
		case base == 16 && 'a' <= c|0x20 && c|0x20 <= 'f':
			d = uint64(c|0x20-'a') + 10
		default:
			return val, n, digit, true
		}
		val = val*base + d
		digit = true
	}
	return val, n, digit, true
}

// parsePton6 reads an IPv6 address as the macOS inet_pton does. It
// differs from netip.ParseAddr only in leading zeros: a group can have
// any number of them, and so can a part of an embedded IPv4 address.
func parsePton6(s string) (netip.Addr, bool) {
	if !strings.Contains(s, ":") {
		return netip.Addr{}, false
	}
	groups := strings.Split(s, ":")
	var b strings.Builder
	for i, g := range groups {
		if i > 0 {
			b.WriteByte(':')
		}
		if i == len(groups)-1 && strings.Contains(g, ".") {
			v4, ok := parsePton4(g)
			if !ok {
				return netip.Addr{}, false
			}
			b.WriteString(v4.String())
			continue
		}
		t := strings.TrimLeft(g, "0")
		if t == "" && g != "" {
			t = "0"
		}
		b.WriteString(t)
	}
	a, err := netip.ParseAddr(b.String())
	if err != nil || !a.Is6() || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a, true
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

// goAddr reads an address field as the Go resolver does: netip.ParseAddr
// (parseLiteralIP, net/hosts.go:18-24). IPv4 has four decimal parts
// without leading zeros, and IPv6 can have a zone, which goAddr removes.
func goAddr(field string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(field)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.WithZone("").Unmap(), true
}
