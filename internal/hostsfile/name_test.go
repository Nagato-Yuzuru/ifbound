// appendDNSNameString in this file is a port of AppendDNSNameString in
// mDNSResponder mDNSCore/DNSCommon.c (mDNSResponder-2600.140.3),
// Copyright (c) 2002-2026 Apple Inc., licensed under the Apache License,
// Version 2.0; the full text is in LICENSES/Apache-2.0.txt at the root of
// the repository, and NOTICE lists it. Changes: the code is written in Go,
// starts from an empty name, and returns the labels and the wire length
// in place of the name.

package hostsfile

import (
	"slices"
	"strings"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
)

// appendDNSNameString is a line-by-line port of AppendDNSNameString onto
// an empty name (mDNSResponder mDNSCore/DNSCommon.c:1120). It returns the
// labels and the length of the wire form, or false when mDNSResponder
// refuses the name. A label of length zero ends the wire form, so the
// labels stop there.
func appendDNSNameString(cstring string) (labels []string, wire int, ok bool) {
	at := func(i int) byte {
		if i < len(cstring) {
			return cstring[i]
		}
		return 0
	}
	const (
		maxDomainName  = 256
		maxDomainLabel = 63
	)
	var c [maxDomainName]byte
	ptr, lim, i := 0, maxDomainName-1, 0
	if at(0) == '.' && at(1) == 0 {
		i++
	}
	for at(i) != 0 && ptr < lim {
		lengthbyte := ptr
		ptr++
		if at(i) == '.' {
			return nil, 0, false
		}
		for at(i) != 0 && at(i) != '.' && ptr < lim {
			ch, next, stop := readNameChar(at, i)
			i = next
			if stop {
				break
			}
			c[ptr] = ch
			ptr++
		}
		if at(i) == '.' {
			i++
		}
		if ptr-lengthbyte-1 > maxDomainLabel {
			return nil, 0, false
		}
		c[lengthbyte] = byte(ptr - lengthbyte - 1)
	}
	c[ptr] = 0
	ptr++
	if at(i) != 0 {
		return nil, 0, false
	}
	return wireLabels(c[:ptr]), ptr, true
}

// readNameChar reads one character of a label at i, as the inner loop of
// AppendDNSNameString does. stop is true for a final backslash: the C
// loop breaks there and leaves i on the NUL.
func readNameChar(at func(int) byte, i int) (ch byte, next int, stop bool) {
	ch = at(i)
	i++
	if ch != '\\' {
		return ch, i, false
	}
	if at(i) == 0 {
		return 0, i, true
	}
	ch = at(i)
	i++
	if isDigit(at(i-1)) && isDigit(at(i)) && isDigit(at(i+1)) {
		if v := int(at(i-1)-'0')*100 + int(at(i)-'0')*10 + int(at(i+1)-'0'); v <= 255 {
			ch = byte(v)
			i += 2
		}
	}
	return ch, i, false
}

// wireLabels returns the labels of a wire-form name up to the first label
// of length zero, with ASCII case folded as SameDomainName does.
func wireLabels(wire []byte) []string {
	var labels []string
	for j := 0; wire[j] != 0; j += 1 + int(wire[j]) {
		l := slices.Clone(wire[j+1 : j+1+int(wire[j])])
		for k, b := range l {
			if 'A' <= b && b <= 'Z' {
				l[k] = b + 'a' - 'A'
			}
		}
		labels = append(labels, string(l))
	}
	return labels
}

// mdnsName uses exactly the names that mDNSResponder accepts, with the
// same labels, except the root name and names of 256 octets in wire form,
// which it reports as unrepresentable.
func FuzzParseName(f *testing.F) {
	for _, s := range []string{
		`protected.example\`, `s\1.example`, `\256.example`, "a..b", "a.b..", "Protected.Example.",
		`a.\`, `\`, ".", `.\`, `\.`, `\\`, `a\.b`, `\0659`, `a\00`, "a.b.",
		label("a", 63) + "." + label("b", 63) + "." + label("c", 63) + "." + label("d", 54) + ".example",
		label("a", 64), `\` + label("a", 63),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if strings.IndexByte(s, 0) >= 0 {
			return // a field never holds a NUL byte
		}
		want, wire, ok := appendDNSNameString(s)
		n, use := mdnsName(s)
		wantUse := nameUsed
		switch {
		case !ok:
			wantUse = nameRefused
		case len(want) == 0 || wire > 255:
			wantUse = nameUnrepresentable
		}
		if use != wantUse {
			t.Fatalf("mdnsName(%q) = %q, %v; want %v (mDNSResponder: ok=%v labels=%q wire=%d)", s, n, use, wantUse, ok, want, wire)
		}
		if use != nameUsed {
			return
		}
		got, err := dnsname.Split(n.String())
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("mdnsName(%q) = %q (%q), want labels %q", s, n, got, want)
		}
	})
}
