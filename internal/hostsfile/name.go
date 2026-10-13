package hostsfile

import (
	"strings"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
)

// mdnsName reads a host name as mDNSResponder does, and returns it in
// the canonical form of dnsname.
//
// mDNSResponder reads a name with AppendDNSNameString (mDNSResponder
// mDNSCore/DNSCommon.c:1120). Its escapes differ from those of dnsname:
// "\" and three digits of at most 255 are one byte, "\" and any other
// byte is that byte (so "\1" is "1" and "\256" is "256"), and a final
// "\" is ignored. mdnsName writes each escape as "\DDD" and gives the
// result to dnsname.Parse.
//
// mDNSResponder accepts a name of 256 octets in wire form
// (MAX_DOMAIN_NAME), and the root name. dnsname cannot represent them,
// so mdnsName returns nameUnrepresentable for them.
func mdnsName(s string) (dnsname.Name, nameUse) {
	if s == "." {
		return dnsname.Name{}, nameUnrepresentable // the root name
	}
	if strings.IndexByte(s, '\\') < 0 {
		return mdnsResult(s) // no escape to rewrite
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i == len(s) {
			break
		}
		c = s[i]
		if i+2 < len(s) && isDigit(c) && isDigit(s[i+1]) && isDigit(s[i+2]) {
			if v := int(c-'0')*100 + int(s[i+1]-'0')*10 + int(s[i+2]-'0'); v <= 255 {
				c = byte(v)
				i += 2
			}
		}
		b.WriteByte('\\')
		b.WriteByte('0' + c/100)
		b.WriteByte('0' + c/10%10)
		b.WriteByte('0' + c%10)
	}
	return mdnsResult(b.String())
}

// mdnsResult parses the rewritten name s. When dnsname refuses s, it
// tells a name that AppendDNSNameString also refuses (an empty label, a
// label over 63 octets, more than 256 octets in wire form) from one that
// it accepts (the root name, exactly 256 octets). A rewritten "." comes
// from ".\", which AppendDNSNameString refuses; mdnsName handles the
// root name ".".
func mdnsResult(s string) (dnsname.Name, nameUse) {
	if n, err := dnsname.Parse(s); err == nil {
		return n, nameUsed
	}
	if s == "" {
		return dnsname.Name{}, nameUnrepresentable // the root name, from a lone backslash
	}
	wire, label := 1, 0 // the root octet; the octets of the current label
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '.' {
			if s[i] == '\\' {
				i += 3 // "\DDD" is one octet
			}
			label++
			continue
		}
		if label == 0 && i < len(s) || label > 63 {
			return dnsname.Name{}, nameRefused
		}
		if label > 0 {
			wire += label + 1
		}
		label = 0
	}
	if wire == 256 {
		return dnsname.Name{}, nameUnrepresentable
	}
	return dnsname.Name{}, nameRefused
}

// literalName reads a host name that a reader compares as a plain
// string: Libinfo (file_module.c:1354) and the Go resolver
// (net/hosts.go:92-96). Such a reader uses every field, so a field that
// dnsname cannot represent (an empty label, a label over 63 octets, a
// name over 255 octets) is nameUnrepresentable, never nameRefused. A
// backslash is a byte of the name, not an escape.
func literalName(s string) (dnsname.Name, nameUse) {
	n, err := dnsname.Parse(strings.ReplaceAll(s, `\`, `\\`))
	if err != nil {
		return dnsname.Name{}, nameUnrepresentable
	}
	return n, nameUsed
}
