// Package dnsname reads DNS names in presentation form, as a resolver
// library prints them.
//
// "\X" stands for the byte X, "\DDD" (three digits, at most 255) for one
// byte, and an unescaped "." ends a label. One final unescaped dot is
// optional. The package does not check the characters of a label: a real
// resolver answers names that a configuration file cannot spell. It folds
// ASCII case only.
package dnsname

import (
	"errors"
	"strconv"
	"strings"
)

// Errors that Split and Parse return.
var (
	// ErrMalformedName means that a name cannot be split into labels.
	ErrMalformedName = errors.New("malformed DNS name")
	// ErrRootName is the error of Parse for the root name. The root name
	// has no labels, so it names no host.
	ErrRootName = errors.New("root DNS name")
)

const (
	maxLabelLen = 63
	maxWireLen  = 255
	// maxTextLen is the length of the longest valid presentation form.
	// The wire form holds a length octet per label and the root octet, so
	// the label octets L and the label count n obey L + n <= 254, and a
	// label holds at most 63 octets. The text is at most 4L + n: each
	// octet as "\DDD", one dot per label (the final dot included). For
	// n <= 3, L <= 63n, so 4L + n <= 759. For n >= 4, L <= 254 - n, so
	// 4L + n <= 4*254 - 3n, which is largest at n = 4: L = 250
	// (63+63+63+61) and a text of 1004.
	maxTextLen = 4*(maxWireLen-1-4) + 4
)

// Name is a DNS name in canonical form: decoded labels with ASCII case
// folded. Only Parse builds one, so two Names are equal exactly when they
// name the same node. The zero Name is not valid and names nothing.
// Name is comparable, so it can be a map key.
type Name struct{ s string }

// Parse reads a presentation-form name into its canonical form. Names
// that differ only in ASCII case, in the escape that spells a byte, or in
// the final dot give the same Name. The root name is an error.
func Parse(s string) (Name, error) {
	labels, err := Split(s)
	if err != nil {
		return Name{}, err
	}
	if len(labels) == 0 {
		return Name{}, ErrRootName
	}
	var b strings.Builder
	for i, l := range labels {
		if i > 0 {
			b.WriteByte('.')
		}
		writeLabel(&b, l)
	}
	return Name{s: b.String()}, nil
}

// String returns the name in presentation form, without the final dot.
// Each label byte that is a dot or a backslash is escaped as "\." or
// "\\". Each byte from 0x00 to 0x20 (space included) and from 0x7F to
// 0xFF is escaped as "\DDD". Every other byte stands for itself.
// So every unescaped dot ends a label, the text decodes to one label list
// only, and two different Names never have the same String. Parse of the
// String gives the same Name.
func (n Name) String() string { return n.s }

func writeLabel(b *strings.Builder, l string) {
	for i := range len(l) {
		switch c := l[i]; {
		case c == '.' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c <= ' ' || c > '~':
			b.WriteByte('\\')
			if c < 100 {
				b.WriteByte('0')
			}
			if c < 10 {
				b.WriteByte('0')
			}
			b.WriteString(strconv.Itoa(int(c)))
		default:
			b.WriteByte(c)
		}
	}
}

// Split splits a presentation-form name into labels, left to right. It
// folds ASCII case. The root name "." gives no labels.
func Split(s string) ([]string, error) {
	// A longer text is malformed anyway. The early check bounds the work
	// for a very long input.
	if len(s) > maxTextLen {
		return nil, ErrMalformedName
	}
	return split(s)
}

func split(s string) ([]string, error) {
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
