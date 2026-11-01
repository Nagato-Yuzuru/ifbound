package policy

import (
	"slices"
	"strconv"
	"strings"
)

// segment is one step of a field path: a key, or an index in an array.
// A path keeps its steps apart, so a quoted key such as "a.b" or "to[0]"
// never equals the path that its characters spell.
type segment struct {
	key   string // the key, when index is negative
	index int    // the index in an array, or -1 for a key
}

func keySeg(name string) segment { return segment{key: name, index: -1} }
func idxSeg(i int) segment       { return segment{index: i} }

// fieldPath is the place of a field in the file, as a list of steps.
type fieldPath []segment

func (p fieldPath) add(s ...segment) fieldPath { return append(slices.Clone(p), s...) }

// String gives the text of the path as FieldError.Field shows it, for
// example "policy[1].to[0]". Two different paths can give the same text.
func (p fieldPath) String() string {
	var b strings.Builder
	for i, s := range p {
		switch {
		case s.index >= 0:
			b.WriteString("[" + strconv.Itoa(s.index) + "]")
		case i > 0:
			b.WriteString("." + s.key)
		default:
			b.WriteString(s.key)
		}
	}
	return b.String()
}

// enc returns a string that is equal for two paths only when the paths are
// equal. It is the key of the maps in index.
func (p fieldPath) enc() string {
	var b strings.Builder
	for _, s := range p {
		if s.index >= 0 {
			b.WriteString("[" + strconv.Itoa(s.index) + "]")
		} else {
			b.WriteString(strconv.Quote(s.key))
		}
	}
	return b.String()
}

// literal reads a path that the code spells out, such as "to[0]" or "[2]".
// It does not read a path that comes from the file.
func literal(s string) fieldPath {
	var p fieldPath
	for s != "" {
		if s[0] == '[' {
			end := strings.IndexByte(s, ']')
			n, _ := strconv.Atoi(s[1:end]) //nolint:errcheck // the code spells the index out
			p = append(p, idxSeg(n))
			s = s[end+1:]
			continue
		}
		end := strings.IndexByte(s, '[')
		if end < 0 {
			end = len(s)
		}
		p = append(p, keySeg(s[:end]))
		s = s[end:]
	}
	return p
}

// newFieldError returns a *FieldError at path p.
func newFieldError(p fieldPath, err error) *FieldError {
	return &FieldError{Field: p.String(), Err: err, path: p}
}
