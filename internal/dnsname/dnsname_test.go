package dnsname_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
)

func mustParse(t *testing.T, s string) dnsname.Name {
	t.Helper()
	n, err := dnsname.Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return n
}

// Spellings of one name give one Name and one String.
func TestParseCanonical(t *testing.T) {
	t.Parallel()
	tests := map[string][]string{
		"cdn.example.net":   {"cdn.example.net", "CDN.Example.NET.", `\099dn.example.net`, `\cdn.example.net`, `\067DN.example.net`},
		`a\.b.example`:      {`a\.b.example`, `A\046B.example.`},
		`a\\b.example`:      {`a\\b.example`, `a\092b.example`},
		`a\032b.example`:    {`a\032b.example`, `a\ b.example`},
		`\000.example`:      {`\000.example`},
		`\255\200.example`:  {`\255\200.example.`},
		`*.example`:         {`*.example`, `\*.example`},
		`a"b;c.example`:     {`a"b;c.example`},
		`\127\031.example`:  {`\127\031.example`},
		`\0099\0100.x`:      {`\0099\0100.x`, "\t9\n0.x"},
		`abc\\\..example\\`: {`abc\\\..example\\.`},
	}
	for want, spellings := range tests {
		for _, s := range spellings {
			n := mustParse(t, s)
			if n.String() != want {
				t.Errorf("Parse(%q).String() = %q, want %q", s, n.String(), want)
			}
			if again := mustParse(t, n.String()); again != n {
				t.Errorf("Parse(%q) = %q, not a fixed point", n.String(), again)
			}
		}
	}
}

// Names whose texts look alike but whose labels differ never share a key.
func TestParseNoCollision(t *testing.T) {
	t.Parallel()
	distinct := []string{
		"a.b.example", `a\.b.example`, `a\\.b.example`, `a\\\..b.example`,
		`a\\b.example`, `a\000b.example`, `a\032b.example`, `ab.example`,
		"example", "example.example",
	}
	seen := map[dnsname.Name]string{}
	for _, s := range distinct {
		n := mustParse(t, s)
		if other, dup := seen[n]; dup {
			t.Errorf("Parse(%q) == Parse(%q) = %q", s, other, n)
		}
		seen[n] = s
	}
}

func TestParseErrors(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"", "a..b", ".a", `a\`, `a\9`, `a\256`, "a.b.."} {
		if n, err := dnsname.Parse(s); !errors.Is(err, dnsname.ErrMalformedName) || n != (dnsname.Name{}) {
			t.Errorf("Parse(%q) = %q, %v; want ErrMalformedName", s, n, err)
		}
	}
	if n, err := dnsname.Parse("."); !errors.Is(err, dnsname.ErrRootName) || n != (dnsname.Name{}) {
		t.Errorf(`Parse(".") = %q, %v; want ErrRootName`, n, err)
	}
}

// The String of a Name decodes to the labels of the input, so String is
// one-to-one on label lists: two Names with one String have the same
// labels.
func FuzzParseRoundTrip(f *testing.F) {
	for _, s := range []string{"a.b", `a\.b`, `a\\.b`, `\000\255.x.`, "A\x00b.c", `\.\\\.`, "a b.c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		labels, err := dnsname.Split(s)
		n, perr := dnsname.Parse(s)
		switch {
		case err != nil:
			if !errors.Is(perr, dnsname.ErrMalformedName) {
				t.Fatalf("Split(%q) = %v, but Parse = %v", s, err, perr)
			}
			return
		case len(labels) == 0:
			if !errors.Is(perr, dnsname.ErrRootName) {
				t.Fatalf("Parse(%q) of the root = %v", s, perr)
			}
			return
		case perr != nil:
			t.Fatalf("Split(%q) ok, Parse = %v", s, perr)
		}
		back, err := dnsname.Split(n.String())
		if err != nil || !slices.Equal(back, labels) {
			t.Fatalf("Split(%q) = %q, %v; want %q", n.String(), back, err, labels)
		}
		if again := mustParse(t, n.String()); again != n {
			t.Fatalf("Parse(%q) = %q, want %q", n.String(), again, n)
		}
		for i := range len(n.String()) {
			if c := n.String()[i]; c >= 'A' && c <= 'Z' {
				t.Fatalf("String %q holds upper case", n.String())
			}
		}
	})
}
