package hostsfile

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
)

// render writes each entry as "addr name alias...".
func render(h Hosts) []string {
	var out []string
	for _, e := range h.Entries {
		s := e.Addr.String() + " " + e.Name.String()
		for _, a := range e.Aliases {
			s += " " + a.String()
		}
		out = append(out, s)
	}
	return out
}

// label returns n bytes of c: a label of length n.
func label(c string, n int) string { return strings.Repeat(c, n) }

func TestParse(t *testing.T) {
	t.Parallel()
	x := func(n int) string { return strings.Repeat("x", n) }
	tests := []struct {
		name      string
		in        string
		want      []string
		malformed int
	}{
		{"empty", "", nil, 0},
		{"comments and blanks", "# top\n\n   \n\t# indented\n", nil, 0},
		{"blank crlf lines", "10.0.0.1 a.example\n\r\n\r\n \t\r\n10.0.0.2 b.example\n", []string{"10.0.0.1 a.example", "10.0.0.2 b.example"}, 0},
		{"one name", "127.0.0.1 localhost\n", []string{"127.0.0.1 localhost"}, 0},
		{"aliases", "10.0.0.1\t a.example  \tb.example\n", []string{"10.0.0.1 a.example b.example"}, 0},
		{"duplicate names", "10.0.0.1 a.example b.example A.Example. b.example\n", []string{"10.0.0.1 a.example b.example"}, 0},
		{"same line twice", "10.0.0.1 h.example\n10.0.0.1 h.example\n", []string{"10.0.0.1 h.example"}, 0},
		{"ipv6", "::1 localhost\n", []string{"::1 localhost"}, 0},

		// Addresses. Each reader reads the address field in its own way.
		// A count of 1 means that one reader refuses the address.
		{"leading zeros", "192.168.001.010 protected.example\n", []string{
			"192.168.1.10 protected.example", // macOS: decimal
			"192.168.1.8 protected.example",  // Chromium: octal
		}, 1}, // Go refuses leading zeros
		{"four parts with zeros", "010.000.000.001 protected.example\n", []string{
			"10.0.0.1 protected.example", // macOS
			"8.0.0.1 protected.example",  // Chromium
		}, 1},
		{"octal loopback", "0177.0.0.1 protected.example\n", []string{
			"177.0.0.1 protected.example", // macOS
			"127.0.0.1 protected.example", // Chromium
		}, 1},
		{"two parts", "127.1 protected.example\n", []string{"127.0.0.1 protected.example"}, 1},
		{"three parts", "10.0.1 protected.example\n", []string{"10.0.0.1 protected.example"}, 1},
		{"hex", "0x0a000001 protected.example\n", []string{"10.0.0.1 protected.example"}, 1},
		{"one number", "167772161 protected.example\n", []string{"10.0.0.1 protected.example"}, 1},
		{"octal part", "0377.1 protected.example\n", []string{"255.0.0.1 protected.example"}, 1},
		{"inet_aton wraps at 32 bits", "4294967297 protected.example\n", []string{"0.0.0.1 protected.example"}, 1},
		{"final dot", "1.2.3.4. protected.example\n", []string{"1.2.3.4 protected.example"}, 1},
		{"ipv6 leading zeros", "00001:: protected.example\n", []string{"1:: protected.example"}, 1},
		{"mapped with zero", "::ffff:1.2.3.04 protected.example\n", []string{"1.2.3.4 protected.example"}, 1},
		{"mapped with octal", "::ffff:010.0.0.1 protected.example\n", []string{
			"10.0.0.1 protected.example", // macOS
			"8.0.0.1 protected.example",  // Chromium
		}, 1},
		{"ipv4-compatible stays ipv6", "::1.2.3.4 protected.example\n", []string{"::102:304 protected.example"}, 0},
		{"ipv6 zone", "fe80::1%en0 protected.example\n", []string{"fe80::1 protected.example"}, 1},
		{"ipv4 zone", "10.0.0.1%en0 protected.example\n", []string{"10.0.0.1 protected.example"}, 1},
		{"empty zone", "1.2.3.4% protected.example\n", []string{"1.2.3.4 protected.example"}, 1},
		{"zone then comma", "fe80::1%en0,protected.example\n", []string{"fe80::1 protected.example"}, 1},
		{"bad address", "not-an-ip h.example\n300.0.0.1 h.example\n08 h.example\n", nil, 3},
		{"white space after address", "1.2.3.4\v h.example\n", nil, 1},

		// Separators and comments.
		{"comma after address", "1.2.3.4,protected.example\n", []string{"1.2.3.4 protected.example"}, 1},
		{"comma between names", "1.2.3.4 a.example,protected.example\n", []string{
			"1.2.3.4 a.example protected.example", // mDNSResponder, Chromium
			"1.2.3.4 a.example,protected.example", // Libinfo: one name
		}, 0},
		{"leading comma", ",1.2.3.4 a.example\n", []string{"1.2.3.4 a.example"}, 1},
		{"hash inside a name", "10.0.0.1 a.example#x protected.example\n", []string{
			"10.0.0.1 a.example#x protected.example", // macOS
			"10.0.0.1 a.example",                     // Chromium: "#" starts a comment
		}, 0},
		{"hash after a name", "10.0.0.1 a.example # protected.example\n", []string{
			"10.0.0.1 a.example",                     // mDNSResponder, Chromium
			"10.0.0.1 a.example # protected.example", // Libinfo
		}, 0},
		{"vertical tab is not a separator", "10.0.0.1 a.example\vb.example\n", []string{`10.0.0.1 a.example\011b.example`}, 1},

		// Line ends.
		{"crlf", "10.0.0.1 h.example\r\n", []string{
			"10.0.0.1 h.example",     // mDNSResponder, Chromium
			`10.0.0.1 h.example\013`, // Libinfo keeps the CR
		}, 0},
		{"cr ends a line in Chromium", "1.2.3.4 a.example\r5.6.7.8 protected.example\r", []string{
			`1.2.3.4 a.example\0135.6.7.8 protected.example`, // macOS: one name with a CR
			"1.2.3.4 a.example",                           // Chromium
			"5.6.7.8 protected.example",                   // Chromium
			"1.2.3.4 a.example 5.6.7.8 protected.example", // Go: CR separates fields
		}, 0},
		{"cr between names", "1.2.3.4 a.example\rprotected.example\n", []string{
			`1.2.3.4 a.example\013protected.example`, // macOS
			"1.2.3.4 a.example",                      // Chromium; "protected.example" is a bad address
			"1.2.3.4 a.example protected.example",    // Go
		}, 1},
		{"comma only line between cr", "1.2.3.4 a.example\r,\r5.6.7.8 protected.example\n", []string{
			`1.2.3.4 a.example\013 \0135.6.7.8 protected.example`, // mDNSResponder
			`1.2.3.4 a.example\013,\0135.6.7.8 protected.example`, // Libinfo
			"1.2.3.4 a.example",                             // Chromium
			"5.6.7.8 protected.example",                     // Chromium
			"1.2.3.4 a.example , 5.6.7.8 protected.example", // Go
		}, 0},
		{"cr at line start", "\r1.2.3.4 protected.example\n", []string{"1.2.3.4 protected.example"}, 1},
		{"comment goes across cr", "1.2.3.4 a.example # c\r5.6.7.8 protected.example\n", []string{
			"1.2.3.4 a.example", // mDNSResponder, Chromium
			`1.2.3.4 a.example # c\0135.6.7.8 protected.example`, // Libinfo
		}, 0},
		{"bad address goes across cr", "bogus a.example\r1.2.3.4 protected.example\n", nil, 1},
		{"no final newline", "10.0.0.1 h.example", []string{
			"10.0.0.1 h.example", // mDNSResponder, Chromium
			"10.0.0.1 h.exampl",  // Libinfo drops the last byte
		}, 0},
		{"nul ends the line", "10.0.0.1 protected.example\x00junk\n", []string{
			"10.0.0.1 protected.example",         // mDNSResponder
			"10.0.0.1 protected.exampl",          // Libinfo drops the byte before the NUL
			`10.0.0.1 protected.example\000junk`, // Go
		}, 1},
		{"nul at line start does not stop the read", "\x00junk\n10.0.0.1 h.example\n", []string{"10.0.0.1 h.example"}, 1},

		// Chunks: a line longer than a chunk is not an error.
		{"long comment after an entry", "10.0.0.1 protected.example\n#" + x(70000), []string{"10.0.0.1 protected.example"}, 1},
		{"long comment before an entry", "#" + x(70000) + "\n10.0.0.1 protected.example\n", []string{"10.0.0.1 protected.example"}, 1},
		{"entry in the second mDNSResponder chunk", "#" + x(1022) + "1.2.3.4 protected.example\n", []string{"1.2.3.4 protected.example"}, 0},
		{"entry in the second Libinfo chunk", "#" + x(4094) + "1.2.3.4 protected.example\n", []string{"1.2.3.4 protected.example"}, 1},
		{"names past the first mDNSResponder chunk", "10.0.0.1" + strings.Repeat(" ", 1015) + "1.2.3.4 b.example\n", []string{
			"1.2.3.4 b.example",          // mDNSResponder, second chunk
			"10.0.0.1 1.2.3.4 b.example", // Libinfo
			"10.0.0.1 b.example",         // Chromium: "1.2.3.4" is not a name
		}, 1},

		// Names: what AppendDNSNameString reads.
		{"name is normalized", "10.0.0.1 Example.COM.\n", []string{"10.0.0.1 example.com"}, 0},
		{"trailing backslash", "10.0.0.1 protected.example\\\n", []string{
			"10.0.0.1 protected.example",   // mDNSResponder
			`10.0.0.1 protected.example\\`, // Libinfo, Go: a literal backslash
		}, 1},
		{"trailing backslash after dot", "10.0.0.1 protected.example.\\\n", []string{
			"10.0.0.1 protected.example",
			`10.0.0.1 protected.example.\\`,
		}, 1},
		{"backslash and one digit", "10.0.0.1 s\\1.example\n", []string{"10.0.0.1 s1.example", `10.0.0.1 s\\1.example`}, 1},
		{"backslash and 256", "10.0.0.1 \\256.example\n", []string{"10.0.0.1 256.example", `10.0.0.1 \\256.example`}, 1},
		{"backslash escapes", "10.0.0.1 a\\.b.example \\065\\066.example\n", []string{
			`10.0.0.1 a\.b.example ab.example`,          // mDNSResponder: escapes
			`10.0.0.1 a\\.b.example \\065\\066.example`, // Libinfo, Go: literal
		}, 1},
		// For the Go resolver, a "#" inside a field starts a comment, and a
		// CR separates fields.
		{"go comment inside a field", "1.2.3.4 a.example\rb.example#x c.example\n", []string{
			`1.2.3.4 a.example\013b.example#x c.example`, // macOS
			"1.2.3.4 a.example",                          // Chromium: CR ends the line
			"1.2.3.4 a.example b.example",                // Go
		}, 1},
		// Libinfo and the Go resolver answer a name under protected.example
		// with a backslash label, so the literal entry must be there.
		{"backslash before a dot", "1.2.3.4 x\\.protected.example\n", []string{
			`1.2.3.4 x\.protected.example`,
			`1.2.3.4 x\\.protected.example`,
		}, 1},
		// Libinfo and the Go resolver answer names that are not valid DNS
		// names. Name cannot represent them.
		{"empty label", "1.2.3.4 x..protected.example\n", nil, 1},
		{"leading dot", "1.2.3.4 .protected.example\n", nil, 1},
		{"label of 64 octets", "1.2.3.4 " + label("x", 64) + ".protected.example\n", nil, 1},
		{"longest name", "10.0.0.1 " + label("a", 63) + "." + label("b", 63) + "." + label("c", 63) + "." + label("d", 53) + ".example\n",
			[]string{"10.0.0.1 " + label("a", 63) + "." + label("b", 63) + "." + label("c", 63) + "." + label("d", 53) + ".example"}, 0},
		{"bad name keeps good names", "10.0.0.1 a..b good.example " + label("a", 64) + ".example other.example\n",
			[]string{"10.0.0.1 good.example other.example"}, 1},
		{"address without name", "10.0.0.1\n10.0.0.2 # a comment\n", []string{
			"10.0.0.2 # a comment", // Libinfo; the others have no name
		}, 2},
		{"root name", "10.0.0.1 .\n", nil, 1},
		{"root first name", "1.2.3.4 . protected.example\n5.6.7.8 .\n", []string{"1.2.3.4 protected.example"}, 2},

		// Names: what Chromium reads.
		{"idn", "1.2.3.4 bücher.example BÜCHER.example\n", []string{
			`1.2.3.4 b\195\188cher.example b\195\156cher.example`, // macOS: bytes
			"1.2.3.4 xn--bcher-kva.example",                       // Chromium: punycode
		}, 0},
		{"percent escape", "1.2.3.4 %70rotected.example\n", []string{
			"1.2.3.4 %70rotected.example", // macOS
			"1.2.3.4 protected.example",   // Chromium
		}, 0},
		{"underscore", "1.2.3.4 _svc.example\n", []string{"1.2.3.4 _svc.example"}, 0},
		{"idna refused", "1.2.3.4 a\u0080b.example\n", []string{`1.2.3.4 a\194\128b.example`}, 0},
		{"name like an address", "1.2.3.4 5.6.7.8 a.123 0x10\n", []string{
			"1.2.3.4 5.6.7.8 a.123 0x10", // macOS; Chromium refuses all three
		}, 1},
	}
	// unrepresentable holds the cases with a name that a reader uses but
	// Name cannot represent.
	unrepresentable := map[string]int{
		"root name":                 1,
		"root first name":           2,
		"idna refused":              1,
		"bad name keeps good names": 1,
		"empty label":               1,
		"leading dot":               1,
		"label of 64 octets":        1,
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h, err := Parse(strings.NewReader(tt.in))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := render(h); !slices.Equal(got, tt.want) {
				t.Errorf("entries:\n got %q\nwant %q", got, tt.want)
			}
			if h.Malformed != tt.malformed {
				t.Errorf("Malformed = %d, want %d", h.Malformed, tt.malformed)
			}
			if len(h.Unrepresentable) != unrepresentable[tt.name] {
				t.Errorf("Unrepresentable = %v, want %d lines", h.Unrepresentable, unrepresentable[tt.name])
			}
		})
	}
}

// The Go resolver reads a line of 64 KiB, and a CR separates its fields.
// Only the Go resolver reads protected.example as a name of the address:
// the macOS readers stop at their chunk size, and for Chromium a CR ends
// the line.
func TestParseGoLongLine(t *testing.T) {
	t.Parallel()
	in := "1.2.3.4" + strings.Repeat("\rn.example", 450) + "\rprotected.example\n"
	h, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if !hasName(h, netip.MustParseAddr("1.2.3.4"), mustName(t, "protected.example")) {
		t.Fatalf("protected.example has no entry with 1.2.3.4")
	}
}

// Chromium reads a whole line, so a name after the last chunk of the
// macOS readers is still found.
func TestParseLongLine(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("1.2.3.4")
	for i := 0; b.Len() < 9000; i++ {
		fmt.Fprintf(&b, " n%04d.example", i)
	}
	b.WriteString(" protected.example\n")
	h, err := Parse(strings.NewReader(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if !hasName(h, netip.MustParseAddr("1.2.3.4"), mustName(t, "protected.example")) {
		t.Fatalf("protected.example has no entry with 1.2.3.4")
	}
}

func mustName(t *testing.T, s string) dnsname.Name {
	t.Helper()
	n, err := dnsname.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// Unrepresentable gives the number of each line and its fields once,
// also when several readers read the same field. mDNSResponder refuses
// the empty label, so its field comes from Libinfo, after ".".
func TestParseUnrepresentableLines(t *testing.T) {
	t.Parallel()
	in := "10.0.0.1 ok.example\n" +
		"1.2.3.4 x..protected.example ok.example . x..protected.example\n" +
		"# 5.6.7.8 .\n" +
		"5.6.7.8 .\n"
	h, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []Line{{Number: 2, Names: []string{".", "x..protected.example"}}, {Number: 4, Names: []string{"."}}}
	if !slices.EqualFunc(h.Unrepresentable, want, func(a, b Line) bool {
		return a.Number == b.Number && slices.Equal(a.Names, b.Names)
	}) {
		t.Fatalf("Unrepresentable = %+v, want %+v", h.Unrepresentable, want)
	}
}

// A name of 256 octets in wire form is valid to mDNSResponder, but dnsname
// cannot represent it. It is skipped alone.
func TestParseNameOverWireLimit(t *testing.T) {
	t.Parallel()
	long := label("a", 63) + "." + label("b", 63) + "." + label("c", 63) + "." + label("d", 54) + ".example"
	h, err := Parse(strings.NewReader("10.0.0.1 " + long + " h.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := render(h), []string{"10.0.0.1 h.example"}; !slices.Equal(got, want) {
		t.Fatalf("entries = %q, want %q", got, want)
	}
}

func TestParseReadError(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	r := io.MultiReader(strings.NewReader("10.0.0.1 a.example\n10.0.0.2 b.exa"), iotest.ErrReader(boom))
	h, err := Parse(r)
	if !errors.Is(err, errRead) {
		t.Fatalf("err = %v, want errRead", err)
	}
	if got, want := render(h), []string{"10.0.0.1 a.example"}; !slices.Equal(got, want) {
		t.Fatalf("entries = %q, want %q", got, want)
	}
}

// The caller owns the result: a change to one entry changes no other.
func TestParseResultIsNotShared(t *testing.T) {
	t.Parallel()
	h, err := Parse(strings.NewReader("10.0.0.1 a.example b.example c.example\n10.0.0.2 d.example e.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	before := render(h)
	h.Entries[0].Aliases[0] = h.Entries[1].Name
	h.Entries[0].Aliases = append(h.Entries[0].Aliases, h.Entries[1].Name)
	if got := render(h)[1]; got != before[1] {
		t.Fatalf("entry 1 = %q, want %q", got, before[1])
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"", "127.0.0.1 localhost\n", "fe80::1%lo0 h\n", "::1 a b # c\n",
		"10.0.0.1\t\tx.test\r\n", "::ffff:1.2.3.4 y\n", "\\ \x00 #\n",
		"1.2.3.4,a,b\n", "127.1 a\\ b\\\n", "#" + strings.Repeat("x", 1100) + "\n1 a\n",
		"0177.1. b%c3%bc.example\r::ffff:010.0.0.1 a#b\n", "1:2::3.4.5.6 xn--a.b \u00fc\u200d.\uff10\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		h, err := Parse(strings.NewReader(s))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if h.Malformed < 0 || h.Malformed > strings.Count(s, "\n")+1 {
			t.Fatalf("Malformed = %d", h.Malformed)
		}
		for _, e := range h.Entries {
			checkEntry(t, e)
		}
	})
}

// checkEntry checks the invariants of Entry.
func checkEntry(t *testing.T, e Entry) {
	t.Helper()
	if !e.Addr.IsValid() || e.Addr.Zone() != "" || e.Addr.Is4In6() {
		t.Fatalf("bad address %v", e.Addr)
	}
	if e.Name.String() == "" {
		t.Fatalf("entry %v has no name", e.Addr)
	}
	seen := map[string]bool{e.Name.String(): true}
	for _, a := range e.Aliases {
		if seen[a.String()] {
			t.Fatalf("entry %v repeats %q", e.Addr, a)
		}
		seen[a.String()] = true
	}
}
