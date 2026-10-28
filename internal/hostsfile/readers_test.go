package hostsfile

import (
	"encoding/hex"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
)

// The golden set holds generated host files and the records that a
// replica of the two macOS readers makes from them. testdata/readers.py
// makes it with testdata/readers.c; the files say how.
//
// Each record must have an entry:
//
//   - MA (mDNSResponder address record): an entry with the address and
//     the name as Name.
//   - MC (mDNSResponder CNAME record): an entry with the target as Name
//     and the alias in Aliases.
//   - LA (Libinfo): an entry with the address and the name.
//
// The residuals that Parse documents are counted and skipped: a name of
// 256 octets, the root name, and a Libinfo name that dnsname cannot
// represent. A file with a residual must list it in Unrepresentable.
func TestParseMatchesMacOSReaders(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/readers.txt")
	if err != nil {
		t.Fatal(err)
	}
	var c readersCheck
	for line := range strings.Lines(string(data)) {
		kind, rest, _ := strings.Cut(strings.TrimSuffix(line, "\n"), " ")
		a, b, _ := strings.Cut(rest, " ")
		switch kind {
		case "F":
			c.file(t, rest)
		case "MA":
			c.address(t, a, b)
		case "MC":
			c.cname(t, a, b)
		case "LA":
			c.libinfo(t, a, b)
		default:
			t.Fatalf("bad record %q", line)
		}
	}
	if c.files < 100 || c.records < 1000 {
		t.Fatalf("golden set has %d files and %d records", c.files, c.records)
	}
	t.Logf("%d files, %d records, %d residual", c.files, c.records, c.residual)
}

// readersCheck checks the records of readers.c against Parse, one file at
// a time.
type readersCheck struct {
	content                  string
	h                        Hosts
	lastMA                   netip.Addr
	files, records, residual int
}

func (c *readersCheck) file(t *testing.T, quoted string) {
	t.Helper()
	var err error
	if c.content, err = strconv.Unquote(quoted); err != nil {
		t.Fatalf("bad file %s: %v", quoted, err)
	}
	if c.h, err = Parse(strings.NewReader(c.content)); err != nil {
		t.Fatal(err)
	}
	c.files++
}

// address checks an mDNSResponder address record: an entry with the
// address and the name as Name.
func (c *readersCheck) address(t *testing.T, a, name string) {
	t.Helper()
	c.records++
	addr := netip.MustParseAddr(a).Unmap()
	c.lastMA = addr
	n, ok := wireName(name)
	if !ok {
		c.unrepresentable(t)
		return
	}
	if !slices.ContainsFunc(c.h.Entries, func(e Entry) bool { return e.Addr == addr && e.Name == n }) {
		t.Errorf("file %q: mDNSResponder %v %q, Parse %q", c.content, addr, n, render(c.h))
	}
}

// cname checks an mDNSResponder CNAME record: an entry with the target as
// Name and the alias in Aliases. For the root name as target, the alias
// must at least have the address of its line.
func (c *readersCheck) cname(t *testing.T, a, b string) {
	t.Helper()
	c.records++
	alias, ok1 := wireName(a)
	target, ok2 := wireName(b)
	if !ok1 || !ok2 {
		c.unrepresentable(t)
		if ok1 && b == "." && !hasName(c.h, c.lastMA, alias) {
			t.Errorf("file %q: alias %q of the root name has no entry with %v", c.content, alias, c.lastMA)
		}
		return
	}
	if !slices.ContainsFunc(c.h.Entries, func(e Entry) bool { return e.Name == target && slices.Contains(e.Aliases, alias) }) {
		t.Errorf("file %q: mDNSResponder %q CNAME %q, Parse %q", c.content, alias, target, render(c.h))
	}
}

// libinfo checks a Libinfo record: an entry with the address and the
// name.
func (c *readersCheck) libinfo(t *testing.T, a, field string) {
	t.Helper()
	c.records++
	addr := netip.MustParseAddr(a).Unmap()
	if strings.Contains(c.content, "%") {
		addr = unembedScope(addr)
	}
	raw, err := hex.DecodeString(field)
	if err != nil {
		t.Fatal(err)
	}
	n, use := literalName(string(raw))
	if use != nameUsed {
		c.unrepresentable(t)
		return
	}
	if !hasName(c.h, addr, n) {
		t.Errorf("file %q: Libinfo %v %q, Parse %q", c.content, addr, n, render(c.h))
	}
}

// unrepresentable counts a record whose name Name cannot represent. Parse
// must list a line of the file in Unrepresentable.
func (c *readersCheck) unrepresentable(t *testing.T) {
	t.Helper()
	c.residual++
	if len(c.h.Unrepresentable) == 0 {
		t.Errorf("file %q: a reader uses a name that Name cannot represent, but Unrepresentable is empty", c.content)
	}
}

// wireName reads a name of readers.c: wire-form labels in hex, joined by
// ".". It returns false for the root name and a name that dnsname cannot
// represent.
func wireName(s string) (dnsname.Name, bool) {
	if s == "." {
		return dnsname.Name{}, false
	}
	var b strings.Builder
	for i, l := range strings.Split(s, ".") {
		if i > 0 {
			b.WriteByte('.')
		}
		raw, err := hex.DecodeString(l)
		if err != nil {
			return dnsname.Name{}, false
		}
		for _, c := range raw {
			b.WriteString(`\` + strconv.Itoa(int(c)/100) + strconv.Itoa(int(c)/10%10) + strconv.Itoa(int(c)%10))
		}
	}
	n, err := dnsname.Parse(b.String())
	return n, err == nil
}

// hasName reports whether an entry has addr and n, as Name or alias.
func hasName(h Hosts, addr netip.Addr, n dnsname.Name) bool {
	return slices.ContainsFunc(h.Entries, func(e Entry) bool {
		return e.Addr == addr && (e.Name == n || slices.Contains(e.Aliases, n))
	})
}
