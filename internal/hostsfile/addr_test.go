package hostsfile

import (
	"net/netip"
	"os"
	"strings"
	"testing"
)

// The corpus holds, for each spelling, how the two macOS readers read it
// as an address. testdata/numerichost.c makes it from libSystem; the file
// says how. The repository builds without cgo, so the test reads the
// recorded results instead of calling libSystem.
//
// Each reader must accept exactly the spellings that macOS accepts, with
// the same address. The first direction prevents a leak, the second keeps
// the reader exact.
func TestMacOSAddrMatchesLibSystem(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/numerichost.tsv")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for line := range strings.Lines(string(data)) {
		n++
		f := strings.Split(strings.TrimSuffix(line, "\n"), "\t")
		if len(f) != 3 {
			t.Fatalf("bad corpus record %q", line)
		}
		in, gai, pton := f[0], f[1], f[2]
		checkAddr(t, "mdnsAddr", mdnsAddr, in, gai)
		if pton != "ERR" && strings.Contains(in, "%") {
			pton = unembedScope(netip.MustParseAddr(pton)).String()
		}
		checkAddr(t, "libinfoAddr", libinfoAddr, in, pton)
	}
	if n < 1000 {
		t.Fatalf("corpus has %d records", n)
	}
}

func checkAddr(t *testing.T, fn string, read func(string) (netip.Addr, bool), in, want string) {
	t.Helper()
	got, ok := read(in)
	switch {
	case want == "ERR" && ok:
		t.Errorf("%s(%q) = %v, macOS refuses it", fn, in, got)
	case want != "ERR" && !ok:
		t.Errorf("%s(%q) refused, macOS reads %s", fn, in, want)
	case want != "ERR" && got != netip.MustParseAddr(want).Unmap():
		t.Errorf("%s(%q) = %v, macOS reads %s", fn, in, got, want)
	}
}

// unembedScope clears the interface index that the macOS inet_pton puts
// into the second group of a link-local address with a zone.
func unembedScope(a netip.Addr) netip.Addr {
	if !a.Is6() || !a.IsLinkLocalUnicast() {
		return a
	}
	b := a.As16()
	b[2], b[3] = 0, 0
	return netip.AddrFrom16(b)
}
