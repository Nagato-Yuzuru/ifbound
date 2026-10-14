package macresolver

import (
	"errors"
	"net/netip"
	"os"
	"reflect"
	"testing"
)

// The fixture follows the output format of "scutil --dns" on macOS 27:
// a default resolver, files, a supplemental resolver of a VPN, a resolver
// with values that the parser cannot read, an mDNS resolver, and a scoped
// section that the parser must skip. macOS 27 prints ports unsigned.
func TestParseScutilReadsUnscopedResolvers(t *testing.T) {
	out, err := os.ReadFile("testdata/scutil-dns.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseScutil(out)
	if err != nil {
		t.Fatalf("parseScutil: %v", err)
	}
	ip := netip.MustParseAddr
	want := []ConfigEntry{
		{Servers: []netip.Addr{ip("192.0.2.1"), ip("2001:db8::1")}, Port: 53},
		{Domain: "example.test", Servers: []netip.Addr{ip("127.0.0.1")}, Port: 10053},
		{Domain: "www.example.test", Servers: []netip.Addr{ip("127.0.0.1")}, Port: 10054},
		{Domain: "api.example.test", Servers: []netip.Addr{ip("10.0.0.53"), ip("fe80::1%utun4")}, Port: 53, Supplemental: true},
		{Domain: "high-port.test", Servers: []netip.Addr{ip("127.0.0.1")}, Port: 53536},
		// The unreadable server is the zero Addr.
		{Domain: "odd.example.test", Servers: []netip.Addr{{}}, Port: 65535},
		{Domain: "local", Port: 53},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseScutil =\n%+v\nwant\n%+v", got, want)
	}
}

func TestParseScutilRefusesUnknownFormat(t *testing.T) {
	tests := map[string]string{
		"empty":              "",
		"no configuration":   "No DNS configuration available\n",
		"field before":       "DNS configuration\n  domain : x.test\n",
		"line without a key": "DNS configuration\nresolver #1\n  domain   : x.test\n  a line without a key\n",
	}
	for name, out := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parseScutil([]byte(out))
			if !errors.Is(err, errConfig) {
				t.Errorf("parseScutil = %+v, %v; want an error that wraps errConfig", got, err)
			}
		})
	}
}

// An unreadable value gives a value that never matches an ifbound file:
// the zero Addr for a server, port 0 for a port.
func TestParseScutilUnreadableValues(t *testing.T) {
	out := "DNS configuration\n\nresolver #1\n  domain   : x.test\n  nameserver[0] : not-an-address\n" +
		"  port     : 70000\n"
	got, err := parseScutil([]byte(out))
	if err != nil {
		t.Fatalf("parseScutil: %v", err)
	}
	want := []ConfigEntry{{Domain: "x.test", Servers: []netip.Addr{{}}, Port: 0}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseScutil = %+v, want %+v", got, want)
	}
}

func TestParseScutilWithoutResolvers(t *testing.T) {
	got, err := parseScutil([]byte("DNS configuration\n\nDNS configuration (for scoped queries)\n\nresolver #1\n  domain : x.test\n"))
	if err != nil || len(got) != 0 {
		t.Errorf("parseScutil = %+v, %v; want no resolvers and no error", got, err)
	}
}
