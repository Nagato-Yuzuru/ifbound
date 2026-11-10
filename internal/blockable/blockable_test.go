package blockable_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
)

// New refuses a loopback, an unspecified, an invalid, and a zoned
// address. A link-local address without a zone can be in a table.
func TestNewRefusesOnlyHostLocalAndBadAddresses(t *testing.T) {
	for s, want := range map[string]bool{
		"127.0.0.1":          false,
		"127.0.0.0":          false,
		"127.255.255.255":    false,
		"::1":                false,
		"0.0.0.0":            false,
		"::":                 false,
		"::ffff:127.0.0.1":   false,
		"::ffff:0.0.0.0":     false,
		"fe80::1%en0":        false,
		"126.255.255.255":    true,
		"128.0.0.0":          true,
		"0.0.0.1":            true,
		"::2":                true,
		"169.254.1.1":        true,
		"fe80::1":            true,
		"203.0.113.1":        true,
		"::ffff:203.0.113.1": true,
		"3fff::1":            true,
	} {
		a := netip.MustParseAddr(s)
		got, ok := blockable.New(a)
		if ok != want {
			t.Errorf("New(%s) ok = %v, want %v", s, ok, want)
		}
		if ok && got.Addr() != a.Unmap() {
			t.Errorf("New(%s) = %v, want %v", s, got, a.Unmap())
		}
		if !ok && got != (blockable.Addr{}) {
			t.Errorf("New(%s) = %v, want the zero Addr", s, got)
		}
	}
	if _, ok := blockable.New(netip.Addr{}); ok {
		t.Error("New(invalid) ok = true, want false")
	}
}

func TestFilterKeepsAcceptedInOrder(t *testing.T) {
	in := []netip.Addr{
		netip.MustParseAddr("203.0.113.2"), netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("::ffff:192.0.2.1"), netip.MustParseAddr("::"),
	}
	var got []string
	for _, a := range blockable.Filter(in) {
		got = append(got, a.String())
	}
	if want := []string{"203.0.113.2", "192.0.2.1"}; !slices.Equal(got, want) {
		t.Errorf("Filter = %v, want %v", got, want)
	}
}
