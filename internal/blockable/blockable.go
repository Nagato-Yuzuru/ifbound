// Package blockable holds Addr: an address that a table can hold as a
// learned or host address. Only New makes an Addr, so each path that
// gives a learned or host address to a table applies the same rule. The
// destinations of the configuration do not use Addr: they are the
// choice of the user.
package blockable

import "net/netip"

// Addr is an address that New accepted. It is valid, has no zone, and
// is not IPv4-mapped. The zero Addr is not valid: only New makes an
// Addr.
type Addr struct{ ip netip.Addr }

// New returns a as an Addr. An IPv4-mapped IPv6 address becomes IPv4,
// so one host has one form in the tables and in the AddrBook. The bool
// is false, and the Addr is the zero Addr, for these addresses:
//
//   - An invalid address.
//   - An address with a zone. A table entry has no zone, so the entry
//     would merge distinct link-local hosts.
//   - A loopback address: all of 127.0.0.0/8, and ::1. Some block rules
//     have no interface, for example the rule of an only_via policy. So
//     such an entry blocks lo0 too, and local services stop, ifbound-dns
//     too. The rule covers all of 127.0.0.0/8, because the listen
//     address of ifbound-dns can be any address in it.
//   - An unspecified address: 0.0.0.0 and ::. macOS sends a connection
//     to 0.0.0.0 to 127.0.0.1, and a connection to :: to ::1, before pf
//     sees the packet. So such an entry matches no packet. It only adds
//     noise to the tables and to the AddrBook.
//
// The rule is the same for the IPv4-mapped form of an address.
func New(a netip.Addr) (Addr, bool) {
	a = a.Unmap()
	if !a.IsValid() || a.Zone() != "" || a.IsLoopback() || a.IsUnspecified() {
		return Addr{}, false
	}
	return Addr{a}, true
}

// Filter returns the addresses of addrs that New accepts, in their
// order.
func Filter(addrs []netip.Addr) []Addr {
	out := make([]Addr, 0, len(addrs))
	for _, a := range addrs {
		if b, ok := New(a); ok {
			out = append(out, b)
		}
	}
	return out
}

// Addr returns the address.
func (a Addr) Addr() netip.Addr { return a.ip }

// Compare compares a and b in the order of netip.Addr.Compare.
func (a Addr) Compare(b Addr) int { return a.ip.Compare(b.ip) }

// String returns the address in the form of netip.Addr.String.
func (a Addr) String() string { return a.ip.String() }
