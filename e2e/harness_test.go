//go:build e2e && darwin

// Package e2e holds the end-to-end tests. They change pf and network
// interfaces, so they run only on a disposable host as root. Build them with
// `mise run e2e:build`.
package e2e

import (
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/testenv"
	"github.com/Nagato-Yuzuru/ifbound/internal/testnet"
)

func requireE2E(t *testing.T) {
	t.Helper()
	testenv.RequireDisposableHost(t)
	testenv.RequireOS(t, "darwin")
	testenv.RequireRoot(t)
	testenv.RequireCommand(t, "ifconfig")
	testenv.RequireCommand(t, "pfctl")
}

// TestHarnessUTUNSeesEgress checks the oracle that later tests rely on: a
// packet routed to the utun peer address arrives at the test's descriptor.
func TestHarnessUTUNSeesEgress(t *testing.T) {
	requireE2E(t)

	// 198.18.0.0/15 is reserved for benchmark tests (RFC 2544), so it does
	// not collide with real networks on the host.
	local := netip.MustParseAddr("198.18.0.1")
	peer := netip.MustParseAddr("198.18.0.2")
	u := testnet.NewUTUN(t)
	u.SetAddr(t, local, peer)

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "udp4", netip.AddrPortFrom(peer, 9).String())
	if err != nil {
		t.Fatalf("dial %s: %v", peer, err)
	}
	t.Cleanup(func() { _ = conn.Close() }) // a UDP close error does not affect the result
	if _, err := conn.Write([]byte("ifbound")); err != nil {
		t.Fatalf("send to %s: %v", peer, err)
	}

	pkt := u.ReadPacket(t, 5*time.Second)
	const ipv4DstOffset = 16
	if len(pkt) < ipv4DstOffset+4 {
		t.Fatalf("packet too short for IPv4: %d bytes", len(pkt))
	}
	got, _ := netip.AddrFromSlice(pkt[ipv4DstOffset : ipv4DstOffset+4])
	if got != peer {
		t.Fatalf("packet destination on %s = %s, want %s", u.Name, got, peer)
	}
}

// TestHarnessFethPairExists checks that a feth pair appears and goes away.
func TestHarnessFethPairExists(t *testing.T) {
	requireE2E(t)

	p := testnet.NewFethPair(t)
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	names := make([]string, 0, len(ifaces))
	for _, ifc := range ifaces {
		names = append(names, ifc.Name)
	}
	for _, want := range []string{p.A, p.B} {
		if !slices.Contains(names, want) {
			t.Errorf("interface %s of pair %s not found in %v", want, p, names)
		}
	}
}
