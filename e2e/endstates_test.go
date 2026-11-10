//go:build e2e && darwin

package e2e

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/pfrules"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
	"github.com/Nagato-Yuzuru/ifbound/internal/testnet"
)

// TestReconcileEndsStatesWhenAllowedUTUNGoesAway checks a UDP flow to an
// only_via destination. The policy names the utun, so the ruleset stays
// the same when the utun goes away. A rule of another tool keeps state
// for the flow, and pf states are floating: without the end of the
// states, the flow continues on the default route.
//
// The socket is bound to the local address of the utun, so the kernel
// sends the flow through the utun. After the utun goes away, the test
// gives that address to the interface of the default route. The packets
// of the socket then leave there with the same addresses and ports, and
// match the state.
func TestReconcileEndsStatesWhenAllowedUTUNGoesAway(t *testing.T) {
	b, _ := newPfBackend(t)
	inv := startInventory(t)
	// 198.18.0.0/15 is for benchmark tests (RFC 2544): no real host
	// answers. The peer of the utun is the destination.
	local := netip.MustParseAddr("198.18.23.1")
	dst := netip.MustParseAddrPort("198.18.23.2:9")
	loadAnchor(t, "com.apple/900.ifbound-e2e", "pass out proto udp to "+dst.Addr().String()+" keep state\n")
	uplink := defaultInterface(t, dst)

	rec := reconcile.Reconciler{
		Compiler:  pfrules.Compiler{},
		Backend:   b,
		Resolver:  reconciletest.NewWorld().Resolver(),
		Inventory: inv,
	}
	var in reconcile.Inputs
	converge := func(t *testing.T) reconcile.Report {
		t.Helper()
		rep, err := rec.Converge(t.Context(), in)
		if err != nil {
			t.Fatalf("Converge: %v", err)
		}
		return rep
	}
	var conn *net.UDPConn
	var utun string

	if !t.Run("flow on the allowed utun", func(t *testing.T) {
		quiet(t, inv)
		u := testnet.NewUTUN(t)
		utun = u.Name
		u.SetAddr(t, local, dst.Addr())
		awaitSignal(t, inv, "creating "+utun)
		in = reconcile.Inputs{Policies: onlyVia(t, dst.Addr(), utun), Book: noAddrs{}}
		converge(t)

		var err error
		conn, err = net.DialUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)), net.UDPAddrFromAddrPort(dst))
		if err != nil {
			t.Fatalf("dial %s from %s: %v", dst, local, err)
		}
		for range 2 {
			if err := exchange(conn); !errors.Is(err, errNoAnswer) {
				t.Fatalf("UDP to %s through %s: %v, want no answer (not blocked)", dst, utun, err)
			}
			requireLeftThrough(t, u, dst.Addr())
		}
		if states := pfctl(t, "-s", "state"); !strings.Contains(states, dst.String()) {
			t.Fatalf("no state to %s after the flow:\n%s", dst, states)
		}
		// The cleanup removes the utun after this quiet, so the next
		// signal comes from the removal.
		quiet(t, inv)
	}) {
		if conn != nil {
			_ = conn.Close() //nolint:errcheck // a UDP close error does not change the result
		}
		return
	}
	t.Cleanup(func() { _ = conn.Close() }) //nolint:errcheck // a UDP close error does not change the result

	// The cleanup of the subtest removed the utun.
	awaitSignal(t, inv, "removing "+utun)
	requireAbsent(t, inv, utun)
	addAlias(t, uplink, local)

	// The premise of the test: before the convergence, the state lets
	// the flow continue on the uplink. Without the end of the states,
	// the check after the convergence fails in the same way.
	if states := pfctl(t, "-s", "state"); !strings.Contains(states, dst.String()) {
		t.Fatalf("the state to %s went away with %s; the test cannot show the leak:\n%s", dst, utun, states)
	}
	if err := exchange(conn); !errors.Is(err, errNoAnswer) {
		t.Fatalf("UDP to %s on %s before the convergence: %v, want no answer (the state lets it pass)", dst, uplink, err)
	}

	rep := converge(t)
	if !slices.Contains(rep.Narrowed, "e2e-flow") {
		t.Errorf("Report.Narrowed = %v, want e2e-flow", rep.Narrowed)
	}
	if states := pfctl(t, "-s", "state"); strings.Contains(states, dst.String()) {
		t.Errorf("a state to %s stays after the convergence:\n%s", dst, states)
	}
	if err := exchange(conn); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("UDP to %s on %s after %s went away: %v, want ECONNREFUSED", dst, uplink, utun, err)
	}
}

// defaultInterface returns the name of the interface that holds the
// source address that the host uses for dst on the current routes.
func defaultInterface(t *testing.T, dst netip.AddrPort) string {
	t.Helper()
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(dst))
	if err != nil {
		t.Fatalf("dial %s: %v", dst, err)
	}
	src := c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
	_ = c.Close() //nolint:errcheck // a UDP close error does not change the result
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			t.Fatalf("addresses of %s: %v", ifc.Name, err)
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(src.AsSlice()) {
				return ifc.Name
			}
		}
	}
	t.Fatalf("no interface holds %s", src)
	return ""
}

// addAlias gives addr to iface until the test ends.
func addAlias(t *testing.T, iface string, addr netip.Addr) {
	t.Helper()
	testnet.Ifconfig(t, iface, "alias", addr.String()+"/32")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "ifconfig", iface, "-alias", addr.String()).CombinedOutput(); err != nil {
			t.Errorf("remove the alias %s from %s: %v: %s", addr, iface, err, out)
		}
	})
}

// onlyVia returns one policy that allows dst only on the interface
// iface.
func onlyVia(t *testing.T, dst netip.Addr, iface string) []policy.Policy {
	t.Helper()
	cfg, err := policy.ParseBytes([]byte("[dns]\nupstream = [\"tls://1.1.1.1@a.example\"]\n" +
		"[[policy]]\nname = \"e2e-flow\"\nto = [\"" + dst.String() + "\"]\nonly_via = [\"" + iface + "\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Policies
}

// requireLeftThrough reads the next packet that left through u and
// checks that it goes to dst.
func requireLeftThrough(t *testing.T, u *testnet.UTUN, dst netip.Addr) {
	t.Helper()
	pkt := u.ReadPacket(t, 5*time.Second)
	got, ok := ipv4Dst(pkt)
	if !ok {
		t.Fatalf("packet too short for IPv4: %d bytes", len(pkt))
	}
	if got != dst {
		t.Fatalf("packet on %s goes to %s, want %s", u.Name, got, dst)
	}
}

// ipv4Dst returns the destination address of an IPv4 packet. It reports
// false when the packet is too short to hold one.
func ipv4Dst(pkt []byte) (netip.Addr, bool) {
	const ipv4DstOffset = 16
	if len(pkt) < ipv4DstOffset+4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(pkt[ipv4DstOffset : ipv4DstOffset+4])), true
}

// exchange sends one datagram on conn and waits 2 s for an answer or an
// error, as udpExchange does on a new socket. A packet that passes gets
// no reply and no event, so only the end of the wait shows that no ICMP
// reject came.
func exchange(conn *net.UDPConn) error {
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("ifbound")); err != nil {
		return err
	}
	_, err := conn.Read(make([]byte, 64))
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return errNoAnswer
	}
	return err
}
