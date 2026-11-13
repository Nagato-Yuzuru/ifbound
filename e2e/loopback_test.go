//go:build e2e && darwin

package e2e

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/pfrules"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// loPolicy allows no interface, so it blocks lo.example on every
// interface except lo0.
const loPolicy = "[[policy]]\nname = \"e2e-lo\"\nto = [\"lo.example\"]\nonly_via = []\n"

// fixedBook gives the same learned addresses to every policy.
type fixedBook []blockable.Addr

func (b fixedBook) Addrs(policy.Name) []blockable.Addr { return b }

// startUDPEcho serves a UDP echo on 127.0.0.1, as ifbound-dns serves
// mDNSResponder there, and returns its address.
func startUDPEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from) //nolint:errcheck // a lost echo shows as no answer in the test
		}
	}()
	t.Cleanup(func() {
		_ = pc.Close() //nolint:errcheck // the close only stops the echo
		<-done
	})
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

// TestLoopbackAnswerDoesNotBlockLocalService checks the two guards that
// keep a loopback answer from blocking a local service: no rule blocks
// lo0, and a loopback or unspecified address does not reach the pf
// table. Without them, mDNSResponder cannot reach ifbound-dns on
// 127.0.0.1, and no protected name resolves. The test first puts
// 127.0.0.1 in the table, as an earlier ifboundd did, to show that the
// rules pass lo0 also with that entry.
func TestLoopbackAnswerDoesNotBlockLocalService(t *testing.T) {
	b, _ := newPfBackend(t)
	echo := startUDPEcho(t)
	cfg, err := policy.ParseBytes([]byte("[dns]\nupstream = [\"tls://1.1.1.1@a.example\"]\n" + loPolicy))
	if err != nil {
		t.Fatal(err)
	}
	rec := reconcile.Reconciler{
		Compiler:  pfrules.Compiler{},
		Backend:   b,
		Resolver:  reconciletest.NewWorld().Resolver(),
		Inventory: reconciletest.NewInventory(),
	}

	load(t, b, compilePolicies(t, loPolicy))
	addEntries(t, b, "e2e-lo", "127.0.0.1/32")
	if err := udpExchange(t, echo); err != nil {
		t.Fatalf("UDP to %s with 127.0.0.1 in the table: %v, want an answer (does a rule block lo0?)", echo, err)
	}

	local := []netip.Addr{
		netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1"),
		netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("::"),
	}
	learned := netip.MustParseAddr("192.0.2.10")
	// The daemon builds learned addresses with blockable.Filter, as here.
	book := fixedBook(blockable.Filter(append(slices.Clone(local), learned)))
	if _, err := rec.Converge(t.Context(), reconcile.Inputs{Policies: cfg.Policies, Book: book}); err != nil {
		t.Fatalf("Converge: %v", err)
	}
	// A report with a refused and a valid address: only the valid one
	// reaches the table.
	reported := netip.MustParseAddr("192.0.2.11")
	if err := rec.AddObserved(t.Context(), "e2e-lo", blockable.Filter([]netip.Addr{netip.MustParseAddr("127.0.0.53"), reported})); err != nil {
		t.Fatalf("AddObserved: %v", err)
	}

	want := []netip.Prefix{netip.PrefixFrom(learned, 32), netip.PrefixFrom(reported, 32)}
	got := slices.SortedFunc(slices.Values(readState(t, b).Tables["e2e-lo"]), netip.Prefix.Compare)
	if !slices.Equal(got, want) {
		t.Errorf("table e2e-lo = %v, want %v", got, want)
	}
	if err := udpExchange(t, echo); err != nil {
		t.Errorf("UDP to %s after the loopback answer: %v, want an answer", echo, err)
	}
}
