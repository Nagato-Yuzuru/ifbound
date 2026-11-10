package daemon_test

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// localAddrs are the loopback addresses (all of 127.0.0.0/8 and ::1),
// the unspecified addresses, and the IPv4-mapped forms of them.
// blockable.New refuses each of them.
var localAddrs = []string{"127.0.0.1", "127.0.0.53", "::1", "0.0.0.0", "::", "::ffff:127.0.0.1", "::ffff:0.0.0.0"}

// requireNoLocalEntry fails when a table holds an address of localAddrs,
// in any form.
func requireNoLocalEntry(t *testing.T, tables map[policy.Name][]netip.Prefix) {
	t.Helper()
	for name, entries := range tables {
		for _, s := range localAddrs {
			a := netip.MustParseAddr(s)
			if slices.Contains(entries, host(s)) || slices.Contains(entries, host(a.Unmap().String())) {
				t.Errorf("table %s = %v, holds %s", name, entries, s)
			}
		}
	}
}

// A filtering upstream can answer a protected name with a loopback or
// unspecified address. A loopback entry blocks lo0, so local services
// stop, ifbound-dns too. An unspecified entry matches no packet. So the
// report is acked, and neither the tables nor the snapshot get the
// address.
func TestReportedLoopbackAddressIsAckedAndNotStored(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.wantState(daemon.StateReady)

		ack, err := h.d.Observe(t.Context(), obs("www.example.net", append([]string{"203.0.113.1"}, localAddrs...)...))
		if err != nil || !ack.Protected {
			t.Fatalf("Observe with local addresses = %+v, %v, want a protected ack", ack, err)
		}
		ack, err = h.d.Observe(t.Context(), obs("example.com", localAddrs...))
		if err != nil || !ack.Protected {
			t.Fatalf("Observe with only local addresses = %+v, %v, want a protected ack", ack, err)
		}

		requireNoLocalEntry(t, h.world.Tables())
		if !h.hasEntry("web", host("203.0.113.1")) {
			t.Errorf("web table = %v, want 203.0.113.1", h.world.Tables()["web"])
		}
		if got, want := h.saved("web"), []netip.Addr{netip.MustParseAddr("203.0.113.1")}; !slices.Equal(got, want) {
			t.Errorf("snapshot web = %v, want %v", got, want)
		}
		if st := h.status(); st.Addrs != 1 {
			t.Errorf("status addresses = %d, want 1", st.Addrs)
		}
	})
}

// An earlier ifboundd can have put a loopback address in a kernel table.
// Adoption does not take it, and the first convergence removes it.
func TestKernelLoopbackEntryIsRemovedAndNotAdopted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		world := reconciletest.NewWorld()
		entries := []netip.Prefix{host("203.0.113.1"), host("127.0.0.1"), host("::1"), host("0.0.0.0")}
		if err := world.Backend().AddEntries(t.Context(), "web", entries); err != nil {
			t.Fatal(err)
		}
		h := start(t, world, reconciletest.NewInventory(en0), filepath.Join(t.TempDir(), "addrbook.json"), configV1)
		defer h.stop()

		h.wantState(daemon.StateReady)
		requireNoLocalEntry(t, h.world.Tables())
		if !h.hasEntry("web", host("203.0.113.1")) {
			t.Errorf("web table = %v, want the adopted 203.0.113.1", h.world.Tables()["web"])
		}
		if got, want := h.saved("web"), []netip.Addr{netip.MustParseAddr("203.0.113.1")}; !slices.Equal(got, want) {
			t.Errorf("snapshot web = %v, want %v", got, want)
		}
	})
}

// An earlier ifboundd can have saved a loopback address in the
// snapshot, and put it in the kernel table. The load of the snapshot
// drops it, and the first convergence removes it from the table. Status
// does not count it.
func TestSnapshotLoopbackEntryLeavesTheTable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := filepath.Join(t.TempDir(), "addrbook.json")
		now := time.Now().UnixNano()
		doc := fmt.Sprintf(`{"version":1,"entries":[`+
			`{"policy":"web","addr":"127.0.0.1","last_seen_unix_nano":%[1]d,"ttl_nano":0,"expiry_unix_nano":%[2]d},`+
			`{"policy":"ads","addr":"::1","last_seen_unix_nano":%[1]d,"ttl_nano":0,"expiry_unix_nano":%[2]d}]}`,
			now, now+int64(time.Hour))
		if err := os.WriteFile(snapshot, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		world := reconciletest.NewWorld()
		for name, entry := range map[policy.Name]netip.Prefix{"web": host("127.0.0.1"), "ads": host("::1")} {
			if err := world.Backend().AddEntries(t.Context(), name, []netip.Prefix{entry}); err != nil {
				t.Fatal(err)
			}
		}

		h := start(t, world, reconciletest.NewInventory(en0), snapshot, configV1)
		defer h.stop()

		h.wantState(daemon.StateReady)
		requireNoLocalEntry(t, h.world.Tables())
		if st := h.status(); st.Addrs != 0 {
			t.Errorf("status addresses = %d, want 0", st.Addrs)
		}
	})
}

// A loopback address in the host file blocks nothing either, by the
// same rule as a report.
func TestHostLoopbackAddressesAreNotBlocked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.writeHosts("127.0.0.1 local.example.net\n::1 local.example.net\n0.0.0.0 zero.example.net\n:: zero.example.net\n127.0.0.53 lo.example.net\n10.0.0.1 lo.example.net\n")
		heal()

		requireNoLocalEntry(t, h.world.Tables())
		if !h.hasEntry("web", host("10.0.0.1")) {
			t.Errorf("web table = %v, want 10.0.0.1", h.world.Tables()["web"])
		}
	})
}

// A configured destination is the choice of the user: the rule does not
// remove it, also when it is a loopback address.
func TestConfiguredLoopbackDestinationStays(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, header+`
[[policy]]
name = "lo"
to = ["lo.example", "127.0.0.2", "::1"]
only_via = ["en0"]
`)
		defer h.stop()
		h.wantState(daemon.StateReady)
		if err := h.observe(obs("lo.example", "127.0.0.1")); err != nil {
			t.Fatalf("Observe = %v, want an ack", err)
		}

		want := []netip.Prefix{host("127.0.0.2"), host("::1")}
		if got := h.world.Tables()["lo"]; !slices.Equal(got, want) {
			t.Errorf("lo table = %v, want %v", got, want)
		}
	})
}
