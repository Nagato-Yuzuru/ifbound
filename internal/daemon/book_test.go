package daemon_test

import (
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// damageFirstRecord flips a byte in the first record of the first
// segment of the book at path. The record after it stays good, so a load
// sees damage, not a torn write.
func damageFirstRecord(t *testing.T, path string) {
	t.Helper()
	ents, err := os.ReadDir(path)
	mustDo(t, err)
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".seg") {
			continue
		}
		seg := filepath.Join(path, e.Name())
		image := readFile(t, seg)
		const firstRecord = 32 // after the segment header
		image[firstRecord+30] ^= 0xff
		mustDo(t, os.WriteFile(seg, image, 0o600))
		return
	}
	t.Fatal("no segment")
}

// A damaged record in the address book does not stop the open: the
// daemon logs the damage, uses the rest of the book, adopts the address
// of the lost lease from the kernel table, and shows the damage in its
// status. The damage does not void the enforcement: reports are acked.
func TestDamagedAddressBookLoadsTheRestAndAdopts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		lost, kept := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")
		mustDo(t, h.observe(obs("www.example.net", lost.String())))
		mustDo(t, h.observe(obs("www.example.net", kept.String())))
		h.stop()
		damageFirstRecord(t, bookPath(h.snapshot))

		h = launch(t, h.spec)
		defer h.stop()
		st := h.wantState(daemon.StateDegraded)
		if !slices.ContainsFunc(st.Reasons, func(r string) bool { return strings.Contains(r, "address book is damaged (places: 1)") }) {
			t.Errorf("reasons = %q, want the book damage", st.Reasons)
		}
		mustDo(t, h.observe(obs("www.example.net", "203.0.113.3")))
		if got := h.saved("web"); !slices.Contains(got, lost) || !slices.Contains(got, kept) {
			t.Errorf("web in the book = %v, want %v adopted and %v kept", got, lost, kept)
		}
		if len(h.logs.events("address book damaged")) != 1 {
			t.Error("no log of the damage")
		}
	})
}

// damageLastRecord flips a byte in the last record of the last segment
// of the book at path. A load cannot tell it from a write that a crash
// cut off.
func damageLastRecord(t *testing.T, path string) {
	t.Helper()
	ents, err := os.ReadDir(path)
	mustDo(t, err)
	var last string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".seg") {
			last = e.Name() // ReadDir sorts by name; the test writes one day only
		}
	}
	if last == "" {
		t.Fatal("no segment")
	}
	seg := filepath.Join(path, last)
	image := readFile(t, seg)
	image[len(image)-1] ^= 0xff
	mustDo(t, os.WriteFile(seg, image, 0o600))
}

// A damaged last record of an acknowledged lease looks like a cut write,
// so the load drops it without a damage report. The daemon then adopts
// the kernel entries, and the address stays blocked: the convergence
// does not remove it from the table.
func TestDamagedLastRecordStaysBlocked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		acked := netip.MustParseAddr("203.0.113.1")
		mustDo(t, h.observe(obs("www.example.net", acked.String())))
		h.stop()
		damageLastRecord(t, bookPath(h.snapshot))

		h = launch(t, h.spec)
		defer h.stop()
		h.wantState(daemon.StateReady)
		heal()
		if !h.hasEntry("web", netip.PrefixFrom(acked, 32)) {
			t.Errorf("web table = %v, want the acked %v kept", h.world.Tables()["web"], acked)
		}
		if got := h.saved("web"); !slices.Contains(got, acked) {
			t.Errorf("web in the book = %v, want %v adopted", got, acked)
		}
	})
}

// An upgrade, a downgrade, and an upgrade again: the earlier version acks
// an address and writes it to its JSON snapshot. The next start merges
// the snapshot into the address book, so the address stays blocked.
func TestAddressThatADowngradedDaemonAckedStaysBlockedAfterTheUpgrade(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		if err := h.observe(obs("example.com", "192.0.2.50")); err != nil {
			t.Fatal(err)
		}
		h.stop()

		// The earlier version: it acks 192.0.2.51, so the table holds it,
		// and it writes its snapshot.
		acked := host("192.0.2.51")
		mustDo(t, h.spec.be.AddEntries(t.Context(), "web", []netip.Prefix{acked}))
		writeSnapshot(t, h.snapshot, map[policy.Name]string{"web": acked.Addr().String()})

		h = launch(t, h.spec)
		defer h.stop()
		h.wantState(daemon.StateReady)
		heal()
		if !h.hasEntry("web", acked) {
			t.Errorf("web table = %v, want the acked %v in it", h.world.Tables()["web"], acked)
		}
		if got := h.saved("web"); !slices.Contains(got, acked.Addr()) {
			t.Errorf("web in the book = %v, want the acked %v", got, acked.Addr())
		}
		if _, err := os.Stat(h.snapshot); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the snapshot is still there: %v", err)
		}
	})
}
