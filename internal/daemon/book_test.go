package daemon_test

import (
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"go.etcd.io/bbolt"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// writeDamagedBook writes an address book at path with one address, and
// then damages the type of each page after the two meta pages.
func writeDamagedBook(t *testing.T, path string) {
	t.Helper()
	s, err := addrstore.Open(path, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := blockable.New(netip.MustParseAddr("203.0.113.1"))
	p, err := s.Touch([]policy.Name{"web"}, []blockable.Addr{a}, 0, time.Now())
	mustDo(t, err)
	mustDo(t, s.Commit(t.Context(), p))
	mustDo(t, s.Close())
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{ReadOnly: true})
	mustDo(t, err)
	pageSize := db.Info().PageSize
	mustDo(t, db.Close())
	image := readFile(t, path)
	const flagsAt = 8 // the offset of the page type in the page header
	for off := 2 * pageSize; off < len(image); off += pageSize {
		image[off+flagsAt], image[off+flagsAt+1] = 0xff, 0xff
	}
	mustDo(t, os.WriteFile(path, image, 0o600))
}

// An address book with a damaged page does not open, and the daemon
// lives: it starts add-only, as for any book that does not open.
func TestDamagedAddressBookGivesTheAddOnlyStart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := unloadableWithKernelEntries(t)
		mustDo(t, os.Remove(s.snapshot))
		writeDamagedBook(t, bookPath(s.snapshot))
		h := launch(t, s)
		defer h.stop()

		wantAddOnly(h)
		if st := h.status(); !strings.Contains(st.Reasons[0], addrstore.ErrCorrupt.Error()) {
			t.Errorf("first reason = %q, want the corrupt store", st.Reasons[0])
		}
		heal()
		wantAddOnly(h)
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
