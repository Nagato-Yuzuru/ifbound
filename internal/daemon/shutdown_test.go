package daemon_test

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
)

// A refresh that the record of an earlier answer covers is not written.
// A stop then writes nothing, and a restart still keeps the address for
// the full retain period after its last answer.
func TestRecordCoversTheRefreshesAfterIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		h.wantState(daemon.StateReady)
		a := netip.MustParseAddr("203.0.113.1")
		if err := h.observe(obs("www.example.net", a.String())); err != nil {
			t.Fatalf("Observe: %v", err)
		}
		time.Sleep(20 * time.Minute) // the record of the first answer covers this one
		last := time.Now()
		if err := h.observe(obs("www.example.net", a.String())); err != nil {
			t.Fatalf("Observe: %v", err)
		}

		h.stop()

		want := last.Add(time.Hour)
		if got, ok := h.savedExpiry("web", a); !ok || got.Before(want) {
			t.Errorf("saved expiry after stop = %v (present %v), want at least %v", got, ok, want)
		}
	})
}
