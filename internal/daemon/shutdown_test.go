package daemon_test

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
)

// A refresh inside the save slack is not written at once. A stop of the
// daemon writes it, so a restart keeps the address for the full retain
// period after its last answer.
func TestStopWritesTheRefreshesInsideTheSlack(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		h.wantState(daemon.StateReady)
		a := netip.MustParseAddr("203.0.113.1")
		if err := h.observe(obs("www.example.net", a.String())); err != nil {
			t.Fatalf("Observe: %v", err)
		}
		time.Sleep(20 * time.Minute) // inside the slack of retain 1h
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
