//go:build e2e && darwin

package e2e

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/macinventory"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/testnet"
)

// signalWait is the longest time from a change to its signal that the
// tests accept. The inventory signals Debounce after the first message.
const signalWait = 5 * time.Second

// TestInventorySignalsInterfaceChanges creates and removes a feth pair
// and a utun. Each change gives a signal on Changes, and the snapshot
// after the signal shows the interface with its class, or without it.
func TestInventorySignalsInterfaceChanges(t *testing.T) {
	requireE2E(t)
	inv := startInventory(t)

	var feth testnet.FethPair
	t.Run("feth appears as hardware", func(t *testing.T) {
		quiet(t, inv)
		feth = testnet.NewFethPair(t)
		awaitSignal(t, inv, "creating "+feth.String())
		for _, name := range []string{feth.A, feth.B} {
			if got := classOf(t, inv, name); got != policy.ClassHardware {
				t.Errorf("class of %s = %v, want %v", name, got, policy.ClassHardware)
			}
		}
		// The cleanup removes the pair after this quiet, so the next
		// signal comes from the removal.
		quiet(t, inv)
	})
	if t.Failed() {
		return
	}
	t.Run("feth goes away", func(t *testing.T) {
		// The cleanup of the subtest above removed the pair.
		awaitSignal(t, inv, "removing "+feth.String())
		requireAbsent(t, inv, feth.A, feth.B)
	})

	var utun string
	t.Run("utun appears as tunnel", func(t *testing.T) {
		quiet(t, inv)
		u := testnet.NewUTUN(t)
		utun = u.Name
		// A utun that is down sends no routing message. The first
		// address brings it up and sends RTM_NEWADDR only, as many VPN
		// clients do it: no "up" here. 198.18.0.0/15 is reserved for
		// benchmark tests (RFC 2544).
		testnet.Ifconfig(t, utun, "inet", "198.18.7.1", "198.18.7.2")
		awaitSignal(t, inv, "creating "+utun)
		if got := classOf(t, inv, utun); got != policy.ClassTunnel {
			t.Errorf("class of %s = %v, want %v", utun, got, policy.ClassTunnel)
		}
		quiet(t, inv) // as for the feth pair
	})
	if t.Failed() {
		return
	}
	t.Run("utun goes away", func(t *testing.T) {
		awaitSignal(t, inv, "removing "+utun)
		requireAbsent(t, inv, utun)
	})
}

// startInventory runs the inventory until the test ends. It returns after
// the first signal, which Run sends when it reads the routing socket.
func startInventory(t *testing.T) *macinventory.Inventory {
	t.Helper()
	inv := macinventory.New()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- inv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	awaitSignal(t, inv, "opening the routing socket")
	return inv
}

// quiet takes the signals of earlier changes, and returns when no signal
// came for three times Debounce. A signal after quiet then comes from the
// next change.
func quiet(t *testing.T, inv *macinventory.Inventory) {
	t.Helper()
	deadline := time.After(signalWait)
	for {
		select {
		case <-inv.Changes():
		case <-time.After(3 * macinventory.Debounce):
			return
		case <-deadline:
			t.Fatalf("signals did not stop within %v", signalWait)
		}
	}
}

func awaitSignal(t *testing.T, inv *macinventory.Inventory, cause string) {
	t.Helper()
	select {
	case <-inv.Changes():
	case <-time.After(signalWait):
		t.Fatalf("no signal within %v after %s", signalWait, cause)
	}
}

func snapshot(t *testing.T, inv *macinventory.Inventory) []reconcile.Interface {
	t.Helper()
	ifaces, err := inv.Interfaces(t.Context())
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}
	return ifaces
}

func classOf(t *testing.T, inv *macinventory.Inventory, name string) policy.Class {
	t.Helper()
	ifaces := snapshot(t, inv)
	i := slices.IndexFunc(ifaces, func(x reconcile.Interface) bool { return x.Name == name })
	if i < 0 {
		t.Fatalf("Interfaces = %v, want %s in the list", ifaces, name)
	}
	return ifaces[i].Class
}

func requireAbsent(t *testing.T, inv *macinventory.Inventory, names ...string) {
	t.Helper()
	ifaces := snapshot(t, inv)
	for _, name := range names {
		if slices.ContainsFunc(ifaces, func(x reconcile.Interface) bool { return x.Name == name }) {
			t.Errorf("Interfaces = %v, want no %s", ifaces, name)
		}
	}
}
