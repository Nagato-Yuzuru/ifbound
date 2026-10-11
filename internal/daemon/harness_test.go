package daemon_test

import (
	"context"
	"net/netip"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrbook"
	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

const header = `
[dns]
listen = "127.0.0.1:53553"
upstream = ["tls://1.1.1.1@cloudflare-dns.com"]
[addrbook]
retain = "1h"
`

const configV1 = header + `
[[policy]]
name = "web"
to = ["example.com", "*.example.net", "192.0.2.10", "198.51.100.0/24"]
only_via = ["en0"]

[[policy]]
name = "ads"
to = ["*.ads.example", "2001:db8::/32"]
deny_via = ["@tunnel"]
`

// configV2 changes the constraint of web, removes ads, and adds mail.
const configV2 = header + `
[[policy]]
name = "web"
to = ["example.com", "*.example.net", "192.0.2.10", "198.51.100.0/24"]
only_via = ["utun*"]

[[policy]]
name = "mail"
to = ["mail.example.org", "203.0.113.0/28"]
deny_via = ["en1"]
`

var (
	en0   = reconcile.Interface{Name: "en0", Class: policy.ClassHardware}
	utun0 = reconcile.Interface{Name: "utun0", Class: policy.ClassTunnel}

	pfDisabled = reconcile.Problem{Text: "pf is disabled", Voids: true}
	conflict   = reconcile.Problem{Text: "foreign resolver entry for example.com"}
)

func parse(t *testing.T, text string) policy.Config {
	t.Helper()
	cfg, err := policy.ParseBytes([]byte(text))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return cfg
}

func obs(qname string, addrs ...string) ipc.Observation {
	o := ipc.Observation{QName: qname, TTL: time.Minute}
	for _, s := range addrs {
		o.Addrs = append(o.Addrs, netip.MustParseAddr(s))
	}
	return o
}

func host(s string) netip.Prefix {
	a := netip.MustParseAddr(s)
	return netip.PrefixFrom(a, a.BitLen())
}

// harness runs one daemon on a World. Use it only inside a synctest
// bubble.
type harness struct {
	t        *testing.T
	world    *reconciletest.World
	inv      *reconciletest.Inventory
	snapshot string
	d        *daemon.Daemon
	stop     func()
}

func newHarness(t *testing.T, cfgText string) *harness {
	t.Helper()
	world := reconciletest.NewWorld()
	return start(t, world, reconciletest.NewInventory(en0), filepath.Join(t.TempDir(), "addrbook.json"), parse(t, cfgText))
}

// start runs a daemon on the World until stop, and waits until the daemon
// blocks for events.
func start(t *testing.T, world *reconciletest.World, inv *reconciletest.Inventory, snapshot string, cfg policy.Config) *harness {
	t.Helper()
	return startOn(t, world, world.Backend(), inv, snapshot, cfg)
}

// startOn is start with a Backend that wraps the one of the World.
func startOn(t *testing.T, world *reconciletest.World, be reconcile.Backend, inv *reconciletest.Inventory, snapshot string, cfg policy.Config) *harness {
	t.Helper()
	d := daemon.New(daemon.Config{
		Policy:   cfg,
		Snapshot: snapshot,
		Platform: reconcile.Reconciler{
			Compiler:  reconciletest.Compiler{},
			Backend:   be,
			Resolver:  world.Resolver(),
			Inventory: inv,
		},
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	synctest.Wait()
	stop := func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	}
	return &harness{t: t, world: world, inv: inv, snapshot: snapshot, d: d, stop: stop}
}

func (h *harness) status() daemon.Status {
	h.t.Helper()
	st, err := h.d.Status(h.t.Context())
	if err != nil {
		h.t.Fatalf("Status: %v", err)
	}
	return st
}

func (h *harness) wantState(want daemon.State) daemon.Status {
	h.t.Helper()
	st := h.status()
	if st.State != want {
		h.t.Fatalf("state = %v (reasons %q), want %v", st.State, st.Reasons, want)
	}
	return st
}

func (h *harness) observe(o ipc.Observation) error {
	return h.d.Observe(h.t.Context(), o)
}

func (h *harness) hasEntry(table policy.Name, p netip.Prefix) bool {
	return slices.Contains(h.world.Tables()[table], p)
}

func (h *harness) references(name policy.Name) bool {
	return slices.Contains(h.world.Referenced(), name)
}

// saved returns the addresses of a policy in the snapshot on disk.
func (h *harness) saved(name policy.Name) []netip.Addr {
	h.t.Helper()
	b := addrbook.New(time.Hour, time.Now)
	if err := b.Load(h.snapshot); err != nil {
		h.t.Fatalf("load snapshot: %v", err)
	}
	return b.Addrs(name)
}

// failWrites makes every write fail until h.world.SetBeforeWrite(nil).
func (h *harness) failWrites() {
	h.world.SetBeforeWrite(func(int) error { return reconciletest.ErrInjected })
}

// failWrite makes only the k-th write from now on fail.
func (h *harness) failWrite(k int) {
	target := h.world.Writes() + k
	h.world.SetBeforeWrite(func(n int) error {
		if n == target {
			return reconciletest.ErrInjected
		}
		return nil
	})
}

// heal lets one self-heal pass run.
func heal() {
	time.Sleep(daemon.SelfHealInterval)
	synctest.Wait()
}

// loadFails is a Backend whose Load fails while fail is set, as pfctl
// does for a ruleset it rejects.
type loadFails struct {
	*reconciletest.Backend
	fail *atomic.Bool
}

func (b loadFails) Load(ctx context.Context, rs reconcile.Ruleset) error {
	if b.fail.Load() {
		return reconciletest.ErrInjected
	}
	return b.Backend.Load(ctx, rs)
}
