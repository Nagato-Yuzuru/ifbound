package daemon_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	"github.com/Nagato-Yuzuru/ifbound/internal/syslookup"
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
	// store is the stored configuration of the daemon.
	store string
	// hosts is the host file of the daemon. It is next to the snapshot,
	// so a restart on the same snapshot reads the same file.
	hosts       string
	hostsWrites int
	logs        *capturedLogs
	d           *daemon.Daemon
	stop        func()
	// spec is what the daemon runs on. restart keeps it.
	spec harnessSpec
}

// harnessSpec is what a daemon of a harness runs on: everything that
// outlives one daemon.
type harnessSpec struct {
	world    *reconciletest.World
	be       reconcile.Backend
	inv      *reconciletest.Inventory
	snapshot string
	store    string
	accounts daemon.AccountReader
	dns      *sysNet
}

// newSpec returns a spec on a new World, with cfgText as the stored
// configuration.
func newSpec(t *testing.T, cfgText string) harnessSpec {
	t.Helper()
	world := reconciletest.NewWorld()
	return harnessSpec{
		world: world, be: world.Backend(), inv: reconciletest.NewInventory(en0),
		snapshot: filepath.Join(t.TempDir(), "addrbook.json"),
		store:    storeConfig(t, t.TempDir(), cfgText),
		dns:      &sysNet{world: world, listen: parse(t, cfgText).DNS.Listen},
	}
}

func newHarness(t *testing.T, cfgText string) *harness {
	t.Helper()
	return launch(t, newSpec(t, cfgText))
}

// start runs a daemon on the World until stop, and waits until the daemon
// blocks for events.
func start(t *testing.T, world *reconciletest.World, inv *reconciletest.Inventory, snapshot, cfgText string) *harness {
	t.Helper()
	return startOn(t, world, world.Backend(), inv, snapshot, cfgText)
}

// startOn is start with a Backend that wraps the one of the World.
func startOn(t *testing.T, world *reconciletest.World, be reconcile.Backend, inv *reconciletest.Inventory, snapshot, cfgText string) *harness {
	t.Helper()
	return startWith(t, world, be, inv, snapshot, cfgText, nil)
}

// startWith is startOn with an account reader. accounts can be nil. The
// stored configuration is cfgText, in a new directory.
func startWith(t *testing.T, world *reconciletest.World, be reconcile.Backend, inv *reconciletest.Inventory, snapshot, cfgText string, accounts daemon.AccountReader) *harness {
	t.Helper()
	return launch(t, harnessSpec{
		world: world, be: be, inv: inv, snapshot: snapshot,
		store:    storeConfig(t, t.TempDir(), cfgText),
		accounts: accounts,
		dns:      &sysNet{world: world, listen: parse(t, cfgText).DNS.Listen},
	})
}

// launch runs a daemon on s until stop, and waits until the daemon blocks
// for events.
func launch(t *testing.T, s harnessSpec) *harness {
	t.Helper()
	return launchHook(t, s, nil)
}

// launchHook is launch with hook, when it is not nil, called on the
// daemon before Run.
func launchHook(t *testing.T, s harnessSpec, hook func(*daemon.Daemon)) *harness {
	t.Helper()
	hosts := filepath.Join(filepath.Dir(s.snapshot), "hosts")
	logs := &capturedLogs{}
	d := daemon.New(daemon.Config{
		ConfigPath: s.store,
		ConfigGID:  -1,
		Snapshot:   s.snapshot,
		HostsFile:  hosts,
		Logger:     slog.New(logs),
		Platform: reconcile.Reconciler{
			Compiler:  scopeCompiler{},
			Backend:   s.be,
			Resolver:  s.world.Resolver(),
			Inventory: s.inv,
		},
		Accounts: s.accounts,
		Lookup:   s.dns,
	})
	s.dns.d.Store(d)
	if hook != nil {
		hook(d)
	}
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
	return &harness{
		t: t, world: s.world, inv: s.inv, snapshot: s.snapshot, store: s.store,
		hosts: hosts, logs: logs, d: d, stop: stop, spec: s,
	}
}

// restart stops the daemon and starts a new one on the same World,
// stored file, and snapshot.
func (h *harness) restart() *harness {
	h.t.Helper()
	h.stop()
	return launch(h.t, h.spec)
}

// storeConfig writes text as the stored configuration in dir, as
// "ifbound apply" leaves it, and returns its path.
func storeConfig(t *testing.T, dir, text string) string {
	t.Helper()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// status waits until every goroutine of the bubble blocks, so that the
// published Status covers the passes that the last step started, such as
// the warm-up of a new configuration. A test of Status itself calls
// h.d.Status.
func (h *harness) status() daemon.Status {
	h.t.Helper()
	synctest.Wait()
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
	_, err := h.d.Observe(h.t.Context(), o)
	return err
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

// sysNet is the system resolver of the tests, together with ifbound-dns.
// A name goes to the server of the most specific applied resolver entry
// of the World that covers it, as the system routes a query; when that is
// the listen address, ifbound-dns reports a probe name to the daemon. The
// answer is always "no such name". While down is set, ifbound-dns
// is not connected: no probe name reaches the daemon.
type sysNet struct {
	world  *reconciletest.World
	listen netip.AddrPort
	d      atomic.Pointer[daemon.Daemon]
	down   atomic.Bool
}

func (s *sysNet) Resolve(_ context.Context, name string) ([]netip.Addr, error) {
	if !s.down.Load() && ipc.IsProbe(name) && routes(s.world.AppliedResolverEntries(), name, s.listen) {
		s.d.Load().ProbeSeen(name)
	}
	return nil, fmt.Errorf("resolve %s: %w", name, syslookup.ErrNotFound)
}

// routes reports whether the most specific entry that covers name has
// server as its server.
func routes(entries []reconcile.ResolverEntry, name string, server netip.AddrPort) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	best, found := "", false
	var to netip.AddrPort
	for _, e := range entries {
		d := e.Domain.String()
		if (name == d || strings.HasSuffix(name, "."+d)) && (!found || len(d) > len(best)) {
			best, found, to = d, true, e.Server
		}
	}
	return found && to == server
}
