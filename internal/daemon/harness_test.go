package daemon_test

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
	// sys is the system resolver of the daemon, when startWith did not
	// get another one.
	sys  *sysNet
	d    *daemon.Daemon
	stop func()
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
	sys := newSysNet(world, cfg.DNS.Listen)
	h := startWith(t, world, be, world.Resolver(), inv, snapshot, cfg, sys)
	h.sys = sys
	return h
}

// attacher is a system resolver that needs the daemon: it acts as
// ifbound-dns too, and reports probes to the daemon.
type attacher interface{ attach(d *daemon.Daemon) }

// startWith is startOn with a given SysResolver, which wraps the one of
// the World, and a given system resolver.
func startWith(t *testing.T, world *reconciletest.World, be reconcile.Backend, rs reconcile.SysResolver, inv *reconciletest.Inventory, snapshot string, cfg policy.Config, lookup daemon.SystemResolver) *harness {
	t.Helper()
	d := daemon.New(daemon.Config{
		Policy:   cfg,
		Snapshot: snapshot,
		Platform: reconcile.Reconciler{
			Compiler:  reconciletest.Compiler{},
			Backend:   be,
			Resolver:  rs,
			Inventory: inv,
		},
		Lookup: lookup,
	})
	if a, ok := lookup.(attacher); ok {
		a.attach(d)
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

// sysNet is the system resolver of the tests, together with ifbound-dns.
// A name goes to the server of the most specific applied resolver entry
// of the World that covers it, as the system routes a query; when that is
// the listen address, ifbound-dns reports a probe name to the daemon. The answer is always
// "no such name". A hook, when set, runs first, and an error from it ends
// the lookup there.
type sysNet struct {
	world  *reconciletest.World
	listen netip.AddrPort
	d      *daemon.Daemon

	mu    sync.Mutex
	names []string
	hook  func(ctx context.Context, name string) error
}

func newSysNet(world *reconciletest.World, listen netip.AddrPort) *sysNet {
	return &sysNet{world: world, listen: listen}
}

func (s *sysNet) attach(d *daemon.Daemon) { s.d = d }

func (s *sysNet) setHook(f func(ctx context.Context, name string) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hook = f
}

func (s *sysNet) Resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	s.mu.Lock()
	s.names = append(s.names, name)
	hook := s.hook
	s.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, name); err != nil {
			return nil, err
		}
	}
	if s.routed(name) && ipc.IsProbe(name) {
		s.d.ProbeSeen(name)
	}
	return nil, fmt.Errorf("resolve %s: %w", name, syslookup.ErrNotFound)
}

// routed reports whether the system sends the queries for name to
// ifbound-dns now.
func (s *sysNet) routed(name string) bool {
	return routes(s.world.AppliedResolverEntries(), name, s.listen)
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

// probes returns the probe names that the daemon sent for alias, in
// order.
func (s *sysNet) probes(alias string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, n := range s.names {
		if ipc.IsProbe(n) && strings.HasSuffix(n, "."+alias) && strings.Count(n, ".") == strings.Count(alias, ".")+1 {
			out = append(out, n)
		}
	}
	return out
}

// writeFails is a SysResolver whose Write fails while fail is set. It
// counts the Write calls.
type writeFails struct {
	*reconciletest.Resolver
	fail   *atomic.Bool
	writes *atomic.Int32 // may be nil
}

func (r writeFails) Write(ctx context.Context, e reconcile.ResolverEntry) error {
	if r.writes != nil {
		r.writes.Add(1)
	}
	if r.fail.Load() {
		return reconciletest.ErrInjected
	}
	return r.Resolver.Write(ctx, e)
}
