package daemon_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
	"github.com/Nagato-Yuzuru/ifbound/internal/syslookup"
)

// Snapshots that the previous ifboundd wrote; see the addrbook tests.
const (
	v2MixedSnapshot       = "../addrbook/testdata/snapshot-v2/mixed.json"
	v2AliasesOnlySnapshot = "../addrbook/testdata/snapshot-v2/aliases-only.json"
)

func hostPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		a := netip.MustParseAddr(s)
		out[i] = netip.PrefixFrom(a, a.BitLen())
	}
	slices.SortFunc(out, netip.Prefix.Compare)
	return out
}

func worldWithLearned(t *testing.T, dir string) *reconciletest.World {
	t.Helper()
	// A first daemon learns addresses; the kernel tables keep them after
	// it stops.
	w := reconciletest.NewWorld()
	rg := newRig(t, w, dir, rigCfgA)
	for _, o := range []ipc.Observation{
		{QName: "example.com", Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, TTL: time.Minute},
		{QName: "x.ads.example", Addrs: []netip.Addr{netip.MustParseAddr("2001:db8::5")}, TTL: time.Minute},
	} {
		if err := rg.d.Observe(context.Background(), o); err != nil {
			t.Fatalf("first daemon: Observe(%s) = %v", o.QName, err)
		}
	}
	rg.stop()
	return w
}

// A snapshot that does not load keeps the daemon in starting. It
// writes nothing: the kernel tables keep every address, the snapshot
// file stays as it is, and no report is acked.
func TestRefusedSnapshotDropsNoKernelAddress(t *testing.T) {
	entries := `[{"policy":"web","addr":"192.0.2.1","last_seen_unix_nano":1,"ttl_nano":0,"expiry_unix_nano":2}]`
	for name, doc := range map[string]string{
		"bad version":        `{"version":3,"entries":` + entries + `,"aliases":[]}`,
		"aliases not array":  `{"version":2,"entries":` + entries + `,"aliases":{}}`,
		"v2 missing aliases": `{"version":2,"entries":` + entries + `}`,
		"truncated":          `{"version":2,"entries":` + entries + `,"alia`,
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { checkRefusedSnapshot(t, doc) })
		})
	}
}

// checkRefusedSnapshot starts a daemon on a snapshot that does not load,
// on a World whose tables hold learned addresses.
func checkRefusedSnapshot(t *testing.T, doc string) {
	dir := t.TempDir()
	w := worldWithLearned(t, dir)
	tables := w.Tables()
	ruleset := w.Ruleset().ID()
	entries := w.ResolverEntries()
	snap := filepath.Join(dir, "addrbook.json")
	if err := os.WriteFile(snap, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	writes := w.Writes()

	rg := newRig(t, w, dir, rigCfgA)
	for range 3 {
		time.Sleep(daemon.SelfHealInterval)
		synctest.Wait()
	}
	if st := rg.status(); st.State != daemon.StateStarting {
		t.Fatalf("state = %v, want starting", st.State)
	}
	err := rg.d.Observe(context.Background(), ipc.Observation{QName: "example.com", Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.9")}})
	if !errors.Is(err, daemon.ErrNotReady) {
		t.Errorf("Observe = %v, want ErrNotReady", err)
	}
	if got := w.Writes(); got != writes {
		t.Errorf("platform writes = %d, want none", got-writes)
	}
	if got := w.Tables(); !slices.Equal(got["web"], tables["web"]) || !slices.Equal(got["ads"], tables["ads"]) {
		t.Errorf("tables %v, want %v", got, tables)
	}
	if w.Ruleset().ID() != ruleset || !slices.Equal(w.ResolverEntries(), entries) {
		t.Error("the ruleset or the resolver entries changed")
	}
	if data, _ := os.ReadFile(snap); !bytes.Equal(data, []byte(doc)) {
		t.Errorf("the refused snapshot was overwritten: %s", data)
	}
}

// A v2 snapshot of the previous version with aliases only has no
// address of a configured policy, so the daemon adopts the kernel
// entries, keeps them, and saves them in the current format.
func TestAliasOnlySnapshotAdoptsKernelEntries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		w := worldWithLearned(t, dir)
		data, err := os.ReadFile(v2AliasesOnlySnapshot)
		if err != nil {
			t.Fatal(err)
		}
		snap := filepath.Join(dir, "addrbook.json")
		if err := os.WriteFile(snap, data, 0o600); err != nil {
			t.Fatal(err)
		}
		rg := newRig(t, w, dir, rigCfgA)
		if st := rg.status(); st.State != daemon.StateReady {
			t.Fatalf("state = %v (%q), want ready", st.State, st.Reasons)
		}
		tables := w.Tables()
		if want := hostPrefixes("192.0.2.1", "192.0.2.10"); !slices.Equal(tables["web"], want) {
			t.Errorf("web table %v, want %v", tables["web"], want)
		}
		if want := hostPrefixes("2001:db8::5"); !slices.Equal(tables["ads"], want) {
			t.Errorf("ads table %v, want %v", tables["ads"], want)
		}
		for _, e := range []struct {
			p policy.Name
			a string
		}{{"web", "192.0.2.1"}, {"ads", "2001:db8::5"}} {
			if _, ok := rg.savedExpiry(e.p, netip.MustParseAddr(e.a)); !ok {
				t.Errorf("adopted %s %s is not in the saved snapshot", e.p, e.a)
			}
		}
		if saved, _ := os.ReadFile(snap); bytes.Contains(saved, []byte("aliases")) {
			t.Errorf("the saved snapshot still has aliases: %s", saved)
		}
		rg.checkResolverEntries(true)
	})
}

// A snapshot that holds addresses only of a policy that the
// configuration removed has no address of a configured policy, so the
// daemon adopts the kernel entries. The book is not empty, but without
// the adoption the convergence would remove the acked addresses of the
// configured policies from their tables.
func TestRemovedPolicyOnlySnapshotAdoptsKernelEntries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		w := worldWithLearned(t, dir)
		now := time.Now().UnixNano()
		doc := fmt.Sprintf(`{"version":1,"entries":[{"policy":"gone","addr":"203.0.113.9",`+
			`"last_seen_unix_nano":%d,"ttl_nano":0,"expiry_unix_nano":%d}]}`, now, now+int64(time.Hour))
		if err := os.WriteFile(filepath.Join(dir, "addrbook.json"), []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		rg := newRig(t, w, dir, rigCfgA)
		if st := rg.status(); st.State != daemon.StateReady {
			t.Fatalf("state = %v (%q), want ready", st.State, st.Reasons)
		}
		tables := w.Tables()
		if want := hostPrefixes("192.0.2.1", "192.0.2.10"); !slices.Equal(tables["web"], want) {
			t.Errorf("web table %v, want %v: the acked address is gone", tables["web"], want)
		}
		if want := hostPrefixes("2001:db8::5"); !slices.Equal(tables["ads"], want) {
			t.Errorf("ads table %v, want %v: the acked address is gone", tables["ads"], want)
		}
		if _, ok := rg.savedExpiry("web", netip.MustParseAddr("192.0.2.1")); !ok {
			t.Error("the adopted web 192.0.2.1 is not in the saved snapshot")
		}
	})
}

// A v2 snapshot of the previous version with entries loads at start:
// its addresses of configured policies go to the tables, the resolver
// gets no alias entry, and reports are acked.
func TestV2SnapshotEntriesReachTheTables(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		data, err := os.ReadFile(v2MixedSnapshot)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "addrbook.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
		w := reconciletest.NewWorld()
		// Resolver entries that the previous version wrote for aliases.
		seedResolverEntries(t, w, "cdn.example.net", "edge.example.org", "alias.example.com")
		rg := newRig(t, w, dir, rigCfgA)
		if st := rg.status(); st.State != daemon.StateReady {
			t.Fatalf("state = %v (%q), want ready", st.State, st.Reasons)
		}
		tables := w.Tables()
		if want := hostPrefixes("192.0.2.1", "2001:db8::1", "192.0.2.10"); !slices.Equal(tables["web"], want) {
			t.Errorf("web table %v, want %v", tables["web"], want)
		}
		if want := hostPrefixes("192.0.2.1", "198.51.100.7"); !slices.Equal(tables["ads"], want) {
			t.Errorf("ads table %v, want %v", tables["ads"], want)
		}
		if _, ok := tables["gone"]; ok {
			t.Error("a table for the unconfigured policy gone exists")
		}
		rg.checkResolverEntries(true)
		if err := rg.d.Observe(context.Background(), ipc.Observation{QName: "www.example.net", Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}); err != nil {
			t.Errorf("Observe after a v2 load = %v, want an ack", err)
		}
	})
}

// gatedWarmLookup routes a probe name to the daemon only while routing is on.
// It records the other names.
type gatedWarmLookup struct {
	d       *daemon.Daemon
	routing atomic.Bool
	mu      sync.Mutex
	probes  int
	names   []string
}

func (l *gatedWarmLookup) Resolve(_ context.Context, name string) ([]netip.Addr, error) {
	if ipc.IsProbe(name) {
		l.mu.Lock()
		l.probes++
		l.mu.Unlock()
		if l.routing.Load() {
			l.d.ProbeSeen(name)
		}
	} else {
		l.mu.Lock()
		l.names = append(l.names, name)
		l.mu.Unlock()
	}
	return nil, fmt.Errorf("resolve %s: %w", name, syslookup.ErrNotFound)
}

func (l *gatedWarmLookup) state() (int, []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.probes, slices.Sorted(slices.Values(l.names))
}

type capturedLogs struct {
	mu   sync.Mutex
	msgs []string
}

func (h *capturedLogs) Enabled(context.Context, slog.Level) bool { return true }
func (h *capturedLogs) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	msg := r.Level.String() + " " + r.Message
	r.Attrs(func(a slog.Attr) bool {
		msg += " " + a.String()
		return true
	})
	h.msgs = append(h.msgs, msg)
	return nil
}
func (h *capturedLogs) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturedLogs) WithGroup(string) slog.Handler      { return h }

// The warm-up resolves a name only after a probe proved that its queries
// reach ifbound-dns. A probe that never arrives is a warning with the
// cause and a later retry, not a lookup.
func TestWarmUpWaitsForTheProbeAndRetriesLater(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := rigCfg(t, rigCfgA)
		w := reconciletest.NewWorld()
		lookup := &gatedWarmLookup{}
		logs := &capturedLogs{}
		d := daemon.New(daemon.Config{
			Policy:   cfg,
			Snapshot: filepath.Join(t.TempDir(), "addrbook.json"),
			Platform: reconcile.Reconciler{
				Compiler: reconciletest.Compiler{}, Backend: w.Backend(), Resolver: w.Resolver(),
				Inventory: reconciletest.NewInventory(rigEn0),
			},
			Lookup: lookup,
			Logger: slog.New(logs),
		})
		lookup.d = d
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- d.Run(ctx) }()

		time.Sleep(2 * daemon.SelfHealInterval)
		synctest.Wait()
		probes, names := lookup.state()
		if probes == 0 {
			t.Fatal("the warm-up sent no probe")
		}
		if len(names) != 0 {
			t.Fatalf("the warm-up resolved %v without a proof", names)
		}
		logs.mu.Lock()
		msgs := slices.Clone(logs.msgs)
		logs.mu.Unlock()
		if !slices.ContainsFunc(msgs, func(m string) bool {
			return strings.HasPrefix(m, "WARN warm-up: no proof") && strings.Contains(m, "error=daemon: probe not seen by ifbound-dns")
		}) {
			t.Errorf("no warning with the probe error for the failed probe: %q", msgs)
		}

		lookup.routing.Store(true)
		time.Sleep(daemon.SelfHealInterval + daemon.WarmUpTimeout + time.Second)
		synctest.Wait()
		if _, names := lookup.state(); !slices.Equal(names, []string{"ads.example", "example.com", "example.net"}) {
			t.Errorf("after the probes pass, the warm-up resolved %v, want ads.example example.com example.net", names)
		}
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
}

func seedResolverEntries(t *testing.T, w *reconciletest.World, domains ...string) {
	t.Helper()
	for _, d := range domains {
		dom, err := policy.ParseDomain(d)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Resolver().Write(context.Background(), reconcile.ResolverEntry{Domain: dom, Server: netip.MustParseAddrPort("127.0.0.1:53553")}); err != nil {
			t.Fatal(err)
		}
	}
}
