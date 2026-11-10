package daemon_test

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/Nagato-Yuzuru/ifbound/internal/matcher"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// writeSnapshot writes a JSON snapshot of an earlier version, which the
// daemon imports at its first start. Each entry was seen now, with a ttl
// of one minute, and expires after the retain of one hour.
func writeSnapshot(t *testing.T, path string, entries map[policy.Name]string) {
	t.Helper()
	now := time.Now()
	var items []string
	for name, addr := range entries {
		items = append(items, fmt.Sprintf(`{"policy":%q,"addr":%q,"last_seen_unix_nano":%d,"ttl_nano":%d,"expiry_unix_nano":%d}`,
			name, addr, now.UnixNano(), time.Minute, now.Add(time.Hour).UnixNano()))
	}
	doc := `{"version":1,"entries":[` + strings.Join(items, ",") + `]}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}

// --- Lifecycle ---

func TestStartLoadsSnapshotAndInstallsEnforcement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := filepath.Join(t.TempDir(), "addrbook.json")
		writeSnapshot(t, snapshot, map[policy.Name]string{"web": "203.0.113.1", "gone": "203.0.113.9"})

		h := start(t, reconciletest.NewWorld(), reconciletest.NewInventory(en0), snapshot, configV1)
		defer h.stop()

		st := h.wantState(daemon.StateReady)
		if st.Addrs != 1 || st.Policies != 2 {
			t.Errorf("status = %+v, want 1 address and 2 policies", st)
		}
		if !h.hasEntry("web", host("203.0.113.1")) {
			t.Errorf("web table = %v, want the snapshot address", h.world.Tables()["web"])
		}
		if _, ok := h.world.Tables()["gone"]; ok {
			t.Error("a table exists for a policy that the configuration does not have")
		}
	})
}

func TestStartPrunesRemovedPoliciesAfterInstall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := filepath.Join(t.TempDir(), "addrbook.json")
		writeSnapshot(t, snapshot, map[policy.Name]string{"web": "203.0.113.1", "gone": "203.0.113.9"})
		h := start(t, reconciletest.NewWorld(), reconciletest.NewInventory(en0), snapshot, configV1)
		defer h.stop()

		// A new address makes the daemon save the book.
		if err := h.observe(obs("www.example.net", "203.0.113.2")); err != nil {
			t.Fatal(err)
		}

		if got := h.saved("gone"); len(got) != 0 {
			t.Errorf("snapshot keeps %v for a policy that left the configuration", got)
		}
	})
}

// unloadableWithKernelEntries is newUnloadableSpec on a World whose
// tables hold learned addresses and no ruleset is loaded, as after a
// reboot of a host where the tables outlive the anchor. The host file
// maps www.example.net to 10.1.1.1.
func unloadableWithKernelEntries(t *testing.T) harnessSpec {
	t.Helper()
	s := newUnloadableSpec(t, configV1)
	for name, entries := range kernelEntries {
		if err := s.be.AddEntries(t.Context(), name, entries); err != nil {
			t.Fatal(err)
		}
	}
	s.hosts = &fakeHosts{}
	s.hosts.set(true, "10.1.1.1 www.example.net\n", nil)
	return s
}

// kernelEntries are the learned addresses in the kernel tables of
// unloadableWithKernelEntries. The configuration has no policy gone.
var kernelEntries = map[policy.Name][]netip.Prefix{
	"web":  {host("203.0.113.1")},
	"ads":  {host("3fff::1")},
	"gone": {host("203.0.113.9")},
}

// A snapshot that does not load keeps the daemon in StateStarting, with
// the snapshot error as the reason, and no report is acked. The daemon
// still enforces what it knows without the book: the ruleset is loaded,
// and the IP and CIDR destinations and the host addresses are in their
// tables. It removes no table entry and drops no table: an entry that
// the book does not have can be an acked address.
func TestSnapshotLoadErrorLoadsTheRulesetAndRemovesNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := unloadableWithKernelEntries(t)
		h := launch(t, s)
		defer h.stop()

		wantAddOnly(h)
		heal()
		wantAddOnly(h)
		if got := readFile(t, s.snapshot); string(got) != "not json" {
			t.Errorf("snapshot = %q, want the refused file unchanged", got)
		}
	})
}

// wantAddOnly checks a daemon of unloadableWithKernelEntries after an
// add-only convergence.
func wantAddOnly(h *harness) {
	h.t.Helper()
	st := h.wantState(daemon.StateStarting)
	if len(st.Reasons) == 0 || !strings.Contains(st.Reasons[0], "loading snapshot") {
		h.t.Errorf("reasons = %q, want the snapshot error first", st.Reasons)
	}
	if !h.references("web") || !h.references("ads") {
		h.t.Errorf("loaded ruleset refers to %v, want web and ads", h.world.Referenced())
	}
	h.wantEntries(map[policy.Name][]netip.Prefix{
		"web": {host("192.0.2.10"), netip.MustParsePrefix("198.51.100.0/24"), host("10.1.1.1")},
		"ads": {netip.MustParsePrefix("2001:db8::/32")},
	})
	h.wantEntries(kernelEntries)
	if err := h.observe(obs("www.example.net", "203.0.113.2")); !errors.Is(err, daemon.ErrNotReady) {
		h.t.Errorf("Observe = %v, want ErrNotReady", err)
	}
}

// wantEntries checks that each table holds the entries of want, and
// possibly more.
func (h *harness) wantEntries(want map[policy.Name][]netip.Prefix) {
	h.t.Helper()
	for name, entries := range want {
		for _, e := range entries {
			if !h.hasEntry(name, e) {
				h.t.Errorf("table %s = %v, want %v in it", name, h.world.Tables()[name], e)
			}
		}
	}
}

// When the snapshot loads again, the next pass is a normal convergence:
// the daemon acks, and an entry that neither the book nor the
// configuration has leaves its table.
func TestRepairedSnapshotEndsTheAddOnlyConvergence(t *testing.T) {
	for _, tt := range []struct {
		name    string
		trigger func(h *harness)
	}{
		{"self-heal", func(*harness) { heal() }},
		{"apply", func(h *harness) {
			if _, err := h.d.Apply(h.t.Context(), []byte(configV1)); err != nil {
				h.t.Fatalf("Apply: %v", err)
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := unloadableWithKernelEntries(t)
				h := launch(t, s)
				defer h.stop()
				h.wantState(daemon.StateStarting)

				writeSnapshot(t, s.snapshot, map[policy.Name]string{"web": "203.0.113.1"})
				tt.trigger(h)
				h.wantState(daemon.StateReady)
				if err := h.observe(obs("www.example.net", "203.0.113.2")); err != nil {
					t.Errorf("Observe = %v, want an ack", err)
				}
				if !h.hasEntry("web", host("203.0.113.1")) || !h.hasEntry("web", host("10.1.1.1")) {
					t.Errorf("web table = %v, want the book and host addresses", h.world.Tables()["web"])
				}
				if h.hasEntry("ads", host("3fff::1")) {
					t.Error("ads keeps 3fff::1, which the loaded book does not have")
				}
				if _, ok := h.world.Tables()["gone"]; ok {
					t.Error("the table of a policy outside the configuration stays")
				}
			})
		})
	}
}

// The first configuration fixes the retain, also when a second one comes
// before the snapshot loads.
func TestConfigChangeWhileStartingKeepsTheFirstRetain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := launch(t, newUnloadableSpec(t, configV1))
		defer h.stop()

		cfg := parse(t, strings.Replace(configV1, `retain = "1h"`, `retain = "2h"`, 1))
		if err := h.d.Reconfigure(t.Context(), cfg); err == nil {
			t.Fatal("Reconfigure = nil, want the snapshot error")
		}
		if st := h.status(); !st.RetainRestart {
			t.Error("RetainRestart = false, want true")
		}
	})
}

// A first convergence that installs the ruleset and then fails a later
// write keeps the loaded book: the daemon acknowledges reports.
func TestFirstConvergenceThatFailsAfterTheInstallAcks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// n is the write count of a clean start. A fault at write n hits
		// a resolver write of the first convergence, after the install.
		ref := newHarness(t, configV1)
		n := ref.world.Writes()
		ref.stop()

		world := reconciletest.NewWorld()
		world.SetBeforeWrite(func(k int) error {
			if k == n {
				return reconciletest.ErrInjected
			}
			return nil
		})
		h := start(t, world, reconciletest.NewInventory(en0), filepath.Join(t.TempDir(), "addrbook.json"), configV1)
		defer h.stop()
		world.SetBeforeWrite(nil)

		if st := h.status(); st.State != daemon.StateReady {
			t.Errorf("state = %v (reasons %q), want ready after the self-test", st.State, st.Reasons)
		}
		if err := h.observe(obs("www.example.net", "203.0.113.1")); err != nil {
			t.Errorf("Observe = %v, want an ack", err)
		}
	})
}

func TestStartWithoutSnapshotAdoptsKernelEntries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		world := reconciletest.NewWorld()
		be := world.Backend()
		for name, entries := range map[policy.Name][]netip.Prefix{
			"web":  {netip.MustParsePrefix("198.51.100.0/24"), host("192.0.2.10"), host("203.0.113.1")},
			"ads":  {host("3fff::1")},
			"gone": {host("203.0.113.9")},
		} {
			if err := be.AddEntries(t.Context(), name, entries); err != nil {
				t.Fatal(err)
			}
		}
		h := start(t, world, reconciletest.NewInventory(en0), filepath.Join(t.TempDir(), "addrbook.json"), configV1)
		defer h.stop()

		h.wantState(daemon.StateReady)
		if !h.hasEntry("web", host("203.0.113.1")) || !h.hasEntry("ads", host("3fff::1")) {
			t.Errorf("tables = %v, want the kernel addresses kept", h.world.Tables())
		}
		if got := h.saved("web"); !slices.Equal(got, []netip.Addr{netip.MustParseAddr("203.0.113.1")}) {
			t.Errorf("snapshot web = %v, want the adopted address only (not the IP destination)", got)
		}
		// The table of a policy outside the configuration is adopted too,
		// and it goes away once the installed ruleset no longer refers to
		// it. The prune after the install removes it from the book.
		if got := h.saved("gone"); len(got) != 0 {
			t.Errorf("book gone = %v, want it pruned after the install", got)
		}
		if _, ok := h.world.Tables()["gone"]; ok {
			t.Error("the table of a policy outside the configuration stays after the install")
		}

		// Adoption gives a fresh retain period, and then the entry expires.
		time.Sleep(time.Hour + time.Nanosecond)
		synctest.Wait()
		if h.hasEntry("web", host("203.0.113.1")) {
			t.Error("adopted address never expires")
		}
	})
}

func TestAdoptionSaveFailureKeepsStarting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSpec(t, configV1)
		if err := s.world.Backend().AddEntries(t.Context(), "web", []netip.Prefix{host("203.0.113.1")}); err != nil {
			t.Fatal(err)
		}
		var fail atomic.Bool
		fail.Store(true)
		h := launchHook(t, s, func(d *daemon.Daemon) { d.SetBookFault(&fail) })
		defer h.stop()

		st := h.wantState(daemon.StateStarting)
		if len(st.Reasons) != 1 || !strings.Contains(st.Reasons[0], "saving adopted entries") {
			t.Errorf("reasons = %q, want the save error", st.Reasons)
		}
		if !h.hasEntry("web", host("203.0.113.1")) || !h.references("web") {
			t.Errorf("tables = %v, referenced = %v, want the kernel address kept and the ruleset loaded",
				h.world.Tables(), h.world.Referenced())
		}

		// A later attempt opens the book again and completes.
		fail.Store(false)
		heal()
		h.wantState(daemon.StateReady)
		if got := h.saved("web"); len(got) != 1 {
			t.Errorf("book web = %v, want the adopted address", got)
		}
	})
}

func TestEntryThatExpiredWhileDownNeverReachesATable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := filepath.Join(t.TempDir(), "addrbook.json")
		writeSnapshot(t, snapshot, map[policy.Name]string{"web": "203.0.113.1"})
		time.Sleep(2 * time.Hour) // the daemon is down past retain
		world := reconciletest.NewWorld()
		var written atomic.Bool
		world.SetAfterWrite(func() {
			if slices.Contains(world.Tables()["web"], host("203.0.113.1")) {
				written.Store(true)
			}
		})

		h := start(t, world, reconciletest.NewInventory(en0), snapshot, configV1)
		defer h.stop()

		h.wantState(daemon.StateReady)
		if written.Load() {
			t.Error("an entry that expired while the daemon was down was written to a table")
		}
	})
}

func TestFailedFirstConvergenceIsUnenforced(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		world := reconciletest.NewWorld()
		world.SetBeforeWrite(func(int) error { return reconciletest.ErrInjected })
		h := start(t, world, reconciletest.NewInventory(en0), filepath.Join(t.TempDir(), "s.json"), configV1)
		defer h.stop()

		h.wantState(daemon.StateUnenforced)
		if err := h.observe(obs("www.example.net", "203.0.113.1")); !errors.Is(err, daemon.ErrUnenforced) {
			t.Errorf("Observe = %v, want ErrUnenforced", err)
		}

		world.SetBeforeWrite(nil)
		heal()
		h.wantState(daemon.StateReady)
	})
}

func TestVoidingProblemAtStartIsUnenforced(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		world := reconciletest.NewWorld()
		world.SetProblems([]reconcile.Problem{unreferenced}, nil)
		h := start(t, world, reconciletest.NewInventory(en0), filepath.Join(t.TempDir(), "s.json"), configV1)
		defer h.stop()

		st := h.wantState(daemon.StateUnenforced)
		if !slices.Equal(st.Reasons, []string{unreferenced.Text}) {
			t.Errorf("reasons = %q, want the problem", st.Reasons)
		}
		if err := h.observe(obs("www.example.net", "203.0.113.1")); !errors.Is(err, daemon.ErrUnenforced) {
			t.Errorf("Observe = %v, want ErrUnenforced", err)
		}

		world.SetProblems(nil, nil)
		heal()
		h.wantState(daemon.StateReady)
		if err := h.observe(obs("www.example.net", "203.0.113.1")); err != nil {
			t.Errorf("Observe = %v, want ack", err)
		}
	})
}

func TestVoidingProblemAfterReadyStopsAcks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.world.SetProblems([]reconcile.Problem{unreferenced}, []reconcile.Problem{conflict})
		heal()

		st := h.wantState(daemon.StateUnenforced)
		if want := []string{unreferenced.Text, conflict.Text}; !slices.Equal(st.Reasons, want) {
			t.Errorf("reasons = %q, want %q", st.Reasons, want)
		}
		if err := h.observe(obs("www.example.net", "203.0.113.1")); !errors.Is(err, daemon.ErrUnenforced) {
			t.Errorf("Observe = %v, want ErrUnenforced", err)
		}
	})
}

func TestNonVoidingProblemDegradesAndAcks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.world.SetProblems(nil, []reconcile.Problem{conflict})
		heal()

		st := h.wantState(daemon.StateDegraded)
		if !slices.Equal(st.Reasons, []string{conflict.Text}) {
			t.Errorf("reasons = %q, want the conflict", st.Reasons)
		}
		if err := h.observe(obs("www.example.net", "203.0.113.1")); err != nil {
			t.Errorf("Observe in Degraded = %v, want ack", err)
		}
		if !h.hasEntry("web", host("203.0.113.1")) {
			t.Error("acked address is not in the table")
		}

		h.world.SetProblems(nil, nil)
		heal()
		if st := h.wantState(daemon.StateReady); len(st.Reasons) != 0 {
			t.Errorf("reasons in Ready = %q, want none", st.Reasons)
		}
	})
}

func TestResolverFailureDegradesAndAcks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		apex, err := policy.ParseDomain("example.com")
		if err != nil {
			t.Fatal(err)
		}
		h.world.RemoveResolverEntry(apex)
		h.failWrite(1) // the resolver write of the next pass
		heal()
		h.world.SetBeforeWrite(nil)

		st := h.wantState(daemon.StateDegraded)
		if len(st.Reasons) != 1 || !strings.Contains(st.Reasons[0], "resolver entry") {
			t.Errorf("reasons = %q, want the resolver error", st.Reasons)
		}
		if err := h.observe(obs("www.example.net", "203.0.113.1")); err != nil {
			t.Errorf("Observe = %v, want ack: the ruleset is installed", err)
		}
	})
}

func TestBackendFailureAfterReadyIsUnenforced(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.failWrites()
		h.world.FlushTable("web")
		heal()

		st := h.wantState(daemon.StateUnenforced)
		if len(st.Reasons) != 1 || !strings.Contains(st.Reasons[0], "convergence failed") {
			t.Errorf("reasons = %q, want the convergence error", st.Reasons)
		}
		h.world.SetBeforeWrite(nil)
		heal()
		h.wantState(daemon.StateReady)
	})
}

func TestShutdownKeepsEnforcement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		if err := h.observe(obs("www.example.net", "203.0.113.1")); err != nil {
			t.Fatal(err)
		}
		tables, ruleset, resolver := h.world.Tables(), h.world.Ruleset().ID(), h.world.ResolverEntries()
		writes := h.world.Writes()

		h.stop()

		if h.world.Writes() != writes {
			t.Errorf("shutdown wrote %d times, want none", h.world.Writes()-writes)
		}
		if h.world.Ruleset().ID() != ruleset || len(h.world.ResolverEntries()) != len(resolver) ||
			!slices.Equal(h.world.Tables()["web"], tables["web"]) {
			t.Error("shutdown changed the enforcement")
		}
	})
}

func TestRequestsAfterRunReturnFailWithErrStopped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		h.stop()

		if err := h.observe(obs("www.example.net", "203.0.113.1")); !errors.Is(err, daemon.ErrStopped) {
			t.Errorf("Observe = %v, want ErrStopped", err)
		}
		if err := h.d.Run(t.Context()); !errors.Is(err, daemon.ErrAlreadyRunning) {
			t.Errorf("second Run = %v, want ErrAlreadyRunning", err)
		}
	})
}

func TestStatusIsACopy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.world.SetProblems(nil, []reconcile.Problem{conflict})
		heal()

		st := h.status()
		st.Reasons[0] = "changed by the caller"

		if got := h.status().Reasons; !slices.Equal(got, []string{conflict.Text}) {
			t.Errorf("reasons = %q after a caller changed its copy", got)
		}
	})
}

// --- Reports ---

func TestObserveInReadyAcksAfterTableAndSnapshot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.wantState(daemon.StateReady)

		if err := h.observe(obs("www.example.net.", "203.0.113.1", "3fff::1")); err != nil {
			t.Fatalf("Observe = %v, want ack", err)
		}

		for _, p := range []netip.Prefix{host("203.0.113.1"), host("3fff::1")} {
			if !h.hasEntry("web", p) {
				t.Errorf("web table lacks %v", p)
			}
		}
		want := []netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("3fff::1")}
		if got := h.saved("web"); !slices.Equal(got, want) {
			t.Errorf("snapshot web = %v, want %v", got, want)
		}
	})
}

func TestObserveWritesTheFormThatTheBookStores(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()

		if err := h.observe(obs("www.example.net", "::ffff:203.0.113.1")); err != nil {
			t.Fatalf("Observe = %v, want ack", err)
		}

		if !h.hasEntry("web", host("203.0.113.1")) || h.hasEntry("web", host("::ffff:203.0.113.1")) {
			t.Errorf("web table = %v, want 203.0.113.1/32 and no mapped form", h.world.Tables()["web"])
		}
		if got := h.saved("web"); !slices.Equal(got, []netip.Addr{netip.MustParseAddr("203.0.113.1")}) {
			t.Errorf("snapshot web = %v, want the unmapped address", got)
		}
	})
}

func TestObserveUnmatchedNameIsAckedAndNotStored(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		writes := h.world.Writes()

		if err := h.observe(obs("www.example.org", "203.0.113.1")); err != nil {
			t.Fatalf("Observe = %v, want ack", err)
		}

		if st := h.status(); st.Addrs != 0 {
			t.Errorf("stored %d addresses, want 0", st.Addrs)
		}
		if h.world.Writes() != writes {
			t.Error("an unmatched report wrote to the platform")
		}
		for name, addrs := range readBook(t, bookPath(h.snapshot)) {
			if len(addrs) != 0 {
				t.Errorf("the book holds %v for %s, want nothing", addrs, name)
			}
		}
	})
}

func TestObserveMalformedNameIsRejected(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()

		err := h.observe(obs("www..example.com", "203.0.113.1"))

		if !errors.Is(err, matcher.ErrMalformedName) {
			t.Errorf("Observe = %v, want ErrMalformedName", err)
		}
		if st := h.status(); st.Addrs != 0 {
			t.Errorf("stored %d addresses, want 0", st.Addrs)
		}
	})
}

func TestObserveStoresForEveryMatchedPolicy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, header+`
[[policy]]
name = "site"
to = ["*.example.com"]
only_via = ["en0"]

[[policy]]
name = "cdn"
to = ["cdn.example.com"]
deny_via = ["@tunnel"]
`)
		defer h.stop()

		if err := h.observe(obs("cdn.example.com", "203.0.113.1")); err != nil {
			t.Fatalf("Observe = %v, want ack", err)
		}

		for _, name := range []policy.Name{"site", "cdn"} {
			if !h.hasEntry(name, host("203.0.113.1")) {
				t.Errorf("table %s lacks the address", name)
			}
			if got := h.saved(name); len(got) != 1 {
				t.Errorf("snapshot %s = %v, want the address", name, got)
			}
		}
	})
}

func TestObserveNotAckedWhenTableWriteFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.failWrites()

		if err := h.observe(obs("www.example.net", "203.0.113.1")); !errors.Is(err, reconciletest.ErrInjected) {
			t.Fatalf("Observe = %v, want ErrInjected", err)
		}
		// The commit comes after the table write, and an address is in
		// the book only after its commit.
		if got := h.saved("web"); len(got) != 0 {
			t.Errorf("book web = %v, want no save before the table write", got)
		}
		h.world.SetBeforeWrite(nil)
		heal()
		if got := h.saved("web"); len(got) != 0 {
			t.Errorf("book web = %v after a self-heal, want the address of the failed report not kept", got)
		}
	})
}

func TestObserveNotAckedWhenSaveFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var fail atomic.Bool
		h := launchHook(t, newSpec(t, configV1), func(d *daemon.Daemon) { d.SetBookFault(&fail) })
		defer h.stop()
		h.wantState(daemon.StateReady)
		fail.Store(true)

		err := h.observe(obs("www.example.net", "203.0.113.1"))

		if !errors.Is(err, daemon.ErrInjectedBook) || !strings.Contains(err.Error(), "saving snapshot") {
			t.Errorf("Observe = %v, want the save error", err)
		}
		if got := h.saved("web"); len(got) != 0 {
			t.Errorf("book web = %v, want nothing after a failed commit", got)
		}
	})
}

func TestAnchorFlushStopsAcksAndConvergesAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.world.FlushAll()

		if err := h.observe(obs("www.example.net", "203.0.113.1")); !errors.Is(err, daemon.ErrUnenforced) {
			t.Fatalf("Observe after an external flush = %v, want ErrUnenforced", err)
		}
		synctest.Wait() // no time passes: this is not the self-heal

		h.wantState(daemon.StateReady)
		if !h.references("web") || !h.hasEntry("web", host("203.0.113.1")) {
			t.Errorf("after the triggered convergence: referenced %v, tables %v", h.world.Referenced(), h.world.Tables())
		}
		if err := h.observe(obs("www.example.net", "203.0.113.2")); err != nil {
			t.Errorf("Observe = %v, want ack", err)
		}
	})
}

func TestForeignRulesetStopsAcksAndConvergesAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		installed := h.world.Ruleset().ID()
		h.world.ExternalLoad([]byte("pass all\n")) // another tool writes the anchor

		if err := h.observe(obs("www.example.net", "203.0.113.1")); !errors.Is(err, daemon.ErrUnenforced) {
			t.Fatalf("Observe with a foreign ruleset loaded = %v, want ErrUnenforced", err)
		}
		synctest.Wait() // no time passes: this is not the self-heal

		if h.world.Ruleset().ID() != installed {
			t.Error("the daemon did not load its ruleset again after the report")
		}
		h.wantState(daemon.StateReady)
		if err := h.observe(obs("www.example.net", "203.0.113.2")); err != nil {
			t.Errorf("Observe after the repair = %v, want ack", err)
		}
	})
}

// A report without an address asks only for the protected flag. It writes
// nothing, but its protected ack still needs the loaded ruleset check. A
// name without a policy needs no check.
func TestObserveWithoutAddressAsksOnlyForTheFlag(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.wantState(daemon.StateReady)
		writes := h.world.Writes()

		for name, want := range map[string]bool{"www.example.net": true, "www.example.org": false} {
			ack, err := h.d.Observe(t.Context(), obs(name))
			if err != nil || ack.Protected != want {
				t.Errorf("Observe(%s) without an address = %+v, %v; want Protected %v", name, ack, err, want)
			}
		}
		synctest.Wait()
		if h.world.Writes() != writes {
			t.Error("a report without an address wrote to the platform")
		}

		h.world.ExternalLoad([]byte("pass all\n"))
		ack, err := h.d.Observe(t.Context(), obs("www.example.org"))
		if err != nil || ack.Protected {
			t.Errorf("Observe of an unmatched name with a foreign ruleset = %+v, %v; want an unprotected ack", ack, err)
		}
	})
}

// A report without an address for a protected name gets the loaded
// ruleset check as a report with addresses does.
func TestForeignRulesetStopsAckOfReportWithoutAddress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.wantState(daemon.StateReady)
		installed := h.world.Ruleset().ID()
		h.world.ExternalLoad([]byte("pass all\n"))

		ack, err := h.d.Observe(t.Context(), obs("www.example.net"))
		if !errors.Is(err, daemon.ErrUnenforced) || ack.Protected {
			t.Fatalf("Observe without an address, foreign ruleset = %+v, %v; want an unprotected ack and ErrUnenforced", ack, err)
		}
		synctest.Wait() // no time passes: this is not the self-heal

		if h.world.Ruleset().ID() != installed {
			t.Error("the daemon did not load its ruleset again after the report")
		}
		h.wantState(daemon.StateReady)
		if ack, err := h.d.Observe(t.Context(), obs("www.example.net")); err != nil || !ack.Protected {
			t.Errorf("Observe after the repair = %+v, %v; want a protected ack", ack, err)
		}
	})
}

// A report without an address gets the phase checks.
func TestObserveWithoutAddressNeedsAnEnforcingPhase(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.world.SetProblems([]reconcile.Problem{unreferenced}, nil)
		heal()
		h.wantState(daemon.StateUnenforced)
		if _, err := h.d.Observe(t.Context(), obs("www.example.net")); !errors.Is(err, daemon.ErrUnenforced) {
			t.Errorf("Observe without an address while unenforced = %v, want ErrUnenforced", err)
		}
	})
}

func TestForeignRulesetIsUnenforcedWhileRepairFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		world := reconciletest.NewWorld()
		var fail atomic.Bool
		h := startOn(t, world, loadFails{world.Backend(), &fail}, reconciletest.NewInventory(en0),
			filepath.Join(t.TempDir(), "s.json"), configV1)
		defer h.stop()
		fail.Store(true) // the repair cannot load the ruleset
		h.world.ExternalLoad([]byte("pass all\n"))

		if err := h.observe(obs("www.example.net", "203.0.113.1")); !errors.Is(err, daemon.ErrUnenforced) {
			t.Fatalf("Observe = %v, want ErrUnenforced", err)
		}
		synctest.Wait()

		h.wantState(daemon.StateUnenforced)
		if err := h.observe(obs("www.example.net", "203.0.113.2")); !errors.Is(err, daemon.ErrUnenforced) {
			t.Errorf("Observe = %v, want ErrUnenforced", err)
		}
	})
}

// TestVoidingProblemIsNoticedWithinSelfHealInterval pins the accepted
// window: the daemon learns of a problem that voids enforcement and keeps
// the loaded ruleset only at a convergence. A problem that appears just
// after one is noticed at the next self-heal, no later than
// SelfHealInterval after it appears, and from then on no report is
// acknowledged.
func TestVoidingProblemIsNoticedWithinSelfHealInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		heal() // a self-heal pass has just run
		time.Sleep(time.Millisecond)
		h.world.SetProblems([]reconcile.Problem{unreferenced}, nil)

		time.Sleep(daemon.SelfHealInterval)
		synctest.Wait()

		h.wantState(daemon.StateUnenforced)
		if err := h.observe(obs("www.example.net", "203.0.113.1")); !errors.Is(err, daemon.ErrUnenforced) {
			t.Errorf("Observe = %v, want ErrUnenforced", err)
		}
	})
}

// A disabled firewall has no window: the Backend reports no loaded
// ruleset, so the next protected report gets no ack. The convergence
// that the report starts enables the firewall again, and the acks come
// back with it, with no self-heal in between.
func TestDisabledFirewallStopsTheNextAck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.wantState(daemon.StateReady)
		installed := h.world.Ruleset().ID()
		heal() // a self-heal pass has just run
		h.world.DisableFirewall()

		if err := h.observe(obs("www.example.net", "203.0.113.1")); !errors.Is(err, daemon.ErrUnenforced) {
			t.Fatalf("Observe with the firewall disabled = %v, want ErrUnenforced", err)
		}
		synctest.Wait() // no time passes: this is not the self-heal

		if id, err := h.world.Backend().LoadedID(t.Context()); err != nil || id != installed {
			t.Errorf("LoadedID after the convergence = %q, %v; want the installed ruleset %q", id, err, installed)
		}
		h.wantState(daemon.StateReady)
		if err := h.observe(obs("www.example.net", "203.0.113.2")); err != nil {
			t.Errorf("Observe after the enabling convergence = %v, want ack", err)
		}
		for _, a := range []string{"203.0.113.1", "203.0.113.2"} {
			if !h.hasEntry("web", host(a)) {
				t.Errorf("address %s is not in the table", a)
			}
		}
	})
}

func TestObserveReturnsContextErrorWhileLoopIsBusy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		release := make(chan struct{})
		h.world.SetBeforeWrite(func(int) error {
			<-release
			return nil
		})
		var wg sync.WaitGroup
		wg.Go(func() {
			if err := h.d.Reconfigure(t.Context(), parse(t, configV2)); err != nil {
				t.Errorf("Reconfigure = %v", err)
			}
		})
		synctest.Wait() // the loop is now inside the Reconfigure write

		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		_, err := h.d.Observe(ctx, obs("www.example.net", "203.0.113.1"))

		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Observe = %v, want DeadlineExceeded", err)
		}
		close(release)
		wg.Wait()
		if st := h.status(); st.Addrs != 0 {
			t.Errorf("a report that the loop never took stored %d addresses", st.Addrs)
		}
	})
}

// --- Configuration ---

func TestReconfigureAddsAndRemovesPolicy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		for _, o := range []ipc.Observation{obs("www.example.net", "203.0.113.1"), obs("x.ads.example", "3fff::1")} {
			if err := h.observe(o); err != nil {
				t.Fatal(err)
			}
		}

		if err := h.d.Reconfigure(t.Context(), parse(t, configV2)); err != nil {
			t.Fatalf("Reconfigure: %v", err)
		}

		tables := h.world.Tables()
		if _, ok := tables["ads"]; ok {
			t.Error("table of the removed policy still exists")
		}
		if !slices.Equal(tables["mail"], []netip.Prefix{netip.MustParsePrefix("203.0.113.0/28")}) {
			t.Errorf("mail table = %v, want its CIDR", tables["mail"])
		}
		if !h.hasEntry("web", host("203.0.113.1")) {
			t.Error("web lost a learned address in the change")
		}
		if got := h.world.Referenced(); !slices.Equal(got, []policy.Name{"web", "mail"}) {
			t.Errorf("referenced = %v, want [web mail]", got)
		}
		st := h.wantState(daemon.StateReady)
		if st.Policies != 2 || st.Addrs != 1 || st.RetainRestart {
			t.Errorf("status = %+v, want 2 policies, 1 address, no restart", st)
		}
	})
}

func TestReconfigurePrunesRemovedPolicyAfterInstall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		if err := h.observe(obs("x.ads.example", "3fff::1")); err != nil {
			t.Fatal(err)
		}
		if err := h.d.Reconfigure(t.Context(), parse(t, configV2)); err != nil {
			t.Fatalf("Reconfigure: %v", err)
		}

		// A new address makes the daemon save the book.
		if err := h.observe(obs("www.example.net", "203.0.113.2")); err != nil {
			t.Fatal(err)
		}

		if got := h.saved("ads"); len(got) != 0 {
			t.Errorf("snapshot keeps %v of the removed policy", got)
		}
	})
}

func TestReportForRemovedPolicyIsAckedAndNotStored(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		if err := h.d.Reconfigure(t.Context(), parse(t, configV2)); err != nil {
			t.Fatalf("Reconfigure: %v", err)
		}

		if err := h.observe(obs("y.ads.example", "3fff::2")); err != nil {
			t.Fatalf("Observe = %v, want ack", err)
		}
		if st := h.status(); st.Addrs != 0 {
			t.Errorf("stored %d addresses, want 0", st.Addrs)
		}
	})
}

// TestNoAckUntilNewConfigurationIsInstalled fails one write of the
// change to configV2. The old ruleset stays loaded: it has no rule for
// mail and the old constraint for web. No report is acknowledged until a
// convergence installs configV2.
func TestNoAckUntilNewConfigurationIsInstalled(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail int // the failing write of the change
	}{{"mail table fill fails", 1}, {"load fails", 2}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := newHarness(t, configV1)
				defer h.stop()
				h.failWrite(tc.fail)

				if err := h.d.Reconfigure(t.Context(), parse(t, configV2)); !errors.Is(err, reconciletest.ErrInjected) {
					t.Fatalf("Reconfigure = %v, want ErrInjected", err)
				}
				h.wantState(daemon.StateUnenforced)
				for _, o := range []ipc.Observation{obs("mail.example.org", "192.0.2.25"), obs("www.example.net", "203.0.113.1")} {
					if err := h.observe(o); !errors.Is(err, daemon.ErrUnenforced) {
						t.Errorf("Observe(%s) = %v, want ErrUnenforced", o.QName, err)
					}
				}

				heal()
				h.wantState(daemon.StateReady)
				if err := h.observe(obs("mail.example.org", "192.0.2.25")); err != nil || !h.references("mail") {
					t.Errorf("after install: Observe = %v, referenced %v", err, h.world.Referenced())
				}
			})
		})
	}
}

func TestPermanentLoadFailureNeverAcks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		world := reconciletest.NewWorld()
		var fail atomic.Bool
		h := startOn(t, world, loadFails{world.Backend(), &fail}, reconciletest.NewInventory(en0),
			filepath.Join(t.TempDir(), "s.json"), configV1)
		defer h.stop()
		fail.Store(true)
		_ = h.d.Reconfigure(t.Context(), parse(t, configV2)) //nolint:errcheck // the load is rejected, so it fails by design

		for range 3 {
			heal()
			if err := h.observe(obs("mail.example.org", "192.0.2.25")); !errors.Is(err, daemon.ErrUnenforced) {
				t.Errorf("Observe = %v, want ErrUnenforced while the ruleset cannot load", err)
			}
		}
	})
}

// TestRevertAfterFailedRemovalKeepsAddresses removes ads with a load
// that fails, then reverts. The ads rule was loaded throughout, so its
// acknowledged addresses must stay blocked.
func TestRevertAfterFailedRemovalKeepsAddresses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		world := reconciletest.NewWorld()
		var fail atomic.Bool
		h := startOn(t, world, loadFails{world.Backend(), &fail}, reconciletest.NewInventory(en0),
			filepath.Join(t.TempDir(), "s.json"), configV1)
		defer h.stop()
		if err := h.observe(obs("x.ads.example", "3fff::1")); err != nil {
			t.Fatal(err)
		}
		fail.Store(true)
		_ = h.d.Reconfigure(t.Context(), parse(t, configV2)) //nolint:errcheck // it fails by design: ads stays loaded
		fail.Store(false)

		if err := h.d.Reconfigure(t.Context(), parse(t, configV1)); err != nil {
			t.Fatalf("revert: %v", err)
		}

		if !h.hasEntry("ads", host("3fff::1")) {
			t.Errorf("ads table = %v, want the acknowledged address kept", h.world.Tables()["ads"])
		}
		if got := h.saved("ads"); len(got) != 1 {
			t.Errorf("snapshot ads = %v, want the address", got)
		}
	})
}

func TestReconfigureWaitsForResultAfterLoopTookIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		release := make(chan struct{})
		h.world.SetBeforeWrite(func(int) error {
			<-release
			return nil
		})
		var wg sync.WaitGroup
		wg.Go(func() {
			time.Sleep(2 * time.Second) // past the caller's deadline
			close(release)
		})

		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		err := h.d.Reconfigure(ctx, parse(t, configV2))
		wg.Wait()

		if err != nil {
			t.Errorf("Reconfigure = %v, want the result of the convergence (nil)", err)
		}
		if !h.references("mail") {
			t.Error("configuration not applied")
		}
	})
}

func TestReconfigureRetainAppliesAtRestartOnly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		if err := h.observe(obs("www.example.net", "203.0.113.1")); err != nil {
			t.Fatal(err)
		}
		shorter := parse(t, configV1)
		shorter.AddrBook.Retain = 10 * time.Minute

		if err := h.d.Reconfigure(t.Context(), shorter); err != nil {
			t.Fatalf("Reconfigure: %v", err)
		}
		if st := h.status(); !st.RetainRestart {
			t.Error("status does not report that retain needs a restart")
		}
		time.Sleep(30 * time.Minute)
		synctest.Wait()
		if !h.hasEntry("web", host("203.0.113.1")) {
			t.Error("a shorter retain removed an entry early")
		}
	})
}

// --- Timers ---

func TestSelfHealRepairsFlushedTable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		if err := h.observe(obs("www.example.net", "203.0.113.1")); err != nil {
			t.Fatal(err)
		}
		h.world.FlushTable("web")

		time.Sleep(daemon.SelfHealInterval - time.Millisecond)
		synctest.Wait()
		if h.hasEntry("web", host("203.0.113.1")) {
			t.Fatal("repaired before the self-heal interval")
		}
		time.Sleep(time.Millisecond)
		synctest.Wait()

		want := []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32"), netip.MustParsePrefix("198.51.100.0/24"), host("203.0.113.1")}
		slices.SortFunc(want, netip.Prefix.Compare)
		if got := h.world.Tables()["web"]; !slices.Equal(got, want) {
			t.Errorf("web table = %v, want %v", got, want)
		}
	})
}

func TestInterfaceChangesShareOneDebouncedRecompile(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		before, writes := h.world.Ruleset().ID(), h.world.Writes()

		half := daemon.InterfaceDebounce / 2
		h.inv.Set(en0, utun0)
		time.Sleep(half)
		synctest.Wait()
		h.inv.Set(utun0)
		synctest.Wait()
		h.inv.Set(en0, utun0)
		synctest.Wait()
		if h.world.Ruleset().ID() != before {
			t.Fatal("recompiled before the debounce ended")
		}
		time.Sleep(daemon.InterfaceDebounce - half)
		synctest.Wait()

		want, err := reconciletest.Compiler{}.Compile(parse(t, configV1).Policies, []reconcile.Interface{en0, utun0}, reconcile.Accounts{})
		if err != nil {
			t.Fatal(err)
		}
		if h.world.Ruleset().ID() != want.ID() {
			t.Error("the loaded ruleset is not compiled from the last interface snapshot")
		}
		if n := h.world.Writes() - writes; n != 1 {
			t.Errorf("%d writes, want one load", n)
		}
	})
}

func TestExpiryTimerRemovesAddressAfterRetain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		if err := h.observe(obs("www.example.net", "203.0.113.1")); err != nil {
			t.Fatal(err)
		}

		time.Sleep(time.Hour) // retain; the entry is kept up to this instant
		synctest.Wait()
		if !h.hasEntry("web", host("203.0.113.1")) {
			t.Fatal("address removed at its expiry instant, want removal after it")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()

		if h.hasEntry("web", host("203.0.113.1")) {
			t.Error("expired address still in the table")
		}
		if st := h.status(); st.Addrs != 0 {
			t.Errorf("status addrs = %d, want 0", st.Addrs)
		}
	})
}

// When the first Load at start fails, the tables can hold the snapshot
// addresses with no loaded rule that refers to them. The state says so,
// no report is acknowledged, and the next convergence installs the
// ruleset.
func TestFirstLoadFailureIsUnenforcedUntilRepaired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := filepath.Join(t.TempDir(), "addrbook.json")
		writeSnapshot(t, snapshot, map[policy.Name]string{"web": "203.0.113.1"})
		world := reconciletest.NewWorld()
		var fail atomic.Bool
		fail.Store(true)
		h := startOn(t, world, loadFails{world.Backend(), &fail}, reconciletest.NewInventory(en0), snapshot, configV1)
		defer h.stop()

		st := h.wantState(daemon.StateUnenforced)
		if !slices.ContainsFunc(st.Reasons, func(r string) bool { return strings.Contains(r, "loading ruleset") }) {
			t.Errorf("reasons = %q, want the load error", st.Reasons)
		}
		if !h.hasEntry("web", host("203.0.113.1")) || h.references("web") {
			t.Fatalf("precondition: want the entry in a table that no loaded rule refers to; tables %v, referenced %v",
				h.world.Tables(), h.world.Referenced())
		}
		if err := h.observe(obs("www.example.net", "203.0.113.2")); !errors.Is(err, daemon.ErrUnenforced) {
			t.Errorf("Observe = %v, want ErrUnenforced", err)
		}

		fail.Store(false)
		heal()

		h.wantState(daemon.StateReady)
		if !h.references("web") || !h.hasEntry("web", host("203.0.113.1")) {
			t.Errorf("after repair: tables %v, referenced %v", h.world.Tables(), h.world.Referenced())
		}
		if err := h.observe(obs("www.example.net", "203.0.113.2")); err != nil {
			t.Errorf("Observe after repair = %v, want an ack", err)
		}
	})
}

// loadedIDFails is a Backend whose LoadedID fails while fail is set.
type loadedIDFails struct {
	*reconciletest.Backend
	fail *atomic.Bool
}

func (b loadedIDFails) LoadedID(ctx context.Context) (string, error) {
	if b.fail.Load() {
		return "", reconciletest.ErrInjected
	}
	return b.Backend.LoadedID(ctx)
}

// When the daemon cannot read the loaded ruleset, a name that matches a
// policy gets no protected ack, with or without an address. A name that
// matches no policy needs no check.
func TestUnreadableLoadedRulesetGivesNoProtectedAck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		world := reconciletest.NewWorld()
		var fail atomic.Bool
		h := startOn(t, world, loadedIDFails{world.Backend(), &fail}, reconciletest.NewInventory(en0),
			filepath.Join(t.TempDir(), "s.json"), configV1)
		defer h.stop()
		h.wantState(daemon.StateReady)
		fail.Store(true)

		for name, o := range map[string]ipc.Observation{
			"matched, no address": obs("www.example.net"),
			"matched, address":    obs("www.example.net", "203.0.113.1"),
		} {
			ack, err := h.d.Observe(t.Context(), o)
			if err == nil || ack.Protected {
				t.Errorf("%s = %+v, %v; want an error and no protected ack", name, ack, err)
			}
		}
		ack, err := h.d.Observe(t.Context(), obs("www.example.org"))
		if err != nil || ack != (ipc.Ack{}) {
			t.Errorf("unmatched = %+v, %v; want ipc.Ack{} and nil", ack, err)
		}
	})
}
