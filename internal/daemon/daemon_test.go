package daemon_test

import (
	"context"
	"errors"
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

	"github.com/Nagato-Yuzuru/ifbound/internal/addrbook"
	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/matcher"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

func writeSnapshot(t *testing.T, path string, entries map[policy.Name]string) {
	t.Helper()
	b := addrbook.New(time.Hour, time.Now)
	for name, addr := range entries {
		if _, err := b.Observe(name, []netip.Addr{netip.MustParseAddr(addr)}, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Save(path); err != nil {
		t.Fatal(err)
	}
}

// --- Lifecycle ---

func TestStartLoadsSnapshotAndInstallsEnforcement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := filepath.Join(t.TempDir(), "addrbook.json")
		writeSnapshot(t, snapshot, map[policy.Name]string{"web": "203.0.113.1", "gone": "203.0.113.9"})

		h := start(t, reconciletest.NewWorld(), reconciletest.NewInventory(en0), snapshot, parse(t, configV1))
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
		h := start(t, reconciletest.NewWorld(), reconciletest.NewInventory(en0), snapshot, parse(t, configV1))
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

func TestSnapshotLoadErrorKeepsStartingUntilRepaired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := filepath.Join(t.TempDir(), "addrbook.json")
		if err := os.WriteFile(snapshot, []byte("not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		h := start(t, reconciletest.NewWorld(), reconciletest.NewInventory(en0), snapshot, parse(t, configV1))
		defer h.stop()

		st := h.wantState(daemon.StateStarting)
		if len(st.Reasons) != 1 || !strings.Contains(st.Reasons[0], "loading snapshot") {
			t.Errorf("reasons = %q, want the snapshot error", st.Reasons)
		}
		if err := h.observe(obs("www.example.net", "203.0.113.1")); !errors.Is(err, daemon.ErrNotReady) {
			t.Errorf("Observe = %v, want ErrNotReady", err)
		}
		heal()
		h.wantState(daemon.StateStarting)
		if n := h.world.Writes(); n != 0 {
			t.Errorf("%d writes without a snapshot, want none: an empty book would unblock addresses", n)
		}

		if err := os.Remove(snapshot); err != nil {
			t.Fatal(err)
		}
		heal()
		h.wantState(daemon.StateReady)
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
		h := start(t, world, reconciletest.NewInventory(en0), filepath.Join(t.TempDir(), "addrbook.json"), parse(t, configV1))
		defer h.stop()

		h.wantState(daemon.StateReady)
		if !h.hasEntry("web", host("203.0.113.1")) || !h.hasEntry("ads", host("3fff::1")) {
			t.Errorf("tables = %v, want the kernel addresses kept", h.world.Tables())
		}
		if got := h.saved("web"); !slices.Equal(got, []netip.Addr{netip.MustParseAddr("203.0.113.1")}) {
			t.Errorf("snapshot web = %v, want the adopted address only (not the IP destination)", got)
		}
		if got := h.saved("gone"); len(got) != 0 {
			t.Errorf("adopted %v from a table outside the configuration", got)
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
		world := reconciletest.NewWorld()
		if err := world.Backend().AddEntries(t.Context(), "web", []netip.Prefix{host("203.0.113.1")}); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(dir, 0o500); err != nil { // the snapshot is missing and cannot be written
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // let TempDir remove it
		h := start(t, world, reconciletest.NewInventory(en0), filepath.Join(dir, "s.json"), parse(t, configV1))
		defer h.stop()

		st := h.wantState(daemon.StateStarting)
		if len(st.Reasons) != 1 || !strings.Contains(st.Reasons[0], "saving adopted entries") {
			t.Errorf("reasons = %q, want the save error", st.Reasons)
		}
		if n := h.world.Writes(); n != 1 {
			t.Errorf("%d writes, want only the setup write", n)
		}

		// A later attempt starts from a fresh book and completes.
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		heal()
		h.wantState(daemon.StateReady)
		if got := h.saved("web"); len(got) != 1 {
			t.Errorf("snapshot web = %v, want the adopted address", got)
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

		h := start(t, world, reconciletest.NewInventory(en0), snapshot, parse(t, configV1))
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
		h := start(t, world, reconciletest.NewInventory(en0), filepath.Join(t.TempDir(), "s.json"), parse(t, configV1))
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
		world.SetProblems([]reconcile.Problem{pfDisabled}, nil)
		h := start(t, world, reconciletest.NewInventory(en0), filepath.Join(t.TempDir(), "s.json"), parse(t, configV1))
		defer h.stop()

		st := h.wantState(daemon.StateUnenforced)
		if !slices.Equal(st.Reasons, []string{pfDisabled.Text}) {
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
		h.world.SetProblems([]reconcile.Problem{pfDisabled}, []reconcile.Problem{conflict})
		heal()

		st := h.wantState(daemon.StateUnenforced)
		if want := []string{pfDisabled.Text, conflict.Text}; !slices.Equal(st.Reasons, want) {
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
		if _, err := os.Stat(h.snapshot); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("snapshot stat = %v, want no snapshot", err)
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
		if _, err := os.Stat(h.snapshot); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("snapshot stat = %v, want no save before the table write", err)
		}

		// The book kept the address, so the self-heal installs it.
		h.world.SetBeforeWrite(nil)
		heal()
		if !h.hasEntry("web", host("203.0.113.1")) {
			t.Error("self-heal did not install the address of the failed report")
		}
	})
}

func TestObserveNotAckedWhenSaveFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		h := start(t, reconciletest.NewWorld(), reconciletest.NewInventory(en0), filepath.Join(dir, "s.json"), parse(t, configV1))
		defer h.stop()
		h.wantState(daemon.StateReady)
		if err := os.Remove(dir); err != nil {
			t.Fatal(err)
		}

		err := h.observe(obs("www.example.net", "203.0.113.1"))

		if err == nil || !strings.Contains(err.Error(), "saving snapshot") {
			t.Errorf("Observe = %v, want a save error", err)
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

func TestForeignRulesetIsUnenforcedWhileRepairFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		world := reconciletest.NewWorld()
		var fail atomic.Bool
		h := startOn(t, world, loadFails{world.Backend(), &fail}, reconciletest.NewInventory(en0),
			filepath.Join(t.TempDir(), "s.json"), parse(t, configV1))
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
// window: the daemon learns of a problem that voids enforcement only at a
// convergence. A problem that appears just after one is noticed at the
// next self-heal, no later than SelfHealInterval after it appears, and
// from then on no report is acknowledged.
func TestVoidingProblemIsNoticedWithinSelfHealInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		heal() // a self-heal pass has just run
		time.Sleep(time.Millisecond)
		h.world.SetProblems([]reconcile.Problem{pfDisabled}, nil)

		time.Sleep(daemon.SelfHealInterval)
		synctest.Wait()

		h.wantState(daemon.StateUnenforced)
		if err := h.observe(obs("www.example.net", "203.0.113.1")); !errors.Is(err, daemon.ErrUnenforced) {
			t.Errorf("Observe = %v, want ErrUnenforced", err)
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
		wg.Go(func() { _ = h.d.Reconfigure(t.Context(), parse(t, configV2)) })
		synctest.Wait() // the loop is now inside the Reconfigure write

		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		err := h.d.Observe(ctx, obs("www.example.net", "203.0.113.1"))

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
			filepath.Join(t.TempDir(), "s.json"), parse(t, configV1))
		defer h.stop()
		fail.Store(true)
		_ = h.d.Reconfigure(t.Context(), parse(t, configV2)) // fails: the load is rejected

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
			filepath.Join(t.TempDir(), "s.json"), parse(t, configV1))
		defer h.stop()
		if err := h.observe(obs("x.ads.example", "3fff::1")); err != nil {
			t.Fatal(err)
		}
		fail.Store(true)
		_ = h.d.Reconfigure(t.Context(), parse(t, configV2)) // fails: ads stays loaded
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
