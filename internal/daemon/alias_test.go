package daemon_test

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// The tests of the probe rule. oracle_alias_spec_test.go holds the
// acceptance checks of the ticket.

const edge = "edge.cdn.test"

// withAliases adds aliases with a TTL of one minute to o.
func withAliases(o ipc.Observation, names ...string) ipc.Observation {
	for _, n := range names {
		o.Aliases = append(o.Aliases, ipc.Alias{Name: n, TTL: time.Minute})
	}
	return o
}

// startDelayed starts a daemon on configV1 whose resolver entries apply
// only at SettleResolver, as on macOS.
func startDelayed(t *testing.T) *harness {
	t.Helper()
	world := reconciletest.NewWorld()
	world.SetResolverDelay(true)
	return start(t, world, reconciletest.NewInventory(en0), filepath.Join(t.TempDir(), "addrbook.json"), parse(t, configV1))
}

func (h *harness) wantProbes(alias string, n int) {
	h.t.Helper()
	if got := h.sys.probes(alias); len(got) != n {
		h.t.Errorf("probes of %s = %q, want %d", alias, got, n)
	}
}

var aliasReport = withAliases(obs("www.example.net", "203.0.113.1"), edge)

func TestNewAliasIsAckedAfterAProbeProvesItsEntry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1) // the system applies each entry at once
		defer h.stop()

		if err := h.observe(aliasReport); err != nil {
			t.Fatalf("Observe = %v, want an ack", err)
		}

		probes := h.sys.probes(edge)
		if len(probes) != 1 {
			t.Fatalf("probes of %s = %q, want 1", edge, probes)
		}
		if !strings.HasPrefix(probes[0], ipc.ProbePrefix) {
			t.Errorf("probe name %q does not start with %q", probes[0], ipc.ProbePrefix)
		}
		if !h.sys.routed(edge) {
			t.Errorf("acked, but no applied resolver entry covers %s: %v", edge, h.world.AppliedResolverEntries())
		}
	})
}

func TestProvenEntryNeedsNoProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()

		for i := range 3 {
			if err := h.observe(aliasReport); err != nil {
				t.Fatalf("report %d: Observe = %v, want an ack", i, err)
			}
		}

		h.wantProbes(edge, 1)
	})
}

func TestProbeRepeatsUntilTheEntryApplies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := startDelayed(t)
		defer h.stop()
		begin := time.Now()
		done := make(chan error, 1)
		go func() { done <- h.observe(aliasReport) }()

		time.Sleep(4*daemon.ProbeInterval + time.Millisecond)
		h.world.SettleResolver()

		if err := <-done; err != nil {
			t.Fatalf("Observe = %v, want an ack after the entry applies", err)
		}
		if got, want := time.Since(begin), 5*daemon.ProbeInterval; got != want {
			t.Errorf("ack after %v, want %v: the probe repeats every %v", got, want, daemon.ProbeInterval)
		}
		probes := h.sys.probes(edge)
		if len(probes) != 6 {
			t.Errorf("probes = %q, want 6", probes)
		}
		if uniq := slices.Compact(slices.Sorted(slices.Values(probes))); len(uniq) != len(probes) {
			t.Errorf("probes = %q, want a new name each time", probes)
		}
	})
}

func TestEntryThatNeverAppliesIsNotAcked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := startDelayed(t)
		defer h.stop()
		ctx, cancel := context.WithTimeout(t.Context(), ipc.DefaultTimeout)
		defer cancel()
		begin := time.Now()

		err := h.d.Observe(ctx, aliasReport)

		if !errors.Is(err, daemon.ErrAliasProbe) || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Observe = %v, want ErrAliasProbe without the context error in the chain", err)
		}
		if got, want := time.Since(begin), ipc.DefaultTimeout-daemon.AckReserve; got != want {
			t.Errorf("the probe gave up after %v, want %v", got, want)
		}
	})
}

func TestProofIsForgottenWhenTheEntryIsRewritten(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		if err := h.observe(aliasReport); err != nil {
			t.Fatal(err)
		}
		d, err := policy.ParseDomain(edge)
		if err != nil {
			t.Fatal(err)
		}

		h.world.RemoveResolverEntry(d)
		heal() // the convergence writes the entry again
		if err := h.observe(aliasReport); err != nil {
			t.Fatalf("Observe after the rewrite = %v, want an ack", err)
		}

		h.wantProbes(edge, 2)
	})
}

// otherServer edits the entry of edge to send its queries to another
// server, as a person or a tool can do outside ifbound. The SysResolver
// still reads the entry as one of ifbound. It is not a write of the
// daemon.
func otherServer(ctx context.Context, t *testing.T, w *reconciletest.World) {
	t.Helper()
	d, err := policy.ParseDomain(edge)
	if err != nil {
		t.Fatal(err)
	}
	e := reconcile.ResolverEntry{Domain: d, Server: netip.MustParseAddrPort("192.0.2.53:53")}
	if err := w.Resolver().Write(ctx, e); err != nil {
		t.Fatal(err)
	}
}

func TestEntryWithAnotherServerIsNotProven(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		if err := h.observe(aliasReport); err != nil {
			t.Fatal(err)
		}

		otherServer(t.Context(), t, h.world)
		if err := h.observe(aliasReport); err != nil {
			t.Fatalf("Observe after the edit = %v, want an ack after a rewrite and a new probe", err)
		}

		h.wantProbes(edge, 2)
		if !h.sys.routed(edge) {
			t.Errorf("acked, but the entry of %s does not send to ifbound-dns: %v", edge, h.world.AppliedResolverEntries())
		}
	})
}

func TestEntryWithAnotherServerIsNotAckedWhileTheRewriteFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		world := reconciletest.NewWorld()
		var fail atomic.Bool
		h := startWith(t, world, world.Backend(), writeFails{Resolver: world.Resolver(), fail: &fail}, reconciletest.NewInventory(en0),
			filepath.Join(t.TempDir(), "addrbook.json"), parse(t, configV1), newSysNet(world, parse(t, configV1).DNS.Listen))
		defer h.stop()
		if err := h.observe(aliasReport); err != nil {
			t.Fatal(err)
		}

		otherServer(t.Context(), t, world)
		fail.Store(true)

		if err := h.observe(aliasReport); !errors.Is(err, daemon.ErrAliasEntry) {
			t.Errorf("Observe = %v, want ErrAliasEntry: the proof of the old entry must not count", err)
		}
	})
}

func TestEntryWithAnotherServerDuringTheProbeIsNotAcked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.sys.setHook(func(ctx context.Context, name string) error {
			h.d.ProbeSeen(name) // the probe arrives
			otherServer(ctx, t, h.world)
			return errors.New("answered")
		})

		if err := h.observe(aliasReport); !errors.Is(err, daemon.ErrAliasEntry) {
			t.Errorf("Observe = %v, want ErrAliasEntry: at the ack the entry sends to another server", err)
		}
	})
}

// Owner decision: a write of the entry by another process counts as a
// rewrite, also with the same server. Here the new entry also applies
// before the daemon reads again, so only the Version shows the write.
func TestProofIsForgottenWhenAnotherProcessRewritesTheEntry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := startDelayed(t)
		defer h.stop()
		done := make(chan error, 1)
		go func() { done <- h.observe(aliasReport) }()
		synctest.Wait()
		h.world.SettleResolver()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if err := h.observe(aliasReport); err != nil {
			t.Fatal(err)
		}
		probes := len(h.sys.probes(edge))

		d, err := policy.ParseDomain(edge)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.world.Resolver().Write(t.Context(), reconcile.ResolverEntry{Domain: d, Server: parse(t, configV1).DNS.Listen}); err != nil {
			t.Fatal(err)
		}
		h.world.SettleResolver()
		if err := h.observe(aliasReport); err != nil {
			t.Fatalf("Observe after the rewrite = %v, want an ack after a new probe", err)
		}

		h.wantProbes(edge, probes+1)
	})
}

// settling is a SysResolver that can report every entry as not active,
// as a platform does during its settle time, and that can hide the
// versions, as a platform without them does.
type settling struct {
	*reconciletest.Resolver
	inactive  *atomic.Bool
	noVersion bool
}

func (r settling) Read(ctx context.Context) (reconcile.ResolverState, error) {
	st, err := r.Resolver.Read(ctx)
	for i := range st.Entries {
		if r.inactive.Load() {
			st.Entries[i].Active = false
		}
		if r.noVersion {
			st.Entries[i].Version = ""
		}
	}
	return st, err
}

func startSettling(t *testing.T, inactive *atomic.Bool, noVersion bool) *harness {
	t.Helper()
	world := reconciletest.NewWorld()
	cfg := parse(t, configV1)
	sys := newSysNet(world, cfg.DNS.Listen)
	h := startWith(t, world, world.Backend(), settling{world.Resolver(), inactive, noVersion}, reconciletest.NewInventory(en0),
		filepath.Join(t.TempDir(), "addrbook.json"), cfg, sys)
	h.sys = sys
	return h
}

// Without versions, only the active flag can show a write by another
// process: an entry that turns not active loses its proof.
func TestProofWithoutVersionsEndsWhenTheEntryTurnsInactive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var inactive atomic.Bool
		h := startSettling(t, &inactive, true)
		defer h.stop()
		for range 2 {
			if err := h.observe(aliasReport); err != nil {
				t.Fatal(err)
			}
		}
		h.wantProbes(edge, 1)

		inactive.Store(true)
		if err := h.observe(aliasReport); err != nil {
			t.Fatalf("Observe = %v, want an ack after a new probe", err)
		}

		h.wantProbes(edge, 2)
	})
}

// A probe that reached ifbound-dns can be reported late, after the daemon
// sent the next probe name; the late report still proves the entry.
func TestLateReportOfAnEarlierProbeName(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		var first string
		h.sys.setHook(func(_ context.Context, name string) error {
			switch {
			case first == "":
				first = name
			case len(h.sys.probes(edge)) == 3:
				h.d.ProbeSeen(first)
			}
			return errors.New("not routed")
		})

		if err := h.observe(aliasReport); err != nil {
			t.Errorf("Observe = %v, want an ack from the late report of the first probe", err)
		}
		h.wantProbes(edge, 3)
	})
}

// A probe below an alias can reach ifbound-dns through the entry of a
// parent domain. When that parent entry is written again while the probe
// runs, the probe proves nothing about the new state.
func TestParentEntryChangedDuringTheProbeIsNotAcked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		h.sys.mu.Lock()
		h.sys.broken["img.ads.test"] = true // only the entry of ads.test routes the probe
		h.sys.mu.Unlock()
		h.sys.setMode(pvHold)
		done := h.observeAsync(pvObs("www.prot.test", []string{"198.18.0.1"}, "img.ads.test"))
		<-h.sys.heldCh

		h.world.RemoveResolverEntry(pvDomain(t, "ads.test"))
		h.tick() // the convergence writes the entry of ads.test again
		h.sys.deliver()

		if err := <-done; !errors.Is(err, daemon.ErrAliasProbe) {
			t.Errorf("Observe = %v, want ErrAliasProbe: the parent entry changed after the probe", err)
		}
	})
}

// A proof made while the SysResolver still reports the entry as not
// active is kept when the version can show a later write. Without a
// version, the daemon cannot tell its own settle time from a write by
// another process, so it probes again.
func TestProofDuringTheSettleTime(t *testing.T) {
	for _, tc := range []struct {
		name      string
		noVersion bool
		probes    int
	}{
		{"with versions", false, 1},
		{"without versions", true, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var inactive atomic.Bool
				inactive.Store(true)
				h := startSettling(t, &inactive, tc.noVersion)
				defer h.stop()

				for i := range 3 {
					if err := h.observe(aliasReport); err != nil {
						t.Fatalf("report %d: Observe = %v, want an ack", i, err)
					}
				}

				h.wantProbes(edge, tc.probes)
			})
		})
	}
}

func TestProofIsForgottenWhileTheResolverReportsAProblem(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		if err := h.observe(aliasReport); err != nil {
			t.Fatal(err)
		}

		h.world.SetProblems(nil, []reconcile.Problem{conflict})
		for i := range 2 { // no proof is kept while the conflict lasts
			if err := h.observe(aliasReport); err != nil {
				t.Fatalf("report %d with a conflict: Observe = %v, want an ack", i, err)
			}
		}
		h.wantProbes(edge, 3)

		h.world.SetProblems(nil, nil)
		for range 2 {
			if err := h.observe(aliasReport); err != nil {
				t.Fatal(err)
			}
		}
		h.wantProbes(edge, 4)
	})
}

func TestFailedEntryWriteFailsLaterReportsAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		world := reconciletest.NewWorld()
		var fail atomic.Bool
		var writes atomic.Int32
		rs := writeFails{Resolver: world.Resolver(), fail: &fail, writes: &writes}
		h := startWith(t, world, world.Backend(), rs, reconciletest.NewInventory(en0),
			filepath.Join(t.TempDir(), "addrbook.json"), parse(t, configV1), newSysNet(world, parse(t, configV1).DNS.Listen))
		defer h.stop()
		fail.Store(true)
		before := writes.Load()

		if err := h.observe(aliasReport); !errors.Is(err, daemon.ErrAliasEntry) {
			t.Fatalf("first Observe = %v, want ErrAliasEntry", err)
		}
		if got := writes.Load() - before; got != 1 {
			t.Fatalf("first report: %d resolver writes, want 1 (its convergence)", got)
		}
		h.wantState(daemon.StateDegraded)
		for i := range 3 {
			if err := h.observe(aliasReport); !errors.Is(err, daemon.ErrAliasEntry) {
				t.Errorf("report %d: Observe = %v, want ErrAliasEntry", i, err)
			}
		}
		if got := writes.Load() - before; got != 1 {
			t.Errorf("%d resolver writes after the later reports, want still 1: they must not converge", got)
		}
		if !h.hasEntry("web", host("203.0.113.1")) {
			t.Error("a rejected report must still block its addresses")
		}

		heal() // the self-heal timer retries the write
		if got := writes.Load() - before; got != 2 {
			t.Errorf("%d resolver writes after a self-heal, want 2", got)
		}
		fail.Store(false)
		heal()
		if err := h.observe(aliasReport); err != nil {
			t.Errorf("Observe after the write works again = %v, want an ack", err)
		}
		h.wantState(daemon.StateReady)
	})
}

func TestEntryChangedDuringTheProbeIsNotAcked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		d, err := policy.ParseDomain(edge)
		if err != nil {
			t.Fatal(err)
		}
		h.sys.setHook(func(context.Context, string) error {
			h.sys.setHook(nil)
			h.world.RemoveResolverEntry(d)
			// An interface change makes the loop converge, and the
			// convergence writes the entry again while the probe waits.
			h.inv.Set(en0)
			time.Sleep(daemon.InterfaceDebounce + time.Millisecond)
			return nil
		})

		if err := h.observe(aliasReport); !errors.Is(err, daemon.ErrAliasProbe) {
			t.Errorf("Observe = %v, want ErrAliasProbe: the probe proved the old entry", err)
		}
	})
}

func TestEntryRemovedAfterTheProbeIsNotAcked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		d, err := policy.ParseDomain(edge)
		if err != nil {
			t.Fatal(err)
		}
		h.sys.setHook(func(_ context.Context, name string) error {
			h.d.ProbeSeen(name) // the probe arrives
			h.world.RemoveResolverEntry(d)
			return errors.New("answered")
		})

		if err := h.observe(aliasReport); !errors.Is(err, daemon.ErrAliasEntry) {
			t.Errorf("Observe = %v, want ErrAliasEntry: the entry was gone at the ack", err)
		}
	})
}

func TestAliasTooLongForAProbeIsNotAcked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 40) + ".test"

		err := h.observe(withAliases(obs("www.example.net", "203.0.113.1"), long))

		if !errors.Is(err, daemon.ErrAliasProbe) {
			t.Errorf("Observe = %v, want ErrAliasProbe: no probe name fits below the alias", err)
		}
	})
}

func TestUnmatchedReportWithAliasIsAckedAndNotStored(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()

		if err := h.observe(withAliases(obs("zz.unrelated.test", "203.0.113.1"), "github.io", edge)); err != nil {
			t.Fatalf("Observe = %v, want an ack", err)
		}
		if st := h.status(); st.Aliases != 0 || st.Addrs != 0 {
			t.Errorf("status = %+v, want nothing learned", st)
		}
		h.wantProbes(edge, 0)
	})
}

func TestStatusCountsAnAliasOfTwoPoliciesTwice(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()

		if err := h.observe(withAliases(obs("www.example.net", "203.0.113.1"), edge, "Edge.CDN.test.", "other.cdn.test")); err != nil {
			t.Fatal(err)
		}
		if err := h.observe(withAliases(obs("x.ads.example", "203.0.113.2"), edge)); err != nil {
			t.Fatal(err)
		}

		if st := h.status(); st.Aliases != 3 {
			t.Errorf("status = %+v, want 3 aliases: 2 of web, 1 of ads", st)
		}
	})
}

// A probe report can arrive after another process wrote the entry again
// with the same server. The report then proves the old entry only.
func TestLateProbeReportAfterARewriteByAnotherProcessIsNotAcked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		h.sys.setMode(pvHold)
		done := h.observeAsync(pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test"))
		<-h.sys.heldCh
		h.sys.setMode(pvDrop)

		e := reconcile.ResolverEntry{Domain: pvDomain(t, "a1.cdn.test"), Server: netip.MustParseAddrPort(pvListen)}
		if err := h.world.Resolver().Write(t.Context(), e); err != nil {
			t.Fatal(err)
		}
		h.sys.deliver()

		if err := <-done; !errors.Is(err, daemon.ErrAliasProbe) {
			t.Errorf("Observe = %v, want ErrAliasProbe: the probe saw the entry before the rewrite", err)
		}
	})
}

// A report with two aliases probes only the one without a proof. When the
// entry of the proven one goes away while the probe waits, the report
// gets no ack.
func TestProvenAliasRemovedDuringAProbeOfAnotherIsNotAcked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		h.ack(pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test"))
		h.sys.setMode(pvHold)
		done := h.observeAsync(pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test", "a2.cdn.test"))
		<-h.sys.heldCh
		if got := len(h.sys.probesOf("a1.cdn.test")); got != 1 {
			t.Fatalf("probes of the proven alias = %d, want 1 (from the first report)", got)
		}

		h.world.RemoveResolverEntry(pvDomain(t, "a1.cdn.test"))
		h.sys.deliver()

		if err := <-done; !errors.Is(err, daemon.ErrAliasEntry) {
			t.Errorf("Observe = %v, want ErrAliasEntry: the entry of a1.cdn.test is gone at the ack", err)
		}
	})
}

// The same, when another process writes the entry of the proven alias
// again with the same server: the entry stays, but its proof ends.
func TestProvenAliasRewrittenDuringAProbeOfAnotherIsNotAcked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		h.ack(pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test"))
		h.sys.setMode(pvHold)
		done := h.observeAsync(pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test", "a2.cdn.test"))
		<-h.sys.heldCh

		e := reconcile.ResolverEntry{Domain: pvDomain(t, "a1.cdn.test"), Server: netip.MustParseAddrPort(pvListen)}
		if err := h.world.Resolver().Write(t.Context(), e); err != nil {
			t.Fatal(err)
		}
		h.sys.deliver()

		if err := <-done; !errors.Is(err, daemon.ErrAliasProbe) {
			t.Errorf("Observe = %v, want ErrAliasProbe: the proof of a1.cdn.test ended during the probe", err)
		}
	})
}

// The probe of img.ads.test reaches ifbound-dns through the entry of
// ads.test. Another process writes ads.test again while the probe waits,
// and the late report proves nothing about the new parent entry.
func TestParentRewrittenOutsideDuringTheProbeIsNotAcked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		h.sys.mu.Lock()
		h.sys.broken["img.ads.test"] = true // only the entry of ads.test routes the probe
		h.sys.mu.Unlock()
		h.sys.setMode(pvHold)
		done := h.observeAsync(pvObs("www.prot.test", []string{"198.18.0.1"}, "img.ads.test"))
		<-h.sys.heldCh
		h.sys.setMode(pvDrop)

		h.rewriteOutside("ads.test")
		h.sys.deliver()

		if err := <-done; !errors.Is(err, daemon.ErrAliasProbe) {
			t.Errorf("Observe = %v, want ErrAliasProbe: the parent entry changed after the probe", err)
		}
	})
}
