package daemon_test

// Checks for the Version rule of the alias proofs (owner side decision:
// "a rewrite by another process counts as a rewrite; the proof is
// forgotten"; contract: reconcile.ManagedEntry.Version changes on every
// write by any process, and "" means that the platform cannot tell, so
// the Active flag decides), for proofs that come through a parent entry,
// and for report loops after the removal of the depth limit.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// Read implements reconcile.SysResolver. With blank set, it reports no
// Version.
func (r pvResolver) Read(ctx context.Context) (reconcile.ResolverState, error) {
	st, err := r.Resolver.Read(ctx)
	if err == nil && r.blank != nil && r.blank.Load() {
		for i := range st.Entries {
			st.Entries[i].Version = ""
		}
	}
	return st, err
}

// rewriteOutside writes the entry of domain again with the address of
// ifbound-dns, as another process does: no write of the daemon.
func (h *pvH) rewriteOutside(domain string) {
	h.t.Helper()
	if err := h.world.Resolver().Write(h.t.Context(), reconcile.ResolverEntry{
		Domain: pvDomain(h.t, domain), Server: netip.MustParseAddrPort(pvListen),
	}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *pvH) probes(alias string) int { return len(h.sys.probesOf(alias)) }

// Version rule: a write by another process changes the Version, and the
// proof is forgotten, also when the system applies the new entry at once
// (no delay, so Active stays true and only the Version tells).
func TestPVVersionChangeOutsideForgetsProof(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		report := pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test")
		h.ack(report)
		h.ack(report)
		if n := h.probes("a1.cdn.test"); n != 1 {
			t.Fatalf("probes before the rewrite = %d, want 1", n)
		}

		h.rewriteOutside("a1.cdn.test")
		h.ack(report)

		if n := h.probes("a1.cdn.test"); n != 2 {
			t.Errorf("probes after a rewrite by another process = %d, want 2: the proof must be forgotten", n)
		}
	})
}

// Version rule: without versions ("") the Active flag decides. A rewrite
// that the system has not applied yet forgets the proof; with no rewrite
// the proof stays (near miss).
func TestPVEmptyVersionFallsBackToActive(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rewrite bool
		probes  int
	}{
		{"rewritten, not applied yet", true, 2},
		{"unchanged", false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := pvStart(t, pvOpts{delay: true})
				defer h.stop()
				h.blank.Store(true)
				report := pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test")
				done := h.observeAsync(report)
				synctest.Wait()
				h.world.SettleResolver()
				if err := <-done; err != nil {
					t.Fatalf("first Observe = %v, want an ack", err)
				}
				first := h.probes("a1.cdn.test")

				if tc.rewrite {
					h.rewriteOutside("a1.cdn.test") // pending: Active is false until the settle
				}
				done = h.observeAsync(report)
				time.Sleep(2 * daemon.ProbeInterval)
				synctest.Wait()
				h.world.SettleResolver()
				if err := <-done; err != nil {
					t.Fatalf("second Observe = %v, want an ack", err)
				}

				if n := h.probes("a1.cdn.test") - first; (n > 0) != (tc.probes == 2) {
					t.Errorf("new probes for the second report = %d, want a new probe: %v", n, tc.probes == 2)
				}
			})
		})
	}
}

// Version rule: a write by another process while the probe runs makes
// the report of that probe tell nothing about the new entry.
func TestPVVersionChangeDuringProbeBlocksAck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		h.sys.setMode(pvHold)
		done := h.observeAsync(pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test"))
		<-h.sys.heldCh
		h.sys.setMode(pvDrop)

		h.rewriteOutside("a1.cdn.test")
		h.sys.deliver()

		if err := <-done; !errors.Is(err, daemon.ErrAliasProbe) {
			t.Errorf("Observe = %v, want ErrAliasProbe: the entry changed after the probe", err)
		}
	})
}

// Decision 5 and the Version rule: a report with two aliases acks only
// when the already proven one still holds its proof at the ack.
func TestPVProvenSecondAliasChangedDuringProbeBlocksAck(t *testing.T) {
	cases := []struct {
		name   string
		change func(h *pvH)
	}{
		{"rewritten outside with the same server", func(h *pvH) { h.rewriteOutside("a2.cdn.test") }},
		{"removed outside", func(h *pvH) { h.world.RemoveResolverEntry(pvDomain(h.t, "a2.cdn.test")) }},
		{"rewritten by ifbound", func(h *pvH) {
			if err := h.world.Resolver().Write(h.t.Context(), reconcile.ResolverEntry{
				Domain: pvDomain(h.t, "a2.cdn.test"), Server: netip.MustParseAddrPort("127.0.0.1:53"),
			}); err != nil {
				h.t.Fatal(err)
			}
			h.tick() // the convergence writes the entry of ifbound again
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { pvSecondAlias(t, tc.change) })
		})
	}
}

func pvSecondAlias(t *testing.T, change func(*pvH)) {
	t.Helper()
	h := pvStart(t, pvOpts{})
	defer h.stop()
	h.ack(pvObs("www.prot.test", []string{"198.18.0.1"}, "a2.cdn.test")) // a2 is proven
	h.sys.setMode(pvHold)
	done := h.observeAsync(pvObs("api.prot.test", []string{"198.18.0.2"}, "a1.cdn.test", "a2.cdn.test"))
	<-h.sys.heldCh
	if p := h.sys.probesOf("a1.cdn.test"); len(p) != 1 {
		t.Fatalf("probes of a1 = %d, want 1 (a2 is proven and needs none)", len(p))
	}
	h.sys.setMode(pvDrop)

	change(h)
	h.sys.deliver()

	if err := <-done; err == nil {
		t.Error("Observe acked, but the proof of a2 ended while a1 was probed")
	}
}

// A proof can come through a parent entry (S4 case E for the alias's
// own entry). When another process removes that parent entry, the proof
// must end before the next report: the queries for the alias now go to
// the default resolver. The self-heal timer repairs the parent later,
// but the next report must not ack before that.
func TestPVParentChangedOutsideForgetsChildProof(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(h *pvH)
	}{
		{"parent removed", func(h *pvH) { h.world.RemoveResolverEntry(pvDomain(h.t, "ads.test")) }},
		{"parent rewritten and never applies", func(h *pvH) {
			h.rewriteOutside("ads.test")
			h.sys.mu.Lock()
			h.sys.broken["ads.test"] = true
			h.sys.mu.Unlock()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := pvStart(t, pvOpts{})
				defer h.stop()
				h.sys.mu.Lock()
				h.sys.broken["img.ads.test"] = true // its own entry never applies
				h.sys.mu.Unlock()
				report := pvObs("www.prot.test", []string{"198.18.0.1"}, "img.ads.test")
				h.ack(report) // proven through the entry of ads.test

				tc.change(h)
				if h.sys.reachesUs("img.ads.test") {
					t.Fatal("scenario: img.ads.test should no longer reach ifbound-dns")
				}

				if err := h.observe(report); err == nil {
					t.Errorf("Observe acked img.ads.test, whose queries go to the default resolver (probes %d)", h.probes("img.ads.test"))
				}
			})
		})
	}
}

// Scope: "that report must not deadlock". Without a depth limit, a
// resolver that sends a query for the alias when it gets a probe still
// cannot hang the daemon: each report has its own budget.
func TestPVReportLoopEndsWithinTheBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		chain := &pvLoopChain{nested: map[string]bool{}}
		h := pvStart(t, pvOpts{wrap: func(h *pvH) daemon.SystemResolver {
			chain.pvSystem, chain.h = h.sys, h
			h.sys.mode = pvDrop // the chain reports the probe itself, after its nested report
			return chain
		}})
		defer h.stop()
		start := time.Now()

		_ = h.observe(pvObs("www.prot.test", []string{"198.18.0.1"}, "l1.cdn.test")) // may ack

		if el := time.Since(start); el >= ipc.DefaultTimeout {
			t.Errorf("Observe took %v, want less than the budget %v", el, ipc.DefaultTimeout)
		}
		h.status() // the loop still serves requests
	})
}

// pvLoopChain answers the probe of l<k>.cdn.test by first letting
// ifbound-dns report l<k>.cdn.test with the alias l<k+1>.cdn.test (own
// budget), and then reporting the probe. It stops at level 64.
type pvLoopChain struct {
	*pvSystem
	h      *pvH
	mu     sync.Mutex
	nested map[string]bool
}

func (c *pvLoopChain) Resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	n := pvCanon(name)
	alias := pvParent(n)
	var k int
	if _, err := fmt.Sscanf(alias, "l%d.cdn.test", &k); err == nil && k < 64 {
		c.mu.Lock()
		first := !c.nested[alias]
		c.nested[alias] = true
		c.mu.Unlock()
		if first {
			nctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ipc.DefaultTimeout)
			_ = c.h.d.Observe(nctx, pvObs(alias, []string{"198.19.1.1"}, fmt.Sprintf("l%d.cdn.test", k+1)))
			cancel()
		}
	}
	addrs, err := c.pvSystem.Resolve(ctx, name)
	if c.reachesUs(n) {
		c.report(n)
	}
	return addrs, err
}

// A sequence of reports, each for the alias of the one before and sent
// after that one finished, is acked at every hop.
func TestPVSequentialAliasHopsAreAcked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		h.ack(pvObs("www.prot.test", []string{"198.18.0.1"}, "l1.cdn.test"))
		for k := 1; k <= 10; k++ {
			h.ack(pvObs(fmt.Sprintf("l%d.cdn.test", k), []string{"198.18.0.2"}, fmt.Sprintf("l%d.cdn.test", k+1)))
		}
	})
}

// pvHeldProbe starts report o with its first probe held, and returns its
// result channel. Later probes are lost.
func (h *pvH) heldProbe(o ipc.Observation) <-chan error {
	h.t.Helper()
	h.sys.setMode(pvHold)
	done := h.observeAsync(o)
	<-h.sys.heldCh
	h.sys.setMode(pvDrop)
	return done
}

// Without versions, a removal of the entry while the probe runs must
// still block the ack: the probe proved an entry that is gone.
func TestPVEntryRemovedDuringProbeWithoutVersions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		h.blank.Store(true)
		done := h.heldProbe(pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test"))

		h.world.RemoveResolverEntry(pvDomain(t, "a1.cdn.test"))
		h.sys.deliver()

		if err := <-done; err == nil {
			t.Error("Observe acked on a probe of an entry that was removed during the probe")
		}
	})
}

// Without versions, a write of ifbound while the probe runs must still
// block the ack: the late report tells nothing about the new entry.
func TestPVEntryRewrittenByIfboundDuringProbeWithoutVersions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		h.blank.Store(true)
		done := h.heldProbe(pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test"))

		if err := h.world.Resolver().Write(t.Context(), reconcile.ResolverEntry{
			Domain: pvDomain(t, "a1.cdn.test"), Server: netip.MustParseAddrPort("127.0.0.1:53"),
		}); err != nil {
			t.Fatal(err)
		}
		h.tick() // ifbound writes its entry again
		h.sys.deliver()

		if err := <-done; err == nil {
			t.Error("Observe acked on a probe that was sent before ifbound wrote the entry again")
		}
	})
}

// The fix for a proof through a parent entry: a write of ifbound to a
// parent entry while the probe runs blocks the ack, also when the alias's
// own entry did not change.
func TestPVParentRewrittenByIfboundDuringProbeBlocksAck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		h.sys.mu.Lock()
		h.sys.broken["img.prot.test"] = true // the probe goes through prot.test
		h.sys.mu.Unlock()
		done := h.heldProbe(pvObs("www.prot.test", []string{"198.18.0.1"}, "img.prot.test"))

		if err := h.world.Resolver().Write(t.Context(), reconcile.ResolverEntry{
			Domain: pvDomain(t, "prot.test"), Server: netip.MustParseAddrPort("127.0.0.1:53"),
		}); err != nil {
			t.Fatal(err)
		}
		h.tick() // ifbound writes the parent entry again
		h.sys.deliver()

		if err := <-done; err == nil {
			t.Error("Observe acked on a probe through a parent entry that ifbound wrote again during the probe")
		}
	})
}

// Decision 5: a proof is forgotten while the SysResolver reports a
// problem. A proof made while a problem was already reported must not be
// kept for the reports after the problem ends.
func TestPVProofMadeUnderAProblemIsNotKept(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		h.world.SetProblems(nil, []reconcile.Problem{{Text: "foreign resolver entry for prot.test"}})
		report := pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test")
		_ = h.observe(report) // its ack is not the subject here
		h.world.SetProblems(nil, nil)
		before := h.probes("a1.cdn.test")

		h.ack(report)

		if n := h.probes("a1.cdn.test") - before; n != 1 {
			t.Errorf("probes after the problem ended = %d, want 1: a proof made under a problem must not be kept", n)
		}
	})
}
