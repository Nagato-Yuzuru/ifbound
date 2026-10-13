package daemon_test

// Acceptance checks for owner decision 5 of the alias work: the daemon
// acks a report with an alias only when the resolver entry of the alias
// sends queries to ifbound-dns and a probe proved that the system applies
// it. The checks also cover decisions 1 to 4 and the earlier acceptance
// list. They use only the public API of the daemon and the platform
// fakes, and their own harness, so they stay independent of the
// implementation tests.
//
// pvSystem plays the system resolver and ifbound-dns together: a probe
// name goes to the server of the most specific applied resolver entry
// that covers it, as on macOS, and ifbound-dns reports it to the daemon
// with ProbeSeen.

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

	"github.com/Nagato-Yuzuru/ifbound/internal/addrbook"
	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
	"github.com/Nagato-Yuzuru/ifbound/internal/syslookup"
)

const pvHeader = `
[dns]
listen = %q
upstream = ["tls://1.1.1.1@cloudflare-dns.com"]
[addrbook]
retain = "1h"
`

const pvPolicies = `
[[policy]]
name = "web"
to = ["*.prot.test"]
only_via = ["en0"]

[[policy]]
name = "ads"
to = ["*.ads.test"]
deny_via = ["@tunnel"]
`

const pvWebOnly = `
[[policy]]
name = "web"
to = ["*.prot.test"]
only_via = ["en0"]
`

const pvListen = "127.0.0.1:10053"

func pvConfig(listen, policies string) string { return fmt.Sprintf(pvHeader, listen) + policies }

func pvParse(t *testing.T, text string) policy.Config {
	t.Helper()
	cfg, err := policy.ParseBytes([]byte(text))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return cfg
}

func pvCanon(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }

func pvHost(s string) netip.Prefix {
	a := netip.MustParseAddr(s)
	return netip.PrefixFrom(a, a.BitLen())
}

// pvProbe is one probe name that the daemon resolved.
type pvProbe struct {
	name, alias string
	at          time.Time
	deadline    time.Time
	bounded     bool
	routed      bool // the name reached ifbound-dns
	seq         int
}

// The delivery modes of pvSystem for a probe that reaches ifbound-dns.
const (
	pvNow    = "now"    // report it before the answer, as the plugin does
	pvHold   = "hold"   // keep it for a late report (deliver)
	pvDrop   = "drop"   // never report it
	pvWrong  = "wrong"  // report the same nonce below another name
	pvForged = "forged" // report a nonce below the alias that the daemon never sent
)

type pvSystem struct {
	world *reconciletest.World

	mu     sync.Mutex
	d      *daemon.Daemon
	listen netip.AddrPort
	// broken holds the domains whose entries the system never applies,
	// as for an entry with an error (S4 case E).
	broken map[string]bool
	mode   string
	held   []string
	heldCh chan string
	probes []pvProbe
	// other answers a name that is not a probe name. Nil: ErrNotFound.
	other func(ctx context.Context, name string) ([]netip.Addr, error)
	// onSeen runs before each report of a probe name to the daemon.
	onSeen func(name string)
	// seq orders probes, reports, and entry writes for the model.
	seq int
}

// next returns a new sequence number. The caller holds s.mu.
func (s *pvSystem) next() int {
	s.seq++
	return s.seq
}

// report tells the daemon that ifbound-dns got the probe name.
func (s *pvSystem) report(name string) {
	s.mu.Lock()
	d, hook := s.d, s.onSeen
	s.mu.Unlock()
	if hook != nil {
		hook(name)
	}
	d.ProbeSeen(name)
}

func newPVSystem(world *reconciletest.World) *pvSystem {
	return &pvSystem{
		world: world, listen: netip.MustParseAddrPort(pvListen), broken: map[string]bool{},
		mode: pvNow, heldCh: make(chan string, 64),
	}
}

func pvIsProbe(name string) bool { return strings.HasPrefix(name, ipc.ProbePrefix) }

// pvParent returns the name below which a probe name sits.
func pvParent(name string) string {
	_, rest, _ := strings.Cut(name, ".")
	return rest
}

// route returns the server of the most specific applied entry that covers
// name, as the system resolver picks it.
func (s *pvSystem) route(name string) (netip.AddrPort, bool) {
	var best reconcile.ResolverEntry
	found := false
	for _, e := range s.world.AppliedResolverEntries() {
		d := e.Domain.String()
		if s.brokenLocked(d) || (name != d && !strings.HasSuffix(name, "."+d)) {
			continue
		}
		if !found || len(d) > len(best.Domain.String()) {
			best, found = e, true
		}
	}
	return best.Server, found
}

func (s *pvSystem) brokenLocked(d string) bool { return s.broken[d] }

// reachesUs reports whether a query for name reaches ifbound-dns.
func (s *pvSystem) reachesUs(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	srv, ok := s.route(pvCanon(name))
	return ok && srv == s.listen
}

func (s *pvSystem) Resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	n := pvCanon(name)
	if !pvIsProbe(n) {
		if s.other != nil {
			return s.other(ctx, n)
		}
		return nil, fmt.Errorf("resolve %s: %w", n, syslookup.ErrNotFound)
	}
	dl, bounded := ctx.Deadline()
	s.mu.Lock()
	srv, ok := s.route(n)
	routed := ok && srv == s.listen
	s.probes = append(s.probes, pvProbe{name: n, alias: pvParent(n), at: time.Now(), deadline: dl, bounded: bounded, routed: routed, seq: s.next()})
	mode := s.mode
	var report string
	switch {
	case !routed || mode == pvDrop:
	case mode == pvHold:
		s.held = append(s.held, n)
		select {
		case s.heldCh <- n:
		default: // nobody waits for the signal
		}
	case mode == pvWrong:
		label, _, _ := strings.Cut(n, ".")
		report = label + ".other.cdn.test"
	case mode == pvForged:
		report = ipc.ProbePrefix + "0000000000000000." + pvParent(n)
	default:
		report = n
	}
	s.mu.Unlock()
	if report != "" {
		s.report(report)
	}
	return nil, fmt.Errorf("resolve %s: %w", n, syslookup.ErrNotFound) // ifbound-dns answers NXDOMAIN
}

func (s *pvSystem) setMode(m string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = m
}

// deliver reports every held probe name, late.
func (s *pvSystem) deliver() {
	s.mu.Lock()
	held := s.held
	s.held = nil
	s.mu.Unlock()
	for _, n := range held {
		s.report(n)
	}
}

func (s *pvSystem) probesOf(alias string) []pvProbe {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []pvProbe
	for _, p := range s.probes {
		if p.alias == alias {
			out = append(out, p)
		}
	}
	return out
}

// pvResolver is the SysResolver of the daemon: the World's, with a
// write fault and a write counter.
type pvResolver struct {
	*reconciletest.Resolver
	fail   *atomic.Bool
	writes *atomic.Int64
	// changed runs after each write or removal that changed the World.
	changed func(d policy.Domain)
	// blank makes Read report no Version, as a platform that cannot
	// tell.
	blank *atomic.Bool
}

func (r pvResolver) Write(ctx context.Context, e reconcile.ResolverEntry) error {
	r.writes.Add(1)
	if r.fail.Load() {
		return reconciletest.ErrInjected
	}
	err := r.Resolver.Write(ctx, e)
	if err == nil && r.changed != nil {
		r.changed(e.Domain)
	}
	return err
}

func (r pvResolver) Remove(ctx context.Context, d policy.Domain) error {
	err := r.Resolver.Remove(ctx, d)
	if err == nil && r.changed != nil {
		r.changed(d)
	}
	return err
}

type pvH struct {
	t        *testing.T
	world    *reconciletest.World
	inv      *reconciletest.Inventory
	sys      *pvSystem
	fail     *atomic.Bool
	writes   *atomic.Int64
	blank    *atomic.Bool
	snapshot string
	cfg      string
	wrap     func(h *pvH) daemon.SystemResolver
	changed  func(d policy.Domain)
	d        *daemon.Daemon
	stopFn   func()
}

// stop stops the daemon that runs now.
func (h *pvH) stop() { h.stopFn() }

type pvOpts struct {
	delay    bool
	cfg      string // "": pvConfig(pvListen, pvPolicies)
	world    *reconciletest.World
	snapshot string
	sys      *pvSystem
	// wrap replaces the system resolver of the daemon.
	wrap func(h *pvH) daemon.SystemResolver
	// changed runs after each resolver write or removal of the daemon.
	changed func(d policy.Domain)
}

// pvStart runs a daemon inside the synctest bubble of t until stop.
func pvStart(t *testing.T, o pvOpts) *pvH {
	t.Helper()
	if o.world == nil {
		o.world = reconciletest.NewWorld()
	}
	o.world.SetResolverDelay(o.delay)
	if o.cfg == "" {
		o.cfg = pvConfig(pvListen, pvPolicies)
	}
	if o.snapshot == "" {
		o.snapshot = filepath.Join(t.TempDir(), "addrbook.json")
	}
	if o.sys == nil {
		o.sys = newPVSystem(o.world)
	}
	h := &pvH{t: t, world: o.world, inv: reconciletest.NewInventory(en0), sys: o.sys,
		fail: &atomic.Bool{}, writes: &atomic.Int64{}, blank: &atomic.Bool{}, snapshot: o.snapshot, cfg: o.cfg, wrap: o.wrap, changed: o.changed}
	h.run()
	return h
}

func (h *pvH) run() {
	var lookup daemon.SystemResolver = h.sys
	if h.wrap != nil {
		lookup = h.wrap(h)
	}
	d := daemon.New(daemon.Config{
		Policy:   pvParse(h.t, h.cfg),
		Snapshot: h.snapshot,
		Platform: reconcile.Reconciler{
			Compiler:  reconciletest.Compiler{},
			Backend:   h.world.Backend(),
			Resolver:  pvResolver{h.world.Resolver(), h.fail, h.writes, h.changed, h.blank},
			Inventory: h.inv,
		},
		Lookup: lookup,
	})
	h.sys.mu.Lock()
	h.sys.d = d
	h.sys.mu.Unlock()
	ctx, cancel := context.WithCancel(h.t.Context())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	synctest.Wait()
	h.d = d
	h.stopFn = func() {
		cancel()
		if err := <-done; err != nil {
			h.t.Errorf("Run: %v", err)
		}
	}
}

// restart stops the daemon, as a crash does, and starts a new one on the
// same World and snapshot.
func (h *pvH) restart() {
	h.stop()
	h.run()
}

func (h *pvH) status() daemon.Status {
	h.t.Helper()
	st, err := h.d.Status(h.t.Context())
	if err != nil {
		h.t.Fatalf("Status: %v", err)
	}
	return st
}

func pvObs(qname string, addrs []string, aliases ...string) ipc.Observation {
	o := ipc.Observation{QName: qname, TTL: time.Minute}
	for _, s := range addrs {
		o.Addrs = append(o.Addrs, netip.MustParseAddr(s))
	}
	for _, a := range aliases {
		o.Aliases = append(o.Aliases, ipc.Alias{Name: a, TTL: time.Minute})
	}
	return o
}

// observe sends o with the 5 s budget of ifbound-dns.
func (h *pvH) observe(o ipc.Observation) error {
	ctx, cancel := context.WithTimeout(h.t.Context(), ipc.DefaultTimeout)
	defer cancel()
	return h.d.Observe(ctx, o)
}

// observeAsync sends o on another goroutine.
func (h *pvH) observeAsync(o ipc.Observation) <-chan error {
	done := make(chan error, 1)
	go func() { done <- h.observe(o) }()
	return done
}

func (h *pvH) ack(o ipc.Observation) {
	h.t.Helper()
	if err := h.observe(o); err != nil {
		h.t.Fatalf("Observe %s = %v, want an ack", o.QName, err)
	}
}

func (h *pvH) missing(name policy.Name, addrs ...string) []string {
	tables := h.world.Tables()
	var out []string
	for _, s := range addrs {
		if !slices.Contains(tables[name], pvHost(s)) {
			out = append(out, s)
		}
	}
	return out
}

func (h *pvH) snap() *addrbook.AddrBook {
	h.t.Helper()
	b := addrbook.New(time.Hour, time.Now)
	if err := b.Load(h.snapshot); err != nil {
		h.t.Fatalf("load snapshot: %v", err)
	}
	return b
}

func pvHasAlias(b *addrbook.AddrBook, name policy.Name, alias string) bool {
	n, err := dnsname.Parse(alias)
	if err != nil {
		panic(err)
	}
	return slices.Contains(b.Aliases(name), n)
}

// entry reports whether the resolver lists an entry for domain with the
// server of ifbound-dns.
func (h *pvH) entry(domain string) bool {
	h.sys.mu.Lock()
	listen := h.sys.listen
	h.sys.mu.Unlock()
	return slices.ContainsFunc(h.world.ResolverEntries(), func(e reconcile.ResolverEntry) bool {
		return e.Domain.String() == domain && e.Server == listen
	})
}

// tick lets the interface debounce timer run one convergence.
func (h *pvH) tick() {
	h.inv.Set(en0)
	time.Sleep(daemon.InterfaceDebounce)
	synctest.Wait()
}

// Decision 5: "the daemon acks only when the alias's resolver entry is
// written and an end-to-end probe proves that it applied ... A new nonce
// per probe; poll every 50 ms." Acceptance: an entry that is not active
// yet blocks the ack; the addresses are in the table at the ack.
func TestPVAcksOnlyAfterTheEntryApplies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{delay: true})
		defer h.stop()
		done := h.observeAsync(pvObs("www.prot.test.", []string{"198.18.0.1"}, "A1.cdn.test."))

		time.Sleep(225 * time.Millisecond)
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("Observe = %v before the entry applied, want a wait", err)
		default:
		}
		pvCheckPolling(t, h.sys.probesOf("a1.cdn.test"))
		if !h.entry("a1.cdn.test") {
			t.Fatalf("the probes run, but no entry for a1.cdn.test is written: %v", h.world.ResolverEntries())
		}

		h.world.SettleResolver()
		time.Sleep(2 * daemon.ProbeInterval)
		synctest.Wait()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Observe = %v after the entry applied, want an ack", err)
			}
		default:
			t.Fatal("no ack after the entry applied and a probe reached ifbound-dns")
		}
		if miss := h.missing("web", "198.18.0.1"); miss != nil {
			t.Errorf("web table lacks %v at the ack", miss)
		}
		if !pvHasAlias(h.snap(), "web", "a1.cdn.test") {
			t.Error("the snapshot lacks the alias at the ack")
		}
	})
}

// pvCheckPolling checks the probes of 225 ms: one every 50 ms, each with
// a new nonce.
func pvCheckPolling(t *testing.T, probes []pvProbe) {
	t.Helper()
	if len(probes) < 4 {
		t.Fatalf("probes in 225 ms = %d, want a probe every 50 ms", len(probes))
	}
	names := map[string]bool{}
	for i, p := range probes {
		if names[p.name] {
			t.Errorf("probe name %s was sent twice: each probe needs a new nonce", p.name)
		}
		names[p.name] = true
		if i == 0 {
			continue
		}
		if gap := p.at.Sub(probes[i-1].at); gap < daemon.ProbeInterval || gap > 2*daemon.ProbeInterval {
			t.Errorf("gap between probes %d and %d = %v, want about %v", i-1, i, gap, daemon.ProbeInterval)
		}
	}
}

// Decision 5: "No proof -> no ack", and "the probe must finish inside
// the ack budget". Input: "keep time left for enforcement and the ack".
func TestPVNoAckWhenTheEntryNeverApplies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{delay: true}) // never settled
		defer h.stop()
		ctx, cancel := context.WithTimeout(t.Context(), ipc.DefaultTimeout)
		defer cancel()
		outer, _ := ctx.Deadline()

		err := h.d.Observe(ctx, pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test"))

		if !errors.Is(err, daemon.ErrAliasProbe) {
			t.Fatalf("Observe = %v, want an error that wraps ErrAliasProbe", err)
		}
		if !time.Now().Before(outer) {
			t.Errorf("Observe returned at the budget end or later: no time is left for the reply")
		}
		probes := h.sys.probesOf("a1.cdn.test")
		if len(probes) == 0 {
			t.Fatal("no probe was sent")
		}
		for _, p := range probes {
			if !p.bounded || !p.deadline.Before(outer) {
				t.Errorf("probe %s has deadline %v (bounded %v), want one before the budget end %v", p.name, p.deadline, p.bounded, outer)
				break
			}
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if n := len(h.sys.probesOf("a1.cdn.test")); n != len(probes) {
			t.Errorf("probes continued after Observe returned: %d, then %d", len(probes), n)
		}
	})
}

// Decision 5: "An alias whose entry is already proven applied needs no
// probe ... the daemon remembers which entries a probe proved, and
// forgets this when the entry is rewritten or the SysResolver reports it
// contested or shadowed."
func TestPVIsRememberedUntilTheEntryChanges(t *testing.T) {
	other := netip.MustParseAddrPort("127.0.0.1:53")
	cases := []struct {
		name   string
		change func(h *pvH)
	}{
		{"removed outside ifbound", func(h *pvH) { h.world.RemoveResolverEntry(pvDomain(h.t, "a1.cdn.test")) }},
		{"rewritten outside ifbound with another server", func(h *pvH) {
			if err := h.world.Resolver().Write(h.t.Context(), reconcile.ResolverEntry{Domain: pvDomain(h.t, "a1.cdn.test"), Server: other}); err != nil {
				h.t.Fatal(err)
			}
		}},
		{"listen address changed", func(h *pvH) {
			h.sys.mu.Lock()
			h.sys.listen = netip.MustParseAddrPort("127.0.0.1:10054")
			h.sys.mu.Unlock()
			if err := h.d.Reconfigure(h.t.Context(), pvParse(h.t, pvConfig("127.0.0.1:10054", pvPolicies))); err != nil {
				h.t.Fatal(err)
			}
		}},
		{"resolver reports a problem", func(h *pvH) {
			h.world.SetProblems(nil, []reconcile.Problem{{Text: "a1.cdn.test is shadowed"}})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { pvRemembered(t, tc.change) })
		})
	}
}

func pvDomain(t *testing.T, s string) policy.Domain {
	t.Helper()
	d, err := policy.ParseDomain(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func pvRemembered(t *testing.T, change func(*pvH)) {
	t.Helper()
	h := pvStart(t, pvOpts{})
	defer h.stop()
	report := pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test")
	h.ack(report)
	if n := len(h.sys.probesOf("a1.cdn.test")); n != 1 {
		t.Fatalf("probes for the first report = %d, want 1", n)
	}
	h.ack(report)
	if n := len(h.sys.probesOf("a1.cdn.test")); n != 1 {
		t.Fatalf("probes after a second report = %d, want still 1: the entry is proven", n)
	}

	change(h)
	h.ack(report)

	if n := len(h.sys.probesOf("a1.cdn.test")); n != 2 {
		t.Errorf("probes after the change = %d, want 2: the proof must be forgotten", n)
	}
	if !h.entry("a1.cdn.test") {
		t.Errorf("acked, but no entry for a1.cdn.test points to ifbound-dns: %v", h.world.ResolverEntries())
	}
}

// Decision 5: the proof is about the alias's own entry ("closes ... the
// case 'entry listed but never applied' (S4 case E)"). A probe name below
// the alias also reaches ifbound-dns through an applied entry of a
// parent domain. When that parent entry goes away, a remembered proof
// must not let the alias through: its own entry never applied.
func TestPVFromAParentEntryDoesNotOutliveTheParent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		h.sys.mu.Lock()
		h.sys.broken["img.ads.test"] = true // its own entry never applies
		h.sys.mu.Unlock()
		report := pvObs("www.prot.test", []string{"198.18.0.1"}, "img.ads.test")
		h.ack(report) // the probe reaches ifbound-dns through the entry of ads.test
		if !h.sys.reachesUs("img.ads.test") {
			t.Fatal("scenario: img.ads.test should reach ifbound-dns through ads.test")
		}

		if err := h.d.Reconfigure(t.Context(), pvParse(t, pvConfig(pvListen, pvWebOnly))); err != nil {
			t.Fatalf("Reconfigure: %v", err)
		}
		if h.sys.reachesUs("img.ads.test") {
			t.Fatal("scenario: img.ads.test should no longer reach ifbound-dns")
		}

		err := h.observe(report)

		if err == nil {
			t.Errorf("Observe acked alias img.ads.test, but its queries go to the default resolver: "+
				"entries %v, probes %d", h.world.ResolverEntries(), len(h.sys.probesOf("img.ads.test")))
		}
	})
}

// Decision 5: "forgets this when the entry is rewritten". An entry that
// another process rewrites with the same server can stop applying (S4
// case E); the SysResolver then reports it as not active.
func TestPVForgottenWhenTheEntryIsRewrittenOutside(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{delay: true})
		defer h.stop()
		report := pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test")
		done := h.observeAsync(report)
		synctest.Wait()
		h.world.SettleResolver()
		time.Sleep(2 * daemon.ProbeInterval)
		synctest.Wait()
		if err := <-done; err != nil {
			t.Fatalf("first Observe = %v, want an ack", err)
		}

		// Another process writes the entry again; the new file never applies.
		if err := h.world.Resolver().Write(t.Context(), reconcile.ResolverEntry{Domain: pvDomain(t, "a1.cdn.test"), Server: netip.MustParseAddrPort(pvListen)}); err != nil {
			t.Fatal(err)
		}
		h.sys.mu.Lock()
		h.sys.broken["a1.cdn.test"] = true
		h.sys.mu.Unlock()
		if h.sys.reachesUs("a1.cdn.test") {
			t.Fatal("scenario: a1.cdn.test should no longer reach ifbound-dns")
		}

		if err := h.observe(report); err == nil {
			t.Errorf("Observe acked a1.cdn.test after its entry was rewritten and does not apply (probes %d)",
				len(h.sys.probesOf("a1.cdn.test")))
		}
	})
}

// Decision 5: only the report of a probe name that the daemon sent for
// this alias proves the entry. Another alias's name, a forged nonce, or
// no report at all give no ack.
func TestPVOnlyTheSentProbeNameCounts(t *testing.T) {
	for _, mode := range []string{pvWrong, pvForged, pvDrop} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := pvStart(t, pvOpts{})
				defer h.stop()
				h.sys.setMode(mode)

				err := h.observe(pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test"))

				if !errors.Is(err, daemon.ErrAliasProbe) {
					t.Errorf("Observe = %v, want an error that wraps ErrAliasProbe", err)
				}
			})
		})
	}
}

// A probe report that arrives late counts only for the entry that the
// probe saw. Coordinator predicate: a probe issued after the entry's last
// write, reported before the ack.
func TestPVLateProbeReport(t *testing.T) {
	cases := []struct {
		name    string
		between func(h *pvH)
		wantAck bool
	}{
		{"nothing changed", func(*pvH) {}, true},
		{"entry removed outside", func(h *pvH) { h.world.RemoveResolverEntry(pvDomain(h.t, "a1.cdn.test")) }, false},
		{"entry rewritten by ifbound", func(h *pvH) {
			if err := h.world.Resolver().Write(h.t.Context(), reconcile.ResolverEntry{
				Domain: pvDomain(h.t, "a1.cdn.test"), Server: netip.MustParseAddrPort("127.0.0.1:53"),
			}); err != nil {
				h.t.Fatal(err)
			}
			h.tick() // the convergence writes the entry of ifbound again
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { pvLate(t, tc.between, tc.wantAck) })
		})
	}
}

func pvLate(t *testing.T, between func(*pvH), wantAck bool) {
	t.Helper()
	h := pvStart(t, pvOpts{})
	defer h.stop()
	h.sys.setMode(pvHold)
	done := h.observeAsync(pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test"))
	<-h.sys.heldCh
	h.sys.setMode(pvDrop) // the later probes are lost

	between(h)
	h.sys.deliver()
	time.Sleep(2 * daemon.ProbeInterval)
	synctest.Wait()

	select {
	case err := <-done:
		switch {
		case wantAck && err != nil:
			t.Errorf("Observe = %v, want an ack from the late report", err)
		case !wantAck && err == nil:
			t.Error("Observe acked on a probe report for an entry that changed after the probe")
		}
	default:
		if wantAck {
			t.Error("no ack after the late report")
		}
		h.sys.setMode(pvDrop)
		if err := <-done; err == nil { // the budget ends
			t.Error("Observe acked without a valid probe report")
		}
	}
}

// The invariant during the probe: a change that voids the ack gives no
// ack. Decision 4: a configuration change during the probe fails the
// report, also when it changes nothing in effect.
func TestPVChangeDuringProbe(t *testing.T) {
	cases := []struct {
		name    string
		change  func(h *pvH)
		wantErr error // nil: want an ack
	}{
		{"matched policy removed", func(h *pvH) {
			_ = h.d.Reconfigure(h.t.Context(), pvParse(h.t, pvConfig(pvListen, strings.Replace(pvPolicies, "prot.test", "other.test", 1))))
		}, daemon.ErrConfigChanged},
		{"same configuration again", func(h *pvH) { _ = h.d.Reconfigure(h.t.Context(), pvParse(h.t, h.cfg)) }, daemon.ErrConfigChanged},
		{"table flushed", func(h *pvH) { h.world.FlushTable("web") }, nil},
		{"anchor flushed", func(h *pvH) { h.world.FlushAll() }, daemon.ErrUnenforced},
		{"anchor flushed and repair fails", func(h *pvH) {
			h.world.FlushAll()
			h.world.SetBeforeWrite(func(int) error { return reconciletest.ErrInjected })
			h.tick()
			h.world.SetBeforeWrite(nil)
		}, daemon.ErrUnenforced},
		{"foreign ruleset", func(h *pvH) { h.world.ExternalLoad([]byte("foreign")) }, daemon.ErrUnenforced},
		{"firewall disabled", func(h *pvH) {
			h.world.SetProblems([]reconcile.Problem{{Text: "pf is disabled", Voids: true}}, nil)
			h.tick()
		}, daemon.ErrUnenforced},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { pvChange(t, tc.change, tc.wantErr) })
		})
	}
}

func pvChange(t *testing.T, change func(*pvH), wantErr error) {
	t.Helper()
	h := pvStart(t, pvOpts{})
	defer h.stop()
	h.sys.setMode(pvHold)
	done := h.observeAsync(pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test"))
	<-h.sys.heldCh

	change(h)
	h.sys.deliver()
	err := <-done

	switch {
	case wantErr != nil && err == nil:
		t.Fatal("Observe acked after the change")
	case wantErr != nil && !errors.Is(err, wantErr):
		t.Errorf("Observe = %v, want an error that wraps %v", err, wantErr)
	case wantErr != nil:
	case err != nil:
		t.Fatalf("Observe = %v, want an ack", err)
	default:
		if miss := h.missing("web", "198.18.0.1"); miss != nil {
			t.Errorf("acked, but web table lacks %v", miss)
		}
		if !slices.Contains(h.world.Referenced(), "web") {
			t.Error("acked, but the loaded ruleset does not reference web")
		}
	}
}

// Decision 1: a failed write of an alias entry blocks the ack; the
// daemon stays Degraded. Decision 3: a report that carries the alias
// fails at once and starts no convergence; the self-heal timer retries.
func TestPVFailedEntryWriteBlocksAckWithoutRetryStorm(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		report := pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test")
		h.fail.Store(true)
		if err := h.observe(report); !errors.Is(err, daemon.ErrAliasEntry) {
			t.Fatalf("Observe with a failing write = %v, want ErrAliasEntry", err)
		}
		if st := h.status(); st.State != daemon.StateDegraded {
			t.Errorf("state = %v, want degraded", st.State)
		}

		before := h.writes.Load()
		for range 3 {
			if err := h.observe(report); !errors.Is(err, daemon.ErrAliasEntry) {
				t.Fatalf("Observe = %v, want ErrAliasEntry at once", err)
			}
		}
		if n := h.writes.Load() - before; n != 0 {
			t.Errorf("reports with the failing alias made %d resolver writes, want 0", n)
		}
		h.ack(pvObs("api.prot.test", []string{"198.18.0.2"})) // no alias: Degraded acks

		time.Sleep(daemon.SelfHealInterval)
		synctest.Wait()
		if h.writes.Load() == before {
			t.Error("the self-heal timer did not retry the write")
		}
		h.fail.Store(false)
		time.Sleep(daemon.SelfHealInterval)
		synctest.Wait()
		h.ack(report)
		if !h.entry("a1.cdn.test") {
			t.Error("acked, but no entry for a1.cdn.test")
		}
	})
}

// Decision 2: a snapshot with aliases only counts as empty, so the daemon
// adopts the learned-looking kernel entries. Near miss: one address in
// the snapshot stops adoption.
func TestPVAliasOnlySnapshotAdopts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		addrs []netip.Addr
		adopt bool
	}{
		{"aliases only", nil, true},
		{"aliases and an address", []netip.Addr{netip.MustParseAddr("198.18.0.5")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { pvAdopt(t, tc.addrs, tc.adopt) })
		})
	}
}

func pvAdopt(t *testing.T, addrs []netip.Addr, adopt bool) {
	t.Helper()
	snapshot := filepath.Join(t.TempDir(), "addrbook.json")
	b := addrbook.New(time.Hour, time.Now)
	if _, err := b.ObserveAliases("web", []string{"a1.cdn.test"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Observe("web", addrs, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := b.Save(snapshot); err != nil {
		t.Fatal(err)
	}
	world := reconciletest.NewWorld()
	if err := world.Backend().AddEntries(t.Context(), "web", []netip.Prefix{pvHost("198.18.0.77")}); err != nil {
		t.Fatal(err)
	}

	h := pvStart(t, pvOpts{world: world, snapshot: snapshot})
	defer h.stop()

	if st := h.status(); st.State != daemon.StateReady {
		t.Fatalf("state = %v %q, want ready", st.State, st.Reasons)
	}
	kept := h.missing("web", "198.18.0.77") == nil
	saved := slices.Contains(h.snap().Addrs("web"), netip.MustParseAddr("198.18.0.77"))
	if kept != adopt || saved != adopt {
		t.Errorf("kernel entry kept = %v, saved = %v; want both %v", kept, saved, adopt)
	}
}

// Input from YUZ-120: no ack for an alias that cannot get a resolver
// entry. Near misses are acked.
func TestPVAliasWithoutPossibleEntryIsNotAcked(t *testing.T) {
	for _, tc := range []struct {
		alias string
		ack   bool
	}{
		{"co.uk", false}, {"github.io", false}, {"cdntest", false}, {"-bad.cdn.test", false},
		{"cdn.123", false}, {"caf\\195\\169.cdn.test", false},
		{"cdn.co.uk", true}, {"x_y.cdn.test", true},
	} {
		t.Run(tc.alias, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := pvStart(t, pvOpts{})
				defer h.stop()

				err := h.observe(pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test", tc.alias))

				switch {
				case tc.ack && err != nil:
					t.Errorf("Observe = %v, want an ack", err)
				case !tc.ack && !errors.Is(err, daemon.ErrAliasEntry):
					t.Errorf("Observe = %v, want an error that wraps ErrAliasEntry", err)
				}
			})
		})
	}
}

// Scope: a report matches the policies of its qname and the policies
// that hold it as a learned alias; both sets combine. Acceptance: a later
// report of a learned alias matches the original policy.
func TestPVLearnedAliasMatchesItsPolicy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		h.ack(pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test", "a1.ads.test"))

		h.ack(pvObs("A1.CDN.TEST.", []string{"198.18.0.2"}))
		h.ack(pvObs("a1.ads.test", []string{"198.18.0.3"}))
		h.ack(pvObs("a2.cdn.test", []string{"198.18.0.4"}))

		if miss := h.missing("web", "198.18.0.2", "198.18.0.3"); miss != nil {
			t.Errorf("web table lacks %v", miss)
		}
		if miss := h.missing("ads", "198.18.0.3"); miss != nil {
			t.Errorf("ads table lacks %v: the matcher set must also apply", miss)
		}
		if len(h.missing("ads", "198.18.0.2")) != 1 || len(h.missing("web", "198.18.0.4")) != 1 {
			t.Error("an address reached a policy that does not match its name")
		}
	})
}

// Acceptance: a crash after the ack keeps the alias (snapshot). Status
// reports the number of learned aliases.
func TestPVCrashKeepsAliasAndStatusCountsIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		if n := h.status().Aliases; n != 0 {
			t.Fatalf("aliases at start = %d, want 0", n)
		}
		h.ack(pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test", "a2.cdn.test", "A2.CDN.test."))
		if n := h.status().Aliases; n != 2 {
			t.Errorf("aliases = %d, want 2", n)
		}

		h.restart()

		if n := h.status().Aliases; n != 2 {
			t.Errorf("aliases after restart = %d, want 2", n)
		}
		h.ack(pvObs("a1.cdn.test", []string{"198.18.0.9"}))
		if miss := h.missing("web", "198.18.0.9"); miss != nil {
			t.Errorf("after restart the alias did not match web: web lacks %v", miss)
		}
	})
}

// Scope: "save needed" from an alias means a successful save before the
// ack.
func TestPVNewAliasNeedsSave(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		h := pvStart(t, pvOpts{snapshot: filepath.Join(dir, "s.json")})
		defer h.stop()
		h.ack(pvObs("www.prot.test", []string{"198.18.0.1"}))
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		h.ack(pvObs("www.prot.test", []string{"198.18.0.1"})) // nothing new: no save

		if err := h.observe(pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test")); err == nil {
			t.Error("Observe acked a new alias that the snapshot does not hold")
		}
	})
}

// Scope: the loop does not block on a probe. Other reports and timers
// continue meanwhile.
func TestPVLoopServesWhileAProbeWaits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		h.sys.setMode(pvHold)
		first := h.observeAsync(pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test"))
		<-h.sys.heldCh

		h.ack(pvObs("www.ads.test", []string{"198.18.0.2"}))
		h.world.FlushTable("ads")
		h.tick()
		if miss := h.missing("ads", "198.18.0.2"); miss != nil {
			t.Errorf("no convergence ran while the probe waits: ads lacks %v", miss)
		}
		h.sys.deliver()
		if err := <-first; err != nil {
			t.Errorf("first Observe = %v, want an ack", err)
		}
	})
}

// Decision 5: the daemon "forgets this [the proof] when ... the
// SysResolver reports it contested or shadowed". A problem that appears
// while the probe runs must not leave a proof behind.
func TestPVProofNotKeptWhenContestedDuringProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		h.sys.setMode(pvHold)
		report := pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test")
		done := h.observeAsync(report)
		<-h.sys.heldCh
		h.world.SetProblems(nil, []reconcile.Problem{{Text: "a1.cdn.test is shadowed"}})
		h.sys.deliver()
		<-done // its result is the subject of TestPVNoAckWhileTheAliasIsContested
		h.world.SetProblems(nil, nil)
		h.sys.setMode(pvNow)
		before := len(h.sys.probesOf("a1.cdn.test"))

		h.ack(report)

		if n := len(h.sys.probesOf("a1.cdn.test")) - before; n != 1 {
			t.Errorf("probes for the next report = %d, want 1: a proof made while contested must not be kept", n)
		}
	})
}

// "Any doubt means no ack": when the SysResolver reports the alias
// contested at the end of the probe, the daemon does not know that the
// follow-up queries reach ifbound-dns.
func TestPVNoAckWhileTheAliasIsContested(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := pvStart(t, pvOpts{})
		defer h.stop()
		h.sys.setMode(pvHold)
		done := h.observeAsync(pvObs("www.prot.test", []string{"198.18.0.1"}, "a1.cdn.test"))
		<-h.sys.heldCh
		h.world.SetProblems(nil, []reconcile.Problem{{Text: "a1.cdn.test is shadowed"}})

		h.sys.deliver()

		if err := <-done; err == nil {
			t.Error("Observe acked while the SysResolver reports the alias contested")
		}
	})
}
