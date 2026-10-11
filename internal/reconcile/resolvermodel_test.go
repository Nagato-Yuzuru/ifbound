package reconcile_test

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/publicsuffix"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// This file is a model test of the resolver part of Converge. It
// computes the desired resolver entries with its own reference, drives
// random sequences of convergences against the reconciletest World, and
// checks every resolver call and every settle of the fake system.
//
// Run more seeds with: go test ./internal/reconcile -run TestResolverModel
// -args -model.seeds=20000

var modelSeeds = flag.Int("model.seeds", 200, "number of random seeds of the resolver model test")

var modelListens = []netip.AddrPort{
	netip.MustParseAddrPort("127.0.0.1:53553"),
	netip.MustParseAddrPort("127.0.0.1:53554"),
}

// modelApexes holds apexes, some nested in others and in aliases.
var modelApexes = []string{
	"example.com", "www.example.com", "example.net", "a.b.example.net",
	"ads.example", "provider.test", "sub.provider.test", canary,
}

// modelAliases holds learned alias names: names at, below, and next to
// apexes; nested aliases; public suffixes; names that the domain rules
// refuse; names that differ only in case or final dot.
var modelAliases = []string{
	"example.com", "WWW.Example.com.", "x.www.example.com", "myexample.com",
	"cdn.example.net", "a.b.example.net", "b.example.net",
	"provider.test", "cdn.provider.test", "deep.cdn.provider.test", "xprovider.test",
	"other.org", "user.github.io", "x.co.uk", canary,
	"com", "co.uk", "github.io", "cdn.cloudflare.net", "local", "test", "arpa",
	"in-addr.arpa", "net",
	`a\032b.test`, `a/b.test`, `*.wild.test`, "192.0.2.1", "-lead.test", `\195\169.test`,
	`a\.b.test`, `\046\046.test`, `\000.test`,
}

const modelConfig = header + `
[[policy]]
name = "p0"
to = ["192.0.2.10"]
only_via = ["en0"]

[[policy]]
name = "p1"
to = ["192.0.2.11"]
only_via = ["en0"]

[[policy]]
name = "p2"
to = ["192.0.2.12"]
deny_via = ["en1"]
`

// aliasBook is a fake AddrSource: learned aliases per policy, no
// addresses.
type aliasBook map[policy.Name][]dnsname.Name

func (aliasBook) Addrs(policy.Name) []netip.Addr { return nil }

func (b aliasBook) Aliases(name policy.Name) []dnsname.Name { return slices.Clone(b[name]) }

// verdict is the reference decision for one alias.
type verdict int

const (
	accepted verdict = iota
	notDomain
	publicSuffix
)

// refAliasEntry is the reference of AliasEntry, built directly on
// the configuration domain rules and the public suffix list.
func refAliasEntry(n dnsname.Name) (string, verdict) {
	d, err := policy.ParseDomain(n.String())
	if err != nil {
		return "", notDomain
	}
	if ps, _ := publicsuffix.PublicSuffix(d.String()); ps == d.String() {
		return "", publicSuffix
	}
	return d.String(), accepted
}

// refDesired is the reference desired set of resolver domains.
func refDesired(apexes []string, policies []policy.Policy, book aliasBook) map[string]bool {
	out := make(map[string]bool)
	for _, a := range apexes {
		out[a] = true
	}
	for _, p := range policies {
		for _, n := range book[p.Name] {
			if d, v := refAliasEntry(n); v == accepted {
				out[d] = true
			}
		}
	}
	others := len(out)
	if out[canary] {
		others--
	}
	if others > 0 {
		out[canary] = true
	}
	return out
}

// atOrBelow reports whether name is d or a name below d, label by
// label.
func atOrBelow(name, d string) bool {
	nl, dl := strings.Split(name, "."), strings.Split(d, ".")
	return len(nl) >= len(dl) && slices.Equal(nl[len(nl)-len(dl):], dl)
}

// covered reports whether an entry for one of domains covers name.
func covered(name string, domains []string) bool {
	return slices.ContainsFunc(domains, func(d string) bool { return atOrBelow(name, d) })
}

// coverageNames is every name whose coverage the model checks: each pool
// domain and one name below it.
func coverageNames() []string {
	set := make(map[string]bool)
	add := func(d string) { set[d], set["zz."+d] = true, true }
	for _, a := range modelApexes {
		add(a)
	}
	for _, s := range modelAliases {
		n, err := dnsname.Parse(s)
		if err != nil {
			continue
		}
		if d, err := policy.ParseDomain(n.String()); err == nil {
			add(d.String())
		}
	}
	return slices.Sorted(maps.Keys(set))
}

type resolverCall struct {
	remove bool
	domain string
	server netip.AddrPort
	failed bool
}

func (c resolverCall) String() string {
	s := "write " + c.domain + " " + c.server.String()
	if c.remove {
		s = "remove " + c.domain
	}
	if c.failed {
		s += " (failed)"
	}
	return s
}

// resolverSnap is the resolver state after one call or settle.
type resolverSnap struct {
	after   string // the event
	present []string
	applied []string
}

// resolverProbe wraps the SysResolver of a World. It injects failures before
// a call reaches the World, settles the fake system at random points,
// and records the calls and a snapshot after each event.
type resolverProbe struct {
	inner   reconcile.SysResolver
	world   *reconciletest.World
	rng     *rand.Rand
	failP   float64
	settleP float64
	// failOn holds domains whose Write always fails.
	failOn map[string]bool
	calls  []resolverCall
	snaps  []resolverSnap
}

var _ reconcile.SysResolver = (*resolverProbe)(nil)

// entryDomains returns the domains of the entries, in the same order.
func entryDomains(es []reconcile.ResolverEntry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Domain.String()
	}
	return out
}

func (p *resolverProbe) snap(event string) {
	p.snaps = append(p.snaps, resolverSnap{
		after:   event,
		present: entryDomains(p.world.ResolverEntries()),
		applied: entryDomains(p.world.AppliedResolverEntries()),
	})
}

func (p *resolverProbe) maybeSettle() {
	if p.rng.Float64() < p.settleP {
		p.world.SettleResolver()
		p.snap("settle")
	}
}

func (p *resolverProbe) reset(failP, settleP float64) {
	p.failP, p.settleP = failP, settleP
	p.calls, p.snaps = nil, nil
}

func (p *resolverProbe) Read(ctx context.Context) (reconcile.ResolverState, error) {
	return p.inner.Read(ctx)
}

func (p *resolverProbe) Write(ctx context.Context, e reconcile.ResolverEntry) error {
	return p.call(resolverCall{domain: e.Domain.String(), server: e.Server}, func() error {
		return p.inner.Write(ctx, e)
	})
}

func (p *resolverProbe) Remove(ctx context.Context, d policy.Domain) error {
	return p.call(resolverCall{remove: true, domain: d.String()}, func() error {
		return p.inner.Remove(ctx, d)
	})
}

func (p *resolverProbe) call(c resolverCall, do func() error) error {
	p.maybeSettle()
	var err error
	if (!c.remove && p.failOn[c.domain]) || p.rng.Float64() < p.failP {
		c.failed = true
		err = fmt.Errorf("probe %s: %w", c.domain, reconciletest.ErrInjected)
	} else {
		err = do()
	}
	p.calls = append(p.calls, c)
	verb := "write"
	if c.remove {
		verb = "remove"
	}
	p.snap(verb + " " + c.domain)
	p.maybeSettle()
	return err
}

// resolverModel is one random run.
type resolverModel struct {
	world    *reconciletest.World
	probe    *resolverProbe
	rec      reconcile.Reconciler
	rng      *rand.Rand
	all      []policy.Policy
	policies []policy.Policy
	apexes   []string
	book     aliasBook
	listen   netip.AddrPort
	delay    bool
	trace    []string
	stats    *modelStats
}

// modelStats counts what the random runs exercised.
type modelStats struct {
	steps, failedSteps, keeps, midSettles, rewrites, removes int
}

func newResolverModel(t *testing.T, seed uint64) *resolverModel {
	t.Helper()
	cfg, err := policy.ParseBytes([]byte(modelConfig))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	rng := rand.New(rand.NewPCG(seed, 0x0dd))
	w := reconciletest.NewWorld()
	m := &resolverModel{
		world:  w,
		probe:  &resolverProbe{inner: w.Resolver(), world: w, rng: rng},
		rng:    rng,
		all:    cfg.Policies,
		book:   make(aliasBook),
		listen: modelListens[0],
		delay:  rng.IntN(2) == 0,
	}
	w.SetResolverDelay(m.delay)
	m.rec = reconcile.Reconciler{
		Compiler:  reconciletest.Compiler{},
		Backend:   w.Backend(),
		Resolver:  m.probe,
		Inventory: reconciletest.NewInventory(en0),
	}
	m.policies = m.all
	return m
}

func (m *resolverModel) inputs() reconcile.Inputs {
	apexes := make([]policy.Domain, len(m.apexes))
	for i, a := range m.apexes {
		d, err := policy.ParseDomain(a)
		if err != nil {
			panic(err) // the pool holds valid domains only
		}
		apexes[i] = d
	}
	return reconcile.Inputs{Policies: m.policies, Book: m.book, Apexes: apexes, Listen: m.listen}
}

func (m *resolverModel) logf(format string, args ...any) {
	m.trace = append(m.trace, fmt.Sprintf(format, args...))
}

// mutate changes the inputs at random.
func (m *resolverModel) mutate() {
	switch m.rng.IntN(6) {
	case 0:
		m.newApexes()
	case 1, 2:
		m.learn()
	case 3:
		m.expire()
	case 4:
		m.newPolicies()
	case 5:
		m.listen = modelListens[m.rng.IntN(len(modelListens))]
		m.logf("listen = %v", m.listen)
	}
}

func (m *resolverModel) newApexes() {
	m.apexes = nil
	for _, a := range modelApexes {
		if m.rng.IntN(4) == 0 {
			m.apexes = append(m.apexes, a)
		}
	}
	m.logf("apexes = %v", m.apexes)
}

func (m *resolverModel) learn() {
	p := m.all[m.rng.IntN(len(m.all))].Name
	for range 1 + m.rng.IntN(3) {
		s := modelAliases[m.rng.IntN(len(modelAliases))]
		n, err := dnsname.Parse(s)
		if err != nil {
			panic(err) // the pool holds names that dnsname accepts
		}
		if !slices.Contains(m.book[p], n) {
			m.book[p] = append(m.book[p], n)
		}
		m.logf("learn %s %q", p, s)
	}
}

func (m *resolverModel) expire() {
	p := m.all[m.rng.IntN(len(m.all))].Name
	if len(m.book[p]) > 0 {
		i := m.rng.IntN(len(m.book[p]))
		m.logf("expire %s %q", p, m.book[p][i])
		m.book[p] = slices.Delete(m.book[p], i, i+1)
	}
}

// newPolicies removes a random part of the policies; the others come
// back.
func (m *resolverModel) newPolicies() {
	m.policies = nil
	var names []policy.Name
	for _, p := range m.all {
		if m.rng.IntN(3) != 0 {
			m.policies = append(m.policies, p)
			names = append(names, p.Name)
		}
	}
	m.logf("policies = %v", names)
}

func servers(w *reconciletest.World) map[string]netip.AddrPort {
	out := make(map[string]netip.AddrPort)
	for _, e := range w.ResolverEntries() {
		out[e.Domain.String()] = e.Server
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

// convergence is what the model knows about one convergence.
type convergence struct {
	listen         netip.AddrPort
	delay          bool
	before, after  map[string]netip.AddrPort
	appliedStart   []string
	appliedEnd     []string
	desired        map[string]bool
	calls          []resolverCall
	snaps          []resolverSnap
	written        map[string]bool
	removed        map[string]bool
	failedWrite    map[string]bool
	failedRemove   map[string]bool
	report         reconcile.Report
	err            error
	worldWrites    int // the World writes of the convergence
	beforeDomains  []string
	desiredDomains []string
}

// step runs one convergence and checks it. It returns whether any call
// failed.
func (m *resolverModel) step(t *testing.T, failP float64) bool {
	t.Helper()
	c := &convergence{
		listen:       m.listen,
		delay:        m.delay,
		before:       servers(m.world),
		appliedStart: entryDomains(m.world.AppliedResolverEntries()),
		desired:      refDesired(m.apexes, m.policies, m.book),
	}
	c.beforeDomains, c.desiredDomains = sortedKeys(c.before), sortedKeys(c.desired)
	settleP := 0.0
	if m.delay {
		settleP = 0.15
	}
	m.probe.reset(failP, settleP)
	worldBefore := m.world.Writes()

	c.report, c.err = m.rec.Converge(t.Context(), m.inputs())

	c.worldWrites = m.world.Writes() - worldBefore
	c.after = servers(m.world)
	c.appliedEnd = entryDomains(m.world.AppliedResolverEntries())
	c.calls, c.snaps = m.probe.calls, m.probe.snaps
	m.logf("converge: calls %v err %v", c.calls, c.err)
	for _, check := range []func() error{
		c.checkCalls, c.checkDesiredAfter, c.checkOldAfter, c.checkResult, c.checkCoverage, c.checkConverged,
	} {
		if err := check(); err != nil {
			t.Fatalf("%v\ntrace:\n  %s", err, strings.Join(m.trace, "\n  "))
		}
	}
	c.count(m.stats)
	return len(c.failedWrite)+len(c.failedRemove) > 0
}

// checkCalls checks the call sequence: writes first, each domain at
// most once, only desired writes to the listen address, no rewrite of an
// entry that is present with that address, removes of old entries only.
func (c *convergence) checkCalls() error {
	c.written, c.removed = make(map[string]bool), make(map[string]bool)
	c.failedWrite, c.failedRemove = make(map[string]bool), make(map[string]bool)
	seenRemove := false
	for _, call := range c.calls {
		d := call.domain
		if call.remove {
			seenRemove = true
			if err := c.checkRemove(d); err != nil {
				return err
			}
			c.removed[d], c.failedRemove[d] = true, call.failed
			continue
		}
		if err := c.checkWrite(call, seenRemove); err != nil {
			return err
		}
		c.written[d], c.failedWrite[d] = true, call.failed
	}
	maps.DeleteFunc(c.failedWrite, func(_ string, v bool) bool { return !v })
	maps.DeleteFunc(c.failedRemove, func(_ string, v bool) bool { return !v })
	for d := range c.desired {
		if s, ok := c.before[d]; (!ok || s != c.listen) && !c.written[d] {
			return fmt.Errorf("desired %s (before: present %v, server %v) not written", d, ok, s)
		}
	}
	return nil
}

func (c *convergence) checkRemove(d string) error {
	if c.removed[d] {
		return fmt.Errorf("remove of %s twice", d)
	}
	if _, ok := c.before[d]; !ok || c.desired[d] {
		return fmt.Errorf("remove of %s: present before %v, desired %v", d, ok, c.desired[d])
	}
	return nil
}

func (c *convergence) checkWrite(call resolverCall, seenRemove bool) error {
	d := call.domain
	switch {
	case seenRemove:
		return fmt.Errorf("write of %s follows a remove: %v", d, c.calls)
	case c.written[d]:
		return fmt.Errorf("write of %s twice", d)
	case !c.desired[d] || call.server != c.listen:
		return fmt.Errorf("write of %s -> %v: desired %v, listen %v", d, call.server, c.desired[d], c.listen)
	}
	if s, ok := c.before[d]; ok && s == c.listen {
		return fmt.Errorf("rewrite of %s, which is present with the desired server", d)
	}
	return nil
}

// checkDesiredAfter: each desired entry holds the listen address, unless
// its write failed; a failed write changes nothing.
func (c *convergence) checkDesiredAfter() error {
	for d := range c.desired {
		s, ok := c.after[d]
		switch {
		case !c.failedWrite[d] && (!ok || s != c.listen):
			return fmt.Errorf("desired %s: present %v server %v, want %v", d, ok, s, c.listen)
		case c.failedWrite[d] && s != c.before[d]:
			return fmt.Errorf("failed write of %s changed it: %v -> %v", d, c.before[d], s)
		}
	}
	for d := range c.after {
		if _, ok := c.before[d]; !ok && !c.desired[d] {
			return fmt.Errorf("new undesired entry %s", d)
		}
	}
	return nil
}

// checkOldAfter checks the keep rule: an old entry stays exactly when a
// failed desired entry is on its label path (at or below it, or at or
// above it), or its remove failed.
func (c *convergence) checkOldAfter() error {
	for d := range c.before {
		if c.desired[d] {
			continue
		}
		keep := slices.ContainsFunc(sortedKeys(c.failedWrite), func(f string) bool { return atOrBelow(f, d) || atOrBelow(d, f) })
		_, kept := c.after[d]
		switch {
		case keep && (c.removed[d] || !kept):
			return fmt.Errorf("old %s removed, but the failed desired entries %v include one on its label path", d, sortedKeys(c.failedWrite))
		case !keep && !c.removed[d]:
			return fmt.Errorf("old %s not removed; failed writes %v", d, sortedKeys(c.failedWrite))
		case !keep && kept != c.failedRemove[d]:
			return fmt.Errorf("old %s kept %v, remove failed %v", d, kept, c.failedRemove[d])
		}
	}
	return nil
}

// checkResult checks the error and the write count of the report.
func (c *convergence) checkResult() error {
	anyFailed := len(c.failedWrite)+len(c.failedRemove) > 0
	switch {
	case anyFailed && !errors.Is(c.err, reconciletest.ErrInjected):
		return fmt.Errorf("calls failed, err = %v", c.err)
	case !anyFailed && c.err != nil:
		return fmt.Errorf("no call failed, err = %v", c.err)
	case c.report.Writes != c.worldWrites:
		return fmt.Errorf("report writes %d, world writes %d", c.report.Writes, c.worldWrites)
	}
	return nil
}

// checkCoverage: a name that an entry covered before and the desired
// set covers stays covered after every call and settle, in the entries
// and in the entries that the system applied. This holds also when calls
// fail.
func (c *convergence) checkCoverage() error {
	for _, n := range coverageNames() {
		if !covered(n, c.beforeDomains) || !covered(n, c.desiredDomains) {
			continue
		}
		for _, s := range c.snaps {
			if !covered(n, s.present) {
				return fmt.Errorf("after %s: %s not covered by the entries %v (before %v)", s.after, n, s.present, c.beforeDomains)
			}
			if covered(n, c.appliedStart) && !covered(n, s.applied) {
				return fmt.Errorf("after %s: %s not covered by the applied entries %v", s.after, n, s.applied)
			}
		}
	}
	return nil
}

// checkConverged: with no failed call, the entries are the desired set,
// and without a delay the system applies them at once.
func (c *convergence) checkConverged() error {
	if len(c.failedWrite)+len(c.failedRemove) > 0 {
		return nil
	}
	if got := sortedKeys(c.after); !slices.Equal(got, c.desiredDomains) {
		return fmt.Errorf("entries %v, want %v", got, c.desiredDomains)
	}
	if !c.delay && !slices.Equal(c.appliedEnd, c.desiredDomains) {
		return fmt.Errorf("applied %v, want %v", c.appliedEnd, c.desiredDomains)
	}
	return nil
}

// count adds the convergence to the statistics.
func (c *convergence) count(st *modelStats) {
	st.steps++
	if len(c.failedWrite)+len(c.failedRemove) > 0 {
		st.failedSteps++
	}
	for _, sn := range c.snaps {
		if sn.after == "settle" {
			st.midSettles++
		}
	}
	for _, call := range c.calls {
		if _, ok := c.before[call.domain]; call.remove {
			st.removes++
		} else if ok {
			st.rewrites++
		}
	}
	for d := range c.before {
		if _, ok := c.after[d]; ok && !c.desired[d] && !c.failedRemove[d] {
			st.keeps++
		}
	}
}

// TestResolverModel drives random sequences of convergences and
// checks each one against the reference.
func TestResolverModel(t *testing.T) {
	stats := &modelStats{}
	for seed := range uint64(*modelSeeds) {
		m := newResolverModel(t, seed)
		m.stats = stats
		m.logf("seed %d delay %v", seed, m.delay)
		for range 20 {
			m.randomStep(t)
		}
	}
	t.Logf("steps %d, with failures %d, kept old entries %d, settles inside a convergence %d, rewrites %d, removes %d",
		stats.steps, stats.failedSteps, stats.keeps, stats.midSettles, stats.rewrites, stats.removes)
}

// randomStep changes the inputs and converges. After a convergence with
// no failed call, it can converge again with the same inputs: that
// convergence makes no resolver call, also when entries are not active
// yet.
func (m *resolverModel) randomStep(t *testing.T) {
	t.Helper()
	m.mutate()
	if m.rng.IntN(2) == 0 {
		m.mutate()
	}
	failP := 0.0
	if m.rng.IntN(3) == 0 {
		failP = 0.3
	}
	if m.delay && m.rng.IntN(2) == 0 {
		m.world.SettleResolver()
		m.logf("settle")
	}
	if m.step(t, failP) || m.rng.IntN(2) == 0 {
		return
	}
	before := m.world.Writes()
	m.step(t, 0)
	if n := len(m.probe.calls); n != 0 || m.world.Writes() != before {
		t.Fatalf("second convergence made %d resolver calls, world writes %d -> %d\ntrace:\n  %s",
			n, before, m.world.Writes(), strings.Join(m.trace, "\n  "))
	}
}
