package reconcile_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/macresolver"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// These tests check the resolver part of Converge against a reference that
// is written down here, not taken from the package: one entry per apex,
// plus the Firefox canary when at least one apex exists.

var errInjectedWrite = errors.New("injected write fault")

// domainUniverse holds apex candidates on shared label paths, the canary,
// and names that the previous version wrote as alias entries.
var domainUniverse = []string{
	"example.com", "a.example.com", "b.a.example.com", "cdn.example.com",
	"example.net", "edge.example.net", "x.org", "y.x.org",
	"alias.example.com", "edge.example.org", "cdn.akamai.example",
	canary, "dns.net",
}

func mustDomain(t *testing.T, s string) policy.Domain {
	t.Helper()
	d, err := policy.ParseDomain(s)
	if err != nil {
		t.Fatalf("ParseDomain(%q): %v", s, err)
	}
	return d
}

// onSamePath reports whether a is at or below b, or b at or below a,
// by whole labels.
func onSamePath(a, b string) bool {
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

func wantDomains(apexes []string) map[string]bool {
	want := map[string]bool{}
	for _, a := range apexes {
		want[a] = true
	}
	if len(apexes) > 0 {
		want[canary] = true
	}
	return want
}

// faultResolver wraps a SysResolver. Writes of the domains in failWrite
// and removes of the domains in failRemove fail without a change. It logs
// every call.
type faultResolver struct {
	reconcile.SysResolver
	failWrite  map[string]bool
	failRemove map[string]bool
	writes     []string // attempted
	removes    []string // attempted
}

func (f *faultResolver) Write(ctx context.Context, e reconcile.ResolverEntry) error {
	d := e.Domain.String()
	f.writes = append(f.writes, d)
	if f.failWrite[d] {
		return errInjectedWrite
	}
	return f.SysResolver.Write(ctx, e)
}

func (f *faultResolver) Remove(ctx context.Context, d policy.Domain) error {
	f.removes = append(f.removes, d.String())
	if f.failRemove[d.String()] {
		return errInjectedWrite
	}
	return f.SysResolver.Remove(ctx, d)
}

// resolverWorld is a SysResolver under test plus a way to read its
// managed entries and the foreign ones independently of Read.
type resolverWorld interface {
	resolver() reconcile.SysResolver
	managed(t *testing.T) map[string]netip.AddrPort
	foreign(t *testing.T) map[string]string // domain to a content digest
	seed(t *testing.T, domain string, server netip.AddrPort)
	seedForeign(t *testing.T, domain string)
}

// fakeWorld uses reconciletest. It has no foreign entries.
type fakeWorld struct{ w *reconciletest.World }

func (f fakeWorld) resolver() reconcile.SysResolver { return f.w.Resolver() }
func (f fakeWorld) managed(*testing.T) map[string]netip.AddrPort {
	out := map[string]netip.AddrPort{}
	for _, e := range f.w.ResolverEntries() {
		out[e.Domain.String()] = e.Server
	}
	return out
}
func (fakeWorld) foreign(*testing.T) map[string]string { return nil }
func (f fakeWorld) seed(t *testing.T, d string, s netip.AddrPort) {
	if err := f.w.Resolver().Write(t.Context(), reconcile.ResolverEntry{Domain: mustDomain(t, d), Server: s}); err != nil {
		t.Fatal(err)
	}
}
func (fakeWorld) seedForeign(*testing.T, string) {}

// macWorld uses the macOS resolver files in a temporary directory.
type macWorld struct {
	dir string
	r   *macresolver.Resolver
}

type noConfig struct{}

func (noConfig) Resolvers(context.Context) ([]macresolver.ConfigEntry, error) { return nil, nil }

func newMacWorld(t *testing.T) *macWorld {
	dir := t.TempDir()
	return &macWorld{dir: dir, r: macresolver.New(dir, noConfig{})}
}

func (m *macWorld) resolver() reconcile.SysResolver { return m.r }

func (m *macWorld) files(t *testing.T) map[string]string {
	t.Helper()
	ents, err := os.ReadDir(m.dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range ents {
		if e.IsDir() {
			out[e.Name()] = "<directory>"
			continue
		}
		data, err := os.ReadFile(filepath.Join(m.dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(data)
	}
	return out
}

func (m *macWorld) managed(t *testing.T) map[string]netip.AddrPort {
	out := map[string]netip.AddrPort{}
	for name, data := range m.files(t) {
		first, rest, _ := strings.Cut(data, "\n")
		if first != macresolver.Marker {
			continue
		}
		var addr string
		var port uint16
		if _, err := fmt.Sscanf(rest, "nameserver %s\nport %d\n", &addr, &port); err != nil {
			t.Fatalf("managed file %s: %q: %v", name, data, err)
		}
		out[name] = netip.AddrPortFrom(netip.MustParseAddr(addr), port)
	}
	return out
}

func (m *macWorld) foreign(t *testing.T) map[string]string {
	out := map[string]string{}
	for name, data := range m.files(t) {
		if first, _, _ := strings.Cut(data, "\n"); first != macresolver.Marker {
			out[name] = data
		}
	}
	return out
}

func (m *macWorld) seed(t *testing.T, d string, s netip.AddrPort) {
	if err := m.r.Write(t.Context(), reconcile.ResolverEntry{Domain: mustDomain(t, d), Server: s}); err != nil {
		t.Fatal(err)
	}
}

func (m *macWorld) seedForeign(t *testing.T, d string) {
	data := "# a VPN client wrote this\nnameserver 10.0.0.1\n"
	if err := os.WriteFile(filepath.Join(m.dir, d), []byte(data), 0o644); err != nil { //nolint:gosec // a resolver file is world-readable
		t.Fatal(err)
	}
}

var (
	listenA = netip.MustParseAddrPort("127.0.0.1:10053")
	listenB = netip.MustParseAddrPort("127.0.0.1:5353")
)

func randomSubset(r *rand.Rand, from []string, p float64) []string {
	var out []string
	for _, s := range from {
		if r.Float64() < p {
			out = append(out, s)
		}
	}
	return out
}

// convergeStep is one convergence and what the test saw around it.
type convergeStep struct {
	before, after map[string]netip.AddrPort
	want          map[string]bool
	failed        []string // writes that failed, foreign refusals included
	failRemove    map[string]bool
	listen        netip.AddrPort
}

func (s convergeStep) onFailedPath(d string) bool {
	return slices.ContainsFunc(s.failed, func(f string) bool { return onSamePath(d, f) })
}

// check returns the first broken invariant of the resolver part, or nil.
func (s convergeStep) check() error {
	// Fail closed: an old entry on the label path of a failed write
	// stays, with its server unless it is desired.
	for d, srv := range s.before {
		if !s.onFailedPath(d) {
			continue
		}
		if got, ok := s.after[d]; !ok || (got != srv && !s.want[d]) {
			return fmt.Errorf("entry %s on the path of a failed write was removed or changed", d)
		}
	}
	// No extra entry: an entry that is not desired was there before and
	// is kept for a failed write or a failed remove.
	for d := range s.after {
		_, was := s.before[d]
		if !s.want[d] && (!was || (!s.failRemove[d] && !s.onFailedPath(d))) {
			return fmt.Errorf("entry %s is not desired and not kept by a fault", d)
		}
	}
	// Every desired entry whose write did not fail has the listen address.
	for d := range s.want {
		if !slices.Contains(s.failed, d) && s.after[d] != s.listen {
			return fmt.Errorf("desired entry %s = %v, want %v", d, s.after[d], s.listen)
		}
	}
	return nil
}

// seedResolverWorld puts entries that an earlier version left, alias
// entries included and some with another server, and foreign files.
func seedResolverWorld(t *testing.T, r *rand.Rand, world resolverWorld, withForeign bool) {
	for _, d := range randomSubset(r, domainUniverse, 0.4) {
		s := listenA
		if r.IntN(4) == 0 {
			s = listenB
		}
		world.seed(t, d, s)
	}
	if !withForeign {
		return
	}
	for _, d := range randomSubset(r, domainUniverse, 0.15) {
		if _, ok := world.managed(t)[d]; !ok {
			world.seedForeign(t, d)
		}
	}
}

// setFaults picks the faults of one convergence. It reports whether the
// convergence is clean.
func (f *faultResolver) setFaults(r *rand.Rand) bool {
	clean := r.IntN(3) == 0
	f.failWrite, f.failRemove = map[string]bool{}, map[string]bool{}
	f.writes, f.removes = nil, nil
	if clean {
		return true
	}
	for _, d := range randomSubset(r, domainUniverse, 0.3) {
		f.failWrite[d] = true
	}
	for _, d := range randomSubset(r, domainUniverse, 0.15) {
		f.failRemove[d] = true
	}
	return false
}

// runResolverConvergence drives random convergences on one world and
// checks the invariants of the resolver part after each one.
func runResolverConvergence(t *testing.T, seed uint64, world resolverWorld, withForeign bool) {
	r := rand.New(rand.NewPCG(seed, 0x5eed))
	seedResolverWorld(t, r, world, withForeign)
	foreignAtStart := world.foreign(t)
	fr := &faultResolver{SysResolver: world.resolver()}
	rec := reconcile.Reconciler{
		Compiler:  reconciletest.Compiler{},
		Backend:   reconciletest.NewWorld().Backend(),
		Resolver:  fr,
		Inventory: reconciletest.NewInventory(),
	}
	listen := listenA
	for step := range 30 {
		apexes := randomSubset(r, domainUniverse, 0.25)
		if r.IntN(10) == 0 {
			listen = map[bool]netip.AddrPort{true: listenA, false: listenB}[listen != listenA]
		}
		clean := fr.setFaults(r)
		in := apexInputs(t, apexes, listen)
		st := convergeStep{before: world.managed(t), want: wantDomains(apexes), failRemove: fr.failRemove, listen: listen}
		_, err := rec.Converge(t.Context(), in)
		st.after = world.managed(t)
		for _, d := range fr.writes {
			if fr.failWrite[d] || foreignAtStart[d] != "" {
				st.failed = append(st.failed, d)
			}
		}
		ctx := fmt.Sprintf("seed %d step %d: apexes %v listen %v failWrite %v failRemove %v\nbefore %v\nafter  %v\nwrites %v removes %v",
			seed, step, apexes, listen, slices.Sorted(maps.Keys(fr.failWrite)), slices.Sorted(maps.Keys(fr.failRemove)), st.before, st.after, fr.writes, fr.removes)
		if foreign := world.foreign(t); !maps.Equal(foreign, foreignAtStart) {
			t.Fatalf("%s\nforeign entries changed: %v -> %v", ctx, foreignAtStart, foreign)
		}
		if err := st.check(); err != nil {
			t.Fatalf("%s\n%v", ctx, err)
		}
		noConflict := !slices.ContainsFunc(slices.Collect(maps.Keys(st.want)), func(d string) bool { return foreignAtStart[d] != "" })
		if clean && noConflict {
			checkCleanConvergence(t, ctx, rec, fr, in, st, err)
		}
		if len(st.failed) == 0 && len(fr.failRemove) == 0 && noConflict && err != nil {
			t.Fatalf("%s\nno fault, but err = %v", ctx, err)
		}
	}
}

func apexInputs(t *testing.T, apexes []string, listen netip.AddrPort) reconcile.Inputs {
	in := reconcile.Inputs{Book: noAddrs{}, Listen: listen}
	for _, a := range apexes {
		in.Apexes = append(in.Apexes, mustDomain(t, a))
	}
	return in
}

// checkCleanConvergence: without a fault, the entries are exactly the
// desired ones, and a second pass writes nothing.
func checkCleanConvergence(t *testing.T, ctx string, rec reconcile.Reconciler, fr *faultResolver, in reconcile.Inputs, st convergeStep, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s\nclean convergence failed: %v", ctx, err)
	}
	if !maps.Equal(domainSet(st.after), st.want) {
		t.Fatalf("%s\nclean convergence: entries %v, want exactly %v", ctx, slices.Sorted(maps.Keys(st.after)), slices.Sorted(maps.Keys(st.want)))
	}
	fr.writes, fr.removes = nil, nil
	if _, err := rec.Converge(t.Context(), in); err != nil || len(fr.writes)+len(fr.removes) > 0 {
		t.Fatalf("%s\nsecond pass: err %v, writes %v, removes %v; want none", ctx, err, fr.writes, fr.removes)
	}
}

func domainSet(m map[string]netip.AddrPort) map[string]bool {
	out := map[string]bool{}
	for k := range m {
		out[k] = true
	}
	return out
}

func TestResolverConvergesFailClosedOnFake(t *testing.T) {
	for seed := range uint64(300) {
		runResolverConvergence(t, seed, fakeWorld{w: reconciletest.NewWorld()}, false)
	}
}

func TestResolverConvergesFailClosedOnMacFiles(t *testing.T) {
	for seed := range uint64(20) {
		runResolverConvergence(t, seed, newMacWorld(t), true)
	}
}

// No apex means no entry at all, the canary included. The canary as an
// apex gets one entry.
func TestResolverCanaryBoundaries(t *testing.T) {
	cases := []struct {
		apexes []string
		want   []string
	}{
		{nil, nil},
		{[]string{canary}, []string{canary}},
		{[]string{"example.com"}, []string{"example.com", canary}},
		{[]string{"dns.net", "example.com"}, []string{"dns.net", "example.com", canary}},
	}
	for _, tc := range cases {
		w := reconciletest.NewWorld()
		fw := fakeWorld{w: w}
		fw.seed(t, "edge.example.org", listenA) // an old entry that is not desired
		fw.seed(t, canary, listenA)
		rec := reconcile.Reconciler{Compiler: reconciletest.Compiler{}, Backend: w.Backend(), Resolver: w.Resolver(), Inventory: reconciletest.NewInventory()}
		in := reconcile.Inputs{Book: noAddrs{}, Listen: listenA}
		for _, a := range tc.apexes {
			in.Apexes = append(in.Apexes, mustDomain(t, a))
		}
		if _, err := rec.Converge(t.Context(), in); err != nil {
			t.Fatal(err)
		}
		got := slices.Sorted(maps.Keys(fw.managed(t)))
		if !slices.Equal(got, tc.want) {
			t.Errorf("apexes %v: entries %v, want %v", tc.apexes, got, tc.want)
		}
	}
}

// The macOS resolver never changes or removes a file that ifbound
// does not manage: Remove leaves it, and Write refuses it.
func TestMacResolverNeverTouchesForeignFiles(t *testing.T) {
	m := newMacWorld(t)
	for _, d := range []string{"example.com", canary, "edge.example.org"} {
		m.seedForeign(t, d)
	}
	if err := os.Mkdir(filepath.Join(m.dir, "x.org"), 0o755); err != nil { //nolint:gosec // a test directory
		t.Fatal(err)
	}
	// A file that starts like the marker but is not the marker line.
	near := macresolver.Marker + " (edited)\nnameserver 127.0.0.1\nport 53553\n"
	if err := os.WriteFile(filepath.Join(m.dir, "example.net"), []byte(near), 0o644); err != nil { //nolint:gosec // a resolver file is world-readable
		t.Fatal(err)
	}
	before := m.foreign(t)
	for _, d := range []string{"example.com", canary, "edge.example.org", "x.org", "example.net"} {
		dom := mustDomain(t, d)
		if err := m.r.Write(t.Context(), reconcile.ResolverEntry{Domain: dom, Server: listenA}); !errors.Is(err, macresolver.ErrConflict) {
			t.Errorf("Write(%s) over a foreign file = %v, want ErrConflict", d, err)
		}
		_ = m.r.Remove(t.Context(), dom) //nolint:errcheck // the error is not the contract; the file is
	}
	if after := m.foreign(t); !maps.Equal(after, before) {
		t.Errorf("foreign files changed:\n%v\n->\n%v", before, after)
	}
	if fi, err := os.Stat(filepath.Join(m.dir, "x.org")); err != nil || !fi.IsDir() {
		t.Errorf("the foreign directory x.org is gone or changed: %v", err)
	}
}
