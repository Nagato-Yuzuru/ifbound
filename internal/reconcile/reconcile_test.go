package reconcile_test

import (
	"errors"
	"maps"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrbook"
	"github.com/Nagato-Yuzuru/ifbound/internal/matcher"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

const header = `
[dns]
listen = "127.0.0.1:53553"
upstream = ["tls://1.1.1.1@cloudflare-dns.com"]
[addrbook]
retain = "1h"
`

// configV1 has two policies.
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
)

func parse(t *testing.T, text string) policy.Config {
	t.Helper()
	cfg, err := policy.ParseBytes([]byte(text))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return cfg
}

type fixture struct {
	world *reconciletest.World
	inv   *reconciletest.Inventory
	rec   reconcile.Reconciler
	book  *addrbook.AddrBook
	now   time.Time
	cfg   policy.Config
}

func newFixture(t *testing.T, cfgText string) *fixture {
	t.Helper()
	f := &fixture{
		world: reconciletest.NewWorld(),
		inv:   reconciletest.NewInventory(en0),
		now:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		cfg:   parse(t, cfgText),
	}
	f.rec = reconcile.Reconciler{
		Compiler:  reconciletest.Compiler{},
		Backend:   f.world.Backend(),
		Resolver:  f.world.Resolver(),
		Inventory: f.inv,
	}
	f.book = addrbook.New(f.cfg.AddrBook.Retain, func() time.Time { return f.now })
	return f
}

func (f *fixture) inputs() reconcile.Inputs {
	return reconcile.Inputs{
		Policies: f.cfg.Policies,
		Book:     f.book,
		Apexes:   matcher.New(f.cfg.Policies).Apexes(),
		Listen:   f.cfg.DNS.Listen,
	}
}

func (f *fixture) converge(t *testing.T) reconcile.Report {
	t.Helper()
	rep, err := f.rec.Converge(t.Context(), f.inputs())
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	return rep
}

func (f *fixture) observe(t *testing.T, name policy.Name, addrs ...string) {
	t.Helper()
	as := make([]netip.Addr, len(addrs))
	for i, s := range addrs {
		as[i] = netip.MustParseAddr(s)
	}
	if _, err := f.book.Observe(name, as, time.Minute); err != nil {
		t.Fatalf("Observe: %v", err)
	}
}

func (f *fixture) reconfigure(t *testing.T, cfgText string) {
	t.Helper()
	f.cfg = parse(t, cfgText)
	names := make([]policy.Name, len(f.cfg.Policies))
	for i, p := range f.cfg.Policies {
		names[i] = p.Name
	}
	f.book.Prune(names)
}

func (f *fixture) compiled(t *testing.T, ifaces ...reconcile.Interface) string {
	t.Helper()
	rs, err := reconciletest.Compiler{}.Compile(f.cfg.Policies, ifaces)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return rs.ID()
}

// tables is the test spelling of table contents. Entry order does not
// matter.
type tables map[policy.Name][]string

func render(in map[policy.Name][]netip.Prefix) tables {
	out := make(tables, len(in))
	for name, ps := range in {
		out[name] = make([]string, len(ps))
		for i, p := range ps {
			out[name][i] = p.String()
		}
		slices.Sort(out[name])
	}
	return out
}

func checkTables(t *testing.T, w *reconciletest.World, want tables) {
	t.Helper()
	got := render(w.Tables())
	sameEntries := func(a, b []string) bool {
		return slices.Equal(a, slices.Sorted(slices.Values(b)))
	}
	if !maps.EqualFunc(got, want, sameEntries) {
		t.Errorf("tables = %v, want %v", got, want)
	}
}

func checkResolver(t *testing.T, w *reconciletest.World, listen netip.AddrPort, domains ...string) {
	t.Helper()
	var got []string
	for _, e := range w.ResolverEntries() {
		if e.Server != listen {
			t.Errorf("resolver entry %s points to %v, want %v", e.Domain, e.Server, listen)
		}
		got = append(got, e.Domain.String())
	}
	if !slices.Equal(got, domains) {
		t.Errorf("resolver entries = %v, want %v", got, domains)
	}
}

var tablesV1 = tables{
	"web": {"198.51.100.0/24", "192.0.2.10/32", "203.0.113.1/32"},
	"ads": {"2001:db8::/32", "3fff::1/128"},
}

func installV1(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t, configV1)
	f.observe(t, "web", "203.0.113.1")
	f.observe(t, "ads", "3fff::1")
	f.converge(t)
	return f
}

func TestConvergeInstallsDesiredStateFromEmptyWorld(t *testing.T) {
	f := newFixture(t, configV1)
	f.observe(t, "web", "203.0.113.1")
	f.observe(t, "ads", "3fff::1")

	rep := f.converge(t)

	checkTables(t, f.world, tablesV1)
	if got, want := f.world.Ruleset().ID(), f.compiled(t, en0); got != want {
		t.Errorf("loaded ruleset = %q, want %q", got, want)
	}
	checkResolver(t, f.world, f.cfg.DNS.Listen, "ads.example", "example.com", "example.net")
	// Two table fills, one load, three resolver entries.
	if rep.Writes != 6 || f.world.Writes() != 6 {
		t.Errorf("writes: report %d, world %d, want 6", rep.Writes, f.world.Writes())
	}
	if rep.Installed != f.compiled(t, en0) {
		t.Errorf("installed = %q, want the compiled ruleset", rep.Installed)
	}
}

func TestConvergeSecondPassWritesNothing(t *testing.T) {
	f := installV1(t)
	before := f.world.Writes()

	rep := f.converge(t)

	if rep.Writes != 0 || f.world.Writes() != before {
		t.Errorf("second pass wrote: report %d, world %d -> %d", rep.Writes, before, f.world.Writes())
	}
}

func TestConvergeRepairsExternalFlush(t *testing.T) {
	f := installV1(t)
	f.world.FlushTable("web")
	f.world.RemoveResolverEntry(f.inputs().Apexes[1]) // example.com

	rep := f.converge(t)

	checkTables(t, f.world, tablesV1)
	checkResolver(t, f.world, f.cfg.DNS.Listen, "ads.example", "example.com", "example.net")
	if rep.Writes != 2 {
		t.Errorf("writes = %d, want 2 (one table fill, one resolver entry)", rep.Writes)
	}
}

func TestConvergeRecompilesOnInterfaceChange(t *testing.T) {
	f := installV1(t)
	f.inv.Set(en0, utun0)

	rep := f.converge(t)

	if got, want := f.world.Ruleset().ID(), f.compiled(t, en0, utun0); got != want {
		t.Errorf("loaded ruleset = %q, want %q", got, want)
	}
	checkTables(t, f.world, tablesV1)
	if rep.Writes != 1 {
		t.Errorf("writes = %d, want 1 (the load)", rep.Writes)
	}
}

func TestConvergeConfigChangeAddsAndRemovesPolicy(t *testing.T) {
	f := installV1(t)
	f.reconfigure(t, configV2)

	f.converge(t)

	checkTables(t, f.world, tables{
		"web":  {"198.51.100.0/24", "192.0.2.10/32", "203.0.113.1/32"},
		"mail": {"203.0.113.0/28"},
	})
	if got, want := f.world.Ruleset().ID(), f.compiled(t, en0); got != want {
		t.Errorf("loaded ruleset = %q, want %q", got, want)
	}
	if got := f.world.Referenced(); !slices.Equal(got, []policy.Name{"web", "mail"}) {
		t.Errorf("referenced tables = %v, want [web mail]", got)
	}
	checkResolver(t, f.world, f.cfg.DNS.Listen, "example.com", "example.net", "mail.example.org")
}

func TestConvergeWithNoPoliciesRemovesEverything(t *testing.T) {
	f := installV1(t)
	f.reconfigure(t, header)

	f.converge(t)

	checkTables(t, f.world, tables{})
	checkResolver(t, f.world, f.cfg.DNS.Listen)
}

func TestConvergeExpiryRemovesAddress(t *testing.T) {
	f := newFixture(t, configV1)
	f.observe(t, "web", "203.0.113.1")
	f.converge(t)
	f.now = f.now.Add(40 * time.Minute)
	f.observe(t, "web", "203.0.113.2")
	f.converge(t)

	f.now = f.now.Add(21 * time.Minute) // 61 minutes after the first answer
	if got := f.book.Expire(); len(got) != 1 || got[0].Addr != netip.MustParseAddr("203.0.113.1") {
		t.Fatalf("Expire = %v, want only 203.0.113.1", got)
	}
	rep := f.converge(t)

	checkTables(t, f.world, tables{
		"web": {"198.51.100.0/24", "192.0.2.10/32", "203.0.113.2/32"},
		"ads": {"2001:db8::/32"},
	})
	if rep.Writes != 1 {
		t.Errorf("writes = %d, want 1 (the removal)", rep.Writes)
	}
}

func TestConvergeRewritesResolverEntryWhenListenChanges(t *testing.T) {
	f := installV1(t)
	f.cfg.DNS.Listen = netip.MustParseAddrPort("127.0.0.1:5353")

	rep := f.converge(t)

	checkResolver(t, f.world, f.cfg.DNS.Listen, "ads.example", "example.com", "example.net")
	if rep.Writes != 3 {
		t.Errorf("writes = %d, want 3", rep.Writes)
	}
}

func TestConvergeReportsExternalProblems(t *testing.T) {
	f := installV1(t)
	want := []reconcile.Problem{{Text: "pf is disabled", Voids: true}, {Text: "foreign entry for example.com"}}
	f.world.SetProblems(want[:1], want[1:])

	rep := f.converge(t)

	if !slices.Equal(rep.Problems, want) {
		t.Errorf("problems = %+v, want %+v", rep.Problems, want)
	}
}

func TestConvergeRunsResolverPartWhenBackendFails(t *testing.T) {
	f := newFixture(t, configV1)
	f.world.SetBeforeWrite(func(n int) error {
		if n == 1 {
			return reconciletest.ErrInjected
		}
		return nil
	})

	rep, err := f.rec.Converge(t.Context(), f.inputs())

	if !errors.Is(err, reconciletest.ErrInjected) {
		t.Fatalf("err = %v, want ErrInjected", err)
	}
	if f.world.Ruleset().ID() != "" {
		t.Error("ruleset loaded after a failed table fill")
	}
	checkResolver(t, f.world, f.cfg.DNS.Listen, "ads.example", "example.com", "example.net")
	if rep.Writes != 3 {
		t.Errorf("writes = %d, want 3 (resolver only)", rep.Writes)
	}
	if rep.Installed != "" {
		t.Errorf("installed = %q after a failed Backend part, want empty", rep.Installed)
	}
}

func TestConvergeInstallsDespiteResolverFailure(t *testing.T) {
	f := newFixture(t, configV1)
	f.world.SetBeforeWrite(func(n int) error {
		if n == 4 { // the first resolver write
			return reconciletest.ErrInjected
		}
		return nil
	})

	rep, err := f.rec.Converge(t.Context(), f.inputs())

	if !errors.Is(err, reconciletest.ErrInjected) {
		t.Fatalf("err = %v, want ErrInjected", err)
	}
	if rep.Installed != f.compiled(t, en0) {
		t.Errorf("installed = %q, want the loaded ruleset: the Backend part completed", rep.Installed)
	}
}

func TestConvergeNotInstalledWhenRemovalFails(t *testing.T) {
	f := installV1(t)
	f.now = f.now.Add(2 * time.Hour)
	f.book.Expire()
	f.world.SetBeforeWrite(func(int) error { return reconciletest.ErrInjected })

	rep, err := f.rec.Converge(t.Context(), f.inputs())

	if !errors.Is(err, reconciletest.ErrInjected) || rep.Installed != "" {
		t.Errorf("err %v, installed %q; want ErrInjected and nothing installed", err, rep.Installed)
	}
}

func TestAdoptableReturnsLearnedLookingEntries(t *testing.T) {
	f := newFixture(t, configV1)
	be := f.world.Backend()
	for name, entries := range map[policy.Name][]netip.Prefix{
		"web":  prefixes("192.0.2.10/32", "198.51.100.0/24", "198.51.100.7/32", "203.0.113.1/32", "10.0.0.0/8"),
		"ads":  prefixes("3fff::1/128"),
		"gone": prefixes("203.0.113.9/32"),
	} {
		if err := be.AddEntries(t.Context(), name, entries); err != nil {
			t.Fatal(err)
		}
	}

	got, err := f.rec.Adoptable(t.Context(), f.cfg.Policies)
	if err != nil {
		t.Fatalf("Adoptable: %v", err)
	}

	want := map[policy.Name][]netip.Addr{
		// 192.0.2.10 is an IP destination; the /24 and /8 are not hosts.
		"web": {netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("203.0.113.1")},
		"ads": {netip.MustParseAddr("3fff::1")},
	}
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Errorf("Adoptable = %v, want %v (no policy outside the configuration)", got, want)
	}
}

func TestAdoptableOfEmptyKernelIsEmpty(t *testing.T) {
	f := newFixture(t, configV1)

	got, err := f.rec.Adoptable(t.Context(), f.cfg.Policies)

	if err != nil || len(got) != 0 {
		t.Errorf("Adoptable = %v, %v; want nothing", got, err)
	}
}

func TestAddObservedAddsHostEntries(t *testing.T) {
	f := installV1(t)
	addrs := []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("3fff::7")}

	if err := f.rec.AddObserved(t.Context(), "web", addrs); err != nil {
		t.Fatalf("AddObserved: %v", err)
	}

	want := tables{
		"web": {"198.51.100.0/24", "192.0.2.10/32", "203.0.113.1/32", "203.0.113.7/32", "3fff::7/128"},
		"ads": tablesV1["ads"],
	}
	checkTables(t, f.world, want)
}

func TestAddObservedWithNoAddressWritesNothing(t *testing.T) {
	f := installV1(t)
	before := f.world.Writes()

	if err := f.rec.AddObserved(t.Context(), "web", nil); err != nil {
		t.Fatalf("AddObserved: %v", err)
	}
	if f.world.Writes() != before {
		t.Errorf("writes %d -> %d, want none", before, f.world.Writes())
	}
}
