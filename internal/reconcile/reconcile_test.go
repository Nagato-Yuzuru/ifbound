package reconcile_test

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrbook"
	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
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
	hosts map[policy.Name][]blockable.Addr
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
		Hosts:    f.hosts,
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
	if _, err := f.book.Observe(name, learned(addrs...), time.Minute); err != nil {
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
	rs, err := reconciletest.Compiler{}.Compile(f.cfg.Policies, ifaces, reconcile.Accounts{})
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
	checkResolver(t, f.world, f.cfg.DNS.Listen, entriesV1...)
	// Two table fills, one load, three apex entries, the canary entry.
	if rep.Writes != 7 || f.world.Writes() != 7 {
		t.Errorf("writes: report %d, world %d, want 7", rep.Writes, f.world.Writes())
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
	checkResolver(t, f.world, f.cfg.DNS.Listen, entriesV1...)
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

// TestConvergeRecompilesOnPossibleClassChange changes only the possible
// classes of an interface. The ruleset must change with them.
func TestConvergeRecompilesOnPossibleClassChange(t *testing.T) {
	f := newFixture(t, configV1)
	none := reconcile.Interface{Name: "ppp0"}
	uncertain := reconcile.Uncertain("ppp0", policy.ClassHardware, policy.ClassTunnel)
	f.inv.Set(en0, none)
	f.converge(t)
	before := f.world.Ruleset().ID()

	f.inv.Set(en0, uncertain)
	rep := f.converge(t)

	if got, want := f.world.Ruleset().ID(), f.compiled(t, en0, uncertain); got != want || got == before {
		t.Errorf("loaded ruleset = %q, want %q, not the ruleset before the change", got, want)
	}
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
	checkResolver(t, f.world, f.cfg.DNS.Listen, "example.com", "example.net", "mail.example.org", canary)
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

// An add-only convergence loads the ruleset and adds the desired
// entries, but removes no desired-state entry and drops no table: here
// an expired address, and the table of a removed policy. It still
// removes an entry that blockable.New refuses, because that removal
// opens no path off the host. The resolver entries converge as in a
// normal pass. A normal convergence with the same inputs then removes
// the rest.
func TestConvergeAddOnlyRemovesNothing(t *testing.T) {
	f := installV1(t)
	seed(t, f.world, map[policy.Name][]string{"web": {"127.0.0.1/32"}, "ads": {"::1/128"}})
	f.reconfigure(t, configV2)
	f.now = f.now.Add(2 * time.Hour)
	f.book.Expire()
	f.hosts = map[policy.Name][]blockable.Addr{"web": learned("10.1.1.1")}
	in := f.inputs()
	in.AddOnly = true

	rep, err := f.rec.Converge(t.Context(), in)
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}

	checkTables(t, f.world, tables{
		"web":  {"198.51.100.0/24", "192.0.2.10/32", "203.0.113.1/32", "10.1.1.1/32"},
		"ads":  {"2001:db8::/32", "3fff::1/128"},
		"mail": {"203.0.113.0/28"},
	})
	if got, want := f.world.Ruleset().ID(), f.compiled(t, en0); got != want || rep.Installed != want {
		t.Errorf("loaded ruleset = %q, installed = %q, want %q", got, rep.Installed, want)
	}
	checkResolver(t, f.world, f.cfg.DNS.Listen, "example.com", "example.net", "mail.example.org", canary)

	f.converge(t)

	checkTables(t, f.world, tables{
		"web":  {"198.51.100.0/24", "192.0.2.10/32", "10.1.1.1/32"},
		"mail": {"203.0.113.0/28"},
	})
}

// A host address is desired while the host file maps it, also when the
// book has none. A host address that the book also has stays when the
// host file drops it. A policy that is not configured gets no table.
func TestConvergeHostAddresses(t *testing.T) {
	f := installV1(t)
	f.hosts = map[policy.Name][]blockable.Addr{
		"web":  learned("203.0.113.1", "203.0.113.9"),
		"gone": learned("203.0.113.7"),
	}

	rep := f.converge(t)

	checkTables(t, f.world, tables{
		"web": {"198.51.100.0/24", "192.0.2.10/32", "203.0.113.1/32", "203.0.113.9/32"},
		"ads": {"2001:db8::/32", "3fff::1/128"},
	})
	if rep.Writes != 1 {
		t.Errorf("writes = %d, want 1 (one table add)", rep.Writes)
	}

	f.hosts = nil
	f.converge(t)

	checkTables(t, f.world, tablesV1)
}

func TestConvergeRewritesResolverEntryWhenListenChanges(t *testing.T) {
	f := installV1(t)
	f.cfg.DNS.Listen = netip.MustParseAddrPort("127.0.0.1:5353")

	rep := f.converge(t)

	checkResolver(t, f.world, f.cfg.DNS.Listen, entriesV1...)
	if rep.Writes != 4 {
		t.Errorf("writes = %d, want 4", rep.Writes)
	}
}

func TestConvergeReportsExternalProblems(t *testing.T) {
	f := installV1(t)
	want := []reconcile.Problem{{Text: "the main ruleset does not reference the anchor", Voids: true}, {Text: "foreign entry for example.com"}}
	f.world.SetProblems(want[:1], want[1:])

	rep := f.converge(t)

	if !slices.Equal(rep.Problems, want) {
		t.Errorf("problems = %+v, want %+v", rep.Problems, want)
	}
}

// The Backend Problems of a Report come from a read after the last
// Backend write. A Load that enables the firewall clears the Problem of
// the disabled firewall in the same convergence, and a Problem that the
// Load does not repair stays. A Load that fails keeps the Problem.
func TestConvergeReportsProblemsAfterTheLoad(t *testing.T) {
	unreferenced := reconcile.Problem{Text: "the main ruleset does not reference the anchor", Voids: true}
	disabled := reconcile.Problem{Text: reconciletest.DisabledText, Voids: true}
	for _, tt := range []struct {
		name    string
		refuse  bool
		want    []reconcile.Problem
		wantErr error
	}{
		{"the load enables the firewall", false, []reconcile.Problem{unreferenced}, nil},
		{"the load fails", true, []reconcile.Problem{unreferenced, disabled}, reconciletest.ErrInjected},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := installV1(t)
			f.world.DisableFirewall()
			f.world.SetProblems([]reconcile.Problem{unreferenced}, nil)
			f.world.SetEnableRefused(tt.refuse)

			rep, err := f.rec.Converge(t.Context(), f.inputs())

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if !slices.Equal(rep.Problems, tt.want) {
				t.Errorf("problems = %+v, want %+v", rep.Problems, tt.want)
			}
		})
	}
}

// readOnce is a Backend whose Reads after the first one fail.
type readOnce struct {
	*reconciletest.Backend
	reads int
}

func (b *readOnce) Read(ctx context.Context) (reconcile.BackendState, error) {
	b.reads++
	if b.reads > 1 {
		return reconcile.BackendState{}, reconciletest.ErrInjected
	}
	return b.Backend.Read(ctx)
}

// Without the read after the Load, the convergence does not know the
// Problems of the loaded ruleset, so it installs nothing.
func TestConvergeNotInstalledWhenTheReadAfterTheLoadFails(t *testing.T) {
	f := installV1(t)
	f.world.DisableFirewall()
	f.rec.Backend = &readOnce{Backend: f.world.Backend()}

	rep, err := f.rec.Converge(t.Context(), f.inputs())

	if !errors.Is(err, reconciletest.ErrInjected) || rep.Installed != "" {
		t.Errorf("err %v, installed %q; want ErrInjected and nothing installed", err, rep.Installed)
	}
}

// A table write can also repair a Backend Problem: AddEntries deletes a
// negated entry inside a prefix that it adds. The Report then gets the
// Backend Problems of a read after that write, also without a Load.
func TestConvergeReportsProblemsAfterATableWrite(t *testing.T) {
	f := installV1(t)
	id := f.world.Ruleset().ID()
	f.world.AddNegated("web", netip.MustParsePrefix("198.51.100.9/32"))
	before, err := f.world.Backend().Read(t.Context())
	if err != nil || len(before.Problems) != 1 || !before.Problems[0].Voids {
		t.Fatalf("Read before the convergence = %+v, %v; want one voiding Problem", before.Problems, err)
	}

	rep := f.converge(t)

	if got := f.world.Ruleset().ID(); got != id {
		t.Fatalf("the convergence loaded the ruleset %q; the test needs a pass without a Load", got)
	}
	if len(rep.Problems) != 0 || rep.Installed != id {
		t.Errorf("problems = %+v, installed = %q; want no Problem and %q", rep.Problems, rep.Installed, id)
	}
	checkTables(t, f.world, tablesV1)
}

// The read after the writes must find the ruleset of the pass loaded.
// When another tool loads a ruleset during the pass, the pass installs
// nothing, also when it loaded the ruleset itself.
func TestConvergeNotInstalledWhenTheRulesetChangesDuringThePass(t *testing.T) {
	for _, tt := range []struct {
		name   string
		before func(w *reconciletest.World)
	}{
		{"after the load", func(w *reconciletest.World) { w.ExternalLoad([]byte("old rules\n")) }},
		{"after a table write", func(w *reconciletest.World) { w.FlushTable("web") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := installV1(t)
			tt.before(f.world)
			first := f.world.Writes() + 1
			f.world.SetAfterWrite(func() {
				if f.world.Writes() == first {
					f.world.ExternalLoad([]byte("foreign rules\n"))
				}
			})

			rep, err := f.rec.Converge(t.Context(), f.inputs())

			if err == nil || rep.Installed != "" {
				t.Errorf("err %v, installed %q; want an error and nothing installed", err, rep.Installed)
			}
		})
	}
}

// noteCompiler wraps the fake Compiler. It reports one problem for each
// user in its accounts, so a test sees which accounts reached Compile.
type noteCompiler struct{ reconciletest.Compiler }

func (c noteCompiler) Compile(ps []policy.Policy, ifaces []reconcile.Interface, accounts reconcile.Accounts) (reconcile.Ruleset, error) {
	rs, err := c.Compiler.Compile(ps, ifaces, accounts)
	var problems []reconcile.Problem
	for _, name := range slices.Sorted(maps.Keys(accounts.Users)) {
		problems = append(problems, reconcile.Problem{Text: "scope dropped: " + name})
	}
	return reconcile.NewRuleset(rs.Body(), problems...), err
}

func TestConvergeReportsCompilerProblemsFirst(t *testing.T) {
	f := installV1(t)
	f.rec.Compiler = noteCompiler{}
	backend := reconcile.Problem{Text: "the main ruleset does not reference the anchor", Voids: true}
	f.world.SetProblems([]reconcile.Problem{backend}, nil)
	in := f.inputs()
	in.Accounts = reconcile.Accounts{Users: map[string]uint32{"b": 2, "a": 1}}

	rep, err := f.rec.Converge(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}

	want := []reconcile.Problem{{Text: "scope dropped: a"}, {Text: "scope dropped: b"}, backend}
	if !slices.Equal(rep.Problems, want) {
		t.Errorf("problems = %+v, want %+v", rep.Problems, want)
	}
	if rep.Installed != f.compiled(t, en0) {
		t.Errorf("installed %q, want the ruleset of the inputs", rep.Installed)
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
	checkResolver(t, f.world, f.cfg.DNS.Listen, entriesV1...)
	if rep.Writes != 4 {
		t.Errorf("writes = %d, want 4 (resolver only)", rep.Writes)
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

	want := map[policy.Name][]blockable.Addr{
		// 192.0.2.10 is an IP destination; the /24 and /8 are not hosts.
		"web": learned("198.51.100.7", "203.0.113.1"),
		"ads": learned("3fff::1"),
		// A loaded rule can still refer to the table of a removed policy.
		"gone": learned("203.0.113.9"),
	}
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Errorf("Adoptable = %v, want %v", got, want)
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
	if err := f.rec.AddObserved(t.Context(), "web", learned("203.0.113.7", "3fff::7")); err != nil {
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
