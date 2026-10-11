package reconcile_test

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/matcher"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// enforcement is what is blocked and resolved on one side of a change.
type enforcement struct {
	tables map[policy.Name][]netip.Prefix
	apexes []string
}

// transition is one change that a single convergence applies.
type transition struct {
	name string
	from string // the configuration that is installed first
	// install runs before the first convergence.
	install func(t *testing.T, f *fixture)
	// change runs after it. It ends with f.reconfigure.
	change func(t *testing.T, f *fixture)
	next   enforcement
	writes int // the writes of the change convergence
}

const moveFrom = header + `
[[policy]]
name = "web"
to = ["www.shop.example", "198.51.100.0/24"]
only_via = ["en0"]
`

// moveTo moves the CIDR from web to the new policy mail, and widens
// www.shop.example to *.shop.example: the new apex covers the old one.
const moveTo = header + `
[[policy]]
name = "web"
to = ["*.shop.example"]
only_via = ["en0"]

[[policy]]
name = "mail"
to = ["mail.example.org", "198.51.100.0/24"]
deny_via = ["en1"]
`

func transitions() []transition {
	return []transition{{
		name: "config change with expiry",
		from: configV1,
		install: func(t *testing.T, f *fixture) {
			f.observe(t, "web", "203.0.113.1", "203.0.113.2")
			f.observe(t, "ads", "3fff::1")
		},
		change: func(t *testing.T, f *fixture) {
			f.now = f.now.Add(40 * time.Minute)
			f.observe(t, "web", "203.0.113.2", "203.0.113.3")
			f.now = f.now.Add(21 * time.Minute)
			f.book.Expire() // 203.0.113.1 and 3fff::1 expire
			f.reconfigure(t, configV2)
			f.observe(t, "mail", "192.0.2.25")
		},
		next: enforcement{
			tables: map[policy.Name][]netip.Prefix{
				"web":  prefixes("198.51.100.0/24", "192.0.2.10/32", "203.0.113.2/32", "203.0.113.3/32"),
				"mail": prefixes("203.0.113.0/28", "192.0.2.25/32"),
			},
			apexes: []string{"example.com", "example.net", "mail.example.org"},
		},
		// Two table fills, one load, one removal, one drop, one resolver
		// write and one resolver removal.
		writes: 7,
	}, {
		name:    "destination moves and apexes merge",
		from:    moveFrom,
		install: func(*testing.T, *fixture) {},
		change:  func(t *testing.T, f *fixture) { f.reconfigure(t, moveTo) },
		next: enforcement{
			tables: map[policy.Name][]netip.Prefix{
				"web":  nil,
				"mail": prefixes("198.51.100.0/24"),
			},
			apexes: []string{"mail.example.org", "shop.example"},
		},
		// One fill, one load, one removal, two resolver writes, one
		// resolver removal.
		writes: 6,
	}}
}

// TestConvergeIsFailClosedAtEveryStep stops one convergence at each write
// in turn: that write and every later one fail. After every write that
// succeeds, three invariants hold:
//
//   - Each table that the loaded ruleset refers to holds every entry that
//     is blocked both before and after the change, or all its entries if
//     only one side has the policy.
//   - An entry that is blocked before and after the change, also in
//     another policy, is in some table that the loaded ruleset refers to.
//   - A name that an old resolver entry covers, and a new one also
//     covers, stays covered.
//
// A later pass with no fault reaches the desired state.
func TestConvergeIsFailClosedAtEveryStep(t *testing.T) {
	for _, tr := range transitions() {
		t.Run(tr.name, func(t *testing.T) {
			if got := prepare(t, tr).converge(t).Writes; got != tr.writes {
				t.Fatalf("the change makes %d writes, want %d: it no longer covers every kind of step", got, tr.writes)
			}
			for failAt := 1; failAt <= tr.writes; failAt++ {
				t.Run(fmt.Sprintf("fail at write %d", failAt), func(t *testing.T) {
					failClosedAt(t, tr, failAt)
				})
			}
		})
	}
}

func failClosedAt(t *testing.T, tr transition, failAt int) {
	f := newFixture(t, tr.from)
	tr.install(t, f)
	f.converge(t)
	old := enforcement{tables: f.world.Tables(), apexes: domains(f)}
	tr.change(t, f)
	base := f.world.Writes()
	f.world.SetAfterWrite(func() { checkFailClosed(t, f, old, tr.next) })
	f.world.SetBeforeWrite(func(n int) error {
		if n-base >= failAt {
			return reconciletest.ErrInjected
		}
		return nil
	})

	if _, err := f.rec.Converge(t.Context(), f.inputs()); !errors.Is(err, reconciletest.ErrInjected) {
		t.Fatalf("err = %v, want ErrInjected", err)
	}
	f.world.SetBeforeWrite(nil)
	f.converge(t)

	checkTables(t, f.world, render(tr.next.tables))
	if got, want := f.world.Ruleset().ID(), f.compiled(t, en0); got != want {
		t.Errorf("loaded ruleset = %q, want %q", got, want)
	}
	checkResolver(t, f.world, f.cfg.DNS.Listen, tr.next.apexes...)
}

func prepare(t *testing.T, tr transition) *fixture {
	t.Helper()
	f := newFixture(t, tr.from)
	tr.install(t, f)
	f.converge(t)
	tr.change(t, f)
	return f
}

func domains(f *fixture) []string {
	var out []string
	for _, d := range matcher.New(f.cfg.Policies).Apexes() {
		out = append(out, d.String())
	}
	return out
}

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func checkFailClosed(t *testing.T, f *fixture, old, next enforcement) {
	t.Helper()
	actual := f.world.Tables()
	referenced := f.world.Referenced()
	for _, name := range referenced {
		for _, p := range needed(old.tables, next.tables, name) {
			if !slices.Contains(actual[name], p) {
				t.Errorf("after write %d: table %s lacks %v while the ruleset refers to it", f.world.Writes(), name, p)
			}
		}
	}
	for _, p := range kept(old.tables, next.tables) {
		if !slices.ContainsFunc(referenced, func(n policy.Name) bool { return slices.Contains(actual[n], p) }) {
			t.Errorf("after write %d: %v is in no table that the ruleset refers to", f.world.Writes(), p)
		}
	}
	var entries []string
	for _, e := range f.world.ResolverEntries() {
		entries = append(entries, e.Domain.String())
	}
	for _, d := range old.apexes {
		if covered(d, next.apexes) && !covered(d, entries) {
			t.Errorf("after write %d: no resolver entry covers %s, which both sides cover", f.world.Writes(), d)
		}
	}
}

// needed returns the entries that a referenced table of the policy must
// hold on the way from old to next.
func needed(old, next map[policy.Name][]netip.Prefix, name policy.Name) []netip.Prefix {
	o, inOld := old[name]
	n, inNext := next[name]
	switch {
	case inOld && inNext:
		return slices.DeleteFunc(slices.Clone(o), func(p netip.Prefix) bool { return !slices.Contains(n, p) })
	case inOld:
		return o
	default:
		return n
	}
}

// kept returns the entries that some policy blocks on both sides.
func kept(old, next map[policy.Name][]netip.Prefix) []netip.Prefix {
	var before, out []netip.Prefix
	for _, ps := range old {
		before = append(before, ps...)
	}
	for _, ps := range next {
		for _, p := range ps {
			if slices.Contains(before, p) {
				out = append(out, p)
			}
		}
	}
	return out
}

func covered(name string, apexes []string) bool {
	return slices.ContainsFunc(apexes, func(a string) bool {
		return name == a || strings.HasSuffix(name, "."+a)
	})
}
