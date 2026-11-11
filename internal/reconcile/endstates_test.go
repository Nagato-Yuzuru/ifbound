package reconcile_test

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/pfrules"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// The configurations name their interfaces, so the pf ruleset stays the
// same when these interfaces appear or go away. Only the end of the
// states can then make the change hold for an existing connection.

// onlyConfig allows each policy on one named interface.
const onlyConfig = header + `
[[policy]]
name = "vpn"
to = ["192.0.2.10", "192.0.2.11"]
only_via = ["utun4"]

[[policy]]
name = "lan"
to = ["198.51.100.7"]
only_via = ["en0"]
`

// denyConfig has a deny_via class that also names utun7, so the ruleset
// lists utun7 before it appears.
const denyConfig = header + `
[[policy]]
name = "novpn"
to = ["203.0.113.5"]
deny_via = ["@tunnel", "utun7"]

[[policy]]
name = "wifi"
to = ["198.51.100.8"]
deny_via = ["en1"]
`

var (
	utun4 = reconcile.Interface{Name: "utun4", Class: policy.ClassTunnel}
	utun7 = reconcile.Interface{Name: "utun7", Class: policy.ClassTunnel}
	ppp0  = reconcile.Uncertain("ppp0", policy.ClassTunnel)
)

type statesFixture struct {
	world *reconciletest.World
	inv   *reconciletest.Inventory
	rec   reconcile.Reconciler
	in    reconcile.Inputs
	// last is the report of the last convergence.
	last reconcile.Report
}

// newStatesFixture uses the pf Compiler, so "the ruleset stays the same"
// is the real ruleset text.
func newStatesFixture(t *testing.T, cfgText string, ifaces ...reconcile.Interface) *statesFixture {
	t.Helper()
	w := reconciletest.NewWorld()
	f := &statesFixture{world: w, inv: reconciletest.NewInventory(ifaces...)}
	f.rec = reconcile.Reconciler{Compiler: pfrules.Compiler{}, Backend: w.Backend(), Resolver: w.Resolver(), Inventory: f.inv}
	f.in = reconcile.Inputs{Policies: parse(t, cfgText).Policies, Book: noAddrs{}}
	f.converge(t)
	return f
}

func (f *statesFixture) converge(t *testing.T) {
	t.Helper()
	rep, err := f.rec.Converge(t.Context(), f.in)
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	f.last = rep
}

// change sets the interfaces, converges, and returns the entries whose
// states ended during the convergence. It fails when the convergence
// loads a ruleset.
func (f *statesFixture) change(t *testing.T, ifaces ...reconcile.Interface) []netip.Prefix {
	t.Helper()
	mark, id := len(f.world.EndedStates()), f.world.Ruleset().ID()
	f.inv.Set(ifaces...)
	f.converge(t)
	if got := f.world.Ruleset().ID(); got != id {
		t.Fatalf("the ruleset changed; the test needs a change that keeps it")
	}
	return f.world.EndedStates()[mark:]
}

// TestConvergeEndsStatesWhenInterfaceChangeNarrows checks that an
// interface change that keeps the ruleset ends the states of exactly the
// policies that it affects, once, and reports these policies.
func TestConvergeEndsStatesWhenInterfaceChangeNarrows(t *testing.T) {
	en2 := reconcile.Interface{Name: "en2", Class: policy.ClassHardware}
	tests := []struct {
		name          string
		config        string
		before, after []reconcile.Interface
		want          []netip.Prefix
		narrowed      []policy.Name
	}{
		// The states of vpn on utun4 can continue on en0. lan denies
		// no interface now.
		{"allowed interface goes away", onlyConfig, []reconcile.Interface{en0, utun4}, []reconcile.Interface{en0}, prefixes("192.0.2.10/32", "192.0.2.11/32"), []policy.Name{"vpn"}},
		// The states of lan on en0 can move to utun4. vpn denies only
		// en0, as before.
		{"denied interface appears", onlyConfig, []reconcile.Interface{en0}, []reconcile.Interface{en0, utun4}, prefixes("198.51.100.7/32"), []policy.Name{"lan"}},
		// The states of novpn on en0 can move to utun7. wifi allows
		// utun7.
		{"deny_via class gets a listed interface", denyConfig, []reconcile.Interface{en0}, []reconcile.Interface{en0, utun7}, prefixes("203.0.113.5/32"), []policy.Name{"novpn"}},
		// The glob selects utun4. en0 leaves the allowed set while
		// utun4 is denied.
		{"glob denies a current interface", header + `
[[policy]]
name = "noutun"
to = ["203.0.113.6"]
deny_via = ["utun*", "en1"]
`, []reconcile.Interface{en0, utun4}, []reconcile.Interface{utun4}, prefixes("203.0.113.6/32"), []policy.Name{"noutun"}},
		// The class of ppp0 is uncertain, and deny_via denies an
		// interface that can have the class. en0 leaves the allowed set
		// while ppp0 is denied.
		{"uncertain class denies a current interface", header + `
[[policy]]
name = "novpn"
to = ["203.0.113.5"]
deny_via = ["@tunnel", "en1"]
`, []reconcile.Interface{en0, ppp0}, []reconcile.Interface{ppp0}, prefixes("203.0.113.5/32"), []policy.Name{"novpn"}},
		{"interface that all policies allow appears", denyConfig, []reconcile.Interface{en0}, []reconcile.Interface{en0, en2}, nil, nil},
		{"denied interface goes away", denyConfig, []reconcile.Interface{en0, utun7}, []reconcile.Interface{en0}, nil, nil},
		{"same interfaces", onlyConfig, []reconcile.Interface{en0, utun4}, []reconcile.Interface{en0, utun4}, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newStatesFixture(t, tt.config, tt.before...)
			if got := f.change(t, tt.after...); !slices.Equal(got, tt.want) {
				t.Errorf("ended states = %v, want %v", got, tt.want)
			}
			if !slices.Equal(f.last.Narrowed, tt.narrowed) {
				t.Errorf("Report.Narrowed = %v, want %v", f.last.Narrowed, tt.narrowed)
			}
			if again := f.change(t, tt.after...); len(again) != 0 {
				t.Errorf("a second pass ended states %v, want none", again)
			}
		})
	}
}

// TestConvergeEndsStatesForUncertainClass checks the safe direction of an
// uncertain class: a deny_via class denies an interface that can have
// the class, so the interface joins the denied set when it appears. No
// selector names the interface.
func TestConvergeEndsStatesForUncertainClass(t *testing.T) {
	f := newStatesFixture(t, header+`
[[policy]]
name = "novpn"
to = ["203.0.113.5"]
deny_via = ["@tunnel"]
`, en0, ppp0)
	// The class keeps ppp0 in the rules, so the ruleset stays the same
	// when en0 leaves the allowed set.
	if got, want := f.change(t, ppp0), prefixes("203.0.113.5/32"); !slices.Equal(got, want) {
		t.Errorf("ended states = %v, want %v", got, want)
	}
}

// TestConvergeLoadEndsStatesOnce checks that a change that also changes
// the ruleset ends the states through the Load only.
func TestConvergeLoadEndsStatesOnce(t *testing.T) {
	f := newStatesFixture(t, header+`
[[policy]]
name = "vpn"
to = ["192.0.2.10"]
only_via = ["@tunnel"]
`, en0, utun4)
	mark, id := len(f.world.EndedStates()), f.world.Ruleset().ID()
	f.inv.Set(en0)
	f.converge(t)
	if f.world.Ruleset().ID() == id {
		t.Fatalf("the ruleset did not change")
	}
	if got, want := f.world.EndedStates()[mark:], prefixes("192.0.2.10/32"); !slices.Equal(got, want) {
		t.Errorf("ended states = %v, want %v", got, want)
	}
}

// TestConvergeEndsStatesAgainAfterFailure checks that a failed end of the
// states keeps the old verdict, so the next pass ends them.
func TestConvergeEndsStatesAgainAfterFailure(t *testing.T) {
	f := newStatesFixture(t, onlyConfig, en0, utun4)
	first := f.world.Writes() + 1
	f.world.SetBeforeWrite(func(n int) error {
		if n == first {
			return reconciletest.ErrInjected
		}
		return nil
	})
	f.inv.Set(en0)
	if _, err := f.rec.Converge(t.Context(), f.in); !errors.Is(err, reconciletest.ErrInjected) {
		t.Fatalf("Converge = %v, want the injected fault", err)
	}
	if got, want := f.change(t, en0), prefixes("192.0.2.10/32", "192.0.2.11/32"); !slices.Equal(got, want) {
		t.Errorf("ended states after the failure = %v, want %v", got, want)
	}
}

// TestConvergeFirstPassEndsStatesOfDenyingPolicies checks a Reconciler
// without an earlier verdict, as after a restart, on a loaded ruleset: a
// policy that denies a current interface ends its states once, because
// a state can have moved there while no Reconciler watched. A policy
// that denies no current interface keeps its states.
func TestConvergeFirstPassEndsStatesOfDenyingPolicies(t *testing.T) {
	f := newStatesFixture(t, onlyConfig+`
[[policy]]
name = "wifi"
to = ["198.51.100.8"]
deny_via = ["en1"]
`, en0, utun4)
	fresh := reconcile.Reconciler{Compiler: pfrules.Compiler{}, Backend: f.world.Backend(), Resolver: f.world.Resolver(), Inventory: f.inv}
	f.rec = fresh
	mark := len(f.world.EndedStates())
	f.converge(t)
	// vpn denies en0, lan denies utun4, and wifi denies no current
	// interface.
	want := prefixes("192.0.2.10/32", "192.0.2.11/32", "198.51.100.7/32")
	if got := f.world.EndedStates()[mark:]; !slices.Equal(got, want) {
		t.Errorf("ended states = %v, want %v", got, want)
	}
	if again := f.change(t, en0, utun4); len(again) != 0 {
		t.Errorf("a second pass ended states %v, want none", again)
	}
}

// TestConvergeCopyStartsAgain checks that a copy of a Reconciler does not
// use the verdicts of the original. The copy then converges as a new
// Reconciler: the policies that deny a current interface end their
// states.
func TestConvergeCopyStartsAgain(t *testing.T) {
	f := newStatesFixture(t, onlyConfig, en0, utun4)
	cp := f.rec
	mark := len(f.world.EndedStates())
	if _, err := cp.Converge(t.Context(), f.in); err != nil {
		t.Fatalf("Converge of the copy: %v", err)
	}
	want := prefixes("192.0.2.10/32", "192.0.2.11/32", "198.51.100.7/32")
	if got := f.world.EndedStates()[mark:]; !slices.Equal(got, want) {
		t.Errorf("ended states = %v, want %v", got, want)
	}
}

// TestConvergeEndsNewEntryOnce checks that an entry that the pass adds
// to a narrowed policy ends its states once: the add ends them, and the
// end of the old states does not repeat it.
func TestConvergeEndsNewEntryOnce(t *testing.T) {
	f := newStatesFixture(t, onlyConfig, en0, utun4)
	f.in.Hosts = map[policy.Name][]blockable.Addr{"vpn": learned("192.0.2.99")}
	got := f.change(t, en0)
	slices.SortFunc(got, netip.Prefix.Compare)
	if want := prefixes("192.0.2.10/32", "192.0.2.11/32", "192.0.2.99/32"); !slices.Equal(got, want) {
		t.Errorf("ended states = %v, want %v, each once", got, want)
	}
}

// noSelection is the pf Compiler without the selection: the ruleset text
// and ID stay the same, but Ruleset.Selected reports no policy.
type noSelection struct{}

func (noSelection) Compile(policies []policy.Policy, ifaces []reconcile.Interface, accounts reconcile.Accounts) (reconcile.Ruleset, error) {
	rs, err := pfrules.Compiler{}.Compile(policies, ifaces, accounts)
	if err != nil {
		return reconcile.Ruleset{}, err
	}
	return reconcile.NewRuleset(rs.Body(), rs.Problems()...), nil
}

// TestConvergeWithoutSelectionFailsClosed checks that a policy without a
// selection denies every current interface: an interface that appears
// narrows it. With the selection, the same change narrows nothing.
func TestConvergeWithoutSelectionFailsClosed(t *testing.T) {
	en2 := reconcile.Interface{Name: "en2", Class: policy.ClassHardware}
	// wifi denies en1 only, and en1 is never present.
	cfg := header + `
[[policy]]
name = "wifi"
to = ["198.51.100.8"]
deny_via = ["en1"]
`
	tests := []struct {
		name     string
		compiler reconcile.Compiler
		want     []netip.Prefix
		narrowed []policy.Name
	}{
		{"no selection", noSelection{}, prefixes("198.51.100.8/32"), []policy.Name{"wifi"}},
		{"selection", pfrules.Compiler{}, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newStatesFixture(t, cfg, en0)
			f.rec = reconcile.Reconciler{Compiler: tt.compiler, Backend: f.world.Backend(), Resolver: f.world.Resolver(), Inventory: f.inv}
			// The first pass of the new Reconciler records its verdicts.
			f.converge(t)
			if got := f.change(t, en0, en2); !slices.Equal(got, tt.want) {
				t.Errorf("ended states = %v, want %v", got, tt.want)
			}
			if !slices.Equal(f.last.Narrowed, tt.narrowed) {
				t.Errorf("Report.Narrowed = %v, want %v", f.last.Narrowed, tt.narrowed)
			}
		})
	}
}

// bookOf is an AddrSource with fixed addresses.
type bookOf map[policy.Name][]blockable.Addr

func (b bookOf) Addrs(name policy.Name) []blockable.Addr { return b[name] }

// TestConvergeAddOnlyEndsStatesToEveryKeptEntry checks that an add-only
// pass that ends the states of a narrowed policy ends them to every entry
// that its table keeps. The book of that pass is empty, so an entry that
// the pass does not desire can be an acknowledged address. The next pass
// with the book finds no narrowing, so it does not end these states. The
// entries whose states end in the two passes together are the same as
// without the add-only pass.
func TestConvergeAddOnlyEndsStatesToEveryKeptEntry(t *testing.T) {
	book := bookOf{"vpn": learned("192.0.2.99")}
	tests := []struct {
		name          string
		fresh         bool
		addOnly       bool
		before, after []reconcile.Interface
		want          []netip.Prefix
	}{
		// After a restart, vpn denies en0 and lan denies utun4.
		{"new Reconciler", true, false, []reconcile.Interface{en0, utun4}, []reconcile.Interface{en0, utun4},
			prefixes("192.0.2.10/32", "192.0.2.11/32", "192.0.2.99/32", "198.51.100.7/32")},
		{"new Reconciler, add-only pass first", true, true, []reconcile.Interface{en0, utun4}, []reconcile.Interface{en0, utun4},
			prefixes("192.0.2.10/32", "192.0.2.11/32", "192.0.2.99/32", "198.51.100.7/32")},
		// The states of vpn on utun4 can continue on en0.
		{"allowed interface goes away", false, false, []reconcile.Interface{en0, utun4}, []reconcile.Interface{en0},
			prefixes("192.0.2.10/32", "192.0.2.11/32", "192.0.2.99/32")},
		{"allowed interface goes away, add-only pass first", false, true, []reconcile.Interface{en0, utun4}, []reconcile.Interface{en0},
			prefixes("192.0.2.10/32", "192.0.2.11/32", "192.0.2.99/32")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newStatesFixture(t, onlyConfig, tt.before...)
			f.in.Book = book
			f.converge(t)
			if tt.fresh {
				f.rec = reconcile.Reconciler{Compiler: pfrules.Compiler{}, Backend: f.world.Backend(), Resolver: f.world.Resolver(), Inventory: f.inv}
			}
			mark, id := len(f.world.EndedStates()), f.world.Ruleset().ID()
			f.inv.Set(tt.after...)
			if tt.addOnly {
				f.in = reconcile.Inputs{Policies: f.in.Policies, Book: noAddrs{}, AddOnly: true}
				f.converge(t)
				f.in.Book, f.in.AddOnly = book, false
			}
			f.converge(t)
			if f.world.Ruleset().ID() != id {
				t.Fatalf("the ruleset changed; the test needs a change that keeps it")
			}
			got := f.world.EndedStates()[mark:]
			slices.SortFunc(got, netip.Prefix.Compare)
			if !slices.Equal(got, tt.want) {
				t.Errorf("ended states = %v, want %v, each once", got, tt.want)
			}
		})
	}
}
