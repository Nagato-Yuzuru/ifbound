package reconcile_test

import (
	"context"
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// failingLoad is a Backend whose Load always fails.
type failingLoad struct{ *reconciletest.Backend }

func (failingLoad) Load(context.Context, reconcile.Ruleset) error {
	return reconciletest.ErrInjected
}

// seed puts entries in the kernel tables, as an earlier ifboundd did.
func seed(t *testing.T, w *reconciletest.World, in map[policy.Name][]string) {
	t.Helper()
	for name, entries := range in {
		if err := w.Backend().AddEntries(t.Context(), name, prefixes(entries...)); err != nil {
			t.Fatal(err)
		}
	}
}

// An earlier ifboundd can have put a loopback or unspecified address in
// a table. Converge removes it before it loads the ruleset, so a Load
// that fails again and again does not keep lo0 blocked. The entry of a
// removed policy goes too: a loaded rule can still refer to its table.
func TestConvergeRemovesRefusedKernelEntryWhenLoadFails(t *testing.T) {
	f := newFixture(t, configV1)
	seed(t, f.world, map[policy.Name][]string{
		"web":  {"203.0.113.1/32", "127.0.0.1/32", "0.0.0.0/32"},
		"ads":  {"::1/128", "::/128"},
		"gone": {"127.0.0.53/32", "203.0.113.9/32"},
	})
	f.rec.Backend = failingLoad{f.world.Backend()}

	_, err := f.rec.Converge(t.Context(), f.inputs())

	if !errors.Is(err, reconciletest.ErrInjected) {
		t.Fatalf("Converge = %v, want ErrInjected", err)
	}
	checkTables(t, f.world, tables{
		"web":  {"198.51.100.0/24", "192.0.2.10/32", "203.0.113.1/32"},
		"ads":  {"2001:db8::/32"},
		"gone": {"203.0.113.9/32"},
	})
}

// A configured destination is the choice of the user, so the removal of
// refused entries keeps it, also when it is a loopback address. A refused
// learned-looking entry next to it goes, in one removal: the removal of
// undesired entries does not remove it again. A second pass writes
// nothing.
func TestConvergeKeepsConfiguredLoopbackDestination(t *testing.T) {
	f := newFixture(t, header+`
[[policy]]
name = "lo"
to = ["lo.example", "127.0.0.2", "::1", "127.0.0.0/8"]
only_via = ["en0"]
`)
	seed(t, f.world, map[policy.Name][]string{"lo": {"127.0.0.1/32", "::/128", "127.0.0.2/32"}})
	f.observe(t, "lo", "192.0.2.1")

	rep := f.converge(t)

	// The refused removal, the add, the Load, and the resolver entries of
	// lo.example and the Firefox canary.
	if rep.Writes != 5 {
		t.Errorf("first pass writes = %d, want 5", rep.Writes)
	}
	checkTables(t, f.world, tables{"lo": {"127.0.0.0/8", "127.0.0.2/32", "192.0.2.1/32", "::1/128"}})
	if rep := f.converge(t); rep.Writes != 0 {
		t.Errorf("second pass writes = %d, want 0", rep.Writes)
	}
}

// Adoption reads the kernel tables after a lost snapshot. It does not
// take an entry that blockable.New refuses, in any table.
func TestAdoptableSkipsRefusedEntries(t *testing.T) {
	f := newFixture(t, configV1)
	seed(t, f.world, map[policy.Name][]string{
		"web":  {"203.0.113.1/32", "127.0.0.1/32", "0.0.0.0/32"},
		"ads":  {"::1/128", "::/128"},
		"gone": {"127.0.0.53/32"},
	})

	got, err := f.rec.Adoptable(t.Context(), f.cfg.Policies)
	if err != nil {
		t.Fatalf("Adoptable: %v", err)
	}

	want := map[policy.Name][]blockable.Addr{"web": learned("203.0.113.1")}
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Errorf("Adoptable = %v, want %v", got, want)
	}
}

// zeroBook gives a valid learned address and the zero blockable.Addr,
// as a bug upstream could.
type zeroBook struct{}

func (zeroBook) Addrs(policy.Name) []blockable.Addr {
	return append(learned("192.0.2.1"), blockable.Addr{})
}

// The zero blockable.Addr comes from a bug upstream. Converge refuses it
// in the learned and in the host addresses before the Backend part
// writes anything: no refused kernel entry goes, no entry comes, and no
// ruleset loads.
func TestConvergeRefusesZeroAddrBeforeAnyBackendWrite(t *testing.T) {
	tests := []struct {
		name string
		set  func(in *reconcile.Inputs)
	}{
		{"book", func(in *reconcile.Inputs) { in.Book = zeroBook{} }},
		{"hosts", func(in *reconcile.Inputs) {
			in.Hosts = map[policy.Name][]blockable.Addr{"web": zeroBook{}.Addrs("web")}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, configV1)
			seed(t, f.world, map[policy.Name][]string{"web": {"127.0.0.1/32"}})
			in := f.inputs()
			tt.set(&in)

			rep, err := f.rec.Converge(t.Context(), in)

			if !errors.Is(err, blockable.ErrZero) {
				t.Fatalf("Converge = %v, want ErrZero", err)
			}
			if rep.Installed != "" {
				t.Errorf("Installed = %q, want empty", rep.Installed)
			}
			checkTables(t, f.world, tables{"web": {"127.0.0.1/32"}})
			if id := f.world.Ruleset().ID(); id != "" {
				t.Errorf("loaded ruleset = %q, want none", id)
			}
		})
	}
}

// AddObserved refuses the whole batch when it holds the zero
// blockable.Addr, and makes no Backend call.
func TestAddObservedRefusesZeroAddr(t *testing.T) {
	f := newFixture(t, configV1)
	before := f.world.Writes()

	err := f.rec.AddObserved(t.Context(), "web", zeroBook{}.Addrs("web"))

	if !errors.Is(err, blockable.ErrZero) {
		t.Fatalf("AddObserved = %v, want ErrZero", err)
	}
	if n := f.world.Writes() - before; n != 0 {
		t.Errorf("Backend writes = %d, want 0", n)
	}
	checkTables(t, f.world, tables{})
}
