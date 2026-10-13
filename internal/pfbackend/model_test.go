package pfbackend_test

// A model-based check: a sequence of Backend writes and external changes
// runs against the kernel model, and after each step Read and LoadedID
// must agree with a plain map model of the tables and the loaded ID.

import (
	"maps"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

var modelPool = pfx(
	"192.0.2.1/32", "192.0.2.2/32", "198.51.100.0/24", "10.0.0.0/8",
	"2001:db8::1/128", "2001:db8:1::/48",
)

var modelTables = []policy.Name{"bing", "doh", "extra", "stray"}

type tableModel map[policy.Name]map[netip.Prefix]bool

// modelRun is the state of one model-based run.
type modelRun struct {
	r        *rig
	rulesets []reconcile.Ruleset
	declared [][]policy.Name
	model    tableModel
	id       string
}

func runModel(t *testing.T, ops []byte) {
	t.Helper()
	m := &modelRun{
		r:        newRig(t),
		rulesets: []reconcile.Ruleset{compileRS(t, testPolicies), compileRS(t, testPolicies+otherPolicy)},
		declared: [][]policy.Name{{"bing", "doh"}, {"bing", "doh", "extra"}},
		model:    tableModel{},
	}
	for i := 0; i+2 < len(ops); i += 3 {
		m.r.clk.t = m.r.clk.t.Add(11 * time.Second) // never hit the rate limit
		if err := m.step(t, ops[i]%7, ops[i+1], ops[i+2]); err != nil {
			t.Fatalf("step %d (op %d): %v", i/3, ops[i]%7, err)
		}
		checkModel(t, m.r, i/3, m.model, m.id)
	}
}

// step runs one Backend write (ops 0..3) or one external change (4..6),
// and changes the model the same way.
func (m *modelRun) step(t *testing.T, op, arg, mask byte) error {
	t.Helper()
	ctx := t.Context()
	tb, set := modelTables[int(arg)%len(modelTables)], subset(mask)
	switch op {
	case 0:
		if m.model[tb] == nil {
			m.model[tb] = map[netip.Prefix]bool{}
		}
		for _, p := range set {
			m.model[tb][p] = true
		}
		return m.r.b.AddEntries(ctx, tb, set)
	case 1:
		for _, p := range set {
			delete(m.model[tb], p)
		}
		return m.r.b.RemoveEntries(ctx, tb, set)
	case 2:
		delete(m.model, tb)
		return m.r.b.DropTable(ctx, tb)
	case 3:
		n := int(arg) % 2
		for _, d := range m.declared[n] {
			if m.model[d] == nil {
				m.model[d] = map[netip.Prefix]bool{}
			}
		}
		m.id = m.rulesets[n].ID()
		return m.r.b.Load(ctx, m.rulesets[n])
	case 4: // another tool flushes the rules of the anchor
		m.r.k.rules[ifb] = nil
		m.id = ""
	case 5: // another tool flushes a table
		if kt := m.r.k.tables[ifb][string(tb)]; kt != nil {
			clear(kt)
			clear(m.model[tb])
		}
	case 6: // another tool disables pf
		m.r.k.enabled, m.r.k.refs = false, nil
		m.id = ""
	}
	return nil
}

func subset(mask byte) []netip.Prefix {
	var out []netip.Prefix
	for i, p := range modelPool {
		if mask&(1<<i) != 0 {
			out = append(out, p)
		}
	}
	return out
}

func checkModel(t *testing.T, r *rig, step int, model tableModel, id string) {
	t.Helper()
	st := mustRead(t, r)
	if st.Ruleset != id {
		t.Fatalf("step %d: Read.Ruleset = %q, want %q", step, st.Ruleset, id)
	}
	if got := mustID(t, r); got != id {
		t.Fatalf("step %d: LoadedID = %q, want %q", step, got, id)
	}
	if got, want := slices.Sorted(maps.Keys(st.Tables)), slices.Sorted(maps.Keys(model)); !slices.Equal(got, want) {
		t.Fatalf("step %d: tables = %v, want %v", step, got, want)
	}
	for name, set := range model {
		want := slices.SortedFunc(maps.Keys(set), netip.Prefix.Compare)
		if got := sorted(st.Tables[name]); !slices.Equal(got, want) {
			t.Fatalf("step %d: table %s = %v, want %v", step, name, got, want)
		}
	}
}

func TestRandomSequencesMatchAModel(t *testing.T) {
	for seed := range uint64(200) {
		rng := rand.New(rand.NewPCG(seed, 0x1f0bd))
		ops := make([]byte, 3*40)
		for i := range ops {
			ops[i] = byte(rng.UintN(256))
		}
		t.Run("", func(t *testing.T) { runModel(t, ops) })
	}
}

func FuzzSequencesMatchAModel(f *testing.F) {
	f.Add([]byte{3, 0, 0, 0, 0, 0x3f, 1, 0, 0x05, 4, 0, 0, 3, 1, 0})
	f.Add([]byte{0, 3, 0xff, 2, 3, 0, 6, 0, 0, 3, 0, 0, 5, 1, 0})
	f.Fuzz(func(t *testing.T, ops []byte) {
		if len(ops) > 3*64 {
			t.Skip()
		}
		runModel(t, ops)
	})
}
