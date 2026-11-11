package reconciletest

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// ContractTarget is a Backend under the contract test, with the external
// steps that the test needs.
type ContractTarget struct {
	Backend reconcile.Backend
	// Ruleset is a ruleset that Load accepts.
	Ruleset reconcile.Ruleset
	// Table is a table that Ruleset declares.
	Table policy.Name
	// Disable disables the firewall, as another tool would. It lets no
	// time pass. Each case disables the firewall soon after an enable, so
	// a Load after Disable and before the next Elapse must fail and leave
	// the firewall disabled.
	Disable func()
	// Elapse lets the rate limit of the enable pass: after it, a Load
	// enables the firewall again.
	Elapse func()
}

// contractStep is one step of a contract case.
type contractStep int

const (
	stepLoad        contractStep = iota
	stepLoadRefused              // a Load that must fail
	stepDisable
	stepElapse
	stepAdd // AddEntries of contractEntry to the Table
)

// contractEntry returns the entry that stepAdd adds.
func contractEntry() netip.Prefix { return netip.MustParsePrefix("203.0.113.7/32") }

// RunBackendContract runs the cases of the reconcile.Backend contract
// for a disabled firewall: what Read and LoadedID report while the
// firewall is disabled, a Load that the Backend refuses soon after an
// enable, a Load after the rate limit, and AddEntries while the firewall
// is disabled. It also runs a write with an invalid entry. Each case
// gets a new target from newTarget.
func RunBackendContract(t *testing.T, newTarget func(t *testing.T) ContractTarget) {
	t.Helper()
	t.Run("invalid entry is refused", func(t *testing.T) { runInvalidEntry(t, newTarget(t)) })
	tests := []struct {
		name  string
		steps []contractStep
		id    bool // Read and LoadedID report the ID of the Ruleset, else ""
		voids bool // Read reports a Problem that voids enforcement
	}{
		{"loaded", []contractStep{stepLoad}, true, false},
		{"disabled after a load", []contractStep{stepLoad, stepDisable}, false, true},
		{"load right after a disable is refused", []contractStep{stepLoad, stepDisable, stepLoadRefused}, false, true},
		{"later load enables", []contractStep{stepLoad, stepDisable, stepLoadRefused, stepElapse, stepLoad}, true, false},
		{"disabled again after the second load", []contractStep{stepLoad, stepDisable, stepElapse, stepLoad, stepDisable}, false, true},
		{"disabled keeps the tables", []contractStep{stepLoad, stepAdd, stepDisable}, false, true},
		{"add while disabled", []contractStep{stepLoad, stepDisable, stepAdd}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tg := newTarget(t)
			for _, s := range tt.steps {
				tg.run(t, s)
			}
			want := ""
			if tt.id {
				want = tg.Ruleset.ID()
			}
			tg.check(t, want, tt.voids, slices.Contains(tt.steps, stepAdd))
		})
	}
}

func (tg ContractTarget) run(t *testing.T, s contractStep) {
	t.Helper()
	switch s {
	case stepLoad:
		if err := tg.Backend.Load(t.Context(), tg.Ruleset); err != nil {
			t.Fatalf("Load: %v", err)
		}
	case stepLoadRefused:
		if err := tg.Backend.Load(t.Context(), tg.Ruleset); err == nil {
			t.Fatalf("Load right after a disable = nil, want an error")
		}
	case stepDisable:
		tg.Disable()
	case stepElapse:
		tg.Elapse()
	case stepAdd:
		if err := tg.Backend.AddEntries(t.Context(), tg.Table, []netip.Prefix{contractEntry()}); err != nil {
			t.Fatalf("AddEntries: %v", err)
		}
	default:
		t.Fatalf("unknown step %d", s)
	}
}

// check checks that Read and LoadedID report the ID want, that Read
// reports a voiding Problem exactly when voids is set, and that Read
// reports contractEntry in the Table when added is set.
func (tg ContractTarget) check(t *testing.T, want string, voids, added bool) {
	t.Helper()
	st, err := tg.Backend.Read(t.Context())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if st.Ruleset != want {
		t.Errorf("Read.Ruleset = %q, want %q", st.Ruleset, want)
	}
	id, err := tg.Backend.LoadedID(t.Context())
	if err != nil {
		t.Fatalf("LoadedID: %v", err)
	}
	if id != want {
		t.Errorf("LoadedID = %q, want %q", id, want)
	}
	if got := slices.ContainsFunc(st.Problems, func(p reconcile.Problem) bool { return p.Voids }); got != voids {
		t.Errorf("voiding Problem = %v, want %v; Problems = %+v", got, voids, st.Problems)
	}
	if added && !slices.Contains(st.Tables[tg.Table], contractEntry()) {
		t.Errorf("Read.Tables[%s] = %v, want %v in it", tg.Table, st.Tables[tg.Table], contractEntry())
	}
}

// runInvalidEntry checks that AddEntries and RemoveEntries refuse a
// batch with an invalid entry and change nothing, also for the valid
// entry in the same batch.
func runInvalidEntry(t *testing.T, tg ContractTarget) {
	tg.run(t, stepLoad)
	batch := []netip.Prefix{contractEntry(), {}}
	if err := tg.Backend.AddEntries(t.Context(), tg.Table, batch); err == nil {
		t.Error("AddEntries with an invalid entry = nil, want an error")
	}
	if tg.holds(t) {
		t.Errorf("Read.Tables[%s] holds %v after a refused AddEntries", tg.Table, contractEntry())
	}
	tg.run(t, stepAdd)
	if err := tg.Backend.RemoveEntries(t.Context(), tg.Table, batch); err == nil {
		t.Error("RemoveEntries with an invalid entry = nil, want an error")
	}
	if !tg.holds(t) {
		t.Errorf("Read.Tables[%s] lost %v after a refused RemoveEntries", tg.Table, contractEntry())
	}
}

// holds reports whether Read reports contractEntry in the Table.
func (tg ContractTarget) holds(t *testing.T) bool {
	t.Helper()
	st, err := tg.Backend.Read(t.Context())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return slices.Contains(st.Tables[tg.Table], contractEntry())
}
