package reconciletest

import (
	"slices"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// ContractTarget is a Backend under the contract test, with the external
// steps that the test needs.
type ContractTarget struct {
	Backend reconcile.Backend
	// Ruleset is a ruleset that Load accepts.
	Ruleset reconcile.Ruleset
	// Disable disables the firewall, as another tool would. After it, a
	// Load must be able to enable the firewall again.
	Disable func()
}

// contractStep is one step of a contract case.
type contractStep int

const (
	stepLoad contractStep = iota
	stepDisable
)

// RunBackendContract runs the cases of the reconcile.Backend contract
// for a disabled firewall. Each case gets a new target from newTarget.
// The fake Backend and the model of the pf Backend both run it, so the
// two cannot drift apart.
func RunBackendContract(t *testing.T, newTarget func(t *testing.T) ContractTarget) {
	t.Helper()
	tests := []struct {
		name   string
		steps  []contractStep
		loaded bool // Read and LoadedID report the ID of the ruleset
	}{
		{"loaded", []contractStep{stepLoad}, true},
		{"disabled after a load", []contractStep{stepLoad, stepDisable}, false},
		{"load after a disable", []contractStep{stepLoad, stepDisable, stepLoad}, true},
		{"disabled again after the second load", []contractStep{stepLoad, stepDisable, stepLoad, stepDisable}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tg := newTarget(t)
			for _, s := range tt.steps {
				tg.run(t, s)
			}
			want := ""
			if tt.loaded {
				want = tg.Ruleset.ID()
			}
			tg.check(t, want)
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
	case stepDisable:
		tg.Disable()
	default:
		t.Fatalf("unknown step %d", s)
	}
}

// check checks that Read and LoadedID report want, and that Read reports
// a voiding Problem exactly when want is "".
func (tg ContractTarget) check(t *testing.T, want string) {
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
	voids := slices.ContainsFunc(st.Problems, func(p reconcile.Problem) bool { return p.Voids })
	if voids != (want == "") {
		t.Errorf("voiding Problem = %v, want %v; Problems = %+v", voids, want == "", st.Problems)
	}
}
