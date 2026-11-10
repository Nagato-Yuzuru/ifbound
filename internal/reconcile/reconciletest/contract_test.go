package reconciletest_test

import (
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

func TestBackendContract(t *testing.T) {
	rs, err := reconciletest.Compiler{}.Compile([]policy.Policy{{Name: "web"}}, nil, reconcile.Accounts{})
	if err != nil {
		t.Fatal(err)
	}
	reconciletest.RunBackendContract(t, func(*testing.T) reconciletest.ContractTarget {
		w := reconciletest.NewWorld()
		return reconciletest.ContractTarget{Backend: w.Backend(), Ruleset: rs, Disable: w.DisableFirewall}
	})
}
