package reconcile_test

import (
	"net/netip"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// ConvergeResolver writes only resolver entries. A Reconciler with only a
// Resolver can run it, so it never reaches a Backend.
func TestConvergeResolverTouchesOnlyTheResolver(t *testing.T) {
	w := reconciletest.NewWorld()
	d, err := policy.ParseDomain("corp.example")
	if err != nil {
		t.Fatal(err)
	}
	listen := netip.MustParseAddrPort("127.0.0.1:53")
	r := reconcile.Reconciler{Resolver: w.Resolver()}
	if _, err := r.ConvergeResolver(t.Context(), reconcile.Inputs{Apexes: []policy.Domain{d}, Listen: listen}); err != nil {
		t.Fatal(err)
	}
	if got := len(w.ResolverEntries()); got != 2 {
		t.Fatalf("entries after a convergence with one apex = %d, want the apex and the canary", got)
	}
	rep, err := r.ConvergeResolver(t.Context(), reconcile.Inputs{})
	if err != nil {
		t.Fatal(err)
	}
	if got := w.ResolverEntries(); len(got) != 0 || rep.Writes != 2 {
		t.Errorf("after the empty convergence: entries %v, writes %d; want none and 2", got, rep.Writes)
	}
	if w.Ruleset().ID() != "" || len(w.Tables()) != 0 {
		t.Errorf("ConvergeResolver changed the Backend: ruleset %q tables %v", w.Ruleset().ID(), w.Tables())
	}
}
