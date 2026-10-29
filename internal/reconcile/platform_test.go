package reconcile_test

import (
	"slices"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

func TestInterfacePossible(t *testing.T) {
	const hw, tun = policy.ClassHardware, policy.ClassTunnel
	certain := reconcile.Uncertain("ppp0", hw, tun)
	certain.Class = tun
	tests := []struct {
		name  string
		iface reconcile.Interface
		want  []policy.Class
	}{
		{"zero value", reconcile.Interface{}, nil},
		{"certain class", reconcile.Interface{Name: "en0", Class: hw}, nil},
		{"certain class set after Uncertain", certain, nil},
		{"both classes, sorted, once each", reconcile.Uncertain("ppp0", tun, hw, tun), []policy.Class{hw, tun}},
		{"one class", reconcile.Uncertain("x", tun), []policy.Class{tun}},
		{"the zero Class is not a class", reconcile.Uncertain("x", 0, hw), []policy.Class{hw}},
		{"only the zero Class", reconcile.Uncertain("x", 0), nil},
		{"no class", reconcile.Uncertain("x"), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.iface.Possible(); !slices.Equal(got, tt.want) {
				t.Errorf("Possible() = %v, want %v", got, tt.want)
			}
		})
	}
	if u := reconcile.Uncertain("ppp0", hw); u.Name != "ppp0" || u.Class != 0 {
		t.Errorf("Uncertain gives name %q and class %v, want ppp0 and the zero Class", u.Name, u.Class)
	}
}
