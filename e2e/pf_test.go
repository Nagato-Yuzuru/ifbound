//go:build e2e && darwin

package e2e

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/pfbackend"
	"github.com/Nagato-Yuzuru/ifbound/pf"
)

// The tests of the pf package compare each operation with pfctl: the
// package writes and pfctl reads, or pfctl writes and the package reads.
// A field order that does not agree with the kernel shows here, not in
// the unit tests.

func openPf(t testing.TB) *pf.Handle {
	t.Helper()
	h, err := pf.Open()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return h
}

func pfEnabled(t testing.TB) bool {
	t.Helper()
	return strings.Contains(pfctl(t, "-s", "info"), "Status: Enabled")
}

func TestPfStatus(t *testing.T) {
	requireE2E(t)
	h := openPf(t)
	// "pfctl -d" disables pf and drops every token. When pf was enabled
	// before the test, enable it again with a new token.
	if pfEnabled(t) {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if out, err := exec.CommandContext(ctx, pfbackend.Path, "-E").CombinedOutput(); err != nil {
				t.Errorf("pfctl -E: %v: %s", err, out)
			}
		})
	}
	for _, enabled := range []bool{true, false} {
		if enabled {
			pfctl(t, "-E")
		} else {
			pfctl(t, "-d")
		}
		s, err := h.Status()
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		if want := pfEnabled(t); s.Running != want || s.Running != enabled {
			t.Errorf("Running = %v, pfctl -s info says enabled = %v, want %v", s.Running, want, enabled)
		}
	}
}
