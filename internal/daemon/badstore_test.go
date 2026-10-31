package daemon_test

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/configstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// learnedV1 are the reports that a run under configV1 acks before the
// store goes bad.
var learnedV1 = []struct {
	q    string
	p    policy.Name
	addr string
}{
	{"example.com", "web", "192.0.2.50"},
	{"a.example.net", "web", "192.0.2.51"},
	{"x.ads.example", "ads", "2001:db8:1::7"},
}

// badStores are the stored files that do not load, with a part of the
// reason that each one gives.
var badStores = []struct {
	name   string
	damage func(t *testing.T, path string)
	reason string
}{
	{"missing", func(t *testing.T, path string) { mustDo(t, os.Remove(path)) }, "no applied configuration"},
	{"does not parse", func(t *testing.T, path string) {
		mustDo(t, os.WriteFile(path, []byte("[[policy]\nname = "), 0o600))
	}, "load config"},
	{"group writable", func(t *testing.T, path string) { mustDo(t, os.Chmod(path, 0o620)) }, "group or others can write"},
	{"others writable", func(t *testing.T, path string) { mustDo(t, os.Chmod(path, 0o602)) }, "group or others can write"},
}

func mustDo(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// A start with a stored file that does not load is Unenforced, acks
// nothing, and keeps the platform state and the snapshot of the last run,
// also across self-heals and interface changes. Apply then gives it a
// configuration, and the snapshot keeps the addresses of the last run.
func TestStartWithABadStoreIsUnenforced(t *testing.T) {
	for _, tt := range badStores {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := newHarness(t, configV1)
				for _, l := range learnedV1 {
					if err := h.observe(obs(l.q, l.addr)); err != nil {
						t.Fatalf("learn %s: %v", l.q, err)
					}
				}
				h.stop()
				tt.damage(t, h.store)
				before, snap := platformOf(h.world), readFile(t, h.snapshot)

				h = launch(t, h.spec)
				defer h.stop()
				wantUnconfigured(h, tt.reason)
				disturb(h)
				h.wantPlatform(before, "without a configuration")
				if !bytes.Equal(readFile(t, h.snapshot), snap) {
					t.Error("the snapshot changed without a configuration")
				}
				wantUnconfigured(h, tt.reason)
				applyKeepsTheSnapshot(h)
			})
		})
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// wantUnconfigured checks a daemon that has no configuration.
func wantUnconfigured(h *harness, reason string) {
	h.t.Helper()
	st := h.status()
	if st.State != daemon.StateUnenforced || len(st.Reasons) != 1 || !strings.Contains(st.Reasons[0], reason) {
		h.t.Fatalf("status = %v %q, want unenforced with %q", st.State, st.Reasons, reason)
	}
	if st.Config != (configstore.Digest{}) || st.Policies != 0 {
		h.t.Errorf("status = %+v, want no configuration", st)
	}
	for _, q := range []string{"example.com", "x.ads.example", "unrelated.test"} {
		if _, err := h.d.Observe(h.t.Context(), obs(q, "192.0.2.77")); !errors.Is(err, daemon.ErrUnenforced) {
			h.t.Errorf("Observe(%s) = %v, want ErrUnenforced", q, err)
		}
	}
}

// disturb runs the events that make a daemon converge: self-heals and
// interface changes.
func disturb(h *harness) {
	heal()
	h.inv.Set(en0, utun0)
	time.Sleep(daemon.InterfaceDebounce + time.Second)
	synctest.Wait()
	heal()
	h.inv.Set(en0)
	time.Sleep(daemon.InterfaceDebounce + time.Second)
	synctest.Wait()
}

func applyKeepsTheSnapshot(h *harness) {
	h.t.Helper()
	st, err := h.d.Apply(h.t.Context(), []byte(configV1))
	if err != nil {
		h.t.Fatalf("Apply: %v", err)
	}
	wantApplied(h.t, st, configV1)
	if st.Addrs != len(learnedV1) {
		h.t.Errorf("Addrs after Apply = %d, want %d from the snapshot", st.Addrs, len(learnedV1))
	}
	heal()
	h.wantState(daemon.StateReady)
	for _, l := range learnedV1 {
		a := host(l.addr)
		if !h.hasEntry(l.p, a) || !slices.Contains(h.saved(l.p), a.Addr()) {
			h.t.Errorf("after Apply: %s of %s is not in its table and the snapshot", l.addr, l.p)
		}
	}
	if err := h.observe(obs("example.com", "192.0.2.79")); err != nil {
		h.t.Errorf("Observe after Apply: %v", err)
	}
}
