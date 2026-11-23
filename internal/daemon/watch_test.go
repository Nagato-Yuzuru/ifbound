package daemon_test

import (
	"context"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/daemon/core"
	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// repairs records the time of each convergence whose trigger is
// firewall_changed, from the time of start. Then it calls after, when
// after is not nil: the event comes after the end of the exclusive
// section of the convergence.
type repairs struct {
	start time.Time
	after func()
	mu    sync.Mutex
	at    []time.Duration
}

func (r *repairs) onLog(e event) {
	if e.msg != "convergence" || e.attrs[logattr.ConvergeTrigger].String() != logattr.TriggerFirewallChanged {
		return
	}
	r.mu.Lock()
	r.at = append(r.at, time.Since(r.start))
	r.mu.Unlock()
	if r.after != nil {
		r.after()
	}
}

func (r *repairs) times() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.at)
}

// launchWatched runs a daemon on s, and records its repairs from the
// start. after is as in repairs.
func launchWatched(t *testing.T, s harnessSpec, after func()) (*harness, *repairs) {
	t.Helper()
	r := &repairs{start: time.Now(), after: after}
	s.onLog = r.onLog
	return launch(t, s), r
}

// loadedID returns the ID of the ruleset that the World has in effect.
func (h *harness) loadedID() string {
	h.t.Helper()
	id, err := h.world.Backend().LoadedID(h.t.Context())
	if err != nil {
		h.t.Fatalf("LoadedID: %v", err)
	}
	return id
}

// A change of another program that breaks the entry to the ruleset is
// found at the next poll, and its convergence loads the ruleset again.
// The poll comes before the first self-heal, so only the watcher can
// repair it in time.
func TestWatcherRepairsAnExternalChange(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(w *reconciletest.World)
	}{
		{"FlushAll", (*reconciletest.World).FlushAll},
		{"DisableFirewall", (*reconciletest.World).DisableFirewall},
		{"ExternalLoad", func(w *reconciletest.World) { w.ExternalLoad([]byte("other\n")) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h, r := launchWatched(t, newSpec(t, configV1), nil)
				defer h.stop()
				h.wantState(daemon.StateReady)
				installed := h.loadedID()
				tt.change(h.world)
				if id := h.loadedID(); id == installed {
					t.Fatalf("LoadedID after the change = %q, want another ID", id)
				}
				time.Sleep(daemon.WatchPeriod)
				synctest.Wait()
				if id := h.loadedID(); id != installed {
					t.Errorf("LoadedID one WatchPeriod after the change = %q, want %q", id, installed)
				}
				if got, want := r.times(), []time.Duration{daemon.WatchPeriod}; !slices.Equal(got, want) {
					t.Errorf("repair times = %v, want %v", got, want)
				}
				if n := len(h.logs.events("firewall changed outside ifbound")); n != 1 {
					t.Errorf("%d firewall change events, want 1", n)
				}
				h.wantState(daemon.StateReady)
			})
		})
	}
}

// The Loads of the daemon itself, after Apply and after an interface
// change, do not look like a firewall change.
func TestWatcherIgnoresOwnLoads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, r := launchWatched(t, newSpec(t, configV1), nil)
		defer h.stop()
		h.wantState(daemon.StateReady)
		writes := h.world.Writes()
		if _, err := h.d.Apply(t.Context(), []byte(configV2)); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		h.inv.Set(en0, utun0)
		// Many polls, fast ones too, and two self-heals.
		time.Sleep(2*daemon.SelfHealInterval + time.Second)
		synctest.Wait()
		if h.world.Writes() == writes {
			t.Fatal("the daemon wrote nothing; the test proves nothing")
		}
		if got := r.times(); len(got) != 0 {
			t.Errorf("repair times = %v, want none", got)
		}
		if n := len(h.logs.events("firewall changed outside ifbound")); n != 0 {
			t.Errorf("%d firewall change events, want 0", n)
		}
	})
}

// A program that breaks the entry again after each repair gets repairs
// that wait longer each time. The order of the waits is in the tests of
// core; this test checks that the daemon keeps to the first ones.
func TestWatcherBacksOffRepeatedRepairs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSpec(t, configV1)
		// The other program flushes the ruleset again after each repair.
		h, r := launchWatched(t, s, s.world.FlushAll)
		defer h.stop()
		h.wantState(daemon.StateReady)
		h.world.FlushAll()
		// Up to the first self-heal: the repairs at 1 s (at once), and at
		// 3 s (the poll at 2 s finds the flush, and the repair waits
		// RepairBackoffMin). The poll at 4 s finds the next flush, and its
		// repair waits 2 s.
		time.Sleep(daemon.SelfHealInterval - time.Millisecond)
		synctest.Wait()
		want := []time.Duration{daemon.WatchPeriod, 2*daemon.WatchPeriod + core.RepairBackoffMin}
		if got := r.times(); !slices.Equal(got, want) {
			t.Errorf("repair times = %v, want %v", got, want)
		}
		waits := h.logs.events("firewall changed outside ifbound")
		var ms []int64
		for _, e := range waits {
			ms = append(ms, e.attrs[logattr.BackoffMS].Int64())
		}
		if want := []int64{0, 1000, 2000}; !slices.Equal(ms, want) {
			t.Errorf("%s of the firewall change events = %v, want %v", logattr.BackoffMS, ms, want)
		}
	})
}

// digestFails is a Backend whose Digest fails while fail is set.
type digestFails struct {
	*reconciletest.Backend
	fail *atomic.Bool
}

func (b digestFails) Digest(ctx context.Context) (reconcile.Digest, error) {
	if b.fail.Load() {
		return reconcile.Digest{}, reconciletest.ErrInjected
	}
	return b.Backend.Digest(ctx)
}

// A failed poll makes the state Degraded with a reason, and logs one
// warning for the series. The next good poll makes the state Ready
// again.
func TestWatcherFailureDegrades(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSpec(t, configV1)
		var fail atomic.Bool
		s.be = digestFails{Backend: s.world.Backend(), fail: &fail}
		h := launch(t, s)
		defer h.stop()
		h.wantState(daemon.StateReady)
		fail.Store(true)
		time.Sleep(3 * daemon.WatchPeriod)
		st := h.wantState(daemon.StateDegraded)
		if !slices.ContainsFunc(st.Reasons, func(r string) bool { return strings.Contains(r, "the watch of the firewall failed") }) {
			t.Errorf("reasons = %q, want the failed watch", st.Reasons)
		}
		warns := h.logs.events("watch of the firewall failed")
		if len(warns) != 1 {
			t.Fatalf("%d watch warnings, want 1", len(warns))
		}
		wantAttrs(t, warns[0], map[string]any{logattr.ErrorType: logattr.ErrorTypePlatform})
		fail.Store(false)
		time.Sleep(daemon.WatchPeriod)
		h.wantState(daemon.StateReady)
	})
}
