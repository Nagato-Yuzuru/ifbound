package daemon_test

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/configstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// wantAttrs fails when e does not have each key of want with its value.
func wantAttrs(t *testing.T, e event, want map[string]any) {
	t.Helper()
	for k, w := range want {
		v, ok := e.attrs[k]
		if !ok {
			t.Errorf("%s event: no %s, want %v (attrs %v)", e.msg, k, w, e.attrs)
			continue
		}
		var eq bool
		switch w := w.(type) {
		case []string:
			got, isSlice := v.Any().([]string)
			eq = isSlice && slices.Equal(got, w)
		case int:
			eq = v.Kind() == slog.KindInt64 && v.Int64() == int64(w)
		default:
			eq = v.Any() == w
		}
		if !eq {
			t.Errorf("%s event: %s = %v, want %v", e.msg, k, v, w)
		}
	}
}

// wantNoAttrs fails when e has one of keys.
func wantNoAttrs(t *testing.T, e event, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if v, ok := e.attrs[k]; ok {
			t.Errorf("%s event: %s = %v, want none", e.msg, k, v)
		}
	}
}

// last returns the last event with the message msg.
func (h *harness) last(msg string) event {
	h.t.Helper()
	evs := h.logs.events(msg)
	if len(evs) == 0 {
		h.t.Fatalf("no %q event", msg)
	}
	return evs[len(evs)-1]
}

// Each convergence pass writes one event. Its level tells the outcome: a
// pass with kernel writes is info, a pass with nothing to do is debug,
// and a failed pass is a warning with the class and the text of the
// error. The same failure again is debug.
func TestConvergenceEvent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.wantState(daemon.StateReady)

		start := slices.DeleteFunc(h.logs.events("convergence"), func(e event) bool {
			return e.attrs[logattr.ConvergeTrigger].String() != logattr.TriggerStart
		})
		if len(start) != 1 {
			t.Fatalf("convergence events of the start = %d, want 1", len(start))
		}
		if start[0].level != slog.LevelInfo || start[0].attrs[logattr.ConvergeWrites].Int64() == 0 {
			t.Errorf("start pass: level %v, attrs %v; want info with writes", start[0].level, start[0].attrs)
		}
		wantAttrs(t, start[0], map[string]any{
			logattr.ConvergeTrigger: logattr.TriggerStart,
			// The self-test has not run yet.
			logattr.EnforcementState: logattr.StateDegraded,
		})
		wantNoAttrs(t, start[0], logattr.ErrorType, logattr.ExceptionMessage)
		if _, ok := start[0].attrs[logattr.ConvergeDurationMS]; !ok {
			t.Errorf("start pass has no %s", logattr.ConvergeDurationMS)
		}

		heal()
		idle := h.last("convergence")
		if idle.level != slog.LevelDebug {
			t.Errorf("idle pass level = %v, want debug", idle.level)
		}
		wantAttrs(t, idle, map[string]any{
			logattr.ConvergeTrigger:  logattr.TriggerSelfHeal,
			logattr.ConvergeWrites:   0,
			logattr.EnforcementState: logattr.StateReady,
		})

		h.world.FlushAll()
		h.failWrites()
		heal()
		failed := h.last("convergence")
		if failed.level != slog.LevelWarn {
			t.Errorf("failed pass level = %v, want warn", failed.level)
		}
		wantAttrs(t, failed, map[string]any{
			logattr.ConvergeTrigger:  logattr.TriggerSelfHeal,
			logattr.ConvergeWrites:   0,
			logattr.EnforcementState: logattr.StateUnenforced,
			logattr.ErrorType:        logattr.ErrorTypePlatform,
		})
		if msg := failed.attrs[logattr.ExceptionMessage].String(); !strings.Contains(msg, reconciletest.ErrInjected.Error()) {
			t.Errorf("%s = %q, want the injected error", logattr.ExceptionMessage, msg)
		}

		heal()
		again := h.last("convergence")
		if again.level != slog.LevelDebug {
			t.Errorf("repeated failure level = %v, want debug", again.level)
		}
		wantAttrs(t, again, map[string]any{logattr.ErrorType: logattr.ErrorTypePlatform})

		h.world.SetBeforeWrite(nil)
		heal()
		if ok := h.last("convergence"); ok.level != slog.LevelInfo {
			t.Errorf("recovered pass level = %v, want info", ok.level)
		}
		h.failWrites()
		h.world.FlushAll()
		heal()
		if f := h.last("convergence"); f.level != slog.LevelWarn {
			t.Errorf("failure after a recovery: level = %v, want warn", f.level)
		}
	})
}

// A convergence that ends pf states writes one event with the cause and
// the policies, besides its convergence event.
func TestStatesEndedEvent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.wantState(daemon.StateReady)
		before := len(h.logs.events("pf states ended"))

		// utun0 is new and both policies deny it.
		h.inv.Set(en0, utun0)
		time.Sleep(daemon.InterfaceDebounce)
		h.wantState(daemon.StateReady)

		evs := h.logs.events("pf states ended")[before:]
		if len(evs) != 1 {
			t.Fatalf("pf states ended events after the change = %d, want 1", len(evs))
		}
		if evs[0].level != slog.LevelInfo {
			t.Errorf("level = %v, want info", evs[0].level)
		}
		wantAttrs(t, evs[0], map[string]any{
			logattr.StatesCause: logattr.StatesCauseNarrowed,
			logattr.PolicyNames: []string{"web", "ads"},
		})
		wantAttrs(t, h.last("convergence"), map[string]any{logattr.ConvergeTrigger: logattr.TriggerInterfaces})
	})
}

// Each Apply writes one event with the digest of the running
// configuration and the state after it. A refused configuration is a
// warning, and the digest stays the one of the configuration that runs.
func TestApplyEvent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.wantState(daemon.StateReady)

		st, err := h.d.Apply(t.Context(), []byte(configV2))
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		evs := h.logs.events("apply")
		if len(evs) != 1 {
			t.Fatalf("apply events = %d, want 1", len(evs))
		}
		if evs[0].level != slog.LevelInfo {
			t.Errorf("level = %v, want info", evs[0].level)
		}
		wantAttrs(t, evs[0], map[string]any{
			logattr.ConfigDigest:         digestOf(configV2).String(),
			logattr.ConfigPreviousDigest: digestOf(configV1).String(),
			logattr.EnforcementState:     st.State.String(),
		})
		wantNoAttrs(t, evs[0], logattr.ErrorType, logattr.ExceptionMessage)
		wantAttrs(t, h.last("convergence"), map[string]any{logattr.ConvergeTrigger: logattr.TriggerConfig})

		if _, err := h.d.Apply(t.Context(), []byte("[[policy]]\nname = 1\n")); err == nil {
			t.Fatal("Apply of an invalid configuration: nil error")
		}
		refused := h.last("apply")
		if refused.level != slog.LevelWarn {
			t.Errorf("refused apply level = %v, want warn", refused.level)
		}
		wantAttrs(t, refused, map[string]any{
			logattr.ConfigDigest:         digestOf(configV2).String(),
			logattr.ConfigPreviousDigest: digestOf(configV2).String(),
			logattr.ErrorType:            logattr.ErrorTypeConfigInvalid,
		})
		if refused.attrs[logattr.ExceptionMessage].String() == "" {
			t.Errorf("refused apply has no %s", logattr.ExceptionMessage)
		}
	})
}

// The apply event tells each other outcome of Apply by its error.type.
func TestApplyEventErrorTypes(t *testing.T) {
	failStore := func(path string, data []byte, gid int) (policy.Config, configstore.Digest, error) {
		return policy.Config{}, configstore.Digest{}, errors.New("store config: disk full")
	}
	notDurable := func(path string, data []byte, gid int) (policy.Config, configstore.Digest, error) {
		cfg, dig, err := configstore.Store(path, data, gid)
		if err != nil {
			return cfg, dig, err
		}
		return cfg, dig, fmt.Errorf("store config: %w: injected", configstore.ErrNotDurable)
	}
	tests := []struct {
		name    string
		store   func(string, []byte, int) (policy.Config, configstore.Digest, error)
		left    bool // the caller leaves before the store
		level   slog.Level
		errType string
	}{
		{"store failed", failStore, false, slog.LevelWarn, logattr.ErrorTypeConfigFile},
		{"not durable", notDurable, false, slog.LevelWarn, logattr.ErrorTypeConfigNotDurable},
		// The caller left: nothing is degraded.
		{"caller left", nil, true, slog.LevelInfo, logattr.ErrorTypeCanceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				wantApplyEvent(t, tt.store, tt.left, tt.level, tt.errType)
			})
		})
	}
}

// wantApplyEvent runs one failing Apply of configV2 on a daemon with
// store, when it is not nil, and checks its one apply event. When left,
// the caller leaves before the store.
func wantApplyEvent(t *testing.T, store func(string, []byte, int) (policy.Config, configstore.Digest, error), left bool, level slog.Level, errType string) {
	t.Helper()
	h := launchHook(t, newSpec(t, configV1), func(d *daemon.Daemon) {
		if store != nil {
			d.SetStore(store)
		}
	})
	defer h.stop()
	h.wantState(daemon.StateReady)
	ctx := t.Context()
	if left {
		ctx = newEndsAtCheck()
	}
	if _, err := h.d.Apply(ctx, []byte(configV2)); err == nil {
		t.Fatal("Apply: nil error")
	}
	evs := h.logs.events("apply")
	if len(evs) != 1 {
		t.Fatalf("apply events = %d, want 1", len(evs))
	}
	if evs[0].level != level {
		t.Errorf("level = %v, want %v", evs[0].level, level)
	}
	wantAttrs(t, evs[0], map[string]any{logattr.ErrorType: errType})
	if evs[0].attrs[logattr.ExceptionMessage].String() == "" {
		t.Errorf("no %s", logattr.ExceptionMessage)
	}
}

// Each warm-up round writes one event with its number and the count of
// its names. The lookups of the harness find no address.
func TestWarmUpRoundEvent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.wantState(daemon.StateReady)

		evs := h.logs.events("warm-up round")
		if len(evs) != 1 {
			t.Fatalf("warm-up round events = %d, want 1", len(evs))
		}
		wantAttrs(t, evs[0], map[string]any{
			logattr.WarmUpRound:     1,
			logattr.WarmUpNameCount: 3,
		})
		empty, _ := evs[0].attrs[logattr.WarmUpEmpty].Any().([]string)
		slices.Sort(empty)
		if want := []string{"ads.example", "example.com", "example.net"}; !slices.Equal(empty, want) {
			t.Errorf("%s = %v, want %v", logattr.WarmUpEmpty, empty, want)
		}
		wantNoAttrs(t, evs[0], logattr.WarmUpCancelled, logattr.WarmUpUnproven, logattr.ErrorType)
	})
}
