package daemon_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/configstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// configUnreachable has an upstream inside a policy that allows no
// interface: it fails policy.Config.CheckUpstreams.
const configUnreachable = configV1 + `
[[policy]]
name = "dark"
to = ["1.1.1.0/24"]
only_via = []
`

// configWarned has an upstream that ifbound-dns reaches only through en0:
// it passes the check with a warning.
const configWarned = configV1 + `
[[policy]]
name = "vpn"
to = ["1.1.1.0/24"]
only_via = ["en0"]
`

// invalidConfigs are configurations that Apply must refuse.
var invalidConfigs = []struct {
	name string
	text string
}{
	{"does not parse", "[dns\nlisten = 1\n"},
	{"unknown key", configV1 + "\nbogus = 1\n"},
	{"upstream unreachable", configUnreachable},
}

func digestOf(text string) configstore.Digest { return sha256.Sum256([]byte(text)) }

func (h *harness) storedText() string {
	h.t.Helper()
	data, err := os.ReadFile(h.store)
	if err != nil {
		h.t.Fatal(err)
	}
	return string(data)
}

// platformState is everything of the World that a daemon can write.
type platformState struct {
	Writes   int
	Ruleset  string
	Tables   map[policy.Name][]netip.Prefix
	Resolver []reconcile.ResolverEntry
}

func platformOf(w *reconciletest.World) platformState {
	return platformState{Writes: w.Writes(), Ruleset: w.Ruleset().ID(), Tables: w.Tables(), Resolver: w.ResolverEntries()}
}

func (h *harness) wantPlatform(want platformState, when string) {
	h.t.Helper()
	if got := platformOf(h.world); !reflect.DeepEqual(got, want) {
		h.t.Errorf("%s: platform changed:\n got %+v\nwant %+v", when, got, want)
	}
}

// wantApplied checks the Status that Apply returned for a converged
// configuration. A probe under the new configuration has not run yet, so
// the self-test can be the one reason.
func wantApplied(t *testing.T, st daemon.Status, text string) {
	t.Helper()
	notRun := st.State == daemon.StateDegraded && len(st.Reasons) == 1 && strings.HasPrefix(st.Reasons[0], notConnected)
	if st.State != daemon.StateReady && !notRun {
		t.Errorf("status after Apply = %v %q, want ready or the self-test that has not run", st.State, st.Reasons)
	}
	if st.Config != digestOf(text) {
		t.Errorf("Status.Config after Apply = %v, want the digest of the applied text", st.Config)
	}
}

// wantUnchanged checks that a refused Apply changed nothing: not the
// stored file, not the platform, not the running configuration
// (configV1), and not the configuration that a restart loads.
func (h *harness) wantUnchanged(before platformState, when string) *harness {
	h.t.Helper()
	if got := h.storedText(); got != configV1 {
		h.t.Errorf("%s: stored file changed:\n%s", when, got)
	}
	h.wantPlatform(before, when)
	st := h.status()
	if st.State != daemon.StateReady || st.Config != digestOf(configV1) || st.Policies != 2 {
		h.t.Errorf("%s: status = %+v, want ready with configV1", when, st)
	}
	// configV1 still runs: ads protects, mail does not.
	if ack, err := h.d.Observe(h.t.Context(), obs("x.ads.example", "192.0.2.200")); err != nil || !ack.Protected {
		h.t.Errorf("%s: report for configV1: ack %+v, err %v; want protected", when, ack, err)
	}
	if !h.hasEntry("ads", host("192.0.2.200")) {
		h.t.Errorf("%s: the acked address is not in the ads table", when)
	}
	if ack, err := h.d.Observe(h.t.Context(), obs("mail.example.org", "203.0.113.5")); err != nil || ack.Protected {
		h.t.Errorf("%s: report for a name only in the refused text: ack %+v, err %v; want unprotected", when, ack, err)
	}
	h = h.restart()
	if st := h.status(); st.Config != digestOf(configV1) {
		h.t.Errorf("%s: after restart Config = %v, want the digest of configV1", when, st.Config)
	}
	return h
}

func TestStatusConfigIsTheDigestOfTheStoredFile(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		_, want, err := configstore.Load(h.store)
		if err != nil {
			t.Fatal(err)
		}
		if st := h.wantState(daemon.StateReady); st.Config != want || want != digestOf(configV1) {
			t.Errorf("Status.Config = %v, want %v", st.Config, want)
		}
	})
}

func TestApplyStoresAndConverges(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()

		st, err := h.d.Apply(t.Context(), []byte(configV2))
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		wantApplied(t, st, configV2)
		if got := h.storedText(); got != configV2 {
			t.Errorf("stored file = %q, want configV2", got)
		}
		_, stored, err := configstore.Load(h.store)
		if err != nil {
			t.Fatal(err)
		}
		if st := h.wantState(daemon.StateReady); st.Config != stored || st.Policies != 2 {
			t.Errorf("status = %+v, want 2 policies and the stored digest %v", st, stored)
		}
		if !h.references("mail") || h.references("ads") {
			t.Errorf("loaded ruleset refers to %v, want the policies of configV2", h.world.Referenced())
		}
		if err := h.observe(obs("mail.example.org", "192.0.2.25")); err != nil {
			t.Errorf("Observe after Apply: %v", err)
		}
		if !h.hasEntry("mail", host("192.0.2.25")) || !slices.Contains(h.saved("mail"), netip.MustParseAddr("192.0.2.25")) {
			t.Error("the address of the new policy is not in its table and the snapshot")
		}
	})
}

// A restart on the same stored file runs what Apply stored there.
func TestRestartLoadsTheAppliedConfig(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		if _, err := h.d.Apply(t.Context(), []byte(configV2)); err != nil {
			t.Fatal(err)
		}
		h = h.restart()
		defer h.stop()
		// The restart has no other source: the spec holds only this file.
		if got := h.storedText(); got != configV2 {
			t.Fatalf("stored file = %q, want configV2", got)
		}
		st := h.wantState(daemon.StateReady)
		if st.Config != digestOf(configV2) || !h.references("mail") || h.references("ads") {
			t.Errorf("after restart: Config %v, referenced %v; want configV2", st.Config, h.world.Referenced())
		}
	})
}

func TestApplyRefusesAnInvalidConfig(t *testing.T) {
	for _, tt := range invalidConfigs {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := newHarness(t, configV1)
				h.wantState(daemon.StateReady)
				before := platformOf(h.world)

				st, err := h.d.Apply(t.Context(), []byte(tt.text))
				var fe *policy.FieldError
				if !errors.As(err, &fe) {
					t.Fatalf("Apply = %v, want a *policy.FieldError", err)
				}
				if !reflect.DeepEqual(st, daemon.Status{}) {
					t.Errorf("status of a refused Apply = %+v, want the zero Status", st)
				}
				h = h.wantUnchanged(before, "refused Apply")
				h.stop()
			})
		})
	}
}

func TestApplyWithAFailedStoreChangesNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		h.wantState(daemon.StateReady)
		before := platformOf(h.world)
		dir := storeDir(h)
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		_, err := h.d.Apply(t.Context(), []byte(configV2))
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err == nil || errors.Is(err, configstore.ErrNotDurable) {
			t.Fatalf("Apply with a read-only store directory = %v, want an error that is not ErrNotDurable", err)
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(ents) != 1 {
			t.Errorf("the store directory holds %d files, want only the stored file", len(ents))
		}
		h = h.wantUnchanged(before, "failed store")
		h.stop()
	})
}

func storeDir(h *harness) string { return filepath.Dir(h.store) }

// A store whose directory sync failed is in place, so the configuration
// applies, and Apply reports the error with the status.
func TestApplyAppliesAStoreThatIsNotDurable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := launchWithStore(t, newSpec(t, configV1), func(path string, data []byte, gid int) (policy.Config, configstore.Digest, error) {
			cfg, dig, err := configstore.Store(path, data, gid)
			if err != nil {
				return cfg, dig, err
			}
			return cfg, dig, fmt.Errorf("store config: %w: injected", configstore.ErrNotDurable)
		})
		defer h.stop()

		st, err := h.d.Apply(t.Context(), []byte(configV2))
		if !errors.Is(err, configstore.ErrNotDurable) {
			t.Fatalf("Apply = %v, want ErrNotDurable", err)
		}
		wantApplied(t, st, configV2)
		if h.storedText() != configV2 || !h.references("mail") {
			t.Errorf("a store that is not durable did not apply: referenced %v", h.world.Referenced())
		}
		if got := h.status().Config; got != digestOf(configV2) {
			t.Errorf("Status.Config = %v, want the digest of configV2", got)
		}
	})
}

// launchWithStore is launch with store as configstore.Store.
func launchWithStore(t *testing.T, s harnessSpec, store func(string, []byte, int) (policy.Config, configstore.Digest, error)) *harness {
	t.Helper()
	return launchHook(t, s, func(d *daemon.Daemon) { d.SetStore(store) })
}

// endsAtCheck is a context that ends at its first Err call. The send to
// the loop does not call Err, so the loop takes the request with a live
// context, and the context ends at the check of Apply before the store.
type endsAtCheck struct {
	once    sync.Once
	done    chan struct{}
	checked atomic.Bool
}

func newEndsAtCheck() *endsAtCheck { return &endsAtCheck{done: make(chan struct{})} }

func (*endsAtCheck) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*endsAtCheck) Value(any) any               { return nil }
func (c *endsAtCheck) Done() <-chan struct{}     { return c.done }

func (c *endsAtCheck) Err() error {
	c.once.Do(func() { close(c.done) })
	c.checked.Store(true)
	return context.Canceled
}

func TestApplyDoesNotStoreAfterItsContextEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		h.wantState(daemon.StateReady)
		before := platformOf(h.world)
		ctx := newEndsAtCheck()

		if _, err := h.d.Apply(ctx, []byte(configV2)); !errors.Is(err, context.Canceled) {
			t.Fatalf("Apply = %v, want context.Canceled", err)
		}
		if !ctx.checked.Load() {
			t.Fatal("the loop did not check the context of Apply")
		}
		h = h.wantUnchanged(before, "ended context")
		h.stop()
	})
}

// A context that ended before the call races the request in call. Each
// side of the race must store nothing.
func TestApplyWithAnEndedContextNeverStores(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.wantState(daemon.StateReady)
		before := platformOf(h.world)
		for i := range 200 {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := h.d.Apply(ctx, []byte(configV2)); !errors.Is(err, context.Canceled) {
				t.Fatalf("try %d: Apply = %v, want context.Canceled", i, err)
			}
			if h.storedText() != configV1 {
				t.Fatalf("try %d: Apply stored after its context ended", i)
			}
		}
		h.wantPlatform(before, "after the Apply calls with an ended context")
		if st := h.status(); st.Config != digestOf(configV1) {
			t.Errorf("Config = %v, want the digest of configV1", st.Config)
		}
	})
}

func TestRunRefusesABadConfig(t *testing.T) {
	tests := []struct {
		name string
		path string
		gid  int
	}{
		{"relative path", "state/config.toml", -1},
		{"path not clean", "/var/db/ifbound/../ifbound/config.toml", -1},
		{"empty path", "", -1},
		{"zero gid", "/var/db/ifbound/config.toml", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := daemon.New(daemon.Config{ConfigPath: tt.path, ConfigGID: tt.gid})
			if err := d.Run(t.Context()); !errors.Is(err, daemon.ErrBadConfig) {
				t.Errorf("Run = %v, want ErrBadConfig", err)
			}
		})
	}
}

// A stored file that fails the upstream check still applies: the check
// protects only DNS. The failure is a reason of StateDegraded.
func TestStoredConfigThatFailsTheUpstreamCheckIsDegraded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configUnreachable)
		defer h.stop()
		st := h.wantState(daemon.StateDegraded)
		if len(st.Reasons) != 1 || !strings.Contains(st.Reasons[0], "upstream check") || st.Config != digestOf(configUnreachable) {
			t.Errorf("status = %+v, want the upstream check and the digest", st)
		}
		if !h.references("dark") {
			t.Error("the daemon does not enforce the stored file")
		}
		if err := h.observe(obs("www.example.net", "203.0.113.1")); err != nil {
			t.Errorf("Observe: %v", err)
		}
	})
}

func TestStatusCarriesTheUpstreamWarnings(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		if st := h.wantState(daemon.StateReady); len(st.Warnings) != 0 {
			t.Errorf("warnings = %v, want none", st.Warnings)
		}
		st, err := h.d.Apply(t.Context(), []byte(configWarned))
		if err != nil {
			t.Fatal(err)
		}
		want := parse(t, configWarned).Warnings()
		if len(want) == 0 || !slices.Equal(st.Warnings, want) || !slices.Equal(h.status().Warnings, want) {
			t.Errorf("warnings = %v, want %v", st.Warnings, want)
		}
	})
}
