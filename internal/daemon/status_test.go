package daemon_test

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// gatedLoad is a Backend whose Load waits while gate is not nil, as a
// slow pfctl does. Set gate only while the loop is idle; a closed gate
// lets every load pass.
type gatedLoad struct {
	*reconciletest.Backend
	gate chan struct{}
}

func (b *gatedLoad) Load(ctx context.Context, rs reconcile.Ruleset) error {
	if b.gate != nil {
		<-b.gate
	}
	return b.Backend.Load(ctx, rs)
}

// startGated starts a daemon on configV1 whose ruleset loads can block.
func startGated(t *testing.T) (*harness, *gatedLoad) {
	t.Helper()
	s := newSpec(t, configV1)
	be := &gatedLoad{Backend: s.world.Backend()}
	s.be = be
	h := launch(t, s)
	h.wantState(daemon.StateReady)
	return h, be
}

// published returns Status without a wait for the loop or the bubble.
func published(t *testing.T, d *daemon.Daemon) daemon.Status {
	t.Helper()
	st, err := d.Status(t.Context())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	return st
}

// Status answers from the published copy while the loop is blocked in a
// platform write: it does not wait for the loop.
func TestStatusAnswersWhileTheLoopIsBlocked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.wantState(daemon.StateReady)
		release := make(chan struct{})
		h.world.SetBeforeWrite(func(int) error { <-release; return nil })
		go func() { _ = h.observe(obs("example.com", "192.0.2.91")) }() //nolint:errcheck // only the blocked write matters
		synctest.Wait()

		got := make(chan daemon.State, 1)
		go func() { got <- published(t, h.d).State }()
		synctest.Wait()
		select {
		case s := <-got:
			if s != daemon.StateReady {
				t.Errorf("Status = %v, want the published ready", s)
			}
		default:
			t.Error("Status waits for the blocked loop")
		}
		h.world.SetBeforeWrite(nil)
		close(release)
	})
}

// The effect of a request is in Status before the request returns, also
// when the rest of the loop pass blocks: a report that finds the ruleset
// gone stops the acks, and Status tells that while the repair blocks.
func TestStatusIsNotOlderThanTheLastRequest(t *testing.T) {
	tests := []struct {
		name   string
		damage func(*reconciletest.World)
	}{
		{"foreign ruleset", func(w *reconciletest.World) { w.ExternalLoad([]byte("pass all\n")) }},
		{"flushed", func(w *reconciletest.World) { w.FlushAll() }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h, be := startGated(t)
				defer h.stop()
				tt.damage(h.world)
				be.gate = make(chan struct{})
				if err := h.observe(obs("www.example.net", "203.0.113.1")); !errors.Is(err, daemon.ErrUnenforced) {
					t.Fatalf("Observe = %v, want ErrUnenforced", err)
				}
				synctest.Wait() // the loop blocks in the Load of the repair
				if st := published(t, h.d); st.State == daemon.StateReady || st.State == daemon.StateDegraded {
					t.Errorf("Status during the repair = %v, want a state that does not ack", st.State)
				}
				close(be.gate)
				h.wantState(daemon.StateReady)
			})
		})
	}
}

// Status shows the new digest from the rename of the stored file, also
// while the convergence of the Apply runs, and no state that acks until
// it ends.
func TestStatusShowsTheAppliedDigestDuringTheConvergence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, be := startGated(t)
		defer h.stop()
		be.gate = make(chan struct{})
		applied := make(chan error, 1)
		go func() {
			_, err := h.d.Apply(t.Context(), []byte(configV2))
			applied <- err
		}()
		synctest.Wait() // the loop blocks in the Load of configV2

		st := published(t, h.d)
		if st.Config != digestOf(configV2) || h.storedText() != configV2 {
			t.Errorf("Status.Config during the convergence = %v, want the digest of the stored configV2", st.Config)
		}
		if st.State == daemon.StateReady || st.State == daemon.StateDegraded {
			t.Errorf("state during the convergence = %v, want a state that does not ack", st.State)
		}
		close(be.gate)
		if err := <-applied; err != nil {
			t.Fatalf("Apply: %v", err)
		}
		h.wantState(daemon.StateReady)
	})
}

// A loop pass that is not a request, here a self-heal that finds a
// voiding problem, is in Status when the pass ends.
func TestStatusFollowsEachLoopPass(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.wantState(daemon.StateReady)
		h.world.SetProblems([]reconcile.Problem{pfDisabled}, nil)
		heal()
		if st := published(t, h.d); st.State != daemon.StateUnenforced {
			t.Errorf("Status after the self-heal = %v, want unenforced", st.State)
		}
	})
}

func TestStatusBeforeRunIsStarting(t *testing.T) {
	d := daemon.New(daemon.Config{})
	if st, err := d.Status(t.Context()); err != nil || st.State != daemon.StateStarting {
		t.Errorf("Status before Run = %+v, %v; want starting", st, err)
	}
}
