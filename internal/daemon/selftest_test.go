package daemon_test

import (
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
)

const notConnected = "ifbound-dns not connected"

// configIPOnly lists no name, so it has no self-test.
const configIPOnly = header + `
[[policy]]
name = "ips"
to = ["192.0.2.10", "198.51.100.0/24"]
only_via = ["en0"]
`

func notConnectedReason(st daemon.Status) bool {
	return slices.ContainsFunc(st.Reasons, func(r string) bool { return strings.HasPrefix(r, notConnected) })
}

// startDNSDown starts a daemon on cfgText while ifbound-dns is not
// connected.
func startDNSDown(t *testing.T, cfgText string) *harness {
	t.Helper()
	s := newSpec(t, cfgText)
	s.dns.down.Store(true)
	return launch(t, s)
}

// Until a probe reaches ifbound-dns, the state is Degraded, also before
// the first warm-up pass ends.
func TestSelfTestIsDegradedBeforeTheFirstProbePasses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := startDNSDown(t, configV1)
		defer h.stop()
		time.Sleep(daemon.WarmUpTimeout / 2)
		if st := h.status(); st.State != daemon.StateDegraded || !notConnectedReason(st) {
			t.Errorf("no probe passed yet: status = %v %q, want degraded with %q", st.State, st.Reasons, notConnected)
		}
	})
}

func TestSelfTestReportsNotConnectedUntilAProbePasses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := startDNSDown(t, configV1)
		defer h.stop()

		time.Sleep(daemon.WarmUpTimeout + time.Second)
		for i := range 4 {
			st := h.status()
			if st.State != daemon.StateDegraded || !notConnectedReason(st) {
				t.Fatalf("pass %d: status = %v %q, want degraded with %q", i, st.State, st.Reasons, notConnected)
			}
			// The problem does not void enforcement: reports are acked.
			if ack, err := h.d.Observe(t.Context(), obs("example.com", "192.0.2.1")); err != nil || !ack.Protected {
				t.Fatalf("pass %d: ack %+v, err %v; want a protected ack", i, ack, err)
			}
			heal()
		}

		h.spec.dns.down.Store(false)
		time.Sleep(daemon.SelfHealInterval + daemon.WarmUpTimeout + time.Second)
		h.wantState(daemon.StateReady)

		// The pass is final for the configuration.
		h.spec.dns.down.Store(true)
		time.Sleep(3 * (daemon.SelfHealInterval + daemon.WarmUpTimeout))
		h.wantState(daemon.StateReady)
	})
}

// Each configuration has its own self-test: after an Apply, the state is
// Degraded until a probe passes under the new configuration.
func TestSelfTestRunsAgainForANewConfig(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.wantState(daemon.StateReady)
		h.spec.dns.down.Store(true)
		if _, err := h.d.Apply(t.Context(), []byte(configV2)); err != nil {
			t.Fatal(err)
		}
		if st := h.status(); st.State != daemon.StateDegraded || !notConnectedReason(st) {
			t.Fatalf("after Apply without ifbound-dns: status = %v %q, want degraded", st.State, st.Reasons)
		}
		h.spec.dns.down.Store(false)
		time.Sleep(daemon.SelfHealInterval + daemon.WarmUpTimeout + time.Second)
		h.wantState(daemon.StateReady)
	})
}

// A configuration without names sends no query to ifbound-dns, so there
// is no self-test and no reason.
func TestSelfTestNeedsANameToProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := startDNSDown(t, configIPOnly)
		defer h.stop()
		for range 3 {
			heal()
		}
		h.wantState(daemon.StateReady)
	})
}

// An Apply of a configuration without names ends the self-test of the
// configuration before it, and so its reason.
func TestApplyWithoutNamesEndsTheSelfTest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := startDNSDown(t, configV1)
		defer h.stop()
		time.Sleep(daemon.WarmUpTimeout + time.Second)
		if st := h.status(); !notConnectedReason(st) {
			t.Fatalf("precondition: status = %v %q, want %q", st.State, st.Reasons, notConnected)
		}
		st, err := h.d.Apply(t.Context(), []byte(configIPOnly))
		if err != nil {
			t.Fatal(err)
		}
		if st.State != daemon.StateReady {
			t.Errorf("Apply of a configuration without names: status = %v %q, want ready", st.State, st.Reasons)
		}
		for range 3 {
			heal()
		}
		h.wantState(daemon.StateReady)
	})
}
