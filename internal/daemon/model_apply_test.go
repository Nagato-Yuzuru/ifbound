package daemon_test

// A second model-based test of the acknowledgement contract. It runs
// random Apply calls (valid, refused, with a failed store, with an ended
// context), restarts on a good or a bad stored file, reports, external
// changes of the platform, write and snapshot faults, and time. The model
// holds only what the spec says: the configuration that runs (the stored
// file at start, then each Apply that returned nil) and the stored bytes.
// The ack check reads the World and the snapshot on disk.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/configstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// configV3 has another retain, and a policy that has a name of configV1.
const configV3 = `
[dns]
listen = "127.0.0.1:53553"
upstream = ["tls://1.1.1.1@cloudflare-dns.com"]
[addrbook]
retain = "2h"

[[policy]]
name = "ads"
to = ["*.ads.example", "mail.example.org"]
deny_via = ["en0"]
`

var (
	amValid  = []string{configV1, configV2, configV3}
	amQNames = []string{"example.com", "EXAMPLE.com.", "www.example.com", "example.net", "a.example.net",
		"b.a.example.net", "x.ads.example", "ads.example", "mail.example.org", "unrelated.test"}
	amAddrs = []string{"192.0.2.20", "192.0.2.21", "198.51.100.3", "203.0.113.4", "2001:db8:5::1", "2001:db8:5::2", "::ffff:192.0.2.22"}
)

// amMatch is the matching rule of the spec: an exact destination matches
// its name, and "*.x" matches x and every name below x.
func amMatch(cfg policy.Config, qname string) []policy.Name {
	q := strings.TrimSuffix(strings.ToLower(qname), ".")
	var out []policy.Name
	for _, p := range cfg.Policies {
		if slices.ContainsFunc(p.To, func(d policy.Destination) bool { return amHit(d, q) }) {
			out = append(out, p.Name)
		}
	}
	return out
}

func amHit(d policy.Destination, q string) bool {
	switch d := d.(type) {
	case policy.ExactDomain:
		return q == d.Domain().String()
	case policy.DomainSuffix:
		s := d.Domain().String()
		return q == s || strings.HasSuffix(q, "."+s)
	case policy.IPAddr, policy.CIDR:
	}
	return false
}

// amModel is the model of one seed.
type amModel struct {
	t   *testing.T
	rnd *rand.Rand
	h   *harness
	log []string
	// running is the configuration that the daemon must run, nil when it
	// has none.
	running *policy.Config
	// stored are the bytes that the store must hold, nil for no file.
	stored []byte
	// frozen is the platform while the daemon has no configuration: the
	// daemon must not write it.
	frozen *platformState

	writeFaults, snapReadOnly bool
	protected                 int
}

func (m *amModel) logf(format string, args ...any) {
	m.log = append(m.log, fmt.Sprintf(format, args...))
}

func (m *amModel) fatalf(format string, args ...any) {
	m.t.Helper()
	tail := m.log[max(0, len(m.log)-25):]
	m.t.Fatalf("%s\nlast steps:\n  %s", fmt.Sprintf(format, args...), strings.Join(tail, "\n  "))
}

// sync sets the model from the stored file after a start.
func (m *amModel) sync() {
	cfg, _, err := configstore.Load(m.h.store)
	if err != nil {
		p := platformOf(m.h.world)
		m.running, m.frozen = nil, &p
		return
	}
	m.running, m.frozen = &cfg, nil
}

// checkStore checks the stored bytes, Status.Config, and the platform of a
// daemon without a configuration.
func (m *amModel) checkStore(after string) {
	m.t.Helper()
	if got := m.storedBytes(); !bytes.Equal(got, m.stored) {
		m.fatalf("%s: stored bytes %q, want %q", after, got, m.stored)
	}
	st := m.h.status()
	want := configstore.Digest{}
	if m.running != nil {
		want = digestOf(string(m.stored))
	}
	if st.Config != want {
		m.fatalf("%s: Status.Config %v, want %v", after, st.Config, want)
	}
	if m.running != nil {
		return
	}
	if acksState(st.State) {
		m.fatalf("%s: state %v without a configuration", after, st.State)
	}
	if got := platformOf(m.h.world); !reflect.DeepEqual(got, *m.frozen) {
		m.fatalf("%s: the daemon wrote without a configuration:\n got %+v\nwant %+v", after, got, *m.frozen)
	}
}

func (m *amModel) storedBytes() []byte {
	data, err := os.ReadFile(m.h.store)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		m.fatalf("%v", err)
	}
	return data
}

func (m *amModel) observe() {
	q := amQNames[m.rnd.IntN(len(amQNames))]
	o := obs(q)
	for _, s := range amAddrs {
		if m.rnd.IntN(3) == 0 {
			o.Addrs = append(o.Addrs, netip.MustParseAddr(s))
		}
	}
	o.TTL = time.Duration(m.rnd.IntN(3600)) * time.Second
	ack, err := m.h.d.Observe(context.Background(), o)
	m.logf("observe %s %v -> %+v %v", q, o.Addrs, ack, err)
	synctest.Wait()
	if err != nil {
		return
	}
	if m.running == nil {
		m.fatalf("ack of %s without a configuration", q)
	}
	matched := amMatch(*m.running, q)
	if ack.Protected != (len(matched) > 0) {
		m.fatalf("ack of %s: protected %v, but it matches %v", q, ack.Protected, matched)
	}
	if len(matched) > 0 && len(o.Addrs) > 0 {
		m.protected++
	}
	for _, p := range matched {
		m.checkAcked(q, p, o.Addrs)
	}
}

// checkAcked checks the invariant for the acked addresses of policy p:
// a report without an address is acked for the protected flag only.
func (m *amModel) checkAcked(q string, p policy.Name, addrs []netip.Addr) {
	if len(addrs) == 0 {
		return
	}
	if !m.h.references(p) {
		m.fatalf("ack of %s: the loaded ruleset does not refer to %s (%v)", q, p, m.h.world.Referenced())
	}
	saved := m.h.saved(p)
	for _, a := range addrs {
		a = a.Unmap()
		if !m.h.hasEntry(p, host(a.String())) {
			m.fatalf("ack of %s: %s is not in table %s", q, a, p)
		}
		if !slices.Contains(saved, a) {
			m.fatalf("ack of %s: %s of %s is not in the snapshot", q, a, p)
		}
	}
}

func (m *amModel) applyValid() {
	text := amValid[m.rnd.IntN(len(amValid))]
	_, err := m.h.d.Apply(context.Background(), []byte(text))
	m.logf("apply valid -> %v", err)
	if err != nil {
		m.fatalf("valid Apply: %v", err)
	}
	cfg := parse(m.t, text)
	m.running, m.stored, m.frozen = &cfg, []byte(text), nil
	m.checkStore("valid Apply")
}

func (m *amModel) applyRefused() {
	text := invalidConfigs[m.rnd.IntN(len(invalidConfigs))].text
	_, err := m.h.d.Apply(context.Background(), []byte(text))
	m.logf("apply invalid -> %v", err)
	if err == nil {
		m.fatalf("invalid Apply returned nil")
	}
	m.checkStore("invalid Apply")
}

func (m *amModel) applyStoreFails() {
	dir := filepath.Dir(m.h.store)
	if err := os.Chmod(dir, 0o500); err != nil {
		m.fatalf("%v", err)
	}
	_, err := m.h.d.Apply(context.Background(), []byte(amValid[m.rnd.IntN(len(amValid))]))
	if cerr := os.Chmod(dir, 0o700); cerr != nil {
		m.fatalf("%v", cerr)
	}
	m.logf("apply with a failed store -> %v", err)
	if err == nil {
		m.fatalf("Apply with a failed store returned nil")
	}
	m.checkStore("failed store")
}

func (m *amModel) applyEnded() {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := m.h.d.Apply(ctx, []byte(amValid[m.rnd.IntN(len(amValid))]))
	m.logf("apply with an ended ctx -> %v", err)
	if err == nil {
		m.fatalf("Apply with an ended ctx returned nil")
	}
	m.checkStore("ended ctx")
}

func (m *amModel) restart() {
	m.h.stop()
	switch m.rnd.IntN(6) {
	case 0:
		if err := os.Remove(m.h.store); err != nil && !errors.Is(err, os.ErrNotExist) {
			m.fatalf("%v", err)
		}
		m.stored = nil
		m.logf("restart, store removed")
	case 1:
		if err := os.WriteFile(m.h.store, []byte("garbage [["), 0o600); err != nil {
			m.fatalf("%v", err)
		}
		m.stored = []byte("garbage [[")
		m.logf("restart, store garbage")
	case 2:
		if m.stored != nil {
			if err := os.Chmod(m.h.store, 0o666); err != nil {
				m.fatalf("%v", err)
			}
		}
		m.logf("restart, store mode 0666")
	default:
		m.logf("restart")
	}
	m.h = launch(m.t, m.h.spec)
	m.sync()
	m.checkStore("restart")
}

func (m *amModel) external() {
	w := m.h.world
	switch m.rnd.IntN(4) {
	case 0:
		w.FlushAll()
		m.logf("external flush all")
	case 1:
		p := []policy.Name{"web", "ads", "mail"}[m.rnd.IntN(3)]
		w.FlushTable(p)
		m.logf("external flush %s", p)
	case 2:
		w.ExternalLoad([]byte("table web foreign\n"))
		m.logf("external load")
	case 3:
		if m.rnd.IntN(2) == 0 {
			w.SetProblems([]reconcile.Problem{pfDisabled}, nil)
			m.logf("pf disabled")
		} else {
			w.SetProblems(nil, nil)
			m.logf("pf enabled")
		}
	}
	if m.frozen != nil {
		p := platformOf(w)
		m.frozen = &p
	}
}

func (m *amModel) faults() {
	if m.rnd.IntN(2) == 0 {
		m.writeFaults = !m.writeFaults
		m.h.world.SetBeforeWrite(nil)
		if m.writeFaults {
			k := 1 + m.rnd.IntN(3)
			m.h.world.SetBeforeWrite(func(n int) error {
				if n%k == 0 {
					return reconciletest.ErrInjected
				}
				return nil
			})
		}
		m.logf("write faults %v", m.writeFaults)
		return
	}
	m.snapReadOnly = !m.snapReadOnly
	mode := os.FileMode(0o700)
	if m.snapReadOnly {
		mode = 0o500
	}
	if err := os.Chmod(filepath.Dir(m.h.snapshot), mode); err != nil {
		m.fatalf("%v", err)
	}
	m.logf("snapshot read-only %v", m.snapReadOnly)
}

func (m *amModel) wait() {
	d := []time.Duration{
		daemon.SelfHealInterval,
		time.Duration(1+m.rnd.IntN(10)) * time.Minute,
		time.Duration(m.rnd.IntN(2000)) * time.Millisecond,
	}[m.rnd.IntN(3)]
	time.Sleep(d)
	m.logf("wait %v", d)
	m.checkStore("wait")
}

func (m *amModel) step() {
	switch n := m.rnd.IntN(100); {
	case n < 40:
		m.observe()
	case n < 50:
		m.applyValid()
	case n < 55:
		m.applyRefused()
	case n < 60:
		m.applyStoreFails()
	case n < 63:
		m.applyEnded()
	case n < 69:
		m.restart()
	case n < 77:
		m.external()
	case n < 85:
		m.faults()
	default:
		m.wait()
	}
}

func runApplyModel(t *testing.T, seed uint64) int {
	m := &amModel{t: t, rnd: rand.New(rand.NewPCG(seed, 179))}
	first := amValid[m.rnd.IntN(len(amValid))]
	s := newSpec(t, first)
	t.Cleanup(func() {
		// Let TempDir remove the directories after a fault.
		_ = os.Chmod(filepath.Dir(s.store), 0o700)    //nolint:errcheck // best effort, for the TempDir cleanup
		_ = os.Chmod(filepath.Dir(s.snapshot), 0o700) //nolint:errcheck // best effort, for the TempDir cleanup
	})
	m.h, m.stored = launch(t, s), []byte(first)
	m.sync()
	defer func() { m.h.stop() }()
	for range *omLen {
		m.step()
	}
	return m.protected
}

// TestRandomOperationsWithAppliesAndRestarts fails when the daemon acks
// an address that is not in its table, in the snapshot, and under the
// loaded ruleset; acks or writes without a configuration; or stores, or
// reports a digest, that differs from the model. It shares the seed and
// step flags of TestRandomOperationsNeverLeakAnAcknowledgedAddress.
func TestRandomOperationsWithAppliesAndRestarts(t *testing.T) {
	protected := 0
	for seed := uint64(*omFirst); seed < uint64(*omFirst+*omSeeds); seed++ {
		ok := t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { protected += runApplyModel(t, seed) })
		})
		if !ok {
			break
		}
	}
	if !t.Failed() && protected < *omSeeds {
		t.Errorf("only %d protected acks with addresses in %d seeds: the run checks too little", protected, *omSeeds)
	}
}
