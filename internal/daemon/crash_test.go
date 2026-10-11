package daemon_test

import (
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// fault is how the injected failure at write N behaves.
type fault int

const (
	// crash fails write N and every later one, as if the process died.
	// A second daemon then starts on the same platform and snapshot.
	crash fault = iota + 1
	// transient fails write N only. The daemon goes on, recovers through
	// the self-heal, and keeps receiving reports.
	transient
)

func (f fault) String() string {
	if f == crash {
		return "crash"
	}
	return "transient"
}

// TestFaultAtEveryWriteKeepsAcknowledgedAddressesBlocked injects a fault
// at each platform write of a long scenario in turn: install, reports,
// expiry, an interface change, a configuration change, and reports after
// it. After every write of every daemon, each acknowledged and unexpired
// address is in its table, and the loaded ruleset refers to that table.
// The only exception is a policy that the configuration removed: its
// table must hold the address while a loaded rule still refers to it.
// Also, each table that the loaded ruleset refers to holds the configured
// destinations of its policy. At the end a restarted daemon reaches the
// desired state.
func TestFaultAtEveryWriteKeepsAcknowledgedAddressesBlocked(t *testing.T) {
	var total int
	synctest.Test(t, func(t *testing.T) { total = faultScenario(t, 0, crash) })
	if total != 22 {
		t.Fatalf("the scenario has %d writes, want 22: it no longer covers every kind of step", total)
	}
	for _, mode := range []fault{crash, transient} {
		for failAt := 1; failAt <= total; failAt++ {
			t.Run(fmt.Sprintf("%v at write %d", mode, failAt), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					if n := faultScenario(t, failAt, mode); n < failAt {
						t.Errorf("the scenario made %d writes; the fault at %d never happened", n, failAt)
					}
				})
			})
		}
	}
}

// faultScenario returns the number of write calls of the first daemon. A
// failAt of 0 injects no fault.
func faultScenario(t *testing.T, failAt int, mode fault) int {
	world := reconciletest.NewWorld()
	inv := reconciletest.NewInventory(en0)
	snapshot := filepath.Join(t.TempDir(), "addrbook.json")
	acks := newAckLog(time.Hour)
	var fired atomic.Bool
	world.SetAfterWrite(func() { checkAcked(t, world, acks) })
	world.SetBeforeWrite(func(n int) error {
		if failAt > 0 && (n == failAt || mode == crash && n > failAt) {
			fired.Store(true)
			return reconciletest.ErrInjected
		}
		return nil
	})

	a := start(t, world, inv, snapshot, parse(t, configV1))
	report := func(name policy.Name, o ipc.Observation) error {
		acks.observed(name, o)
		err := a.observe(o)
		if err == nil {
			acks.add(name, o)
		}
		return err
	}
	_ = report("web", obs("www.example.net", "203.0.113.1", "203.0.113.2"))
	_ = report("ads", obs("x.ads.example", "3fff::1"))
	time.Sleep(40 * time.Minute)
	_ = report("web", obs("example.com", "203.0.113.2", "203.0.113.3"))
	_ = report("ads", obs("y.ads.example", "3fff::2")) // live when ads leaves
	time.Sleep(21 * time.Minute)                       // 203.0.113.1 and 3fff::1 expire
	synctest.Wait()
	inv.Set(en0, utun0)
	time.Sleep(daemon.InterfaceDebounce)
	synctest.Wait()
	acks.remove("ads")
	_ = a.d.Reconfigure(t.Context(), parse(t, configV2))
	_ = report("mail", obs("mail.example.org", "192.0.2.25"))
	heal()
	heal()
	recovered := mode == transient && fired.Load()
	for _, r := range []struct {
		name policy.Name
		o    ipc.Observation
	}{{"mail", obs("mail.example.org", "192.0.2.26")}, {"web", obs("www.example.net", "203.0.113.4")}} {
		if err := report(r.name, r.o); recovered && err != nil {
			t.Errorf("after recovery, Observe(%s) = %v, want ack", r.o.QName, err)
		}
	}
	writes := world.Writes()
	a.stop()

	world.SetBeforeWrite(nil)
	b := start(t, world, inv, snapshot, parse(t, configV2))
	defer b.stop()
	b.wantState(daemon.StateReady)
	checkRecovered(t, world, acks)
	return writes
}

func checkRecovered(t *testing.T, world *reconciletest.World, acks *ackLog) {
	t.Helper()
	tables := world.Tables()
	if got := slices.Sorted(maps.Keys(tables)); !slices.Equal(got, []policy.Name{"mail", "web"}) {
		t.Errorf("tables after restart = %v, want mail and web only", got)
	}
	static := staticEntries()
	live := acks.live(time.Now())
	for name, entries := range tables {
		for _, e := range append(slices.Clone(static[name]), live[name]...) {
			if !slices.Contains(entries, e) {
				t.Errorf("table %s lacks %v after restart", name, e)
			}
		}
		for _, e := range entries {
			if !slices.Contains(static[name], e) && !acks.wasObserved(name, e) {
				t.Errorf("table %s holds %v, which no report or destination gave", name, e)
			}
		}
	}
	rs, err := reconciletest.Compiler{}.Compile(parse(t, configV2).Policies, []reconcile.Interface{en0, utun0})
	if err != nil {
		t.Fatal(err)
	}
	if world.Ruleset().ID() != rs.ID() {
		t.Error("the loaded ruleset is not the desired one after restart")
	}
	var domains []string
	for _, e := range world.ResolverEntries() {
		domains = append(domains, e.Domain.String())
	}
	if want := []string{"example.com", "example.net", "mail.example.org", "use-application-dns.net"}; !slices.Equal(domains, want) {
		t.Errorf("resolver entries = %v, want %v", domains, want)
	}
}

type ackKey struct {
	policy policy.Name
	entry  netip.Prefix
}

// ackLog holds the acknowledged addresses and the last instant each one
// must stay blocked. The test goroutine writes it; the after-write hook
// reads it on the daemon goroutine.
//
// The scenario spaces the reports of one address by more than the save
// slack, so every acknowledgement saves the snapshot and the snapshot
// expiry equals the acknowledged one.
type ackLog struct {
	mu       sync.Mutex
	retain   time.Duration
	expiry   map[ackKey]time.Time
	seen     map[ackKey]bool
	excluded map[policy.Name]bool // removed from the configuration
}

func newAckLog(retain time.Duration) *ackLog {
	return &ackLog{
		retain:   retain,
		expiry:   make(map[ackKey]time.Time),
		seen:     make(map[ackKey]bool),
		excluded: make(map[policy.Name]bool),
	}
}

func (l *ackLog) observed(name policy.Name, o ipc.Observation) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, a := range o.Addrs {
		l.seen[ackKey{name, host(a.String())}] = true
	}
}

func (l *ackLog) wasObserved(name policy.Name, e netip.Prefix) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seen[ackKey{name, e}]
}

func (l *ackLog) add(name policy.Name, o ipc.Observation) {
	l.mu.Lock()
	defer l.mu.Unlock()
	until := time.Now().Add(max(o.TTL, l.retain))
	for _, a := range o.Addrs {
		k := ackKey{name, host(a.String())}
		if until.After(l.expiry[k]) {
			l.expiry[k] = until
		}
	}
}

// remove marks a policy as removed from the configuration.
func (l *ackLog) remove(name policy.Name) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.excluded[name] = true
}

// live returns the acknowledged entries that are not expired at now, by
// policy, for the policies that the configuration still has.
func (l *ackLog) live(now time.Time) map[policy.Name][]netip.Prefix {
	out := make(map[policy.Name][]netip.Prefix)
	for k := range l.liveKeys(now) {
		if !l.isRemoved(k.policy) {
			out[k.policy] = append(out[k.policy], k.entry)
		}
	}
	return out
}

func (l *ackLog) liveKeys(now time.Time) map[ackKey]bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[ackKey]bool)
	for k, until := range l.expiry {
		if !now.After(until) {
			out[k] = true
		}
	}
	return out
}

func (l *ackLog) isRemoved(name policy.Name) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.excluded[name]
}

// staticEntries are the configured destinations of every policy in
// configV1 and configV2. Web has the same ones in both.
func staticEntries() map[policy.Name][]netip.Prefix {
	return map[policy.Name][]netip.Prefix{
		"web":  {netip.MustParsePrefix("192.0.2.10/32"), netip.MustParsePrefix("198.51.100.0/24")},
		"ads":  {netip.MustParsePrefix("2001:db8::/32")},
		"mail": {netip.MustParsePrefix("203.0.113.0/28")},
	}
}

func checkAcked(t *testing.T, w *reconciletest.World, acks *ackLog) {
	t.Helper()
	tables := w.Tables()
	referenced := w.Referenced()
	static := staticEntries()
	for _, name := range referenced {
		for _, e := range static[name] {
			if !slices.Contains(tables[name], e) {
				t.Errorf("after write %d: the ruleset refers to table %s, which lacks its destination %v",
					w.Writes(), name, e)
			}
		}
	}
	for k := range acks.liveKeys(time.Now()) {
		isReferenced := slices.Contains(referenced, k.policy)
		switch {
		case !isReferenced && acks.isRemoved(k.policy):
			// The policy left the configuration and the loaded ruleset.
		case !isReferenced:
			t.Errorf("after write %d: acknowledged %v of %s, but no loaded rule refers to table %s",
				w.Writes(), k.entry, k.policy, k.policy)
		case !slices.Contains(tables[k.policy], k.entry):
			t.Errorf("after write %d: acknowledged %v is not in table %s", w.Writes(), k.entry, k.policy)
		}
	}
}
