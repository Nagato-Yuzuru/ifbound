package daemon_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	"github.com/Nagato-Yuzuru/ifbound/internal/syslookup"
)

// These tests check the ack rule and the adoption at start. They drive one
// daemon through random events and checks every reply to a report
// against the spec. The expected policy matches and the expected
// resolver entries are written down by hand.

const rigHeader = `
[dns]
listen = "127.0.0.1:53553"
upstream = ["tls://1.1.1.1@cloudflare-dns.com"]
[addrbook]
retain = "1h"
`

const rigCfgA = rigHeader + `
[[policy]]
name = "web"
to = ["example.com", "*.example.net", "192.0.2.10"]
only_via = ["en0"]

[[policy]]
name = "ads"
to = ["*.ads.example", "*.example.net"]
deny_via = ["@tunnel"]
`

// rigCfgB changes a constraint only: same names, new ruleset.
const rigCfgB = rigHeader + `
[[policy]]
name = "web"
to = ["example.com", "*.example.net", "192.0.2.10"]
only_via = ["utun*"]

[[policy]]
name = "ads"
to = ["*.ads.example", "*.example.net"]
deny_via = ["@tunnel"]
`

const (
	rigRetain = time.Hour
	rigSlack  = 30 * time.Minute // min(1h, retain/2)
)

// rigMatch is the policy set of each qname, from the policy rules:
// an exact name matches itself only, "*.d" matches d and every name
// below it, case does not count. A nil entry means no match; a missing
// entry means a malformed name.
var rigMatch = map[string][]policy.Name{
	"example.com":             {"web"},
	"EXAMPLE.Com.":            {"web"},
	"www.example.net":         {"ads", "web"},
	"a.b.example.net.":        {"ads", "web"},
	"x.ads.example":           {"ads"},
	"www.example.com":         nil,
	"nomatch.org":             nil,
	"cdn.akamai.test":         nil,
	"ads.example.com":         nil,
	"a..b.example.net":        nil, // malformed: see rigMalformed
	"use-application-dns.net": nil,
}

var rigMalformed = map[string]bool{"a..b.example.net": true}

// rigEntries are the resolver entries of both configurations: one per
// apex, and the canary.
var rigEntries = []string{"ads.example", "example.com", "example.net", "use-application-dns.net"}

var (
	rigEn0   = reconcile.Interface{Name: "en0", Class: policy.ClassHardware}
	rigUtun0 = reconcile.Interface{Name: "utun0", Class: policy.ClassTunnel}
)

var rigAddrPool = []string{"192.0.2.1", "192.0.2.2", "2001:db8::5", "::ffff:198.51.100.9", "198.51.100.9"}

var rigTTLs = []time.Duration{0, time.Minute, 2 * time.Hour}

// rigLookup is the system resolver of the rig, together with
// ifbound-dns: a probe name that an applied entry routes to ifbound-dns
// reaches the daemon. The answer is always "no such name", so the
// warm-up learns nothing.
type rigLookup struct {
	world  *reconciletest.World
	listen netip.AddrPort
	d      *daemon.Daemon
}

func (l *rigLookup) Resolve(_ context.Context, name string) ([]netip.Addr, error) {
	if ipc.IsProbe(name) && routes(l.world.AppliedResolverEntries(), name, l.listen) {
		l.d.ProbeSeen(name)
	}
	return nil, fmt.Errorf("resolve %s: %w", name, syslookup.ErrNotFound)
}

// rigResolver lets a test fail the resolver writes only.
type rigResolver struct {
	*reconciletest.Resolver
	fail *atomic.Bool
}

func (r rigResolver) Write(ctx context.Context, e reconcile.ResolverEntry) error {
	if r.fail.Load() {
		return reconciletest.ErrInjected
	}
	return r.Resolver.Write(ctx, e)
}

type rig struct {
	t        *testing.T
	world    *reconciletest.World
	inv      *reconciletest.Inventory
	dir      string
	snap     string
	d        *daemon.Daemon
	lookup   *rigLookup
	resFail  atomic.Bool
	stats    map[string]int
	f        rigFaults
	trace    []string
	stopOnce sync.Once
	stop     func()
}

func newRig(t *testing.T, world *reconciletest.World, dir string, cfgText string) *rig {
	t.Helper()
	rg := &rig{t: t, world: world, inv: reconciletest.NewInventory(rigEn0), dir: dir, snap: filepath.Join(dir, "addrbook.json"), lookup: &rigLookup{world: world, listen: rigCfg(t, cfgText).DNS.Listen}, stats: map[string]int{}}
	rg.d = daemon.New(daemon.Config{
		ConfigPath: storeConfig(t, t.TempDir(), cfgText),
		ConfigGID:  -1,
		Snapshot:   rg.snap,
		// No host file: the tests here do not depend on the host file of the machine.
		HostsFile: filepath.Join(filepath.Dir(rg.snap), "hosts"),
		Platform: reconcile.Reconciler{
			Compiler:  reconciletest.Compiler{},
			Backend:   world.Backend(),
			Resolver:  rigResolver{Resolver: world.Resolver(), fail: &rg.resFail},
			Inventory: rg.inv,
		},
		Lookup: rg.lookup,
	})
	rg.lookup.d = rg.d
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rg.d.Run(ctx) }()
	synctest.Wait()
	rg.stop = func() {
		rg.stopOnce.Do(func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("Run: %v", err)
			}
		})
	}
	t.Cleanup(rg.stop)
	return rg
}

// status waits until the loop blocks, so that the published Status
// covers every pass that the last event started, such as the repair
// after a report that found the ruleset changed.
func (rg *rig) status() daemon.Status {
	rg.t.Helper()
	synctest.Wait()
	st, err := rg.d.Status(context.Background())
	if err != nil {
		rg.t.Fatalf("Status: %v", err)
	}
	return st
}

func rigCfg(t *testing.T, text string) policy.Config {
	t.Helper()
	cfg, err := policy.ParseBytes([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// savedExpiry returns the expiry of (p, a) in the snapshot on disk.
func (rg *rig) savedExpiry(p policy.Name, a netip.Addr) (time.Time, bool) {
	data, err := os.ReadFile(rg.snap)
	if err != nil {
		return time.Time{}, false
	}
	var f struct {
		Entries []struct {
			Policy string `json:"policy"`
			Addr   string `json:"addr"`
			Expiry int64  `json:"expiry_unix_nano"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		rg.t.Fatalf("snapshot on disk does not decode: %v", err)
	}
	for _, e := range f.Entries {
		if e.Policy == string(p) && e.Addr == a.String() {
			return time.Unix(0, e.Expiry), true
		}
	}
	return time.Time{}, false
}

type rigFaults struct {
	writes   bool // every platform write fails
	readOnly bool // the snapshot directory is read-only
	resolver bool // resolver writes fail
	tampered bool // the ruleset changed outside since the last convergence
	voids    bool // a problem voids enforcement
}

func (f rigFaults) healthy() bool { return !f.writes && !f.readOnly && !f.tampered }

func (rg *rig) setReadOnly(on bool) {
	mode := os.FileMode(0o700)
	if on {
		mode = 0o500
	}
	if err := os.Chmod(rg.dir, mode); err != nil {
		rg.t.Fatal(err)
	}
}

func (rg *rig) fatalf(format string, args ...any) {
	rg.t.Helper()
	rg.t.Fatalf("%s\n"+format, append([]any{strings.Join(rg.trace, "\n")}, args...)...)
}

func (rg *rig) logf(format string, args ...any) {
	rg.trace = append(rg.trace, fmt.Sprintf(format, args...))
}

func rigObservation(r *rand.Rand) ipc.Observation {
	qnames := slices.Sorted(maps.Keys(rigMatch))
	o := ipc.Observation{QName: qnames[r.IntN(len(qnames))], TTL: rigTTLs[r.IntN(len(rigTTLs))]}
	for _, s := range rigSubsetOf(r, rigAddrPool, 0.4) {
		o.Addrs = append(o.Addrs, netip.MustParseAddr(s))
	}
	return o
}

func (rg *rig) count(q string, state daemon.State, err error) {
	kind := "matched"
	switch {
	case rigMalformed[q]:
		kind = "malformed"
	case len(rigMatch[q]) == 0:
		kind = "unmatched"
	}
	outcome := "ack"
	if err != nil {
		outcome = "reject"
	}
	rg.stats[fmt.Sprintf("%s %v %s", kind, state, outcome)]++
}

// checkObserve sends one report and checks the reply against the spec.
// It reports whether the daemon found the loaded ruleset changed, which
// makes it converge right after the report.
func (rg *rig) checkObserve(r *rand.Rand) (rechecked bool) {
	rg.t.Helper()
	o := rigObservation(r)
	st := rg.status()
	tablesBefore := rg.world.Tables()
	snapBefore, _ := os.ReadFile(rg.snap) //nolint:errcheck // a missing snapshot reads as empty; the test compares the bytes after
	start := time.Now()
	_, err := rg.d.Observe(context.Background(), o)
	if waited := time.Since(start); waited != 0 {
		rg.fatalf("Observe(%q) waited %v; a report must never wait", o.QName, waited)
	}
	rg.logf("observe %q %v ttl %v in %v %+v -> %v", o.QName, o.Addrs, o.TTL, st.State, rg.f, err)
	rg.count(o.QName, st.State, err)
	want, known := rigMatch[o.QName]
	switch {
	case !known:
		rg.fatalf("qname %q is not in the match table", o.QName)
	case rigMalformed[o.QName]:
		if err == nil {
			rg.fatalf("a malformed name was acked")
		}
	case st.State == daemon.StateStarting:
		if !errors.Is(err, daemon.ErrNotReady) {
			rg.fatalf("in starting: err = %v, want ErrNotReady", err)
		}
	case st.State == daemon.StateUnenforced:
		if !errors.Is(err, daemon.ErrUnenforced) {
			rg.fatalf("in unenforced: err = %v, want ErrUnenforced", err)
		}
	case len(want) == 0, len(o.Addrs) == 0:
		// A report without an address only asks for the protected flag,
		// so its ack promises nothing about the platform.
		rg.checkUnmatched(err, st.State, tablesBefore, snapBefore)
	case err != nil:
		if rg.f.healthy() {
			rg.fatalf("matched name in %v without a fault: err = %v, want an ack", st.State, err)
		}
		return errors.Is(err, daemon.ErrUnenforced)
	default:
		rg.checkAck(o, want, start)
	}
	return false
}

// checkUnmatched pins today's behavior: an unmatched name, and a report
// without an address, is acked in ready and degraded, and changes no
// table and no snapshot.
func (rg *rig) checkUnmatched(err error, state daemon.State, tablesBefore map[policy.Name][]netip.Prefix, snapBefore []byte) {
	rg.t.Helper()
	if err != nil {
		rg.fatalf("unmatched name in %v: err = %v, want an ack", state, err)
	}
	if after := rg.world.Tables(); !maps.EqualFunc(after, tablesBefore, slices.Equal) {
		rg.fatalf("unmatched name changed the tables: %v -> %v", tablesBefore, after)
	}
	if after, _ := os.ReadFile(rg.snap); !bytes.Equal(after, snapBefore) { //nolint:errcheck // a missing snapshot reads as empty, as before
		rg.fatalf("unmatched name changed the snapshot")
	}
}

// checkAck checks what an ack promises: each address is in the table of
// each matching policy, the loaded ruleset refers to that table, and the
// snapshot on disk keeps the address for at least retain minus the save
// slack.
func (rg *rig) checkAck(o ipc.Observation, want []policy.Name, start time.Time) {
	rg.t.Helper()
	tables := rg.world.Tables()
	referenced := rg.world.Referenced()
	floor := start.Add(max(o.TTL, rigRetain) - rigSlack)
	for _, p := range want {
		if !slices.Contains(referenced, p) {
			rg.fatalf("acked, but the loaded ruleset does not refer to table %s (refers to %v)", p, referenced)
		}
		for _, a := range o.Addrs {
			a = a.Unmap()
			if !slices.Contains(tables[p], netip.PrefixFrom(a, a.BitLen())) {
				rg.fatalf("acked, but %v is not in table %s: %v", a, p, tables[p])
			}
			if exp, ok := rg.savedExpiry(p, a); !ok || exp.Before(floor) {
				rg.fatalf("acked, but the snapshot keeps %s %v until %v (present %v), want at least %v", p, a, exp, ok, floor)
			}
		}
	}
}

func rigSubsetOf(r *rand.Rand, from []string, p float64) []string {
	var out []string
	for _, s := range from {
		if r.Float64() < p {
			out = append(out, s)
		}
	}
	return out
}

func (rg *rig) checkResolverEntries(exact bool) {
	rg.t.Helper()
	var got []string
	for _, e := range rg.world.ResolverEntries() {
		got = append(got, e.Domain.String())
	}
	for _, d := range got {
		if !slices.Contains(rigEntries, d) {
			rg.fatalf("resolver entry %s is not an apex or the canary (entries %v)", d, got)
		}
	}
	if exact && !slices.Equal(got, rigEntries) {
		rg.fatalf("converged resolver entries %v, want %v", got, rigEntries)
	}
}

// checkConvergedState checks the state after a convergence, from the
// spec: a voiding problem stops the acks; without one and without failed
// table writes, the daemon acks.
func (rg *rig) checkConvergedState(after string) {
	rg.t.Helper()
	st := rg.status()
	switch {
	case rg.f.voids && st.State != daemon.StateUnenforced:
		rg.fatalf("a voiding problem, but state %v after %s", st.State, after)
	case !rg.f.voids && !rg.f.writes && st.State != daemon.StateReady && st.State != daemon.StateDegraded:
		rg.fatalf("no fault that voids enforcement, but state %v (%q) after %s", st.State, st.Reasons, after)
	}
}

func (rg *rig) heal() {
	time.Sleep(daemon.SelfHealInterval)
	synctest.Wait()
	rg.f.tampered = false
	rg.checkConvergedState("a self-heal")
	rg.logf("heal -> %v", rg.status().State)
}

func (rg *rig) toggleWrites() {
	rg.f.writes = !rg.f.writes
	if rg.f.writes {
		rg.world.SetBeforeWrite(func(int) error { return reconciletest.ErrInjected })
	} else {
		rg.world.SetBeforeWrite(nil)
	}
	rg.logf("writes fail: %v", rg.f.writes)
}

func (rg *rig) toggleVoids() {
	rg.f.voids = !rg.f.voids
	if rg.f.voids {
		rg.world.SetProblems([]reconcile.Problem{{Text: "pf is disabled", Voids: true}}, nil)
	} else {
		rg.world.SetProblems(nil, nil)
	}
	rg.logf("voiding problem: %v", rg.f.voids)
}

// resolverEvent changes the resolver side: the apply delay, an external
// removal, or a problem that does not void enforcement.
func (rg *rig) resolverEvent(r *rand.Rand) {
	switch r.IntN(3) {
	case 0:
		rg.world.SetResolverDelay(r.IntN(2) == 0)
		rg.world.SettleResolver()
		rg.logf("resolver delay toggled")
	case 1:
		d := rigEntries[r.IntN(len(rigEntries))]
		dom, err := policy.ParseDomain(d)
		if err != nil {
			rg.t.Fatal(err)
		}
		rg.world.RemoveResolverEntry(dom)
		rg.logf("external removal of resolver entry %s", d)
	default:
		rg.world.SetProblems(nil, []reconcile.Problem{{Text: "foreign resolver entry for example.com"}})
		rg.f.voids = false
		rg.logf("non-voiding resolver problem")
	}
}

// later lets d pass: the timers that fall in it fire.
func (rg *rig) later(d time.Duration) {
	time.Sleep(d)
	synctest.Wait()
	rg.f.tampered = false
	rg.logf("%v later", d)
}

// event runs one random event.
func (rg *rig) event(r *rand.Rand) {
	switch op := r.IntN(20); {
	case op < 8:
		if rg.checkObserve(r) {
			// The daemon converges right after a report that found the
			// ruleset changed outside.
			rg.f.tampered = false
			rg.checkConvergedState("a report that found the ruleset changed")
		}
	case op == 8:
		rg.toggleWrites()
	case op == 9:
		rg.f.readOnly = !rg.f.readOnly
		rg.setReadOnly(rg.f.readOnly)
		rg.logf("snapshot dir read-only: %v", rg.f.readOnly)
	case op == 10:
		rg.f.resolver = !rg.f.resolver
		rg.resFail.Store(rg.f.resolver)
		rg.logf("resolver writes fail: %v", rg.f.resolver)
	case op == 11:
		rg.world.ExternalLoad([]byte("foreign rules\n"))
		rg.f.tampered = true
		rg.logf("external ruleset load")
	case op == 12:
		rg.world.FlushAll()
		rg.f.tampered = true
		rg.logf("external flush of all")
	case op == 13:
		name := []policy.Name{"web", "ads"}[r.IntN(2)]
		rg.world.FlushTable(name)
		rg.logf("external flush of table %s", name)
	case op == 14:
		rg.toggleVoids()
	case op == 15:
		text := []string{rigCfgA, rigCfgB}[r.IntN(2)]
		err := rg.d.Reconfigure(context.Background(), rigCfg(rg.t, text))
		rg.f.tampered = false
		rg.logf("reconfigure -> %v", err)
	case op == 16:
		if r.IntN(2) == 0 {
			rg.inv.Set(rigEn0)
		} else {
			rg.inv.Set(rigEn0, rigUtun0)
		}
		rg.later(daemon.InterfaceDebounce)
	case op == 17:
		rg.resolverEvent(r)
	case op == 18:
		rg.heal()
	default:
		rg.later(20 * time.Minute)
	}
}

func runAckInvariant(t *testing.T, seed uint64, stats map[string]int) {
	r := rand.New(rand.NewPCG(seed, 0xac4))
	rg := newRig(t, reconciletest.NewWorld(), t.TempDir(), rigCfgA)
	rg.logf("seed %d", seed)
	defer rg.setReadOnly(false)
	defer func() {
		for k, v := range rg.stats {
			stats[k] += v
		}
	}()
	for range 80 {
		rg.event(r)
		rg.checkResolverEntries(false)
	}
	// Settle: without faults the daemon reaches ready, and the resolver
	// entries are exactly the apexes and the canary.
	rg.world.SetBeforeWrite(nil)
	rg.world.SetProblems(nil, nil)
	rg.resFail.Store(false)
	rg.setReadOnly(false)
	rg.f = rigFaults{}
	rg.heal()
	rg.heal()
	if st := rg.status(); st.State != daemon.StateReady {
		rg.fatalf("after settle: state %v (%q), want ready", st.State, st.Reasons)
	}
	rg.checkResolverEntries(true)
	for range 10 {
		rg.checkObserve(r)
	}
}

// Random event sequences: every reply to a report obeys the
// ack invariant, and no report waits.
func TestAckInvariantUnderRandomEvents(t *testing.T) {
	stats := map[string]int{}
	for seed := range uint64(30) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { runAckInvariant(t, seed, stats) })
		})
	}
	t.Logf("outcomes: %v", stats)
	// The runs must reach each outcome that the ack rule names.
	for _, k := range []string{
		"matched ready ack", "matched degraded ack", "matched ready reject",
		"matched unenforced reject", "unmatched ready ack", "unmatched unenforced reject",
		"malformed ready reject",
	} {
		if stats[k] == 0 {
			t.Errorf("no %q case in the random runs", k)
		}
	}
}
