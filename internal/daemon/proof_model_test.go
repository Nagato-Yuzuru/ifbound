package daemon_test

// A model-based check of the ack invariant under owner decision 5,
// independent of model_test.go and of the implementation tests. Random
// operations interleave reports with aliases, probe reports that come at
// once, late, never, for another name, or for a forged nonce, the platform
// settle, resolver-entry write failures, removals and rewrites of entries
// by other processes (with the same or another server), SysResolver
// problems, configuration changes, table and anchor flushes, expiry, and
// restarts.
//
// At the moment Observe returns nil, the oracle checks:
//
//   - P0: each alias has a resolver entry with the listen address;
//   - P1: a probe name below the alias that the daemon sent after the
//     last write of the entry before the report started was reported by
//     ifbound-dns;
//   - P2: a query for the alias reaches ifbound-dns: the most specific
//     applied entry that covers it has the listen address;
//   - the loaded ruleset is the one of the current configuration and has
//     a table for each matched policy, each report address is in those
//     tables, and the snapshot holds the addresses and the aliases.
//
// The matched policies are a lower bound: the configuration text and the
// aliases of earlier acks. Other processes can also rewrite an entry with
// the same server, and entries can never apply (S4 case E).

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrbook"
	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

const pmRetain = time.Hour

type pmPol struct {
	name policy.Name
	apex string
}

var pmCfgs = []struct {
	listen string
	pols   []pmPol
}{
	{"127.0.0.1:10053", []pmPol{{"web", "prot.test"}, {"ads", "ads.test"}}},
	{"127.0.0.1:10053", []pmPol{{"web", "prot.test"}}},
	{"127.0.0.1:10053", []pmPol{{"web", "prot.test"}, {"ads", "ads.test"}, {"mail", "mail.test"}}},
	{"127.0.0.1:10054", []pmPol{{"web", "prot.test"}, {"ads", "ads.test"}}},
}

func pmToml(i int) string {
	var b strings.Builder
	for _, p := range pmCfgs[i].pols {
		fmt.Fprintf(&b, "[[policy]]\nname = %q\nto = [\"*.%s\"]\nonly_via = [\"en0\"]\n", p.name, p.apex)
	}
	return pvConfig(pmCfgs[i].listen, b.String())
}

var (
	pmQNames  = []string{"www.prot.test", "api.prot.test.", "www.ads.test", "x.mail.test", "www.free.test"}
	pmAliases = []string{"a1.cdn.test", "a2.cdn.test", "a3.edge.test", "img.prot.test", "b1.ads.test"}
	pmModes   = []string{pvNow, pvNow, pvNow, pvHold, pvDrop, pvWrong, pvForged}
)

type pmOp struct {
	kind    string
	qname   string
	addrs   []netip.Addr
	aliases []string
	ttl     time.Duration
	s       string // mode, alias
	n       int
}

func (o pmOp) String() string {
	switch o.kind {
	case "report":
		return fmt.Sprintf("report %s %v aliases=%v ttl=%v", o.qname, o.addrs, o.aliases, o.ttl)
	case "sleep":
		return fmt.Sprintf("sleep %v", time.Duration(o.n))
	case "mode", "remove", "rewriteOther", "rewriteSame", "breakNext":
		return o.kind + " " + o.s
	case "reconfigure", "flush", "stray":
		return fmt.Sprintf("%s %d", o.kind, o.n)
	default:
		return o.kind
	}
}

type pmRand struct {
	r      *rand.Rand
	strict bool
}

func (g pmRand) pick(n int) int { return g.r.IntN(n) }

func (g pmRand) report() pmOp {
	o := pmOp{kind: "report"}
	if g.pick(3) == 0 {
		o.qname = pmAliases[g.pick(len(pmAliases))]
	} else {
		o.qname = pmQNames[g.pick(len(pmQNames))]
	}
	o.addrs = []netip.Addr{netip.AddrFrom4([4]byte{198, 18, 0, byte(1 + g.pick(12))})}
	for range g.pick(3) {
		if a := pmAliases[g.pick(len(pmAliases))]; pvCanon(a) != pvCanon(o.qname) {
			o.aliases = append(o.aliases, a)
		}
	}
	if g.pick(30) == 0 {
		o.aliases = append(o.aliases, "co.uk")
	}
	o.ttl = []time.Duration{0, 30 * time.Second, 10 * time.Minute}[g.pick(3)]
	return o
}

func (g pmRand) alias() string { return pmAliases[g.pick(len(pmAliases))] }

// domain picks the entry that another process changes: an alias or an
// apex, so a proof that came through a parent entry is also tested.
func (g pmRand) domain() string {
	all := append(slices.Clone(pmAliases), "prot.test", "ads.test")
	return all[g.pick(len(all))]
}

func (g pmRand) op() pmOp {
	switch k := g.pick(100); {
	case k < 36:
		return g.report()
	case k < 44:
		return pmOp{kind: "mode", s: pmModes[g.pick(len(pmModes))]}
	case k < 50:
		return pmOp{kind: "deliver"}
	case k < 53:
		return pmOp{kind: "stray", n: g.pick(1 << 16)}
	case k < 62:
		return pmOp{kind: "settle"}
	case k < 65:
		return pmOp{kind: "writefail"}
	case k < 68:
		return pmOp{kind: "remove", s: g.domain()}
	case k < 71:
		return pmOp{kind: "rewriteOther", s: g.domain()}
	case k < 74 && g.strict:
		return pmOp{kind: "rewriteSame", s: g.domain()}
	case k < 77 && g.strict:
		return pmOp{kind: "breakNext", s: g.alias()}
	case k < 80:
		return pmOp{kind: "problems"}
	case k < 84:
		return pmOp{kind: "reconfigure", n: g.pick(len(pmCfgs))}
	case k < 88:
		return pmOp{kind: "flush", n: g.pick(3)}
	case k < 97:
		sleeps := []time.Duration{60 * time.Millisecond, 60 * time.Millisecond, 200 * time.Millisecond, 6 * time.Second, 70 * time.Minute}
		return pmOp{kind: "sleep", n: int(sleeps[g.pick(len(sleeps))])}
	case k < 99:
		return pmOp{kind: "restart"}
	default:
		return pmOp{kind: "voids"}
	}
}

func pmGen(seed uint64, steps int, strict bool) []pmOp {
	g := pmRand{rand.New(rand.NewPCG(seed, 0x5)), strict}
	ops := make([]pmOp, steps)
	for i := range ops {
		ops[i] = g.op()
	}
	return ops
}

type pmKey struct {
	pol  policy.Name
	item string
}

// pmRun is one run. Lock order: pmRun.mu, then pvSystem.mu.
type pmRun struct {
	t   *testing.T
	h   *pvH
	sys *pvSystem

	mu         sync.Mutex
	cfg        int
	writes     map[string][]int // domain -> sequence numbers of its writes and removals
	reported   map[string]int   // probe name -> sequence number of its first report
	nextBroken map[string]bool
	problems   bool
	addrs      map[pmKey]time.Time
	aliases    map[pmKey]time.Time
	viol       []string
	stats      map[string]int
	step       int
	pending    sync.WaitGroup
}

func (r *pmRun) violate(kind, format string, args ...any) {
	r.stats["violation "+kind]++
	r.viol = append(r.viol, fmt.Sprintf("step %d [%s]: ", r.step, kind)+fmt.Sprintf(format, args...))
}

// changed records a write or removal of the entry of d. The caller holds
// no lock.
func (r *pmRun) changed(d string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sys.mu.Lock()
	defer r.sys.mu.Unlock()
	r.writes[d] = append(r.writes[d], r.sys.next())
	if r.nextBroken[d] {
		r.sys.broken[d] = true
		delete(r.nextBroken, d)
	} else {
		delete(r.sys.broken, d)
	}
}

func (r *pmRun) seen(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sys.mu.Lock()
	defer r.sys.mu.Unlock()
	if _, ok := r.reported[name]; !ok {
		r.reported[name] = r.sys.next()
	}
}

func (r *pmRun) seq() int {
	r.sys.mu.Lock()
	defer r.sys.mu.Unlock()
	return r.sys.next()
}

func (r *pmRun) configured(p policy.Name) bool {
	return slices.ContainsFunc(pmCfgs[r.cfg].pols, func(x pmPol) bool { return x.name == p })
}

func (r *pmRun) matched(qname string, now time.Time) []policy.Name {
	q := pvCanon(qname)
	var out []policy.Name
	for _, p := range pmCfgs[r.cfg].pols {
		if q == p.apex || strings.HasSuffix(q, "."+p.apex) {
			out = append(out, p.name)
		}
	}
	for k, exp := range r.aliases {
		if k.item == q && now.Before(exp) && r.configured(k.pol) && !slices.Contains(out, k.pol) {
			out = append(out, k.pol)
		}
	}
	return out
}

func (r *pmRun) observe(o ipc.Observation) {
	r.mu.Lock()
	submitted := time.Now()
	m := r.matched(o.QName, submitted)
	d := r.h.d
	r.mu.Unlock()
	startSeq := r.seq()
	ctx, cancel := context.WithTimeout(r.t.Context(), ipc.DefaultTimeout)
	defer cancel()
	err := d.Observe(ctx, o)
	ackSeq := r.seq()
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.stats["no ack"]++
		return
	}
	r.checkAck(o, m, submitted, startSeq, ackSeq)
}

func (r *pmRun) checkAck(o ipc.Observation, m []policy.Name, submitted time.Time, startSeq, ackSeq int) {
	if len(m) == 0 {
		r.stats["ack unmatched"]++
		return
	}
	r.stats["ack matched"]++
	if len(o.Aliases) > 0 {
		r.stats["ack with aliases"]++
	}
	r.checkRuleset(o, m)
	r.checkTables(o, m)
	r.checkProof(o, startSeq, ackSeq)
	r.checkSnapshot(o, m)
	for _, p := range m {
		for _, a := range o.Addrs {
			r.extend(r.addrs, pmKey{p, a.String()}, submitted.Add(max(o.TTL, pmRetain)))
		}
		for _, a := range o.Aliases {
			r.extend(r.aliases, pmKey{p, pvCanon(a.Name)}, submitted.Add(max(a.TTL, pmRetain)))
		}
	}
}

func (r *pmRun) extend(m map[pmKey]time.Time, k pmKey, exp time.Time) {
	if exp.After(m[k]) {
		m[k] = exp
	}
}

func (r *pmRun) checkRuleset(o ipc.Observation, m []policy.Name) {
	want, err := reconciletest.Compiler{}.Compile(pvParse(r.t, pmToml(r.cfg)).Policies, []reconcile.Interface{en0}, reconcile.Accounts{})
	if err != nil {
		r.violate("model", "compile: %v", err)
		return
	}
	if r.h.world.Ruleset().ID() != want.ID() {
		r.violate("ruleset", "ack of %s: the loaded ruleset is not the one of the current configuration", o.QName)
	}
	for _, p := range m {
		if !slices.Contains(r.h.world.Referenced(), p) {
			r.violate("ruleset", "ack of %s: matched policy %s has no table in the loaded ruleset", o.QName, p)
		}
	}
}

func (r *pmRun) checkTables(o ipc.Observation, m []policy.Name) {
	tables := r.h.world.Tables()
	for _, p := range m {
		for _, a := range o.Addrs {
			if !slices.Contains(tables[p], netip.PrefixFrom(a, a.BitLen())) {
				r.violate("table", "ack of %s: %v is not in table %s", o.QName, a, p)
			}
		}
	}
}

// checkProof checks P0, P1, and P2 for each alias. The caller holds r.mu.
func (r *pmRun) checkProof(o ipc.Observation, startSeq, ackSeq int) {
	listen := netip.MustParseAddrPort(pmCfgs[r.cfg].listen)
	entries := r.h.world.ResolverEntries()
	r.sys.mu.Lock()
	defer r.sys.mu.Unlock()
	for _, a := range o.Aliases {
		n := pvCanon(a.Name)
		if !slices.ContainsFunc(entries, func(e reconcile.ResolverEntry) bool { return e.Domain.String() == n && e.Server == listen }) {
			r.violate("P0 entry", "ack of %s: alias %s has no entry with %v", o.QName, n, listen)
		}
		last := 0
		for _, w := range r.writes[n] {
			if w < startSeq {
				last = w
			}
		}
		if !slices.ContainsFunc(r.sys.probes, func(p pvProbe) bool {
			rep, ok := r.reported[p.name]
			return p.alias == n && p.seq > last && ok && rep < ackSeq
		}) {
			r.violate("P1 proof", "ack of %s: no reported probe below %s after its write #%d", o.QName, n, last)
		}
		if srv, ok := r.sys.route(n); !ok || srv != listen {
			r.violate("P2 route", "ack of %s: a query for %s does not reach ifbound-dns (route %v %v)", o.QName, n, srv, ok)
		}
	}
}

func (r *pmRun) checkSnapshot(o ipc.Observation, m []policy.Name) {
	snap := addrbook.New(pmRetain, time.Now)
	if err := snap.Load(r.h.snapshot); err != nil {
		r.violate("snapshot", "ack of %s: snapshot does not load: %v", o.QName, err)
		return
	}
	for _, p := range m {
		for _, a := range o.Addrs {
			if !slices.Contains(snap.Addrs(p), a) {
				r.violate("snapshot", "ack of %s: snapshot of %s lacks %v", o.QName, p, a)
			}
		}
		for _, a := range o.Aliases {
			if dn, _ := dnsname.Parse(a.Name); !slices.Contains(snap.Aliases(p), dn) {
				r.violate("snapshot", "ack of %s: snapshot of %s lacks alias %s", o.QName, p, a.Name)
			}
		}
	}
}

// foreign writes or removes an entry as another process does.
func (r *pmRun) foreign(alias string, server netip.AddrPort, remove, broken bool) {
	d, err := policy.ParseDomain(alias)
	if err != nil {
		r.t.Fatal(err)
	}
	if remove {
		r.h.world.RemoveResolverEntry(d)
	} else if err := r.h.world.Resolver().Write(r.t.Context(), reconcile.ResolverEntry{Domain: d, Server: server}); err != nil {
		r.t.Fatal(err)
	}
	r.mu.Lock()
	r.nextBroken[alias] = broken
	r.mu.Unlock()
	r.changed(alias)
}

func (r *pmRun) exec(o pmOp) {
	switch o.kind {
	case "report":
		obs := ipc.Observation{QName: o.qname, Addrs: o.addrs, TTL: o.ttl}
		for _, a := range o.aliases {
			obs.Aliases = append(obs.Aliases, ipc.Alias{Name: a, TTL: o.ttl})
		}
		r.pending.Go(func() { r.observe(obs) })
	case "mode":
		r.sys.setMode(o.s)
	case "deliver":
		r.sys.deliver()
	case "stray":
		r.stray(o.n)
	case "settle":
		r.h.world.SettleResolver()
	case "writefail":
		r.h.fail.Store(!r.h.fail.Load())
	case "remove":
		r.foreign(o.s, netip.AddrPort{}, true, false)
	case "rewriteOther":
		r.foreign(o.s, netip.MustParseAddrPort("127.0.0.1:53"), false, false)
	case "rewriteSame":
		r.foreign(o.s, netip.MustParseAddrPort(pmCfgs[r.cfg].listen), false, true)
	case "breakNext":
		r.mu.Lock()
		r.nextBroken[o.s] = true
		r.mu.Unlock()
	case "problems":
		r.problems = !r.problems
		r.setProblems()
	default:
		r.execPlatform(o)
	}
	synctest.Wait()
}

func (r *pmRun) execPlatform(o pmOp) {
	switch o.kind {
	case "reconfigure":
		r.mu.Lock()
		for k := range r.addrs {
			if !slices.ContainsFunc(pmCfgs[o.n].pols, func(x pmPol) bool { return x.name == k.pol }) {
				delete(r.addrs, k)
			}
		}
		for k := range r.aliases {
			if !slices.ContainsFunc(pmCfgs[o.n].pols, func(x pmPol) bool { return x.name == k.pol }) {
				delete(r.aliases, k)
			}
		}
		r.cfg = o.n
		r.mu.Unlock()
		r.sys.mu.Lock()
		r.sys.listen = netip.MustParseAddrPort(pmCfgs[o.n].listen) // ifbound-dns restarts on the new address
		r.sys.mu.Unlock()
		r.h.cfg = pmToml(o.n)
		_ = r.h.d.Reconfigure(r.t.Context(), pvParse(r.t, r.h.cfg)) // applies also on error
	case "flush":
		if o.n == 0 {
			r.h.world.FlushAll()
		} else {
			r.h.world.FlushTable(pmCfgs[0].pols[o.n-1].name)
		}
	case "sleep":
		time.Sleep(time.Duration(o.n))
	case "restart":
		r.h.restart()
	case "voids":
		r.h.world.SetProblems([]reconcile.Problem{{Text: "pf is disabled", Voids: true}}, nil)
		time.Sleep(daemon.SelfHealInterval)
		synctest.Wait()
		r.setProblems()
	}
}

func (r *pmRun) setProblems() {
	var rp []reconcile.Problem
	if r.problems {
		rp = []reconcile.Problem{{Text: "a resolver entry is shadowed"}}
	}
	r.h.world.SetProblems(nil, rp)
}

// stray reports out of turn an earlier probe name that reached
// ifbound-dns (a late or repeated report), or a forged one below an
// alias. A name that never reached ifbound-dns is never reported.
func (r *pmRun) stray(n int) {
	r.sys.mu.Lock()
	var routed []string
	for _, p := range r.sys.probes {
		if p.routed {
			routed = append(routed, p.name)
		}
	}
	var name string
	if len(routed) > 0 && n%3 != 0 {
		name = routed[n%len(routed)]
	} else {
		name = fmt.Sprintf("%s%016x.%s", ipc.ProbePrefix, n, pmAliases[n%len(pmAliases)])
	}
	r.sys.mu.Unlock()
	r.sys.report(name)
}

// quiesce ends every fault, settles, converges, and checks that each
// live acknowledged entry is enforced, saved, and, for an alias, routed
// to ifbound-dns.
func (r *pmRun) quiesce() {
	r.h.fail.Store(false)
	r.problems = false
	r.h.world.SetProblems(nil, nil)
	r.mu.Lock()
	clear(r.nextBroken)
	r.mu.Unlock()
	r.sys.mu.Lock()
	clear(r.sys.broken)
	r.sys.mu.Unlock()
	r.sys.setMode(pvNow)
	r.sys.deliver()
	r.h.world.SettleResolver()
	time.Sleep(ipc.DefaultTimeout)
	r.pending.Wait()
	time.Sleep(2 * daemon.SelfHealInterval)
	synctest.Wait()
	r.h.world.SettleResolver()

	st, err := r.h.d.Status(r.t.Context())
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil || st.State != daemon.StateReady {
		r.violate("quiesce", "state %v %q (%v), want ready", st.State, st.Reasons, err)
	}
	snap := addrbook.New(pmRetain, time.Now)
	if err := snap.Load(r.h.snapshot); err != nil {
		r.violate("quiesce", "snapshot: %v", err)
		return
	}
	r.verifyAddrs(snap)
	r.verifyAliases(snap)
}

func (r *pmRun) live(k pmKey, exp time.Time) bool {
	return time.Now().Add(time.Minute).Before(exp) && r.configured(k.pol)
}

func (r *pmRun) verifyAddrs(snap *addrbook.AddrBook) {
	tables := r.h.world.Tables()
	for k, exp := range r.addrs {
		if !r.live(k, exp) {
			continue
		}
		a := netip.MustParseAddr(k.item)
		if !slices.Contains(tables[k.pol], netip.PrefixFrom(a, a.BitLen())) || !slices.Contains(snap.Addrs(k.pol), a) {
			r.violate("quiesce", "acknowledged %v of %s is not in its table and snapshot", a, k.pol)
		}
	}
}

func (r *pmRun) verifyAliases(snap *addrbook.AddrBook) {
	listen := netip.MustParseAddrPort(pmCfgs[r.cfg].listen)
	for k, exp := range r.aliases {
		if !r.live(k, exp) {
			continue
		}
		r.sys.mu.Lock()
		srv, ok := r.sys.route(k.item)
		r.sys.mu.Unlock()
		if !ok || srv != listen {
			r.violate("quiesce", "acknowledged alias %s of %s does not reach ifbound-dns", k.item, k.pol)
		}
		if dn, _ := dnsname.Parse(k.item); !slices.Contains(snap.Aliases(k.pol), dn) {
			r.violate("quiesce", "acknowledged alias %s of %s is not in the snapshot", k.item, k.pol)
		}
	}
}

func pmRunOps(t *testing.T, ops []pmOp) (viol []string, stats map[string]int) {
	synctest.Test(t, func(t *testing.T) {
		r := &pmRun{
			t: t, writes: map[string][]int{}, reported: map[string]int{}, nextBroken: map[string]bool{},
			addrs: map[pmKey]time.Time{}, aliases: map[pmKey]time.Time{}, stats: map[string]int{},
		}
		world := reconciletest.NewWorld()
		r.sys = newPVSystem(world)
		r.sys.onSeen = r.seen
		r.h = pvStart(t, pvOpts{
			delay: true, world: world, sys: r.sys, cfg: pmToml(0),
			snapshot: filepath.Join(t.TempDir(), "addrbook.json"),
			changed:  func(d policy.Domain) { r.changed(d.String()) },
		})
		for i, o := range ops {
			r.mu.Lock()
			r.step = i
			r.mu.Unlock()
			r.exec(o)
		}
		r.mu.Lock()
		r.step = len(ops)
		r.mu.Unlock()
		r.quiesce()
		r.h.stop()
		viol, stats = r.viol, r.stats
	})
	return viol, stats
}

func pmSeeds() int {
	if s := os.Getenv("ORACLE_SEEDS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			return n
		}
	}
	if testing.Short() {
		return 20
	}
	return 150
}

func pmRunSeeds(t *testing.T, strict bool) {
	total := map[string]int{}
	failed := 0
	for seed := range uint64(pmSeeds()) {
		ops := pmGen(seed, 60, strict)
		viol, stats := pmRunOps(t, ops)
		for k, v := range stats {
			total[k] += v
		}
		if len(viol) == 0 {
			continue
		}
		if failed++; failed <= 3 {
			var b strings.Builder
			for i, o := range ops {
				fmt.Fprintf(&b, "  %2d %v\n", i, o)
			}
			t.Errorf("seed %d: %d violations, first: %s\nops:\n%s", seed, len(viol), viol[0], b.String())
		}
	}
	t.Logf("failed seeds: %d of %d; stats: %v", failed, pmSeeds(), total)
	if total["ack with aliases"] == 0 {
		t.Errorf("the model never acked a report with aliases: %v", total)
	}
}

func TestPVModelAckInvariant(t *testing.T) { pmRunSeeds(t, true) }
