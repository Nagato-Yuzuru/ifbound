package daemon_test

// A model-based test of the acknowledgement contract of the daemon. It
// runs random operations (reports, configuration changes, interface
// changes, write and save faults, problems, external flushes and loads,
// time, crashes, restarts, lost snapshots) against a model written from
// the spec. It uses only the public API of the daemon and the
// reconciletest fakes as the platform, and none of the helpers or
// checkers of the other test files, so it checks them independently.
//
// For a longer run: go test ./internal/daemon -run RandomOperations
// -args -model.seeds=2000

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
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

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/matcher"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
	"github.com/Nagato-Yuzuru/ifbound/internal/syslookup"
)

var (
	omSeeds = flag.Int("model.seeds", 100, "number of random seeds of the model test")
	omFirst = flag.Int("model.first", 1, "first seed of the model test")
	omLen   = flag.Int("model.steps", 60, "steps per seed")
	// omStrictVoid makes an ack inside the detection latency of a voiding
	// problem (no Backend.Read since it appeared) a failure. Off, such
	// acks are counted and logged instead.
	omStrictVoid      = flag.Bool("model.strictvoid", false, "fail acks made before the daemon could read a voiding problem")
	omVoidLatencyAcks int
	// omStats counts how often the interesting situations occurred, so a
	// reader can see that the random runs reach them.
	omStats = map[string]int{}
)

const (
	omRetain = time.Hour
	// omSlack is the save slack of the addrbook persist rule for omRetain:
	// min(1h, retain/2). After a restart, an ack is durable only to its
	// expiry minus this slack.
	omSlack = 30 * time.Minute
)

// ---- configuration model ----

type omPol struct {
	Name string
	To   []string
	Via  int
}

type omCfg []omPol

var (
	omVias    = []string{`only_via = ["en0"]`, `only_via = ["utun*"]`, `deny_via = ["@tunnel"]`, `deny_via = ["en1"]`}
	omNames   = []string{"pa", "pb", "pc", "pd"}
	omDomains = []string{"a.example", "b.example", "*.s.example", "*.t.example", "c.example"}
	omStatics = []string{"192.0.2.10", "192.0.2.20", "198.51.100.0/24", "2001:db8::/32"}
	omQNames  = []string{"a.example", "b.example", "s.example", "x.s.example", "deep.y.s.example",
		"w.t.example", "c.example", "X.S.Example.", "nomatch.example"}
	omMalformed = []string{"", "a..b", strings.Repeat("a", 64) + ".example"}

	omEn0   = reconcile.Interface{Name: "en0", Class: policy.ClassHardware}
	omEn1   = reconcile.Interface{Name: "en1", Class: policy.ClassHardware}
	omUtun0 = reconcile.Interface{Name: "utun0", Class: policy.ClassTunnel}
	omIfs   = [][]reconcile.Interface{{omEn0}, {omEn0, omUtun0}, {omEn0, omEn1}, {omUtun0}}
)

func (c omCfg) clone() omCfg {
	out := make(omCfg, len(c))
	for i, p := range c {
		out[i] = omPol{Name: p.Name, To: slices.Clone(p.To), Via: p.Via}
	}
	return out
}

func (c omCfg) toml() string {
	var b strings.Builder
	b.WriteString("[dns]\nlisten = \"127.0.0.1:53553\"\nupstream = [\"tls://1.1.1.1@cloudflare-dns.com\"]\n[addrbook]\nretain = \"1h\"\n")
	for _, p := range c {
		q := make([]string, len(p.To))
		for i, s := range p.To {
			q[i] = fmt.Sprintf("%q", s)
		}
		fmt.Fprintf(&b, "[[policy]]\nname = %q\nto = [%s]\n%s\n", p.Name, strings.Join(q, ", "), omVias[p.Via])
	}
	return b.String()
}

func (c omCfg) String() string {
	var parts []string
	for _, p := range c {
		parts = append(parts, fmt.Sprintf("%s%v/%s", p.Name, p.To, omVias[p.Via]))
	}
	return "{" + strings.Join(parts, "; ") + "}"
}

func (c omCfg) has(name string) bool {
	return slices.ContainsFunc(c, func(p omPol) bool { return p.Name == name })
}

// matches is the matching rule of the policy spec, written here from the
// spec: an exact domain matches itself; "*.x" matches x and every name
// below it. Comparison ignores ASCII case and one final dot.
func (c omCfg) matches(qname string) []string {
	q := strings.ToLower(strings.TrimSuffix(qname, "."))
	var out []string
	for _, p := range c {
		for _, d := range p.To {
			suf, wild := strings.CutPrefix(d, "*.")
			if (!wild && q == d) || (wild && (q == suf || strings.HasSuffix(q, "."+suf))) {
				out = append(out, p.Name)
				break
			}
		}
	}
	return out
}

// staticHost reports whether a is a configured IP destination of the
// policy.
func (c omCfg) staticHost(name string, a netip.Addr) bool {
	for _, p := range c {
		if p.Name != name {
			continue
		}
		for _, d := range p.To {
			if ip, err := netip.ParseAddr(d); err == nil && ip == a {
				return true
			}
		}
	}
	return false
}

// ---- operations ----

type omOp struct {
	Kind    string
	Q       string
	Addrs   []string
	TTL     time.Duration
	Cfg     omCfg
	K       int
	Idx     int
	Table   string
	D       time.Duration
	DelSnap bool
	On      bool
	Sub     *omOp
}

func (o omOp) String() string {
	switch o.Kind {
	case "observe", "unmatched", "malformed", "observeCancelled", "observeCancelMidway":
		return fmt.Sprintf("%s(%q, %v, ttl=%v)", o.Kind, o.Q, o.Addrs, o.TTL)
	case "reconfigure":
		return fmt.Sprintf("reconfigure(%v)", o.Cfg)
	case "ifaces":
		return fmt.Sprintf("ifaces(%v)", omIfs[o.Idx])
	case "failWrite":
		return fmt.Sprintf("failWrite(k=%d)", o.K)
	case "saveFail":
		return fmt.Sprintf("saveFail(%v)", o.On)
	case "problems":
		return fmt.Sprintf("problems(%d)", o.Idx)
	case "flushTable":
		return fmt.Sprintf("flushTable(%s)", o.Table)
	case "flushAll":
		return "flushAll()"
	case "externalLoad":
		return fmt.Sprintf("externalLoad(%d)", o.Idx)
	case "advance":
		return fmt.Sprintf("advance(%v)", o.D)
	case "crash":
		return fmt.Sprintf("crash(fromWrite=%d, during=%v, delSnap=%v)", o.K, o.Sub, o.DelSnap)
	case "restart":
		return fmt.Sprintf("restart(delSnap=%v)", o.DelSnap)
	}
	return o.Kind
}

type omGen struct {
	rng    *rand.Rand
	cfg    omCfg
	unique int
}

func (g *omGen) randomPol(name string) omPol {
	doms := slices.Clone(omDomains)
	g.rng.Shuffle(len(doms), func(i, j int) { doms[i], doms[j] = doms[j], doms[i] })
	sts := slices.Clone(omStatics)
	g.rng.Shuffle(len(sts), func(i, j int) { sts[i], sts[j] = sts[j], sts[i] })
	to := append(doms[:1+g.rng.IntN(2)], sts[:g.rng.IntN(3)]...)
	return omPol{Name: name, To: slices.Clone(to), Via: g.rng.IntN(len(omVias))}
}

func (g *omGen) randomCfg() omCfg {
	names := slices.Clone(omNames)
	g.rng.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
	var c omCfg
	for _, n := range names[:1+g.rng.IntN(3)] {
		c = append(c, g.randomPol(n))
	}
	return c
}

func (g *omGen) mutate(cur omCfg) omCfg {
	c := cur.clone()
	switch g.rng.IntN(6) {
	case 0:
		return g.randomCfg()
	case 1: // only_via <-> deny_via, or another selector
		i := g.rng.IntN(len(c))
		c[i].Via = (c[i].Via + 1 + g.rng.IntN(len(omVias)-1)) % len(omVias)
	case 2: // change destinations
		i := g.rng.IntN(len(c))
		c[i].To = g.randomPol(c[i].Name).To
	case 3: // move a destination to another policy
		if len(c) < 2 {
			return g.randomCfg()
		}
		i, j := g.rng.IntN(len(c)), g.rng.IntN(len(c))
		if i == j || len(c[i].To) < 2 {
			c[i].Via = (c[i].Via + 1) % len(omVias)
			return c
		}
		k := g.rng.IntN(len(c[i].To))
		d := c[i].To[k]
		c[i].To = slices.Delete(c[i].To, k, k+1)
		if !slices.Contains(c[j].To, d) {
			c[j].To = append(c[j].To, d)
		}
	case 4: // add a policy
		for _, n := range omNames {
			if !c.has(n) {
				return append(c, g.randomPol(n))
			}
		}
	case 5: // remove a policy
		if len(c) > 1 {
			i := g.rng.IntN(len(c))
			c = slices.Delete(c, i, i+1)
		}
	}
	return c
}

func (g *omGen) poolAddrs() []string {
	n := 1 + g.rng.IntN(2)
	var out []string
	for range n {
		out = append(out, fmt.Sprintf("203.0.113.%d", 1+g.rng.IntN(10)))
	}
	if g.rng.IntN(5) == 0 {
		out = append(out, fmt.Sprintf("2001:db9::%x", 1+g.rng.IntN(4)))
	}
	return out
}

// uniqueAddr is never reused, so a test can see whether it was stored.
func (g *omGen) uniqueAddr(prefix string) string {
	g.unique++
	return fmt.Sprintf("%s.%d.%d", prefix, g.unique/250, 1+g.unique%250)
}

// qname is mostly a name that a current policy covers.
func (g *omGen) qname() string {
	if g.rng.IntN(10) < 3 {
		return omQNames[g.rng.IntN(len(omQNames))]
	}
	p := g.cfg[g.rng.IntN(len(g.cfg))]
	var doms []string
	for _, d := range p.To {
		if _, err := netip.ParsePrefix(d); err != nil {
			if _, err := netip.ParseAddr(d); err != nil {
				doms = append(doms, d)
			}
		}
	}
	if len(doms) == 0 {
		return omQNames[g.rng.IntN(len(omQNames))]
	}
	d := doms[g.rng.IntN(len(doms))]
	if suf, ok := strings.CutPrefix(d, "*."); ok {
		d = []string{suf, "w." + suf, "deep.y." + suf}[g.rng.IntN(3)]
	}
	if g.rng.IntN(6) == 0 {
		d = strings.ToUpper(d) + "."
	}
	return d
}

func (g *omGen) ttl() time.Duration {
	return []time.Duration{0, time.Minute, 2 * time.Hour}[g.rng.IntN(3)]
}

func (g *omGen) op(allowCrash bool) omOp {
	r := g.rng.IntN(100)
	switch {
	case r < 30:
		return omOp{Kind: "observe", Q: g.qname(), Addrs: g.poolAddrs(), TTL: g.ttl()}
	case r < 34:
		return omOp{Kind: "unmatched", Q: "zz.unrelated.test", Addrs: []string{g.uniqueAddr("100.64")}, TTL: g.ttl()}
	case r < 37:
		return omOp{Kind: "malformed", Q: omMalformed[g.rng.IntN(len(omMalformed))], Addrs: []string{g.uniqueAddr("100.64")}, TTL: g.ttl()}
	case r < 40:
		return omOp{Kind: "observeCancelled", Q: omQNames[g.rng.IntN(len(omQNames)-1)], Addrs: []string{g.uniqueAddr("198.18")}, TTL: g.ttl()}
	case r < 43:
		return omOp{Kind: "observeCancelMidway", Q: omQNames[g.rng.IntN(len(omQNames)-1)], Addrs: []string{g.uniqueAddr("198.18")}, TTL: g.ttl()}
	case r < 53:
		g.cfg = g.mutate(g.cfg)
		return omOp{Kind: "reconfigure", Cfg: g.cfg.clone()}
	case r < 57:
		return omOp{Kind: "ifaces", Idx: g.rng.IntN(len(omIfs))}
	case r < 65:
		return omOp{Kind: "failWrite", K: 1 + g.rng.IntN(6)}
	case r < 69:
		return omOp{Kind: "saveFail", On: g.rng.IntN(2) == 0}
	case r < 75:
		return omOp{Kind: "problems", Idx: g.rng.IntN(5)}
	case r < 79:
		return omOp{Kind: "flushTable", Table: omNames[g.rng.IntN(len(omNames))]}
	case r < 81:
		return omOp{Kind: "flushAll"}
	case r < 83:
		return omOp{Kind: "externalLoad", Idx: g.rng.IntN(2)}
	case r < 93:
		d := []time.Duration{600 * time.Millisecond, 5 * time.Second, 31 * time.Minute, 61 * time.Minute, 2*time.Hour + time.Minute}[g.rng.IntN(5)]
		return omOp{Kind: "advance", D: d}
	case r < 97 && allowCrash:
		sub := g.op(false)
		return omOp{Kind: "crash", K: 1 + g.rng.IntN(4), Sub: &sub, DelSnap: g.rng.IntN(3) == 0}
	default:
		return omOp{Kind: "restart", DelSnap: g.rng.IntN(3) == 0}
	}
}

func omGenerate(seed uint64, steps int) (omCfg, []omOp) {
	g := &omGen{rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
	g.cfg = g.randomCfg()
	initial := g.cfg.clone()
	var ops []omOp
	for len(ops) < steps {
		if g.rng.IntN(25) == 0 && len(g.cfg) > 1 {
			// A removal whose convergence fails, then a revert: the
			// revert must still find the acked addresses (spec 4).
			prev := g.cfg.clone()
			i := g.rng.IntN(len(g.cfg))
			g.cfg = slices.Delete(g.cfg.clone(), i, i+1)
			ops = append(ops, omOp{Kind: "failWrite", K: 1 + g.rng.IntN(3)},
				omOp{Kind: "reconfigure", Cfg: g.cfg.clone()},
				omOp{Kind: "reconfigure", Cfg: prev.clone()})
			g.cfg = prev
			continue
		}
		ops = append(ops, g.op(true))
	}
	return initial, ops
}

// ---- runner and model ----

type omKey struct {
	P string
	A netip.Addr
}

type omEntry struct {
	mem, disk time.Time // the guaranteed expiry in this process, and after a restart
	taint     bool      // known unprotected through an external event or a config change
	taintSeq  int       // readSeq when the taint started
}

const (
	segNone = iota
	segBackend
	segResolver
)

type omRun struct {
	t     *testing.T
	world *reconciletest.World
	inv   *reconciletest.Inventory
	snap  string
	dir   string

	d      *daemon.Daemon
	cancel context.CancelFunc
	done   chan error

	mu      sync.Mutex
	cfg     omCfg
	pcfg    policy.Config
	tracked map[omKey]*omEntry
	pending map[omKey]*omEntry // entries of removed policies, kept for a revert until a prune is due

	readSeq                 int
	voidOn, nonvoidOn       bool
	voidSeq, nonvoidSeq     int
	rsDamageSeq             int
	seg, phase              int
	segFailed               bool
	resolverFailed          []string // domains of the failed resolver Writes in this convergence
	failAt, failFrom        int
	saveFail                bool
	block, entered, release chan struct{}
	adoptPending            bool
	adoptExpect             []omKey
	adoptForbid             []omKey
	violations              []string
	step                    int
}

func (r *omRun) violate(format string, args ...any) {
	r.violations = append(r.violations, fmt.Sprintf("step %d: ", r.step)+fmt.Sprintf(format, args...))
}

func (r *omRun) setCfg(c omCfg) {
	pc, err := policy.ParseBytes([]byte(c.toml()))
	if err != nil {
		r.t.Fatalf("generated config does not parse: %v\n%s", err, c.toml())
	}
	r.cfg, r.pcfg = c, pc
}

func (r *omRun) pol(name string) (policy.Policy, bool) {
	for _, p := range r.pcfg.Policies {
		if string(p.Name) == name {
			return p, true
		}
	}
	return policy.Policy{}, false
}

// line is the ruleset line that refers to the table of p with its
// constraint, as the platform compiler writes it.
func omLine(p policy.Policy) []byte {
	rs, err := reconciletest.Compiler{}.Compile([]policy.Policy{p}, nil, reconcile.Accounts{})
	if err != nil {
		panic(err) // an empty line is a prefix of every body, so omRefers would match anything
	}
	return rs.Body()
}

func omRefers(body []byte, p policy.Policy) bool {
	l := omLine(p)
	return bytes.HasPrefix(body, l) || bytes.Contains(body, append([]byte("\n"), l...))
}

type omView struct {
	tables map[policy.Name][]netip.Prefix
	body   []byte
	void   bool
}

func (r *omRun) view() omView {
	st, _ := r.world.Backend().Read(context.Background()) //nolint:errcheck // the fake never fails
	return omView{
		tables: st.Tables,
		body:   r.world.Ruleset().Body(),
		void:   slices.ContainsFunc(st.Problems, func(p reconcile.Problem) bool { return p.Voids }),
	}
}

func omHost(a netip.Addr) netip.Prefix { return netip.PrefixFrom(a, a.BitLen()) }

// unprotected returns why k leaks, or "".
func (r *omRun) unprotected(v omView, k omKey) string {
	p, ok := r.pol(k.P)
	switch {
	case !ok:
		return "policy is not current"
	case !slices.Contains(v.tables[policy.Name(k.P)], omHost(k.A)):
		return "missing from its table"
	case !omRefers(v.body, p):
		return "loaded ruleset does not refer to the table with the current constraint"
	case v.void:
		return "a problem voids enforcement"
	}
	return ""
}

// checkLocked drops expired entries and reports a LEAK for every tracked
// entry that is unprotected without an excuse.
func (r *omRun) checkLocked(where string) {
	now := time.Now()
	v := r.view()
	for k, e := range r.pending {
		if !now.Before(e.mem) {
			delete(r.pending, k)
		}
	}
	for k, e := range r.tracked {
		if !now.Before(e.mem) {
			delete(r.tracked, k)
			continue
		}
		why := r.unprotected(v, k)
		if why == "" {
			e.taint = false
			continue
		}
		if !e.taint {
			r.violate("LEAK at %s: %s/%v %s", where, k.P, k.A, why)
			e.taint, e.taintSeq = true, r.readSeq
		}
	}
}

func (r *omRun) check(where string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checkLocked(where)
}

// taintLocked marks the entries that an external event or a config change
// left unprotected.
func (r *omRun) taintLocked() {
	v := r.view()
	for k, e := range r.tracked {
		if r.unprotected(v, k) != "" && !e.taint {
			e.taint, e.taintSeq = true, r.readSeq
		}
	}
}

// ---- platform probes: they record the call trace, never change results ----

type omBackend struct {
	in *reconciletest.Backend
	r  *omRun
}

const (
	kAdd = iota + 1
	kLoad
	kRemove
	kDrop
)

var kNames = map[int]string{kAdd: "AddEntries", kLoad: "Load", kRemove: "RemoveEntries", kDrop: "DropTable"}

func (b *omBackend) Read(ctx context.Context) (reconcile.BackendState, error) {
	st, err := b.in.Read(ctx)
	b.r.mu.Lock()
	b.r.readSeq++
	b.r.seg, b.r.phase, b.r.segFailed = segBackend, 0, false
	b.r.mu.Unlock()
	return st, err
}

func (b *omBackend) LoadedID(ctx context.Context) (string, error) { return b.in.LoadedID(ctx) }

func (b *omBackend) pre(kind int) {
	r := b.r
	r.mu.Lock()
	defer r.mu.Unlock()
	omStats["write "+kNames[kind]]++
	if r.seg != segBackend {
		if kind != kAdd {
			r.violate("spec3: %s outside a convergence", kNames[kind])
		}
		r.seg = segNone
		return
	}
	if r.segFailed {
		r.violate("spec3: %s after a failed Backend write in the same convergence", kNames[kind])
	}
	if kind < r.phase {
		r.violate("spec3: %s after %s in one convergence", kNames[kind], kNames[r.phase])
	}
	r.phase = kind
}

func (b *omBackend) post(err error) {
	b.r.mu.Lock()
	defer b.r.mu.Unlock()
	if err != nil && b.r.seg == segBackend {
		b.r.segFailed = true
	}
}

func (b *omBackend) Load(ctx context.Context, rs reconcile.Ruleset) error {
	b.pre(kLoad)
	ifs, _ := b.r.inv.Interfaces(ctx) //nolint:errcheck // the fake inventory never fails
	b.r.mu.Lock()
	want, cerr := reconciletest.Compiler{}.Compile(b.r.pcfg.Policies, ifs, reconcile.Accounts{})
	if cerr != nil {
		b.r.violate("spec3: compile of the current config: %v", cerr)
	}
	if rs.ID() != want.ID() {
		b.r.violate("spec3: Load of a ruleset that is not the one for the current config and interfaces")
	}
	if b.r.world.Ruleset().ID() == rs.ID() {
		b.r.violate("spec3: Load of the ruleset that is already loaded")
	}
	b.r.mu.Unlock()
	err := b.in.Load(ctx, rs)
	b.post(err)
	return err
}

func (b *omBackend) AddEntries(ctx context.Context, t policy.Name, e []netip.Prefix) error {
	b.pre(kAdd)
	err := b.in.AddEntries(ctx, t, e)
	b.post(err)
	return err
}

func (b *omBackend) RemoveEntries(ctx context.Context, t policy.Name, e []netip.Prefix) error {
	b.pre(kRemove)
	err := b.in.RemoveEntries(ctx, t, e)
	b.post(err)
	return err
}

func (b *omBackend) DropTable(ctx context.Context, t policy.Name) error {
	b.pre(kDrop)
	err := b.in.DropTable(ctx, t)
	b.post(err)
	return err
}

type omResolver struct {
	in *reconciletest.Resolver
	r  *omRun
}

func (s *omResolver) Read(ctx context.Context) (reconcile.ResolverState, error) {
	st, err := s.in.Read(ctx)
	r := s.r
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seg != segBackend {
		r.violate("spec3: resolver part without a backend part before it")
	} else if !r.segFailed {
		// The backend part succeeded for a config without the pending
		// policies: from here on a prune of them is due (spec 4).
		omStats["prune due with pending entries"] += min(len(r.pending), 1)
		clear(r.pending)
	}
	r.seg, r.phase, r.segFailed, r.resolverFailed = segResolver, 0, false, nil
	return st, err
}

// write checks the order of the resolver part: every Write before every
// Remove, and no Remove of an entry on the same label path as a domain
// whose Write failed. A failed write does not stop the others.
func (s *omResolver) write(kind int, name string, d policy.Domain, f func() error) error {
	r := s.r
	r.mu.Lock()
	switch {
	case r.seg != segResolver:
		r.violate("spec3: resolver %s outside a convergence", name)
	case kind < r.phase:
		r.violate("spec3: resolver %s after a resolver Remove", name)
	case kind == 2 && slices.ContainsFunc(r.resolverFailed, func(f string) bool {
		return f == d.String() || strings.HasSuffix(f, "."+d.String()) || strings.HasSuffix(d.String(), "."+f)
	}):
		r.violate("spec3: resolver Remove of %s on the label path of a failed resolver Write", d)
	}
	r.phase = kind
	r.mu.Unlock()
	err := f()
	if err != nil && kind == 1 {
		r.mu.Lock()
		r.resolverFailed = append(r.resolverFailed, d.String())
		r.mu.Unlock()
	}
	return err
}

func (s *omResolver) Write(ctx context.Context, e reconcile.ResolverEntry) error {
	return s.write(1, "Write", e.Domain, func() error { return s.in.Write(ctx, e) })
}

func (s *omResolver) Remove(ctx context.Context, d policy.Domain) error {
	return s.write(2, "Remove", d, func() error { return s.in.Remove(ctx, d) })
}

// omLookup is the system resolver with ifbound-dns: a probe name goes to
// ifbound-dns when an applied entry covers it, and ifbound-dns reports
// it. The warm-up of the daemon sends its probes here.
type omLookup struct{ r *omRun }

func (l omLookup) Resolve(_ context.Context, name string) ([]netip.Addr, error) {
	l.r.mu.Lock()
	routed := ipc.IsProbe(name) && l.r.routedLocked(name)
	d := l.r.d
	l.r.mu.Unlock()
	if routed {
		d.ProbeSeen(name)
	}
	return nil, fmt.Errorf("resolve %s: %w", name, syslookup.ErrNotFound)
}

// routedLocked reports whether the system sends the queries for name to
// ifbound-dns: the most specific applied entry that covers it has the
// listen address.
func (r *omRun) routedLocked(name string) bool {
	best, found := "", false
	var to netip.AddrPort
	for _, e := range r.world.AppliedResolverEntries() {
		d := e.Domain.String()
		if (name == d || strings.HasSuffix(name, "."+d)) && (!found || len(d) > len(best)) {
			best, found, to = d, true, e.Server
		}
	}
	return found && to == r.pcfg.DNS.Listen
}

// ---- daemon lifecycle ----

func (r *omRun) start() {
	r.mu.Lock()
	pc := r.pcfg
	r.mu.Unlock()
	r.d = daemon.New(daemon.Config{
		Policy:   pc,
		Snapshot: r.snap,
		Platform: reconcile.Reconciler{
			Compiler:  reconciletest.Compiler{},
			Backend:   &omBackend{in: r.world.Backend(), r: r},
			Resolver:  &omResolver{in: r.world.Resolver(), r: r},
			Inventory: r.inv,
		},
		Lookup: omLookup{r},
	})
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel, r.done = cancel, make(chan error, 1)
	go func() { r.done <- r.d.Run(ctx) }()
	synctest.Wait()
}

func (r *omRun) stop() {
	r.cancel()
	if err := <-r.done; err != nil {
		r.violate("Run returned %v, want nil", err)
	}
}

func (r *omRun) restart(delSnap bool) {
	r.stop()
	r.mu.Lock()
	r.failAt, r.failFrom, r.block = 0, 0, nil
	if delSnap {
		r.deleteSnapshotLocked()
	}
	now := time.Now()
	for _, m := range []map[omKey]*omEntry{r.tracked, r.pending} {
		for _, e := range m {
			e.mem = e.disk
		}
	}
	if delSnap {
		r.expectAdoptionLocked(now)
	}
	r.mu.Unlock()
	r.start()
}

// deleteSnapshotLocked removes the snapshot. The directory may be
// read-only for a Save fault; the removal must still happen.
func (r *omRun) deleteSnapshotLocked() {
	if err := os.Chmod(r.dir, 0o700); err != nil {
		r.t.Fatal(err)
	}
	if err := os.Remove(r.snap); err != nil && !errors.Is(err, os.ErrNotExist) {
		r.t.Fatal(err)
	}
	if r.saveFail {
		if err := os.Chmod(r.dir, 0o500); err != nil {
			r.t.Fatal(err)
		}
	}
}

// expectAdoptionLocked updates the model for a start without a snapshot.
func (r *omRun) expectAdoptionLocked(now time.Time) {
	clear(r.pending)
	r.computeAdoption()
	for k, e := range r.tracked {
		if slices.Contains(r.adoptExpect, k) {
			e.mem, e.disk = now.Add(omRetain), now.Add(omRetain)
		} else {
			delete(r.tracked, k) // lost with the snapshot and the kernel: a double fault
		}
	}
	r.adoptPending = true
}

// computeAdoption derives what an adoption must save from the kernel
// tables and the current config. The daemon writes nothing while it is
// starting, so the tables are those of the restart, less external flushes.
func (r *omRun) computeAdoption() {
	{
		v := r.view()
		r.adoptExpect, r.adoptForbid = nil, nil
		for _, p := range r.cfg {
			for _, pf := range v.tables[policy.Name(p.Name)] {
				if !pf.IsSingleIP() {
					continue
				}
				k := omKey{p.Name, pf.Addr()}
				if r.cfg.staticHost(p.Name, pf.Addr()) {
					r.adoptForbid = append(r.adoptForbid, k)
				} else {
					r.adoptExpect = append(r.adoptExpect, k)
				}
			}
		}
	}
}

// ---- snapshot reader, written from the file format ----

type omSnapEntry struct {
	Policy string `json:"policy"`
	Addr   string `json:"addr"`
	Expiry int64  `json:"expiry_unix_nano"`
}

func (r *omRun) snapEntries() []omSnapEntry {
	data, err := os.ReadFile(r.snap)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		r.violate("reading snapshot: %v", err)
		return nil
	}
	var f struct {
		Entries []omSnapEntry `json:"entries"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		r.violate("snapshot is not JSON: %v", err)
	}
	return f.Entries
}

func (r *omRun) snapExpiry(k omKey) (time.Time, bool) {
	for _, e := range r.snapEntries() {
		if e.Policy == k.P && e.Addr == k.A.String() {
			return time.Unix(0, e.Expiry), true
		}
	}
	return time.Time{}, false
}

// ---- checks around requests ----

func (r *omRun) status() daemon.Status {
	st, err := r.d.Status(context.Background())
	if err != nil {
		r.violate("Status: %v", err)
	}
	return st
}

func acksState(s daemon.State) bool { return s == daemon.StateReady || s == daemon.StateDegraded }

func (r *omRun) statusCheck() {
	st := r.status()
	r.mu.Lock()
	defer r.mu.Unlock()
	if st.Policies != len(r.cfg) {
		r.violate("status: Policies=%d, want %d", st.Policies, len(r.cfg))
	}
	if st.RetainRestart {
		r.violate("status: RetainRestart with an unchanged retain")
	}
	if (st.State == daemon.StateReady) != (len(st.Reasons) == 0) {
		r.violate("status: state %v with reasons %q", st.State, st.Reasons)
	}
	if acksState(st.State) {
		r.checkAckingStatusLocked(st)
	}
	if st.State != daemon.StateStarting {
		r.checkAddrCountLocked(st)
	}
	omStats["status "+st.State.String()]++
	if r.adoptPending && st.State != daemon.StateStarting {
		r.checkAdoptionLocked()
	}
}

func (r *omRun) checkAckingStatusLocked(st daemon.Status) {
	if r.rsDamageSeq < r.readSeq {
		body := r.world.Ruleset().Body()
		for _, p := range r.pcfg.Policies {
			if !omRefers(body, p) {
				r.violate("status: %v but the loaded ruleset lacks %s with its current constraint", st.State, p.Name)
			}
		}
	}
	if r.voidOn && r.readSeq > r.voidSeq {
		r.violate("status: %v with a known voiding problem", st.State)
	}
	if st.State == daemon.StateReady && r.nonvoidOn && r.readSeq > r.nonvoidSeq {
		r.violate("status: ready with a known problem")
	}
}

func (r *omRun) checkAddrCountLocked(st daemon.Status) {
	n := 0
	for k := range r.tracked {
		if r.cfg.has(k.P) {
			n++
		}
	}
	if st.Addrs < n {
		r.violate("status: Addrs=%d, but %d acked entries are unexpired", st.Addrs, n)
	}
}

func (r *omRun) checkAdoptionLocked() {
	omStats["adoption checked, entries"] += len(r.adoptExpect)
	omStats["adoption checked"]++
	r.adoptPending = false
	for _, k := range r.adoptExpect {
		if _, ok := r.snapExpiry(k); !ok {
			r.violate("spec5: left starting without %s/%v in the saved snapshot", k.P, k.A)
		}
	}
	for _, k := range r.adoptForbid {
		if _, ok := r.snapExpiry(k); ok {
			r.violate("spec5: adopted the configured IP destination %s/%v", k.P, k.A)
		}
	}
}

// onAck applies the model update and every ack-time check.
func (r *omRun) onAck(pre daemon.Status, q string, addrs []netip.Addr, ttl time.Duration, unique bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !acksState(pre.State) {
		r.violate("spec1/2: ack of %q in state %v", q, pre.State)
	}
	matched := r.cfg.matches(q)
	omStats["ack "+pre.State.String()]++
	if len(matched) == 0 {
		omStats["ack unmatched"]++
		if unique {
			r.checkNotStoredLocked("spec1: unmatched "+strconv.Quote(q), addrs, true)
		}
		return
	}
	now := time.Now()
	r.recordAckLocked(matched, addrs, now.Add(max(ttl, omRetain)))
	v := r.view()
	for _, p := range r.pcfg.Policies {
		if !omRefers(v.body, p) {
			r.violate("spec1: ack while the loaded ruleset lacks %s with its current constraint", p.Name)
		}
	}
	if r.voidOn && r.readSeq > r.voidSeq {
		r.violate("spec2: ack while a known problem voids enforcement")
	}
	r.checkTrackedAtAckLocked(v, q, now)
}

// checkNotStoredLocked reports each address that reached a table, or the
// snapshot when inSnapshot is set.
func (r *omRun) checkNotStoredLocked(what string, addrs []netip.Addr, inSnapshot bool) {
	v := r.view()
	for _, a := range addrs {
		for name, t := range v.tables {
			if slices.Contains(t, omHost(a)) {
				r.violate("%s stored %v in table %s", what, a, name)
			}
		}
		if !inSnapshot {
			continue
		}
		for _, e := range r.snapEntries() {
			if e.Addr == a.String() {
				r.violate("%s stored %v in the snapshot", what, a)
			}
		}
	}
}

func (r *omRun) recordAckLocked(matched []string, addrs []netip.Addr, exp time.Time) {
	omStats["ack matched"]++
	if len(r.tracked) > 0 {
		omStats["ack with earlier acked entries"]++
	}
	for _, p := range matched {
		for _, a := range addrs {
			k := omKey{p, a}
			e := r.tracked[k]
			if e == nil {
				e = &omEntry{}
				r.tracked[k] = e
			}
			e.taint = false
			if exp.After(e.mem) {
				e.mem = exp
			}
			if d := exp.Add(-omSlack); d.After(e.disk) {
				e.disk = d
			}
			if got, ok := r.snapExpiry(k); !ok || got.Before(exp.Add(-omSlack)) {
				r.violate("spec1: ack of %s/%v, snapshot expiry %v (present %v), want >= %v", p, a, got, ok, exp.Add(-omSlack))
			}
		}
	}
}

func (r *omRun) checkTrackedAtAckLocked(v omView, q string, now time.Time) {
	for k, e := range r.tracked {
		if !now.Before(e.mem) {
			delete(r.tracked, k)
			continue
		}
		why := r.unprotected(v, k)
		if why == "a problem voids enforcement" && !e.taint && r.readSeq == r.voidSeq && !*omStrictVoid {
			// The daemon cannot know yet: no convergence has read the problem.
			omVoidLatencyAcks++
			e.taint, e.taintSeq = true, r.voidSeq
			continue
		}
		switch {
		case why == "":
			e.taint = false
		case !e.taint:
			r.violate("LEAK at ack of %q: %s/%v %s", q, k.P, k.A, why)
			e.taint, e.taintSeq = true, r.readSeq
		case r.readSeq > e.taintSeq:
			r.violate("LEAK at ack of %q: %s/%v %s, and a convergence has read the damage since", q, k.P, k.A, why)
		}
	}
}

func omAddrs(ss []string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func (r *omRun) faultsArmed() bool {
	return r.failFrom > 0 || r.failAt > r.world.Writes() || r.saveFail || r.rsDamageSeq >= r.readSeq || r.block != nil
}

func (r *omRun) observe(o omOp) {
	pre := r.status()
	addrs := omAddrs(o.Addrs)
	obs := ipc.Observation{QName: o.Q, Addrs: addrs, TTL: o.TTL}
	r.mu.Lock()
	armed := r.faultsArmed()
	matched := r.cfg.matches(o.Q)
	r.mu.Unlock()

	var (
		err error
		ack ipc.Ack
		// flagged is true when ack is the reply to obs.
		flagged bool
	)
	switch o.Kind {
	case "observeCancelled":
		if err = r.observeCancelled(obs); errors.Is(err, context.Canceled) {
			return
		}
	case "observeCancelMidway":
		err = r.observeCancelMidway(obs)
	default:
		ack, err = r.d.Observe(context.Background(), obs)
		flagged = true
	}

	r.mu.Lock()
	if flagged && err == nil && ack.Protected != (len(matched) > 0) {
		r.violate("spec: ack of %q has protected=%v, but it matches %d policies", o.Q, ack.Protected, len(matched))
	}
	r.checkObserveResultLocked(pre.State, o, len(matched) > 0, armed, err)
	r.mu.Unlock()
	if err == nil {
		r.onAck(pre, o.Q, addrs, o.TTL, o.Kind != "observe")
	}
	if o.Kind == "malformed" {
		r.mu.Lock()
		r.checkNotStoredLocked("spec1: malformed name", addrs, false)
		r.mu.Unlock()
	}
}

// observeCancelled reports with a context that has already ended.
func (r *omRun) observeCancelled(obs ipc.Observation) error {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := r.d.Observe(ctx, obs)
	r.mu.Lock()
	defer r.mu.Unlock()
	omStats["pre-cancelled: "+fmt.Sprint(errors.Is(err, context.Canceled))]++
	if errors.Is(err, context.Canceled) {
		r.checkNotStoredLocked("spec6: Observe returned ctx.Err but", obs.Addrs, false)
	}
	return err
}

// observeCancelMidway ends the context of a report while the loop works
// on it, if the report reaches a write.
func (r *omRun) observeCancelMidway(obs ipc.Observation) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	r.mu.Lock()
	r.block, r.entered, r.release = entered, entered, release
	r.mu.Unlock()
	res := make(chan error, 1)
	go func() {
		_, err := r.d.Observe(ctx, obs)
		res <- err
	}()
	synctest.Wait()
	taken := false
	select {
	case <-entered:
		r.mu.Lock()
		omStats["cancel while taken"]++
		r.mu.Unlock()
		taken = true
		cancel()
		close(release)
	default:
	}
	err := <-res
	r.mu.Lock()
	defer r.mu.Unlock()
	r.block = nil
	if taken && errors.Is(err, context.Canceled) {
		r.violate("spec6: a request the loop took returned ctx.Err instead of its reply")
	}
	return err
}

func (r *omRun) checkObserveResultLocked(pre daemon.State, o omOp, matched, armed bool, err error) {
	switch pre {
	case daemon.StateStarting:
		if err != nil && !errors.Is(err, daemon.ErrNotReady) {
			r.violate("Observe in starting = %v, want ErrNotReady", err)
		}
	case daemon.StateUnenforced:
		if err != nil && !errors.Is(err, daemon.ErrUnenforced) {
			r.violate("Observe in unenforced = %v, want ErrUnenforced", err)
		}
	case daemon.StateReady, daemon.StateDegraded:
		if o.Kind == "malformed" && !errors.Is(err, matcher.ErrMalformedName) {
			r.violate("spec1: malformed %q = %v, want ErrMalformedName", o.Q, err)
		}
		if o.Kind != "malformed" && !matched && err != nil {
			r.violate("spec1: unmatched %q = %v, want an ack", o.Q, err)
		}
		if o.Kind == "observe" && matched && err != nil && !armed {
			r.violate("liveness: %q rejected in %v with no fault armed: %v", o.Q, pre, err)
		}
	default:
		r.violate("unknown state %v", pre)
	}
}

func (r *omRun) exec(o omOp) {
	switch o.Kind {
	case "observe", "unmatched", "malformed", "observeCancelled", "observeCancelMidway":
		r.observe(o)
	case "reconfigure":
		r.reconfigure(o.Cfg)
	case "ifaces":
		r.inv.Set(omIfs[o.Idx]...)
	case "failWrite":
		r.mu.Lock()
		r.failAt = r.world.Writes() + o.K
		r.mu.Unlock()
	case "saveFail":
		r.setSaveFail(o.On)
	case "problems":
		r.setProblems(o.Idx)
	case "flushTable", "flushAll":
		r.flush(o)
	case "externalLoad":
		r.externalLoad(o.Idx)
	case "advance":
		time.Sleep(o.D)
	case "crash":
		r.mu.Lock()
		r.failFrom = r.world.Writes() + o.K
		r.mu.Unlock()
		r.exec(*o.Sub)
		synctest.Wait()
		r.check("crash point")
		r.restart(o.DelSnap)
	case "restart":
		r.restart(o.DelSnap)
	}
}

func (r *omRun) reconfigure(cfg omCfg) {
	r.mu.Lock()
	for k, e := range r.tracked {
		if !cfg.has(k.P) {
			r.pending[k] = e
			delete(r.tracked, k)
		}
	}
	for k, e := range r.pending {
		if cfg.has(k.P) {
			omStats["revert restores pending entry"]++
			e.taint = false
			r.tracked[k] = e
			delete(r.pending, k)
		}
	}
	r.setCfg(cfg.clone())
	if r.adoptPending {
		r.computeAdoption()
	}
	r.taintLocked()
	pc := r.pcfg
	r.mu.Unlock()
	_ = r.d.Reconfigure(context.Background(), pc) //nolint:errcheck // injected faults can fail it; the status check judges the outcome
}

func (r *omRun) setSaveFail(on bool) {
	mode := os.FileMode(0o700)
	if on {
		mode = 0o500
	}
	if err := os.Chmod(r.dir, mode); err != nil {
		r.t.Fatal(err)
	}
	r.mu.Lock()
	r.saveFail = on
	r.mu.Unlock()
}

func (r *omRun) setProblems(idx int) {
	var be, rs []reconcile.Problem
	void := reconcile.Problem{Text: "pf is disabled", Voids: true}
	soft := reconcile.Problem{Text: "a soft backend problem"}
	conflict := reconcile.Problem{Text: "foreign resolver entry"}
	switch idx {
	case 1:
		be = []reconcile.Problem{void}
	case 2:
		be = []reconcile.Problem{soft}
	case 3:
		rs = []reconcile.Problem{conflict}
	case 4:
		be, rs = []reconcile.Problem{void}, []reconcile.Problem{conflict}
	}
	r.world.SetProblems(be, rs)
	r.mu.Lock()
	defer r.mu.Unlock()
	newVoid := idx == 1 || idx == 4
	if newVoid && !r.voidOn {
		r.voidSeq = r.readSeq
	}
	r.voidOn = newVoid
	newSoft := idx >= 2
	if newSoft && !r.nonvoidOn {
		r.nonvoidSeq = r.readSeq
	}
	r.nonvoidOn = newSoft
	r.taintLocked()
}

func (r *omRun) flush(o omOp) {
	if o.Kind == "flushAll" {
		r.world.FlushAll()
	} else {
		r.world.FlushTable(policy.Name(o.Table))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if o.Kind == "flushAll" {
		r.rsDamageSeq = r.readSeq
	}
	if r.adoptPending {
		r.forgetFlushedBeforeAdoptionLocked()
	}
	r.taintLocked()
}

// forgetFlushedBeforeAdoptionLocked drops what a flush removed before the
// daemon could adopt it.
func (r *omRun) forgetFlushedBeforeAdoptionLocked() {
	v := r.view()
	for k := range r.tracked {
		if r.unprotected(v, k) == "missing from its table" {
			delete(r.tracked, k)
		}
	}
	r.adoptExpect = slices.DeleteFunc(r.adoptExpect, func(k omKey) bool {
		return !slices.Contains(v.tables[policy.Name(k.P)], omHost(k.A))
	})
}

// externalLoad has another tool load a ruleset into the anchor: "pass
// all", or the current tables with other constraints.
func (r *omRun) externalLoad(idx int) {
	rs := reconcile.NewRuleset([]byte("pass all\n"))
	if idx == 1 {
		r.mu.Lock()
		c := r.cfg.clone()
		r.mu.Unlock()
		for i := range c {
			c[i].Via = (c[i].Via + 1) % len(omVias)
		}
		pc, err := policy.ParseBytes([]byte(c.toml()))
		if err != nil {
			r.t.Fatal(err)
		}
		rs, err = reconciletest.Compiler{}.Compile(pc.Policies, nil, reconcile.Accounts{})
		if err != nil {
			r.t.Fatal(err)
		}
	}
	r.world.ExternalLoad(rs.Body())
	r.mu.Lock()
	r.rsDamageSeq = r.readSeq
	r.taintLocked()
	r.mu.Unlock()
}

// omRunOps runs one sequence in a fresh bubble and returns the
// violations, and the index of the step that found the first one.
func omRunOps(t *testing.T, initial omCfg, ops []omOp) (viol []string, at int) {
	at = -1
	synctest.Test(t, func(t *testing.T) {
		r := newOmRun(t, initial)
		defer func() { // let TempDir cleanup remove it
			if err := os.Chmod(r.dir, 0o700); err != nil {
				t.Error(err)
			}
		}()
		r.start()
		r.check("start")
		r.statusCheck()
		for i, o := range ops {
			r.step = i
			r.exec(o)
			synctest.Wait()
			r.check("step")
			r.statusCheck()
			if len(r.violations) > 0 {
				break
			}
		}
		if len(r.violations) == 0 {
			r.step = len(ops)
			r.recoverAndCheck()
		}
		r.stop()
		if len(r.violations) > 0 {
			at = r.step
		}
		viol = r.violations
	})
	return viol, at
}

func newOmRun(t *testing.T, initial omCfg) *omRun {
	dir := t.TempDir()
	r := &omRun{
		t: t, world: reconciletest.NewWorld(), inv: reconciletest.NewInventory(omEn0),
		dir: dir, snap: filepath.Join(dir, "addrbook.json"),
		tracked: map[omKey]*omEntry{}, pending: map[omKey]*omEntry{}, rsDamageSeq: -1,
	}
	r.setCfg(initial.clone())
	r.world.SetBeforeWrite(func(n int) error {
		r.mu.Lock()
		blk, rel := r.block, r.release
		r.block = nil
		fail := n == r.failAt || (r.failFrom > 0 && n >= r.failFrom)
		r.mu.Unlock()
		if blk != nil {
			close(blk)
			<-rel
		}
		if fail {
			return reconciletest.ErrInjected
		}
		return nil
	})
	r.world.SetAfterWrite(func() { r.check("write") })
	return r
}

// recoverAndCheck clears every fault: the daemon must reach Ready with
// every acked address protected.
func (r *omRun) recoverAndCheck() {
	if err := os.Chmod(r.dir, 0o700); err != nil {
		r.t.Error(err)
	}
	r.world.SetProblems(nil, nil)
	r.mu.Lock()
	r.failAt, r.failFrom, r.saveFail, r.voidOn, r.nonvoidOn = 0, 0, false, false, false
	r.mu.Unlock()
	time.Sleep(daemon.SelfHealInterval)
	synctest.Wait()
	r.statusCheck()
	if st := r.status(); st.State != daemon.StateReady {
		r.violate("liveness: state %v (%q) after all faults cleared", st.State, st.Reasons)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v := r.view()
	for k := range r.tracked {
		if why := r.unprotected(v, k); why != "" {
			r.violate("LEAK after recovery: %s/%v %s", k.P, k.A, why)
		}
	}
}

// omShrink removes steps while the sequence still fails.
func omShrink(t *testing.T, initial omCfg, ops []omOp, at int) []omOp {
	ops = slices.Clone(ops[:min(at+1, len(ops))])
	budget := 300
	for changed := true; changed && budget > 0; {
		changed = false
		for i := len(ops) - 1; i >= 0 && budget > 0; i-- {
			cand := slices.Delete(slices.Clone(ops), i, i+1)
			budget--
			if v, _ := omRunOps(t, initial, cand); len(v) > 0 {
				ops, changed = cand, true
			}
		}
	}
	return ops
}

// TestRandomOperationsNeverLeakAnAcknowledgedAddress fails on a LEAK:
// after an ack, an acknowledged and unexpired address of a current policy
// is missing from its table, or the loaded ruleset does not refer to that
// table with the current constraint, or a known problem voids
// enforcement. It also checks the write order, the state, adoption, and
// liveness after every fault clears. A failing seed is shrunk to a short
// list of steps.
func TestRandomOperationsNeverLeakAnAcknowledgedAddress(t *testing.T) {
	fails := 0
	for seed := uint64(*omFirst); seed < uint64(*omFirst+*omSeeds); seed++ {
		initial, ops := omGenerate(seed, *omLen)
		viol, at := omRunOps(t, initial, ops)
		if len(viol) == 0 {
			continue
		}
		fails++
		short := omShrink(t, initial, ops, at)
		v2, _ := omRunOps(t, initial, short)
		var b strings.Builder
		fmt.Fprintf(&b, "seed %d: initial %v\nshrunk steps:\n", seed, initial)
		for i, o := range short {
			fmt.Fprintf(&b, "  %d: %v\n", i, o)
		}
		fmt.Fprintf(&b, "violations (shrunk): %q\nviolations (full run): %q", v2, viol[:min(3, len(viol))])
		t.Error(b.String())
		if fails >= 3 {
			t.Fatal("stopping after 3 failing seeds")
		}
	}
	t.Logf("entries acked inside the voiding-problem detection latency: %d", omVoidLatencyAcks)
	t.Logf("coverage: %v", omStats)
}
