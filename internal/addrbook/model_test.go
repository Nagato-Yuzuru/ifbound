package addrbook

// Model-based test of the persist rule. A random sequence of Observe,
// Save (success, failure, crash before rename), clock moves, Expire and
// Prune runs against the book and against an independent model of the
// spec. The model computes needSave from its own savedExpiry (the expiry
// the last successful Save wrote) and checks it against Observe. At each
// crash, a fresh book loads the snapshot, and for every acknowledged
// observation o of address k, Expire at o + retain - slack must keep k.

import (
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

type oKey struct {
	p policy.Name
	a netip.Addr
}

type oMem struct {
	lastSeen time.Time
	ttl      time.Duration
	expiry   time.Time
	saved    time.Time // zero: never written by a successful Save
}

type oDisk struct {
	lastSeen time.Time
	ttl      time.Duration
	expiry   time.Time
}

type oPending struct {
	k oKey
	t time.Time
}

type oCrash struct{}

var (
	oMinT = time.Unix(0, math.MinInt64)
	oMaxT = time.Unix(0, math.MaxInt64)
)

func oInRange(t time.Time) bool { return !t.Before(oMinT) && !t.After(oMaxT) }

func oLater(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

type oWorld struct {
	t       *testing.T
	rng     *rand.Rand
	log     []string
	retain  time.Duration
	slack   time.Duration
	now     time.Time
	path    string
	book    *AddrBook
	mem     map[oKey]*oMem
	disk    map[oKey]oDisk // nil: no snapshot on disk
	acked   map[oKey]time.Time
	pending []oPending
	// expiredAt is the latest clock time of an in-memory Expire. The
	// guarantee cannot hold for a load time before it.
	expiredAt time.Time
	withExp   bool
	stats     *oStats
}

// oStats shows that a run exercised the paths the guarantee is about.
type oStats struct{ quietAcks, savedAcks, checks, failedSaves, rangeErrs int }

func (w *oWorld) fail(format string, args ...any) {
	w.t.Helper()
	w.t.Fatalf("%s\nops:\n  %s", fmt.Sprintf(format, args...), strings.Join(w.log, "\n  "))
}

func (w *oWorld) logf(format string, args ...any) {
	w.log = append(w.log, fmt.Sprintf(format, args...))
}

var oPool = []netip.Addr{
	netip.MustParseAddr("192.0.2.1"),
	netip.MustParseAddr("192.0.2.2"),
	netip.MustParseAddr("2001:db8::1"),
	netip.MustParseAddr("::ffff:192.0.2.1"), // unmaps to the first
}

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.IntN(len(xs))] }

func (w *oWorld) step() {
	n := w.rng.IntN(100)
	switch {
	case n < 35:
		w.observe()
	case n < 55:
		w.move()
	case n < 70:
		w.save(true)
	case n < 78:
		w.save(false)
	case n < 82:
		w.crashInSave()
	case n < 88:
		w.crash()
	case n < 94 && w.withExp:
		w.expire()
	case n < 97 && w.withExp:
		w.prune()
	default:
		w.observeBad()
	}
}

func (w *oWorld) move() {
	r := w.retain
	d := pick(w.rng, []time.Duration{
		time.Nanosecond, time.Second, 30 * time.Minute, time.Hour - time.Nanosecond,
		time.Hour, time.Hour + time.Nanosecond, r / 2, r - w.slack, r - w.slack + time.Nanosecond,
		w.slack + time.Nanosecond, r, r + time.Nanosecond, 2 * r, -time.Second, -time.Hour, -r,
	})
	if w.rng.IntN(60) == 0 {
		d = pick(w.rng, []time.Duration{240 * 365 * 24 * time.Hour, -240 * 365 * 24 * time.Hour})
	}
	w.now = w.now.Add(d)
	w.logf("clock %+v -> %v", d, w.now)
}

func (w *oWorld) observe() {
	name := pick(w.rng, []policy.Name{"p", "q"})
	var addrs []netip.Addr
	for _, a := range oPool {
		if w.rng.IntN(2) == 0 {
			addrs = append(addrs, a)
		}
	}
	ttl := pick(w.rng, []time.Duration{0, time.Second, 30 * time.Minute, 3 * time.Hour, 8 * 24 * time.Hour})
	got, err := w.book.Observe(name, addrs, ttl)
	w.logf("observe %s %v ttl=%v -> %v %v", name, addrs, ttl, got, err)
	if err != nil {
		w.fail("observe: %v", err)
	}
	want := false
	var keys []oKey
	for _, a := range addrs {
		k := oKey{name, a.Unmap()}
		newExp := w.now.Add(max(ttl, w.retain))
		saved := time.Time{}
		if m, ok := w.mem[k]; ok {
			newExp = oLater(m.expiry, newExp)
			saved = m.saved
		}
		if saved.Add(w.slack).Before(newExp) {
			want = true
		}
		w.mem[k] = &oMem{lastSeen: w.now, ttl: ttl, expiry: newExp, saved: saved}
		keys = append(keys, k)
	}
	if got != want {
		w.fail("needSave = %v, model says %v", got, want)
	}
	for _, k := range keys {
		if !got {
			w.stats.quietAcks++
			w.ack(k, w.now)
		} else {
			w.pending = append(w.pending, oPending{k, w.now})
		}
	}
}

func (w *oWorld) observeBad() {
	before := w.snapshotMem()
	bad := pick(w.rng, []netip.Addr{{}, netip.MustParseAddr("fe80::1%en0")})
	_, err := w.book.Observe("p", []netip.Addr{oPool[0], bad}, 0)
	w.logf("observe bad %v -> %v", bad, err)
	if err == nil {
		w.fail("observe of a bad address succeeded")
	}
	if after := w.snapshotMem(); !slices.Equal(before, after) {
		w.fail("refused observe changed the book: %v -> %v", before, after)
	}
}

func (w *oWorld) snapshotMem() []string {
	var out []string
	for name, m := range w.book.entries {
		for a, r := range m {
			out = append(out, fmt.Sprintf("%s %v %v %v %v", name, a, r.lastSeen, r.ttl, r.expiry))
		}
	}
	slices.Sort(out)
	return out
}

// ack records the keep-until instant that the guarantee gives an
// acknowledged observation at t under the current retain.
func (w *oWorld) ack(k oKey, t time.Time) {
	until := t.Add(w.retain - w.slack)
	if old, ok := w.acked[k]; !ok || until.After(old) {
		w.acked[k] = until
	}
}

func (w *oWorld) save(ok bool) {
	if !ok {
		w.book.rename = func(string, string) error { return os.ErrPermission }
		defer func() { w.book.rename = osRename }()
	}
	err := w.book.Save(w.path)
	w.logf("save ok=%v -> %v", ok, err)
	inRange := true
	for _, m := range w.mem {
		inRange = inRange && oInRange(m.lastSeen) && oInRange(m.expiry)
	}
	switch {
	case !ok && err == nil:
		w.fail("injected rename failure, but Save returned nil")
	case !inRange && !errors.Is(err, ErrTimeRange):
		w.fail("time out of range, Save err = %v", err)
	case ok && inRange && err != nil:
		w.fail("save: %v", err)
	}
	if errors.Is(err, ErrTimeRange) {
		w.stats.rangeErrs++
	}
	if err != nil {
		w.stats.failedSaves++
		return // a failed Save changes nothing
	}
	w.disk = make(map[oKey]oDisk, len(w.mem))
	for k, m := range w.mem {
		m.saved = m.expiry
		w.disk[k] = oDisk{m.lastSeen, m.ttl, m.expiry}
	}
	for _, p := range w.pending {
		w.stats.savedAcks++
		w.ack(p.k, p.t)
	}
	w.pending = nil
}

func (w *oWorld) crashInSave() {
	w.book.rename = func(string, string) error { panic(oCrash{}) }
	crashed := false
	func() {
		defer func() {
			if _, ok := recover().(oCrash); ok {
				crashed = true
			}
		}()
		_ = w.book.Save(w.path) //nolint:errcheck // the rename hook panics, so Save never returns
	}()
	w.logf("save crashed before rename = %v", crashed)
	w.crash()
}

func (w *oWorld) expire() {
	got := w.book.Expire()
	w.logf("expire -> %d", len(got))
	var want []oKey
	for k, m := range w.mem {
		if w.now.After(m.expiry) {
			want = append(want, k)
			delete(w.mem, k)
		}
	}
	w.expiredAt = oLater(w.expiredAt, w.now)
	if len(got) != len(want) {
		w.fail("expire removed %d, model %d", len(got), len(want))
	}
	for _, e := range got {
		if !slices.Contains(want, oKey{e.Policy, e.Addr}) {
			w.fail("expire removed %v %v, model did not", e.Policy, e.Addr)
		}
	}
}

func (w *oWorld) prune() {
	keep := pick(w.rng, [][]policy.Name{nil, {"p"}, {"q"}, {"p", "q"}})
	got := w.book.Prune(keep)
	w.logf("prune keep=%v -> %d", keep, len(got))
	n := 0
	for k := range w.mem {
		if !slices.Contains(keep, k.p) {
			delete(w.mem, k)
			n++
		}
	}
	if n != len(got) {
		w.fail("prune removed %d, model %d", len(got), n)
	}
	// A pruned policy is no longer configured; the guarantee ends for it.
	for k := range w.acked {
		if !slices.Contains(keep, k.p) {
			delete(w.acked, k)
		}
	}
	w.pending = slices.DeleteFunc(w.pending, func(p oPending) bool { return !slices.Contains(keep, p.k.p) })
}

// crash drops the in-memory book, checks the guarantee on the snapshot, and
// continues with a book loaded from it.
func (w *oWorld) crash() {
	w.logf("crash at %v", w.now)
	w.pending = nil
	// A restart may come with a larger configured retain.
	if w.rng.IntN(4) == 0 && w.retain > 0 && w.retain < math.MaxInt64/4 {
		w.retain *= 2
		w.slack = min(time.Hour, w.retain/2)
		w.logf("restart with retain %v", w.retain)
	}
	for k, at := range w.acked {
		if at.Before(w.expiredAt) {
			continue
		}
		c := at
		b := New(w.retain, func() time.Time { return c })
		if err := b.Load(w.path); err != nil {
			w.fail("load after crash: %v", err)
		}
		b.Expire()
		w.stats.checks++
		if !slices.Contains(b.Addrs(k.p), k.a) {
			w.fail("LEAK: %s %v is gone after Load+Expire at %v, its keep-until", k.p, k.a, at)
		}
	}
	w.book = New(w.retain, func() time.Time { return w.now })
	if err := w.book.Load(w.path); err != nil {
		w.fail("load after crash: %v", err)
	}
	w.mem = make(map[oKey]*oMem)
	for k, d := range w.disk {
		exp := oLater(d.expiry, d.lastSeen.Add(max(d.ttl, w.retain)))
		w.mem[k] = &oMem{lastSeen: d.lastSeen, ttl: d.ttl, expiry: exp, saved: d.expiry}
	}
	if got := len(w.snapshotMem()); got != len(w.mem) {
		w.fail("loaded %d entries, model %d", got, len(w.mem))
	}
}

func runModel(t *testing.T, withExp bool) {
	retains := []time.Duration{0, 2 * time.Second, 30 * time.Minute, 2 * time.Hour, 24 * time.Hour, 7 * 24 * time.Hour, math.MaxInt64}
	// Save syncs to disk, so a seed costs milliseconds.
	const seeds = 60
	st := &oStats{}
	defer func() { t.Logf("%+v", *st) }()
	for seed := range seeds {
		rng := rand.New(rand.NewPCG(uint64(seed), 0x5eed))
		r := pick(rng, retains)
		w := &oWorld{
			t: t, rng: rng, retain: r, slack: min(time.Hour, r/2),
			now:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			path: filepath.Join(t.TempDir(), "book.json"),
			mem:  map[oKey]*oMem{}, acked: map[oKey]time.Time{}, withExp: withExp, stats: st,
		}
		w.logf("seed %d retain %v", seed, r)
		w.book = New(r, func() time.Time { return w.now })
		for range 40 {
			w.step()
		}
		w.crash()
	}
}

func TestModelPersistRule(t *testing.T) {
	t.Parallel() // the two runs wait on fsync, so they overlap well
	runModel(t, false)
}

func TestModelPersistRuleWithExpire(t *testing.T) {
	t.Parallel()
	runModel(t, true)
}
