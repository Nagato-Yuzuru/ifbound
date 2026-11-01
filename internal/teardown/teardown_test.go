package teardown_test

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/enforcementlock"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
	"github.com/Nagato-Yuzuru/ifbound/internal/teardown"
)

// ref is a pf reference: pf gives a released value again, so only the
// value with its creation time names one reference.
type ref struct {
	value string
	born  time.Time
}

// kernel is the pf state that the fake Backend changes. It outlives one
// Run, as the kernel outlives a process.
type kernel struct {
	now    time.Time
	refs   []ref
	free   []string // released values; the next enable takes the last one
	next   int
	labels []ref // the token labels in the rules of the anchor
	rules  bool  // the anchor holds rules
	tables bool  // the anchor holds tables
}

func (k *kernel) enable() ref {
	var v string
	if n := len(k.free); n > 0 {
		v, k.free = k.free[n-1], k.free[:n-1]
	} else {
		k.next++
		v = strconv.Itoa(1000 + k.next)
	}
	r := ref{value: v, born: k.now}
	k.refs = append(k.refs, r)
	return r
}

// The steps of Unload in the fake Backend.
const (
	stepRelease = "release"
	stepRules   = "flush rules"
	stepTables  = "flush tables"
)

// fakeBackend unloads with the steps of pfbackend.Unload: it reads the
// token labels, gives back each labelled token that pf holds with the
// same creation time, then flushes the rules (with the labels) and the
// tables. A new fakeBackend is a new process: it knows only the labels.
type fakeBackend struct {
	k *kernel
	// stop makes the Unload step with this name fail.
	stop    string
	unloads int
}

func (b *fakeBackend) Unload(context.Context) error {
	b.unloads++
	if b.stop == stepRelease {
		return reconciletest.ErrInjected
	}
	for _, l := range b.k.labels {
		if i := slices.Index(b.k.refs, l); i >= 0 {
			b.k.refs = slices.Delete(b.k.refs, i, i+1)
			b.k.free = append(b.k.free, l.value)
		}
	}
	if b.stop == stepRules {
		return reconciletest.ErrInjected
	}
	b.k.rules, b.k.labels = false, nil
	if b.stop == stepTables {
		return reconciletest.ErrInjected
	}
	b.k.tables = false
	return nil
}

type rig struct {
	k     *kernel
	w     *reconciletest.World
	other ref // the reference of another tool, taken before ifbound
	lock  string
}

func (r *rig) teardown(stop string) (teardown.Teardown, *fakeBackend) {
	b := &fakeBackend{k: r.k, stop: stop}
	return teardown.Teardown{Lock: r.lock, Backend: b, Resolver: r.w.Resolver()}, b
}

// newRig returns a host with the enforcement of ifbound: a pf reference
// with its label, rules, tables, and resolver entries. Another tool also
// holds a pf reference.
func newRig(t *testing.T) *rig {
	t.Helper()
	k := &kernel{now: time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)}
	r := &rig{k: k, w: reconciletest.NewWorld(), lock: filepath.Join(t.TempDir(), "enforcement.lock")}
	r.other = k.enable()
	k.labels = []ref{k.enable()}
	k.rules, k.tables = true, true
	d, err := policy.ParseDomain("corp.example")
	if err != nil {
		t.Fatal(err)
	}
	in := reconcile.Inputs{Apexes: []policy.Domain{d}, Listen: netip.MustParseAddrPort("127.0.0.1:53")}
	if _, err := (reconcile.Reconciler{Resolver: r.w.Resolver()}).ConvergeResolver(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	return r
}

// requireEmpty fails unless the host holds no enforcement of ifbound and
// every reference of the other tools stays.
func requireEmpty(t *testing.T, r *rig, others []ref) {
	t.Helper()
	if r.k.rules || r.k.tables || len(r.k.labels) != 0 {
		t.Errorf("after the teardown: rules %v tables %v labels %v, want none", r.k.rules, r.k.tables, r.k.labels)
	}
	if !slices.Equal(r.k.refs, others) {
		t.Errorf("pf references after the teardown = %v, want the other tools only: %v", r.k.refs, others)
	}
	if entries := r.w.ResolverEntries(); len(entries) != 0 {
		t.Errorf("resolver entries after the teardown = %v, want none", entries)
	}
}

func TestRunRemovesTheEnforcement(t *testing.T) {
	r := newRig(t)
	td, _ := r.teardown("")
	if err := td.Run(t.Context()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	requireEmpty(t, r, []ref{r.other})
	if err := td.Run(t.Context()); err != nil {
		t.Errorf("a second Run = %v, want nil", err)
	}
	requireEmpty(t, r, []ref{r.other})
}

// stop names one step of the teardown that fails.
type stop struct {
	unload string // the Unload step that fails, or ""
	write  int    // the resolver write that fails, or 0
}

// A stop at each step, then a second Run in a new process, finishes the
// teardown. Between the runs, a third tool takes a pf reference, and pf
// can give it the value that ifbound released.
func TestRunFinishesAfterAStopAtEachStep(t *testing.T) {
	stops := []stop{{unload: stepRelease}, {unload: stepRules}, {unload: stepTables}}
	for n := 1; n <= 2; n++ { // the apex entry and the canary entry
		stops = append(stops, stop{write: n})
	}
	for _, s := range stops {
		name := s.unload
		if s.write > 0 {
			name = "resolver write " + strconv.Itoa(s.write)
		}
		t.Run(name, func(t *testing.T) { runAfterAStop(t, s) })
	}
}

func runAfterAStop(t *testing.T, s stop) {
	r := newRig(t)
	entries := r.w.ResolverEntries()
	if s.write > 0 {
		fail := r.w.Writes() + s.write
		r.w.SetBeforeWrite(func(n int) error {
			if n == fail {
				return reconciletest.ErrInjected
			}
			return nil
		})
	}
	first, _ := r.teardown(s.unload)
	if err := first.Run(t.Context()); !errors.Is(err, reconciletest.ErrInjected) {
		t.Fatalf("Run with a stop = %v, want the injected fault", err)
	}
	if s.unload != "" && !slices.Equal(r.w.ResolverEntries(), entries) {
		t.Errorf("a Run whose unload failed changed the resolver entries to %v: they keep the protected names failing", r.w.ResolverEntries())
	}
	r.w.SetBeforeWrite(nil)
	r.k.now = r.k.now.Add(time.Minute)
	third := r.k.enable()
	second, _ := r.teardown("")
	if err := second.Run(t.Context()); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	requireEmpty(t, r, []ref{r.other, third})
}

func TestRunWhileTheLockIsHeldChangesNothing(t *testing.T) {
	r := newRig(t)
	l, err := enforcementlock.Acquire(r.lock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close() //nolint:errcheck // the test ends; the close only releases the lock
	refs, writes := slices.Clone(r.k.refs), r.w.Writes()
	td, b := r.teardown("")
	if err := td.Run(t.Context()); !errors.Is(err, enforcementlock.ErrHeld) {
		t.Fatalf("Run while the lock is held = %v, want ErrHeld", err)
	}
	if b.unloads != 0 || r.w.Writes() != writes || !slices.Equal(r.k.refs, refs) || !r.k.rules {
		t.Errorf("Run while the lock is held changed the host: unloads %d, writes %d -> %d, refs %v",
			b.unloads, writes, r.w.Writes(), r.k.refs)
	}
}
