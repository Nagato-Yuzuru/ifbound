package core

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// TestStepEnforcementModel gives Step random sequences of the events of
// the shell: configuration reads, passes with random results of the host
// file, the book, and the convergence, ruleset mismatches, self-test
// results, account results, interface changes, and ticks. A fake shell
// answers each sync effect in the same drain, as the shell does. After
// each Step, it checks:
//
//   - determinism: two Step calls on equal input give equal output;
//   - an open gate needs a configuration, the loaded book, a convergence
//     after the last good configuration read that was not add-only and
//     installed a ruleset, no voiding Problem, and no mismatch after it;
//   - a Tick before NextWake gives no sync effect;
//   - a Step gives at most one ExpireBook.
//
// After each drain, it checks:
//
//   - a good configuration read gives a Converge in the drain, in every
//     book state;
//   - a convergence that installed a ruleset with the loaded book and no
//     voiding Problem opens the gate in the drain;
//   - the shell holds a book exactly when the state is BookAdopting or
//     BookLoaded, and the state is BookAdopting exactly while an
//     adoption is owed;
//   - no Converge comes without a configuration.
//
// The fake shell answers ExpireBook, PruneBook, and AdoptBook only with
// the book that they need. The facts can have an expiry that is already
// due, as for an entry that expired while the daemon was down.
func TestStepEnforcementModel(t *testing.T) {
	for seed := range uint64(300) {
		m := enfModel{rng: rand.New(rand.NewPCG(seed, 2)), now: t0}
		m.s = New(t0, m.rng.IntN(2) == 0)
		for i := range 300 {
			if err := m.next(); err != nil {
				t.Fatalf("seed %d, event %d: %v", seed, i, err)
			}
		}
	}
}

// enfModel is what the test knows, from the events alone, of the
// configuration, the book, and the convergences.
type enfModel struct {
	rng *rand.Rand
	s   State
	now time.Time

	// configured is true after a good configuration read, and gen counts
	// those reads.
	configured bool
	gen        uint64
	// holds is true while the fake shell holds an open book. owed is
	// true from an open that can miss an acknowledged lease to the first
	// good adoption.
	holds, owed bool
	// conv is the last convergence, and mismatch is true when a mismatch
	// came after it.
	conv     *modelConv
	mismatch bool
	// pending is true when a Converge waits for a pass.
	pending bool
	// flight is the account read in flight, if any.
	flight *ReadAccounts
	// drain holds the effects of the current drain.
	drain []Effect
}

type modelConv struct {
	gen    uint64
	loaded bool
	rep    reconcile.Report
	voids  bool
}

var errModel = errors.New("model failure")

func (m *enfModel) next() error {
	m.now = m.now.Add(time.Duration(m.rng.IntN(1500)) * time.Millisecond)
	switch k := m.rng.IntN(16); {
	case k < 2:
		return m.configRead()
	case k < 6 && m.pending:
		return m.pass()
	case k < 7:
		steps := []reconcile.ReportStep{reconcile.StepTableAdd, reconcile.StepCommit, reconcile.StepLoadedID, reconcile.StepRuleset}
		return m.outside(ReportFailed{At: m.now, Step: steps[m.rng.IntN(len(steps))], Err: errModel})
	case k < 8:
		g := uint64(m.rng.IntN(int(m.gen) + 2))
		return m.outside(SelfTestResult{At: m.now, Proved: g * uint64(m.rng.IntN(2)), Missed: g})
	case k < 9 && m.flight != nil:
		f := *m.flight
		m.flight = nil
		res := AccountsRead{At: m.now, ID: f.ID, Users: map[string]Lookup{}}
		for _, u := range f.Users {
			res.Users[u] = Lookup{ID: 500, Found: m.rng.IntN(3) > 0}
		}
		return m.outside(res)
	case k < 10:
		return m.outside(InterfacesChanged{At: m.now})
	case k < 11 && m.loaded():
		return m.outside(BookChanged{At: m.now, Facts: m.facts()})
	case k < 13:
		if next, ok := NextWake(m.s); ok && m.rng.IntN(2) == 0 {
			m.now = maxTime(m.now, next)
		}
		return m.outside(Tick{At: m.now})
	case k < 14:
		return m.outside(FirewallChanged{At: m.now})
	case k < 15 && m.rng.IntN(2) == 0:
		return m.outside(WatchFailed{At: m.now, Err: errModel})
	case k < 15:
		return m.outside(WatchSucceeded{At: m.now})
	default:
		return m.outside(Tick{At: m.now})
	}
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// configRead gives a good read, or a failed read at start.
func (m *enfModel) configRead() error {
	if !m.configured && m.rng.IntN(3) == 0 {
		return m.outside(ConfigRead{At: m.now, Err: errModel})
	}
	var users []string
	if m.rng.IntN(2) == 0 {
		users = []string{"alice"}
	}
	m.configured = true
	m.gen++
	if err := m.outside(ConfigRead{At: m.now, Config: scoped(users, nil)}); err != nil {
		return err
	}
	if countOf[Converge](m.drain) == 0 {
		return fmt.Errorf("a good configuration read with the book %T gave no Converge: %v", m.book(), m.drain)
	}
	return nil
}

// pass runs one convergence pass, as the shell does: the PassStarted
// drain, and then the Converged drain with a random result.
func (m *enfModel) pass() error {
	if err := m.outside(PassStarted{At: m.now}); err != nil {
		return err
	}
	m.pending = false
	rep := reconcile.Report{Installed: []string{"", "r1", "r2"}[m.rng.IntN(3)]}
	voids := false
	if m.rng.IntN(3) == 0 {
		voids = m.rng.IntN(2) == 0
		rep.Problems = []reconcile.Problem{{Text: "backend problem", Voids: voids}}
	}
	var err error
	if m.rng.IntN(4) == 0 {
		err = errModel
	}
	m.conv = &modelConv{gen: m.gen, loaded: m.loaded(), rep: rep, voids: voids}
	m.mismatch = false
	if err := m.outside(Converged{At: m.now, Report: rep, Err: err}); err != nil {
		return err
	}
	if rep.Installed != "" && !voids && m.loaded() {
		if g, ok := GateOf(m.s).State.(Open); !ok || g.Installed != rep.Installed {
			return fmt.Errorf("a convergence that installed %q with the loaded book gave the gate %#v", rep.Installed, GateOf(m.s).State)
		}
	}
	return nil
}

// outside gives one outside event and drains it.
func (m *enfModel) outside(ev Event) error {
	if f, ok := ev.(ReportFailed); ok && f.Step == reconcile.StepRuleset && m.configured {
		m.mismatch = true
	}
	m.drain = nil
	if err := m.step(ev); err != nil {
		return err
	}
	if _, ok := ev.(ReportFailed); ok && m.configured && PhaseOf(m.s).Lifecycle == Ready {
		return fmt.Errorf("phase Ready right after the report failure %+v", ev)
	}
	_, adopting := m.book().(BookAdopting)
	_, loaded := m.book().(BookLoaded)
	if adopting != (m.holds && m.owed) || loaded != m.loaded() {
		return fmt.Errorf("the shell holds a book %v with an adoption owed %v, the state has %T", m.holds, m.owed, m.book())
	}
	if !m.configured && countOf[Converge](m.drain) > 0 {
		return fmt.Errorf("a Converge without a configuration: %v", m.drain)
	}
	return nil
}

// step runs Step on ev, checks the invariants of one Step, and answers
// each sync effect.
func (m *enfModel) step(ev Event) error {
	before := m.s
	s1, effects := Step(before, ev)
	s2, again := Step(before, ev)
	if !reflect.DeepEqual(s1, s2) || !reflect.DeepEqual(effects, again) {
		return fmt.Errorf("two Step calls on equal input gave different output for %#v", ev)
	}
	m.s = s1
	m.drain = append(m.drain, effects...)
	if n := countOf[ExpireBook](effects); n > 1 {
		return fmt.Errorf("one Step on %T gave %d ExpireBook: %v", ev, n, effects)
	}
	if tick, ok := ev.(Tick); ok {
		if next, due := NextWake(before); !due || tick.At.Before(next) {
			if i := slices.IndexFunc(effects, func(e Effect) bool { _, ok := e.(SyncEffect); return ok }); i >= 0 {
				return fmt.Errorf("a Tick at %v before the wake %v, %v gave %v", tick.At, next, due, effects)
			}
		}
	}
	if err := m.checkGate(); err != nil {
		return fmt.Errorf("after %T: %w", ev, err)
	}
	for _, e := range effects {
		res, err := m.answer(e)
		if err != nil {
			return err
		}
		if res != nil {
			if err := m.step(res); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkGate checks that an open gate has each fact that acking needs.
func (m *enfModel) checkGate() error {
	g, open := GateOf(m.s).State.(Open)
	if !open {
		return nil
	}
	c := m.conv
	switch {
	case !m.configured:
		return errors.New("gate open without a configuration")
	case !m.loaded():
		return errors.New("gate open without the loaded book")
	case c == nil || c.gen != m.gen:
		return errors.New("gate open without a convergence of the current configuration")
	case !c.loaded:
		return errors.New("gate open after an add-only convergence")
	case c.rep.Installed == "" || g.Installed != c.rep.Installed:
		return fmt.Errorf("gate open with %q after a convergence that installed %q", g.Installed, c.rep.Installed)
	case c.voids:
		return errors.New("gate open with a voiding Problem")
	case m.mismatch:
		return errors.New("gate open after a ruleset mismatch")
	}
	return nil
}

// answer is the fake shell: it returns the result of a sync effect, or
// nil for an effect without one.
func (m *enfModel) answer(e Effect) (Event, error) {
	switch e := e.(type) {
	case Converge:
		m.pending = true
	case ReadHosts:
		res := HostsRead{At: m.now, ID: e.ID, New: m.rng.IntN(2) == 0}
		if m.rng.IntN(4) == 0 {
			res.Err = errModel
		}
		return res, nil
	case ReadKernelHosts:
		return KernelRead{At: m.now, ID: e.ID}, nil
	case OpenBook:
		return m.open()
	case AdoptBook:
		if !m.holds || !m.owed {
			return nil, fmt.Errorf("AdoptBook with a book %v and an adoption owed %v", m.holds, m.owed)
		}
		if m.rng.IntN(4) == 0 {
			return BookAdopted{At: m.now, Err: errModel}, nil
		}
		m.owed = false
		return BookAdopted{At: m.now, Facts: m.facts()}, nil
	case ExpireBook:
		if !m.loaded() {
			return nil, errors.New("ExpireBook without the loaded book")
		}
		return BookExpired{At: m.now, Removed: m.rng.IntN(2), Facts: m.facts()}, nil
	case PruneBook:
		if !m.loaded() {
			return nil, errors.New("PruneBook without the loaded book")
		}
		return BookChanged{At: m.now, Facts: m.facts()}, nil
	case ReadAccounts:
		if m.flight != nil {
			return nil, fmt.Errorf("a second account read %v while %v is in flight", e, *m.flight)
		}
		m.flight = &e
	case AccountsOverdue, AccountLookupsFailed, HostsReadFailed, KernelHostsFailed, ReportPathFailed,
		RepairPlanned, WatchFailing:
	}
	return nil, nil
}

// open answers OpenBook. A good open of a book that can miss an
// acknowledged lease makes an adoption owed: a book with damage, a torn
// book, and a fresh book without an address of the policy.
func (m *enfModel) open() (Event, error) {
	if m.holds {
		return nil, errors.New("OpenBook while the shell holds a book")
	}
	if m.rng.IntN(4) == 0 {
		return BookOpened{At: m.now, Err: errModel}, nil
	}
	res := BookOpened{At: m.now, Facts: m.facts(), Torn: m.rng.IntN(4) == 0, Fresh: m.rng.IntN(2) == 0}
	if m.rng.IntN(6) == 0 {
		res.Damage = errModel
	}
	m.holds = true
	m.owed = res.Damage != nil || res.Torn || res.Fresh && res.Facts.Counts["web"] == 0
	return res, nil
}

// facts returns random facts of the book, with no expiry, or with an
// expiry from 5s before now to 5s after it.
func (m *enfModel) facts() addrstore.BookFacts {
	f := addrstore.BookFacts{Retain: time.Hour, Counts: map[policy.Name]int{"web": m.rng.IntN(3)}}
	if m.rng.IntN(3) > 0 {
		f.NextExpiry = m.now.Add(time.Duration(m.rng.IntN(10001)-5000) * time.Millisecond)
	}
	return f
}

// loaded reports whether the shell holds a book that holds each
// acknowledged lease.
func (m *enfModel) loaded() bool { return m.holds && !m.owed }

func (m *enfModel) book() Book {
	if c, ok := m.s.Config().(Configured); ok {
		return c.Book
	}
	return nil
}
