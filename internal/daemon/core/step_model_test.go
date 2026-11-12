package core

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"
	"time"
)

// TestStepAccountReadsModel gives Step random sequences of account events
// and checks the bound, the determinism, the pending read, the stale
// results, and the wake time after each event.
func TestStepAccountReadsModel(t *testing.T) {
	for seed := range uint64(300) {
		m := accountModel{rng: rand.New(rand.NewPCG(seed, 0)), now: t0}
		for i := range 300 {
			if err := m.next(); err != nil {
				t.Fatalf("seed %d, event %d: %v", seed, i, err)
			}
		}
	}
}

// accountModel is what the test knows of the account reads that Step
// started: the read that the shell runs, and whether a trigger came
// during it.
type accountModel struct {
	rng   *rand.Rand
	s     State
	now   time.Time
	scope ReadAccounts // the names of the last AccountsWanted
	// flight is the read that Step started and that has no result yet.
	flight  ReadAccounts
	started time.Time
	busy    bool
	// again is true when an AccountsWanted came during the flight.
	again bool
}

func (m *accountModel) next() error {
	m.now = m.now.Add(time.Duration(m.rng.IntN(4)) * time.Second)
	switch m.rng.IntN(4) {
	case 0:
		return m.want()
	case 1:
		if m.busy {
			return m.result()
		}
		return m.stale()
	case 2:
		return m.stale()
	default:
		_, err := m.step(Tick{At: m.now})
		return err
	}
}

func (m *accountModel) want() error {
	ev := AccountsWanted{At: m.now, Users: m.names("alice", "bob", "carol"), Groups: m.names("staff", "admin")}
	wasBusy := m.busy
	m.scope = ReadAccounts{Users: ev.Users, Groups: ev.Groups}
	reads, err := m.step(ev)
	switch {
	case err != nil:
		return err
	case wasBusy && len(reads) > 0:
		return fmt.Errorf("AccountsWanted during a flight started %v", reads)
	case wasBusy:
		m.again = true
	case len(reads) != 1:
		return fmt.Errorf("AccountsWanted without a flight started %d reads, want 1", len(reads))
	}
	return nil
}

func (m *accountModel) result() error {
	ev := AccountsRead{At: m.now, ID: m.flight.ID, Users: m.lookups(m.flight.Users), Groups: m.lookups(m.flight.Groups)}
	again := m.again
	m.busy, m.again = false, false
	reads, err := m.step(ev)
	switch {
	case err != nil:
		return err
	case again && len(reads) != 1:
		return fmt.Errorf("the result of a read with a pending trigger started %d reads, want 1", len(reads))
	case !again && len(reads) > 0:
		return fmt.Errorf("the result of a read without a pending trigger started %v", reads)
	}
	return nil
}

// stale gives a result whose ID is not the one of the flight, at the
// current time. It must change nothing.
func (m *accountModel) stale() error {
	id := ReqID(m.rng.IntN(5))
	if m.busy && id == m.flight.ID {
		id++
	}
	ev := AccountsRead{At: m.s.now, ID: id, Users: m.lookups([]string{"alice"})}
	got, effects := Step(m.s, ev)
	if !reflect.DeepEqual(got, m.s) || len(effects) > 0 {
		return fmt.Errorf("stale result %d changed the state or gave %v", id, effects)
	}
	return nil
}

// step runs Step twice on the same state, checks the invariants, and
// returns the reads that it started.
func (m *accountModel) step(ev Event) ([]ReadAccounts, error) {
	s1, effects := Step(m.s, ev)
	s2, again := Step(m.s, ev)
	if !reflect.DeepEqual(s1, s2) || !reflect.DeepEqual(effects, again) {
		return nil, fmt.Errorf("two Step calls on equal input gave different output for %#v", ev)
	}
	m.s = s1
	var reads []ReadAccounts
	converges := 0
	for _, e := range effects {
		switch e := e.(type) {
		case ReadAccounts:
			reads = append(reads, e)
		case Converge:
			converges++
		case AccountsOverdue, AccountLookupsFailed:
		}
	}
	switch {
	case converges > 1:
		return nil, fmt.Errorf("%d Converge effects for one event, want at most 1", converges)
	case len(reads) > 1 || (m.busy && len(reads) > 0):
		return nil, fmt.Errorf("a second read started: %v while one is in flight %v", reads, m.busy)
	}
	for _, r := range reads {
		if !slices.Equal(r.Users, m.scope.Users) || !slices.Equal(r.Groups, m.scope.Groups) {
			return nil, fmt.Errorf("read %v does not ask for the names of the last trigger %v", r, m.scope)
		}
		m.flight, m.started, m.busy = r, m.now, true
	}
	return reads, m.checkWake()
}

// checkWake checks that the wake time is the deadline of the flight
// until the flight is overdue.
func (m *accountModel) checkWake() error {
	got, ok := NextWake(m.s)
	deadline := m.started.Add(AccountReadTimeout)
	switch {
	case m.busy && m.now.Before(deadline):
		if !ok || !got.Equal(deadline) {
			return fmt.Errorf("NextWake = %v, %v; want the deadline %v", got, ok, deadline)
		}
	case ok:
		return fmt.Errorf("NextWake = %v with nothing due, want none", got)
	}
	return nil
}

// names returns a random subset of all, in order.
func (m *accountModel) names(all ...string) []string {
	var out []string
	for _, n := range all {
		if m.rng.IntN(2) == 0 {
			out = append(out, n)
		}
	}
	return out
}

func (m *accountModel) lookups(names []string) map[string]Lookup {
	out := make(map[string]Lookup, len(names))
	for _, n := range names {
		switch m.rng.IntN(4) {
		case 0:
			out[n] = Lookup{Err: errRead}
		case 1:
			out[n] = Lookup{}
		default:
			out[n] = Lookup{ID: uint32(500 + m.rng.IntN(3)), Found: true}
		}
	}
	return out
}
