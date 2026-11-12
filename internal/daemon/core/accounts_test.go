package core

import (
	"strings"
	"testing"
	"time"
)

// startAccounts gives Step an AccountsWanted for alice at start, and
// returns the state and the read that it started.
func startAccounts(t *testing.T, s State, start time.Time) (State, ReadAccounts) {
	t.Helper()
	s, effects := Step(s, AccountsWanted{At: start, Users: []string{"alice"}})
	for _, e := range effects {
		if r, ok := e.(ReadAccounts); ok {
			return s, r
		}
	}
	t.Fatalf("AccountsWanted started no read: %v", effects)
	return s, ReadAccounts{}
}

// endAccounts gives Step the result of r at end, with alice found, or
// with alice failed when fail is true.
func endAccounts(s State, r ReadAccounts, end time.Time, fail bool) State {
	lk := Lookup{ID: 501, Found: true}
	if fail {
		lk = Lookup{Err: errRead}
	}
	s, _ = Step(s, AccountsRead{At: end, ID: r.ID, Users: map[string]Lookup{"alice": lk}})
	return s
}

func lateProblem(s State) bool {
	p, ok := AccountsProblem(s)
	return ok && strings.Contains(p.Text, "takes longer than")
}

func TestAccountReadIsOverdueAtItsDeadline(t *testing.T) {
	for _, c := range []struct {
		now  time.Duration
		want bool
	}{
		{0, false},
		{AccountReadTimeout - time.Nanosecond, false},
		{AccountReadTimeout, true},
		{AccountReadTimeout + time.Hour, true},
	} {
		s, _ := startAccounts(t, State{}, t0)
		s, effects := Step(s, Tick{At: at(c.now)})
		if got := countOf[AccountsOverdue](effects) == 1; got != c.want {
			t.Errorf("Tick at %v: AccountsOverdue %v, want %v; effects %v", c.now, got, c.want, effects)
		}
		if got := lateProblem(s); got != c.want {
			t.Errorf("Tick at %v: the problem tells a slow read %v, want %v", c.now, got, c.want)
		}
	}
}

func TestAccountReadIsLateWhenItEndsAtOrAfterItsDeadline(t *testing.T) {
	for _, c := range []struct {
		name string
		took time.Duration
		fail bool
		want bool
	}{
		{"on time", AccountReadTimeout - time.Nanosecond, false, false},
		{"at the deadline", AccountReadTimeout, false, true},
		{"after the deadline", 2 * AccountReadTimeout, false, true},
		{"failed after the deadline", 2 * AccountReadTimeout, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, r := startAccounts(t, State{}, t0)
			s = endAccounts(s, r, at(c.took), c.fail)
			if got := lateProblem(s); got != c.want {
				t.Errorf("the problem tells a slow read %v, want %v", got, c.want)
			}
		})
	}

	// A read on time after a late one ends the late problem. The start
	// of the next read does not end it.
	s, r := startAccounts(t, State{}, t0)
	s = endAccounts(s, r, at(2*AccountReadTimeout), false)
	s, r = startAccounts(t, s, at(2*AccountReadTimeout))
	if !lateProblem(s) {
		t.Error("the start of a read ended the late problem of the last read")
	}
	s = endAccounts(s, r, at(2*AccountReadTimeout+time.Second), false)
	if lateProblem(s) {
		t.Error("the late problem stays after a read on time")
	}
}

// When the time of HostsWanted makes the account read overdue, Step asks
// for the host file read first and for the convergence last.
func TestHostsWantedPastTheAccountDeadlineReadsTheHostsBeforeItConverges(t *testing.T) {
	s, _ := startAccounts(t, State{}, t0)
	_, effects := Step(s, HostsWanted{At: at(AccountReadTimeout)})
	read, conv := -1, -1
	for i, e := range effects {
		switch e.(type) {
		case ReadHosts:
			read = i
		case Converge:
			conv = i
		case ReadAccounts, AccountsOverdue, AccountLookupsFailed, ReadKernelHosts, HostsReadFailed, KernelHostsFailed:
		}
	}
	if read < 0 || conv != len(effects)-1 {
		t.Errorf("effects %v: ReadHosts at %d, Converge at %d; want both, and Converge last", effects, read, conv)
	}
}
