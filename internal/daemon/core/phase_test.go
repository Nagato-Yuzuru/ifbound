package core

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// shell answers the sync effects as the shell does. A nil field gives a
// good result: a host file without entries, a book that opens with one
// address and no damage, and an expire or prune that removes nothing.
type shell struct {
	hosts func(ReadHosts) HostsRead
	open  func(OpenBook) BookOpened
	adopt func(AdoptBook) BookAdopted
}

var oneAddr = addrstore.BookFacts{Retain: time.Hour, Counts: map[policy.Name]int{"web": 1}, NextExpiry: t0.Add(time.Hour)}

func (sh shell) answer(s State, e SyncEffect) Event {
	now := s.now
	switch e := e.(type) {
	case ReadHosts:
		if sh.hosts != nil {
			return sh.hosts(e)
		}
		return HostsRead{At: now, ID: e.ID, New: true}
	case ReadKernelHosts:
		return KernelRead{At: now, ID: e.ID}
	case OpenBook:
		if sh.open != nil {
			return sh.open(e)
		}
		return BookOpened{At: now, Facts: oneAddr}
	case AdoptBook:
		if sh.adopt != nil {
			return sh.adopt(e)
		}
		return BookAdopted{At: now, Facts: oneAddr}
	case ExpireBook:
		return BookExpired{At: now, Facts: oneAddr}
	case PruneBook:
		return BookChanged{At: now, Facts: oneAddr}
	case Converge:
		return nil
	default:
		return nil
	}
}

// drain gives ev to Step and the result of each sync effect after it,
// as the shell does in one drain. It returns every effect of the drain.
func (sh shell) drain(s State, ev Event) (State, []Effect) {
	s, effects := Step(s, ev)
	all := slices.Clone(effects)
	for _, e := range effects {
		se, ok := e.(SyncEffect)
		if !ok {
			continue
		}
		if res := sh.answer(s, se); res != nil {
			var more []Effect
			s, more = sh.drain(s, res)
			all = append(all, more...)
		}
	}
	return s, all
}

// pass runs one convergence pass with the report and the error.
func (sh shell) pass(s State, at time.Time, rep reconcile.Report, err error) State {
	s, _ = sh.drain(s, PassStarted{At: at})
	s, _ = sh.drain(s, Converged{At: at, Report: rep, Err: err})
	return s
}

var errLoad = errors.New("load failed")

// ready returns a state with the configuration of scoped(alice), the
// loaded book, the ruleset r1 installed, the self-test passed, and a
// good account read. The shell sh answers the host file read.
func ready(t *testing.T, sh shell) State {
	t.Helper()
	s, effects := sh.drain(State{}, ConfigRead{At: t0, Config: scoped([]string{"alice"}, nil)})
	s = sh.pass(s, t0, reconcile.Report{Installed: "r1"}, nil)
	s, _ = sh.drain(s, SelfTestResult{At: t0, Proved: 1})
	r := readOf(t, effects)
	s, _ = sh.drain(s, AccountsRead{At: t0, ID: r.ID, Users: map[string]Lookup{"alice": {ID: 501, Found: true}}})
	return s
}

func readOf(t *testing.T, effects []Effect) ReadAccounts {
	t.Helper()
	for _, e := range effects {
		if r, ok := e.(ReadAccounts); ok {
			return r
		}
	}
	t.Fatalf("no account read in %v", effects)
	return ReadAccounts{}
}

// TestPhaseOfEachInputState checks the phase for each state of an
// input: no good value, a good value and a new error, and a good value
// and no error. A problem of an input does not void enforcement.
func TestPhaseOfEachInputState(t *testing.T) {
	failHosts := shell{hosts: func(e ReadHosts) HostsRead { return HostsRead{ID: e.ID, Err: errRead} }}
	for _, c := range []struct {
		name   string
		state  func(t *testing.T) State
		want   Lifecycle
		reason string
	}{
		{"hosts: no good value", func(t *testing.T) State { return ready(t, failHosts) }, Degraded, "host file cannot be read"},
		{"hosts: good value and a new error", func(t *testing.T) State {
			return failHosts.pass(ready(t, shell{}), at(time.Second), reconcile.Report{Installed: "r1"}, nil)
		}, Degraded, "host file cannot be read"},
		{"hosts: good value and no error", func(t *testing.T) State { return ready(t, shell{}) }, Ready, ""},
		{"accounts: no good value", func(t *testing.T) State {
			s, _ := shell{}.drain(State{}, ConfigRead{At: t0, Config: scoped([]string{"alice"}, nil)})
			s = shell{}.pass(s, t0, reconcile.Report{Installed: "r1"}, nil)
			s, _ = shell{}.drain(s, SelfTestResult{At: t0, Proved: 1})
			return s
		}, Degraded, "accounts are not read yet"},
		{"accounts: good value and a new error", func(t *testing.T) State {
			s := ready(t, shell{})
			s, effects := shell{}.drain(s, ConfigRead{At: at(time.Second), Config: scoped([]string{"alice"}, nil)})
			s = shell{}.pass(s, at(time.Second), reconcile.Report{Installed: "r1"}, nil)
			s, _ = shell{}.drain(s, SelfTestResult{At: at(time.Second), Proved: 2})
			r := readOf(t, effects)
			s, _ = shell{}.drain(s, AccountsRead{At: at(time.Second), ID: r.ID, Users: map[string]Lookup{"alice": {Err: errRead}}})
			return s
		}, Degraded, "lookup of 1 user and group accounts failed"},
		{"accounts: good value and no error", func(t *testing.T) State { return ready(t, shell{}) }, Ready, ""},
	} {
		t.Run(c.name, func(t *testing.T) { checkPhase(t, c.state(t), c.want, c.reason) })
	}
}

// TestPhaseOfEachConfigurationAndBookState checks the phase and the gate
// for each state of the configuration, the book, and the last
// convergence.
func TestPhaseOfEachConfigurationAndBookState(t *testing.T) {
	cfg := ConfigRead{At: t0, Config: scoped(nil, nil)}
	configured := func() State { s, _ := shell{}.drain(State{}, cfg); return s }
	installed := func(rep reconcile.Report, err error) func() State {
		return func() State {
			s := shell{}.pass(configured(), t0, rep, err)
			s, _ = shell{}.drain(s, SelfTestResult{At: t0, Proved: 1})
			return s
		}
	}
	unloadable := shell{open: func(OpenBook) BookOpened { return BookOpened{At: t0, Err: errLoad} }}
	for _, c := range []struct {
		name   string
		state  func() State
		want   Lifecycle
		reason string
	}{
		{"before the load of the stored configuration", func() State { return New(t0, true) }, Starting, ReasonNotLoaded},
		{"stored configuration does not load", func() State {
			s, _ := shell{}.drain(State{}, ConfigRead{At: t0, Err: errLoad})
			return s
		}, Unenforced, "did not load"},
		{"configured, no convergence", configured, Unenforced, "not installed yet"},
		{"book does not load", func() State {
			return unloadable.pass(configured(), t0, reconcile.Report{Installed: "r1"}, nil)
		}, Starting, "loading the address book: load failed"},
		{"adoption fails", func() State {
			sh := shell{
				open:  func(OpenBook) BookOpened { return BookOpened{At: t0, Torn: true} },
				adopt: func(AdoptBook) BookAdopted { return BookAdopted{At: t0, Err: errLoad} },
			}
			return sh.pass(configured(), t0, reconcile.Report{Installed: "r1"}, nil)
		}, Starting, "load failed"},
		{"installed", installed(reconcile.Report{Installed: "r1"}, nil), Ready, ""},
		{"installed with a problem", installed(reconcile.Report{Installed: "r1", Problems: []reconcile.Problem{{Text: "conflict"}}}, nil), Degraded, "conflict"},
		{"installed with a voiding problem", installed(reconcile.Report{Installed: "r1", Problems: []reconcile.Problem{{Text: "pf disabled", Voids: true}}}, nil), Unenforced, "pf disabled"},
		{"installed and the pass failed", installed(reconcile.Report{Installed: "r1"}, errLoad), Degraded, "convergence failed: load failed"},
		{"not installed", installed(reconcile.Report{}, errLoad), Unenforced, "convergence failed"},
		{"self-test not passed", func() State {
			return shell{}.pass(configured(), t0, reconcile.Report{Installed: "r1"}, nil)
		}, Degraded, "ifbound-dns not connected"},
		{"damaged book", func() State {
			sh := shell{open: func(OpenBook) BookOpened { return BookOpened{At: t0, Facts: oneAddr, Damage: errLoad} }}
			s := sh.pass(configured(), t0, reconcile.Report{Installed: "r1"}, nil)
			s, _ = sh.drain(s, SelfTestResult{At: t0, Proved: 1})
			return s
		}, Degraded, "address book is damaged"},
		{"installed, then a ruleset mismatch", func() State {
			s, _ := shell{}.drain(installed(reconcile.Report{Installed: "r1"}, nil)(), ReportFailed{At: t0, Step: reconcile.StepRuleset, Err: ErrUnenforced})
			return s
		}, Unenforced, "changed outside ifbound"},
		{"installed, then a new configuration", func() State {
			s, _ := shell{}.drain(installed(reconcile.Report{Installed: "r1"}, nil)(), cfg)
			return s
		}, Unenforced, "not installed yet"},
	} {
		t.Run(c.name, func(t *testing.T) { checkPhase(t, c.state(), c.want, c.reason) })
	}
}

// checkPhase checks the lifecycle of s, that a reason has the text
// reason (or that there is no reason when it is empty), and that the
// gate is open with r1 exactly in Ready and Degraded.
func checkPhase(t *testing.T, s State, want Lifecycle, reason string) {
	t.Helper()
	p := PhaseOf(s)
	if p.Lifecycle != want {
		t.Errorf("lifecycle %v %q, want %v", p.Lifecycle, p.Reasons, want)
	}
	if reason == "" && len(p.Reasons) > 0 || reason != "" && !slices.ContainsFunc(p.Reasons, func(r string) bool { return strings.Contains(r, reason) }) {
		t.Errorf("reasons %q, want one with %q", p.Reasons, reason)
	}
	acks := want == Ready || want == Degraded
	switch st := GateOf(s).State.(type) {
	case Open:
		if !acks || st.Installed != "r1" {
			t.Errorf("gate open with %q in %v", st.Installed, want)
		}
	case Closed:
		wantErr := ErrUnenforced
		if want == Starting {
			wantErr = ErrNotReady
		}
		if acks || !errors.Is(st.Err, wantErr) {
			t.Errorf("gate closed with %v in %v", st.Err, want)
		}
	}
}

// A good configuration read asks for a convergence in each book state,
// with the trigger start only for the stored configuration at start.
func TestConfigReadConvergesInEachBookState(t *testing.T) {
	cfg := ConfigRead{At: t0, Config: scoped(nil, nil)}
	unloadable := shell{open: func(OpenBook) BookOpened { return BookOpened{At: t0, Err: errLoad} }}
	failed, _ := shell{}.drain(State{}, ConfigRead{At: t0, Err: errLoad})
	loading, _ := shell{}.drain(State{}, cfg)
	for _, c := range []struct {
		name    string
		s       State
		trigger string
	}{
		{"at start", State{}, logattr.TriggerStart},
		{"after a failed load at start", failed, logattr.TriggerConfig},
		{"book loading", loading, logattr.TriggerConfig},
		{"book unloadable", unloadable.pass(loading, t0, reconcile.Report{}, nil), logattr.TriggerConfig},
		{"book loaded", shell{}.pass(loading, t0, reconcile.Report{Installed: "r1"}, nil), logattr.TriggerConfig},
	} {
		_, effects := Step(c.s, cfg)
		if got := effects[len(effects)-1]; got != (Converge{Trigger: c.trigger}) {
			t.Errorf("%s: last effect %v, want Converge %q", c.name, got, c.trigger)
		}
	}
}

// The self-heal stays on the grid of New, a burst of interface changes
// gives one convergence, and the expiry of the book comes at its next
// expiry.
func TestTimers(t *testing.T) {
	s, _ := shell{}.drain(New(t0, false), ConfigRead{At: t0, Config: scoped(nil, nil)})
	s = shell{}.pass(s, t0, reconcile.Report{Installed: "r1"}, nil)
	wantWake := func(want time.Time) {
		t.Helper()
		if got, ok := NextWake(s); !ok || !got.Equal(want) {
			t.Errorf("NextWake = %v, %v; want %v", got, ok, want)
		}
	}
	wantWake(at(SelfHealInterval))

	var effects []Effect
	s, effects = Step(s, Tick{At: at(2*SelfHealInterval + time.Second)})
	if effects[len(effects)-1] != (Converge{Trigger: logattr.TriggerSelfHeal}) {
		t.Errorf("late self-heal gave %v, want Converge self_heal", effects)
	}
	wantWake(at(3 * SelfHealInterval))

	s, _ = Step(s, InterfacesChanged{At: at(11 * time.Second)})
	s, _ = Step(s, InterfacesChanged{At: at(11*time.Second + InterfaceDebounce/2)})
	wantWake(at(11*time.Second + InterfaceDebounce))
	s, effects = Step(s, Tick{At: at(11*time.Second + InterfaceDebounce)})
	if len(effects) != 1 || effects[0] != (Converge{Trigger: logattr.TriggerInterfaces}) {
		t.Errorf("debounce gave %v, want one Converge interfaces", effects)
	}
	wantWake(at(3 * SelfHealInterval))

	s, _ = Step(s, BookChanged{At: at(12 * time.Second), Facts: addrstore.BookFacts{NextExpiry: at(13 * time.Second)}})
	wantWake(at(13 * time.Second))
	s, effects = Step(s, Tick{At: at(13 * time.Second)})
	if len(effects) != 1 || effects[0] != (ExpireBook{At: at(13 * time.Second)}) {
		t.Fatalf("expiry gave %v, want ExpireBook", effects)
	}
	wantWake(at(3 * SelfHealInterval))
	if _, effects = Step(s, BookExpired{At: at(13 * time.Second)}); len(effects) > 0 {
		t.Errorf("an expire that removed nothing gave %v", effects)
	}
	if _, effects = Step(s, BookExpired{At: at(13 * time.Second), Removed: 1}); len(effects) != 1 || effects[0] != (Converge{Trigger: logattr.TriggerExpiry}) {
		t.Errorf("an expire that removed an entry gave %v, want Converge expiry", effects)
	}
}
