package core

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

var errReport = errors.New("report step failed")

func failed(step reconcile.ReportStep) ReportFailed {
	return ReportFailed{At: t0, Step: step, Err: errReport}
}

// triggers returns the triggers of the Converge effects.
func triggers(effects []Effect) []string {
	var out []string
	for _, e := range effects {
		if c, ok := e.(Converge); ok {
			out = append(out, c.Trigger)
		}
	}
	return out
}

// A report failure is a fact of the State. A failure that a Load
// repairs asks for a convergence. A failed commit does not: a Load does
// not repair the disk. Only a changed ruleset voids the enforcement.
func TestReportFailureSetsThePhase(t *testing.T) {
	for _, c := range []struct {
		step    reconcile.ReportStep
		want    Lifecycle
		reason  string
		trigger []string
	}{
		{reconcile.StepTableAdd, Degraded, "a DNS report got no ack: report step failed", []string{logattr.TriggerReportFailed}},
		{reconcile.StepLoadedID, Degraded, "a DNS report got no ack: report step failed", []string{logattr.TriggerReportFailed}},
		{reconcile.StepCommit, Degraded, "a DNS report got no ack: report step failed", nil},
		{reconcile.StepRuleset, Unenforced, reasonRulesetChanged, []string{logattr.TriggerRulesetChanged}},
	} {
		s, effects := shell{}.drain(ready(t, shell{}), failed(c.step))
		p := PhaseOf(s)
		if p.Lifecycle != c.want || !slices.Contains(p.Reasons, c.reason) {
			t.Errorf("step %d: phase = %v %q, want %v with %q", c.step, p.Lifecycle, p.Reasons, c.want, c.reason)
		}
		if got := triggers(effects); !slices.Equal(got, c.trigger) {
			t.Errorf("step %d: triggers = %v, want %v", c.step, got, c.trigger)
		}
		if n := countOf[ReportPathFailed](effects); n != 1 {
			t.Errorf("step %d: %d ReportPathFailed, want 1", c.step, n)
		}
	}
}

// A failure that repeats at the same step is logged once, also across a
// convergence. A failure at another step, or after a success, is logged
// again.
func TestReportFailureLogsEachNewStep(t *testing.T) {
	s := ready(t, shell{})
	var logged []reconcile.ReportStep
	commit, add := failed(reconcile.StepCommit), failed(reconcile.StepTableAdd)
	pass := Converged{At: t0, Report: reconcile.Report{Installed: "r1"}}
	for _, ev := range []Event{commit, commit, pass, commit, add, add, commit, ReportSucceeded{At: t0}, commit} {
		var effects []Effect
		s, effects = shell{}.drain(s, ev)
		for _, e := range effects {
			if f, ok := e.(ReportPathFailed); ok {
				logged = append(logged, f.Step)
			}
		}
	}
	want := []reconcile.ReportStep{reconcile.StepCommit, reconcile.StepTableAdd, reconcile.StepCommit, reconcile.StepCommit}
	if !slices.Equal(logged, want) {
		t.Errorf("logged steps = %v, want %v", logged, want)
	}
}

// A success clears each failure but a changed ruleset. A convergence
// clears each failure.
func TestReportFailureClears(t *testing.T) {
	steps := []reconcile.ReportStep{reconcile.StepTableAdd, reconcile.StepCommit, reconcile.StepLoadedID, reconcile.StepRuleset}
	for _, step := range steps {
		s, _ := shell{}.drain(ready(t, shell{}), failed(step))
		afterSuccess, _ := shell{}.drain(s, ReportSucceeded{At: t0})
		if got, want := PhaseOf(afterSuccess).Lifecycle, map[bool]Lifecycle{true: Unenforced, false: Ready}[step == reconcile.StepRuleset]; got != want {
			t.Errorf("step %d, then a success: %v, want %v", step, got, want)
		}
		afterPass := shell{}.pass(s, t0.Add(time.Second), reconcile.Report{Installed: "r1"}, nil)
		if got := PhaseOf(afterPass).Lifecycle; got != Ready {
			t.Errorf("step %d, then a convergence: %v, want Ready", step, got)
		}
	}
}

// A changed ruleset stays the cause until a convergence: a later
// failure at another step does not hide it.
func TestReportFailureKeepsTheChangedRuleset(t *testing.T) {
	s, _ := shell{}.drain(ready(t, shell{}), failed(reconcile.StepRuleset))
	s, _ = shell{}.drain(s, failed(reconcile.StepCommit))
	if p := PhaseOf(s); p.Lifecycle != Unenforced || !slices.Contains(p.Reasons, reasonRulesetChanged) {
		t.Errorf("phase = %v %q, want Unenforced with %q", p.Lifecycle, p.Reasons, reasonRulesetChanged)
	}
}

// Without a configuration no report reaches the report path.
func TestReportFailureWithoutConfigurationIsIgnored(t *testing.T) {
	s, effects := shell{}.drain(State{}, failed(reconcile.StepTableAdd))
	if len(effects) != 0 {
		t.Errorf("effects = %v, want none", effects)
	}
	if p := PhaseOf(s); slices.ContainsFunc(p.Reasons, func(r string) bool { return strings.Contains(r, "DNS report") }) {
		t.Errorf("reasons = %q, want no report reason", p.Reasons)
	}
}

// A Backend can report no loaded ruleset after a table add that did not
// finish. The reason then names the add, not a change outside ifbound.
// The phase stays Unenforced: no report gets an ack until a convergence.
func TestRulesetMismatchAfterAFailedAddNamesTheAdd(t *testing.T) {
	s, _ := shell{}.drain(ready(t, shell{}), ReportFailed{At: t0, Step: reconcile.StepTableAdd, Err: errors.New("ending the states failed")})
	s, _ = shell{}.drain(s, failed(reconcile.StepRuleset))
	p := PhaseOf(s)
	want := "the loaded ruleset is not known after a table add did not finish: ending the states failed"
	if p.Lifecycle != Unenforced || !slices.Equal(p.Reasons, []string{want}) {
		t.Errorf("phase = %v %q, want Unenforced with %q", p.Lifecycle, p.Reasons, want)
	}
	if _, ok := GateOf(s).State.(Closed); !ok {
		t.Errorf("gate = %#v, want closed", GateOf(s).State)
	}
	s = shell{}.pass(s, t0.Add(time.Second), reconcile.Report{Installed: "r1"}, nil)
	s, _ = shell{}.drain(s, failed(reconcile.StepRuleset))
	if p := PhaseOf(s); !slices.Equal(p.Reasons, []string{reasonRulesetChanged}) {
		t.Errorf("a mismatch after a convergence: reasons %q, want %q", p.Reasons, reasonRulesetChanged)
	}
}
