package core

import (
	"fmt"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// reasonRulesetChanged is the reason of Unenforced after a report found
// another loaded ruleset.
const reasonRulesetChanged = "the loaded ruleset changed outside ifbound"

// ReportFailed tells that a DNS report failed at Step and got no ack.
type ReportFailed struct {
	At   time.Time
	Step reconcile.ReportStep
	Err  error
}

// ReportSucceeded tells that a DNS report got a protected ack after a
// ReportFailed. The shell sends it only then.
type ReportSucceeded struct{ At time.Time }

func (e ReportFailed) at() time.Time    { return e.At }
func (e ReportSucceeded) at() time.Time { return e.At }

// ReportPathFailed tells the log of a report failure at a step that
// differs from the step of the failure before. A failure that repeats at
// the same step is not logged again until a report succeeds, also across
// convergences.
type ReportPathFailed struct {
	Step reconcile.ReportStep
	Err  error
}

func (ReportPathFailed) isEffect() {}
func (ReportPathFailed) isOut()    {}

// reports is what Step knows of the report path.
type reports struct {
	// cause is the latest report failure since the last convergence, or
	// nil. A success also clears it, unless it is a failure at
	// StepRuleset: that one voids the enforcement until a convergence.
	cause *ReportFailed
	// afterAdd is the failed table add before a cause at StepRuleset in
	// the same convergence interval, or nil. A Backend can report no
	// loaded ruleset after an add that did not finish, so the reason
	// names the add, not a change outside ifbound.
	afterAdd *ReportFailed
	// logged is the step of the last ReportPathFailed, or zero after a
	// success.
	logged reconcile.ReportStep
}

// repairable reports whether a Load of the ruleset can repair a failure
// at step. Such a failure asks for a convergence. A failed commit of the
// address book does not: a Load does not repair the disk. Its cause goes
// away at the next convergence all the same, and the next failed commit
// sets it again: no event tells that the disk works again.
func repairable(step reconcile.ReportStep) bool {
	switch step {
	case reconcile.StepTableAdd, reconcile.StepLoadedID, reconcile.StepRuleset:
		return true
	case reconcile.StepCommit:
		return false
	default:
		panic(fmt.Sprintf("core: unknown report step %d", step))
	}
}

// applyReportFailed keeps the failure as the cause. It returns the
// trigger of the convergence that the failure asks for, or "". Without
// a configuration no report reaches the report path, so it ignores the
// event then.
func (s State) applyReportFailed(ev ReportFailed, out []Effect) (State, []Effect, string) {
	if _, ok := s.Config().(Configured); !ok {
		return s, out, ""
	}
	if s.reports.logged != ev.Step {
		s.reports.logged = ev.Step
		out = append(out, ReportPathFailed{Step: ev.Step, Err: ev.Err})
	}
	if old := s.reports.cause; old != nil && old.Step == reconcile.StepRuleset {
		// Only a convergence clears this cause, and it voids the
		// enforcement: a later failure of another step must not hide it.
		return s, out, ""
	}
	if old := s.reports.cause; ev.Step == reconcile.StepRuleset && old != nil && old.Step == reconcile.StepTableAdd {
		s.reports.afterAdd = old
	}
	s.reports.cause = &ev
	switch {
	case ev.Step == reconcile.StepRuleset:
		return s, out, logattr.TriggerRulesetChanged
	case repairable(ev.Step):
		return s, out, logattr.TriggerReportFailed
	default:
		return s, out, ""
	}
}

// applyReportSucceeded clears the cause, unless it is a failure at
// StepRuleset.
func (s State) applyReportSucceeded() State {
	s.reports.logged = 0
	if c := s.reports.cause; c != nil && c.Step != reconcile.StepRuleset {
		s.reports.cause = nil
	}
	return s
}

// reportProblem is the problem of a report failure that does not void
// the enforcement.
func reportProblem(s State) (reconcile.Problem, bool) {
	c := s.reports.cause
	if c == nil || c.Step == reconcile.StepRuleset {
		return reconcile.Problem{}, false
	}
	return reconcile.Problem{Text: "a DNS report got no ack: " + c.Err.Error()}, true
}

// rulesetReason returns the reason of Unenforced when a report found
// another loaded ruleset after the last convergence.
func rulesetReason(s State) (string, bool) {
	c := s.reports.cause
	switch {
	case c == nil || c.Step != reconcile.StepRuleset:
		return "", false
	case s.reports.afterAdd != nil:
		return "the loaded ruleset is not known after a table add did not finish: " + s.reports.afterAdd.Err.Error(), true
	default:
		return reasonRulesetChanged, true
	}
}

// clearReports clears the cause. A convergence calls it.
func (s State) clearReports() State {
	s.reports.cause, s.reports.afterAdd = nil, nil
	return s
}
