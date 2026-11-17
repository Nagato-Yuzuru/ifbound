package core

import (
	"errors"
	"fmt"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// Answer is the answer to one DNS report. Only Admit and AckAfterCheck
// make one, and only AckAfterCheck makes a protected one: the fields are
// not exported. The zero Answer refuses the report with ErrUnenforced.
type Answer struct {
	kind answerKind
	err  error
	// step is the step of the report path whose failure is a fact for
	// Step, or zero.
	step reconcile.ReportStep
}

type answerKind uint8

const (
	refused answerKind = iota
	unprotected
	protected
)

// Protected reports whether the report gets a protected ack: its
// addresses are in the tables, and the installed ruleset is loaded.
func (a Answer) Protected() bool { return a.kind == protected }

// Err returns nil when the report gets an ack, protected or not, and the
// error of the refusal otherwise.
func (a Answer) Err() error {
	switch a.kind {
	case protected, unprotected:
		return nil
	case refused:
		if a.err == nil {
			return ErrUnenforced
		}
		return a.err
	default:
		panic(fmt.Sprintf("core: unknown answer kind %d", a.kind))
	}
}

// Failure returns the step of the report path whose failure the refusal
// tells Step about, and its error. It reports false for an ack and for a
// refusal that is no such failure, for example a closed gate or a stale
// epoch.
func (a Answer) Failure() (reconcile.ReportStep, error, bool) {
	if a.kind != refused || a.step == 0 {
		return 0, nil, false
	}
	return a.step, a.Err(), true
}

// Admit decides on a report before the report path. A closed gate and a
// malformed name refuse the report, and a name that matches no policy
// gets an unprotected ack: decided is true then. Else it returns the
// policies of the name and the epoch of the gate, and the shell runs
// reconcile.Record with them.
func Admit(g Gate, qname string) (names []policy.Name, epoch uint64, a Answer, decided bool) {
	var o Open
	switch st := g.State.(type) {
	case Closed:
		return nil, 0, Answer{err: st.Err}, true
	case Open:
		o = st
	default:
		panic(fmt.Sprintf("core: unknown gate state %T", st))
	}
	names, err := g.Matcher.Match(qname)
	if err != nil {
		return nil, 0, Answer{err: fmt.Errorf("classifying qname: %w", err)}, true
	}
	if len(names) == 0 {
		return nil, 0, Answer{kind: unprotected}, true
	}
	return names, o.Epoch, Answer{}, false
}

// AckAfterCheck answers a report after reconcile.Record. The gate g must
// be read after Record returned, so that the answer never trusts a gate
// that is older than the check. The report gets a protected ack only
// when g is open and c proves the epoch and the installed ruleset of g.
func AckAfterCheck(g Gate, c reconcile.Checked, err error) Answer {
	var o Open
	switch st := g.State.(type) {
	case Closed:
		return Answer{err: st.Err}
	case Open:
		o = st
	default:
		panic(fmt.Sprintf("core: unknown gate state %T", st))
	}
	if err != nil {
		if re, ok := errors.AsType[*reconcile.ReportError](err); ok {
			return Answer{err: err, step: re.Step}
		}
		return Answer{err: err}
	}
	switch {
	case c.Proves(o.Epoch, o.Installed):
		return Answer{kind: protected}
	case c.Mismatch(o.Epoch, o.Installed):
		return Answer{err: ErrUnenforced, step: reconcile.StepRuleset}
	default:
		// The check ran for an older gate.
		return Answer{err: reconcile.ErrStale}
	}
}
