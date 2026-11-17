package reconcile

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// ErrStale is the error of a report whose gate is older than the last
// write that can remove an entry or replace the ruleset. The report got
// no check. A new report uses the new gate.
var ErrStale = errors.New("the enforcement changed during the report")

// Ledger is the part of the address book that a report writes.
// *addrstore.Store implements it.
type Ledger interface {
	Touch(names []policy.Name, addrs []blockable.Addr, ttl time.Duration, at time.Time) (addrstore.Pending, error)
	Commit(ctx context.Context, p addrstore.Pending) error
}

// Sighting is one DNS report that matched at least one policy.
type Sighting struct {
	// Names are the policies that the name of the report matches.
	Names []policy.Name
	// Addrs are the addresses of the answer that blockable.New accepts.
	Addrs []blockable.Addr
	TTL   time.Duration
	At    time.Time
	// Epoch is Open.Epoch of the gate that admitted the report.
	Epoch uint64
}

// ReportError is the error of a report that failed at Step.
type ReportError struct {
	Step ReportStep
	Err  error
}

func (e *ReportError) Error() string { return e.Err.Error() }
func (e *ReportError) Unwrap() error { return e.Err }

// Checked is what Record proved about the Backend. Only Record makes a
// Checked that proves something: the zero Checked proves nothing.
type Checked struct {
	ok     bool
	epoch  uint64
	loaded string
}

// Proves reports whether the check holds for a gate with epoch and the
// installed ruleset ID installed: the Guard had epoch, and the Backend
// had installed loaded, while the tables held the addresses of the
// report.
func (c Checked) Proves(epoch uint64, installed string) bool {
	return c.ok && c.epoch == epoch && c.loaded == installed
}

// Mismatch reports whether the check ran for epoch and found another
// loaded ruleset than installed.
func (c Checked) Mismatch(epoch uint64, installed string) bool {
	return c.ok && c.epoch == epoch && c.loaded != installed
}

// Record runs the report path of s in one shared section of g. It
// checks that the epoch of g is still s.Epoch, adds the addresses to the
// table of each policy, commits them to l, and reads the ID of the
// loaded ruleset. No convergence runs inside the section, so none can
// read the book before the commit or remove an entry before the check.
// A report without an address skips the add and the commit, but not the
// check. The same s.Addrs go to the tables and to the book, so a table
// entry and its book key cannot differ. An address is in the book only
// after its commit: after a failure the book does not have it.
//
// It returns a Checked only when every step succeeded. A failure at a
// step returns a *ReportError. A stale epoch returns ErrStale. When ctx
// ends, it returns ctx.Err() and no Checked, also when the steps
// succeeded: the caller left, so no answer uses the check. A step that
// fails after ctx ended is no *ReportError, so the failure of the
// caller is not a fact of the report path.
func Record(ctx context.Context, g *Guard, l Ledger, s Sighting) (Checked, error) {
	var c Checked
	err := g.Shared(ctx, func(a Adder) error {
		if err := ctx.Err(); err != nil {
			// Shared can enter with an ended ctx when the lock is free
			// too: a report whose caller left writes nothing.
			return fmt.Errorf("report: %w", err)
		}
		if g.epoch != s.Epoch {
			return ErrStale
		}
		if err := write(ctx, a, l, s); err != nil {
			return err
		}
		id, err := a.LoadedID(ctx)
		if err != nil {
			return stepError(ctx, StepLoadedID, fmt.Errorf("reading the loaded ruleset: %w", err))
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("report: %w", err)
		}
		c = Checked{ok: true, epoch: s.Epoch, loaded: id}
		return nil
	})
	return c, err
}

// write adds the addresses of s to the table of each policy and commits
// them to l. A report without an address writes nothing.
func write(ctx context.Context, a Adder, l Ledger, s Sighting) error {
	if len(s.Addrs) == 0 {
		return nil
	}
	p, err := l.Touch(s.Names, s.Addrs, s.TTL, s.At)
	if err != nil {
		return fmt.Errorf("recording addresses: %w", err)
	}
	for _, name := range s.Names {
		if err := AddObserved(ctx, a, name, s.Addrs); err != nil {
			return stepError(ctx, StepTableAdd, err)
		}
	}
	if err := l.Commit(ctx, p); err != nil {
		return stepError(ctx, StepCommit, fmt.Errorf("saving the address book: %w", err))
	}
	return nil
}

// stepError is the error of a failure at step. After ctx ended, it is
// the error of ctx: the failure of the caller is not a fact of the
// report path.
func stepError(ctx context.Context, step ReportStep, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("report: %w", ctx.Err())
	}
	return &ReportError{Step: step, Err: err}
}
