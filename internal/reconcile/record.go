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
// step returns a *ReportError. A stale epoch returns ErrStale.
func Record(ctx context.Context, g *Guard, l Ledger, s Sighting) (Checked, error) {
	var c Checked
	err := g.Shared(func(a Adder) error {
		if g.epoch != s.Epoch {
			return ErrStale
		}
		if len(s.Addrs) > 0 {
			p, err := l.Touch(s.Names, s.Addrs, s.TTL, s.At)
			if err != nil {
				return fmt.Errorf("recording addresses: %w", err)
			}
			for _, name := range s.Names {
				if err := AddObserved(ctx, a, name, s.Addrs); err != nil {
					return &ReportError{Step: StepTableAdd, Err: err}
				}
			}
			if err := l.Commit(ctx, p); err != nil {
				return &ReportError{Step: StepCommit, Err: fmt.Errorf("saving the address book: %w", err)}
			}
		}
		id, err := a.LoadedID(ctx)
		if err != nil {
			return &ReportError{Step: StepLoadedID, Err: fmt.Errorf("reading the loaded ruleset: %w", err)}
		}
		c = Checked{ok: true, epoch: s.Epoch, loaded: id}
		return nil
	})
	return c, err
}
