package core

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// AccountReadTimeout is the budget of one account read. A lookup in the
// local account database takes milliseconds; a network directory that
// does not answer can take much longer.
const AccountReadTimeout = 5 * time.Second

// accountReads is what Step knows of the account reads. They are the only
// input with a budget, so the deadline is here and not in Observed: an
// input without a budget cannot be late.
type accountReads struct {
	Observed[Accounts]
	// deadline is the end of the budget of the read in flight.
	deadline time.Time
	// late is true when the last read that ended was at or after its
	// deadline.
	late bool
}

// overdue reports whether the read in flight is at or past its deadline
// at now.
func (a accountReads) overdue(now time.Time) bool {
	_, busy := a.InFlight()
	return busy && !now.Before(a.deadline)
}

// Accounts is the account snapshot that the convergences use. The
// Compiler drops the scope of a policy that names an account that is not
// in the snapshot, so the zero snapshot drops every scope.
type Accounts struct {
	IDs reconcile.Accounts
	// Failed is the number of names whose lookup failed in the read.
	Failed int
}

// Lookup is the result of the lookup of one name. Found is false, with
// a nil Err, for a name that the host does not know.
type Lookup struct {
	ID    uint32
	Found bool
	Err   error
}

// AccountsWanted asks for a read of the accounts that the scopes of the
// configuration name. During a read it asks for one more read after it.
type AccountsWanted struct {
	At            time.Time
	Users, Groups []string
}

// AccountsRead is the result of the read ID: a lookup for each name
// that the read asked for.
type AccountsRead struct {
	At            time.Time
	ID            ReqID
	Users, Groups map[string]Lookup
}

func (e AccountsWanted) at() time.Time { return e.At }
func (e AccountsRead) at() time.Time   { return e.At }

// ReadAccounts starts the read ID of the users and groups. Its result
// is an AccountsRead with the same ID.
type ReadAccounts struct {
	ID            ReqID
	Users, Groups []string
}

// AccountsOverdue tells that the read in flight is past its budget.
type AccountsOverdue struct{}

// AccountLookupsFailed tells the names whose lookup failed, at the first
// read that fails after a good one. Users and Groups are sorted.
type AccountLookupsFailed struct {
	Users, Groups []string
	Err           error
}

func (ReadAccounts) isEffect()         {}
func (ReadAccounts) isAsync()          {}
func (AccountsOverdue) isEffect()      {}
func (AccountsOverdue) isOut()         {}
func (AccountLookupsFailed) isEffect() {}
func (AccountLookupsFailed) isOut()    {}

// AccountIDs returns the account snapshot of the last read. It is zero
// before the first read ends.
func (s State) AccountIDs() reconcile.Accounts {
	last, _ := s.accounts.Last()
	return last.Value.IDs
}

// AccountsProblem returns the Problem of the account reads, if there is
// one. The caller checks first that a scope names an account and that
// there is a reader. It does not void enforcement: a scope that the
// snapshot cannot resolve is dropped, and the policy then applies to all
// traffic.
func AccountsProblem(s State) (reconcile.Problem, bool) {
	last, done := s.accounts.Last()
	overdue := s.accounts.overdue(s.now)
	var text string
	switch {
	case !done:
		text = "the accounts are not read yet, so each scoped policy applies to all traffic"
		if overdue {
			text += fmt.Sprintf("; the read takes longer than %s", AccountReadTimeout)
		}
	case overdue || s.accounts.late:
		text = fmt.Sprintf("the account read takes longer than %s, so a changed account applies late", AccountReadTimeout)
	case last.Value.Failed > 0:
		text = fmt.Sprintf("the lookup of %d user and group accounts failed; each keeps the id of its last good lookup, and a scope that has an account without one applies to all traffic", last.Value.Failed)
	default:
		return reconcile.Problem{}, false
	}
	return reconcile.Problem{Text: text}, true
}

// readAccounts starts a read of the names of the last AccountsWanted.
// During a read it starts nothing: the next read starts when the read in
// flight ends.
func (s State) readAccounts(out []Effect) (State, []Effect) {
	id := s.nextID + 1
	o, started := s.accounts.Start(id)
	s.accounts.Observed = o
	if !started {
		return s, out
	}
	s.nextID, s.accounts.deadline = id, s.now.Add(AccountReadTimeout)
	return s, append(out, ReadAccounts{ID: id, Users: s.scope.users, Groups: s.scope.groups})
}

// accountsOverdue tells that the read in flight passed its budget. A
// directory that is always slow tells it once: not again while each read
// ends late.
func (s State) accountsOverdue(out []Effect) []Effect {
	if s.accounts.late {
		return out
	}
	return append(out, AccountsOverdue{})
}

// applyAccounts makes a new snapshot from the result of the read in
// flight, and starts the next read if a trigger came during it. A name
// whose lookup failed keeps the id of its last good lookup, or stays
// unknown if it has none. It reports whether the snapshot or its problem
// changed. It changes nothing for the result of another read.
func (s State) applyAccounts(ev AccountsRead, out []Effect) (State, []Effect, bool) {
	before, wasDone := s.accounts.Last()
	wasLate := s.accounts.late
	users, failedUsers, userErrs := mergeLookups("user", ev.Users, before.Value.IDs.Users)
	groups, failedGroups, groupErrs := mergeLookups("group", ev.Groups, before.Value.IDs.Groups)
	errs := slices.Concat(userErrs, groupErrs)
	snap := Accounts{IDs: reconcile.Accounts{Users: users, Groups: groups}, Failed: len(errs)}
	o, ok := s.accounts.Finish(ev.ID, snap, nil, s.now)
	if !ok {
		return s, out, false
	}
	s.accounts.Observed, s.accounts.late = o, !s.now.Before(s.accounts.deadline)
	if before.Value.Failed == 0 && len(errs) > 0 {
		// The details go to the log at the first read that fails after a
		// good one. The problem text has only the count, so it does not
		// change with them.
		out = append(out, AccountLookupsFailed{Users: failedUsers, Groups: failedGroups, Err: errors.Join(errs...)})
	}
	if o.Again() {
		s, out = s.readAccounts(out)
	}
	changed := !wasDone || s.accounts.late != wasLate || snap.Failed != before.Value.Failed ||
		!maps.Equal(before.Value.IDs.Users, users) || !maps.Equal(before.Value.IDs.Groups, groups)
	return s, out, changed
}

// mergeLookups returns the ids of the found names, and the last id of
// each failed name that had one. It returns the failed names sorted, with
// one error for each, in the same order.
func mergeLookups(kind string, res map[string]Lookup, last map[string]uint32) (ids map[string]uint32, failed []string, errs []error) {
	ids = make(map[string]uint32, len(res))
	for _, name := range slices.Sorted(maps.Keys(res)) {
		switch lk := res[name]; {
		case lk.Err != nil:
			failed = append(failed, name)
			errs = append(errs, fmt.Errorf("%s %s: %w", kind, name, lk.Err))
			if id, ok := last[name]; ok {
				ids[name] = id
			}
		case lk.Found:
			ids[name] = lk.ID
		}
	}
	return ids, failed, errs
}
