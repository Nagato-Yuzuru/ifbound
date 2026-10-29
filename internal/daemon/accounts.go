package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// AccountReadTimeout is the budget of one account read. A lookup in the
// local account database takes milliseconds; a network directory that
// does not answer can take much longer.
const AccountReadTimeout = 5 * time.Second

// AccountReader looks up the ids of user and group accounts.
// accounts.Reader implements it. A lookup gives found false, with a nil
// error, for a name that the host does not know. An error means that the
// lookup failed, not that the name is unknown.
//
// A lookup can block, and nothing can stop it. The daemon calls the
// lookups outside the loop, one at a time, on one goroutine.
type AccountReader interface {
	LookupUser(name string) (uid uint32, found bool, err error)
	LookupGroup(name string) (gid uint32, found bool, err error)
}

// accountsState is the account snapshot that the convergences use. The
// Compiler drops the scope of a policy that names an account that is not
// in the snapshot, so the zero snapshot drops every scope. Only the Run
// goroutine touches it. A read runs on its own goroutine, and at most one
// read is in work: a lookup that hangs then holds one goroutine only.
type accountsState struct {
	reader AccountReader // nil: no reader, and the snapshot stays zero
	snap   reconcile.Accounts
	// done is true after the first read ended.
	done bool
	// failed is the number of names whose lookup failed in the last read.
	failed int
	// reading is true while a read is in work, and again asks for one
	// more read after it, because a trigger came meanwhile.
	reading, again bool
	// overdue is true when the read in work is past its budget, and late
	// is true when the last read that ended was past its budget. So a
	// directory that is always slow keeps one problem, and the state does
	// not change at each read. timeout fires at the end of the budget; it
	// is nil when no read is in work or the read is overdue.
	overdue, late bool
	timeout       <-chan time.Time
	// results receives the result of the read in work. It has room for
	// one result, so a read never waits for the loop, also after Run
	// returned.
	results chan accountsRead
}

func newAccountsState(r AccountReader) accountsState {
	return accountsState{reader: r, results: make(chan accountsRead, 1)}
}

// lookup is the result of the lookup of one name.
type lookup struct {
	id    uint32
	found bool
	err   error
}

// accountsRead is the result of one read: a lookup for each user and
// group that the scopes named when the read started.
type accountsRead struct {
	users, groups map[string]lookup
}

// readAccounts starts a read of the accounts that the scopes of the
// configuration name. When a read is in work, it starts no second one:
// the next read starts when the read in work ends.
func (l *loop) readAccounts(ctx context.Context) {
	a := &l.accounts
	if a.reader == nil {
		return
	}
	if a.reading {
		a.again = true
		return
	}
	a.reading, a.overdue = true, false
	a.timeout = time.After(AccountReadTimeout)
	users, groups := scopeNames(l.cfg.Policies)
	r, results := a.reader, a.results
	// Run does not wait for this goroutine. A lookup that still runs when
	// Run returns goes on until the system call returns, and its result
	// goes into the buffer of results, where nobody reads it.
	go func() { results <- lookupAll(ctx, r, users, groups) }()
}

// lookupAll looks up each name. After ctx ends, it looks up no more
// names, and each one that is left gets the error of ctx.
func lookupAll(ctx context.Context, r AccountReader, users, groups []string) accountsRead {
	run := func(names []string, f func(string) (uint32, bool, error)) map[string]lookup {
		out := make(map[string]lookup, len(names))
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				out[name] = lookup{err: err}
				continue
			}
			id, found, err := f(name)
			out[name] = lookup{id: id, found: found, err: err}
		}
		return out
	}
	return accountsRead{users: run(users, r.LookupUser), groups: run(groups, r.LookupGroup)}
}

// accountsOverdue marks the read in work as past its budget. The
// snapshot stays, and the read still applies when it ends.
func (l *loop) accountsOverdue(ctx context.Context) {
	a := &l.accounts
	a.overdue, a.timeout = true, nil
	if !a.late {
		l.log.WarnContext(ctx, "account read takes longer than its budget", slog.Duration("budget", AccountReadTimeout))
	}
}

// applyAccounts makes a new snapshot from a read that ended, and starts
// the next read if a trigger came meanwhile. A name whose lookup failed
// keeps the id of its last good lookup, or stays unknown if it has none.
// It reports whether the snapshot or its problem changed.
func (l *loop) applyAccounts(ctx context.Context, r accountsRead) bool {
	a := &l.accounts
	before, wasFailed, wasDone, wasLate := a.snap, a.failed, a.done, a.late
	a.late = a.overdue
	a.reading, a.overdue, a.timeout, a.done = false, false, nil, true

	type failure struct {
		kind, name string
		err        error
	}
	var failures []failure
	merge := func(kind string, res map[string]lookup, last map[string]uint32) map[string]uint32 {
		out := make(map[string]uint32, len(res))
		for name, lk := range res {
			switch {
			case lk.err != nil:
				failures = append(failures, failure{kind, name, lk.err})
				if id, ok := last[name]; ok {
					out[name] = id
				}
			case lk.found:
				out[name] = lk.id
			}
		}
		return out
	}
	a.snap = reconcile.Accounts{
		Users:  merge("user", r.users, before.Users),
		Groups: merge("group", r.groups, before.Groups),
	}
	a.failed = len(failures)
	if wasFailed == 0 {
		// The details go to the log at the first read that fails after a
		// good one. The problem text has only the count, so it does not
		// change with them.
		for _, f := range failures {
			l.log.WarnContext(ctx, "account lookup failed",
				slog.String("kind", f.kind), slog.String("name", f.name), slog.Any("error", f.err))
		}
	}
	if a.again {
		a.again = false
		l.readAccounts(ctx)
	}
	return !wasDone || a.late != wasLate || a.failed != wasFailed ||
		!maps.Equal(before.Users, a.snap.Users) || !maps.Equal(before.Groups, a.snap.Groups)
}

// accountsProblem returns the Problem of the account snapshot, if there
// is one. It does not void enforcement: a scope that the snapshot cannot
// resolve is dropped, and the policy then applies to all traffic.
func (l *loop) accountsProblem() (reconcile.Problem, bool) {
	a := &l.accounts
	if users, groups := scopeNames(l.cfg.Policies); len(users) == 0 && len(groups) == 0 {
		return reconcile.Problem{}, false
	}
	var text string
	switch {
	case a.reader == nil:
		text = "there is no account reader, so each scoped policy applies to all traffic"
	case !a.done:
		text = "the accounts are not read yet, so each scoped policy applies to all traffic"
		if a.overdue {
			text += fmt.Sprintf("; the read takes longer than %s", AccountReadTimeout)
		}
	case a.overdue || a.late:
		text = fmt.Sprintf("the account read takes longer than %s, so a changed account applies late", AccountReadTimeout)
	case a.failed > 0:
		text = fmt.Sprintf("the lookup of %d user and group accounts failed; each keeps the id of its last good lookup, and a scope that has an account without one applies to all traffic", a.failed)
	default:
		return reconcile.Problem{}, false
	}
	return reconcile.Problem{Text: text}, true
}

// scopeNames returns the user names and the group names that the scopes
// of the policies list, each sorted and without duplicates.
func scopeNames(policies []policy.Policy) (users, groups []string) {
	for _, p := range policies {
		for _, u := range p.Scope.Users() {
			users = append(users, u.String())
		}
		for _, g := range p.Scope.Groups() {
			groups = append(groups, g.String())
		}
	}
	slices.Sort(users)
	slices.Sort(groups)
	return slices.Compact(users), slices.Compact(groups)
}
