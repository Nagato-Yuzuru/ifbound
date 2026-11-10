package daemon

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon/core"
	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// AccountReadTimeout is the budget of one account read. A lookup in the
// local account database takes milliseconds; a network directory that
// does not answer can take much longer.
const AccountReadTimeout = core.AccountReadTimeout

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

// wantAccounts asks core for a read of the accounts that the scopes of
// the configuration name. Without a reader it does nothing, and the
// snapshot stays zero.
func (l *loop) wantAccounts(ctx context.Context) {
	if l.accountReader == nil {
		return
	}
	users, groups := scopeNames(l.policies())
	l.drive(ctx, core.AccountsWanted{At: time.Now(), Users: users, Groups: groups})
}

// readAccounts runs the read of e on its own goroutine. core starts at
// most one read at a time, so a lookup that hangs holds one goroutine
// only, and the result always has room in accountResults: a read never
// waits for the loop, also after Run returned.
func (l *loop) readAccounts(ctx context.Context, e core.ReadAccounts) {
	r, results := l.accountReader, l.accountResults
	// Run does not wait for this goroutine. A lookup that still runs when
	// Run returns goes on until the system call returns, and its result
	// goes into the buffer of results, where nobody reads it.
	go func() { results <- lookupAll(ctx, r, e) }()
}

// lookupAll looks up each name of e. After ctx ends, it looks up no more
// names, and each one that is left gets the error of ctx. The loop sets
// the time of the result when it takes it.
func lookupAll(ctx context.Context, r AccountReader, e core.ReadAccounts) core.AccountsRead {
	run := func(names []string, f func(string) (uint32, bool, error)) map[string]core.Lookup {
		out := make(map[string]core.Lookup, len(names))
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				out[name] = core.Lookup{Err: err}
				continue
			}
			id, found, err := f(name)
			out[name] = core.Lookup{ID: id, Found: found, Err: err}
		}
		return out
	}
	return core.AccountsRead{ID: e.ID, Users: run(e.Users, r.LookupUser), Groups: run(e.Groups, r.LookupGroup)}
}

// logLookupsFailed writes the event of the first read that fails after a
// good one.
func (l *loop) logLookupsFailed(ctx context.Context, e core.AccountLookupsFailed) {
	attrs := []slog.Attr{
		slog.String(logattr.ErrorType, logattr.ErrorTypeLookup),
		slog.String(logattr.ExceptionMessage, e.Err.Error()),
	}
	if len(e.Users) > 0 {
		attrs = append(attrs, slog.Any(logattr.AccountUsers, e.Users))
	}
	if len(e.Groups) > 0 {
		attrs = append(attrs, slog.Any(logattr.AccountGroups, e.Groups))
	}
	l.log.LogAttrs(ctx, slog.LevelWarn, "account lookups failed", attrs...)
}

// accountsProblem returns the Problem of the account snapshot, if there
// is one. It does not void enforcement: a scope that the snapshot cannot
// resolve is dropped, and the policy then applies to all traffic.
func (l *loop) accountsProblem(policies []policy.Policy) (reconcile.Problem, bool) {
	if users, groups := scopeNames(policies); len(users) == 0 && len(groups) == 0 {
		return reconcile.Problem{}, false
	}
	if l.accountReader == nil {
		return reconcile.Problem{Text: "there is no account reader, so each scoped policy applies to all traffic"}, true
	}
	return core.AccountsProblem(l.core)
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
