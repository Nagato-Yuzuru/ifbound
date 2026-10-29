// Package accounts looks up the ids of user and group accounts of the
// host through os/user. On macOS, os/user asks Directory Services also
// without cgo, so it finds the accounts that are not in /etc/passwd, for
// example the accounts of a network directory.
package accounts

import (
	"errors"
	"fmt"
	"os/user"
	"strconv"
)

var (
	errLookup = errors.New("account lookup failed")
	errID     = errors.New("account id is not a 32-bit number")
)

// Reader looks up accounts. The zero Reader uses os/user. It implements
// daemon.AccountReader.
//
// A lookup can block for a long time, for example when a network
// directory does not answer, and nothing can stop it. The caller decides
// how long it waits.
type Reader struct {
	// lookupUser and lookupGroup replace os/user in tests. Nil means
	// os/user.
	lookupUser  func(name string) (*user.User, error)
	lookupGroup func(name string) (*user.Group, error)
}

// LookupUser returns the uid of a user. found is false, with a nil error,
// when the host does not know the name. Any other failure is an error.
func (r Reader) LookupUser(name string) (uid uint32, found bool, err error) {
	lookup := r.lookupUser
	if lookup == nil {
		lookup = user.Lookup
	}
	u, err := lookup(name)
	if _, unknown := errors.AsType[user.UnknownUserError](err); unknown {
		return 0, false, nil
	}
	if err != nil {
		// %v: the os/user error is not part of the contract.
		return 0, false, fmt.Errorf("%w: user %q: %v", errLookup, name, err)
	}
	return parseID("user", name, u.Uid)
}

// LookupGroup returns the gid of a group. found is false, with a nil
// error, when the host does not know the name. Any other failure is an
// error.
func (r Reader) LookupGroup(name string) (gid uint32, found bool, err error) {
	lookup := r.lookupGroup
	if lookup == nil {
		lookup = user.LookupGroup
	}
	g, err := lookup(name)
	if _, unknown := errors.AsType[user.UnknownGroupError](err); unknown {
		return 0, false, nil
	}
	if err != nil {
		// %v: the os/user error is not part of the contract.
		return 0, false, fmt.Errorf("%w: group %q: %v", errLookup, name, err)
	}
	return parseID("group", name, g.Gid)
}

// parseID parses an id as os/user gives it: a decimal number. macOS gives
// nobody (-2) as 4294967294, so a valid id fits in a uint32.
func parseID(kind, name, s string) (uint32, bool, error) {
	id, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false, fmt.Errorf("%s %q: %w: %q", kind, name, errID, s)
	}
	return uint32(id), true, nil
}
