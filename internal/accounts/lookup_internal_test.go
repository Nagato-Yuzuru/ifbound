package accounts

import (
	"errors"
	"os/user"
	"testing"
)

var errDirectory = errors.New("opendirectoryd: operation timed out")

// A failed lookup is an error, never "not found": the daemon keeps the
// last good id of such a name, but drops the scope of a name that is
// not found.
func TestFailedLookupIsAnError(t *testing.T) {
	r := Reader{
		lookupUser:  func(string) (*user.User, error) { return nil, errDirectory },
		lookupGroup: func(string) (*user.Group, error) { return nil, errDirectory },
	}
	if _, found, err := r.LookupUser("alice"); found || !errors.Is(err, errLookup) {
		t.Errorf("LookupUser = %v, %v; want false and an error that wraps errLookup", found, err)
	}
	if _, found, err := r.LookupGroup("staff"); found || !errors.Is(err, errLookup) {
		t.Errorf("LookupGroup = %v, %v; want false and an error that wraps errLookup", found, err)
	}
}

func TestIDThatIsNotANumberIsAnError(t *testing.T) {
	r := Reader{
		lookupUser:  func(n string) (*user.User, error) { return &user.User{Username: n, Uid: "-2"}, nil },
		lookupGroup: func(n string) (*user.Group, error) { return &user.Group{Name: n, Gid: "4294967296"}, nil },
	}
	if _, found, err := r.LookupUser("alice"); found || !errors.Is(err, errID) {
		t.Errorf("LookupUser = %v, %v; want false and an error that wraps errID", found, err)
	}
	if _, found, err := r.LookupGroup("staff"); found || !errors.Is(err, errID) {
		t.Errorf("LookupGroup = %v, %v; want false and an error that wraps errID", found, err)
	}
}

func TestLookupGivesTheID(t *testing.T) {
	r := Reader{
		lookupUser:  func(n string) (*user.User, error) { return &user.User{Username: n, Uid: "4294967294", Gid: "7"}, nil },
		lookupGroup: func(n string) (*user.Group, error) { return &user.Group{Name: n, Gid: "20"}, nil },
	}
	if id, found, err := r.LookupUser("nobody"); id != 4294967294 || !found || err != nil {
		t.Errorf("LookupUser = %d, %v, %v; want 4294967294, true, nil", id, found, err)
	}
	if id, found, err := r.LookupGroup("staff"); id != 20 || !found || err != nil {
		t.Errorf("LookupGroup = %d, %v, %v; want 20, true, nil", id, found, err)
	}
}
