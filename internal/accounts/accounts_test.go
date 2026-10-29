package accounts_test

import (
	"os/user"
	"strconv"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/accounts"
	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
)

var _ daemon.AccountReader = accounts.Reader{}

func formatID(id uint32) string { return strconv.FormatUint(uint64(id), 10) }

// The test process runs as an account of the host, so the Reader must
// find it and its primary group with the ids that the process has.
// user.Current answers from the process ids and a cache, so the test also
// looks up root and the group with gid 0, which makes os/user ask the
// account database by name.
func TestReaderFindsKnownAccounts(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	grp, err := user.LookupGroupId(cur.Gid)
	if err != nil {
		t.Fatalf("primary group %s: %v", cur.Gid, err)
	}
	root, err := user.LookupGroupId("0")
	if err != nil {
		t.Fatalf("group 0: %v", err)
	}
	r := accounts.Reader{}
	for _, u := range []struct{ name, uid string }{{cur.Username, cur.Uid}, {"root", "0"}} {
		id, found, err := r.LookupUser(u.name)
		if err != nil || !found || formatID(id) != u.uid {
			t.Errorf("LookupUser(%s) = %d, %v, %v; want %s, true, nil", u.name, id, found, err, u.uid)
		}
	}
	for _, g := range []struct{ name, gid string }{{grp.Name, grp.Gid}, {root.Name, "0"}} {
		id, found, err := r.LookupGroup(g.name)
		if err != nil || !found || formatID(id) != g.gid {
			t.Errorf("LookupGroup(%s) = %d, %v, %v; want %s, true, nil", g.name, id, found, err, g.gid)
		}
	}
}

// An unknown name is not an error: the Compiler drops the scope that
// names it.
func TestReaderDoesNotFindUnknownNames(t *testing.T) {
	const name = "ifbound-no-such-account"
	r := accounts.Reader{}
	if _, found, err := r.LookupUser(name); found || err != nil {
		t.Errorf("LookupUser(%s) = %v, %v; want false, nil", name, found, err)
	}
	if _, found, err := r.LookupGroup(name); found || err != nil {
		t.Errorf("LookupGroup(%s) = %v, %v; want false, nil", name, found, err)
	}
}
