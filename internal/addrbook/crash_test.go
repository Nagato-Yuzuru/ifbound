package addrbook

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type crash struct{}

// A real Save that stops after the temporary file is written and before
// the rename. The panic skips all cleanup, like a killed process.
func TestCrashBeforeRenameKeepsOldSnapshot(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	a1 := netip.MustParseAddr("192.0.2.1")
	a2 := netip.MustParseAddr("192.0.2.2")
	path := filepath.Join(t.TempDir(), "book.json")

	b := New(time.Hour*24, clock)
	if _, err := b.Observe("p", []netip.Addr{a1}, 0); err != nil {
		t.Fatal(err)
	}
	if err := b.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Observe("p", []netip.Addr{a2}, 0); err != nil {
		t.Fatal(err)
	}
	b.rename = func(string, string) error { panic(crash{}) }
	func() {
		defer func() {
			if _, ok := recover().(crash); !ok {
				t.Fatal("save did not reach the rename step")
			}
		}()
		_ = b.Save(path) //nolint:errcheck // the rename hook panics, so Save never returns
	}()

	temps, err := filepath.Glob(path + tempInfix + "*")
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 1 {
		t.Fatalf("temporary files next to the snapshot: %v", temps)
	}
	data, err := os.ReadFile(temps[0])
	if err != nil || len(data) == 0 {
		t.Fatalf("temporary file is not written: %v", err)
	}

	b2 := New(time.Hour*24, clock)
	if err := b2.Load(path); err != nil {
		t.Fatal(err)
	}
	if got := b2.Addrs("p"); len(got) != 1 || got[0] != a1 {
		t.Fatalf("old snapshot lost: %v", got)
	}

	// The next real Save cleans the leftover.
	b.rename = osRename
	if err := b.Save(path); err != nil {
		t.Fatal(err)
	}
	temps, err = filepath.Glob(path + tempInfix + "*")
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 0 {
		t.Fatalf("leftover temporary files: %v", temps)
	}
}

// A Save that fails must not move the saved expiry, or a retry would skip
// the save.
func TestFailedRenameKeepsNeedSave(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := New(time.Hour*24, func() time.Time { return now })
	addrs := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	if _, err := b.Observe("p", addrs, 0); err != nil {
		t.Fatal(err)
	}
	b.rename = func(string, string) error { return os.ErrPermission }
	if err := b.Save(filepath.Join(t.TempDir(), "book.json")); err == nil {
		t.Fatal("save succeeded")
	}
	need, err := b.Observe("p", addrs, 0)
	if err != nil || !need {
		t.Fatalf("after a failed save: needSave = %v, err = %v", need, err)
	}
}

// The file renamed over the snapshot is a fully written temp file
// with the snapshot's own prefix, in the snapshot's directory.
func TestSaveRenamesFullTempInSameDir(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := New(time.Hour, func() time.Time { return now })
	if _, err := b.Observe("p", []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 0); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "book.json")
	var from string
	var data []byte
	b.rename = func(o, n string) error {
		from = o
		var err error
		data, err = os.ReadFile(o)
		if err != nil {
			t.Errorf("read temp file: %v", err)
		}
		if n != path {
			t.Errorf("rename target %s, want %s", n, path)
		}
		return osRename(o, n)
	}
	if err := b.Save(path); err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(from) != filepath.Dir(path) || !strings.HasPrefix(filepath.Base(from), "book.json.addrbook-tmp-") {
		t.Fatalf("temp file %s", from)
	}
	final, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || string(data) != string(final) {
		t.Fatalf("temp content %q, final %q", data, final)
	}
}
