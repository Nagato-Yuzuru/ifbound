package macresolver

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// noVersion returns the entries without their Version. The tests in this
// file check Version.
func noVersion(entries []reconcile.ManagedEntry) []reconcile.ManagedEntry {
	out := slices.Clone(entries)
	for i := range out {
		out[i].Version = ""
	}
	return out
}

// version reads the Version of the one entry in the directory.
func (f fixture) version(t *testing.T) string {
	t.Helper()
	st := f.read(t)
	if len(st.Entries) != 1 || st.Entries[0].Version == "" {
		t.Fatalf("entries = %+v, want one entry with a version", st.Entries)
	}
	return st.Entries[0].Version
}

func TestVersionStaysWithoutWrite(t *testing.T) {
	f := newFixture(t)
	f.write(t, "example.test", listen)
	v := f.version(t)
	f.clock.t = f.clock.t.Add(time.Hour)
	if got := f.version(t); got != v {
		t.Errorf("version after a second Read = %q, want %q", got, v)
	}
	// Write skips the identical content, so the entry does not change.
	f.write(t, "example.test", listen)
	if got := f.version(t); got != v {
		t.Errorf("version after an identical Write = %q, want %q", got, v)
	}
}

// Writes in the same clock tick give the same modification time and the
// same size. The new inode of each write still gives a new version.
func TestVersionChangesOnWriteInSameTick(t *testing.T) {
	f := newFixture(t)
	f.write(t, "example.test", listen)
	v1 := f.version(t)
	f.write(t, "example.test", netip.MustParseAddrPort("127.0.0.1:10054"))
	v2 := f.version(t)
	f.write(t, "example.test", listen)
	v3 := f.version(t)
	if v1 == v2 || v2 == v3 || v1 == v3 {
		t.Errorf("versions = %q, %q, %q; want three different versions", v1, v2, v3)
	}
}

// Another process rewrites the entry with the same content.
func TestVersionChangesOnForeignRewrite(t *testing.T) {
	tests := map[string]func(t *testing.T, path string, data []byte){
		"in place": func(t *testing.T, path string, data []byte) {
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		// The new file gets the old modification time, so only the inode
		// tells the files apart.
		"rename": func(t *testing.T, path string, data []byte) {
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			tmp := path + ".new"
			if err := os.WriteFile(tmp, data, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(tmp, fi.ModTime(), fi.ModTime()); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tmp, path); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, rewrite := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.write(t, "example.test", listen)
			v := f.version(t)
			path := filepath.Join(f.dir, "example.test")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			rewrite(t, path, data)
			if got := f.content(t, "example.test"); got != string(data) {
				t.Fatalf("content changed to %q", got)
			}
			if got := f.version(t); got == v {
				t.Errorf("version after a rewrite = %q, want a new version", got)
			}
		})
	}
}
