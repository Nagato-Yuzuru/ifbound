package addrstore

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"go.etcd.io/bbolt"
)

// The offsets of two fields in the header of a bbolt page: the flags
// (the page type) and the number of elements, each a uint16.
const (
	flagsAt = 8
	countAt = 10
)

// A damaged page header makes bbolt panic, read outside the file, or read
// entries that are not there. Open returns ErrCorrupt for a book with such
// a page, and the process lives.
func TestOpenOfABookWithADamagedPageReturnsErrCorrupt(t *testing.T) {
	path := dbPath(t)
	s, _ := openCounted(t, path, "")
	record(t, s, "web", 0, t0, "192.0.2.1", "192.0.2.2")
	record(t, s, "ads", 0, t0, "192.0.2.3")
	pageSize := s.db.Info().PageSize
	used := usedPages(t, s.db)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	good := readBytes(t, path)

	type damage struct {
		name  string
		field int
		value [2]byte
	}
	damages := []damage{
		{"flags", flagsAt, [2]byte{0xff, 0xff}},
		{"element count", countAt, [2]byte{0xff, 0x7f}},
	}
	// A freelist count of one entry for each page of the file names a
	// page two times, or a page outside the file. The entries stay inside
	// the freelist page, so bbolt reads them without a fault.
	var pageCount [2]byte
	binary.NativeEndian.PutUint16(pageCount[:], uint16(len(good)/pageSize))
	freelistDamage := damage{"element count of one entry for each page", countAt, pageCount}
	for id, typ := range used {
		damages := damages
		if typ == "freelist" {
			damages = append(slices.Clip(damages), freelistDamage)
		}
		for _, d := range damages {
			t.Run(fmt.Sprintf("%s of %s page %d", d.name, typ, id), func(t *testing.T) {
				image := slices.Clone(good)
				copy(image[id*pageSize+d.field:], d.value[:])
				openDamaged(t, image)
			})
		}
	}
}

// openDamaged writes image to a new file, and checks that two Opens of
// that file return ErrCorrupt.
func openDamaged(t *testing.T, image []byte) {
	t.Helper()
	bad := filepath.Join(t.TempDir(), "bad.db")
	if err := os.WriteFile(bad, image, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(bad, "", retain)
	if err == nil {
		_ = s.Close() //nolint:errcheck // the test failed already
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Errorf("Open = %v, want ErrCorrupt", err)
	}
	// Open unlocked the file: a new Open does not wait for its lock. On
	// Linux, the lock stays after a close while a map of the file exists.
	if _, err := Open(bad, "", retain); !errors.Is(err, ErrCorrupt) {
		t.Errorf("second Open = %v, want ErrCorrupt", err)
	}
}

// usedPages returns the type of each page after the two meta pages that
// the book uses: the freelist, and the branch and leaf pages.
func usedPages(t *testing.T, db *bbolt.DB) map[int]string {
	t.Helper()
	used := map[int]string{}
	err := db.View(func(tx *bbolt.Tx) error {
		for id := 2; ; id++ {
			info, err := tx.Page(id)
			if err != nil {
				return err
			}
			if info == nil {
				return nil
			}
			if info.Type != "free" {
				used[id] = info.Type
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"freelist", "leaf"} {
		if !slices.Contains(slices.Collect(maps.Values(used)), want) {
			t.Fatalf("the book has the pages %v, want a %s page", used, want)
		}
	}
	return used
}

// A page that is damaged after Open fails the commit that reads it with
// ErrCorrupt, and the process lives. The index does not change.
func TestCommitThatReadsADamagedPageReturnsErrCorrupt(t *testing.T) {
	path := dbPath(t)
	s, _ := openCounted(t, path, "")
	record(t, s, "web", 0, t0, "192.0.2.1")
	pageSize := s.db.Info().PageSize
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	for id, typ := range usedPages(t, s.db) {
		if typ != "leaf" {
			continue
		}
		if _, err := f.WriteAt([]byte{0xff, 0x7f}, int64(id*pageSize+countAt)); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	p, err := s.Touch(names("web"), addrs("192.0.2.2"), 0, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(t.Context(), p); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Commit = %v, want ErrCorrupt", err)
	}
	if got := strs(s.Addrs("web")); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("web = %v, want only the committed 192.0.2.1", got)
	}
}
