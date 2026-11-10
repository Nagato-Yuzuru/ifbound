package addrstore

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A crash at any step of a group commit leaves the old book or the new
// book, never a part of the group.
//
// bbolt commits in these steps: it writes the changed data pages in the
// order of their ids, syncs, writes one meta page, and syncs. The test
// takes the file before and after a commit of a group, and builds the
// file of a crash after each step: after each data page, inside a data
// page, inside the meta page, and after it. Each such file must open to
// the old or the new set of addresses.
func TestCrashInAGroupCommitLeavesTheOldOrTheNewBook(t *testing.T) {
	path := dbPath(t)
	s, _ := openCounted(t, path, "")
	record(t, s, "web", 0, t0, "192.0.2.1")
	old := readBytes(t, path)
	// One group: a refresh beyond the slack, and new addresses in two
	// policies.
	p, err := s.Touch(names("web", "ads"), addrs("192.0.2.1", "192.0.2.2", "2001:db8::1"), 0, t0.Add(retain))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	pageSize := s.db.Info().PageSize
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	newer := readBytes(t, path)

	oldBook := map[string][]string{"web": {"192.0.2.1"}}
	newBook := map[string][]string{"web": {"192.0.2.1", "192.0.2.2", "2001:db8::1"}, "ads": {"192.0.2.1", "192.0.2.2", "2001:db8::1"}}
	data, meta := changedPages(old, newer, pageSize)
	if len(data) == 0 || meta < 0 {
		t.Fatalf("the commit changed data pages %v and meta page %d; want both", data, meta)
	}

	// The file grows before the writes: its new part is zero.
	image := make([]byte, max(len(old), len(newer)))
	copy(image, old)
	crash := func(step string, want map[string][]string) {
		t.Helper()
		if got := bookAt(t, image); !equalBooks(got, want) {
			t.Errorf("crash %s: book %v, want %v", step, got, want)
		}
	}
	page := func(id int) (int, int) { return id * pageSize, min((id+1)*pageSize, len(newer)) }
	crash("before the first write", oldBook)
	for i, id := range data {
		from, to := page(id)
		half := from + (to-from)/2
		copy(image[from:half], newer[from:half])
		crash(fmt.Sprintf("inside data page %d of %d", i+1, len(data)), oldBook)
		copy(image[half:to], newer[half:to])
		crash(fmt.Sprintf("after data page %d of %d", i+1, len(data)), oldBook)
	}
	from, to := page(meta)
	// The checksum of the meta page covers its first bytes, so a torn
	// write there is a broken meta page.
	copy(image[from:from+32], newer[from:from+32])
	crash("inside the meta page", oldBook)
	copy(image[from:to], newer[from:to])
	crash("after the meta page", newBook)
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// changedPages returns the ids of the data pages that differ between old
// and newer, in ascending order, and the id of the meta page (0 or 1)
// that differs, or -1.
func changedPages(old, newer []byte, pageSize int) (data []int, meta int) {
	meta = -1
	for id := 0; id*pageSize < len(newer); id++ {
		from, to := id*pageSize, min((id+1)*pageSize, len(newer))
		var before []byte
		if from < len(old) {
			before = old[from:min(to, len(old))]
		}
		if slices.Equal(before, newer[from:to]) {
			continue
		}
		if id < 2 {
			meta = id
		} else {
			data = append(data, id)
		}
	}
	return data, meta
}

// bookAt opens a copy of image and returns the addresses of each policy.
func bookAt(t *testing.T, image []byte) map[string][]string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "crash.db")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, "", retain)
	if err != nil {
		t.Fatalf("Open after the crash: %v", err)
		return nil
	}
	defer s.Close() //nolint:errcheck // the test only reads this copy
	out := map[string][]string{}
	for name := range latestFacts(t, s).Counts {
		out[string(name)] = strs(s.Addrs(name))
	}
	return out
}

func equalBooks(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !slices.Equal(v, b[k]) {
			return false
		}
	}
	return true
}
