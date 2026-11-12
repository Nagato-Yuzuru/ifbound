package addrstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrbook"
	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

const retain = time.Hour

var (
	t0          = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	errInjected = errors.New("injected")
)

// bound is the durable bound of a record written at at with ttl 0:
// what a load gives for that answer.
func bound(at time.Time) time.Time {
	return at.Truncate(time.Minute).Add(renewAfter + retain)
}

// syncs is the sync function of a test Store. It counts the syncs of
// segment files and of the directory, and the test can fail them or
// hold them at a step. Each fsync of the Store goes through it.
type syncs struct {
	mu        sync.Mutex
	files     int
	dirs      int
	fail      error
	beforeOne func() // when set, runs before a file sync; it can block
}

func (c *syncs) sync(f *os.File) error {
	c.mu.Lock()
	isDir := filepath.Base(f.Name()) == "."
	if isDir {
		c.dirs++
	} else {
		c.files++
	}
	before, fail := c.beforeOne, c.fail
	c.mu.Unlock()
	if before != nil && !isDir {
		before()
	}
	if fail != nil {
		return fail
	}
	return f.Sync()
}

func (c *syncs) count() (files, dirs int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.files, c.dirs
}

func (c *syncs) set(f func(c *syncs)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(c)
}

func bookDir(t *testing.T) string { return filepath.Join(t.TempDir(), "addrbook") }

// openCounted opens a Store with a counting sync function. The counts
// start after Open.
func openCounted(t *testing.T, path, legacy string) (*Store, *syncs) {
	t.Helper()
	c := &syncs{}
	s, err := open(path, legacy, retain, c.sync)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() }) //nolint:errcheck // a second Close after the test closed it returns the same result
	c.set(func(c *syncs) { c.files, c.dirs = 0, 0 })
	return s, c
}

func addr(s string) blockable.Addr {
	a, ok := blockable.New(netipMust(s))
	if !ok {
		panic("refused test address " + s)
	}
	return a
}

func addrs(ss ...string) []blockable.Addr {
	out := make([]blockable.Addr, len(ss))
	for i, s := range ss {
		out[i] = addr(s)
	}
	return out
}

func names(ns ...policy.Name) []policy.Name { return ns }

// record touches and commits one answer, as the daemon does for a report.
func record(t *testing.T, s *Store, name policy.Name, ttl time.Duration, at time.Time, as ...string) {
	t.Helper()
	p, err := s.Touch(names(name), addrs(as...), ttl, at)
	if err != nil {
		t.Fatalf("Touch: %v", err)
	}
	if err := s.Commit(context.Background(), p); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

// latestFacts returns the latest facts that the Store sent.
func latestFacts(t *testing.T, s *Store) BookFacts {
	t.Helper()
	select {
	case f := <-s.Facts():
		return f
	default:
		t.Fatal("no facts")
		return BookFacts{}
	}
}

// reopen closes s and opens the book again with retain r.
func reopen(t *testing.T, s *Store, path string, r time.Duration) *Store {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s2, err := Open(path, "", r)
	if err != nil {
		t.Fatalf("Open again: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() }) //nolint:errcheck // a second Close returns the same result
	return s2
}

func strs(as []blockable.Addr) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}

func segments(t *testing.T, path string) []string {
	t.Helper()
	ents, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), segSuffix) {
			out = append(out, e.Name())
		}
	}
	return out
}

func commitOne(s *Store, name policy.Name, a string) error {
	p, err := s.Touch(names(name), addrs(a), 0, t0)
	if err != nil {
		return err
	}
	return s.Commit(context.Background(), p)
}

// runGroup holds the committer in the sync of a first report, lets each
// of waiters start and block, sets fail for the next syncs, and then
// releases the committer. It returns the errors of the waiters and the
// error of the first report. Call it inside a synctest bubble. It first
// commits 192.0.2.1 of web, and resets the counts.
func runGroup(s *Store, c *syncs, fail error, waiters []func() error) (group []error, first error) {
	// A first append starts the segment, so that the held report and the
	// group then do only file syncs.
	if err := commitOne(s, "web", "192.0.2.1"); err != nil {
		return nil, err
	}
	c.set(func(c *syncs) { c.files, c.dirs = 0, 0 })
	entered, release := make(chan struct{}), make(chan struct{})
	c.set(func(c *syncs) {
		c.beforeOne = func() { entered <- struct{}{}; <-release }
	})
	firstErr := make(chan error, 1)
	go func() { firstErr <- commitOne(s, "web", "192.0.2.2") }()
	<-entered // the committer holds the first sync
	c.set(func(c *syncs) { c.beforeOne, c.fail = nil, fail })
	results := make(chan error, len(waiters))
	for _, w := range waiters {
		go func() { results <- w() }()
	}
	synctest.Wait() // every waiter blocks in its send to the committer
	close(release)
	first = <-firstErr
	for range waiters {
		group = append(group, <-results)
	}
	return group, first
}

func newAddressWaiters(s *Store, n int) []func() error {
	var ws []func() error
	for i := range n {
		ws = append(ws, func() error { return commitOne(s, "web", fmt.Sprintf("192.0.2.%d", 10+i)) })
	}
	return ws
}

// The reports that wait while the committer is busy share one sync and
// one result.
func TestWaitingReportsShareOneSync(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, c := openCounted(t, bookDir(t), "")
		group, first := runGroup(s, c, nil, newAddressWaiters(s, 5))
		if first != nil {
			t.Fatalf("first report: %v", first)
		}
		for i, err := range group {
			if err != nil {
				t.Errorf("waiter %d: %v", i, err)
			}
		}
		// One file sync for the held report, one for the group.
		if files, dirs := c.count(); files != 2 || dirs != 0 {
			t.Errorf("syncs = %d file, %d directory; want 2, 0", files, dirs)
		}
		if got := len(s.Addrs("web")); got != 7 {
			t.Errorf("web has %d addresses, want 7", got)
		}
	})
}

// A failed sync fails each member of its group, and the index stays as
// before. The next commit starts a new segment.
func TestFailedSyncFailsTheGroupAndChangesNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := bookDir(t)
		s, c := openCounted(t, path, "")
		group, first := runGroup(s, c, errInjected, newAddressWaiters(s, 3))
		if first != nil {
			t.Fatalf("first report: %v", first)
		}
		for i, err := range group {
			if !errors.Is(err, errInjected) {
				t.Errorf("waiter %d = %v, want the injected error", i, err)
			}
		}
		if got := strs(s.Addrs("web")); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2"}) {
			t.Errorf("web = %v, want only the reports before the group", got)
		}
		c.set(func(c *syncs) { c.fail = nil })
		if err := commitOne(s, "web", "192.0.2.10"); err != nil {
			t.Fatalf("commit after the failure: %v", err)
		}
		if got := len(segments(t, path)); got != 2 {
			t.Errorf("%d segments, want 2: a failed append starts a new one", got)
		}
	})
}

// An entry is in the index only after its sync returned.
func TestEntryIsInTheIndexOnlyAfterItsSync(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, c := openCounted(t, bookDir(t), "")
		entered, release := make(chan struct{}), make(chan struct{})
		c.set(func(c *syncs) { c.beforeOne = func() { entered <- struct{}{}; <-release } })
		done := make(chan error, 1)
		go func() { done <- commitOne(s, "web", "192.0.2.1") }()
		<-entered
		if got := s.Addrs("web"); len(got) != 0 {
			t.Errorf("web = %v during the sync, want nothing", strs(got))
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if got := strs(s.Addrs("web")); !slices.Equal(got, []string{"192.0.2.1"}) {
			t.Errorf("web = %v after the sync, want [192.0.2.1]", got)
		}
	})
}

// A new address needs one file sync. A refresh that its record covers
// needs none; a refresh past it needs one.
func TestSyncCounts(t *testing.T) {
	edge := bound(t0).Add(-retain) // the latest answer whose expiry the record covers
	steps := []struct {
		name string
		at   time.Time
		as   []string
		want int
	}{
		{"new address", t0, []string{"192.0.2.1"}, 1},
		{"refresh at the bound", edge, []string{"192.0.2.1"}, 0},
		{"refresh past the bound", edge.Add(time.Nanosecond), []string{"192.0.2.1"}, 1},
		{"two new addresses and a covered one", edge, []string{"192.0.2.1", "192.0.2.2", "2001:db8::1"}, 1},
	}
	s, c := openCounted(t, bookDir(t), "")
	for _, st := range steps {
		before, _ := c.count()
		record(t, s, "web", 0, st.at, st.as...)
		if files, _ := c.count(); files-before != st.want {
			t.Errorf("%s: %d file syncs, want %d", st.name, files-before, st.want)
		}
	}
}

// A load keeps each acknowledged lease: the expiry after the load is not
// earlier than in memory before it, and at most renewAfter and a minute
// later.
func TestReopenKeepsEachAcknowledgedLease(t *testing.T) {
	path := bookDir(t)
	s, _ := openCounted(t, path, "")
	record(t, s, "web", 0, t0.Add(30*time.Second), "192.0.2.1")
	record(t, s, "web", 3*time.Hour, t0, "2001:db8::1")
	record(t, s, "ads", 0, t0, "192.0.2.1")
	before := latestFacts(t, s)
	s = reopen(t, s, path, retain)
	after := latestFacts(t, s)
	if !sameCounts(before.Counts, after.Counts) {
		t.Errorf("counts after the load = %v, want %v", after.Counts, before.Counts)
	}
	if lo, hi := before.NextExpiry, before.NextExpiry.Add(renewAfter+time.Minute); after.NextExpiry.Before(lo) || after.NextExpiry.After(hi) {
		t.Errorf("NextExpiry after the load = %v, want in [%v, %v]", after.NextExpiry, lo, hi)
	}
	if got := strs(s.Addrs("ads")); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("ads = %v, want [192.0.2.1]", got)
	}
}

func sameCounts[K comparable, V comparable](a, b map[K]V) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// Expire and Prune change only the index: a load brings the entries
// back, and the owner removes them again.
func TestRemovalsAreNotRecorded(t *testing.T) {
	path := bookDir(t)
	s, c := openCounted(t, path, "")
	record(t, s, "web", 0, t0, "192.0.2.1")
	record(t, s, "gone", 0, t0, "192.0.2.9")
	files, _ := c.count()
	if n, err := s.Apply(context.Background(), Prune{Keep: names("web")}); err != nil || n != 1 {
		t.Fatalf("Prune = %d, %v; want 1, nil", n, err)
	}
	if n, err := s.Apply(context.Background(), Expire{At: t0.Add(2 * retain)}); err != nil || n != 1 {
		t.Fatalf("Expire = %d, %v; want 1, nil", n, err)
	}
	if got, _ := c.count(); got != files {
		t.Errorf("the removals made %d syncs, want 0", got-files)
	}
	s = reopen(t, s, path, retain)
	if len(s.Addrs("gone")) != 1 || len(s.Addrs("web")) != 1 {
		t.Errorf("after the load: web %v, gone %v; want both back", strs(s.Addrs("web")), strs(s.Addrs("gone")))
	}
}

// Expire removes the entries that expired, and the segments whose
// records give no entry that is still kept.
func TestExpireRemovesEntriesAndOldSegments(t *testing.T) {
	path := bookDir(t)
	s, _ := openCounted(t, path, "")
	record(t, s, "web", 0, t0, "192.0.2.1")
	later := t0.Add(72 * time.Hour)
	record(t, s, "web", 0, later, "192.0.2.2")
	if got := len(segments(t, path)); got != 2 {
		t.Fatalf("%d segments, want one for each day", got)
	}
	n, err := s.Apply(context.Background(), Expire{At: bound(t0).Add(time.Nanosecond)})
	if err != nil || n != 1 {
		t.Fatalf("Expire = %d, %v; want 1, nil", n, err)
	}
	if got := segments(t, path); len(got) != 1 || !strings.HasPrefix(got[0], "2026-01-04.") {
		t.Errorf("segments = %v, want only the one of 2026-01-04", got)
	}
	s = reopen(t, s, path, retain)
	if got := strs(s.Addrs("web")); !slices.Equal(got, []string{"192.0.2.2"}) {
		t.Errorf("web after the load = %v, want [192.0.2.2]", got)
	}
}

// A refresh at the same time as Expire either keeps its entry or asks for
// a commit. It never reports a known entry that Expire then removes. The
// test does not force an order: the scheduler picks one in each round,
// so a round can miss the race of the two compare-and-swaps on one slot.
// The race detector checks the rounds.
func TestConcurrentRefreshAndExpireNeverLoseAKnownEntry(t *testing.T) {
	s, _ := openCounted(t, bookDir(t), "")
	for i := range 50 {
		a := fmt.Sprintf("192.0.2.%d", 1+i)
		record(t, s, "web", 0, t0, a)
		var p Pending
		var wg sync.WaitGroup
		wg.Go(func() {
			var err error
			if p, err = s.Touch(names("web"), addrs(a), 0, t0.Add(time.Minute)); err != nil {
				t.Errorf("Touch: %v", err)
			}
		})
		wg.Go(func() {
			if _, err := s.Apply(context.Background(), Expire{At: t0.Add(retain + time.Nanosecond)}); err != nil {
				t.Errorf("Expire: %v", err)
			}
		})
		wg.Wait()
		if p.Empty() && !slices.Contains(s.Addrs("web"), addr(a)) {
			t.Fatalf("%s: Touch found it known, but Expire removed it", a)
		}
	}
}

// Adopt writes only the addresses that the book does not hold, so the
// adoption at each start does not move a known expiry.
func TestAdoptWritesOnlyNewAddresses(t *testing.T) {
	s, _ := openCounted(t, bookDir(t), "")
	record(t, s, "web", 0, t0, "192.0.2.1")
	known := latestFacts(t, s).NextExpiry
	found := map[policy.Name][]blockable.Addr{"web": addrs("192.0.2.1", "192.0.2.2")}
	n, err := s.Apply(context.Background(), Adopt{Found: found, At: t0.Add(10 * time.Hour)})
	if err != nil || n != 1 {
		t.Fatalf("Adopt = %d, %v; want 1, nil", n, err)
	}
	if got := latestFacts(t, s).NextExpiry; !got.Equal(known) {
		t.Errorf("NextExpiry = %v, want the known expiry %v", got, known)
	}
	if n, err := s.Apply(context.Background(), Adopt{Found: found, At: t0.Add(20 * time.Hour)}); err != nil || n != 0 {
		t.Errorf("Adopt again = %d, %v; want 0, nil", n, err)
	}
}

// A load with a larger retain keeps each entry for that retain.
func TestLoadAppliesTheLargerRetain(t *testing.T) {
	path := bookDir(t)
	s, _ := openCounted(t, path, "")
	record(t, s, "web", 0, t0, "192.0.2.1")
	s = reopen(t, s, path, 3*24*time.Hour)
	want := t0.Add(renewAfter + 3*24*time.Hour + time.Nanosecond)
	if got := latestFacts(t, s).NextExpiry; !got.Equal(want) {
		t.Errorf("NextExpiry = %v, want %v", got, want)
	}
}

func TestBadInputIsRefused(t *testing.T) {
	s, c := openCounted(t, bookDir(t), "")
	long := policy.Name(strings.Repeat("p", policy.MaxNameLen+1))
	tests := []struct {
		name  string
		names []policy.Name
		as    []blockable.Addr
		ttl   time.Duration
		at    time.Time
		want  error
	}{
		{"empty policy", names(""), addrs("192.0.2.1"), 0, t0, ErrEmptyPolicy},
		{"long policy", names(long), addrs("192.0.2.1"), 0, t0, ErrLongPolicy},
		{"negative ttl", names("web"), addrs("192.0.2.1"), -1, t0, ErrNegativeTTL},
		{"zero address", names("web"), []blockable.Addr{{}}, 0, t0, blockable.ErrZero},
		{"time before the epoch", names("web"), addrs("192.0.2.1"), 0, time.Unix(-60, 0), ErrTimeRange},
	}
	for _, tt := range tests {
		if _, err := s.Touch(tt.names, tt.as, tt.ttl, tt.at); !errors.Is(err, tt.want) {
			t.Errorf("%s: Touch = %v, want %v", tt.name, err, tt.want)
		}
	}
	if _, err := s.Apply(context.Background(), Adopt{Found: map[policy.Name][]blockable.Addr{long: addrs("192.0.2.1")}, At: t0}); !errors.Is(err, ErrLongPolicy) {
		t.Errorf("Adopt with a long policy = %v, want ErrLongPolicy", err)
	}
	if files, _ := c.count(); files != 0 {
		t.Errorf("refused input made %d syncs", files)
	}
}

func TestRequestAfterCloseFails(t *testing.T) {
	s, err := Open(bookDir(t), "", retain)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	p, err := s.Touch(names("web"), addrs("192.0.2.1"), 0, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(context.Background(), p); !errors.Is(err, ErrClosed) {
		t.Errorf("Commit after Close = %v, want ErrClosed", err)
	}
	if _, err := s.Apply(context.Background(), Expire{At: t0}); !errors.Is(err, ErrClosed) {
		t.Errorf("Expire after Close = %v, want ErrClosed", err)
	}
}

// Only one Store at a time holds a book.
func TestSecondOpenIsLocked(t *testing.T) {
	path := bookDir(t)
	s, _ := openCounted(t, path, "")
	if _, err := Open(path, "", retain); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open = %v, want ErrLocked", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path, "", retain)
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	_ = s2.Close() //nolint:errcheck // the test checks only that the Open works
}

// A path that is a file or a symlink does not open, and Open creates
// nothing at the target of a link.
func TestOpenRefusesAFileAndASymlink(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(file, "", retain); !errors.Is(err, ErrBadPath) {
		t.Errorf("Open(file) = %v, want ErrBadPath", err)
	}
	target := filepath.Join(dir, "missing")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, "", retain); !errors.Is(err, ErrBadPath) {
		t.Errorf("Open(dangling symlink) = %v, want ErrBadPath", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the link target exists after the refused Open: %v", err)
	}
}

// Read gives what a load gives, and works while a Store holds the book.
func TestReadSeesTheDurableEntries(t *testing.T) {
	path := bookDir(t)
	s, _ := openCounted(t, path, "")
	record(t, s, "web", 0, t0, "192.0.2.1")
	record(t, s, "ads", 0, t0, "2001:db8::1")
	got, err := Read(path, retain)
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{
		{"ads", addr("2001:db8::1"), bound(t0)},
		{"web", addr("192.0.2.1"), bound(t0)},
	}
	if !slices.EqualFunc(got, want, func(a, b Entry) bool {
		return a.Policy == b.Policy && a.Addr == b.Addr && a.Expiry.Equal(b.Expiry)
	}) {
		t.Errorf("Read = %v, want %v", got, want)
	}
	if got, err := Read(filepath.Join(t.TempDir(), "none"), retain); err != nil || len(got) != 0 {
		t.Errorf("Read of a missing book = %v, %v; want nothing", got, err)
	}
}

// ---- import of the JSON snapshot ----

func writeJSON(t *testing.T, path string, entries ...string) {
	t.Helper()
	doc := `{"version":1,"entries":[`
	for i, e := range entries {
		if i > 0 {
			doc += ","
		}
		doc += e
	}
	doc += "]}"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}

func jsonEntry(p, a string, exp time.Duration) string {
	return fmt.Sprintf(`{"policy":%q,"addr":%q,"last_seen_unix_nano":%d,"ttl_nano":0,"expiry_unix_nano":%d}`,
		p, a, t0.UnixNano(), t0.Add(exp).UnixNano())
}

// Open imports the JSON snapshot, skips the refused addresses, and
// removes the snapshot.
func TestOpenImportsTheJSONSnapshot(t *testing.T) {
	dir := t.TempDir()
	path, legacy := filepath.Join(dir, "addrbook"), filepath.Join(dir, "addrbook.json")
	writeJSON(t, legacy,
		jsonEntry("web", "192.0.2.1", 2*time.Hour),
		jsonEntry("web", "127.0.0.1", 2*time.Hour),
		jsonEntry("ads", "0.0.0.0", 2*time.Hour),
		jsonEntry("ads", "2001:db8::1", retain))
	s, err := Open(path, legacy, retain)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() }) //nolint:errcheck // a second Close returns the same result
	if got := strs(s.Addrs("web")); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("web = %v, want [192.0.2.1]", got)
	}
	if got := strs(s.Addrs("ads")); !slices.Equal(got, []string{"2001:db8::1"}) {
		t.Errorf("ads = %v, want [2001:db8::1]", got)
	}
	if f := latestFacts(t, s); !f.NextExpiry.Equal(t0.Add(retain + time.Nanosecond)) {
		t.Errorf("NextExpiry = %v, want the stored expiry %v", f.NextExpiry, t0.Add(retain))
	}
	if _, err := os.Stat(legacy); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the imported snapshot is still there: %v", err)
	}
	entries, err := Read(path, retain)
	if err != nil || len(entries) != 2 {
		t.Errorf("Read = %v, %v; want the two imported entries", entries, err)
	}
}

// A JSON snapshot that does not decode is an Open error. Open leaves the
// snapshot as it is, and imports nothing.
func TestOpenRefusesACorruptJSONSnapshot(t *testing.T) {
	dir := t.TempDir()
	path, legacy := filepath.Join(dir, "addrbook"), filepath.Join(dir, "addrbook.json")
	if err := os.WriteFile(legacy, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, legacy, retain); !errors.Is(err, addrbook.ErrSnapshot) {
		t.Fatalf("Open with a corrupt snapshot = %v, want addrbook.ErrSnapshot", err)
	}
	if data, err := os.ReadFile(legacy); err != nil || string(data) != "not json" {
		t.Errorf("the corrupt snapshot changed: %q, %v", data, err)
	}
	writeJSON(t, legacy, jsonEntry("web", "192.0.2.1", retain))
	s, err := Open(path, legacy, retain)
	if err != nil {
		t.Fatalf("Open after the repair: %v", err)
	}
	defer s.Close() //nolint:errcheck // the test checks no write after this point
	if got := strs(s.Addrs("web")); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("web = %v, want [192.0.2.1]", got)
	}
}
