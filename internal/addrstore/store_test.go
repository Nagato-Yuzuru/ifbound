package addrstore

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"go.etcd.io/bbolt"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrbook"
	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

const retain = time.Hour

// slack is the save slack for retain: min(1h, retain/2).
const slack = 30 * time.Minute

var (
	t0          = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	errInjected = errors.New("injected")
)

// commits is the transaction function of a test Store. It counts the
// commits, and the test can fail them or hold them at a step. Every
// fsync of the Store is in a commit, so a count of 0 means no fsync.
type commits struct {
	mu   sync.Mutex
	n    int
	fail error
	// before and after, when set, run around the write of the file. They
	// can block to hold the committer at that step.
	before, after func()
}

func (c *commits) update(db *bbolt.DB, fn func(*bbolt.Tx) error) error {
	c.mu.Lock()
	c.n++
	before := c.before
	c.mu.Unlock()
	if before != nil {
		before()
	}
	c.mu.Lock()
	fail, after := c.fail, c.after
	c.mu.Unlock()
	if fail != nil {
		return fail
	}
	err := db.Update(fn)
	if after != nil {
		after()
	}
	return err
}

func (c *commits) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func (c *commits) set(f func(c *commits)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(c)
}

func dbPath(t *testing.T) string { return filepath.Join(t.TempDir(), "addrbook.db") }

// openCounted opens a Store with a counting transaction function. The
// count starts after Open.
func openCounted(t *testing.T, path, legacy string) (*Store, *commits) {
	t.Helper()
	c := &commits{}
	s, err := open(path, legacy, retain, c.update)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() }) //nolint:errcheck // a second Close after the test closed it returns the same result
	c.set(func(c *commits) { c.n = 0 })
	return s, c
}

func addr(s string) blockable.Addr {
	a, ok := blockable.New(netip.MustParseAddr(s))
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
func record(t *testing.T, s *Store, name policy.Name, ttl time.Duration, at time.Time, as ...string) Pending {
	t.Helper()
	p, err := s.Touch(names(name), addrs(as...), ttl, at)
	if err != nil {
		t.Fatalf("Touch: %v", err)
	}
	if err := s.Commit(context.Background(), p); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return p
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

// reopen closes s and opens the file again with retain r.
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

// runGroup holds the committer in the commit of a first report, lets
// each of waiters start and block, sets fail for the next commits, and
// then releases the committer. It returns the error of the first report
// and the errors of the waiters. Call it inside a synctest bubble.
//
// It returns the errors of the waiters first, and then the error of the
// first report.
func runGroup(s *Store, c *commits, fail error, waiters []func() error) (group []error, first error) {
	entered, release := make(chan struct{}), make(chan struct{})
	c.set(func(c *commits) {
		c.before = func() { entered <- struct{}{}; <-release }
	})
	firstErr := make(chan error, 1)
	go func() { firstErr <- commitOne(s, "web", "192.0.2.2") }()
	<-entered // the committer holds the first commit
	c.set(func(c *commits) { c.before, c.fail = nil, fail })
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

// A new address needs one commit. The group of reports that wait while
// the committer is busy shares one commit and one result.
func TestWaitingReportsShareOneCommit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, c := openCounted(t, dbPath(t), "")
		const n = 5
		group, first := runGroup(s, c, nil, newAddressWaiters(s, n))
		if first != nil {
			t.Fatalf("first Commit: %v", first)
		}
		for _, err := range group {
			if err != nil {
				t.Errorf("Commit of the group: %v", err)
			}
		}
		if got := c.count(); got != 2 {
			t.Errorf("commits = %d, want 2: one for the first report, one for the group of %d", got, n)
		}
		if got := len(s.Addrs("web")); got != 1+n {
			t.Errorf("web has %d addresses, want %d", got, 1+n)
		}
	})
}

// A failed commit fails every waiter of its group and leaves the index
// and the file as before.
func TestFailedCommitFailsTheGroupAndChangesNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := dbPath(t)
		s, c := openCounted(t, path, "")
		record(t, s, "web", 0, t0, "192.0.2.1")
		// One waiter refreshes the known address beyond the slack, the
		// others bring new addresses.
		refresh := func() error {
			p, err := s.Touch(names("web"), addrs("192.0.2.1"), 0, t0.Add(slack+time.Second))
			if err != nil {
				return err
			}
			return s.Commit(context.Background(), p)
		}
		group, first := runGroup(s, c, errInjected, append(newAddressWaiters(s, 2), refresh))
		if !errors.Is(first, errInjected) {
			t.Fatalf("first Commit = %v, want the injected error", first)
		}
		for _, err := range group {
			if !errors.Is(err, errInjected) {
				t.Errorf("Commit of the group = %v, want the injected error", err)
			}
		}
		checkOnlyTheOldEntry(t, s, c, path)
	})
}

// checkOnlyTheOldEntry checks that web holds only 192.0.2.1 with the
// expiry of its commit at t0, in memory and on disk, while the commits
// still fail.
func checkOnlyTheOldEntry(t *testing.T, s *Store, c *commits, path string) {
	t.Helper()
	if got := strs(s.Addrs("web")); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("web = %v, want only the committed 192.0.2.1", got)
	}
	// The expiry in memory did not move: Expire just after the old
	// expiry removes the entry. The delete fails, but the removal in
	// memory is final and counts.
	if n, err := s.Apply(context.Background(), Expire{At: t0.Add(retain + time.Nanosecond)}); n != 1 || !errors.Is(err, errInjected) {
		t.Errorf("Expire after the old expiry = %d, %v; want 1 and the injected error", n, err)
	}
	if got := s.Addrs("web"); len(got) != 0 {
		t.Errorf("web after Expire = %v, want none", got)
	}
	c.set(func(c *commits) { c.fail = nil })
	s2 := reopen(t, s, path, retain)
	if got := strs(s2.Addrs("web")); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("web on disk = %v, want only 192.0.2.1", got)
	}
	if f := latestFacts(t, s2); !f.NextExpiry.Equal(t0.Add(retain + time.Nanosecond)) {
		t.Errorf("NextExpiry on disk = %v, want the old expiry %v", f.NextExpiry, t0.Add(retain))
	}
}

func commitOne(s *Store, name policy.Name, a string) error {
	p, err := s.Touch(names(name), addrs(a), 0, t0)
	if err != nil {
		return err
	}
	return s.Commit(context.Background(), p)
}

// An entry is in the index only after its commit: while the committer
// holds a written transaction, a reader does not see the entry, and a
// Touch of it still needs a commit.
func TestEntryIsInTheIndexOnlyAfterItsCommit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, c := openCounted(t, dbPath(t), "")
		written, release := make(chan struct{}), make(chan struct{})
		c.set(func(c *commits) {
			c.after = func() { written <- struct{}{}; <-release }
		})
		done := make(chan error, 1)
		go func() { done <- commitOne(s, "web", "192.0.2.1") }()
		<-written // the transaction is on disk; the index is not changed yet

		if got := s.Addrs("web"); len(got) != 0 {
			t.Errorf("web = %v before the commit returned, want none", got)
		}
		if p, err := s.Touch(names("web"), addrs("192.0.2.1"), 0, t0); err != nil || p.Empty() {
			t.Errorf("Touch before the commit returned: Empty %v, err %v; want a Pending", p.Empty(), err)
		}

		c.set(func(c *commits) { c.after = nil })
		close(release)
		if err := <-done; err != nil {
			t.Fatalf("Commit: %v", err)
		}
		if got := strs(s.Addrs("web")); !slices.Equal(got, []string{"192.0.2.1"}) {
			t.Errorf("web = %v after the commit, want [192.0.2.1]", got)
		}
		if p, err := s.Touch(names("web"), addrs("192.0.2.1"), 0, t0); err != nil || !p.Empty() {
			t.Errorf("Touch after the commit: Empty %v, err %v; want an empty Pending", p.Empty(), err)
		}
	})
}

// The structural counts of the persist rule: a new address is one
// commit; a refresh inside the slack is none; a refresh beyond the slack
// is one.
func TestCommitCounts(t *testing.T) {
	s, c := openCounted(t, dbPath(t), "")
	steps := []struct {
		name    string
		at      time.Time
		as      []string
		commits int
	}{
		{"new address", t0, []string{"192.0.2.1"}, 1},
		{"same address again", t0, []string{"192.0.2.1"}, 0},
		{"refresh at the slack edge", t0.Add(slack), []string{"192.0.2.1"}, 0},
		{"refresh past the slack", t0.Add(slack + time.Nanosecond), []string{"192.0.2.1"}, 1},
		{"two new addresses and a known one", t0.Add(slack), []string{"192.0.2.1", "192.0.2.2", "2001:db8::1"}, 1},
	}
	for _, st := range steps {
		before := c.count()
		record(t, s, "web", 0, st.at, st.as...)
		if got := c.count() - before; got != st.commits {
			t.Errorf("%s: %d commits, want %d", st.name, got, st.commits)
		}
	}
}

// Refreshes inside the slack, in any order, give the same expiry, and
// Flush writes it with one commit.
func TestSlackRefreshesInAnyOrderGiveTheSameExpiry(t *testing.T) {
	ats := []time.Time{t0.Add(10 * time.Minute), t0.Add(25 * time.Minute), t0.Add(slack)}
	want := t0.Add(slack + retain + time.Nanosecond)
	for _, order := range [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			path := dbPath(t)
			s, c := openCounted(t, path, "")
			record(t, s, "web", 0, t0, "192.0.2.1")
			before := c.count()
			refreshAll(t, s, ats, order)
			if got := c.count() - before; got != 0 {
				t.Errorf("%d commits for refreshes inside the slack, want 0", got)
			}
			if _, err := s.Apply(context.Background(), Flush{}); err != nil {
				t.Fatalf("Flush: %v", err)
			}
			if got := c.count() - before; got != 1 {
				t.Errorf("%d commits for the Flush, want 1", got)
			}
			s2 := reopen(t, s, path, retain)
			if f := latestFacts(t, s2); !f.NextExpiry.Equal(want) {
				t.Errorf("NextExpiry after the Flush = %v, want %v", f.NextExpiry, want)
			}
		})
	}
}

// refreshAll touches 192.0.2.1 of web at each time of ats, started in
// the order of order, all at the same time. Each must be a refresh in
// memory.
func refreshAll(t *testing.T, s *Store, ats []time.Time, order []int) {
	t.Helper()
	var wg sync.WaitGroup
	for _, i := range order {
		wg.Go(func() {
			if p, err := s.Touch(names("web"), addrs("192.0.2.1"), 0, ats[i]); err != nil || !p.Empty() {
				t.Errorf("Touch at %v: Empty %v, err %v; want a refresh in memory", ats[i], p.Empty(), err)
			}
		})
	}
	wg.Wait()
}

// Without Flush, a refresh inside the slack stays in memory: a crash
// keeps the expiry on disk, which is at most the slack earlier. A Flush
// with nothing to write does no commit.
func TestCloseWithoutFlushKeepsTheDiskExpiry(t *testing.T) {
	path := dbPath(t)
	s, c := openCounted(t, path, "")
	record(t, s, "web", 0, t0, "192.0.2.1")
	record(t, s, "web", 0, t0.Add(slack), "192.0.2.1")
	s2 := reopen(t, s, path, retain)
	if f := latestFacts(t, s2); !f.NextExpiry.Equal(t0.Add(retain + time.Nanosecond)) {
		t.Errorf("NextExpiry = %v, want the expiry of the commit %v", f.NextExpiry, t0.Add(retain))
	}
	before := c.count()
	if _, err := s2.Apply(context.Background(), Flush{}); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := c.count() - before; got != 0 {
		t.Errorf("Flush with nothing to write: %d commits, want 0", got)
	}
}

// Expire removes an entry one nanosecond after its expiry, durably, and
// sends the new facts.
func TestExpireRemovesAfterTheExpiry(t *testing.T) {
	path := dbPath(t)
	s, _ := openCounted(t, path, "")
	record(t, s, "web", 0, t0, "192.0.2.1")
	record(t, s, "web", 2*time.Hour, t0, "192.0.2.2")
	if f := latestFacts(t, s); f.Counts["web"] != 2 || !f.NextExpiry.Equal(t0.Add(retain+time.Nanosecond)) {
		t.Errorf("facts = %+v, want 2 web addresses and the first expiry after %v", f, t0.Add(retain))
	}
	if n, err := s.Apply(context.Background(), Expire{At: t0.Add(retain)}); err != nil || n != 0 {
		t.Errorf("Expire at the expiry = %d, %v; want 0, nil", n, err)
	}
	if n, err := s.Apply(context.Background(), Expire{At: t0.Add(retain + time.Nanosecond)}); err != nil || n != 1 {
		t.Errorf("Expire after the expiry = %d, %v; want 1, nil", n, err)
	}
	if f := latestFacts(t, s); f.Counts["web"] != 1 || !f.NextExpiry.Equal(t0.Add(2*time.Hour+time.Nanosecond)) {
		t.Errorf("facts = %+v, want 1 web address that expires after %v", f, t0.Add(2*time.Hour))
	}
	s2 := reopen(t, s, path, retain)
	if got := strs(s2.Addrs("web")); !slices.Equal(got, []string{"192.0.2.2"}) {
		t.Errorf("web on disk = %v, want [192.0.2.2]", got)
	}
}

// Prune removes each policy that is not kept, durably.
func TestPruneRemovesThePoliciesNotKept(t *testing.T) {
	path := dbPath(t)
	s, c := openCounted(t, path, "")
	record(t, s, "web", 0, t0, "192.0.2.1")
	record(t, s, "gone", 0, t0, "192.0.2.1", "192.0.2.9")
	before := c.count()
	if n, err := s.Apply(context.Background(), Prune{Keep: names("web")}); err != nil || n != 2 {
		t.Errorf("Prune = %d, %v; want 2, nil", n, err)
	}
	if n, err := s.Apply(context.Background(), Prune{Keep: names("web")}); err != nil || n != 0 {
		t.Errorf("second Prune = %d, %v; want 0, nil", n, err)
	}
	if got := c.count() - before; got != 1 {
		t.Errorf("%d commits, want 1: a Prune with nothing to remove writes nothing", got)
	}
	s2 := reopen(t, s, path, retain)
	if got := s2.Addrs("gone"); len(got) != 0 {
		t.Errorf("gone on disk = %v, want none", got)
	}
	if got := strs(s2.Addrs("web")); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("web on disk = %v, want [192.0.2.1]", got)
	}
}

// A refresh that races with Expire either keeps its entry or asks for a
// commit. It never reports a known entry that Expire then removes.
func TestRefreshRacingExpireNeverLosesAKnownEntry(t *testing.T) {
	s, _ := openCounted(t, dbPath(t), "")
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

// A larger retain at Open raises each expiry to last_seen + max(ttl,
// retain).
func TestOpenRaisesExpiryWhenRetainGrew(t *testing.T) {
	path := dbPath(t)
	s, _ := openCounted(t, path, "")
	record(t, s, "web", 0, t0, "192.0.2.1")
	s2 := reopen(t, s, path, 3*time.Hour)
	if f := latestFacts(t, s2); !f.NextExpiry.Equal(t0.Add(3*time.Hour+time.Nanosecond)) || f.Retain != 3*time.Hour {
		t.Errorf("facts = %+v, want retain 3h and the first expiry after %v", f, t0.Add(3*time.Hour))
	}
}

// Touch and Adopt refuse bad input and change nothing.
func TestBadInputIsRefused(t *testing.T) {
	s, c := openCounted(t, dbPath(t), "")
	record(t, s, "web", 0, t0, "192.0.2.1")
	before := c.count()
	cases := []struct {
		name  string
		names []policy.Name
		as    []blockable.Addr
		ttl   time.Duration
		at    time.Time
		want  error
	}{
		{"empty policy", names("web", ""), addrs("192.0.2.2"), 0, t0, ErrEmptyPolicy},
		{"negative ttl", names("web"), addrs("192.0.2.2"), -time.Second, t0, ErrNegativeTTL},
		{"zero Addr", names("web"), []blockable.Addr{addr("192.0.2.2"), {}}, 0, t0, blockable.ErrZero},
		{"time out of range", names("web"), addrs("192.0.2.2"), 0, time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC), ErrTimeRange},
		{"expiry out of range", names("web"), addrs("192.0.2.2"), 0, time.Unix(0, 1<<63-1), ErrTimeRange},
	}
	for _, tt := range cases {
		if _, err := s.Touch(tt.names, tt.as, tt.ttl, tt.at); !errors.Is(err, tt.want) {
			t.Errorf("Touch with %s = %v, want %v", tt.name, err, tt.want)
		}
	}
	if _, err := s.Apply(context.Background(), Adopt{Found: map[policy.Name][]blockable.Addr{"web": {{}}}, At: t0}); !errors.Is(err, blockable.ErrZero) {
		t.Errorf("Adopt of the zero Addr = %v, want blockable.ErrZero", err)
	}
	if got := c.count() - before; got != 0 {
		t.Errorf("%d commits after refused input, want 0", got)
	}
	if got := strs(s.Addrs("web")); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("web = %v, want [192.0.2.1]", got)
	}
}

// Adopt commits each address with a fresh retain period, in one commit.
func TestAdoptCommitsEachAddressOnce(t *testing.T) {
	path := dbPath(t)
	s, c := openCounted(t, path, "")
	found := map[policy.Name][]blockable.Addr{"web": addrs("192.0.2.1", "192.0.2.2"), "ads": addrs("198.51.100.1")}
	if _, err := s.Apply(context.Background(), Adopt{Found: found, At: t0}); err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	if got := c.count(); got != 1 {
		t.Errorf("%d commits, want 1", got)
	}
	s2 := reopen(t, s, path, retain)
	if got := strs(s2.Addrs("web")); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Errorf("web on disk = %v", got)
	}
	if f := latestFacts(t, s2); f.Counts["ads"] != 1 || !f.NextExpiry.Equal(t0.Add(retain+time.Nanosecond)) {
		t.Errorf("facts on disk = %+v", f)
	}
}

// A request after Close gets ErrClosed.
func TestRequestAfterCloseFails(t *testing.T) {
	s, _ := openCounted(t, dbPath(t), "")
	p, err := s.Touch(names("web"), addrs("192.0.2.1"), 0, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Commit(context.Background(), p); !errors.Is(err, ErrClosed) {
		t.Errorf("Commit after Close = %v, want ErrClosed", err)
	}
	if _, err := s.Apply(context.Background(), Flush{}); !errors.Is(err, ErrClosed) {
		t.Errorf("Flush after Close = %v, want ErrClosed", err)
	}
}

func TestOpenRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.db")
	link := filepath.Join(dir, "addrbook.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, "", retain); !errors.Is(err, ErrBadPath) {
		t.Errorf("Open(symlink) = %v, want ErrBadPath", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the link target exists after the refused Open: %v", err)
	}
}

// A file with an unknown version does not open.
func TestOpenRefusesAnUnknownVersion(t *testing.T) {
	path := dbPath(t)
	db, err := bbolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		meta, err := tx.CreateBucket([]byte(metaBucket))
		if err != nil {
			return err
		}
		return meta.Put([]byte(versionKey), []byte{0, 0, 0, 0, 0, 0, 0, 2})
	})
	if cerr := db.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, "", retain); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Open(version 2) = %v, want ErrCorrupt", err)
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

// The first Open imports the JSON snapshot, skips the refused addresses,
// and removes the snapshot. A later Open does not import again.
func TestOpenImportsTheJSONSnapshotOnce(t *testing.T) {
	dir := t.TempDir()
	path, legacy := filepath.Join(dir, "addrbook.db"), filepath.Join(dir, "addrbook.json")
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
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	writeJSON(t, legacy, jsonEntry("web", "198.51.100.1", retain))
	s2, err := Open(path, legacy, retain)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() }) //nolint:errcheck // a second Close returns the same result
	if got := strs(s2.Addrs("web")); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("web after the second Open = %v, want only the first import", got)
	}
}

// A JSON snapshot that does not decode is an Open error. Open leaves the
// snapshot as it is, and imports nothing.
func TestOpenRefusesACorruptJSONSnapshot(t *testing.T) {
	dir := t.TempDir()
	path, legacy := filepath.Join(dir, "addrbook.db"), filepath.Join(dir, "addrbook.json")
	if err := os.WriteFile(legacy, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, legacy, retain); !errors.Is(err, addrbook.ErrSnapshot) {
		t.Fatalf("Open with a corrupt snapshot = %v, want addrbook.ErrSnapshot", err)
	}
	if data, err := os.ReadFile(legacy); err != nil || string(data) != "not json" {
		t.Errorf("the corrupt snapshot changed: %q, %v", data, err)
	}
	// The import did not commit, so a repaired snapshot imports.
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

// A crash after the import committed and before the removal of the
// snapshot does not import the snapshot again.
func TestCrashBeforeTheRemovalOfTheSnapshotDoesNotImportAgain(t *testing.T) {
	dir := t.TempDir()
	path, legacy := filepath.Join(dir, "addrbook.db"), filepath.Join(dir, "addrbook.json")
	writeJSON(t, legacy, jsonEntry("web", "192.0.2.1", retain))
	var image []byte
	c := &commits{after: func() {
		var err error
		if image, err = os.ReadFile(path); err != nil {
			t.Error(err)
		}
	}}
	s, err := open(path, legacy, retain, c.update)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// The crash state: the file as the import left it, and the snapshot,
	// here with other entries so that a second import shows.
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, legacy, jsonEntry("web", "198.51.100.1", retain))
	s2, err := Open(path, legacy, retain)
	if err != nil {
		t.Fatalf("Open after the crash: %v", err)
	}
	defer s2.Close() //nolint:errcheck // the test checks no write after this point
	if got := strs(s2.Addrs("web")); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("web = %v, want only the first import", got)
	}
	if _, err := os.Stat(legacy); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the snapshot is still there: %v", err)
	}
}

// After a refresh in memory, NextExpiry is behind. An Expire at that
// instant removes nothing, and sends facts with the real first expiry,
// so a timer on NextExpiry does not fire again at once.
func TestExpireThatRemovesNothingSendsTheLaterNextExpiry(t *testing.T) {
	s, _ := openCounted(t, dbPath(t), "")
	record(t, s, "web", 0, t0, "192.0.2.1")
	record(t, s, "web", 0, t0.Add(slack), "192.0.2.1") // in memory only
	stale := latestFacts(t, s).NextExpiry
	if !stale.Equal(t0.Add(retain + time.Nanosecond)) {
		t.Fatalf("NextExpiry = %v, want the expiry on disk %v", stale, t0.Add(retain))
	}
	if n, err := s.Apply(context.Background(), Expire{At: stale}); err != nil || n != 0 {
		t.Fatalf("Expire at the stale NextExpiry = %d, %v; want 0, nil", n, err)
	}
	if got, want := latestFacts(t, s).NextExpiry, t0.Add(slack+retain+time.Nanosecond); !got.Equal(want) {
		t.Errorf("NextExpiry after the Expire = %v, want %v", got, want)
	}
}
