// Package addrstore keeps the address book: the addresses that DNS
// answers gave for protected names. An address stays blocked for at
// least the retain time after the last answer that contained it.
//
// An acknowledged answer grants a lease to each cache after ifbound-dns:
// mDNSResponder, the memory of a program, and the caches of a VM guest.
// ifbound cannot clear those caches, so the book keeps each address for
// its lease. A suspended VM keeps its caches across a reboot, a panic, or
// a power loss of the host, so each lease is durable before its ack.
//
// The book is a log of leases on disk (see segment.go for the format)
// and an index in memory. One goroutine, the committer, is the only
// writer of both. Touch reads the index and finds what must be written;
// Commit gives that work to the committer and waits. The committer takes
// one request and then each request that waits at that time (it has no
// timer), appends their records, syncs the file one time, updates the
// index, and gives each waiter the same result. So an entry is in the
// index only after its record is durable, and a failed commit changes
// nothing.
//
// Persist rule: a record keeps its entry until its write time +
// renewAfter + its hold. Touch asks for a write only when that bound does
// not cover the new expiry, so a name that an answer gives again and
// again writes at most one record in each renewAfter. After a load, an
// expiry is at most renewAfter + one minute later than in memory before:
// the error is always on the side of more blocking.
//
// The log never records a removal. Expire and Prune change only the
// index. A load reads every record again, and the owner prunes the
// policies that the configuration removed and expires the rest. A
// segment goes when none of its records can give an entry that is still
// kept.
//
// The book has no call that removes an entry because a lookup failed. An
// entry leaves only through Expire or Prune. Destinations that the
// configuration gives as CIDR or IP are not in the book.
package addrstore

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrbook"
	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// renewAfter is how long the record of an entry covers the refreshes of
// that entry. A busy name then writes at most one record in each
// renewAfter, and a load gives each entry up to renewAfter more than its
// expiry in memory.
const renewAfter = 24 * time.Hour

// Errors of the Store.
var (
	ErrEmptyPolicy = errors.New("addrstore: empty policy name")
	ErrNegativeTTL = errors.New("addrstore: negative ttl")
	// ErrLongPolicy is the error for a policy name longer than
	// policy.MaxNameLen.
	ErrLongPolicy = errors.New("addrstore: policy name too long")
	// ErrTimeRange is the error for a time that the book cannot hold.
	ErrTimeRange = errors.New("addrstore: time outside the stored range")
	// ErrBadPath is the error of Open for a path that is not a directory,
	// or that leaves its parent directory through a symlink.
	ErrBadPath = errors.New("addrstore: bad store path")
	// ErrLocked is the error of Open when another Store holds the book.
	ErrLocked = errors.New("addrstore: book in use")
	// ErrCorrupt is in the chain of each error of Damage and Read for a
	// place that is not in the file format.
	ErrCorrupt = errors.New("addrstore: corrupt store")
	// ErrClosed is the error of a request after Close.
	ErrClosed = errors.New("addrstore: closed")

	errUnknownOp = errors.New("addrstore: unknown op")
)

// stamp is an entry in memory; the index keys hold the rest. Times are
// Unix nanoseconds, so a monotonic clock reading cannot reach the book.
// A stamp is immutable after it is in a slot.
type stamp struct {
	seen   int64
	expiry int64
	// gone marks an entry that the committer removes. Touch does not
	// refresh it.
	gone bool
}

// merge returns the later of a and b: the later last_seen and the later
// expiry. The result does not depend on the order of the arguments.
func merge(a, b stamp) stamp {
	return stamp{seen: max(a.seen, b.seen), expiry: max(a.expiry, b.expiry)}
}

// key is one entry of the book.
type key struct {
	policy policy.Name
	addr   blockable.Addr
}

// BookFacts is what the book tells its owner. The Store sends a new
// value after each change, and after each Expire and Prune.
type BookFacts struct {
	Retain time.Duration
	// Counts is the number of addresses of each policy that has one. The
	// map is new in each value; do not change it.
	Counts map[policy.Name]int
	// NextExpiry is the first instant at which an entry can be expired:
	// one nanosecond after the earliest expiry. It is the zero time when
	// the book is empty. A refresh in memory can move an expiry later
	// without a new value, so Expire at NextExpiry can remove nothing;
	// its new value then has the later NextExpiry.
	NextExpiry time.Time
}

// Store is the address book. Create it with Open. Its methods are safe
// for concurrent use.
type Store struct {
	dir    *segDir // only the committer uses it after Open
	retain time.Duration
	damage error
	fresh  bool

	reqs      chan request
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	facts     chan BookFacts

	// mu guards the maps of index. Only the committer changes them. The
	// slots change through their atomic fields.
	mu    sync.RWMutex
	index map[policy.Name]map[blockable.Addr]*slot
}

// Open opens the book in the directory at path. It creates the
// directory when it is missing; its parent must exist. Retain is the
// floor of the keep time: a load keeps each entry for at least retain
// after the write time of its record.
//
// Open reads every segment. A place that is not in the file format does
// not stop the open: Open skips it, keeps the rest, and Damage reports
// it. A write that a crash cut off is not damage: no ack came after it.
//
// When the JSON snapshot at legacy exists, Open writes its entries to
// the book and then removes it. Earlier versions wrote that snapshot,
// also after a downgrade from this version. The book keeps the later
// expiry of each address, so the same snapshot again changes nothing. It
// skips the entries whose address blockable.New refuses or whose policy
// name does not fit. It can bring back an entry that this version
// removed; the next Expire or Prune removes it again.
//
// Open does not remove expired entries: Expire does.
//
// Open returns an error that wraps ErrBadPath for a path that is not a
// directory, ErrLocked when another Store holds the book, and the error
// of addrbook.Read for a snapshot that does not import. After an error,
// nothing is open. Call Close when done.
func Open(path, legacy string, retain time.Duration) (*Store, error) {
	return open(path, legacy, retain, nil)
}

// open is Open with the sync function of the segments. A nil sync is
// (*os.File).Sync.
func open(path, legacy string, retain time.Duration, sync func(*os.File) error) (*Store, error) {
	dir, err := openDir(path)
	if err != nil {
		return nil, fmt.Errorf("open addrstore %s: %w", path, err)
	}
	if sync != nil {
		dir.sync = sync
	}
	s := &Store{
		dir:    dir,
		retain: retain,
		reqs:   make(chan request),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		facts:  make(chan BookFacts, 1),
	}
	if err := s.prepare(legacy); err != nil {
		_ = dir.close() //nolint:errcheck // the error of prepare is the one to report; each write that it made was synced
		return nil, fmt.Errorf("open addrstore %s: %w", path, err)
	}
	s.publish()
	go s.run()
	return s, nil
}

// prepare loads the index, writes the legacy snapshot to the book, and
// removes the snapshot.
func (s *Store) prepare(legacy string) error {
	segs, err := loadSegments(s.dir.root, s.retain)
	if err != nil {
		return err
	}
	var damage []error
	s.index = make(map[policy.Name]map[blockable.Addr]*slot)
	for _, seg := range segs {
		damage = append(damage, seg.damage...)
		s.dir.bounds[seg.name] = seg.bound
		for _, r := range seg.records {
			s.loadRecord(r)
		}
	}
	s.damage = errors.Join(damage...)
	s.fresh = len(segs) == 0
	if legacy == "" {
		return nil
	}
	entries, err := addrbook.Read(legacy)
	if err != nil {
		return fmt.Errorf("import: %w", err)
	}
	var writes []write
	for _, e := range entries {
		st, err := legacyStamp(e)
		if err != nil {
			return fmt.Errorf("import %s %s: %w", e.Policy, e.Addr, err)
		}
		if len(e.Policy) > policy.MaxNameLen {
			continue
		}
		writes = append(writes, write{key{e.Policy, e.Addr}, st})
	}
	if len(writes) > 0 {
		if err := s.commit(writes); err != nil {
			return fmt.Errorf("import: %w", err)
		}
	}
	// After the import commits, a crash can leave the snapshot. The next
	// Open imports it again, which changes nothing.
	if err := os.Remove(legacy); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove the imported snapshot: %w", err)
	}
	return nil
}

// loadRecord merges one record into the index.
func (s *Store) loadRecord(r lease) {
	st := r.stamp(s.retain)
	byAddr := s.index[r.policy]
	if byAddr == nil {
		byAddr = make(map[blockable.Addr]*slot)
		s.index[r.policy] = byAddr
	}
	if sl := byAddr[r.addr]; sl != nil {
		sl.mergeCur(st)
		sl.raise(st.expiry)
		return
	}
	byAddr[r.addr] = newSlot(st, st.expiry)
}

func legacyStamp(e addrbook.Entry) (stamp, error) {
	seen, err := nanos(e.LastSeen)
	if err != nil {
		return stamp{}, err
	}
	exp, err := nanos(e.Expiry)
	if err != nil {
		return stamp{}, err
	}
	return stamp{seen: seen, expiry: max(exp, seen)}, nil
}

// nanos returns t as Unix nanoseconds, or ErrTimeRange for a time that
// they cannot hold.
func nanos(t time.Time) (int64, error) {
	n := t.UnixNano()
	if !t.Equal(time.Unix(0, n)) {
		return 0, fmt.Errorf("%w: %v", ErrTimeRange, t)
	}
	return n, nil
}

// addNanos returns a + d, and false when the sum overflows.
func addNanos(a, d int64) (int64, bool) {
	if d > 0 && a > (1<<63-1)-d {
		return 0, false
	}
	return a + d, true
}

// Damage returns the places of the book that Open skipped because they
// are not in the file format, joined, or nil when there are none. Each
// error wraps ErrCorrupt and names the segment, and the offset of a
// record. The leases in those places are lost.
func (s *Store) Damage() error { return s.damage }

// Fresh reports whether Open found no segment: no earlier run of this
// version wrote a lease. The entries can still come from the JSON
// snapshot of an earlier version, which did not write each lease before
// its ack.
func (s *Store) Fresh() bool { return s.fresh }

// Entry is one entry of the book as a load gives it.
type Entry struct {
	Policy policy.Name
	Addr   blockable.Addr
	// Expiry is the last instant at which the entry is kept.
	Expiry time.Time
}

// Read returns the entries that a Store with retain would load from the
// book at path, sorted by policy and address. It takes no lock and
// writes nothing, so it can read the book of a running Store; it then
// sees each record that was durable when it read the segment. It returns
// the entries also when the error wraps ErrCorrupt: the error is then the
// Damage of such a load. A missing directory is an empty book.
func Read(path string, retain time.Duration) ([]Entry, error) {
	root, err := os.OpenRoot(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read addrstore %s: %w", path, err)
	}
	defer root.Close() //nolint:errcheck // a read-only handle
	segs, err := loadSegments(root, retain)
	if err != nil {
		return nil, fmt.Errorf("read addrstore %s: %w", path, err)
	}
	merged := make(map[key]int64)
	var damage []error
	for _, seg := range segs {
		damage = append(damage, seg.damage...)
		for _, r := range seg.records {
			merged[r.key()] = max(merged[r.key()], r.stamp(retain).expiry)
		}
	}
	out := make([]Entry, 0, len(merged))
	for _, k := range slices.SortedFunc(maps.Keys(merged), func(a, b key) int {
		if a.policy != b.policy {
			if a.policy < b.policy {
				return -1
			}
			return 1
		}
		return a.addr.Compare(b.addr)
	}) {
		out = append(out, Entry{k.policy, k.addr, time.Unix(0, merged[k])})
	}
	return out, errors.Join(damage...)
}

// Addrs returns the addresses of one policy in ascending order.
func (s *Store) Addrs(name policy.Name) []blockable.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]blockable.Addr, 0, len(s.index[name]))
	for a, sl := range s.index[name] {
		if !sl.cur.Load().gone {
			out = append(out, a)
		}
	}
	slices.SortFunc(out, blockable.Addr.Compare)
	return out
}

// Facts returns the channel of the latest BookFacts. It always holds the
// latest value that no receive took yet: the Store replaces an old value
// that nobody took. Open puts the first value in it, and the Store puts
// a new value before a Commit that changed the book, an Expire, a Prune,
// or an Adopt that wrote returns. It has one receiver: the owner of the
// Store.
func (s *Store) Facts() <-chan BookFacts { return s.facts }

// publish sends the facts of the index. Only one goroutine at a time
// calls it: Open before the committer starts, then the committer.
func (s *Store) publish() {
	f := BookFacts{Retain: s.retain, Counts: make(map[policy.Name]int)}
	first, found := int64(0), false
	s.mu.RLock()
	for name, byAddr := range s.index {
		for _, sl := range byAddr {
			st := sl.cur.Load()
			if st.gone {
				continue
			}
			f.Counts[name]++
			if !found || st.expiry < first {
				first, found = st.expiry, true
			}
		}
	}
	s.mu.RUnlock()
	if found {
		f.NextExpiry = time.Unix(0, first).Add(time.Nanosecond)
	}
	select {
	case <-s.facts:
	default:
	}
	s.facts <- f
}

// Close stops the committer and closes the book. A request that waits
// gets ErrClosed. Each acknowledged lease is already durable, so Close
// has nothing to write. Only the first call does the work; each call
// returns its result.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		close(s.stop)
		<-s.done
		s.closeErr = s.dir.close()
	})
	return s.closeErr
}
