// Package addrstore keeps the address book: the addresses that DNS
// answers gave for protected names. An address stays blocked for at
// least the retain time after the last answer that contained it.
//
// The book is a bbolt file and an index in memory. One goroutine, the
// committer, is the only writer of both. Touch reads the index and finds
// what must be written; Commit gives that work to the committer and
// waits. The committer takes one request and then each request that
// waits at that time (it has no timer), writes them in one transaction,
// updates the index, and gives each waiter the same result. So an entry
// is in the index only after its commit, and a failed commit changes
// nothing.
//
// Persist rule: Touch does not ask for a commit when the new expiry of a
// known address is at most the save slack after its expiry on disk. It
// then changes only the expiry in memory. After a crash, an address that
// a caller acknowledged after Commit returned stays in the book for at
// least retain minus the save slack after its last answer. Apply(Flush)
// writes the expiries in memory, for a clean shutdown.
//
// The file format: the bucket "meta" holds the key "version" with the
// value 1 as a big-endian uint64. The bucket "book" holds one bucket for
// each policy, with the policy name as its name. Its keys are addresses
// in the form of netip.Addr.MarshalBinary (4 or 16 bytes). Each value is
// 24 bytes: last_seen as Unix nanoseconds, the ttl in nanoseconds, and
// the expiry as Unix nanoseconds, each a big-endian int64.
//
// The book has no call that removes an entry because a lookup failed. An
// entry leaves only through Expire or Prune. Destinations that the
// configuration gives as CIDR or IP are not in the book.
package addrstore

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"runtime/debug"
	"slices"
	"sync"
	"syscall"
	"time"

	"go.etcd.io/bbolt"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrbook"
	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// maxSaveSlack caps the save slack. Touch asks for a commit only when
// the expiry on disk is more than the slack behind the new expiry. This
// way a busy name does not cause a disk write for every answer. The
// slack is the smaller of this value and half of retain.
const maxSaveSlack = time.Hour

// lockWait is how long Open waits for the lock on the file that another
// open Store holds. Open then fails, and the caller can try again later.
const lockWait = time.Second

// formatVersion is the version of the file format.
const formatVersion = 1

// valueLen is the length of a stored value.
const valueLen = 24

// The bucket and key names of the file format.
const (
	metaBucket = "meta"
	versionKey = "version"
	bookBucket = "book"
)

// Errors of the Store.
var (
	ErrEmptyPolicy = errors.New("addrstore: empty policy name")
	ErrNegativeTTL = errors.New("addrstore: negative ttl")
	// ErrTimeRange is the error for a time that Unix nanoseconds cannot
	// hold.
	ErrTimeRange = errors.New("addrstore: time outside the stored range")
	// ErrBadPath is the error of Open for a path that is a symlink.
	ErrBadPath = errors.New("addrstore: bad store path")
	// ErrCorrupt is the error for a file that is not in the file format:
	// an unknown version, an invalid entry, or a damaged page. Open
	// returns it, and so does a commit that reads a damaged page. The
	// book does not start empty in this case. An empty book could unblock
	// addresses that applications still use.
	ErrCorrupt = errors.New("addrstore: corrupt store")
	// ErrClosed is the error of a request after Close.
	ErrClosed = errors.New("addrstore: closed")

	errUnknownOp = errors.New("addrstore: unknown op")
)

// stamp is the stored form of an entry; the index keys hold the rest.
// Times are Unix nanoseconds, so a monotonic clock reading cannot reach
// the book. A stamp is immutable after it is in a slot.
type stamp struct {
	seen   int64
	ttl    int64
	expiry int64
	// gone marks an entry that the committer removes. Touch does not
	// refresh it.
	gone bool
}

// merge returns the later of a and b: the later expiry, and the later
// last_seen with its ttl (the larger ttl when last_seen is equal). The
// result does not depend on the order of the arguments.
func merge(a, b stamp) stamp {
	out := a
	if b.seen > a.seen || b.seen == a.seen && b.ttl > a.ttl {
		out.seen, out.ttl = b.seen, b.ttl
	}
	out.expiry = max(a.expiry, b.expiry)
	return out
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
	db     *bbolt.DB
	retain time.Duration
	slack  int64
	// update runs one write transaction under guard. It runs db.Update; a
	// test gives a function that counts or fails the commits.
	update func(func(*bbolt.Tx) error) error

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

// Open opens the book at path, and creates the file when it is missing.
// Retain is the floor of the keep time. When the JSON snapshot at legacy
// exists, Open merges it into the book in one transaction, and then
// removes it. Earlier versions wrote that snapshot, also after a
// downgrade from this version. The merge keeps the later expiry of each
// address, so a merge of the same snapshot again changes nothing. It
// skips the entries whose address blockable.New refuses. It can bring
// back an entry that this version removed; the next Expire or Prune
// removes it again.
//
// When retain is larger than when an entry was written, the expiry of
// the entry becomes the later of the stored one and last_seen +
// max(ttl, retain). Open does not remove expired entries: Expire does.
//
// Open returns an error that wraps ErrBadPath for a symlink path,
// ErrCorrupt for a file that is not in the file format or has a damaged
// page, and the error of addrbook.Read for a snapshot that does not
// import. After an error, nothing is open. Call Close when done.
func Open(path, legacy string, retain time.Duration) (*Store, error) {
	return open(path, legacy, retain, nil)
}

// open is Open with the transaction function of the committer. A nil
// update is db.Update.
func open(path, legacy string, retain time.Duration, update func(*bbolt.DB, func(*bbolt.Tx) error) error) (*Store, error) {
	var file *os.File
	opts := &bbolt.Options{
		Timeout: lockWait,
		// The open refuses a symlink itself, so a link that replaces the
		// file after a check cannot redirect it.
		OpenFile: func(name string, flag int, perm os.FileMode) (*os.File, error) {
			f, err := os.OpenFile(name, flag|syscall.O_NOFOLLOW, perm)
			file = f
			return f, err
		},
	}
	var db *bbolt.DB
	err := guard(func() error {
		var err error
		db, err = bbolt.Open(path, 0o600, opts)
		return err
	})
	switch {
	case errors.Is(err, syscall.ELOOP):
		return nil, fmt.Errorf("open addrstore: %w: %s is a symlink", ErrBadPath, path)
	case errors.Is(err, ErrCorrupt) && file != nil:
		// bbolt stopped inside Open and did not return the DB, so its
		// memory map of the file stays. On Linux, the map keeps the open
		// file alive after Close, and the lock stays with it. Thus unlock
		// the file before the close, as DB.Close does.
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN) //nolint:errcheck // the corrupt file is the error to report; after a failed unlock, the next Open fails with a timeout
		_ = file.Close()                                   //nolint:errcheck // the corrupt file is the error to report; nothing was written
		return nil, fmt.Errorf("open addrstore %s: %w", path, err)
	case err != nil:
		return nil, fmt.Errorf("open addrstore %s: %w", path, err)
	}
	commit := db.Update
	if update != nil {
		commit = func(fn func(*bbolt.Tx) error) error { return update(db, fn) }
	}
	s := &Store{
		db:     db,
		retain: retain,
		slack:  int64(min(maxSaveSlack, retain/2)),
		update: func(fn func(*bbolt.Tx) error) error { return guard(func() error { return commit(fn) }) },
		reqs:   make(chan request),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		facts:  make(chan BookFacts, 1),
	}
	if err := guard(func() error { return s.prepare(legacy) }); err != nil {
		_ = db.Close() //nolint:errcheck // the error of prepare is the one to report; nothing was written that a failed close could lose
		return nil, fmt.Errorf("open addrstore %s: %w", path, err)
	}
	s.publish()
	go s.run()
	return s, nil
}

// guard runs fn and returns its error. It returns an error that wraps
// ErrCorrupt when fn panics or reads memory that is not there. bbolt
// reads the file through a memory map and trusts its pages: a damaged
// page makes it panic, or read outside the map. Every read of a page
// goes through guard: Open, and each transaction of the committer.
func guard(fn func() error) (err error) {
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: %v", ErrCorrupt, r)
		}
	}()
	return fn()
}

// prepare merges the legacy snapshot into the book, removes the
// snapshot, and loads the index.
func (s *Store) prepare(legacy string) error {
	if err := s.checkFreelist(); err != nil {
		return err
	}
	version, err := s.version()
	if err != nil {
		return err
	}
	var entries []addrbook.Entry
	if legacy != "" {
		if entries, err = addrbook.Read(legacy); err != nil {
			return fmt.Errorf("import: %w", err)
		}
	}
	if version != formatVersion || len(entries) > 0 {
		if err := s.importEntries(entries); err != nil {
			return fmt.Errorf("import: %w", err)
		}
	}
	if legacy != "" {
		// After the merge commits, a crash can leave the snapshot. The
		// next Open merges it again, which changes nothing.
		if err := os.Remove(legacy); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove the imported snapshot: %w", err)
		}
	}
	index, err := s.load()
	if err != nil {
		return err
	}
	s.index = index
	return nil
}

// checkFreelist returns an error that wraps ErrCorrupt when the freelist
// that Open read does not name each free page one time only. bbolt reads
// the freelist without a check. A damaged count makes it read entries
// that are not there. Past the end of its map, other memory of the
// process often follows (on Linux, for example), so that read does not
// always fault. A commit could then use a page two times, or a page that
// is not in the file. A free page is a page of the file under its
// high-water mark, and a meta page is never free.
func (s *Store) checkFreelist() error {
	free := 0
	err := s.db.View(func(tx *bbolt.Tx) error {
		for id := 2; ; id++ {
			info, err := tx.Page(id)
			if err != nil {
				return err
			}
			if info == nil {
				return nil
			}
			if info.Type == "free" {
				free++
			}
		}
	})
	if err != nil {
		return err
	}
	if n := s.db.Stats().FreePageN; n != free {
		return fmt.Errorf("%w: the freelist has %d entries for %d free pages", ErrCorrupt, n, free)
	}
	return nil
}

// version returns the format version of the file, or 0 when the file has
// none: it is new, or its first import did not commit.
func (s *Store) version() (uint64, error) {
	var v uint64
	err := s.db.View(func(tx *bbolt.Tx) error {
		meta := tx.Bucket([]byte(metaBucket))
		if meta == nil {
			return nil
		}
		raw := meta.Get([]byte(versionKey))
		if len(raw) != 8 {
			return fmt.Errorf("%w: bad version value", ErrCorrupt)
		}
		v = binary.BigEndian.Uint64(raw)
		if v != formatVersion {
			return fmt.Errorf("%w: unknown version %d", ErrCorrupt, v)
		}
		return nil
	})
	return v, err
}

// importEntries merges entries into the book, and writes the format
// version, in one transaction. For an address that the book has, the
// stored entry becomes the merge of the two: the later expiry wins.
func (s *Store) importEntries(entries []addrbook.Entry) error {
	return s.update(func(tx *bbolt.Tx) error {
		book, err := tx.CreateBucketIfNotExists([]byte(bookBucket))
		if err != nil {
			return err
		}
		for _, e := range entries {
			k := key{e.Policy, e.Addr}
			st, err := stampOf(e)
			if err != nil {
				return fmt.Errorf("%s %s: %w", e.Policy, e.Addr, err)
			}
			old, ok, err := s.get(book, k)
			if err != nil {
				return err
			}
			if ok {
				st = merge(old, st)
			}
			if err := put(book, k, st); err != nil {
				return err
			}
		}
		meta, err := tx.CreateBucketIfNotExists([]byte(metaBucket))
		if err != nil {
			return err
		}
		return meta.Put([]byte(versionKey), binary.BigEndian.AppendUint64(nil, formatVersion))
	})
}

// get returns the stored entry of k, and false when the book has none.
func (s *Store) get(book *bbolt.Bucket, k key) (stamp, bool, error) {
	pb := book.Bucket([]byte(k.policy))
	if pb == nil {
		return stamp{}, false, nil
	}
	addr, err := k.addr.Addr().MarshalBinary()
	if err != nil {
		return stamp{}, false, err
	}
	v := pb.Get(addr)
	if v == nil {
		return stamp{}, false, nil
	}
	_, st, _, err := s.decode(addr, v)
	if err != nil {
		return stamp{}, false, fmt.Errorf("%w: policy %s: %v", ErrCorrupt, k.policy, err)
	}
	return st, true, nil
}

func stampOf(e addrbook.Entry) (stamp, error) {
	seen, err := nanos(e.LastSeen)
	if err != nil {
		return stamp{}, err
	}
	exp, err := nanos(e.Expiry)
	if err != nil {
		return stamp{}, err
	}
	return stamp{seen: seen, ttl: int64(e.TTL), expiry: exp}, nil
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

// load reads the book into a new index.
func (s *Store) load() (map[policy.Name]map[blockable.Addr]*slot, error) {
	index := make(map[policy.Name]map[blockable.Addr]*slot)
	err := s.db.View(func(tx *bbolt.Tx) error {
		book := tx.Bucket([]byte(bookBucket))
		if book == nil {
			return fmt.Errorf("%w: no bucket %q", ErrCorrupt, bookBucket)
		}
		return book.ForEachBucket(func(name []byte) error {
			p := policy.Name(name)
			if p == "" {
				return fmt.Errorf("%w: %v", ErrCorrupt, ErrEmptyPolicy)
			}
			return book.Bucket(name).ForEach(func(k, v []byte) error {
				a, st, ok, err := s.decode(k, v)
				if err != nil {
					return fmt.Errorf("%w: policy %s: %v", ErrCorrupt, p, err)
				}
				if !ok {
					return nil
				}
				if index[p] == nil {
					index[p] = make(map[blockable.Addr]*slot)
				}
				index[p][a] = newSlot(s.rebase(st), st)
				return nil
			})
		})
	})
	return index, err
}

var (
	errBadKey           = errors.New("bad address key")
	errValueLen         = errors.New("bad value length")
	errExpiryBeforeSeen = errors.New("expiry before last_seen")
)

// decode returns one stored entry. The bool is false for an address that
// blockable.New refuses: an earlier version can have written it.
func (s *Store) decode(k, v []byte) (blockable.Addr, stamp, bool, error) {
	var ip netip.Addr
	if err := ip.UnmarshalBinary(k); err != nil || !ip.IsValid() {
		return blockable.Addr{}, stamp{}, false, fmt.Errorf("%w %x", errBadKey, k)
	}
	if len(v) != valueLen {
		return blockable.Addr{}, stamp{}, false, errValueLen
	}
	st := stamp{
		seen:   int64(binary.BigEndian.Uint64(v[0:8])),
		ttl:    int64(binary.BigEndian.Uint64(v[8:16])),
		expiry: int64(binary.BigEndian.Uint64(v[16:24])),
	}
	switch {
	case st.ttl < 0:
		return blockable.Addr{}, stamp{}, false, ErrNegativeTTL
	case st.expiry < st.seen:
		return blockable.Addr{}, stamp{}, false, errExpiryBeforeSeen
	}
	a, ok := blockable.New(ip)
	return a, st, ok, nil
}

// rebase applies the retain floor of this Store to a stored entry.
func (s *Store) rebase(st stamp) stamp {
	if floor, ok := addNanos(st.seen, max(st.ttl, int64(s.retain))); ok && floor > st.expiry {
		st.expiry = floor
	}
	return st
}

// addNanos returns a + d, and false when the sum overflows.
func addNanos(a, d int64) (int64, bool) {
	if d > 0 && a > (1<<63-1)-d {
		return 0, false
	}
	return a + d, true
}

func put(book *bbolt.Bucket, k key, st stamp) error {
	pb, err := book.CreateBucketIfNotExists([]byte(k.policy))
	if err != nil {
		return err
	}
	addr, err := k.addr.Addr().MarshalBinary()
	if err != nil {
		return err
	}
	v := make([]byte, 0, valueLen)
	v = binary.BigEndian.AppendUint64(v, uint64(st.seen))
	v = binary.BigEndian.AppendUint64(v, uint64(st.ttl))
	v = binary.BigEndian.AppendUint64(v, uint64(st.expiry))
	return pb.Put(addr, v)
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
// or a Flush that wrote returns. It has one receiver: the owner of the
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

// Close stops the committer and closes the file. A request that waits
// gets ErrClosed. Close does not flush: call Apply with Flush first.
// Only the first call does the work; each call returns its result.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		close(s.stop)
		<-s.done
		s.closeErr = s.db.Close()
	})
	return s.closeErr
}
