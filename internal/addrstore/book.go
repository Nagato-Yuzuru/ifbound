package addrstore

import (
	"context"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	"go.etcd.io/bbolt"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// slot is one entry of the index. cur is the entry in memory; saved is
// the entry that the last commit wrote. cur is never earlier than saved
// for long: the committer sets saved and then merges it into cur.
type slot struct {
	cur   atomic.Pointer[stamp]
	saved atomic.Pointer[stamp]
}

func newSlot(cur, saved stamp) *slot {
	sl := &slot{}
	sl.cur.Store(&cur)
	sl.saved.Store(&saved)
	return sl
}

// refresh merges obs into the entry in memory when the merged expiry is
// at most slack after the expiry on disk. It reports whether it did; on
// false the entry needs a commit. A removed entry always needs one.
func (sl *slot) refresh(obs stamp, slack int64) bool {
	for {
		old := sl.cur.Load()
		if old.gone {
			return false
		}
		next := merge(*old, obs)
		if next.expiry-slack > sl.saved.Load().expiry {
			return false
		}
		if next == *old || sl.cur.CompareAndSwap(old, &next) {
			return true
		}
	}
}

// mergeCur merges st into the entry in memory.
func (sl *slot) mergeCur(st stamp) {
	for {
		old := sl.cur.Load()
		next := merge(*old, st)
		if next == *old || sl.cur.CompareAndSwap(old, &next) {
			return
		}
	}
}

// write is one entry that a commit writes.
type write struct {
	key key
	st  stamp
}

// Pending is the work that Touch found: the entries that need a commit.
// The zero Pending needs none.
type Pending struct{ writes []write }

// Empty reports whether p needs no commit.
func (p Pending) Empty() bool { return len(p.writes) == 0 }

// Touch records that an answer for each policy in names contained addrs
// with ttl, at the time at. For each address the expiry becomes the
// later of the old expiry and at + max(ttl, retain), so it never moves
// earlier.
//
// A known address whose new expiry is at most the save slack after its
// expiry on disk changes only in memory, at once. Every other address,
// and every new one, goes into the Pending, and the index does not change
// until Commit writes it. Commit the Pending, and acknowledge the answer
// only after Commit returns nil.
//
// If any input is invalid, Touch changes nothing. The zero
// blockable.Addr is invalid: the error then wraps blockable.ErrZero.
func (s *Store) Touch(names []policy.Name, addrs []blockable.Addr, ttl time.Duration, at time.Time) (Pending, error) {
	obs, err := s.observation(names, addrs, ttl, at)
	if err != nil {
		return Pending{}, err
	}
	var p Pending
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, name := range names {
		for _, a := range addrs {
			if sl := s.index[name][a]; sl != nil && sl.refresh(obs, s.slack) {
				continue
			}
			p.writes = append(p.writes, write{key{name, a}, obs})
		}
	}
	return p, nil
}

// observation checks the input of Touch and Adopt, and returns the stamp
// of an answer at the time at.
func (s *Store) observation(names []policy.Name, addrs []blockable.Addr, ttl time.Duration, at time.Time) (stamp, error) {
	if slices.Contains(names, "") {
		return stamp{}, ErrEmptyPolicy
	}
	if ttl < 0 {
		return stamp{}, ErrNegativeTTL
	}
	if err := blockable.Check(addrs); err != nil {
		return stamp{}, fmt.Errorf("addrstore: %w", err)
	}
	seen, err := nanos(at)
	if err != nil {
		return stamp{}, err
	}
	exp, ok := addNanos(seen, int64(max(ttl, s.retain)))
	if !ok {
		return stamp{}, fmt.Errorf("%w: %v + %v", ErrTimeRange, at, max(ttl, s.retain))
	}
	return stamp{seen: seen, ttl: int64(ttl), expiry: exp}, nil
}

// Commit writes the entries of p. It shares one transaction with the
// other requests that wait at the same time, and returns the result of
// that transaction. After a nil return the entries are on disk and in
// the index. After an error the index is as before. An empty p returns
// nil at once. It returns ctx.Err() when ctx ends first, and ErrClosed
// after Close; the commit can still happen after ctx ends.
func (s *Store) Commit(ctx context.Context, p Pending) error {
	if p.Empty() {
		return nil
	}
	_, err := s.send(ctx, request{writes: p.writes})
	return err
}

// Op is one book operation for Apply.
//
//sumtype:decl
type Op interface{ isOp() }

// Expire removes each entry whose expiry is before At.
type Expire struct{ At time.Time }

// Prune removes every entry of a policy that is not in Keep. An empty
// Keep removes all entries.
type Prune struct{ Keep []policy.Name }

// Adopt writes the addresses in Found as answers with TTL 0 at At: each
// gets a fresh retain period. Adopt always commits each entry, also one
// inside the save slack.
type Adopt struct {
	Found map[policy.Name][]blockable.Addr
	At    time.Time
}

// Flush writes each entry whose state in memory is not on disk: the
// refreshes inside the save slack. Call it before Close.
type Flush struct{}

func (Expire) isOp() {}
func (Prune) isOp()  {}
func (Adopt) isOp()  {}
func (Flush) isOp()  {}

// queuedOp is an Op that the committer runs alone, in its order. Adopt is
// not one: Apply sends it as writes.
//
//sumtype:decl
type queuedOp interface{ isQueuedOp() }

func (Expire) isQueuedOp() {}
func (Prune) isQueuedOp()  {}
func (Flush) isQueuedOp()  {}

// Apply runs op on the committer, after the requests before it. It
// returns the number of entries that Expire or Prune removed, and 0 for
// the other operations.
//
// Adopt and Flush are commits: after an error, the index is as before.
// A removal by Expire or Prune is final in memory also when its delete
// fails, and the count includes it: an entry that the delete left on
// disk is expired, and the next Expire after Open removes it again, or
// it is of a removed policy, and the next Prune removes it again. A
// failed Expire thus cannot repeat at once.
//
// Errors: as Commit, and the errors of Touch for the input of Adopt.
func (s *Store) Apply(ctx context.Context, op Op) (int, error) {
	switch op := op.(type) {
	case Expire:
		if _, err := nanos(op.At); err != nil {
			return 0, err
		}
		return s.send(ctx, request{op: op})
	case Prune:
		return s.send(ctx, request{op: op})
	case Flush:
		return s.send(ctx, request{op: op})
	case Adopt:
		var writes []write
		for name, addrs := range op.Found {
			obs, err := s.observation([]policy.Name{name}, addrs, 0, op.At)
			if err != nil {
				return 0, err
			}
			for _, a := range addrs {
				writes = append(writes, write{key{name, a}, obs})
			}
		}
		if len(writes) == 0 {
			return 0, nil
		}
		return s.send(ctx, request{writes: writes})
	default:
		return 0, fmt.Errorf("%w: %T", errUnknownOp, op)
	}
}

// request is one unit of work for the committer: a group member with
// writes, or an op.
type request struct {
	writes []write
	op     queuedOp
	reply  chan result
}

type result struct {
	removed int
	err     error
}

func (s *Store) send(ctx context.Context, r request) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	r.reply = make(chan result, 1)
	select {
	case s.reqs <- r:
	case <-s.done:
		return 0, ErrClosed
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	select {
	case res := <-r.reply:
		return res.removed, res.err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// run is the committer. It takes one request, and with a write request
// also every write request that waits at that time. It has no timer: a
// group is what waits when the committer is free. An Op runs alone, in
// its order.
func (s *Store) run() {
	defer close(s.done)
	var next *request
	for {
		r := next
		next = nil
		if r == nil {
			select {
			case req := <-s.reqs:
				r = &req
			case <-s.stop:
				return
			}
		}
		if r.op != nil {
			removed, err := s.runOp(r.op)
			r.reply <- result{removed, err}
			continue
		}
		var group []request
		group, next = s.group(*r)
		var writes []write
		for _, g := range group {
			writes = append(writes, g.writes...)
		}
		err := s.commit(writes)
		for _, g := range group {
			g.reply <- result{err: err}
		}
	}
}

// group returns first and each write request that waits now, up to the
// first Op that waits, which it returns as next.
func (s *Store) group(first request) (group []request, next *request) {
	group = []request{first}
	for {
		select {
		case req := <-s.reqs:
			if req.op != nil {
				return group, &req
			}
			group = append(group, req)
		default:
			return group, nil
		}
	}
}

func (s *Store) runOp(op queuedOp) (int, error) {
	switch op := op.(type) {
	case Expire:
		at := op.At.UnixNano()
		return s.remove(func(_ policy.Name, st *stamp) bool { return at > st.expiry })
	case Prune:
		return s.remove(func(name policy.Name, _ *stamp) bool { return !slices.Contains(op.Keep, name) })
	case Flush:
		return 0, s.flush()
	default:
		return 0, fmt.Errorf("%w: %T", errUnknownOp, op)
	}
}

// commit writes writes in one transaction, each merged with the entry in
// memory, and then puts them in the index. After an error the index is
// unchanged.
func (s *Store) commit(writes []write) error {
	merged := make(map[key]stamp, len(writes))
	for _, w := range writes {
		if st, ok := merged[w.key]; ok {
			merged[w.key] = merge(st, w.st)
		} else {
			merged[w.key] = w.st
		}
	}
	s.mu.RLock()
	for k, st := range merged {
		if sl := s.index[k.policy][k.addr]; sl != nil {
			if cur := sl.cur.Load(); !cur.gone {
				merged[k] = merge(st, *cur)
			}
		}
	}
	s.mu.RUnlock()
	if err := s.write(merged); err != nil {
		return fmt.Errorf("addrstore: commit: %w", err)
	}
	s.mu.Lock()
	for k, st := range merged {
		byAddr := s.index[k.policy]
		if byAddr == nil {
			byAddr = make(map[blockable.Addr]*slot)
			s.index[k.policy] = byAddr
		}
		sl := byAddr[k.addr]
		if sl == nil || sl.cur.Load().gone {
			byAddr[k.addr] = newSlot(st, st)
			continue
		}
		// saved first: a refresh between the two steps then compares
		// with the new disk state.
		sl.saved.Store(&st)
		sl.mergeCur(st)
	}
	s.mu.Unlock()
	s.publish()
	return nil
}

func (s *Store) write(entries map[key]stamp) error {
	return s.update(func(tx *bbolt.Tx) error {
		book := tx.Bucket([]byte(bookBucket))
		if book == nil {
			return fmt.Errorf("%w: no bucket %q", ErrCorrupt, bookBucket)
		}
		for k, st := range entries {
			if err := put(book, k, st); err != nil {
				return err
			}
		}
		return nil
	})
}

// flush commits each entry whose state in memory is not on disk.
func (s *Store) flush() error {
	dirty := make(map[key]stamp)
	s.mu.RLock()
	for name, byAddr := range s.index {
		for a, sl := range byAddr {
			if cur := sl.cur.Load(); !cur.gone && *cur != *sl.saved.Load() {
				dirty[key{name, a}] = *cur
			}
		}
	}
	s.mu.RUnlock()
	if len(dirty) == 0 {
		return nil
	}
	writes := make([]write, 0, len(dirty))
	for k, st := range dirty {
		writes = append(writes, write{k, st})
	}
	return s.commit(writes)
}

// remove marks each entry for which drop is true as gone, deletes them
// in one transaction, and then takes them out of the index, also when
// the delete fails.
func (s *Store) remove(drop func(policy.Name, *stamp) bool) (int, error) {
	gone := s.mark(drop)
	if len(gone) == 0 {
		// The facts can be behind a refresh in memory: a NextExpiry
		// before the real first expiry. New facts let the owner wait for
		// the real one.
		s.publish()
		return 0, nil
	}
	err := s.update(func(tx *bbolt.Tx) error { return deleteKeys(tx, gone) })
	s.mu.Lock()
	for _, k := range gone {
		delete(s.index[k.policy], k.addr)
		if len(s.index[k.policy]) == 0 {
			delete(s.index, k.policy)
		}
	}
	s.mu.Unlock()
	s.publish()
	if err != nil {
		return len(gone), fmt.Errorf("addrstore: delete: %w", err)
	}
	return len(gone), nil
}

// mark marks each entry for which drop is true as gone, and returns
// them. A refresh that wins the race against the mark keeps its entry:
// mark reads the entry again and asks drop again.
func (s *Store) mark(drop func(policy.Name, *stamp) bool) []key {
	var gone []key
	s.mu.RLock()
	defer s.mu.RUnlock()
	for name, byAddr := range s.index {
		for a, sl := range byAddr {
			if sl.markIf(func(st *stamp) bool { return drop(name, st) }) {
				gone = append(gone, key{name, a})
			}
		}
	}
	return gone
}

// markIf replaces the entry in memory with a gone stamp while drop is
// true for it, and reports whether it did.
func (sl *slot) markIf(drop func(*stamp) bool) bool {
	for {
		cur := sl.cur.Load()
		if !drop(cur) {
			return false
		}
		if sl.cur.CompareAndSwap(cur, &stamp{gone: true}) {
			return true
		}
	}
}

func deleteKeys(tx *bbolt.Tx, gone []key) error {
	book := tx.Bucket([]byte(bookBucket))
	if book == nil {
		return fmt.Errorf("%w: no bucket %q", ErrCorrupt, bookBucket)
	}
	for _, k := range gone {
		pb := book.Bucket([]byte(k.policy))
		if pb == nil {
			continue
		}
		addr, err := k.addr.Addr().MarshalBinary()
		if err != nil {
			return err
		}
		if err := pb.Delete(addr); err != nil {
			return err
		}
	}
	return nil
}
