package addrstore

import (
	"context"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// slot is one entry of the index. cur is the entry in memory; bound is
// the expiry that the durable records of the entry give at a load. cur
// can be later than bound only during a commit that writes it.
type slot struct {
	cur   atomic.Pointer[stamp]
	bound atomic.Int64
}

func newSlot(cur stamp, bound int64) *slot {
	sl := &slot{}
	sl.cur.Store(&cur)
	sl.bound.Store(bound)
	return sl
}

// refresh merges obs into the entry in memory when the durable bound
// covers the merged expiry. It reports whether it did; on false the
// entry needs a commit. A removed entry always needs one.
func (sl *slot) refresh(obs stamp) bool {
	for {
		old := sl.cur.Load()
		if old.gone {
			return false
		}
		next := merge(*old, obs)
		if next.expiry > sl.bound.Load() {
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

// raise moves the durable bound to b when b is later.
func (sl *slot) raise(b int64) {
	for {
		old := sl.bound.Load()
		if b <= old || sl.bound.CompareAndSwap(old, b) {
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
// A known address whose durable record covers the new expiry changes
// only in memory, at once. Every other address, and every new one, goes
// into the Pending, and the index does not change until Commit writes
// it. Commit the Pending, and acknowledge the answer only after Commit
// returns nil.
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
			if sl := s.index[name][a]; sl != nil && sl.refresh(obs) {
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
	st := stamp{seen: seen, expiry: exp}
	for _, name := range names {
		// A record must hold the entry: check the fields now, so that a
		// commit cannot fail for one member of a group.
		if _, err := recordOf(key{policy: name}, st); err != nil {
			return stamp{}, err
		}
	}
	return st, nil
}

// Commit writes the entries of p. It shares one sync with the other
// requests that wait at the same time, and returns the result of that
// write. After a nil return the entries are durable and in the index.
// After an error the index is as before. An empty p returns nil at once.
// It returns ctx.Err() when ctx ends first, and ErrClosed after Close;
// the commit can still happen after ctx ends.
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

// Expire removes each entry whose expiry is before At. It also removes
// each segment that holds no entry that is kept at At.
type Expire struct{ At time.Time }

// Prune removes every entry of a policy that is not in Keep. An empty
// Keep removes all entries.
type Prune struct{ Keep []policy.Name }

// Adopt writes each address in Found that the book does not hold, as an
// answer with TTL 0 at At: it gets a fresh retain period. An address
// that the book holds keeps its expiry, so an adoption at each start
// does not keep an entry forever.
type Adopt struct {
	Found map[policy.Name][]blockable.Addr
	At    time.Time
}

func (Expire) isOp() {}
func (Prune) isOp()  {}
func (Adopt) isOp()  {}

// Apply runs op on the committer, after the requests before it. It
// returns the number of entries that Expire or Prune removed, or that
// Adopt wrote.
//
// Expire and Prune change only the index: the log never records a
// removal (see the package doc). Adopt is a commit: after an error, the
// index is as before. Expire returns an error only when a segment that
// it removes stays; its count is then still right.
//
// Errors: as Commit, and the errors of Touch for the input of Adopt.
func (s *Store) Apply(ctx context.Context, op Op) (int, error) {
	switch op := op.(type) {
	case Expire:
		if _, err := nanos(op.At); err != nil {
			return 0, err
		}
	case Prune:
	case Adopt:
		for name, addrs := range op.Found {
			if _, err := s.observation([]policy.Name{name}, addrs, 0, op.At); err != nil {
				return 0, err
			}
		}
	default:
		return 0, fmt.Errorf("%w: %T", errUnknownOp, op)
	}
	return s.send(ctx, request{op: op})
}

// request is one unit of work for the committer: a group member with
// writes, or an op.
type request struct {
	writes []write
	op     Op
	reply  chan result
}

type result struct {
	n   int
	err error
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
		return res.n, res.err
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
			n, err := s.runOp(r.op)
			r.reply <- result{n, err}
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

func (s *Store) runOp(op Op) (int, error) {
	switch op := op.(type) {
	case Expire:
		at := op.At.UnixNano()
		n := s.remove(func(_ policy.Name, st *stamp) bool { return at > st.expiry })
		if err := s.dir.gc(at); err != nil {
			return n, fmt.Errorf("addrstore: remove expired segments: %w", err)
		}
		return n, nil
	case Prune:
		return s.remove(func(name policy.Name, _ *stamp) bool { return !slices.Contains(op.Keep, name) }), nil
	case Adopt:
		return s.adopt(op)
	default:
		return 0, fmt.Errorf("%w: %T", errUnknownOp, op)
	}
}

// adopt commits the addresses of op that the index does not hold.
func (s *Store) adopt(op Adopt) (int, error) {
	var writes []write
	s.mu.RLock()
	for name, addrs := range op.Found {
		// Apply checked the input, so the observation cannot fail.
		obs, _ := s.observation([]policy.Name{name}, addrs, 0, op.At) //nolint:errcheck // see above
		for _, a := range addrs {
			if sl := s.index[name][a]; sl != nil && !sl.cur.Load().gone {
				continue
			}
			writes = append(writes, write{key{name, a}, obs})
		}
	}
	s.mu.RUnlock()
	if len(writes) == 0 {
		return 0, nil
	}
	if err := s.commit(writes); err != nil {
		return 0, err
	}
	return len(writes), nil
}

// commit appends one record for each entry of writes, each merged with
// the entry in memory, syncs, and then puts them in the index. After an
// error the index is unchanged.
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
	recs := make([]lease, 0, len(merged))
	var day int64
	for k, st := range merged {
		r, err := recordOf(k, st)
		if err != nil {
			return fmt.Errorf("addrstore: commit: %w", err)
		}
		recs = append(recs, r)
		day = max(day, int64(r.minute)/(24*60))
	}
	if err := s.dir.append(recs, day, s.retain); err != nil {
		return fmt.Errorf("addrstore: commit: %w", err)
	}
	s.mu.Lock()
	for _, r := range recs {
		k, st := r.key(), merged[r.key()]
		bound := r.stamp(s.retain).expiry
		byAddr := s.index[k.policy]
		if byAddr == nil {
			byAddr = make(map[blockable.Addr]*slot)
			s.index[k.policy] = byAddr
		}
		sl := byAddr[k.addr]
		if sl == nil || sl.cur.Load().gone {
			byAddr[k.addr] = newSlot(st, bound)
			continue
		}
		// bound first: a refresh between the two steps then compares
		// with the new durable state.
		sl.raise(bound)
		sl.mergeCur(st)
	}
	s.mu.Unlock()
	s.publish()
	return nil
}

// remove marks each entry for which drop is true as gone, and then takes
// them out of the index. It returns their number.
func (s *Store) remove(drop func(policy.Name, *stamp) bool) int {
	gone := s.mark(drop)
	if len(gone) > 0 {
		s.mu.Lock()
		for _, k := range gone {
			delete(s.index[k.policy], k.addr)
			if len(s.index[k.policy]) == 0 {
				delete(s.index, k.policy)
			}
		}
		s.mu.Unlock()
	}
	// With no removal, the facts can still be behind a refresh in memory:
	// a NextExpiry before the real first expiry. New facts let the owner
	// wait for the real one.
	s.publish()
	return len(gone)
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
