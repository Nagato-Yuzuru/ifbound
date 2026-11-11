// Package addrbook keeps the addresses that DNS answers gave for protected
// names. An address stays blocked for at least the retain time after the
// last answer that contained it.
//
// The book has no call that removes an entry because a lookup failed. An
// entry leaves only through Expire or Prune. Destinations that the
// configuration gives as CIDR or IP are not in the book.
//
// Persist rule for the caller: when Observe returns needSave, call Save
// and acknowledge only after Save succeeds. After a crash, an
// acknowledged address then stays in the book for at least retain minus
// the save slack after its last answer.
package addrbook

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// maxSaveSlack caps the save slack. Observe asks for a Save only when the
// saved expiry is more than the slack behind the new expiry. This way a
// busy name does not cause a disk write for every answer. The slack is the
// smaller of this value and half of retain.
const maxSaveSlack = time.Hour

// Errors that Observe returns for input it refuses.
var (
	ErrEmptyPolicy = errors.New("addrbook: empty policy name")
	ErrNegativeTTL = errors.New("addrbook: negative ttl")
)

// Entry is one resolved address of one policy, as Expire and Prune
// report it.
type Entry struct {
	Policy   policy.Name
	Addr     netip.Addr
	LastSeen time.Time
	// TTL is the TTL of the last answer.
	TTL time.Duration
	// Expiry is the last instant at which the entry is still kept.
	Expiry time.Time
}

// record is the stored form of an entry; the map keys hold the rest.
type record struct {
	lastSeen time.Time
	ttl      time.Duration
	expiry   time.Time
	// savedExpiry is the expiry that the last successful Save wrote. It is
	// the zero time if the entry was never saved.
	savedExpiry time.Time
}

// AddrBook maps (policy, address) to the time of the last DNS answer.
//
// An AddrBook is not safe for concurrent use. Only the Reconciler
// goroutine may use it.
type AddrBook struct {
	retain  time.Duration
	now     func() time.Time
	entries map[policy.Name]map[blockable.Addr]*record
	rename  func(oldpath, newpath string) error // a seam for the crash test
}

// New returns an empty book. Retain is the floor of the keep time. Now is
// the clock; tests give a fake one.
func New(retain time.Duration, now func() time.Time) *AddrBook {
	return &AddrBook{
		retain:  retain,
		now:     now,
		entries: make(map[policy.Name]map[blockable.Addr]*record),
		rename:  osRename,
	}
}

func (b *AddrBook) saveSlack() time.Duration {
	return min(maxSaveSlack, b.retain/2)
}

// Observe records that an answer for the policy contained addrs with ttl.
// For each address it sets last_seen to the clock time and ttl to the
// reported ttl. The expiry becomes the later of the old expiry and
// now + max(ttl, retain), so it never moves earlier.
//
// NeedSave is true when the snapshot on disk is behind: for some address,
// the expiry in the last successful Save is more than the save slack
// before the new expiry. A failed Save changes nothing, so the retry
// still reports true. If any input is invalid, Observe changes nothing.
// The zero blockable.Addr is invalid: the error then wraps
// blockable.ErrZero.
func (b *AddrBook) Observe(name policy.Name, addrs []blockable.Addr, ttl time.Duration) (needSave bool, err error) {
	if name == "" {
		return false, ErrEmptyPolicy
	}
	if ttl < 0 {
		return false, ErrNegativeTTL
	}
	if err := blockable.Check(addrs); err != nil {
		return false, fmt.Errorf("addrbook: policy %s: %w", name, err)
	}
	now := b.now().Round(0) // strip the monotonic reading
	floor := now.Add(max(ttl, b.retain))
	byAddr := b.entries[name]
	if byAddr == nil && len(addrs) > 0 {
		byAddr = make(map[blockable.Addr]*record)
		b.entries[name] = byAddr
	}
	for _, a := range addrs {
		rec := &record{lastSeen: now, ttl: ttl, expiry: floor}
		if old, ok := byAddr[a]; ok {
			rec.savedExpiry = old.savedExpiry
			if old.expiry.After(floor) {
				rec.expiry = old.expiry
			}
		}
		if rec.savedExpiry.Add(b.saveSlack()).Before(rec.expiry) {
			needSave = true
		}
		byAddr[a] = rec
	}
	return needSave, nil
}

// Addrs returns the addresses of one policy in ascending order.
func (b *AddrBook) Addrs(name policy.Name) []blockable.Addr {
	out := make([]blockable.Addr, 0, len(b.entries[name]))
	for a := range b.entries[name] {
		out = append(out, a)
	}
	slices.SortFunc(out, blockable.Addr.Compare)
	return out
}

// Len returns the number of addresses of one policy, as len(b.Addrs(name))
// does, without a copy.
func (b *AddrBook) Len(name policy.Name) int { return len(b.entries[name]) }

// NextExpiry returns the first instant at which an entry is expired: one
// nanosecond after the earliest expiry. Expire at that instant removes
// the entry. The bool is false when the book is empty.
func (b *AddrBook) NextExpiry() (time.Time, bool) {
	var first time.Time
	found := false
	for _, byAddr := range b.entries {
		for _, r := range byAddr {
			if !found || r.expiry.Before(first) {
				first, found = r.expiry, true
			}
		}
	}
	return first.Add(time.Nanosecond), found
}

// Expire removes the entries whose expiry is before the clock time. It
// returns them sorted by policy and address.
func (b *AddrBook) Expire() []Entry {
	now := b.now()
	var removed []Entry
	for name, byAddr := range b.entries {
		for a, r := range byAddr {
			if now.After(r.expiry) {
				removed = append(removed, entryOf(name, a, r))
				delete(byAddr, a)
			}
		}
		if len(byAddr) == 0 {
			delete(b.entries, name)
		}
	}
	sortEntries(removed)
	return removed
}

// Prune removes every entry of a policy that is not in keep, sorted by
// policy and address. An empty keep removes all entries.
func (b *AddrBook) Prune(keep []policy.Name) []Entry {
	var removed []Entry
	for name, byAddr := range b.entries {
		if slices.Contains(keep, name) {
			continue
		}
		for a, r := range byAddr {
			removed = append(removed, entryOf(name, a, r))
		}
		delete(b.entries, name)
	}
	sortEntries(removed)
	return removed
}

func entryOf(name policy.Name, a blockable.Addr, r *record) Entry {
	return Entry{Policy: name, Addr: a.Addr(), LastSeen: r.lastSeen, TTL: r.ttl, Expiry: r.expiry}
}

func (b *AddrBook) isEmpty() bool {
	return len(b.entries) == 0
}

func sortEntries(es []Entry) {
	slices.SortFunc(es, func(a, c Entry) int {
		return cmp.Or(cmp.Compare(a.Policy, c.Policy), a.Addr.Compare(c.Addr))
	})
}
