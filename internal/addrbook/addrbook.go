// Package addrbook keeps the addresses that DNS answers gave for protected
// names. An address stays blocked for at least the retain time after the
// last answer that contained it.
//
// The book also keeps the alias names of those answers, as the DNS plugin
// reports them. An alias follows the same rules as an address: retain,
// expiry, the persist rule, Expire and Prune. The root name "." is never
// an alias, because the plugin never reports it, so the book refuses it.
//
// The book has no call that removes an entry because a lookup failed. An
// entry leaves only through Expire or Prune. Destinations that the
// configuration gives as CIDR or IP are not in the book.
//
// Persist rule for the caller: when Observe or ObserveAliases returns
// needSave, call Save and acknowledge only after Save succeeds. After a
// crash, an acknowledged address or alias then stays in the book for at
// least retain minus the save slack after its last answer.
package addrbook

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// maxSaveSlack caps the save slack. Observe asks for a Save only when the
// saved expiry is more than the slack behind the new expiry. This way a
// busy name does not cause a disk write for every answer. The slack is the
// smaller of this value and half of retain.
const maxSaveSlack = time.Hour

// Errors that Observe and ObserveAliases return for input they refuse.
// ObserveAliases also returns an error that wraps
// dnsname.ErrMalformedName or dnsname.ErrRootName.
var (
	ErrInvalidAddr = errors.New("addrbook: invalid address")
	ErrZonedAddr   = errors.New("addrbook: zoned address")
	ErrEmptyPolicy = errors.New("addrbook: empty policy name")
	ErrNegativeTTL = errors.New("addrbook: negative ttl")
)

// Entry is one resolved address or one alias of one policy, as Expire
// and Prune report it. An address entry has a valid Addr and a zero
// Alias. An alias entry has a non-zero Alias and an invalid Addr.
type Entry struct {
	Policy   policy.Name
	Addr     netip.Addr
	Alias    dnsname.Name
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

// AddrBook maps (policy, address) and (policy, alias) to the time of the
// last DNS answer.
//
// An AddrBook is not safe for concurrent use. Only the Reconciler
// goroutine may use it.
type AddrBook struct {
	retain  time.Duration
	now     func() time.Time
	entries map[policy.Name]map[netip.Addr]*record
	aliases map[policy.Name]map[dnsname.Name]*record
	rename  func(oldpath, newpath string) error // a seam for the crash test
}

// New returns an empty book. Retain is the floor of the keep time. Now is
// the clock; tests give a fake one.
func New(retain time.Duration, now func() time.Time) *AddrBook {
	return &AddrBook{
		retain:  retain,
		now:     now,
		entries: make(map[policy.Name]map[netip.Addr]*record),
		aliases: make(map[policy.Name]map[dnsname.Name]*record),
		rename:  osRename,
	}
}

func (b *AddrBook) saveSlack() time.Duration {
	return min(maxSaveSlack, b.retain/2)
}

// canonical returns the stored form of an address: IPv4-mapped IPv6 is
// unmapped, so one host has one key. A zone is an error. Dropping it would
// merge distinct link-local hosts into one entry.
func canonical(a netip.Addr) (netip.Addr, error) {
	switch {
	case !a.IsValid():
		return netip.Addr{}, ErrInvalidAddr
	case a.Zone() != "":
		return netip.Addr{}, ErrZonedAddr
	}
	return a.Unmap(), nil
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
func (b *AddrBook) Observe(name policy.Name, addrs []netip.Addr, ttl time.Duration) (needSave bool, err error) {
	if name == "" {
		return false, ErrEmptyPolicy
	}
	if ttl < 0 {
		return false, ErrNegativeTTL
	}
	canon := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		c, err := canonical(a)
		if err != nil {
			return false, fmt.Errorf("observe %q: %w", name, err)
		}
		canon = append(canon, c)
	}
	return observeIn(b, b.entries, name, canon, ttl), nil
}

// ObserveAliases records that an answer for the policy gave aliases with
// ttl. Each alias is a name in presentation form, as the DNS plugin
// reports it; the book keeps its canonical form (see dnsname.Parse).
// Expiry and needSave follow the rules of Observe. A malformed name or
// the root name is an error, and then ObserveAliases changes nothing.
func (b *AddrBook) ObserveAliases(name policy.Name, aliases []string, ttl time.Duration) (needSave bool, err error) {
	if name == "" {
		return false, ErrEmptyPolicy
	}
	if ttl < 0 {
		return false, ErrNegativeTTL
	}
	canon := make([]dnsname.Name, 0, len(aliases))
	for _, s := range aliases {
		n, err := dnsname.Parse(s)
		if err != nil {
			return false, fmt.Errorf("observe %q alias %q: %w", name, s, err)
		}
		canon = append(canon, n)
	}
	return observeIn(b, b.aliases, name, canon, ttl), nil
}

// observeIn applies the expiry rule and the save rule of Observe to the
// keys of one policy. The keys are valid.
func observeIn[K comparable](b *AddrBook, byPolicy map[policy.Name]map[K]*record, name policy.Name, keys []K, ttl time.Duration) (needSave bool) {
	now := b.now().Round(0) // strip the monotonic reading
	floor := now.Add(max(ttl, b.retain))
	byKey := byPolicy[name]
	if byKey == nil && len(keys) > 0 {
		byKey = make(map[K]*record)
		byPolicy[name] = byKey
	}
	for _, k := range keys {
		rec := &record{lastSeen: now, ttl: ttl, expiry: floor}
		if old, ok := byKey[k]; ok {
			rec.savedExpiry = old.savedExpiry
			if old.expiry.After(floor) {
				rec.expiry = old.expiry
			}
		}
		if rec.savedExpiry.Add(b.saveSlack()).Before(rec.expiry) {
			needSave = true
		}
		byKey[k] = rec
	}
	return needSave
}

// Addrs returns the addresses of one policy in ascending order.
func (b *AddrBook) Addrs(name policy.Name) []netip.Addr {
	out := make([]netip.Addr, 0, len(b.entries[name]))
	for a := range b.entries[name] {
		out = append(out, a)
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// Aliases returns the aliases of one policy, sorted by their String.
func (b *AddrBook) Aliases(name policy.Name) []dnsname.Name {
	out := make([]dnsname.Name, 0, len(b.aliases[name]))
	for n := range b.aliases[name] {
		out = append(out, n)
	}
	slices.SortFunc(out, compareNames)
	return out
}

// AliasPolicies returns the names of the policies that hold the alias,
// in ascending order. It costs time in proportion to the number of
// policies with aliases.
func (b *AddrBook) AliasPolicies(alias dnsname.Name) []policy.Name {
	var out []policy.Name
	for name, byAlias := range b.aliases {
		if _, ok := byAlias[alias]; ok {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

func compareNames(x, y dnsname.Name) int { return cmp.Compare(x.String(), y.String()) }

// NextExpiry returns the first instant at which an entry is expired: one
// nanosecond after the earliest expiry. Expire at that instant removes
// the entry. Aliases count as entries. The bool is false when the book
// is empty.
func (b *AddrBook) NextExpiry() (time.Time, bool) {
	first, found := earliestIn(b.entries, time.Time{}, false)
	first, found = earliestIn(b.aliases, first, found)
	return first.Add(time.Nanosecond), found
}

func earliestIn[K comparable](byPolicy map[policy.Name]map[K]*record, first time.Time, found bool) (time.Time, bool) {
	for _, byKey := range byPolicy {
		for _, r := range byKey {
			if !found || r.expiry.Before(first) {
				first, found = r.expiry, true
			}
		}
	}
	return first, found
}

// Expire removes the addresses and aliases whose expiry is before the
// clock time. It returns them sorted (see Prune).
func (b *AddrBook) Expire() []Entry {
	now := b.now()
	removed := expireIn(b.entries, now, addrEntry)
	removed = append(removed, expireIn(b.aliases, now, aliasEntry)...)
	sortEntries(removed)
	return removed
}

func expireIn[K comparable](byPolicy map[policy.Name]map[K]*record, now time.Time, entry func(policy.Name, K, *record) Entry) []Entry {
	var removed []Entry
	for name, byKey := range byPolicy {
		for k, r := range byKey {
			if now.After(r.expiry) {
				removed = append(removed, entry(name, k, r))
				delete(byKey, k)
			}
		}
		if len(byKey) == 0 {
			delete(byPolicy, name)
		}
	}
	return removed
}

// Prune removes every address and alias of a policy that is not in keep.
// An empty keep removes all of them. The result is sorted by policy;
// within a policy, addresses in ascending order come first, then aliases
// sorted by their String.
func (b *AddrBook) Prune(keep []policy.Name) []Entry {
	removed := pruneIn(b.entries, keep, addrEntry)
	removed = append(removed, pruneIn(b.aliases, keep, aliasEntry)...)
	sortEntries(removed)
	return removed
}

func pruneIn[K comparable](byPolicy map[policy.Name]map[K]*record, keep []policy.Name, entry func(policy.Name, K, *record) Entry) []Entry {
	var removed []Entry
	for name, byKey := range byPolicy {
		if slices.Contains(keep, name) {
			continue
		}
		for k, r := range byKey {
			removed = append(removed, entry(name, k, r))
		}
		delete(byPolicy, name)
	}
	return removed
}

func addrEntry(name policy.Name, a netip.Addr, r *record) Entry {
	return Entry{Policy: name, Addr: a, LastSeen: r.lastSeen, TTL: r.ttl, Expiry: r.expiry}
}

func aliasEntry(name policy.Name, n dnsname.Name, r *record) Entry {
	return Entry{Policy: name, Alias: n, LastSeen: r.lastSeen, TTL: r.ttl, Expiry: r.expiry}
}

func (b *AddrBook) isEmpty() bool {
	return len(b.entries) == 0 && len(b.aliases) == 0
}

func sortEntries(es []Entry) {
	slices.SortFunc(es, func(a, c Entry) int {
		return cmp.Or(
			cmp.Compare(a.Policy, c.Policy),
			compareBools(a.Alias != dnsname.Name{}, c.Alias != dnsname.Name{}),
			a.Addr.Compare(c.Addr),
			compareNames(a.Alias, c.Alias),
		)
	})
}

// compareBools orders false before true.
func compareBools(x, y bool) int {
	switch {
	case x == y:
		return 0
	case x:
		return 1
	default:
		return -1
	}
}
