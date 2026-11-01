package addrbook_test

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrbook"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

const retain = 7 * 24 * time.Hour

var (
	a1 = netip.MustParseAddr("192.0.2.1")
	a2 = netip.MustParseAddr("2001:db8::1")
	a3 = netip.MustParseAddr("192.0.2.3")
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newBook(t *testing.T) (*addrbook.AddrBook, *fakeClock) {
	t.Helper()
	c := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	return addrbook.New(retain, c.now), c
}

func observe(t *testing.T, b *addrbook.AddrBook, name policy.Name, ttl time.Duration, addrs ...netip.Addr) bool {
	t.Helper()
	need, err := b.Observe(name, addrs, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return need
}

func save(t *testing.T, b *addrbook.AddrBook, path string) {
	t.Helper()
	if err := b.Save(path); err != nil {
		t.Fatal(err)
	}
}

func restart(t *testing.T, c *fakeClock, path string) *addrbook.AddrBook {
	t.Helper()
	b := addrbook.New(retain, c.now)
	if err := b.Load(path); err != nil {
		t.Fatal(err)
	}
	return b
}

func snapPath(t *testing.T) string { return filepath.Join(t.TempDir(), "book.json") }

func TestExpiryBoundaries(t *testing.T) {
	tests := []struct {
		name string
		ttl  time.Duration
		keep time.Duration // the book must still hold the entry after this long
	}{
		{"ttl below retain", time.Minute, retain},
		{"ttl above retain", 2 * retain, 2 * retain},
		{"ttl equals retain", retain, retain},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, c := newBook(t)
			start := c.t
			observe(t, b, "p", tt.ttl, a1)
			next, _ := b.NextExpiry()
			if want := start.Add(tt.keep + time.Nanosecond); !next.Equal(want) {
				t.Fatalf("next expiry = %v, want %v", next, want)
			}
			c.advance(tt.keep) // exactly at the boundary: kept
			if got := b.Expire(); len(got) != 0 {
				t.Fatalf("expired at the boundary: %v", got)
			}
			c.advance(time.Nanosecond) // one tick after: gone
			if got := b.Expire(); len(got) != 1 || got[0].Addr != a1 {
				t.Fatalf("not expired after the boundary: %v", got)
			}
			if _, ok := b.NextExpiry(); ok {
				t.Fatal("empty book has a next expiry")
			}
		})
	}
}

func TestNextExpiryLoopConverges(t *testing.T) {
	b, c := newBook(t)
	observe(t, b, "p", 0, a1)
	c.advance(time.Hour)
	observe(t, b, "q", 3*retain, a2)
	for range 10 {
		next, ok := b.NextExpiry()
		if !ok {
			return
		}
		c.t = next // a timer that fires at the deadline
		b.Expire()
	}
	t.Fatal("loop of NextExpiry and Expire does not converge")
}

func TestObserveExtendsLastSeen(t *testing.T) {
	b, c := newBook(t)
	observe(t, b, "p", time.Minute, a1)
	c.advance(retain - time.Hour)
	observe(t, b, "p", time.Minute, a1)
	c.advance(retain) // past the first expiry, at the second
	if got := b.Expire(); len(got) != 0 {
		t.Fatalf("entry expired too early: %v", got)
	}
}

func TestObserveNeverMovesExpiryEarlier(t *testing.T) {
	b, c := newBook(t)
	start := c.t
	observe(t, b, "p", 30*24*time.Hour, a1)
	c.advance(time.Hour)
	observe(t, b, "p", time.Minute, a1)
	got, _ := b.NextExpiry()
	if want := start.Add(30*24*time.Hour + time.Nanosecond); !got.Equal(want) {
		t.Fatalf("expiry = %v, want %v", got, want)
	}
	if e := b.Prune(nil); len(e) != 1 || e[0].TTL != time.Minute {
		t.Fatalf("stored ttl must be the reported one: %v", e)
	}
	observe(t, b, "p", 40*24*time.Hour, a1)
	got, _ = b.NextExpiry()
	if want := c.t.Add(40*24*time.Hour + time.Nanosecond); !got.Equal(want) {
		t.Fatalf("expiry = %v, want %v", got, want)
	}
}

func TestHugeRetainClockStepBack(t *testing.T) {
	r := 106751 * 24 * time.Hour
	c := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	b := addrbook.New(r, c.now)
	observe(t, b, "p", 0, a1)
	before, _ := b.NextExpiry()
	c.advance(-24 * time.Hour)
	observe(t, b, "p", 0, a1)
	if after, _ := b.NextExpiry(); after.Before(before) {
		t.Fatalf("expiry moved earlier: %v -> %v", before, after)
	}
}

// The caller rule: Observe says needSave, the caller saves, and only then
// acknowledges. These tests follow it and restart after a crash.
func TestNeedSaveFailedSaveThenRetry(t *testing.T) {
	b, c := newBook(t)
	good := snapPath(t)
	save(t, b, good)
	bad := filepath.Join(t.TempDir(), "no-dir", "book.json")
	if !observe(t, b, "p", time.Minute, a1) {
		t.Fatal("new address: needSave = false")
	}
	if err := b.Save(bad); err == nil {
		t.Fatal("save to a missing directory succeeded")
	}
	if !observe(t, b, "p", time.Minute, a1) {
		t.Fatal("retry after a failed save: needSave = false")
	}
	save(t, b, good)
	if got := restart(t, c, good).Addrs("p"); !slices.Equal(got, []netip.Addr{a1}) {
		t.Fatalf("restart addrs = %v", got)
	}
}

func TestNeedSaveRefreshIsPersisted(t *testing.T) {
	b, c := newBook(t)
	path := snapPath(t)
	observe(t, b, "p", time.Minute, a1)
	save(t, b, path)
	c.advance(6 * 24 * time.Hour)
	if !observe(t, b, "p", time.Minute, a1) {
		t.Fatal("refresh after 6 days: needSave = false")
	}
	save(t, b, path)
	c.advance(2 * 24 * time.Hour) // crash 2 days after the last answer
	if got := restart(t, c, path).Expire(); len(got) != 0 {
		t.Fatalf("restart expired %v", got)
	}
}

func TestNeedSaveExpiredButPresent(t *testing.T) {
	b, c := newBook(t)
	path := snapPath(t)
	observe(t, b, "p", time.Minute, a1)
	save(t, b, path)
	c.advance(retain + time.Hour) // the expiry timer is late
	if !observe(t, b, "p", time.Minute, a1) {
		t.Fatal("observe of an expired entry: needSave = false")
	}
	save(t, b, path)
	c.advance(time.Minute)
	if got := restart(t, c, path).Expire(); len(got) != 0 {
		t.Fatalf("restart expired %v", got)
	}
}

func TestNeedSaveSlack(t *testing.T) {
	b, c := newBook(t)
	observe(t, b, "p", 0, a1)
	save(t, b, snapPath(t))
	c.advance(30 * time.Minute)
	if observe(t, b, "p", 0, a1) {
		t.Fatal("expiry moved by 30m, inside the 1h slack: needSave = true")
	}
	c.advance(40 * time.Minute) // 70m after the saved expiry base
	if !observe(t, b, "p", 0, a1) {
		t.Fatal("expiry moved by 70m, past the slack: needSave = false")
	}
}

func TestObserveRefusesBadInput(t *testing.T) {
	b, _ := newBook(t)
	tests := []struct {
		name  string
		pol   policy.Name
		addrs []netip.Addr
		ttl   time.Duration
		want  error
	}{
		{"empty policy", "", []netip.Addr{a1}, 0, addrbook.ErrEmptyPolicy},
		{"invalid addr", "p", []netip.Addr{a2, {}}, 0, addrbook.ErrInvalidAddr},
		{"zoned addr", "p", []netip.Addr{a2, netip.MustParseAddr("fe80::1%en0")}, 0, addrbook.ErrZonedAddr},
		{"negative ttl", "p", []netip.Addr{a2}, -1, addrbook.ErrNegativeTTL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := b.Observe(tt.pol, tt.addrs, tt.ttl); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if len(b.Addrs("p")) != 0 {
				t.Fatal("refused observe changed the book")
			}
		})
	}
}

func TestObserveUnmapsIPv4InIPv6(t *testing.T) {
	b, _ := newBook(t)
	observe(t, b, "p", 0, netip.MustParseAddr("::ffff:192.0.2.1"), a1)
	if got := b.Addrs("p"); !slices.Equal(got, []netip.Addr{a1}) {
		t.Fatalf("addrs = %v", got)
	}
}

func TestExpireAndPruneAreSorted(t *testing.T) {
	fill := func() *addrbook.AddrBook {
		b, _ := newBook(t)
		for _, n := range []policy.Name{"d", "b", "a", "c"} {
			observe(t, b, n, 0, a3, a2, a1)
		}
		return b
	}
	sorted := func(es []addrbook.Entry) bool {
		return slices.IsSortedFunc(es, func(x, y addrbook.Entry) int {
			if x.Policy != y.Policy {
				return strings.Compare(string(x.Policy), string(y.Policy))
			}
			return x.Addr.Compare(y.Addr)
		})
	}
	b := fill()
	if got := b.Prune([]policy.Name{"c"}); len(got) != 9 || !sorted(got) {
		t.Fatalf("prune: %d entries, sorted=%v", len(got), sorted(got))
	}
	if got := b.Addrs("c"); len(got) != 3 || !slices.IsSortedFunc(got, netip.Addr.Compare) {
		t.Fatalf("addrs = %v", got)
	}
	if got := b.Addrs("a"); len(got) != 0 {
		t.Fatalf("pruned policy still has %v", got)
	}
	b = fill()
	b.Prune(nil)
	if len(b.Addrs("a")) != 0 {
		t.Fatal("prune(nil) keeps entries")
	}
	bb, cc := newBook(t)
	for _, n := range []policy.Name{"d", "b", "a", "c"} {
		observe(t, bb, n, 0, a3, a2, a1)
	}
	cc.advance(retain + time.Second)
	if got := bb.Expire(); len(got) != 12 || !sorted(got) {
		t.Fatalf("expire: %d entries, sorted=%v", len(got), sorted(got))
	}
}

func TestEntriesCarryNoMonotonicReading(t *testing.T) {
	b := addrbook.New(retain, time.Now) // time.Now carries a monotonic reading
	observe(t, b, "p", 0, a1)
	got := b.Prune(nil)
	if len(got) != 1 || strings.Contains(got[0].LastSeen.String(), "m=") {
		t.Fatalf("last_seen keeps a monotonic reading: %v", got)
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	b, c := newBook(t)
	observe(t, b, "p", time.Minute, a1, a2)
	observe(t, b, "q", 30*24*time.Hour, a1)
	path := snapPath(t)
	save(t, b, path)
	b2 := restart(t, c, path)
	for _, n := range []policy.Name{"p", "q"} {
		if !slices.Equal(b2.Addrs(n), b.Addrs(n)) {
			t.Fatalf("addrs of %s differ after load", n)
		}
	}
	n1, _ := b.NextExpiry()
	n2, _ := b2.NextExpiry()
	if !n1.Equal(n2) {
		t.Fatalf("next expiry %v != %v", n2, n1)
	}
	e1, e2 := b.Prune(nil), b2.Prune(nil)
	if len(e1) != len(e2) {
		t.Fatal("entry count differs")
	}
	for i := range e1 {
		if e1[i].TTL != e2[i].TTL || !e1[i].LastSeen.Equal(e2[i].LastSeen) || !e1[i].Expiry.Equal(e2[i].Expiry) {
			t.Fatalf("entry %d differs: %v vs %v", i, e1[i], e2[i])
		}
	}
}

func TestLoadKeepsExpiredEntriesUntilExpire(t *testing.T) {
	b, c := newBook(t)
	observe(t, b, "p", time.Minute, a1, a2)
	observe(t, b, "q", 30*24*time.Hour, a1)
	path := snapPath(t)
	save(t, b, path)
	c.advance(2 * retain)
	b2 := restart(t, c, path)
	if len(b2.Addrs("p")) != 2 {
		t.Fatal("load dropped expired entries")
	}
	if got := b2.Expire(); len(got) != 2 {
		t.Fatalf("expire removed %v", got)
	}
}

func TestLoadRaisesExpiryWhenRetainGrew(t *testing.T) {
	b, c := newBook(t)
	start := c.t
	observe(t, b, "p", 0, a1)
	path := snapPath(t)
	save(t, b, path)
	b2 := addrbook.New(2*retain, c.now)
	if err := b2.Load(path); err != nil {
		t.Fatal(err)
	}
	next, _ := b2.NextExpiry()
	if want := start.Add(2*retain + time.Nanosecond); !next.Equal(want) {
		t.Fatalf("next expiry = %v, want %v", next, want)
	}
}

func TestLoadIntoNonEmptyBookFails(t *testing.T) {
	b, _ := newBook(t)
	path := snapPath(t)
	save(t, b, path)
	observe(t, b, "p", 0, a1)
	if err := b.Load(path); !errors.Is(err, addrbook.ErrNotEmpty) {
		t.Fatalf("err = %v", err)
	}
	if len(b.Addrs("p")) != 1 {
		t.Fatal("failed load changed the book")
	}
}

func TestLoadMissingFile(t *testing.T) {
	b, _ := newBook(t)
	if err := b.Load(snapPath(t)); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.NextExpiry(); ok {
		t.Fatal("book not empty")
	}
}

func TestLoadPathErrors(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	b0, _ := newBook(t)
	save(t, b0, good)
	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, "dangling.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(good, filepath.Join(dir, "link.json")); err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{
		"missing parent":  filepath.Join(dir, "no-dir", "book.json"),
		"dangling link":   filepath.Join(dir, "dangling.json"),
		"symlink to file": filepath.Join(dir, "link.json"),
		"directory":       dir,
		"parent is file":  filepath.Join(good, "book.json"),
	}
	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			b, _ := newBook(t)
			if err := b.Load(path); err == nil {
				t.Fatal("load succeeded")
			}
		})
	}
	t.Run("unreadable file", func(t *testing.T) {
		p := filepath.Join(dir, "secret.json")
		if err := os.WriteFile(p, []byte("{}"), 0o000); err != nil {
			t.Fatal(err)
		}
		b, _ := newBook(t)
		if os.Geteuid() != 0 && b.Load(p) == nil {
			t.Fatal("read error became an empty book")
		}
	})
}

func entryJSON(mods ...func(map[string]any)) string {
	m := map[string]any{
		"policy": "p", "addr": "192.0.2.1",
		"last_seen_unix_nano": 1, "ttl_nano": 0, "expiry_unix_nano": 2,
	}
	for _, f := range mods {
		f(m)
	}
	out, _ := json.Marshal(m) //nolint:errcheck // the map holds only JSON-safe values, so Marshal cannot fail
	return string(out)
}

func with(k string, v any) func(map[string]any) {
	return func(m map[string]any) { m[k] = v }
}

func without(k string) func(map[string]any) {
	return func(m map[string]any) { delete(m, k) }
}

func doc(entries ...string) string {
	return `{"version":1,"entries":[` + strings.Join(entries, ",") + `]}`
}

func TestLoadRejectsBadSnapshots(t *testing.T) {
	tests := map[string]string{
		"malformed":         `{"version":1,`,
		"empty file":        ``,
		"not an object":     `[]`,
		"unknown version":   `{"version":99,"entries":[]}`,
		"missing version":   `{"entries":[]}`,
		"missing entries":   `{"version":1}`,
		"null entries":      `{"version":1,"entries":null}`,
		"duplicate entries": `{"version":1,"entries":[],"entries":[]}`,
		"duplicate version": `{"version":1,"version":1,"entries":[]}`,
		"unknown field":     `{"version":1,"entries":[],"x":1}`,
		"upper-case keys":   `{"VERSION":1,"ENTRIES":[]}`,
		"trailing bracket":  `{"version":1,"entries":[]}]`,
		"trailing brace":    `{"version":1,"entries":[]}}`,
		"trailing doc":      `{"version":1,"entries":[]} {}`,
		"entry unknown key": doc(entryJSON(with("x", 1))),
		"entry case key":    doc(strings.Replace(entryJSON(), `"policy"`, `"Policy"`, 1)),
		"entry dup key":     doc(strings.Replace(entryJSON(), `"ttl_nano":0`, `"ttl_nano":0,"ttl_nano":0`, 1)),
		"missing expiry":    doc(entryJSON(without("expiry_unix_nano"))),
		"null ttl":          doc(entryJSON(with("ttl_nano", nil))),
		"empty policy":      doc(entryJSON(with("policy", ""))),
		"bad addr":          doc(entryJSON(with("addr", "nope"))),
		"empty addr":        doc(entryJSON(with("addr", ""))),
		"mapped addr":       doc(entryJSON(with("addr", "::ffff:192.0.2.1"))),
		"zoned addr":        doc(entryJSON(with("addr", "fe80::1%en0"))),
		"negative ttl":      doc(entryJSON(with("ttl_nano", -1))),
		"expiry < seen":     doc(entryJSON(with("expiry_unix_nano", 0))),
		"duplicate entry":   doc(entryJSON(), entryJSON()),
		"one bad of two":    doc(entryJSON(), entryJSON(with("policy", ""), with("addr", "192.0.2.2"))),
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			path := snapPath(t)
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			b, _ := newBook(t)
			err := b.Load(path)
			if !errors.Is(err, addrbook.ErrSnapshot) {
				t.Fatalf("err = %v, want ErrSnapshot", err)
			}
			if _, ok := b.NextExpiry(); ok {
				t.Fatal("failed load changed the book")
			}
		})
	}
}

func TestSaveWritesSortedEntries(t *testing.T) {
	b, _ := newBook(t)
	for _, n := range []policy.Name{"d", "b", "a", "c"} {
		observe(t, b, n, 0, a3, a2, a1)
	}
	path := snapPath(t)
	save(t, b, path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Entries []struct {
			Policy string
			Addr   netip.Addr
		}
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if !slices.IsSortedFunc(f.Entries, func(x, y struct {
		Policy string
		Addr   netip.Addr
	}) int {
		if x.Policy != y.Policy {
			return strings.Compare(x.Policy, y.Policy)
		}
		return x.Addr.Compare(y.Addr)
	}) || len(f.Entries) != 12 {
		t.Fatalf("snapshot is not sorted: %s", data)
	}
}

func TestSaveRefusesOutOfRangeTime(t *testing.T) {
	for _, when := range []time.Time{time.Date(2300, 1, 1, 0, 0, 0, 0, time.UTC), {}} {
		c := &fakeClock{t: when}
		b := addrbook.New(retain, c.now)
		observe(t, b, "p", 0, a1)
		path := snapPath(t)
		if err := b.Save(path); !errors.Is(err, addrbook.ErrTimeRange) {
			t.Fatalf("clock %v: err = %v", when, err)
		}
		ents, err := os.ReadDir(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if len(ents) != 0 {
			t.Fatalf("clock %v: save wrote %v", when, ents)
		}
	}
}

func TestSaveRefusesSymlinkPath(t *testing.T) {
	b, _ := newBook(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "book.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := b.Save(link); !errors.Is(err, addrbook.ErrBadPath) {
		t.Fatalf("err = %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep" {
		t.Fatal("save wrote through the symlink")
	}
}

func TestSaveLeavesNoTempFile(t *testing.T) {
	b, _ := newBook(t)
	dir := t.TempDir()
	save(t, b, filepath.Join(dir, "book.json"))
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) != 1 {
		t.Fatalf("dir = %v, %v", ents, err)
	}
}

// Len counts what Addrs returns through Observe, a duplicate address,
// Expire, and Prune.
func TestLenCountsTheAddressesOfAPolicy(t *testing.T) {
	b, c := newBook(t)
	check := func(when string) {
		t.Helper()
		for _, n := range []policy.Name{"p", "q", "none"} {
			if got, want := b.Len(n), len(b.Addrs(n)); got != want {
				t.Errorf("%s: Len(%s) = %d, want %d", when, n, got, want)
			}
		}
	}
	check("empty")
	observe(t, b, "p", 0, a1, a2)
	observe(t, b, "p", 0, a1)
	observe(t, b, "q", 0, a3)
	check("observed")
	if b.Len("p") != 2 || b.Len("q") != 1 {
		t.Fatalf("Len = %d, %d, want 2, 1", b.Len("p"), b.Len("q"))
	}
	c.advance(retain / 2)
	observe(t, b, "p", 0, a1)
	c.advance(retain/2 + time.Second)
	b.Expire()
	check("expired")
	if b.Len("p") != 1 || b.Len("q") != 0 {
		t.Fatalf("after Expire: Len = %d, %d, want 1, 0", b.Len("p"), b.Len("q"))
	}
	b.Prune(nil)
	check("pruned")
}
