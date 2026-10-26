package addrbook_test

// Behavior tests through the public API only.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
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

var oT0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func oBook(r time.Duration) (*addrbook.AddrBook, *fakeClock) {
	c := &fakeClock{t: oT0}
	return addrbook.New(r, c.now), c
}

func mustObserve(t *testing.T, b *addrbook.AddrBook, name policy.Name, ttl time.Duration, addrs ...netip.Addr) bool {
	t.Helper()
	need, err := b.Observe(name, addrs, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return need
}

func TestNeedSaveSlackEdge(t *testing.T) {
	for _, r := range []time.Duration{2 * time.Second, 30 * time.Minute, 2 * time.Hour, retain} {
		t.Run(r.String(), func(t *testing.T) {
			slack := min(time.Hour, r/2)
			b, c := oBook(r)
			path := snapPath(t)
			if !mustObserve(t, b, "p", 0, a1) {
				t.Fatal("never saved: needSave = false")
			}
			save(t, b, path)
			c.advance(slack) // saved + slack == new expiry: not behind
			if mustObserve(t, b, "p", 0, a1) {
				t.Fatal("new expiry == saved + slack: needSave = true")
			}
			c.advance(time.Nanosecond) // one tick past
			if !mustObserve(t, b, "p", 0, a1) {
				t.Fatal("new expiry == saved + slack + 1ns: needSave = false")
			}
			// A failed Save changes nothing.
			if err := b.Save(filepath.Join(t.TempDir(), "missing", "b.json")); err == nil {
				t.Fatal("save to a missing dir succeeded")
			}
			if !mustObserve(t, b, "p", 0, a1) {
				t.Fatal("after a failed Save: needSave = false")
			}
			save(t, b, path)
			if mustObserve(t, b, "p", 0, a1) {
				t.Fatal("after a successful Save: needSave = true")
			}
		})
	}
}

func TestExpiryRule(t *testing.T) {
	tests := []struct {
		name     string
		ttl      time.Duration
		wantKeep time.Duration
	}{
		{"ttl 0", 0, retain},
		{"ttl < retain", time.Hour, retain},
		{"ttl > retain", retain + time.Hour, retain + time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, c := oBook(retain)
			mustObserve(t, b, "p", tt.ttl, a1)
			e := b.Prune(nil)
			if len(e) != 1 || !e[0].Expiry.Equal(oT0.Add(tt.wantKeep)) || e[0].TTL != tt.ttl ||
				!e[0].LastSeen.Equal(oT0) || e[0].Policy != "p" || e[0].Addr != a1 {
				t.Fatalf("entry = %+v", e)
			}
			_ = c
		})
	}
}

func TestExpiryNeverEarlierClockBack(t *testing.T) {
	b, c := oBook(retain)
	mustObserve(t, b, "p", 30*24*time.Hour, a1)
	c.advance(-48 * time.Hour)
	mustObserve(t, b, "p", 0, a1)
	e := b.Prune(nil)
	if len(e) != 1 || !e[0].Expiry.Equal(oT0.Add(30*24*time.Hour)) || e[0].TTL != 0 || !e[0].LastSeen.Equal(oT0.Add(-48*time.Hour)) {
		t.Fatalf("entry = %+v", e)
	}
}

func TestNoOverflow(t *testing.T) {
	far := time.Unix(math.MaxInt64/2, 0) // far beyond year 2262
	cases := []struct {
		name  string
		start time.Time
		r     time.Duration
		ttl   time.Duration
		steps []time.Duration
	}{
		{"max retain", oT0, math.MaxInt64, 0, []time.Duration{-math.MaxInt64, math.MaxInt64}},
		{"max ttl", oT0, retain, math.MaxInt64, []time.Duration{math.MaxInt64, -math.MaxInt64}},
		{"clock far future", far, math.MaxInt64, math.MaxInt64, []time.Duration{math.MaxInt64, math.MaxInt64}},
		{"clock far past", time.Unix(-math.MaxInt64/2, 0), math.MaxInt64, 0, []time.Duration{-math.MaxInt64}},
		// The end of time.Time: Add saturates, so the expiry may equal now.
		{"clock at end of time", time.Unix(math.MaxInt64-62135596800-5, 0), math.MaxInt64, math.MaxInt64, []time.Duration{math.MaxInt64, -time.Hour}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := &fakeClock{t: tt.start}
			b := addrbook.New(tt.r, c.now)
			var prev time.Time
			for i, d := range append([]time.Duration{0}, tt.steps...) {
				c.advance(d)
				mustObserve(t, b, "p", tt.ttl, a1)
				next, ok := b.NextExpiry()
				if !ok || next.Before(c.t) || (tt.name != "clock at end of time" && !next.After(c.t)) {
					t.Fatalf("step %d: next expiry %v not after now %v", i, next, c.t)
				}
				if i > 0 && next.Before(prev) {
					t.Fatalf("step %d: expiry moved earlier %v -> %v", i, prev, next)
				}
				prev = next
				if got := b.Expire(); len(got) != 0 {
					t.Fatalf("step %d: fresh entry expired: %v", i, got)
				}
			}
		})
	}
}

func TestNextExpiryIsFirstExpiredInstant(t *testing.T) {
	b, c := oBook(retain)
	mustObserve(t, b, "p", 0, a1)
	c.advance(time.Hour)
	mustObserve(t, b, "q", 2*retain, a2)
	mustObserve(t, b, "q", 0, a3)
	next, ok := b.NextExpiry()
	if !ok || !next.Equal(oT0.Add(retain+time.Nanosecond)) {
		t.Fatalf("next = %v %v", next, ok)
	}
	c.t = next.Add(-time.Nanosecond)
	if got := b.Expire(); len(got) != 0 {
		t.Fatalf("expired before NextExpiry: %v", got)
	}
	c.t = next
	if got := b.Expire(); len(got) != 1 || got[0].Addr != a1 {
		t.Fatalf("Expire at NextExpiry = %v", got)
	}
	for i := 0; ; i++ {
		n, ok := b.NextExpiry()
		if !ok {
			break
		}
		if i > 3 {
			t.Fatal("loop does not converge")
		}
		c.t = n
		if len(b.Expire()) == 0 {
			t.Fatalf("Expire at NextExpiry %v removed nothing", n)
		}
	}
	if _, ok := b.NextExpiry(); ok {
		t.Fatal("empty book has a next expiry")
	}
}

func TestSortedAndPruneNil(t *testing.T) {
	addrs := []netip.Addr{a2, a3, a1, netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("::1")}
	want := slices.Clone(addrs)
	slices.SortFunc(want, netip.Addr.Compare)
	for range 20 {
		b, c := oBook(retain)
		for _, p := range []policy.Name{"z", "a", "m"} {
			mustObserve(t, b, p, 0, addrs...)
		}
		if got := b.Addrs("m"); !slices.Equal(got, want) {
			t.Fatalf("Addrs = %v", got)
		}
		c.advance(retain + 1)
		got := b.Expire()
		if len(got) != 15 || !slices.IsSortedFunc(got, cmpEntry) {
			t.Fatalf("Expire not sorted: %v", got)
		}
		for _, p := range []policy.Name{"z", "a", "m"} {
			mustObserve(t, b, p, 0, addrs...)
		}
		pr := b.Prune([]policy.Name{"m"})
		if len(pr) != 10 || !slices.IsSortedFunc(pr, cmpEntry) || pr[0].Policy != "a" || pr[9].Policy != "z" {
			t.Fatalf("Prune = %v", pr)
		}
		if len(b.Addrs("m")) != 5 {
			t.Fatal("Prune removed a kept policy")
		}
		if len(b.Prune(nil)) != 5 || len(b.Addrs("m")) != 0 {
			t.Fatal("Prune(nil) did not empty the book")
		}
		if _, ok := b.NextExpiry(); ok {
			t.Fatal("book not empty after Prune(nil)")
		}
	}
}

func cmpEntry(x, y addrbook.Entry) int {
	if c := strings.Compare(string(x.Policy), string(y.Policy)); c != 0 {
		return c
	}
	return x.Addr.Compare(y.Addr)
}

func validSnapshot(t *testing.T) []byte {
	t.Helper()
	b, _ := oBook(retain)
	mustObserve(t, b, "p", time.Minute, a1, a2)
	mustObserve(t, b, "q", 0, a3)
	path := snapPath(t)
	save(t, b, path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestLoadPaths(t *testing.T) {
	data := validSnapshot(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, data, 0o600); err != nil {
		t.Fatal(err)
	}
	mk := func(f func(p string)) string {
		p := filepath.Join(t.TempDir(), "book.json")
		f(p)
		return p
	}
	errCases := map[string]string{
		"dangling symlink": mk(func(p string) { must(t, os.Symlink(filepath.Join(dir, "nope"), p)) }),
		"symlink to file":  mk(func(p string) { must(t, os.Symlink(good, p)) }),
		"missing parent":   filepath.Join(dir, "nodir", "book.json"),
		"parent is file":   filepath.Join(good, "book.json"),
		"directory":        mk(func(p string) { must(t, os.Mkdir(p, 0o700)) }),
		"unreadable":       mk(func(p string) { must(t, os.WriteFile(p, data, 0o000)) }),
	}
	for name, p := range errCases {
		t.Run(name, func(t *testing.T) {
			b, _ := oBook(retain)
			if err := b.Load(p); err == nil {
				t.Fatalf("Load(%s) = nil", p)
			}
			if _, ok := b.NextExpiry(); ok {
				t.Fatal("failed Load changed the book")
			}
		})
	}
	t.Run("missing file in existing dir", func(t *testing.T) {
		b, _ := oBook(retain)
		if err := b.Load(filepath.Join(dir, "absent.json")); err != nil {
			t.Fatal(err)
		}
		if _, ok := b.NextExpiry(); ok {
			t.Fatal("book not empty")
		}
	})
	t.Run("non-empty book", func(t *testing.T) {
		b, _ := oBook(retain)
		mustObserve(t, b, "x", 0, a1)
		if err := b.Load(good); !errors.Is(err, addrbook.ErrNotEmpty) {
			t.Fatalf("err = %v", err)
		}
		if got := b.Addrs("x"); !slices.Equal(got, []netip.Addr{a1}) || len(b.Addrs("p")) != 0 {
			t.Fatal("failed Load changed the book")
		}
	})
	t.Run("good", func(t *testing.T) {
		b, _ := oBook(retain)
		must(t, b.Load(good))
		if !slices.Equal(b.Addrs("p"), []netip.Addr{a1, a2}) || !slices.Equal(b.Addrs("q"), []netip.Addr{a3}) {
			t.Fatal("round trip lost entries")
		}
	})
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestLoadStrictDecode(t *testing.T) {
	const ok = `{"policy":"p","addr":"192.0.2.1","last_seen_unix_nano":1,"ttl_nano":0,"expiry_unix_nano":2}`
	repl := func(old, new string) string { return strings.Replace(ok, old, new, 1) }
	docs := map[string]string{
		"Version case":       `{"Version":1,"entries":[]}`,
		"Entries case":       `{"version":1,"Entries":[]}`,
		"unknown top key":    `{"version":1,"entries":[],"x":1}`,
		"dup version":        `{"version":1,"version":1,"entries":[]}`,
		"dup entries":        `{"version":1,"entries":[` + ok + `],"entries":[]}`,
		"missing version":    `{"entries":[]}`,
		"missing entries":    `{"version":1}`,
		"null entries":       `{"version":1,"entries":null}`,
		"entries object":     `{"version":1,"entries":{}}`,
		"version 99":         `{"version":99,"entries":[]}`,
		"version 0":          `{"version":0,"entries":[]}`,
		"version string":     `{"version":"1","entries":[]}`,
		"version float":      `{"version":1.0,"entries":[]}`,
		"version null":       `{"version":null,"entries":[]}`,
		"trailing garbage":   `{"version":1,"entries":[]}x`,
		"trailing object":    `{"version":1,"entries":[]}{}`,
		"top null":           `null`,
		"top array":          `[]`,
		"empty file":         ``,
		"null item":          `{"version":1,"entries":[null]}`,
		"array item":         `{"version":1,"entries":[[]]}`,
		"trailing comma":     `{"version":1,"entries":[],}`,
		"missing comma":      `{"version":1 "entries":[]}`,
		"Policy case":        `{"version":1,"entries":[` + repl(`"policy"`, `"Policy"`) + `]}`,
		"entry dup key":      `{"version":1,"entries":[` + repl(`"ttl_nano":0`, `"ttl_nano":0,"ttl_nano":0`) + `]}`,
		"entry unknown key":  `{"version":1,"entries":[` + repl(`"ttl_nano":0`, `"ttl_nano":0,"x":0`) + `]}`,
		"expiry < last_seen": `{"version":1,"entries":[` + repl(`"expiry_unix_nano":2`, `"expiry_unix_nano":0`) + `]}`,
		"bad addr":           `{"version":1,"entries":[` + repl(`192.0.2.1`, `192.0.2`) + `]}`,
		"zoned addr":         `{"version":1,"entries":[` + repl(`192.0.2.1`, `fe80::1%en0`) + `]}`,
		"4in6 addr":          `{"version":1,"entries":[` + repl(`192.0.2.1`, `::ffff:192.0.2.1`) + `]}`,
		"empty addr":         `{"version":1,"entries":[` + repl(`192.0.2.1`, ``) + `]}`,
		"empty policy":       `{"version":1,"entries":[` + repl(`"p"`, `""`) + `]}`,
		"negative ttl":       `{"version":1,"entries":[` + repl(`"ttl_nano":0`, `"ttl_nano":-1`) + `]}`,
		"string ttl":         `{"version":1,"entries":[` + repl(`"ttl_nano":0`, `"ttl_nano":"0"`) + `]}`,
		"float ttl":          `{"version":1,"entries":[` + repl(`"ttl_nano":0`, `"ttl_nano":0.5`) + `]}`,
		"overflow seen":      `{"version":1,"entries":[` + repl(`"last_seen_unix_nano":1`, `"last_seen_unix_nano":9223372036854775808`) + `]}`,
		"duplicate entry":    `{"version":1,"entries":[` + ok + `,` + ok + `]}`,
		"dup via 4in6 canon": `{"version":1,"entries":[` + ok + `,` + repl(`192.0.2.1`, `::ffff:192.0.2.1`) + `]}`,
	}
	for _, f := range []string{"policy", "addr", "last_seen_unix_nano", "ttl_nano", "expiry_unix_nano"} {
		var m map[string]any
		must(t, json.Unmarshal([]byte(ok), &m))
		delete(m, f)
		bs, err := json.Marshal(m)
		must(t, err)
		docs["missing "+f] = `{"version":1,"entries":[` + string(bs) + `]}`
		m2 := map[string]any{}
		must(t, json.Unmarshal([]byte(ok), &m2))
		m2[f] = nil
		bs, err = json.Marshal(m2)
		must(t, err)
		docs["null "+f] = `{"version":1,"entries":[` + string(bs) + `]}`
	}
	dir := t.TempDir()
	// Green: the near-miss documents load.
	for name, d := range map[string]string{
		"empty entries": `{"version":1,"entries":[]}`,
		"one entry":     `{"version":1,"entries":[` + ok + `]}`,
		"whitespace":    " {\n\"version\" : 1 , \"entries\" : [ " + ok + " ] }\n",
		"expiry==seen":  `{"version":1,"entries":[` + repl(`"expiry_unix_nano":2`, `"expiry_unix_nano":1`) + `]}`,
	} {
		p := filepath.Join(dir, "g"+fmt.Sprint(len(name))+strings.ReplaceAll(name, " ", "_"))
		must(t, os.WriteFile(p, []byte(d), 0o600))
		b, _ := oBook(retain)
		if err := b.Load(p); err != nil {
			t.Errorf("green %s: %v", name, err)
		}
	}
	for name, d := range docs {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "book.json")
			must(t, os.WriteFile(p, []byte(d), 0o600))
			b, _ := oBook(retain)
			err := b.Load(p)
			if err == nil {
				t.Fatalf("Load accepted %s", d)
			}
			if _, ok := b.NextExpiry(); ok {
				t.Fatal("failed Load changed the book")
			}
		})
	}
}

func TestLoadTruncatedPrefixes(t *testing.T) {
	data := validSnapshot(t)
	dir := t.TempDir()
	for n := range len(data) {
		p := filepath.Join(dir, fmt.Sprintf("t%d", n))
		must(t, os.WriteFile(p, data[:n], 0o600))
		b, _ := oBook(retain)
		if err := b.Load(p); err == nil {
			t.Fatalf("prefix of %d/%d bytes loaded: %q", n, len(data), data[:n])
		}
		if _, ok := b.NextExpiry(); ok {
			t.Fatalf("prefix %d: failed Load changed the book", n)
		}
	}
}

func TestLoadRaisesExpiryForGrownRetain(t *testing.T) {
	b, _ := oBook(time.Hour)
	mustObserve(t, b, "p", time.Minute, a1)
	path := snapPath(t)
	save(t, b, path)
	big, _ := oBook(retain)
	must(t, big.Load(path))
	if e := big.Prune(nil); len(e) != 1 || !e[0].Expiry.Equal(oT0.Add(retain)) || e[0].TTL != time.Minute {
		t.Fatalf("raised entry = %+v", e)
	}
	small, _ := oBook(time.Minute)
	must(t, small.Load(path))
	if e := small.Prune(nil); len(e) != 1 || !e[0].Expiry.Equal(oT0.Add(time.Hour)) {
		t.Fatalf("shrunk retain moved expiry: %+v", e)
	}
}

func TestSaveRefusals(t *testing.T) {
	t.Run("out of range time", func(t *testing.T) {
		c := &fakeClock{t: time.Date(2300, 1, 1, 0, 0, 0, 0, time.UTC)}
		b := addrbook.New(retain, c.now)
		mustObserve(t, b, "p", 0, a1)
		dir := t.TempDir()
		if err := b.Save(filepath.Join(dir, "b.json")); !errors.Is(err, addrbook.ErrTimeRange) {
			t.Fatalf("err = %v", err)
		}
		ents, err := os.ReadDir(dir)
		must(t, err)
		if len(ents) != 0 {
			t.Fatalf("files written: %v", ents)
		}
	})
	t.Run("expiry just past range", func(t *testing.T) {
		c := &fakeClock{t: time.Unix(0, math.MaxInt64-int64(retain)+1)}
		b := addrbook.New(retain, c.now)
		mustObserve(t, b, "p", 0, a1)
		if err := b.Save(filepath.Join(t.TempDir(), "b.json")); !errors.Is(err, addrbook.ErrTimeRange) {
			t.Fatalf("err = %v", err)
		}
		c.t = time.Unix(0, math.MaxInt64-int64(retain))
		b2 := addrbook.New(retain, c.now)
		mustObserve(t, b2, "p", 0, a1)
		if err := b2.Save(filepath.Join(t.TempDir(), "b.json")); err != nil {
			t.Fatalf("expiry at the max: %v", err)
		}
	})
	t.Run("symlink at path", func(t *testing.T) {
		b, _ := oBook(retain)
		mustObserve(t, b, "p", 0, a1)
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		must(t, os.WriteFile(target, []byte("keep"), 0o600))
		link := filepath.Join(dir, "b.json")
		must(t, os.Symlink(target, link))
		if err := b.Save(link); !errors.Is(err, addrbook.ErrBadPath) {
			t.Fatalf("err = %v", err)
		}
		d, err := os.ReadFile(target)
		must(t, err)
		if string(d) != "keep" {
			t.Fatal("symlink target overwritten")
		}
		ents, err := os.ReadDir(dir)
		must(t, err)
		if len(ents) != 2 {
			t.Fatalf("files written: %v", ents)
		}
		if !mustObserve(t, b, "p", 0, a1) {
			t.Fatal("refused Save moved the saved expiry")
		}
	})
}

func TestSaveTempCleanupScope(t *testing.T) {
	cases := []tempCase{
		{"plain", "book.json",
			[]string{"book.json.addrbook-tmp-1", "book.json.addrbook-tmp-"},
			[]string{"book.json.bak", "other.json.addrbook-tmp-1", "book.json.addrbook-tm", "xbook.json.addrbook-tmp-1"}},
	}
	runTempCleanup(t, cases)
	// A second book in the same directory: its temp files are foreign.
	t.Run("two books", func(t *testing.T) {
		dir := t.TempDir()
		other := filepath.Join(dir, "other.json.addrbook-tmp-9")
		must(t, os.WriteFile(other, []byte("x"), 0o600))
		b, _ := oBook(retain)
		mustObserve(t, b, "p", 0, a1)
		save(t, b, filepath.Join(dir, "book.json"))
		if _, err := os.Stat(other); err != nil {
			t.Fatal("Save removed the temp file of another book")
		}
	})
}

type tempCase struct {
	name   string
	base   string
	remove []string
	keep   []string
}

func runTempCleanup(t *testing.T, cases []tempCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, f := range append(slices.Clone(tt.remove), tt.keep...) {
				must(t, os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600))
			}
			b, _ := oBook(retain)
			mustObserve(t, b, "p", 0, a1)
			if err := b.Save(filepath.Join(dir, tt.base)); err != nil {
				t.Fatalf("Save: %v", err)
			}
			checkTemps(t, dir, tt)
		})
	}
}

func checkTemps(t *testing.T, dir string, tt tempCase) {
	t.Helper()
	for _, f := range tt.keep {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("foreign file %s removed", f)
		}
	}
	for _, f := range tt.remove {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			t.Errorf("own temp %s kept", f)
		}
	}
}

// DEFECT: removeTemps passes the snapshot path to filepath.Glob, so glob
// metacharacters in the path select other files or fail every Save.
func TestDefectTempGlob(t *testing.T) {
	runTempCleanup(t, []tempCase{
		{"star in name", "b*.json",
			[]string{"b*.json.addrbook-tmp-1"},
			[]string{"bx.json.addrbook-tmp-1"}},
		{"bracket in name", "[ab].json",
			[]string{"[ab].json.addrbook-tmp-1"},
			[]string{"a.json.addrbook-tmp-1"}},
		{"question in name", "b?.json",
			[]string{"b?.json.addrbook-tmp-1"},
			[]string{"bx.json.addrbook-tmp-1"}},
	})
	t.Run("glob char in dir", func(t *testing.T) {
		root := t.TempDir()
		own := filepath.Join(root, "d[1]")
		other := filepath.Join(root, "d1")
		must(t, os.Mkdir(own, 0o700))
		must(t, os.Mkdir(other, 0o700))
		victim := filepath.Join(other, "book.json.addrbook-tmp-1")
		must(t, os.WriteFile(victim, []byte("x"), 0o600))
		b, _ := oBook(retain)
		mustObserve(t, b, "p", 0, a1)
		if err := b.Save(filepath.Join(own, "book.json")); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if _, err := os.Stat(victim); err != nil {
			t.Fatalf("Save removed %s in another directory", victim)
		}
	})
	t.Run("unclosed bracket", func(t *testing.T) {
		b, _ := oBook(retain)
		mustObserve(t, b, "p", 0, a1)
		if err := b.Save(filepath.Join(t.TempDir(), "[book.json")); err != nil {
			t.Fatalf("Save to a valid path failed: %v", err)
		}
	})
}

func TestObserveRejectsChangeNothing(t *testing.T) {
	cases := []struct {
		name  string
		pol   policy.Name
		addrs []netip.Addr
		ttl   time.Duration
		want  error
	}{
		{"empty policy", "", []netip.Addr{a1}, 0, addrbook.ErrEmptyPolicy},
		{"invalid addr last", "p", []netip.Addr{a1, a2, {}}, 0, addrbook.ErrInvalidAddr},
		{"zoned addr last", "p", []netip.Addr{a1, netip.MustParseAddr("fe80::1%en0")}, 0, addrbook.ErrZonedAddr},
		{"zoned 4in6", "p", []netip.Addr{a1, netip.MustParseAddr("::ffff:192.0.2.9%en0")}, 0, addrbook.ErrZonedAddr},
		{"negative ttl", "p", []netip.Addr{a1}, -time.Nanosecond, addrbook.ErrNegativeTTL},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			b, c := oBook(retain)
			mustObserve(t, b, "p", 0, a3)
			c.advance(time.Hour)
			need, err := b.Observe(tt.pol, tt.addrs, tt.ttl)
			if !errors.Is(err, tt.want) || need {
				t.Fatalf("need=%v err=%v, want %v", need, err, tt.want)
			}
			e := b.Prune(nil)
			if len(e) != 1 || e[0].Addr != a3 || !e[0].LastSeen.Equal(oT0) {
				t.Fatalf("refused Observe changed the book: %+v", e)
			}
		})
	}
	b, _ := oBook(retain)
	mustObserve(t, b, "p", 0, netip.MustParseAddr("::ffff:192.0.2.1"))
	mustObserve(t, b, "p", 0, a1)
	if got := b.Addrs("p"); !slices.Equal(got, []netip.Addr{a1}) || !got[0].Is4() {
		t.Fatalf("4in6 not unmapped: %v", got)
	}
}
