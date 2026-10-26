package addrbook_test

import (
	"bytes"
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

// The files in testdata/snapshot-v2 were written by the previous ifboundd
// (snapshot format v2, with the "aliases" key). A generator test in the
// previous source tree wrote them.
const (
	v2Mixed       = "testdata/snapshot-v2/mixed.json"
	v2AliasesOnly = "testdata/snapshot-v2/aliases-only.json"
	v2Empty       = "testdata/snapshot-v2/empty.json"
)

// savedEntry is one address entry as the snapshot stores it.
type savedEntry struct {
	Policy   string `json:"policy"`
	Addr     string `json:"addr"`
	LastSeen int64  `json:"last_seen_unix_nano"`
	TTL      int64  `json:"ttl_nano"`
	Expiry   int64  `json:"expiry_unix_nano"`
}

func compareSaved(a, b savedEntry) int {
	return strings.Compare(a.Policy+"|"+a.Addr, b.Policy+"|"+b.Addr)
}

// genT0 is the clock of the generator at its first Observe.
var genT0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func ns(d time.Duration) int64 { return genT0.Add(d).UnixNano() }

// v2MixedWant is what the generator recorded, computed from the
// Observe rule (last_seen = clock, expiry = max(old, clock + max(ttl,
// retain))) with retain 1h. It is not read from the file.
func v2MixedWant() []savedEntry {
	const h = time.Hour
	want := []savedEntry{
		{"ads", "192.0.2.1", ns(60 * time.Second), int64(2 * h), ns(60*time.Second + 2*h)},
		{"ads", "198.51.100.7", ns(60 * time.Second), int64(30 * time.Second), ns(60*time.Second + h)},
		{"gone", "203.0.113.9", ns(1500 * time.Millisecond), int64(90 * time.Second), ns(1500*time.Millisecond + h)},
		{"web", "192.0.2.1", ns(120 * time.Second), 0, ns(120*time.Second + h)},
		{"web", "2001:db8::1", ns(0), int64(h), ns(h)},
	}
	slices.SortFunc(want, compareSaved)
	return want
}

// readSaved reads the version and the entries of a snapshot,
// and fails the test when the file has a top-level key other than
// "version" and "entries".
func readSaved(t *testing.T, path string) (int, []savedEntry) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("saved snapshot is not a JSON object: %v", err)
	}
	keys := slices.Sorted(func(yield func(string) bool) {
		for k := range top {
			if !yield(k) {
				return
			}
		}
	})
	if !slices.Equal(keys, []string{"entries", "version"}) {
		t.Fatalf("saved snapshot keys = %q, want [entries version]", keys)
	}
	var f struct {
		Version int          `json:"version"`
		Entries []savedEntry `json:"entries"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("decode saved snapshot: %v", err)
	}
	slices.SortFunc(f.Entries, compareSaved)
	return f.Version, f.Entries
}

func copySnapshot(t *testing.T, src string) string {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "addrbook.json")
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return dst
}

func hourBook(now time.Time) *addrbook.AddrBook {
	return addrbook.New(time.Hour, func() time.Time { return now })
}

// A v2 snapshot of the previous version loads; every address entry
// keeps its policy, address, last_seen, ttl and expiry; the aliases are
// gone; a Save writes a format that Load reads back to the same entries.
func TestV2SnapshotLoadsWithAllEntriesAndTimes(t *testing.T) {
	now := genT0.Add(3 * time.Minute)
	b := hourBook(now)
	if err := b.Load(copySnapshot(t, v2Mixed)); err != nil {
		t.Fatalf("Load(v2 of the previous version) = %v, want nil", err)
	}
	wantAddrs := map[policy.Name][]netip.Addr{
		"ads":       {netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.7")},
		"gone":      {netip.MustParseAddr("203.0.113.9")},
		"web":       {netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
		"aliasonly": nil,
	}
	for name, want := range wantAddrs {
		if got := b.Addrs(name); !slices.Equal(got, want) {
			t.Errorf("Addrs(%s) = %v, want %v", name, got, want)
		}
	}
	next, ok := b.NextExpiry()
	if want := time.Unix(0, ns(time.Hour)).Add(time.Nanosecond); !ok || !next.Equal(want) {
		t.Errorf("NextExpiry = %v, %v; want %v (alias records must not count)", next, ok, want)
	}

	out := filepath.Join(t.TempDir(), "resaved.json")
	if err := b.Save(out); err != nil {
		t.Fatalf("Save after Load: %v", err)
	}
	version, got := readSaved(t, out)
	if version != 1 {
		t.Errorf("saved version = %d, want 1", version)
	}
	if want := v2MixedWant(); !slices.Equal(got, want) {
		t.Errorf("saved entries:\n got %+v\nwant %+v", got, want)
	}

	// Read back exactly: a second load and save gives the same bytes.
	b2 := hourBook(now)
	if err := b2.Load(out); err != nil {
		t.Fatalf("Load(own save) = %v", err)
	}
	out2 := filepath.Join(t.TempDir(), "again.json")
	if err := b2.Save(out2); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("save -> load -> save changed the bytes:\n%s\n%s", first, second)
	}
}

// A v2 snapshot with aliases only, and an empty v2 snapshot,
// load into an empty book.
func TestV2SnapshotWithoutEntriesLoadsEmpty(t *testing.T) {
	for _, src := range []string{v2AliasesOnly, v2Empty} {
		t.Run(filepath.Base(src), func(t *testing.T) {
			b := hourBook(genT0)
			if err := b.Load(copySnapshot(t, src)); err != nil {
				t.Fatalf("Load = %v, want nil", err)
			}
			if got := b.Addrs("web"); len(got) != 0 {
				t.Errorf("Addrs(web) = %v, want none", got)
			}
			if _, ok := b.NextExpiry(); ok {
				t.Error("NextExpiry reports an entry; alias records must not become entries")
			}
		})
	}
}

// Load checks the top level of a v2 snapshot strictly (see
// TestMalformedSnapshotsAreRefused), but it does not check the items of
// "aliases" on purpose: the book does not use them. So any items load.
func TestV2AliasItemsAreIgnored(t *testing.T) {
	entry := `{"policy":"web","addr":"192.0.2.1","last_seen_unix_nano":1,"ttl_nano":0,"expiry_unix_nano":2}`
	for name, aliases := range map[string]string{
		"empty":           `[]`,
		"garbage items":   `[1, "x", null, {}, [[]]]`,
		"unknown fields":  `[{"policy":"web","alias":"a.example","extra":true}]`,
		"bad alias name":  `[{"policy":"web","alias":"..","last_seen_unix_nano":1,"ttl_nano":0,"expiry_unix_nano":2}]`,
		"whitespace":      " \n[ ] ",
		"negative ttl":    `[{"policy":"web","alias":"a.example","last_seen_unix_nano":1,"ttl_nano":-5,"expiry_unix_nano":2}]`,
		"empty policy":    `[{"policy":"","alias":"a.example","last_seen_unix_nano":1,"ttl_nano":0,"expiry_unix_nano":2}]`,
		"duplicate alias": `[{"policy":"web","alias":"a.example","last_seen_unix_nano":1,"ttl_nano":0,"expiry_unix_nano":2},{"policy":"web","alias":"a.example","last_seen_unix_nano":1,"ttl_nano":0,"expiry_unix_nano":2}]`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "s.json")
			doc := `{"version":2,"entries":[` + entry + `],"aliases":` + aliases + `}`
			if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			b := hourBook(genT0)
			if err := b.Load(path); err != nil {
				t.Fatalf("Load = %v, want nil", err)
			}
			if got := b.Addrs("web"); !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.0.2.1")}) {
				t.Errorf("Addrs(web) = %v", got)
			}
		})
	}
}

// Malformed snapshots are refused with ErrSnapshot, and the book
// stays empty.
func TestMalformedSnapshotsAreRefused(t *testing.T) {
	entries := `[{"policy":"web","addr":"192.0.2.1","last_seen_unix_nano":1,"ttl_nano":0,"expiry_unix_nano":2}]`
	cases := map[string]string{
		"version 3":                 `{"version":3,"entries":` + entries + `,"aliases":[]}`,
		"version 0":                 `{"version":0,"entries":` + entries + `}`,
		"version -1":                `{"version":-1,"entries":` + entries + `}`,
		"version string":            `{"version":"2","entries":` + entries + `,"aliases":[]}`,
		"version float":             `{"version":2.5,"entries":` + entries + `,"aliases":[]}`,
		"version null":              `{"version":null,"entries":` + entries + `,"aliases":[]}`,
		"no version":                `{"entries":` + entries + `,"aliases":[]}`,
		"v2 aliases object":         `{"version":2,"entries":` + entries + `,"aliases":{}}`,
		"v2 aliases string":         `{"version":2,"entries":` + entries + `,"aliases":"[]"}`,
		"v2 aliases null":           `{"version":2,"entries":` + entries + `,"aliases":null}`,
		"v2 aliases number":         `{"version":2,"entries":` + entries + `,"aliases":0}`,
		"v2 aliases true":           `{"version":2,"entries":` + entries + `,"aliases":true}`,
		"v2 missing aliases":        `{"version":2,"entries":` + entries + `}`,
		"v2 missing entries":        `{"version":2,"aliases":[]}`,
		"v2 unknown key":            `{"version":2,"entries":` + entries + `,"aliases":[],"x":1}`,
		"v2 duplicate aliases key":  `{"version":2,"entries":` + entries + `,"aliases":[],"aliases":[]}`,
		"v2 key case":               `{"version":2,"entries":` + entries + `,"Aliases":[]}`,
		"v1 with aliases":           `{"version":1,"entries":` + entries + `,"aliases":[]}`,
		"v2 trailing data":          `{"version":2,"entries":` + entries + `,"aliases":[]} {}`,
		"v2 truncated aliases":      `{"version":2,"entries":` + entries + `,"aliases":[`,
		"v2 truncated in alias":     `{"version":2,"entries":` + entries + `,"aliases":[{"policy":"w`,
		"v2 aliases unclosed array": `{"version":2,"entries":` + entries + `,"aliases":[1,}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			wantRefused(t, []byte(doc))
		})
	}
}

func wantRefused(t *testing.T, doc []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	b := hourBook(genT0)
	err := b.Load(path)
	if !errors.Is(err, addrbook.ErrSnapshot) {
		t.Fatalf("Load(%q) = %v, want an error that wraps ErrSnapshot", doc, err)
	}
	if got := b.Addrs("web"); len(got) != 0 {
		t.Errorf("a refused Load left entries: %v", got)
	}
	// The book is still empty: a later Load works.
	if err := b.Load(filepath.Join(t.TempDir(), "missing.json")); err != nil {
		t.Errorf("Load after a refused Load = %v, want nil", err)
	}
}

// Every strict prefix of a v2 snapshot of the previous version is
// refused with ErrSnapshot.
func TestTruncatedV2SnapshotIsRefused(t *testing.T) {
	data, err := os.ReadFile(v2Mixed)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.TrimSpace(data)
	for n := 1; n < len(data); n++ {
		path := filepath.Join(t.TempDir(), "s.json")
		if err := os.WriteFile(path, data[:n], 0o600); err != nil {
			t.Fatal(err)
		}
		if err := hourBook(genT0).Load(path); !errors.Is(err, addrbook.ErrSnapshot) {
			t.Fatalf("Load(first %d of %d bytes) = %v, want ErrSnapshot", n, len(data), err)
		}
	}
}

// FuzzSnapshotRoundTrip: for any existing file, Load either refuses
// it with ErrSnapshot and keeps the book empty, or it accepts it, and
// then Save writes a file that Load reads back to the same entries, and a
// second Save writes the same bytes.
func FuzzSnapshotRoundTrip(f *testing.F) {
	for _, p := range []string{v2Mixed, v2AliasesOnly, v2Empty} {
		data, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(`{"version":1,"entries":[]}`))
	f.Add([]byte(`{"version":2,"entries":[],"aliases":{}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "s.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		b := hourBook(genT0)
		if err := b.Load(path); err != nil {
			if !errors.Is(err, addrbook.ErrSnapshot) {
				t.Fatalf("Load of a regular file = %v, want nil or ErrSnapshot", err)
			}
			if _, ok := b.NextExpiry(); ok {
				t.Fatal("a refused Load left entries")
			}
			return
		}
		roundTrip(t, b, dir)
	})
}

// roundTrip saves b, loads the file, and saves again: the two files
// are equal and have version 1. A time that the format cannot hold is a
// documented refusal of Save.
func roundTrip(t *testing.T, b *addrbook.AddrBook, dir string) {
	t.Helper()
	out := filepath.Join(dir, "out.json")
	if err := b.Save(out); err != nil {
		if errors.Is(err, addrbook.ErrTimeRange) {
			return
		}
		t.Fatalf("Save after Load: %v", err)
	}
	b2 := hourBook(genT0)
	if err := b2.Load(out); err != nil {
		t.Fatalf("Load(own save) = %v", err)
	}
	out2 := filepath.Join(dir, "out2.json")
	if err := b2.Save(out2); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("round trip changed the bytes:\n%s\n%s", first, second)
	}
	if v, _ := readSaved(t, out); v != 1 {
		t.Fatalf("saved version %d, want 1", v)
	}
}
