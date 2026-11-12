package addrbook_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrbook"
	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// The files in testdata/snapshot-v2 were written by the previous ifboundd
// (snapshot format v2, with the "aliases" key). A generator test in the
// previous source tree wrote them. The daemon tests read them too.
const (
	v2Mixed       = "testdata/snapshot-v2/mixed.json"
	v2AliasesOnly = "testdata/snapshot-v2/aliases-only.json"
	v2Empty       = "testdata/snapshot-v2/empty.json"
)

// genT0 is the clock of the generator at its first Observe.
var genT0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// validEntry is one entry that Read accepts.
const validEntry = `{"policy":"p","addr":"192.0.2.1","last_seen_unix_nano":1,"ttl_nano":0,"expiry_unix_nano":2}`

// validEntryWant is what Read returns for validEntry.
func validEntryWant(t *testing.T) addrbook.Entry {
	t.Helper()
	return addrbook.Entry{
		Policy:   "p",
		Addr:     mustAddr(t, "192.0.2.1"),
		LastSeen: time.Unix(0, 1).UTC(),
		TTL:      0,
		Expiry:   time.Unix(0, 2).UTC(),
	}
}

func mustAddr(t *testing.T, s string) blockable.Addr {
	t.Helper()
	a, ok := blockable.New(netip.MustParseAddr(s))
	if !ok {
		t.Fatalf("blockable.New(%s) refused", s)
	}
	return a
}

// writeSnapshot writes data to a new file and returns its path.
func writeSnapshot(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "addrbook.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// wantEntries fails the test when got differs from want in count, order or
// any field. It also checks that Read returns every time in UTC.
func wantEntries(t *testing.T, got, want []addrbook.Entry) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("Read returned %d entries, want %d:\n got %+v\nwant %+v", len(got), len(want), got, want)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.Policy != w.Policy || g.Addr != w.Addr || g.TTL != w.TTL ||
			!g.LastSeen.Equal(w.LastSeen) || !g.Expiry.Equal(w.Expiry) {
			t.Errorf("entry %d:\n got %+v\nwant %+v", i, g, w)
		}
		if g.LastSeen.Location() != time.UTC || g.Expiry.Location() != time.UTC {
			t.Errorf("entry %d times are not in UTC: %v, %v", i, g.LastSeen.Location(), g.Expiry.Location())
		}
	}
}

// v2MixedWant is what the generator recorded: last_seen is the clock of
// the Observe call, and expiry is max(old, clock + max(ttl, retain)) with
// retain 1h. The order is the order of the file. The test does not
// compute it from the file.
func v2MixedWant(t *testing.T) []addrbook.Entry {
	t.Helper()
	const h = time.Hour
	at := func(d time.Duration) time.Time { return genT0.Add(d) }
	return []addrbook.Entry{
		{Policy: "ads", Addr: mustAddr(t, "192.0.2.1"), LastSeen: at(60 * time.Second), TTL: 2 * h, Expiry: at(60*time.Second + 2*h)},
		{Policy: "ads", Addr: mustAddr(t, "198.51.100.7"), LastSeen: at(60 * time.Second), TTL: 30 * time.Second, Expiry: at(60*time.Second + h)},
		{Policy: "gone", Addr: mustAddr(t, "203.0.113.9"), LastSeen: at(1500 * time.Millisecond), TTL: 90 * time.Second, Expiry: at(1500*time.Millisecond + h)},
		{Policy: "web", Addr: mustAddr(t, "192.0.2.1"), LastSeen: at(120 * time.Second), TTL: 0, Expiry: at(120*time.Second + h)},
		{Policy: "web", Addr: mustAddr(t, "2001:db8::1"), LastSeen: at(0), TTL: h, Expiry: at(h)},
	}
}

// A v2 snapshot of the previous version gives every address entry with its
// policy, address, last_seen, ttl and expiry. The aliases give nothing.
func TestReadV2SnapshotReturnsEveryEntryWithItsTimes(t *testing.T) {
	got, err := addrbook.Read(v2Mixed)
	if err != nil {
		t.Fatalf("Read(%s) = %v, want nil", v2Mixed, err)
	}
	wantEntries(t, got, v2MixedWant(t))
}

// A v2 snapshot with aliases only, and an empty v2 snapshot, give no entry.
func TestReadV2SnapshotWithoutEntriesReturnsNone(t *testing.T) {
	for _, src := range []string{v2AliasesOnly, v2Empty} {
		t.Run(filepath.Base(src), func(t *testing.T) {
			got, err := addrbook.Read(src)
			if err != nil {
				t.Fatalf("Read = %v, want nil", err)
			}
			if len(got) != 0 {
				t.Errorf("Read = %+v, want no entry; alias records must not become entries", got)
			}
		})
	}
}

// Read checks the top level of a v2 snapshot strictly (see
// TestReadRefusesMalformedSnapshots), but it does not check the items of
// "aliases" on purpose: the book does not use them. So any items are fine.
func TestReadIgnoresAliasItems(t *testing.T) {
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
			path := writeSnapshot(t, `{"version":2,"entries":[`+validEntry+`],"aliases":`+aliases+`}`)
			got, err := addrbook.Read(path)
			if err != nil {
				t.Fatalf("Read = %v, want nil", err)
			}
			wantEntries(t, got, []addrbook.Entry{validEntryWant(t)})
		})
	}
}

// Documents that are close to the refused ones, but valid.
func TestReadAcceptsNearMissDocuments(t *testing.T) {
	seenEqualsExpiry := validEntryWant(t)
	seenEqualsExpiry.Expiry = seenEqualsExpiry.LastSeen
	maxTTL := validEntryWant(t)
	maxTTL.TTL = time.Duration(1<<63 - 1)
	tests := []struct {
		name string
		doc  string
		want []addrbook.Entry
	}{
		{"v1 with no entry", `{"version":1,"entries":[]}`, nil},
		{"v1 with one entry", `{"version":1,"entries":[` + validEntry + `]}`, []addrbook.Entry{validEntryWant(t)}},
		{"whitespace between tokens", " {\n\"version\" : 1 , \"entries\" : [ " + validEntry + " ] }\n", []addrbook.Entry{validEntryWant(t)}},
		{"expiry equals last_seen", `{"version":1,"entries":[` + strings.Replace(validEntry, `"expiry_unix_nano":2`, `"expiry_unix_nano":1`, 1) + `]}`, []addrbook.Entry{seenEqualsExpiry}},
		{"largest ttl", `{"version":1,"entries":[` + strings.Replace(validEntry, `"ttl_nano":0`, `"ttl_nano":9223372036854775807`, 1) + `]}`, []addrbook.Entry{maxTTL}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := addrbook.Read(writeSnapshot(t, tt.doc))
			if err != nil {
				t.Fatalf("Read = %v, want nil", err)
			}
			wantEntries(t, got, tt.want)
		})
	}
}

// Read returns the entries in the order of the file, not sorted. The same
// address in two policies, and two addresses in one policy, are not
// duplicates.
func TestReadReturnsEntriesInFileOrder(t *testing.T) {
	entry := func(policy, addr string) string {
		return `{"policy":"` + policy + `","addr":"` + addr + `","last_seen_unix_nano":1,"ttl_nano":0,"expiry_unix_nano":2}`
	}
	path := writeSnapshot(t, `{"version":1,"entries":[`+
		entry("z", "198.51.100.7")+","+entry("a", "192.0.2.1")+","+entry("z", "192.0.2.1")+","+entry("a", "2001:db8::1")+`]}`)
	got, err := addrbook.Read(path)
	if err != nil {
		t.Fatalf("Read = %v, want nil", err)
	}
	want := []addrbook.Entry{validEntryWant(t), validEntryWant(t), validEntryWant(t), validEntryWant(t)}
	for i, k := range []struct {
		policy policy.Name
		addr   string
	}{{"z", "198.51.100.7"}, {"a", "192.0.2.1"}, {"z", "192.0.2.1"}, {"a", "2001:db8::1"}} {
		want[i].Policy = k.policy
		want[i].Addr = mustAddr(t, k.addr)
	}
	wantEntries(t, got, want)
}

// An entry whose expiry is long past stays in the result: the caller
// decides when an entry leaves.
func TestReadKeepsExpiredEntries(t *testing.T) {
	const (
		seen   = 1_000_000_000_000_000_000 // 2001-09-09
		expiry = seen + int64(time.Hour)
	)
	path := writeSnapshot(t, `{"version":1,"entries":[{"policy":"p","addr":"192.0.2.1",`+
		`"last_seen_unix_nano":1000000000000000000,"ttl_nano":60000000000,"expiry_unix_nano":1000003600000000000}]}`)
	got, err := addrbook.Read(path)
	if err != nil {
		t.Fatalf("Read = %v, want nil", err)
	}
	wantEntries(t, got, []addrbook.Entry{{
		Policy:   "p",
		Addr:     mustAddr(t, "192.0.2.1"),
		LastSeen: time.Unix(0, seen).UTC(),
		TTL:      time.Minute,
		Expiry:   time.Unix(0, expiry).UTC(),
	}})
	if !got[0].Expiry.Before(time.Now()) {
		t.Fatal("test data is not expired")
	}
}

// An earlier ifboundd can have saved a loopback or unspecified address.
// Read drops such an entry. The other entries stay, in order.
func TestReadDropsRefusedAddresses(t *testing.T) {
	entry := func(policy, addr string) string {
		return `{"policy":"` + policy + `","addr":"` + addr + `","last_seen_unix_nano":1,"ttl_nano":0,"expiry_unix_nano":2}`
	}
	path := writeSnapshot(t, `{"version":1,"entries":[`+
		entry("web", "127.0.0.1")+","+entry("web", "192.0.2.1")+","+entry("web", "0.0.0.0")+","+
		entry("ads", "::1")+","+entry("ads", "::")+","+entry("ads", "2001:db8::1")+`]}`)
	got, err := addrbook.Read(path)
	if err != nil {
		t.Fatalf("Read = %v, want nil", err)
	}
	web, ads := validEntryWant(t), validEntryWant(t)
	web.Policy = "web"
	ads.Policy, ads.Addr = "ads", mustAddr(t, "2001:db8::1")
	wantEntries(t, got, []addrbook.Entry{web, ads})
}

// Two entries with the same policy and address are refused.
func TestReadRefusesDuplicateEntries(t *testing.T) {
	path := writeSnapshot(t, `{"version":1,"entries":[`+validEntry+`,`+validEntry+`]}`)
	got, err := addrbook.Read(path)
	if !errors.Is(err, addrbook.ErrSnapshot) {
		t.Fatalf("Read = %v, want an error that wraps ErrSnapshot", err)
	}
	if got != nil {
		t.Errorf("Read returned %+v with an error, want no entry", got)
	}
}

// Read returns ErrSnapshot, and no entry, for each document below.
func TestReadRefusesMalformedSnapshots(t *testing.T) {
	repl := func(old, repl string) string {
		return `{"version":1,"entries":[` + strings.Replace(validEntry, old, repl, 1) + `]}`
	}
	v2 := func(extra string) string {
		return `{"version":2,"entries":[` + validEntry + `]` + extra + `}`
	}
	docs := map[string]string{
		// Whole document.
		"empty file":       ``,
		"malformed":        `{"version":1,`,
		"top null":         `null`,
		"top array":        `[]`,
		"trailing garbage": `{"version":1,"entries":[]}x`,
		"trailing object":  `{"version":1,"entries":[]}{}`,
		"trailing bracket": `{"version":1,"entries":[]}]`,
		"trailing brace":   `{"version":1,"entries":[]}}`,
		"trailing comma":   `{"version":1,"entries":[],}`,
		"missing comma":    `{"version":1 "entries":[]}`,
		// Top-level keys.
		"version key case":    `{"Version":1,"entries":[]}`,
		"entries key case":    `{"version":1,"Entries":[]}`,
		"all upper-case keys": `{"VERSION":1,"ENTRIES":[]}`,
		"unknown top key":     `{"version":1,"entries":[],"x":1}`,
		"duplicate version":   `{"version":1,"version":1,"entries":[]}`,
		"duplicate entries":   `{"version":1,"entries":[` + validEntry + `],"entries":[]}`,
		"missing version":     `{"entries":[]}`,
		"missing entries":     `{"version":1}`,
		"null entries":        `{"version":1,"entries":null}`,
		"entries object":      `{"version":1,"entries":{}}`,
		"null item":           `{"version":1,"entries":[null]}`,
		"array item":          `{"version":1,"entries":[[]]}`,
		// Version.
		"version 99":     `{"version":99,"entries":[]}`,
		"version 3":      `{"version":3,"entries":[],"aliases":[]}`,
		"version 0":      `{"version":0,"entries":[]}`,
		"version -1":     `{"version":-1,"entries":[]}`,
		"version string": `{"version":"1","entries":[]}`,
		"version float":  `{"version":1.5,"entries":[]}`,
		"version null":   `{"version":null,"entries":[]}`,
		// Version 2 and aliases.
		"v1 with aliases":           `{"version":1,"entries":[],"aliases":[]}`,
		"v2 aliases object":         v2(`,"aliases":{}`),
		"v2 aliases string":         v2(`,"aliases":"[]"`),
		"v2 aliases null":           v2(`,"aliases":null`),
		"v2 aliases number":         v2(`,"aliases":0`),
		"v2 aliases true":           v2(`,"aliases":true`),
		"v2 missing aliases":        v2(``),
		"v2 missing entries":        `{"version":2,"aliases":[]}`,
		"v2 unknown key":            v2(`,"aliases":[],"x":1`),
		"v2 duplicate aliases key":  v2(`,"aliases":[],"aliases":[]`),
		"v2 aliases key case":       v2(`,"Aliases":[]`),
		"v2 trailing data":          v2(`,"aliases":[]`) + ` {}`,
		"v2 truncated aliases":      `{"version":2,"entries":[` + validEntry + `],"aliases":[`,
		"v2 truncated in alias":     `{"version":2,"entries":[` + validEntry + `],"aliases":[{"policy":"w`,
		"v2 aliases unclosed array": `{"version":2,"entries":[` + validEntry + `],"aliases":[1,}`,
		// Entry keys.
		"entry key case":    repl(`"policy"`, `"Policy"`),
		"entry unknown key": repl(`"ttl_nano":0`, `"ttl_nano":0,"x":0`),
		"entry dup key":     repl(`"ttl_nano":0`, `"ttl_nano":0,"ttl_nano":0`),
		// Entry values.
		"empty policy":         repl(`"p"`, `""`),
		"invalid UTF-8":        repl(`"p"`, "\"p\xff\""),
		"negative ttl":         repl(`"ttl_nano":0`, `"ttl_nano":-1`),
		"string ttl":           repl(`"ttl_nano":0`, `"ttl_nano":"0"`),
		"float ttl":            repl(`"ttl_nano":0`, `"ttl_nano":0.5`),
		"expiry before seen":   repl(`"expiry_unix_nano":2`, `"expiry_unix_nano":0`),
		"last_seen overflow":   repl(`"last_seen_unix_nano":1`, `"last_seen_unix_nano":9223372036854775808`),
		"unparsable addr":      repl(`192.0.2.1`, `192.0.2`),
		"nonsense addr":        repl(`192.0.2.1`, `nope`),
		"empty addr":           repl(`192.0.2.1`, ``),
		"zoned addr":           repl(`192.0.2.1`, `fe80::1%en0`),
		"4in6 addr":            repl(`192.0.2.1`, `::ffff:192.0.2.1`),
		"one bad of two":       `{"version":1,"entries":[` + validEntry + `,` + strings.Replace(strings.Replace(validEntry, `"p"`, `""`, 1), `192.0.2.1`, `192.0.2.2`, 1) + `]}`,
		"4in6 after plain dup": `{"version":1,"entries":[` + validEntry + `,` + strings.Replace(validEntry, `192.0.2.1`, `::ffff:192.0.2.1`, 1) + `]}`,
	}
	// A missing key and a null value are refused for each entry key.
	for _, key := range []string{"policy", "addr", "last_seen_unix_nano", "ttl_nano", "expiry_unix_nano"} {
		var m map[string]any
		if err := json.Unmarshal([]byte(validEntry), &m); err != nil {
			t.Fatal(err)
		}
		delete(m, key)
		docs["missing "+key] = oneEntryDoc(t, m)
		m[key] = nil
		docs["null "+key] = oneEntryDoc(t, m)
	}
	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			got, err := addrbook.Read(writeSnapshot(t, doc))
			if !errors.Is(err, addrbook.ErrSnapshot) {
				t.Fatalf("Read(%q) = %v, want an error that wraps ErrSnapshot", doc, err)
			}
			if got != nil {
				t.Errorf("Read returned %+v with an error, want no entry", got)
			}
		})
	}
}

func oneEntryDoc(t *testing.T, entry map[string]any) string {
	t.Helper()
	b, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	return `{"version":1,"entries":[` + string(b) + `]}`
}

// Every strict prefix of a v2 snapshot of the previous version is
// refused with ErrSnapshot.
func TestReadRefusesEveryTruncatedV2Snapshot(t *testing.T) {
	data, err := os.ReadFile(v2Mixed)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.TrimSpace(data)
	path := filepath.Join(t.TempDir(), "addrbook.json")
	for n := 0; n < len(data); n++ {
		if err := os.WriteFile(path, data[:n], 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := addrbook.Read(path)
		if !errors.Is(err, addrbook.ErrSnapshot) {
			t.Fatalf("Read(first %d of %d bytes) = %v, want ErrSnapshot", n, len(data), err)
		}
		if got != nil {
			t.Fatalf("Read(first %d of %d bytes) returned %+v with an error", n, len(data), got)
		}
	}
}

// A path that does not exist, in a directory that does, is an empty
// snapshot and not an error.
func TestReadMissingFileReturnsNoEntries(t *testing.T) {
	got, err := addrbook.Read(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("Read = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("Read = %+v, want nil", got)
	}
}

func TestReadRefusesPathThatIsNotAPlainFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{"version":1,"entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "dangling.json")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"symlink to a file": link,
		"dangling symlink":  dangling,
		"directory":         dir,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := addrbook.Read(path)
			if !errors.Is(err, addrbook.ErrBadPath) {
				t.Fatalf("Read(%s) = %v, want an error that wraps ErrBadPath", path, err)
			}
			if got != nil {
				t.Errorf("Read returned %+v with an error", got)
			}
		})
	}
}

// A missing directory is an error, not an empty snapshot. An empty book
// could unblock addresses that applications still use.
func TestReadRefusesPathWithoutDirectory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file.json")
	if err := os.WriteFile(file, []byte(`{"version":1,"entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := map[string]string{
		"missing directory":   filepath.Join(dir, "no-dir", "addrbook.json"),
		"directory is a file": filepath.Join(file, "addrbook.json"),
		"missing directories": filepath.Join(dir, "a", "b", "addrbook.json"),
	}
	for name, path := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := addrbook.Read(path)
			if err == nil {
				t.Fatalf("Read(%s) = nil, want an error", path)
			}
			if errors.Is(err, addrbook.ErrSnapshot) {
				t.Errorf("Read(%s) = %v: a path error must not look like a bad snapshot", path, err)
			}
			if got != nil {
				t.Errorf("Read returned %+v with an error", got)
			}
		})
	}
}

// A read error is an error, never an empty snapshot.
func TestReadReportsUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read a file with mode 000")
	}
	path := writeSnapshot(t, `{"version":1,"entries":[]}`)
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	got, err := addrbook.Read(path)
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Read = %v, want an error that wraps fs.ErrPermission", err)
	}
	if got != nil {
		t.Errorf("Read returned %+v with an error", got)
	}
}
