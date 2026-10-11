package addrbook_test

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/addrbook"
	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

func observeAliases(t *testing.T, b *addrbook.AddrBook, name policy.Name, ttl time.Duration, aliases ...string) bool {
	t.Helper()
	need, err := b.ObserveAliases(name, aliases, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return need
}

func aliasTexts(ns []dnsname.Name) []string {
	out := make([]string, len(ns))
	for i, n := range ns {
		out[i] = n.String()
	}
	return out
}

func mustName(t *testing.T, s string) dnsname.Name {
	t.Helper()
	n, err := dnsname.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAliasExpiryBoundaries(t *testing.T) {
	tests := map[string]struct {
		ttl, keep time.Duration
	}{
		"ttl below retain": {time.Minute, retain},
		"ttl above retain": {2 * retain, 2 * retain},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			b, c := newBook(t)
			start := c.t
			observeAliases(t, b, "p", tc.ttl, "CDN.Example.NET.")
			next, ok := b.NextExpiry()
			if want := start.Add(tc.keep + time.Nanosecond); !ok || !next.Equal(want) {
				t.Fatalf("next expiry = %v %v, want %v", next, ok, want)
			}
			c.t = start.Add(tc.keep)
			if got := b.Expire(); len(got) != 0 {
				t.Fatalf("expired at the expiry: %v", got)
			}
			c.advance(time.Nanosecond)
			want := addrbook.Entry{Policy: "p", Alias: mustName(t, "cdn.example.net"), LastSeen: start, TTL: tc.ttl, Expiry: start.Add(tc.keep)}
			if got := b.Expire(); !slices.Equal(got, []addrbook.Entry{want}) {
				t.Fatalf("Expire = %v, want %v", got, want)
			}
			if len(b.Aliases("p")) != 0 {
				t.Fatal("alias still in the book")
			}
			if _, ok := b.NextExpiry(); ok {
				t.Fatal("book not empty")
			}
		})
	}
}

func TestAliasExpiryNeverMovesEarlier(t *testing.T) {
	b, c := newBook(t)
	start := c.t
	observeAliases(t, b, "p", 3*retain, "cdn.example.net")
	c.advance(time.Hour)
	observeAliases(t, b, "p", 0, "cdn.example.net")
	c.advance(-2 * time.Hour) // the clock steps back
	observeAliases(t, b, "p", 0, "cdn.example.net")
	next, _ := b.NextExpiry()
	if want := start.Add(3*retain + time.Nanosecond); !next.Equal(want) {
		t.Fatalf("next expiry = %v, want %v", next, want)
	}
}

// The save rule for aliases is the rule for addresses: the saved expiry
// must be within the slack of the new expiry.
func TestAliasNeedSave(t *testing.T) {
	b, c := newBook(t)
	path := snapPath(t)
	if !observeAliases(t, b, "p", 0, "cdn.example.net") {
		t.Fatal("a new alias does not need a save")
	}
	if !observeAliases(t, b, "p", 0, "cdn.example.net") {
		t.Fatal("an unsaved alias does not need a save")
	}
	save(t, b, path)
	c.advance(time.Hour) // the slack for a retain of 7 days
	if observeAliases(t, b, "p", 0, "CDN.example.net") {
		t.Fatal("a refresh within the slack needs a save")
	}
	c.advance(time.Nanosecond)
	if !observeAliases(t, b, "p", 0, "cdn.example.net") {
		t.Fatal("a refresh beyond the slack does not need a save")
	}
	if !observeAliases(t, b, "q", 0, "cdn.example.net") {
		t.Fatal("an alias of a new policy does not need a save")
	}
	save(t, b, path)
	if observeAliases(t, b, "p", 0, "cdn.example.net") || observe(t, b, "p", 0) {
		t.Fatal("needs a save after a save")
	}
}

// A loaded alias counts as saved with the expiry in the file: a refresh
// beyond the slack must ask for a save, one within it must not.
func TestLoadedAliasNeedSave(t *testing.T) {
	b, c := newBook(t)
	start := c.t
	path := snapPath(t)
	observeAliases(t, b, "p", 0, "cdn.example.net")
	save(t, b, path)
	const slack = time.Hour // the slack for a retain of 7 days
	c.t = start.Add(slack)
	if observeAliases(t, restart(t, c, path), "p", 0, "cdn.example.net") {
		t.Fatal("a refresh within the slack after Load needs a save")
	}
	c.t = start.Add(slack + time.Nanosecond)
	if !observeAliases(t, restart(t, c, path), "p", 0, "cdn.example.net") {
		t.Fatal("a refresh beyond the slack after Load does not need a save")
	}
}

func TestObserveAliasesRefusesBadInput(t *testing.T) {
	tests := map[string]struct {
		name    policy.Name
		ttl     time.Duration
		aliases []string
		want    error
	}{
		"malformed":       {"p", 0, []string{"ok.example", "a..b"}, dnsname.ErrMalformedName},
		"empty name":      {"p", 0, []string{""}, dnsname.ErrMalformedName},
		"dangling escape": {"p", 0, []string{`a\`}, dnsname.ErrMalformedName},
		"root":            {"p", 0, []string{"ok.example", "."}, dnsname.ErrRootName},
		"empty policy":    {"", 0, []string{"ok.example"}, addrbook.ErrEmptyPolicy},
		"negative ttl":    {"p", -1, []string{"ok.example"}, addrbook.ErrNegativeTTL},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			b, _ := newBook(t)
			observeAliases(t, b, "p", 0, "old.example")
			if _, err := b.ObserveAliases(tc.name, tc.aliases, tc.ttl); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if got := aliasTexts(b.Aliases("p")); !slices.Equal(got, []string{"old.example"}) {
				t.Fatalf("refused observe changed the book: %v", got)
			}
		})
	}
}

func TestAliasesSortedAndCanonical(t *testing.T) {
	b, _ := newBook(t)
	observeAliases(t, b, "p", 0, "b.example", `A\.B.example.`, "a.b.example", `\097.example`, "B.EXAMPLE")
	want := []string{"a.b.example", "a.example", `a\.b.example`, "b.example"}
	if got := aliasTexts(b.Aliases("p")); !slices.Equal(got, want) {
		t.Fatalf("Aliases = %q, want %q", got, want)
	}
	if got := b.Aliases("q"); len(got) != 0 {
		t.Fatalf("Aliases of an unknown policy = %v", got)
	}
}

func TestAliasPolicies(t *testing.T) {
	b, _ := newBook(t)
	observeAliases(t, b, "q", 0, "cdn.example.net", "only-q.example")
	observeAliases(t, b, "p", 0, "CDN.example.NET.")
	observeAliases(t, b, "r", 0, "other.example")
	observe(t, b, "s", 0, a1)
	tests := map[string][]policy.Name{
		"cdn.example.net":  {"p", "q"},
		"only-q.example":   {"q"},
		"other.example":    {"r"},
		"absent.example":   nil,
		`cdn\.example.net`: nil,
	}
	for alias, want := range tests {
		if got := b.AliasPolicies(mustName(t, alias)); !slices.Equal(got, want) {
			t.Errorf("AliasPolicies(%q) = %v, want %v", alias, got, want)
		}
	}
	if got := b.AliasPolicies(dnsname.Name{}); got != nil {
		t.Errorf("AliasPolicies(zero) = %v", got)
	}
}

func TestPruneAndExpireCoverAliases(t *testing.T) {
	b, c := newBook(t)
	for _, p := range []policy.Name{"z", "a", "m"} {
		observeAliases(t, b, p, 0, "y.example", "x.example")
		observe(t, b, p, 0, a2, a1)
	}
	pr := b.Prune([]policy.Name{"m"})
	var got []string
	for _, e := range pr {
		got = append(got, string(e.Policy)+" "+e.Addr.String()+" "+e.Alias.String())
	}
	want := []string{
		"a 192.0.2.1 ", "a 2001:db8::1 ", "a invalid IP x.example", "a invalid IP y.example",
		"z 192.0.2.1 ", "z 2001:db8::1 ", "z invalid IP x.example", "z invalid IP y.example",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Prune = %q, want %q", got, want)
	}
	if len(b.Aliases("m")) != 2 || len(b.Aliases("a")) != 0 {
		t.Fatal("Prune touched the wrong policy")
	}
	if b.AliasPolicies(mustName(t, "x.example")) == nil {
		t.Fatal("kept alias is gone")
	}
	c.advance(retain + 1)
	if got := b.Expire(); len(got) != 4 {
		t.Fatalf("Expire = %v", got)
	}
	if len(b.Prune(nil)) != 0 {
		t.Fatal("book not empty after Expire")
	}
	observeAliases(t, b, "a", 0, "x.example")
	if got := b.Prune(nil); len(got) != 1 || got[0].Alias.String() != "x.example" {
		t.Fatalf("Prune(nil) = %v", got)
	}
}

func TestAliasSnapshotRoundTrip(t *testing.T) {
	b, c := newBook(t)
	observeAliases(t, b, "p", time.Minute, "cdn.example.net", `a\.b.example`, `\000\255.example`)
	c.advance(time.Hour)
	observeAliases(t, b, "q", 30*24*time.Hour, "cdn.example.net")
	observe(t, b, "p", 0, a1)
	path := snapPath(t)
	save(t, b, path)
	b2 := restart(t, c, path)
	for _, n := range []policy.Name{"p", "q"} {
		if !slices.Equal(b2.Aliases(n), b.Aliases(n)) || !slices.Equal(b2.Addrs(n), b.Addrs(n)) {
			t.Fatalf("policy %s differs after load", n)
		}
	}
	// A loaded alias counts as saved.
	if observeAliases(t, restart(t, c, path), "q", 0, "cdn.example.net") {
		t.Fatal("a loaded alias needs a save within the slack")
	}
	if e1, e2 := b.Prune(nil), b2.Prune(nil); !slices.EqualFunc(e1, e2, func(x, y addrbook.Entry) bool {
		return x.Policy == y.Policy && x.Addr == y.Addr && x.Alias == y.Alias && x.TTL == y.TTL &&
			x.LastSeen.Equal(y.LastSeen) && x.Expiry.Equal(y.Expiry)
	}) {
		t.Fatalf("entries differ after load:\n%v\n%v", e1, e2)
	}
}

func TestSaveWritesVersion2(t *testing.T) {
	b, _ := newBook(t)
	path := snapPath(t)
	save(t, b, path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"version":2,"entries":[],"aliases":[]}`; string(data) != want {
		t.Fatalf("empty snapshot = %s, want %s", data, want)
	}
}

// A snapshot of the previous version has no aliases key. It loads, and
// the next Save writes the current version.
func TestLoadVersion1(t *testing.T) {
	path := snapPath(t)
	v1 := `{"version":1,"entries":[{"policy":"p","addr":"192.0.2.1","last_seen_unix_nano":1,"ttl_nano":0,"expiry_unix_nano":2}]}`
	must(t, os.WriteFile(path, []byte(v1), 0o600))
	b, _ := newBook(t)
	if err := b.Load(path); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(b.Addrs("p"), []netip.Addr{a1}) || len(b.Aliases("p")) != 0 {
		t.Fatalf("loaded %v %v", b.Addrs("p"), b.Aliases("p"))
	}
	save(t, b, path)
	var f struct {
		Version int
		Aliases []json.RawMessage
	}
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &f); err != nil || f.Version != 2 || f.Aliases == nil {
		t.Fatalf("saved %s, %v", data, err)
	}
}

// A book loaded from a version 1 snapshot takes aliases, and the next
// Save keeps them.
func TestVersion1BookTakesAliases(t *testing.T) {
	path := snapPath(t)
	v1 := `{"version":1,"entries":[{"policy":"p","addr":"192.0.2.1","last_seen_unix_nano":0,"ttl_nano":0,"expiry_unix_nano":0}]}`
	must(t, os.WriteFile(path, []byte(v1), 0o600))
	b, c := newBook(t)
	if err := b.Load(path); err != nil {
		t.Fatal(err)
	}
	need, err := b.ObserveAliases("p", []string{"CDN.example.net."}, 0)
	if err != nil || !need {
		t.Fatalf("ObserveAliases after a version 1 Load = %v, %v; want true, nil", need, err)
	}
	save(t, b, path)
	if got := aliasTexts(restart(t, c, path).Aliases("p")); !slices.Equal(got, []string{"cdn.example.net"}) {
		t.Fatalf("Aliases after Save and Load = %q", got)
	}
}

func aliasJSON(mods ...func(map[string]any)) string {
	m := map[string]any{
		"policy": "p", "alias": "cdn.example.net",
		"last_seen_unix_nano": 1, "ttl_nano": 0, "expiry_unix_nano": 2,
	}
	for _, f := range mods {
		f(m)
	}
	out, _ := json.Marshal(m)
	return string(out)
}

func docV2(aliases ...string) string {
	return `{"version":2,"entries":[],"aliases":[` + strings.Join(aliases, ",") + `]}`
}

func TestLoadAliasSnapshots(t *testing.T) {
	good := map[string]string{
		"no aliases":     docV2(),
		"one alias":      docV2(aliasJSON()),
		"escaped alias":  docV2(aliasJSON(with("alias", `a\.b\000.example`))),
		"two policies":   docV2(aliasJSON(), aliasJSON(with("policy", "q"))),
		"keys reordered": `{"aliases":[],"entries":[],"version":2}`,
	}
	for name, content := range good {
		t.Run("green "+name, func(t *testing.T) {
			path := snapPath(t)
			must(t, os.WriteFile(path, []byte(content), 0o600))
			b, _ := newBook(t)
			if err := b.Load(path); err != nil {
				t.Fatal(err)
			}
		})
	}
	bad := map[string]string{
		"version 1 with aliases": `{"version":1,"entries":[],"aliases":[]}`,
		"version 2 no aliases":   `{"version":2,"entries":[]}`,
		"version 3":              `{"version":3,"entries":[],"aliases":[]}`,
		"Aliases case":           `{"version":2,"entries":[],"Aliases":[]}`,
		"dup aliases":            `{"version":2,"entries":[],"aliases":[],"aliases":[]}`,
		"null aliases":           `{"version":2,"entries":[],"aliases":null}`,
		"aliases object":         `{"version":2,"entries":[],"aliases":{}}`,
		"alias in entries":       `{"version":2,"entries":[` + aliasJSON() + `],"aliases":[]}`,
		"entry in aliases":       docV2(entryJSON()),
		"upper case":             docV2(aliasJSON(with("alias", "CDN.example.net"))),
		"final dot":              docV2(aliasJSON(with("alias", "cdn.example.net."))),
		"needless escape":        docV2(aliasJSON(with("alias", `\099dn.example.net`))),
		"malformed":              docV2(aliasJSON(with("alias", "a..b"))),
		"root":                   docV2(aliasJSON(with("alias", "."))),
		"empty alias":            docV2(aliasJSON(with("alias", ""))),
		"null alias":             docV2(aliasJSON(with("alias", nil))),
		"missing alias":          docV2(aliasJSON(without("alias"))),
		"unknown key":            docV2(aliasJSON(with("x", 1))),
		"empty policy":           docV2(aliasJSON(with("policy", ""))),
		"negative ttl":           docV2(aliasJSON(with("ttl_nano", -1))),
		"expiry < seen":          docV2(aliasJSON(with("expiry_unix_nano", 0))),
		"duplicate":              docV2(aliasJSON(), aliasJSON()),
		"one bad of two":         docV2(aliasJSON(), aliasJSON(with("alias", "a..b"), with("policy", "q"))),
		"bad entry, good alias":  `{"version":2,"entries":[` + entryJSON(with("addr", "nope")) + `],"aliases":[` + aliasJSON() + `]}`,
	}
	for name, content := range bad {
		t.Run(name, func(t *testing.T) {
			path := snapPath(t)
			must(t, os.WriteFile(path, []byte(content), 0o600))
			b, _ := newBook(t)
			if err := b.Load(path); !errors.Is(err, addrbook.ErrSnapshot) {
				t.Fatalf("err = %v, want ErrSnapshot", err)
			}
			if _, ok := b.NextExpiry(); ok {
				t.Fatal("failed load changed the book")
			}
		})
	}
}

func TestLoadIntoBookWithAliasesFails(t *testing.T) {
	b, _ := newBook(t)
	path := snapPath(t)
	save(t, b, path)
	observeAliases(t, b, "p", 0, "cdn.example.net")
	if err := b.Load(path); !errors.Is(err, addrbook.ErrNotEmpty) {
		t.Fatalf("err = %v", err)
	}
	if len(b.Aliases("p")) != 1 {
		t.Fatal("failed load changed the book")
	}
}
