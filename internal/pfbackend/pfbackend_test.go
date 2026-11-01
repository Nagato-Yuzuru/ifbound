package pfbackend

import (
	"errors"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/pfrules"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

const testConfig = `
[[policy]]
name     = "bing"
to       = ["*.bing.com", "203.0.113.0/24"]
only_via = ["@tunnel"]

[[policy]]
name     = "doh"
to       = ["1.1.1.1/32"]
only_via = []
`

var testIfaces = []reconcile.Interface{
	{Name: "en0", Class: policy.ClassHardware},
	{Name: "utun4", Class: policy.ClassTunnel},
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTest(t *testing.T) (*Backend, *fakePF, *clock) {
	t.Helper()
	f := newFakePF()
	c := &clock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	f.now = c.now
	return New(f, c.now, slog.New(slog.DiscardHandler)), f, c
}

func compile(t *testing.T, config string) reconcile.Ruleset {
	t.Helper()
	cfg, err := policy.ParseBytes([]byte("[dns]\nupstream = [\"tls://1.1.1.1@a.example\"]\n" + config))
	if err != nil {
		t.Fatal(err)
	}
	rs, err := pfrules.Compiler{}.Compile(cfg.Policies, testIfaces, reconcile.Accounts{})
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func loadedID(t *testing.T, b *Backend) string {
	t.Helper()
	id, err := b.LoadedID(t.Context())
	if err != nil {
		t.Fatalf("LoadedID: %v", err)
	}
	st, err := b.Read(t.Context())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if st.Ruleset != id {
		t.Fatalf("Read reports ruleset %q, LoadedID %q", st.Ruleset, id)
	}
	return id
}

func TestLoadRefusesARulesetWithoutID(t *testing.T) {
	b, f, _ := newTest(t)
	if err := b.Load(t.Context(), reconcile.Ruleset{}); !errors.Is(err, errRulesetID) {
		t.Errorf("Load(zero Ruleset) error = %v, want errRulesetID", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("Load ran pfctl %v for a ruleset without ID", f.calls)
	}
}

// TestLoadedIDAfterExternalChange checks that each external change of the
// rules gives "" and never the ID of the loaded ruleset.
func TestLoadedIDAfterExternalChange(t *testing.T) {
	tests := []struct {
		name   string
		change func(f *fakePF)
	}{
		{"anchor rules flushed", func(f *fakePF) { f.anchors[Anchor] = nil }},
		{"anchor loaded by another tool", func(f *fakePF) {
			f.anchors[Anchor] = []string{"block drop out quick all"}
		}},
		{"rule in a sub-anchor", func(f *fakePF) {
			f.anchors[Anchor+"/tag.bing"] = []string{"pass out quick all no state"}
		}},
		{"rule in a nested sub-anchor", func(f *fakePF) {
			f.anchors[Anchor+"/tag.bing"] = []string{`anchor "z" all`}
			f.anchors[Anchor+"/tag.bing/z"] = []string{"pass out quick all no state"}
		}},
		{"pf disabled", func(f *fakePF) { f.enabled, f.tokens = false, nil }},
		{"pfctl cannot read a sub-anchor", func(f *fakePF) {
			f.complain = func(args []string) bool { return slices.Contains(args, Anchor+"/*") }
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, f, _ := newTest(t)
			if err := b.Load(t.Context(), compile(t, testConfig)); err != nil {
				t.Fatalf("Load: %v", err)
			}
			tt.change(f)
			if got := loadedID(t, b); got != "" {
				t.Errorf("loaded ID = %q, want \"\"", got)
			}
		})
	}
}

func TestLoadedIDBeforeAnyLoad(t *testing.T) {
	b, f, _ := newTest(t)
	f.enabled = true
	if got := loadedID(t, b); got != "" {
		t.Errorf("loaded ID = %q, want \"\"", got)
	}
}

// TestLoadFlushesSubAnchors checks the repair of rules that another tool
// put in a sub-anchor, also in the sub-anchor of a removed policy.
func TestLoadFlushesSubAnchors(t *testing.T) {
	b, f, _ := newTest(t)
	rs := compile(t, testConfig)
	f.anchors[Anchor+"/tag.bing"] = []string{"pass out quick all no state"}
	f.anchors[Anchor+"/tag.gone"] = []string{"pass out quick all no state"}
	if err := b.Load(t.Context(), rs); err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, sub := range []string{"tag.bing", "tag.gone"} {
		if rules := f.anchors[Anchor+"/"+sub]; len(rules) != 0 {
			t.Errorf("sub-anchor %s holds %v after Load, want no rule", sub, rules)
		}
	}
	if got := loadedID(t, b); got != rs.ID() {
		t.Errorf("loaded ID = %q, want %q", got, rs.ID())
	}
}

func TestLoadEnablesPfWithRateLimit(t *testing.T) {
	b, f, c := newTest(t)
	rs := compile(t, testConfig)
	if err := b.Load(t.Context(), rs); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !f.enabled || !slices.Equal(values(b), []string{"1001"}) {
		t.Fatalf("after Load: enabled %v, tokens %v; want enabled with token 1001", f.enabled, values(b))
	}

	f.enabled, f.tokens = false, nil // pfctl -d drops every token
	c.t = c.t.Add(EnableInterval - time.Second)
	if err := b.Load(t.Context(), rs); !errors.Is(err, errDisabled) {
		t.Fatalf("Load within the interval: error = %v, want errDisabled", err)
	}
	if n := len(f.callsOf("-E")); n != 1 {
		t.Errorf("pfctl -E ran %d times, want 1", n)
	}

	c.t = c.t.Add(time.Second)
	if err := b.Load(t.Context(), rs); err != nil {
		t.Fatalf("Load after the interval: %v", err)
	}
	if !f.enabled || !slices.Equal(values(b), []string{"1002"}) {
		t.Errorf("after the second enable: enabled %v, tokens %v; want enabled with token 1002", f.enabled, values(b))
	}
}

// TestLoadTakesItsOwnReference checks that Load takes a pf reference also
// when another tool keeps pf enabled, and gives back its old one.
func TestLoadTakesItsOwnReference(t *testing.T) {
	b, f, _ := newTest(t)
	f.enabled, f.tokens = true, []string{"77"}
	for _, want := range []string{"1001", "1002"} {
		if err := b.Load(t.Context(), compile(t, testConfig)); err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !slices.Equal(f.tokens, []string{"77", want}) || !slices.Equal(values(b), []string{want}) {
			t.Errorf("after Load: tokens %v, tokens of ifbound %v; want [77 %s] and %s", f.tokens, values(b), want, want)
		}
	}
	if calls := f.callsOf("-d"); len(calls) != 0 {
		t.Errorf("Load ran %v", calls)
	}
}

func TestLoadKeepsEntriesAndEndsTheirStates(t *testing.T) {
	b, f, _ := newTest(t)
	f.tables["bing"] = map[netip.Prefix]bool{netip.MustParsePrefix("198.51.100.7/32"): false}
	f.tables["doh"] = map[netip.Prefix]bool{netip.MustParsePrefix("2001:db8::/32"): false}
	for _, a := range []string{"198.51.100.7", "2001:db8::9", "192.0.2.50"} {
		f.states[netip.MustParseAddr(a)] = true
	}
	if err := b.Load(t.Context(), compile(t, testConfig)); err != nil {
		t.Fatalf("Load: %v", err)
	}
	st, err := b.Read(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := map[policy.Name][]netip.Prefix{"bing": prefixes("198.51.100.7/32"), "doh": prefixes("2001:db8::/32")}
	if !maps.EqualFunc(st.Tables, want, slices.Equal) {
		t.Errorf("tables after Load = %v, want %v", st.Tables, want)
	}
	if got := slices.Collect(maps.Keys(f.states)); !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.0.2.50")}) {
		t.Errorf("states after Load = %v, want only the state to 192.0.2.50", got)
	}
}

func TestAddEntries(t *testing.T) {
	b, f, _ := newTest(t)
	entries := prefixes("198.51.100.1/32", "2001:db8::1/128", "203.0.113.0/24")
	f.states[netip.MustParseAddr("203.0.113.9")] = true
	f.states[netip.MustParseAddr("2001:db8::1")] = true
	for range 2 {
		if err := b.AddEntries(t.Context(), "bing", entries); err != nil {
			t.Fatalf("AddEntries: %v", err)
		}
	}
	st, err := b.Read(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Tables["bing"]; !slices.Equal(got, prefixes("198.51.100.1/32", "203.0.113.0/24", "2001:db8::1/128")) {
		t.Errorf("table bing = %v, want each entry once", got)
	}
	if len(f.states) != 0 {
		t.Errorf("states after AddEntries = %v, want none", f.states)
	}

	if err := b.AddEntries(t.Context(), "empty", nil); err != nil {
		t.Fatalf("AddEntries with no entry: %v", err)
	}
	if _, ok := f.tables["empty"]; !ok {
		t.Error("AddEntries with no entry did not create the table")
	}
}

func TestAddEntriesReplacesANegatedEntry(t *testing.T) {
	b, f, _ := newTest(t)
	e := netip.MustParsePrefix("198.51.100.1/32")
	f.tables["bing"] = map[netip.Prefix]bool{e: true}
	if err := b.AddEntries(t.Context(), "bing", []netip.Prefix{e}); err != nil {
		t.Fatalf("AddEntries: %v", err)
	}
	if neg, ok := f.tables["bing"][e]; !ok || neg {
		t.Errorf("table bing holds %v (present %v, negated %v), want the entry not negated", e, ok, neg)
	}

	f.tables["bing"][e] = true
	f.stickyNegation = true
	if err := b.AddEntries(t.Context(), "bing", []netip.Prefix{e}); !errors.Is(err, errConflict) {
		t.Errorf("AddEntries with a negated entry that stays: error = %v, want errConflict", err)
	}
}

func TestAddEntriesRefusesAnInvalidEntry(t *testing.T) {
	b, f, _ := newTest(t)
	if err := b.AddEntries(t.Context(), "bing", []netip.Prefix{{}}); !errors.Is(err, errEntry) {
		t.Errorf("AddEntries(invalid) error = %v, want errEntry", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("AddEntries ran pfctl %v for an invalid entry", f.calls)
	}
}

func TestRemoveEntries(t *testing.T) {
	b, f, _ := newTest(t)
	keep, gone := netip.MustParsePrefix("198.51.100.1/32"), netip.MustParsePrefix("198.51.100.2/32")
	f.tables["bing"] = map[netip.Prefix]bool{keep: false, gone: false}
	for range 2 {
		if err := b.RemoveEntries(t.Context(), "bing", []netip.Prefix{gone}); err != nil {
			t.Fatalf("RemoveEntries: %v", err)
		}
	}
	if got := slices.Collect(maps.Keys(f.tables["bing"])); !slices.Equal(got, []netip.Prefix{keep}) {
		t.Errorf("table bing = %v, want [%v]", got, keep)
	}
	if err := b.RemoveEntries(t.Context(), "missing", []netip.Prefix{gone}); err != nil {
		t.Errorf("RemoveEntries from a missing table: %v", err)
	}
	f.fail = func(args []string) bool { return slices.Contains(args, "delete") }
	if err := b.RemoveEntries(t.Context(), "bing", []netip.Prefix{keep}); !errors.Is(err, errPfctl) {
		t.Errorf("RemoveEntries with a failing pfctl: error = %v, want errPfctl", err)
	}
}

func TestDropTable(t *testing.T) {
	b, f, _ := newTest(t)
	f.tables["bing"] = map[netip.Prefix]bool{netip.MustParsePrefix("198.51.100.1/32"): false}
	for range 2 {
		if err := b.DropTable(t.Context(), "bing"); err != nil {
			t.Fatalf("DropTable: %v", err)
		}
	}
	if _, ok := f.tables["bing"]; ok {
		t.Error("table bing exists after DropTable")
	}
}

func TestReadReportsNegatedEntries(t *testing.T) {
	b, f, _ := newTest(t)
	f.enabled = true
	f.tables["bing"] = map[netip.Prefix]bool{
		netip.MustParsePrefix("10.0.0.0/8"):  false,
		netip.MustParsePrefix("10.1.2.3/32"): true,
	}
	st, err := b.Read(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := st.Tables["bing"]; !ok || len(got) != 0 {
		t.Errorf("table bing = %v (exists %v), want an empty table: the negated entry voids 10.0.0.0/8", got, ok)
	}
	want := []reconcile.Problem{voids("the table bing of the ifbound anchor holds the negated entry !10.1.2.3/32, which exempts these addresses")}
	if !slices.Equal(st.Problems, want) {
		t.Errorf("problems = %v, want %v", st.Problems, want)
	}

	// A negated entry inside no entry of its table exempts nothing.
	f.tables["bing"] = map[netip.Prefix]bool{netip.MustParsePrefix("192.0.2.0/24"): false, netip.MustParsePrefix("10.1.2.3/32"): true}
	if st, err := b.Read(t.Context()); err != nil || len(st.Problems) != 0 {
		t.Errorf("Read with a negated entry outside the entries = (%v, %v), want no problem", st.Problems, err)
	}
}

func TestReadProblems(t *testing.T) {
	passQuickRule := "pass out quick on en0 all flags S/SA keep state"
	tests := []struct {
		name   string
		change func(f *fakePF)
		want   []string // a part of the text of each Problem, in order
	}{
		{"clean host", func(*fakePF) {}, nil},
		{"pf disabled", func(f *fakePF) { f.enabled = false }, []string{"pf is disabled"}},
		{"no com.apple anchor rule", func(f *fakePF) { f.main = f.main[:1] }, []string{`no rule anchor "com.apple/*"`}},
		{"main ruleset empty", func(f *fakePF) { f.main = nil }, []string{`no rule anchor "com.apple/*"`}},
		{"quick pass in the main ruleset first", func(f *fakePF) {
			f.main = append([]string{passQuickRule}, f.main...)
		}, []string{"in the main pf ruleset comes before"}},
		{"quick pass in the main ruleset after the anchor", func(f *fakePF) {
			f.main = append(f.main, passQuickRule)
		}, nil},
		{"quick pass in an earlier anchor of the main ruleset", func(f *fakePF) {
			f.main = append([]string{`anchor "vpn/*" all`}, f.main...)
			f.anchors["vpn/kill"] = []string{passQuickRule}
		}, []string{"in the anchor vpn/kill comes before"}},
		{"quick pass in an earlier com.apple anchor", func(f *fakePF) {
			f.anchors["com.apple/0.tool"] = []string{passQuickRule}
		}, []string{"in the anchor com.apple/0.tool comes before"}},
		{"quick pass below an earlier com.apple anchor", func(f *fakePF) {
			f.anchors["com.apple/0.tool"] = []string{`anchor "com.apple/0.tool/*" all`}
			f.anchors["com.apple/0.tool/x"] = []string{passQuickRule}
		}, []string{"in the anchor com.apple/0.tool/x comes before"}},
		{"non-quick pass in an earlier com.apple anchor", func(f *fakePF) {
			f.anchors["com.apple/0.tool"] = []string{"pass out on en0 inet all flags any keep state"}
		}, nil},
		{"quick pass in a later com.apple anchor", func(f *fakePF) {
			f.anchors["com.apple/100.tool"] = []string{passQuickRule}
			f.anchors["com.apple/000.ifboundx"] = []string{passQuickRule}
		}, nil},
		{"pfctl cannot read an earlier anchor", func(f *fakePF) {
			f.anchors["com.apple/0.tool"] = nil
			f.complain = func(args []string) bool {
				return slices.Contains(args, "com.apple/0.tool") && slices.Contains(args, "-sr")
			}
		}, []string{"cannot read the rules of the anchor com.apple/0.tool"}},
		{"pfctl cannot read the filter rules of a later anchor", func(f *fakePF) {
			f.complain = func(args []string) bool {
				return slices.Contains(args, "com.apple/200.AirDrop") && slices.Contains(args, "-sr")
			}
		}, nil},
		{"set skip on en0", func(f *fakePF) { f.ifaces = []string{"en0 (skip)", "lo0"} }, []string{"skips the interface en0"}},
		{"set skip on lo0", func(f *fakePF) { f.ifaces = []string{"en0", "lo0 (skip)"} }, nil},
		{"anchor reference for inbound packets only", func(f *fakePF) {
			f.main[1] = `anchor "com.apple/*" in all`
		}, []string{`no rule anchor "com.apple/*"`}},
		{"nat pass in a later anchor", func(f *fakePF) {
			f.anchors["com.apple/300.share"] = nil
			f.nat["com.apple/300.share"] = []string{"nat pass on en0 inet from 192.168.2.0/24 to any -> (en0) round-robin"}
		}, []string{"in the anchor com.apple/300.share passes"}},
		{"nat pass in the main ruleset", func(f *fakePF) {
			f.nat[""] = append(f.nat[""], "binat pass on en0 from 192.168.2.5 to any -> 192.168.64.99")
		}, []string{"in the main pf ruleset passes"}},
		{"nat without pass", func(f *fakePF) {
			f.anchors["com.apple/300.share"] = nil
			f.nat["com.apple/300.share"] = []string{"nat on en0 inet from 192.168.2.0/24 to any -> (en0) round-robin"}
		}, nil},
		{"pfctl cannot read the NAT rules of an anchor", func(f *fakePF) {
			f.complain = func(args []string) bool {
				return slices.Contains(args, "com.apple/200.AirDrop") && slices.Contains(args, "-sn")
			}
		}, []string{"cannot read the NAT rules of the anchor com.apple/200.AirDrop"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, f, _ := newTest(t)
			f.enabled = true
			tt.change(f)
			st, err := b.Read(t.Context())
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if len(st.Problems) != len(tt.want) {
				t.Fatalf("problems = %v, want %d matching %q", st.Problems, len(tt.want), tt.want)
			}
			for i, p := range st.Problems {
				if !p.Voids || !strings.Contains(p.Text, tt.want[i]) {
					t.Errorf("problem %d = %+v, want a voiding problem with %q", i, p, tt.want[i])
				}
			}
		})
	}
}

func TestPfctlFailure(t *testing.T) {
	b, f, _ := newTest(t)
	f.fail = func(args []string) bool { return slices.Contains(args, "-f") }
	err := b.Load(t.Context(), compile(t, testConfig))
	if !errors.Is(err, errPfctl) || !strings.Contains(err.Error(), "injected failure") {
		t.Errorf("Load with a failing pfctl: error = %v, want errPfctl with the stderr text", err)
	}
	f.fail = func(args []string) bool { return slices.Contains(args, "-sT") }
	if _, err := b.Read(t.Context()); !errors.Is(err, errPfctl) {
		t.Errorf("Read with a failing pfctl: error = %v, want errPfctl", err)
	}
	f.states[netip.MustParseAddr("198.51.100.1")] = true
	f.fail = func(args []string) bool { return slices.Contains(args, "-k") }
	if err := b.AddEntries(t.Context(), "bing", prefixes("198.51.100.1/32")); !errors.Is(err, errPfctl) {
		t.Errorf("AddEntries with a failing state kill: error = %v, want errPfctl", err)
	}
}

// values returns the token values that the Backend holds.
func values(b *Backend) []string {
	var out []string
	for _, t := range b.tokens {
		out = append(out, t.value)
	}
	return out
}

func TestReleaseToken(t *testing.T) {
	b, f, c := newTest(t)
	if err := b.release(t.Context()); err != nil || len(f.calls) != 0 {
		t.Fatalf("release without a token: error %v, calls %v; want nothing", err, f.calls)
	}
	if err := b.Load(t.Context(), compile(t, testConfig)); err != nil {
		t.Fatal(err)
	}
	f.tokens = append(f.tokens, "77")
	if err := b.release(t.Context()); err != nil {
		t.Fatalf("release: %v", err)
	}
	if !slices.Equal(f.tokens, []string{"77"}) || !f.enabled {
		t.Errorf("after release: tokens %v, enabled %v; want the other token only, pf enabled", f.tokens, f.enabled)
	}

	f.enabled, f.tokens = false, nil
	c.t = c.t.Add(EnableInterval)
	if err := b.Load(t.Context(), compile(t, testConfig)); err != nil {
		t.Fatal(err)
	}
	f.enabled, f.tokens = false, nil // pfctl -d drops every token
	before := len(f.callsOf("-X"))
	if err := b.release(t.Context()); err != nil {
		t.Errorf("release after pf was disabled: %v", err)
	}
	if len(b.tokens) != 0 {
		t.Errorf("tokens after release = %v, want none", b.tokens)
	}
	if calls := f.callsOf("-X"); len(calls) != before {
		t.Errorf("release after pf was disabled ran %v", calls)
	}

	c.t = c.t.Add(EnableInterval)
	if err := b.Load(t.Context(), compile(t, testConfig)); err != nil {
		t.Fatal(err)
	}
	f.fail = func(args []string) bool { return slices.Contains(args, "-X") }
	held := slices.Clone(b.tokens)
	if err := b.release(t.Context()); !errors.Is(err, errPfctl) || !slices.Equal(b.tokens, held) {
		t.Errorf("release with a failing pfctl: error %v, tokens %v; want errPfctl and %v kept", err, b.tokens, held)
	}
}

// pf gives a released value again. A token whose value another process
// holds now, with another creation time, is not the token of ifbound.
func TestReleaseLeavesAReusedValue(t *testing.T) {
	b, f, c := newTest(t)
	if err := b.Load(t.Context(), compile(t, testConfig)); err != nil {
		t.Fatal(err)
	}
	mine := b.tokens[0]
	f.tokens, f.free = nil, []string{mine.value} // pfctl -d drops it
	c.t = c.t.Add(time.Minute)
	f.enabled = true
	if _, err := f.Run(t.Context(), nil, "-E"); err != nil { // another tool gets the same value
		t.Fatal(err)
	}
	if !slices.Equal(f.tokens, []string{mine.value}) {
		t.Fatalf("the other tool got %v, want the reused value %s", f.tokens, mine.value)
	}
	if err := b.release(t.Context()); err != nil {
		t.Fatalf("release: %v", err)
	}
	if calls := f.callsOf("-X"); len(calls) != 0 {
		t.Errorf("release ran %v: the value belongs to another process now", calls)
	}
	if !f.enabled || !slices.Equal(f.tokens, []string{mine.value}) {
		t.Errorf("after release: enabled %v tokens %v; want the reference of the other tool", f.enabled, f.tokens)
	}
}
