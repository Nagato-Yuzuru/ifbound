package pfbackend_test

// Tests of the pf Backend through its public methods (New, the
// reconcile.Backend methods, and Release), against the kernel model in
// kernel_test.go. The expected values come from the contract in
// internal/reconcile/platform.go and from pf.conf(5).

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/pfbackend"
	"github.com/Nagato-Yuzuru/ifbound/internal/pfrules"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

const testPolicies = `
[[policy]]
name     = "bing"
to       = ["*.bing.com", "203.0.113.0/24"]
only_via = ["@tunnel"]

[[policy]]
name     = "doh"
to       = ["1.1.1.1/32", "2606:4700:4700::1111/128"]
only_via = []
`

const otherPolicy = `
[[policy]]
name     = "extra"
to       = ["192.0.2.1"]
only_via = []
`

var modelIfaces = []reconcile.Interface{
	{Name: "en0", Class: policy.ClassHardware},
	{Name: "utun4", Class: policy.ClassTunnel},
}

type modelClock struct{ t time.Time }

func (c *modelClock) now() time.Time { return c.t }

// warnings records the level of each log record.
type warnings struct {
	mu     sync.Mutex
	levels []slog.Level
}

func (w *warnings) Enabled(context.Context, slog.Level) bool { return true }
func (w *warnings) Handle(_ context.Context, r slog.Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.levels = append(w.levels, r.Level)
	return nil
}
func (w *warnings) WithAttrs([]slog.Attr) slog.Handler { return w }
func (w *warnings) WithGroup(string) slog.Handler      { return w }

func (w *warnings) count(l slog.Level) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, x := range w.levels {
		if x == l {
			n++
		}
	}
	return n
}

type rig struct {
	b   *pfbackend.Backend
	k   *kernel
	clk *modelClock
	log *warnings
}

// newRig returns a Backend on a fresh kernel. Each test checks at the end
// that the Backend never ran "pfctl -d".
func newRig(t *testing.T) *rig {
	t.Helper()
	k := newKernel()
	clk := &modelClock{t: time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)}
	w := &warnings{}
	t.Cleanup(func() {
		if k.disables != 0 {
			t.Errorf("the Backend ran pfctl -d %d times; it must never disable pf", k.disables)
		}
	})
	return &rig{b: pfbackend.New(k, clk.now, slog.New(w)), k: k, clk: clk, log: w}
}

func compileRS(t *testing.T, config string) reconcile.Ruleset {
	t.Helper()
	cfg, err := policy.ParseBytes([]byte("[dns]\nupstream = [\"tls://1.1.1.1@a.example\"]\n" + config))
	if err != nil {
		t.Fatalf("parsing config: %v", err)
	}
	rs, err := pfrules.Compiler{}.Compile(cfg.Policies, modelIfaces, reconcile.Accounts{})
	if err != nil {
		t.Fatalf("compiling: %v", err)
	}
	return rs
}

func mustLoad(t *testing.T, r *rig, rs reconcile.Ruleset) {
	t.Helper()
	if err := r.b.Load(t.Context(), rs); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func mustRead(t *testing.T, r *rig) reconcile.BackendState {
	t.Helper()
	st, err := r.b.Read(t.Context())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return st
}

func mustID(t *testing.T, r *rig) string {
	t.Helper()
	id, err := r.b.LoadedID(t.Context())
	if err != nil {
		t.Fatalf("LoadedID: %v", err)
	}
	return id
}

func pfx(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func voiding(ps []reconcile.Problem) []reconcile.Problem {
	var out []reconcile.Problem
	for _, p := range ps {
		if p.Voids {
			out = append(out, p)
		}
	}
	return out
}

const ifb = pfbackend.Anchor

// Load: one transaction into com.apple/000.ifbound

func TestLoadIsOneTransactionIntoTheIfboundAnchor(t *testing.T) {
	r := newRig(t)
	rs := compileRS(t, testPolicies)
	if ifb != "com.apple/000.ifbound" {
		t.Fatalf("Anchor = %q, want com.apple/000.ifbound", ifb)
	}
	mustLoad(t, r, rs)
	loads := r.k.callsWith("-f")
	if len(loads) != 1 {
		t.Fatalf("Load ran %d pfctl -f calls %v, want exactly 1", len(loads), loads)
	}
	if got := loads[0]; !slices.Equal(got, []string{"-a", ifb, "-f", "-"}) {
		t.Errorf("load call = %v, want [-a %s -f -]", got, ifb)
	}
	// The anchor holds every rule of the compiled body, in one load.
	got := strings.Join(r.k.rules[ifb], "\n")
	for line := range strings.Lines(string(rs.Body())) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "table ") || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(got, line) {
			t.Errorf("anchor misses the compiled rule %q", line)
		}
	}
}

func TestLoadWritesNoOtherAnchorAndNoMainRuleset(t *testing.T) {
	r := newRig(t)
	before := slices.Clone(r.k.mainRules)
	airdrop := slices.Clone(r.k.rules["com.apple/200.AirDrop"])
	alf := slices.Clone(r.k.rules["com.apple/250.ApplicationFirewall"])
	mustLoad(t, r, compileRS(t, testPolicies))
	if !slices.Equal(r.k.mainRules, before) {
		t.Errorf("main ruleset changed to %v", r.k.mainRules)
	}
	if !slices.Equal(r.k.rules["com.apple/200.AirDrop"], airdrop) || !slices.Equal(r.k.rules["com.apple/250.ApplicationFirewall"], alf) {
		t.Errorf("Load changed an anchor of macOS")
	}
	for _, c := range r.k.calls {
		i := slices.Index(c, "-a")
		writes := slices.Contains(c, "-f") || slices.Contains(c, "-F") || slices.Contains(c, "-T") && !slices.Contains(c, "show")
		if writes && (i < 0 || c[i+1] != ifb && !strings.HasPrefix(c[i+1], ifb+"/")) {
			t.Errorf("Load wrote outside the ifbound anchor: %v", c)
		}
	}
}

// Load keeps the tables (S3)

func TestLoadKeepsTableEntries(t *testing.T) {
	r := newRig(t)
	r.k.setEntries(ifb, "bing", "203.0.113.0/24", "198.51.100.7/32")
	r.k.setEntries(ifb, "doh", "1.1.1.1/32")
	r.k.setEntries(ifb, "orphan", "192.0.2.9/32")
	mustLoad(t, r, compileRS(t, testPolicies))
	mustLoad(t, r, compileRS(t, testPolicies+otherPolicy))
	if got, want := r.k.entries(ifb, "bing"), pfx("198.51.100.7/32", "203.0.113.0/24"); !slices.Equal(got, want) {
		t.Errorf("bing after reload = %v, want %v", got, want)
	}
	if got, want := r.k.entries(ifb, "doh"), pfx("1.1.1.1/32"); !slices.Equal(got, want) {
		t.Errorf("doh after reload = %v, want %v", got, want)
	}
	if got, want := r.k.entries(ifb, "orphan"), pfx("192.0.2.9/32"); !slices.Equal(got, want) {
		t.Errorf("a table that no rule refers to = %v, want %v (only DropTable removes a table)", got, want)
	}
	for _, verb := range []string{"add", "delete", "kill", "flush", "replace"} {
		if c := r.k.callsWith("-T", verb); len(c) != 0 {
			t.Errorf("Load ran -T %s: %v; Load never fills, empties, or drops a table", verb, c)
		}
	}
	// The contract: a declared table that is missing exists after Load,
	// empty.
	if tb, ok := r.k.tables[ifb]["extra"]; !ok || len(tb) != 0 {
		t.Errorf("declared table extra after Load = %v (exists %v), want an empty table", tb, ok)
	}
}

// Read and LoadedID: from the kernel, ID equals the Compiler ID

func TestLoadedIDIsTheCompilerID(t *testing.T) {
	r := newRig(t)
	if got := mustID(t, r); got != "" {
		t.Errorf("LoadedID before any Load = %q, want \"\"", got)
	}
	rs1 := compileRS(t, testPolicies)
	rs2 := compileRS(t, testPolicies+otherPolicy)
	for _, rs := range []reconcile.Ruleset{rs1, rs2, rs1} {
		mustLoad(t, r, rs)
		if got := mustID(t, r); got != rs.ID() {
			t.Errorf("LoadedID = %q, want the Compiler ID %q", got, rs.ID())
		}
		if got := mustRead(t, r).Ruleset; got != rs.ID() {
			t.Errorf("Read.Ruleset = %q, want the Compiler ID %q", got, rs.ID())
		}
	}
}

func TestReadSeesExternalChanges(t *testing.T) {
	rs := compileRS(t, testPolicies)
	tests := []struct {
		name   string
		change func(k *kernel)
		check  func(t *testing.T, r *rig)
	}{
		{"rules flushed", func(k *kernel) { k.rules[ifb] = nil }, wantNoID},
		{"anchor loaded by another tool", func(k *kernel) { k.load(ifb, []byte("block drop out quick all\n")) }, wantNoID},
		{"same rules without the sentinel", func(k *kernel) {
			k.rules[ifb] = slices.DeleteFunc(slices.Clone(k.rules[ifb]), func(s string) bool { return strings.Contains(s, "label") })
		}, wantNoID},
		{"rule put in a sub-anchor", func(k *kernel) { k.rules[ifb+"/tag.bing"] = []string{"pass out quick all no state"} }, wantNoID},
		{"rule put in a nested sub-anchor", func(k *kernel) {
			k.rules[ifb+"/tag.bing"] = []string{`anchor "deep" all`}
			k.rules[ifb+"/tag.bing/deep"] = []string{"pass out quick all no state"}
		}, wantNoID},
		{"pf disabled", func(k *kernel) { k.enabled, k.refs = false, nil }, wantNoID},
		{"table flushed", func(k *kernel) { clear(k.tables[ifb]["doh"]) }, func(t *testing.T, r *rig) {
			t.Helper()
			if got := mustRead(t, r).Tables["doh"]; len(got) != 0 {
				t.Errorf("Read.Tables[doh] after an external flush = %v, want empty", got)
			}
			if _, ok := mustRead(t, r).Tables["doh"]; !ok {
				t.Errorf("Read.Tables misses the flushed but present table doh")
			}
		}},
		{"table killed", func(k *kernel) { delete(k.tables[ifb], "doh") }, func(t *testing.T, r *rig) {
			t.Helper()
			if _, ok := mustRead(t, r).Tables["doh"]; ok {
				t.Errorf("Read.Tables still has the killed table doh")
			}
		}},
		{"entry added by another tool", func(k *kernel) { k.tables[ifb]["doh"][netip.MustParsePrefix("9.9.9.9/32")] = false }, func(t *testing.T, r *rig) {
			t.Helper()
			if got, want := mustRead(t, r).Tables["doh"], pfx("1.1.1.1/32", "9.9.9.9/32"); !slices.Equal(sorted(got), want) {
				t.Errorf("Read.Tables[doh] = %v, want %v", got, want)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t)
			mustLoad(t, r, rs)
			if err := r.b.AddEntries(t.Context(), "doh", pfx("1.1.1.1/32")); err != nil {
				t.Fatal(err)
			}
			if got := mustRead(t, r); got.Ruleset != rs.ID() || len(voiding(got.Problems)) != 0 {
				t.Fatalf("before the change: Read = %+v, want ID %s and no voiding Problem", got, rs.ID())
			}
			tt.change(r.k)
			tt.check(t, r)
		})
	}
}

func wantNoID(t *testing.T, r *rig) {
	t.Helper()
	if got := mustID(t, r); got != "" {
		t.Errorf("LoadedID after the change = %q, want \"\"", got)
	}
	if got := mustRead(t, r).Ruleset; got != "" {
		t.Errorf("Read.Ruleset after the change = %q, want \"\"", got)
	}
}

func sorted(ps []netip.Prefix) []netip.Prefix {
	ps = slices.Clone(ps)
	slices.SortFunc(ps, netip.Prefix.Compare)
	return ps
}

func TestLoadRepairsSubAnchorRules(t *testing.T) {
	r := newRig(t)
	rs := compileRS(t, testPolicies)
	mustLoad(t, r, rs)
	r.k.rules[ifb+"/tag.bing"] = []string{"pass out quick all no state"}
	r.k.rules[ifb+"/tag.removed"] = []string{"pass out quick all no state"}
	mustLoad(t, r, rs)
	for _, sub := range []string{"tag.bing", "tag.removed"} {
		if got := r.k.rules[ifb+"/"+sub]; len(got) != 0 {
			t.Errorf("sub-anchor %s after Load = %v, want no rule", sub, got)
		}
	}
	if got := mustID(t, r); got != rs.ID() {
		t.Errorf("LoadedID after the repair = %q, want %q", got, rs.ID())
	}
}

func TestReadReportsNegatedEntriesOutsideTables(t *testing.T) {
	r := newRig(t)
	mustLoad(t, r, compileRS(t, testPolicies))
	r.k.setEntries(ifb, "bing", "203.0.113.0/24", "!203.0.113.9/32", "198.51.100.1/32")
	st := mustRead(t, r)
	// The negated entry blocks nothing, and it voids the prefix that holds it.
	if got, want := sorted(st.Tables["bing"]), pfx("198.51.100.1/32"); !slices.Equal(got, want) {
		t.Errorf("Read.Tables[bing] = %v, want %v", got, want)
	}
	if len(voiding(st.Problems)) != 1 {
		t.Errorf("Read.Problems = %+v, want one voiding Problem for !203.0.113.9", st.Problems)
	}
}

// Writes: -T add / -T delete / -T kill, idempotent

func TestWritesUseTheTableCommandsAndAreIdempotent(t *testing.T) {
	r := newRig(t)
	mustLoad(t, r, compileRS(t, testPolicies))
	ctx := t.Context()
	add := pfx("198.51.100.1/32", "2001:db8::1/128", "10.0.0.0/8")
	for range 2 {
		if err := r.b.AddEntries(ctx, "bing", add); err != nil {
			t.Fatalf("AddEntries: %v", err)
		}
	}
	if got, want := r.k.entries(ifb, "bing"), sorted(add); !slices.Equal(got, want) {
		t.Errorf("bing after AddEntries twice = %v, want %v", got, want)
	}
	if err := r.b.AddEntries(ctx, "fresh", pfx("192.0.2.5/32")); err != nil {
		t.Fatalf("AddEntries to a missing table: %v", err)
	}
	if got, want := r.k.entries(ifb, "fresh"), pfx("192.0.2.5/32"); !slices.Equal(got, want) {
		t.Errorf("AddEntries did not create the table: %v, want %v", got, want)
	}
	checkRemoveAndDrop(t, r)
}

func checkRemoveAndDrop(t *testing.T, r *rig) {
	t.Helper()
	ctx := t.Context()
	for range 2 {
		if err := r.b.RemoveEntries(ctx, "bing", pfx("10.0.0.0/8")); err != nil {
			t.Fatalf("RemoveEntries: %v", err)
		}
	}
	if got, want := r.k.entries(ifb, "bing"), pfx("198.51.100.1/32", "2001:db8::1/128"); !slices.Equal(got, want) {
		t.Errorf("bing after RemoveEntries twice = %v, want %v", got, want)
	}
	if err := r.b.RemoveEntries(ctx, "missing", pfx("10.0.0.0/8")); err != nil {
		t.Errorf("RemoveEntries on a missing table = %v, want nil", err)
	}
	for range 2 {
		if err := r.b.DropTable(ctx, "bing"); err != nil {
			t.Errorf("DropTable: %v", err)
		}
	}
	if _, ok := r.k.tables[ifb]["bing"]; ok {
		t.Errorf("table bing exists after DropTable")
	}
	for _, verb := range []string{"add", "delete", "kill"} {
		if len(r.k.callsWith("-T", verb)) == 0 {
			t.Errorf("no pfctl -T %s call", verb)
		}
	}
	for _, c := range r.k.callsWith("-T") {
		if i := slices.Index(c, "-a"); i < 0 || c[i+1] != ifb {
			t.Errorf("table command outside the ifbound anchor: %v", c)
		}
	}
}

func TestWriteErrorsAreReported(t *testing.T) {
	r := newRig(t)
	mustLoad(t, r, compileRS(t, testPolicies))
	r.k.fail = func(args []string) bool { return slices.Contains(args, "-T") && !slices.Contains(args, "show") }
	ctx := t.Context()
	if err := r.b.AddEntries(ctx, "bing", pfx("192.0.2.1/32")); err == nil {
		t.Errorf("AddEntries with a failing pfctl = nil, want an error")
	}
	if err := r.b.RemoveEntries(ctx, "bing", pfx("192.0.2.1/32")); err == nil {
		t.Errorf("RemoveEntries with a failing pfctl = nil, want an error")
	}
	if err := r.b.DropTable(ctx, "bing"); err == nil {
		t.Errorf("DropTable with a failing pfctl = nil, want an error")
	}
	if err := r.b.AddEntries(ctx, "bing", []netip.Prefix{{}}); err == nil {
		t.Errorf("AddEntries with an invalid prefix = nil, want an error")
	}
}

// States: after Load and AddEntries

func TestLoadEndsStatesToTableEntries(t *testing.T) {
	r := newRig(t)
	r.k.setEntries(ifb, "bing", "203.0.113.0/24")
	r.k.setEntries(ifb, "doh", "1.1.1.1/32", "2606:4700:4700::1111/128")
	r.k.states = []netip.Addr{
		netip.MustParseAddr("203.0.113.77"), netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("8.8.4.4"),
	}
	mustLoad(t, r, compileRS(t, testPolicies))
	for _, a := range []string{"203.0.113.77", "1.1.1.1", "2606:4700:4700::1111"} {
		if r.k.hasState(a) {
			t.Errorf("a state to %s survives Load", a)
		}
	}
}

func TestAddEntriesEndsStatesToNewEntries(t *testing.T) {
	r := newRig(t)
	mustLoad(t, r, compileRS(t, testPolicies))
	r.k.states = []netip.Addr{netip.MustParseAddr("198.51.100.3"), netip.MustParseAddr("2001:db8::3")}
	if err := r.b.AddEntries(t.Context(), "bing", pfx("198.51.100.3/32", "2001:db8::/64")); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"198.51.100.3", "2001:db8::3"} {
		if r.k.hasState(a) {
			t.Errorf("a state to %s survives AddEntries", a)
		}
	}
}

// Problems with Voids

func TestVoidingProblems(t *testing.T) {
	tests := []struct {
		name   string
		change func(k *kernel)
		voids  bool
	}{
		{"clean macOS default", func(*kernel) {}, false},
		{"pf disabled", func(k *kernel) { k.enabled, k.refs = false, nil }, true},
		{"main ruleset without anchor com.apple/*", func(k *kernel) {
			k.mainRules = []string{`scrub-anchor "com.apple/*" all fragment reassemble`}
		}, true},
		{"main ruleset flushed", func(k *kernel) { k.mainRules = nil }, true},
		{"pass quick in an anchor that sorts before", func(k *kernel) {
			k.rules["com.apple/000.aaa-vpn"] = []string{"pass out quick all flags S/SA keep state"}
		}, true},
		{"pass quick in an anchor one byte before", func(k *kernel) {
			k.rules["com.apple/000.ifbounc"] = []string{"pass out quick on en0 all"}
		}, true},
		{"pass quick in a sub-anchor of an earlier anchor", func(k *kernel) {
			k.rules["com.apple/000.aaa-vpn"] = []string{`anchor "inner" all`}
			k.rules["com.apple/000.aaa-vpn/inner"] = []string{"pass out quick all"}
		}, true},
		{"pass quick in the main ruleset before the anchor", func(k *kernel) {
			k.mainRules = []string{"pass out quick on en0 all", `anchor "com.apple/*" all`}
		}, true},
		{"set skip on a physical interface", func(k *kernel) { k.ifaces = []string{"ALL", "en0 (skip)", "lo0"} }, true},
		// Near misses: these do not void the ifbound rules.
		{"pass quick in an anchor that sorts after", func(k *kernel) {
			k.rules["com.apple/300.late"] = []string{"pass out quick all"}
		}, false},
		{"pass quick in an anchor whose name extends the ifbound name", func(k *kernel) {
			k.rules["com.apple/000.ifbound0"] = []string{"pass out quick all"}
		}, false},
		{"pass without quick before", func(k *kernel) {
			k.rules["com.apple/000.aaa-vpn"] = []string{"pass out all flags S/SA keep state"}
		}, false},
		{"block quick before", func(k *kernel) {
			k.rules["com.apple/000.aaa-vpn"] = []string{"block drop out quick all"}
		}, false},
		{"pass quick in the main ruleset after the anchor", func(k *kernel) {
			k.mainRules = []string{`anchor "com.apple/*" all`, "pass out quick on en0 all"}
		}, false},
		{"set skip on loopback", func(k *kernel) { k.ifaces = []string{"ALL", "en0", "lo0 (skip)"} }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t)
			mustLoad(t, r, compileRS(t, testPolicies))
			tt.change(r.k)
			st := mustRead(t, r)
			if got := len(voiding(st.Problems)) > 0; got != tt.voids {
				t.Errorf("voiding Problem = %v, want %v; Problems = %+v", got, tt.voids, st.Problems)
			}
		})
	}
}

// Enable: -E with a token, rate limit, warning, never -d

func TestLoadEnablesPfAndKeepsTheToken(t *testing.T) {
	r := newRig(t)
	mustLoad(t, r, compileRS(t, testPolicies))
	if !r.k.enabled {
		t.Fatalf("pf is disabled after Load")
	}
	if len(r.k.refs) != 1 {
		t.Fatalf("pf holds %d references after Load, want 1", len(r.k.refs))
	}
	if r.log.count(slog.LevelWarn) < 1 {
		t.Errorf("no warning logged when the Backend enabled pf")
	}
	tok := r.k.refs[0]
	if err := r.b.Release(t.Context()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if got := r.k.callsWith("-X", tok); len(got) != 1 {
		t.Errorf("Release ran %v, want one pfctl -X %s", got, tok)
	}
	if r.k.enabled {
		t.Errorf("pf is still enabled after Release of the only reference")
	}
	if err := r.b.Release(t.Context()); err != nil {
		t.Errorf("a second Release = %v, want nil", err)
	}
}

func TestEnableIsRateLimited(t *testing.T) {
	r := newRig(t)
	rs := compileRS(t, testPolicies)
	mustLoad(t, r, rs)
	r.k.enabled, r.k.refs = false, nil // another tool ran pfctl -d
	r.clk.t = r.clk.t.Add(5 * time.Second)
	if err := r.b.Load(t.Context(), rs); err == nil {
		t.Errorf("Load 5 s after the last enable = nil, want an error from the rate limit")
	}
	if n := len(r.k.callsWith("-E")); n != 1 {
		t.Errorf("pfctl -E ran %d times within the rate limit, want 1", n)
	}
	if got := mustRead(t, r); len(voiding(got.Problems)) == 0 {
		t.Errorf("Read while pf stays disabled has no voiding Problem")
	}
	r.clk.t = r.clk.t.Add(pfbackend.EnableInterval)
	mustLoad(t, r, rs)
	if !r.k.enabled || len(r.k.callsWith("-E")) != 2 {
		t.Errorf("after the rate limit: enabled %v, -E calls %d, want true and 2", r.k.enabled, len(r.k.callsWith("-E")))
	}
	if r.log.count(slog.LevelWarn) < 2 {
		t.Errorf("warnings = %d, want one per enable", r.log.count(slog.LevelWarn))
	}
}

func TestReleaseWithoutTokenRunsNothing(t *testing.T) {
	r := newRig(t)
	if err := r.b.Release(t.Context()); err != nil {
		t.Errorf("Release without a token = %v, want nil", err)
	}
	if len(r.k.calls) != 0 {
		t.Errorf("Release without a token ran %v", r.k.calls)
	}
}

func TestNoMethodRunsPfctlDisable(t *testing.T) {
	r := newRig(t)
	rs := compileRS(t, testPolicies)
	ctx := t.Context()
	mustLoad(t, r, rs)
	_ = r.b.AddEntries(ctx, "bing", pfx("192.0.2.1/32"))    //nolint:errcheck // the test inspects the recorded pfctl calls, not the results
	_ = r.b.RemoveEntries(ctx, "bing", pfx("192.0.2.1/32")) //nolint:errcheck // the test inspects the recorded pfctl calls, not the results
	_ = r.b.DropTable(ctx, "doh")                           //nolint:errcheck // the test inspects the recorded pfctl calls, not the results
	_, _ = r.b.Read(ctx)                                    //nolint:errcheck // the test inspects the recorded pfctl calls, not the results
	_, _ = r.b.LoadedID(ctx)                                //nolint:errcheck // the test inspects the recorded pfctl calls, not the results
	_ = r.b.Release(ctx)                                    //nolint:errcheck // the test inspects the recorded pfctl calls, not the results
	for _, c := range r.k.calls {
		if slices.Contains(c, "-d") || slices.Contains(c, "-F") && slices.Contains(c, "all") {
			t.Errorf("forbidden pfctl call %v", c)
		}
	}
}
