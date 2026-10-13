//go:build e2e && darwin

package e2e

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/pfbackend"
	"github.com/Nagato-Yuzuru/ifbound/internal/pfrules"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
	"github.com/Nagato-Yuzuru/ifbound/internal/testnet"
)

// These tests load the ifbound anchor into the pf of the host. Each test
// flushes the anchor and gives back the pf token at the end.

type testClock struct{ t time.Time }

func (c *testClock) now() time.Time { return c.t }

// newPfBackend returns a Backend on the real pfctl, with a clock that the
// test moves.
func newPfBackend(t *testing.T) (*pfbackend.Backend, *testClock) {
	t.Helper()
	requireE2E(t)
	c := &testClock{t: time.Now()}
	b := pfbackend.New(pfbackend.Exec{Path: pfbackend.Path}, c.now, slog.New(slog.DiscardHandler))
	t.Cleanup(func() {
		// t.Context is already canceled when cleanups run.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, pfbackend.Path, "-a", pfbackend.Anchor, "-F", "all").CombinedOutput(); err != nil {
			t.Errorf("flush %s: %v: %s", pfbackend.Anchor, err, out)
		}
		if err := b.Release(ctx); err != nil {
			t.Errorf("Release: %v", err)
		}
	})
	return b, c
}

func compilePolicies(t *testing.T, config string, ifaces ...reconcile.Interface) reconcile.Ruleset {
	t.Helper()
	cfg, err := policy.ParseBytes([]byte("[dns]\nupstream = [\"tls://1.1.1.1@a.example\"]\n" + config))
	if err != nil {
		t.Fatal(err)
	}
	rs, err := pfrules.Compiler{}.Compile(cfg.Policies, ifaces, reconcile.Accounts{})
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func pfctl(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), pfbackend.Path, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("pfctl %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func load(t *testing.T, b *pfbackend.Backend, rs reconcile.Ruleset) {
	t.Helper()
	if err := b.Load(t.Context(), rs); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func readState(t *testing.T, b *pfbackend.Backend) reconcile.BackendState {
	t.Helper()
	st, err := b.Read(t.Context())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return st
}

func requireLoadedID(t *testing.T, b *pfbackend.Backend, want string) {
	t.Helper()
	id, err := b.LoadedID(t.Context())
	if err != nil {
		t.Fatalf("LoadedID: %v", err)
	}
	if id != want {
		t.Fatalf("LoadedID = %q, want %q", id, want)
	}
}

func addEntries(t *testing.T, b *pfbackend.Backend, table policy.Name, entries ...string) {
	t.Helper()
	ps := make([]netip.Prefix, len(entries))
	for i, e := range entries {
		ps[i] = netip.MustParsePrefix(e)
	}
	if err := b.AddEntries(t.Context(), table, ps); err != nil {
		t.Fatalf("AddEntries %s: %v", table, err)
	}
}

const policyA = `
[[policy]]
name     = "e2e-a"
to       = ["192.0.2.0/24"]
only_via = []
`

// TestPfBackendReloadKeepsEntries checks that the ID that the kernel
// gives back is the Compiler ID, and that a reload keeps the entries that
// AddEntries added.
func TestPfBackendReloadKeepsEntries(t *testing.T) {
	b, _ := newPfBackend(t)
	rs := compilePolicies(t, policyA)
	load(t, b, rs)
	requireLoadedID(t, b, rs.ID())
	addEntries(t, b, "e2e-a", "198.51.100.7/32", "2001:db8::7/128")

	rs2 := compilePolicies(t, policyA+"\n[[policy]]\nname = \"e2e-b\"\nto = [\"192.0.2.99\"]\nonly_via = [\"lo0\"]\n")
	load(t, b, rs2)
	requireLoadedID(t, b, rs2.ID())
	st := readState(t, b)
	if st.Ruleset != rs2.ID() {
		t.Errorf("Read ruleset = %q, want %q", st.Ruleset, rs2.ID())
	}
	want := []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32"), netip.MustParsePrefix("2001:db8::7/128")}
	if got := st.Tables["e2e-a"]; !slices.Equal(got, want) {
		t.Errorf("table e2e-a after the reload = %v, want %v", got, want)
	}
	if got, ok := st.Tables["e2e-b"]; !ok || len(got) != 0 {
		t.Errorf("table e2e-b after the reload = %v (exists %v), want an empty table", got, ok)
	}
}

// TestPfBackendSeesExternalChanges checks that Read and LoadedID read the
// kernel: an external flush of a table, of the rules, and a rule that
// another tool puts in a sub-anchor are visible at once.
func TestPfBackendSeesExternalChanges(t *testing.T) {
	b, _ := newPfBackend(t)
	rs := compilePolicies(t, "[[policy]]\nname = \"e2e-c\"\nto = [\"192.0.2.0/24\"]\nonly_via = [\"lo0\"]\n")
	load(t, b, rs)
	addEntries(t, b, "e2e-c", "198.51.100.8/32")

	pfctl(t, "-a", pfbackend.Anchor, "-t", "e2e-c", "-T", "flush")
	if got, ok := readState(t, b).Tables["e2e-c"]; !ok || len(got) != 0 {
		t.Errorf("table e2e-c after an external flush = %v (exists %v), want an empty table", got, ok)
	}

	sub := pfbackend.Anchor + "/tag.e2e-c"
	cmd := exec.CommandContext(t.Context(), pfbackend.Path, "-a", sub, "-f", "-")
	cmd.Stdin = strings.NewReader("pass out quick all no state\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("load a rule into %s: %v: %s", sub, err, out)
	}
	requireLoadedID(t, b, "")
	load(t, b, rs)
	requireLoadedID(t, b, rs.ID())

	pfctl(t, "-a", pfbackend.Anchor, "-F", "rules")
	requireLoadedID(t, b, "")
	if st := readState(t, b); st.Ruleset != "" {
		t.Errorf("Read ruleset after an external flush = %q, want \"\"", st.Ruleset)
	}
}

// TestPfBackendBlocksOnPhysicalInterface checks a policy that allows only
// a utun interface: a connected UDP socket to a table address on the
// default route (the physical interface) gets ECONNREFUSED, and a packet
// to a table address behind the utun leaves through the utun.
func TestPfBackendBlocksOnPhysicalInterface(t *testing.T) {
	b, _ := newPfBackend(t)
	u := testnet.NewUTUN(t)
	// 198.18.0.0/15 is for benchmark tests (RFC 2544) and 192.0.2.0/24 is
	// for documentation (RFC 5737): no real host answers.
	u.SetAddr(t, netip.MustParseAddr("198.18.20.1"), netip.MustParseAddr("198.18.20.2"))
	blocked := netip.MustParseAddrPort("192.0.2.10:9")
	allowed := netip.MustParseAddrPort("198.18.20.2:9")

	if err := udpExchange(t, blocked); !errors.Is(err, errNoAnswer) {
		t.Fatalf("UDP to %s before the load: %v, want no answer", blocked, err)
	}

	config := "[[policy]]\nname = \"e2e-phys\"\nto = [\"192.0.2.10\", \"198.18.20.2\"]\nonly_via = [\"" + u.Name + "\"]\n"
	load(t, b, compilePolicies(t, config, reconcile.Interface{Name: u.Name, Class: policy.ClassTunnel}))
	addEntries(t, b, "e2e-phys", "192.0.2.10/32", "198.18.20.2/32")

	if err := udpExchange(t, blocked); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("UDP to %s on the default route: %v, want ECONNREFUSED", blocked, err)
	}
	if err := udpExchange(t, allowed); !errors.Is(err, errNoAnswer) {
		t.Errorf("UDP to %s through %s: %v, want no answer (not blocked)", allowed, u.Name, err)
	}
	pkt := u.ReadPacket(t, 5*time.Second)
	const ipv4DstOffset = 16
	if len(pkt) < ipv4DstOffset+4 {
		t.Fatalf("packet too short for IPv4: %d bytes", len(pkt))
	}
	if got, _ := netip.AddrFromSlice(pkt[ipv4DstOffset : ipv4DstOffset+4]); got != allowed.Addr() {
		t.Errorf("packet on %s goes to %s, want %s", u.Name, got, allowed.Addr())
	}
}

var errNoAnswer = errors.New("no answer before the deadline")

// udpExchange sends one datagram on a connected UDP socket and waits 2 s
// for an answer or an error. A block with ICMP port unreachable gives
// ECONNREFUSED; a packet that leaves gets no answer here.
func udpExchange(t *testing.T, to netip.AddrPort) error {
	t.Helper()
	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "udp4", to.String())
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }() // a UDP close error does not change the result
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("ifbound")); err != nil {
		return err
	}
	_, err = conn.Read(make([]byte, 64))
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return errNoAnswer
	}
	return err
}

// TestPfBackendDisabledVoids checks that "pfctl -d" gives a Problem that
// voids the enforcement and no loaded ruleset, and that Load enables pf
// again.
func TestPfBackendDisabledVoids(t *testing.T) {
	b, c := newPfBackend(t)
	rs := compilePolicies(t, policyA)
	load(t, b, rs)
	requireLoadedID(t, b, rs.ID())

	pfctl(t, "-d")
	st := readState(t, b)
	if st.Ruleset != "" {
		t.Errorf("Read ruleset with pf disabled = %q, want \"\"", st.Ruleset)
	}
	if !slices.ContainsFunc(st.Problems, func(p reconcile.Problem) bool { return p.Voids && strings.Contains(p.Text, "disabled") }) {
		t.Errorf("problems with pf disabled = %v, want a voiding problem", st.Problems)
	}
	requireLoadedID(t, b, "")

	c.t = c.t.Add(pfbackend.EnableInterval)
	load(t, b, rs)
	requireLoadedID(t, b, rs.ID())
	if st := readState(t, b); slices.ContainsFunc(st.Problems, func(p reconcile.Problem) bool { return p.Voids }) {
		t.Errorf("problems after Load = %v, want no voiding problem", st.Problems)
	}
}

// TestPfBackendAddEndsStates checks that AddEntries ends a state that
// another rule keeps for an address that the table now holds.
func TestPfBackendAddEndsStates(t *testing.T) {
	b, _ := newPfBackend(t)
	load(t, b, compilePolicies(t, "[[policy]]\nname = \"e2e-s\"\nto = [\"192.0.2.0/24\"]\nonly_via = []\n"))

	other := "com.apple/900.ifbound-e2e"
	cmd := exec.CommandContext(t.Context(), pfbackend.Path, "-a", other, "-f", "-")
	cmd.Stdin = strings.NewReader("pass out proto udp to 198.18.21.0/24 keep state\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("load %s: %v: %s", other, err, out)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, pfbackend.Path, "-a", other, "-F", "all").CombinedOutput(); err != nil {
			t.Errorf("flush %s: %v: %s", other, err, out)
		}
	})

	dst := netip.MustParseAddrPort("198.18.21.9:9")
	if err := udpExchange(t, dst); !errors.Is(err, errNoAnswer) {
		t.Fatalf("UDP to %s: %v, want no answer", dst, err)
	}
	if states := pfctl(t, "-s", "state"); !strings.Contains(states, dst.String()) {
		t.Fatalf("no state to %s after the send:\n%s", dst, states)
	}
	addEntries(t, b, "e2e-s", "198.18.21.9/32")
	if states := pfctl(t, "-s", "state"); strings.Contains(states, dst.String()) {
		t.Errorf("a state to %s stays after AddEntries:\n%s", dst, states)
	}
}

// loadAnchor loads rules into an anchor of another tool, and flushes the
// anchor at the end of the test.
func loadAnchor(t *testing.T, anchor, rules string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), pfbackend.Path, "-a", anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("load %s: %v: %s", anchor, err, out)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, pfbackend.Path, "-a", anchor, "-F", "all").CombinedOutput(); err != nil {
			t.Errorf("flush %s: %v: %s", anchor, err, out)
		}
	})
}

// TestPfBackendNatPassVoids checks that a "nat pass" rule in an anchor
// that pf evaluates after the ifbound anchor gives a voiding Problem: the
// packets that it translates skip the filter rules.
func TestPfBackendNatPassVoids(t *testing.T) {
	b, _ := newPfBackend(t)
	load(t, b, compilePolicies(t, policyA))
	voids := func() bool {
		return slices.ContainsFunc(readState(t, b).Problems, func(p reconcile.Problem) bool {
			return p.Voids && strings.Contains(p.Text, "NAT rule")
		})
	}
	loadAnchor(t, "com.apple/900.ifbound-e2e", "nat on lo0 inet from any to 192.0.2.11 -> 127.0.0.1\n")
	if voids() {
		t.Errorf("a nat rule without pass gives a voiding Problem")
	}
	loadAnchor(t, "com.apple/900.ifbound-e2e", "nat pass on lo0 inet from any to 192.0.2.11 -> 127.0.0.1\n")
	if !voids() {
		t.Errorf("problems with a nat pass rule = %v, want a voiding Problem", readState(t, b).Problems)
	}
}

// TestPfBackendTopLevelRuleIsAChange checks that a rule that another tool
// adds at the top level of the ifbound anchor, with a read-modify-write
// that keeps the sentinel rules, gives no loaded ruleset, and that Load
// removes it.
func TestPfBackendTopLevelRuleIsAChange(t *testing.T) {
	b, _ := newPfBackend(t)
	rs := compilePolicies(t, policyA)
	load(t, b, rs)
	cur, err := exec.CommandContext(t.Context(), pfbackend.Path, "-a", pfbackend.Anchor, "-sr").Output()
	if err != nil {
		t.Fatalf("read %s: %v", pfbackend.Anchor, err)
	}
	rules := "pass out quick all no state\n" + string(cur)
	cmd := exec.CommandContext(t.Context(), pfbackend.Path, "-a", pfbackend.Anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("read-modify-write of %s: %v: %s", pfbackend.Anchor, err, out)
	}
	requireLoadedID(t, b, "")
	load(t, b, rs)
	requireLoadedID(t, b, rs.ID())
	if got := pfctl(t, "-a", pfbackend.Anchor, "-sr"); strings.Contains(got, "pass out quick") {
		t.Errorf("the anchor holds the foreign rule after Load:\n%s", got)
	}
}

type noAddrs struct{}

func (noAddrs) Addrs(policy.Name) []netip.Addr { return nil }

// TestPfBackendRepairsNegatedEntryInsideAPrefix checks that one
// convergence of the real Reconciler deletes a negated entry that another
// tool adds inside a prefix of an ifbound table. Before the repair, Read
// reports a voiding Problem and leaves the prefix out of Tables.
func TestPfBackendRepairsNegatedEntryInsideAPrefix(t *testing.T) {
	b, _ := newPfBackend(t)
	cfg, err := policy.ParseBytes([]byte("[dns]\nupstream = [\"tls://1.1.1.1@a.example\"]\n" + policyA))
	if err != nil {
		t.Fatal(err)
	}
	rec := reconcile.Reconciler{
		Compiler:  pfrules.Compiler{},
		Backend:   b,
		Resolver:  reconciletest.NewWorld().Resolver(),
		Inventory: reconciletest.NewInventory(),
	}
	converge := func() {
		t.Helper()
		if _, err := rec.Converge(t.Context(), reconcile.Inputs{Policies: cfg.Policies, Book: noAddrs{}}); err != nil {
			t.Fatalf("Converge: %v", err)
		}
	}
	held := netip.MustParsePrefix("192.0.2.0/24")
	converge()

	pfctl(t, "-a", pfbackend.Anchor, "-t", "e2e-a", "-T", "add", "!192.0.2.9")
	st := readState(t, b)
	if slices.Contains(st.Tables["e2e-a"], held) {
		t.Errorf("Read.Tables[e2e-a] = %v holds %v, which a negated entry voids", st.Tables["e2e-a"], held)
	}
	if !slices.ContainsFunc(st.Problems, func(p reconcile.Problem) bool { return p.Voids && strings.Contains(p.Text, "!192.0.2.9") }) {
		t.Errorf("problems with the negated entry = %v, want a voiding Problem", st.Problems)
	}

	converge()
	if got := pfctl(t, "-a", pfbackend.Anchor, "-t", "e2e-a", "-T", "show"); strings.Contains(got, "!") {
		t.Errorf("table e2e-a after one convergence holds a negated entry:\n%s", got)
	}
	st = readState(t, b)
	if !slices.Contains(st.Tables["e2e-a"], held) {
		t.Errorf("Read.Tables[e2e-a] after one convergence = %v, want %v", st.Tables["e2e-a"], held)
	}
	if len(st.Problems) != 0 {
		t.Errorf("problems after one convergence = %v, want none", st.Problems)
	}
}

// TestPfBackendReleaseAfterRestart checks that a new Backend on the same
// pf (a restarted daemon) reads the token of ifbound from the anchor, and
// that Release gives it back.
func TestPfBackendReleaseAfterRestart(t *testing.T) {
	b, _ := newPfBackend(t)
	before := references(t)
	load(t, b, compilePolicies(t, policyA))
	if got := references(t); len(got) != len(before)+1 {
		t.Fatalf("references after Load = %v, want one more than %v", got, before)
	}
	again := pfbackend.New(pfbackend.Exec{Path: pfbackend.Path}, time.Now, slog.New(slog.DiscardHandler))
	readState(t, again)
	if err := again.Release(t.Context()); err != nil {
		t.Fatalf("Release by the restarted Backend: %v", err)
	}
	if got := references(t); !slices.Equal(got, before) {
		t.Errorf("references after Release = %v, want %v", got, before)
	}
}

// references returns the tokens that "pfctl -s References" lists.
func references(t *testing.T) []string {
	t.Helper()
	var toks []string
	for line := range strings.Lines(pfctl(t, "-s", "References")) {
		f := strings.Fields(line)
		if len(f) >= 3 && f[1] == "pfctl" {
			toks = append(toks, f[2])
		}
	}
	slices.Sort(toks)
	return toks
}
