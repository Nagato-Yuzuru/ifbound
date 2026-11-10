//go:build e2e && darwin

package e2e

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/pfbackend"
	"github.com/Nagato-Yuzuru/ifbound/internal/pfrules"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
	"github.com/Nagato-Yuzuru/ifbound/internal/testnet"
)

// These tests load the ifbound anchor into the pf of the host. Each test
// unloads the Backend at the end: it gives back the pf token and flushes
// the anchor.

type testClock struct{ t time.Time }

func (c *testClock) now() time.Time { return c.t }

// newPfBackend returns a Backend on the real pfctl, with a clock that the
// test moves.
func newPfBackend(t testing.TB) (*pfbackend.Backend, *testClock) {
	t.Helper()
	requireE2E(t)
	c := &testClock{t: time.Now()}
	b := pfbackend.New(pfbackend.Exec{Path: pfbackend.Path}, openPf(t), c.now, slog.New(slog.DiscardHandler))
	t.Cleanup(func() {
		// t.Context is already canceled when cleanups run.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := b.Unload(ctx); err != nil {
			t.Errorf("Unload: %v", err)
		}
	})
	return b, c
}

func compilePolicies(t testing.TB, config string, ifaces ...reconcile.Interface) reconcile.Ruleset {
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

func pfctl(t testing.TB, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), pfbackend.Path, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("pfctl %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// loadOnly loads rules into the anchor as another tool does. Flag "-N"
// loads only the NAT rules, "-R" only the filter rules: the other
// rulesets of the anchor stay.
func loadOnly(t *testing.T, anchor, flag, rules string) {
	t.Helper()
	skipUpCallOnArm64(t, rules)
	cmd := exec.CommandContext(t.Context(), pfbackend.Path, "-a", anchor, flag, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("load %q into %s: %v: %s", rules, anchor, err, out)
	}
}

func load(t testing.TB, b *pfbackend.Backend, rs reconcile.Ruleset) {
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

// benchPolicies are four policies, two of them with an anchor rule and a
// sub-anchor, as the ack path of a small configuration sees them.
const benchPolicies = policyA + `
[[policy]]
name     = "e2e-b1"
to       = ["198.51.100.0/24"]
only_via = ["lo0"]

[[policy]]
name     = "e2e-b2"
to       = ["203.0.113.0/24"]
only_via = ["lo0"]

[[policy]]
name     = "e2e-b3"
to       = ["198.18.30.0/24"]
only_via = []
`

// BenchmarkPfBackendLoadedID measures the check of the loaded ruleset
// that the ack path does: the pf status and every rule below the anchor,
// through ioctl.
func BenchmarkPfBackendLoadedID(b *testing.B) {
	be, _ := newPfBackend(b)
	rs := compilePolicies(b, benchPolicies)
	load(b, be, rs)
	for b.Loop() {
		if id, err := be.LoadedID(b.Context()); err != nil || id != rs.ID() {
			b.Fatalf("LoadedID = (%q, %v), want %q", id, err, rs.ID())
		}
	}
}

// BenchmarkPfBackendAddEntries measures the write that the ack path does
// for one DNS answer: one host entry, and the end of its states.
func BenchmarkPfBackendAddEntries(b *testing.B) {
	be, _ := newPfBackend(b)
	load(b, be, compilePolicies(b, benchPolicies))
	for i := 0; b.Loop(); i++ {
		e := netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(1 + i%250)}), 32)
		if err := be.AddEntries(b.Context(), "e2e-a", []netip.Prefix{e}); err != nil {
			b.Fatalf("AddEntries(%v): %v", e, err)
		}
	}
}

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

	// Each change below is one that Load repairs: LoadedID gives "", and
	// the next Load gives the ID back. A change that Load does not repair
	// would make the Reconciler load again and again.
	for _, c := range []struct{ anchor, flag, rule string }{
		{pfbackend.Anchor, "-N", "nat on lo0 inet from any to 198.18.40.1 -> 127.0.0.1\n"},
		{pfbackend.Anchor + "/e2e-other", "-R", "pass out quick all no state\n"},
	} {
		loadOnly(t, c.anchor, c.flag, c.rule)
		requireLoadedID(t, b, "")
		load(t, b, rs)
		requireLoadedID(t, b, rs.ID())
	}
	// pf never evaluates the NAT rules of a sub-anchor: the anchor holds
	// no nat-anchor rule. So such a rule does not change the ID.
	loadOnly(t, sub, "-N", "nat on lo0 inet from any to 198.18.40.2 -> 127.0.0.1\n")
	requireLoadedID(t, b, rs.ID())
	pfctl(t, "-a", sub, "-F", "nat")

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

// TestPfBackendRouteRules checks route rules of another tool in an anchor
// that pf evaluates after the ifbound anchor. The policy allows only a
// test utun, and the inventory of the compile also holds the uplink (the
// interface of the default route). The destination is the peer of the
// utun, so each packet starts on the utun, where the ifbound anchor tags
// it.
func TestPfBackendRouteRules(t *testing.T) {
	b, _ := newPfBackend(t)
	u := testnet.NewUTUN(t)
	// 198.18.0.0/15 is for benchmark tests (RFC 2544): no real host
	// answers.
	u.SetAddr(t, netip.MustParseAddr("198.18.24.1"), netip.MustParseAddr("198.18.24.2"))
	dst := netip.MustParseAddrPort("198.18.24.2:9")
	uplink, gateway := defaultRoute(t)
	config := "[[policy]]\nname = \"e2e-route\"\nto = [\"" + dst.Addr().String() + "\"]\nonly_via = [\"" + u.Name + "\"]\n"
	load(t, b, compilePolicies(t, config,
		reconcile.Interface{Name: u.Name, Class: policy.ClassTunnel},
		reconcile.Interface{Name: uplink, Class: policy.ClassHardware}))
	addEntries(t, b, "e2e-route", dst.Addr().String()+"/32")
	const other = "com.apple/900.ifbound-e2e"
	voiding := func(t *testing.T) []reconcile.Problem {
		t.Helper()
		return slices.DeleteFunc(readState(t, b).Problems, func(p reconcile.Problem) bool { return !p.Voids })
	}
	to := " inet proto udp to " + dst.Addr().String()

	t.Run("route-to the allowed utun, as a VPN client does", func(t *testing.T) {
		loadAnchor(t, other, "pass out quick route-to ("+u.Name+" "+dst.Addr().String()+")"+to+" no state\n")
		if ps := voiding(t); len(ps) != 0 {
			t.Errorf("voiding Problems = %v, want none", ps)
		}
		if err := udpExchange(t, dst); !errors.Is(err, errNoAnswer) {
			t.Fatalf("UDP to %s: %v, want no answer (not blocked)", dst, err)
		}
		requireLeftThrough(t, u, dst.Addr())
	})
	// The floating state passes the routed packet on the utun without the
	// rules. The policy allows the utun, so Read reports no Problem.
	t.Run("route-to the allowed utun with state", func(t *testing.T) {
		loadAnchor(t, other, "pass out quick route-to ("+u.Name+" "+dst.Addr().String()+")"+to+" keep state\n")
		if ps := voiding(t); len(ps) != 0 {
			t.Errorf("voiding Problems = %v, want none", ps)
		}
		if err := udpExchange(t, dst); !errors.Is(err, errNoAnswer) {
			t.Fatalf("UDP to %s: %v, want no answer (not blocked)", dst, err)
		}
		requireLeftThrough(t, u, dst.Addr())
	})
	// pf_route evaluates the packet again on the uplink, with the tag
	// that it got on the utun. The ifbound rules block it there.
	t.Run("route-to the uplink without state", func(t *testing.T) {
		loadAnchor(t, other, "pass out route-to ("+uplink+" "+gateway+")"+to+" no state\n")
		if ps := voiding(t); len(ps) != 0 {
			t.Errorf("voiding Problems = %v, want none", ps)
		}
		if err := udpExchange(t, dst); !errors.Is(err, syscall.ECONNREFUSED) {
			t.Errorf("UDP to %s routed to %s: %v, want ECONNREFUSED", dst, uplink, err)
		}
	})
	// pf creates the state before it routes the packet. On the uplink the
	// floating state passes the packet without the rules, so Read reports
	// the rule.
	t.Run("route-to the uplink with state", func(t *testing.T) {
		loadAnchor(t, other, "pass out route-to ("+uplink+" "+gateway+")"+to+" keep state\n")
		if ps := voiding(t); !slices.ContainsFunc(ps, func(p reconcile.Problem) bool { return strings.Contains(p.Text, "keeps state") }) {
			t.Errorf("voiding Problems = %v, want one for the route rule with state", ps)
		}
		if err := udpExchange(t, dst); !errors.Is(err, errNoAnswer) {
			t.Errorf("UDP to %s routed to %s: %v, want no answer (the state passes it)", dst, uplink, err)
		}
	})
}

// defaultRoute returns the interface and the gateway of the default
// route.
func defaultRoute(t *testing.T) (iface, gateway string) {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		t.Fatalf("route -n get default: %v: %s", err, out)
	}
	for line := range strings.Lines(string(out)) {
		key, value, _ := strings.Cut(strings.TrimSpace(line), ": ")
		switch key {
		case "interface":
			iface = value
		case "gateway":
			gateway = value
		}
	}
	if iface == "" || gateway == "" {
		t.Fatalf("no default route with a gateway:\n%s", out)
	}
	return iface, gateway
}

var errNoAnswer = errors.New("no answer before the deadline")

// udpExchange sends one datagram on a connected UDP socket and waits 2 s
// for an answer or an error. A block with ICMP port unreachable gives
// ECONNREFUSED; a packet that leaves gets no answer here. A packet that
// passes causes no event, so only the end of the wait shows that no
// reject came.
func udpExchange(t *testing.T, to netip.AddrPort) error {
	t.Helper()
	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "udp4", to.String())
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }() //nolint:errcheck // a UDP close error does not change the result
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

// skipUpCallOnArm64 skips the test when rules hold an anchor call that
// starts with "../" and the kernel is arm64. pf_anchor_setup removes each
// "../" from the call, but it then appends the rest with the length of the
// full call. The arm64 kernel checks the bounds of the call, so the load
// stops the kernel with a panic ("Bounds safety trap"), and the host
// restarts. The Intel kernel does not check the bounds, so the test runs
// there. The test binary is built for the architecture of the host, so
// GOARCH is the architecture of the kernel.
func skipUpCallOnArm64(t testing.TB, rules string) {
	t.Helper()
	if runtime.GOARCH == "arm64" && strings.Contains(rules, `anchor "../`) {
		t.Skip(`an anchor call that starts with "../" stops the arm64 kernel with a panic`)
	}
}

// loadAnchor loads rules into an anchor of another tool, and flushes the
// anchor at the end of the test.
func loadAnchor(t testing.TB, anchor, rules string) {
	t.Helper()
	skipUpCallOnArm64(t, rules)
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

// TestPfBackendRulesBeforeTheAnchorVoid checks rules that another tool
// loads in an anchor that pf evaluates before the ifbound anchor: a quick
// anchor rule that calls an anchor with a pass rule, and an anchor rule
// that calls an anchor out of its own subtree, which holds a quick pass
// rule. Real pf then passes a protected packet on the default route (the
// physical interface), and Read reports a voiding Problem that names the
// anchor of the rule.
func TestPfBackendRulesBeforeTheAnchorVoid(t *testing.T) {
	// "000.e2e" comes before "000.ifbound" in byte order.
	const earlier = "com.apple/000.e2e-ifbound"
	type foreign struct{ anchor, rules string }
	tests := []struct {
		name  string
		loads []foreign // in order
		want  string    // a part of the text of the voiding Problem
	}{
		{"quick anchor that calls a pass rule", []foreign{
			{earlier, "anchor \"vpn\" quick all\n"},
			{earlier + "/vpn", "pass out all no state\n"},
		}, "in the anchor " + earlier + " "},
		{"absolute call out of the subtree", []foreign{
			{earlier, "anchor \"/ifbound-e2e-vpn\" all\n"},
			{"ifbound-e2e-vpn", "pass out quick all no state\n"},
		}, "in the anchor ifbound-e2e-vpn "},
		{"relative call out of the subtree", []foreign{
			{earlier, "anchor \"../zzz.ifbound-e2e\" all\n"},
			{"com.apple/zzz.ifbound-e2e", "pass out quick all no state\n"},
		}, "in the anchor com.apple/zzz.ifbound-e2e "},
	}
	dst := netip.MustParseAddrPort("192.0.2.12:9")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := newPfBackend(t)
			config := "[[policy]]\nname = \"e2e-q\"\nto = [\"192.0.2.12\"]\nonly_via = []\n"
			load(t, b, compilePolicies(t, config))
			addEntries(t, b, "e2e-q", "192.0.2.12/32")
			if err := udpExchange(t, dst); !errors.Is(err, syscall.ECONNREFUSED) {
				t.Fatalf("UDP to %s before the rules of the other tool: %v, want ECONNREFUSED", dst, err)
			}
			for _, l := range tt.loads {
				loadAnchor(t, l.anchor, l.rules)
			}
			if err := udpExchange(t, dst); !errors.Is(err, errNoAnswer) {
				t.Errorf("UDP to %s with the rules of the other tool: %v, want no answer (pf passes it)", dst, err)
			}
			ps := readState(t, b).Problems
			if !slices.ContainsFunc(ps, func(p reconcile.Problem) bool { return p.Voids && strings.Contains(p.Text, tt.want) }) {
				t.Errorf("problems = %v, want a voiding Problem with %q", ps, tt.want)
			}
		})
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

func (noAddrs) Addrs(policy.Name) []blockable.Addr { return nil }

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

// TestPfBackendUnloadAfterRestart checks that a new Backend on the same
// pf (a restarted daemon) reads the token of ifbound from the anchor, and
// that Unload gives it back.
func TestPfBackendUnloadAfterRestart(t *testing.T) {
	b, _ := newPfBackend(t)
	before := references(t)
	load(t, b, compilePolicies(t, policyA))
	if got := references(t); len(got) != len(before)+1 {
		t.Fatalf("references after Load = %v, want one more than %v", got, before)
	}
	again := pfbackend.New(pfbackend.Exec{Path: pfbackend.Path}, openPf(t), time.Now, slog.New(slog.DiscardHandler))
	readState(t, again)
	if err := again.Unload(t.Context()); err != nil {
		t.Fatalf("Unload by the restarted Backend: %v", err)
	}
	if got := references(t); !slices.Equal(got, before) {
		t.Errorf("references after Unload = %v, want %v", got, before)
	}
}

// TestPfBackendLoadAfterRestartKeepsTableEntries checks that a new
// Backend on the same pf (a restarted daemon) that loads the ruleset again
// keeps the entries of the persist tables. A restart then needs no book
// to keep the acknowledged addresses blocked: adoption reads them back
// from the tables.
func TestPfBackendLoadAfterRestartKeepsTableEntries(t *testing.T) {
	b, _ := newPfBackend(t)
	rs := compilePolicies(t, policyA)
	load(t, b, rs)
	learned := netip.MustParsePrefix("203.0.113.7/32")
	if err := b.AddEntries(t.Context(), "e2e-a", []netip.Prefix{learned}); err != nil {
		t.Fatalf("AddEntries: %v", err)
	}
	again := pfbackend.New(pfbackend.Exec{Path: pfbackend.Path}, openPf(t), time.Now, slog.New(slog.DiscardHandler))
	readState(t, again)
	load(t, again, rs)
	if got := readState(t, again).Tables["e2e-a"]; !slices.Contains(got, learned) {
		t.Errorf("table e2e-a after the Load of the restarted Backend = %v, want %v in it", got, learned)
	}
}

// references returns the tokens that "pfctl -s References" lists, of
// every process: pfctl, and the test process for the references of the
// Backend. A line of a reference starts with the pid and ends with the
// token and the age, which takes three fields ("0 days 00:00:05"). A
// process name can hold spaces.
func references(t *testing.T) []string {
	t.Helper()
	var toks []string
	for line := range strings.Lines(pfctl(t, "-s", "References")) {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		if _, err := strconv.Atoi(f[0]); err == nil {
			toks = append(toks, f[len(f)-4])
		}
	}
	slices.Sort(toks)
	return toks
}
