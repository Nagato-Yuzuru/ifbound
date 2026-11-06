//go:build e2e && darwin

package e2e

import (
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/pfbackend"
	"github.com/Nagato-Yuzuru/ifbound/pf"
)

// pfAnchor is not below com.apple/, so no rule of the main ruleset
// evaluates it. The table tests need no evaluation.
const pfAnchor = "ifbound-e2e-pf"

// flushAnchorTables deletes the tables of the anchor at the end of the
// test.
func flushAnchorTables(t testing.TB, anchor string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, pfbackend.Path, "-a", anchor, "-F", "Tables").CombinedOutput(); err != nil {
			t.Errorf("flush tables of %s: %v: %s", anchor, err, out)
		}
	})
}

// showTable returns the entries that "pfctl -T show" prints, sorted. It
// reads stdout only: pfctl writes notes such as "No ALTQ support in
// kernel" to stderr.
func showTable(t testing.TB, tbl pf.Table) []string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), pfbackend.Path, "-a", tbl.Anchor, "-t", tbl.Name, "-T", "show").Output()
	if err != nil {
		t.Fatalf("pfctl -T show %s: %v", tbl, err)
	}
	var lines []string
	for line := range strings.Lines(string(out)) {
		if f := strings.TrimSpace(line); f != "" {
			lines = append(lines, f)
		}
	}
	slices.Sort(lines)
	return lines
}

// addrText prints an Addr as "pfctl -T show" does: no prefix length for a
// host.
func addrText(a pf.Addr) string {
	s := a.Prefix.String()
	if a.Prefix.IsSingleIP() {
		s = a.Prefix.Addr().String()
	}
	if a.Negated {
		s = "!" + s
	}
	return s
}

func addr(s string) pf.Addr {
	neg := strings.HasPrefix(s, "!")
	s = strings.TrimPrefix(s, "!")
	if !strings.Contains(s, "/") {
		a := netip.MustParseAddr(s)
		return pf.Addr{Prefix: netip.PrefixFrom(a, a.BitLen()), Negated: neg}
	}
	return pf.Addr{Prefix: netip.MustParsePrefix(s), Negated: neg}
}

func TestPfTableWriteThenPfctlReads(t *testing.T) {
	requireE2E(t)
	h := openPf(t)
	tbl := pf.Table{Anchor: pfAnchor, Name: "e2e-w"}
	flushAnchorTables(t, pfAnchor)

	if err := h.CreateTable(tbl); err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := pfctl(t, "-a", pfAnchor, "-sT"); !strings.Contains(got, tbl.Name) {
		t.Fatalf("pfctl -sT does not list %s:\n%s", tbl.Name, got)
	}
	if err := h.CreateTable(tbl); err != nil {
		t.Errorf("create of an existing table: %v", err)
	}

	addrs := []pf.Addr{addr("198.51.100.8"), addr("!198.51.100.9"), addr("2001:db8::1"), addr("203.0.113.0/24")}
	fb, err := h.AddAddrs(tbl, addrs)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	for i, f := range fb {
		if f != pf.FeedbackAdded {
			t.Errorf("feedback of %v = %s, want added", addrs[i], f)
		}
	}
	want := make([]string, 0, len(addrs))
	for _, a := range addrs {
		want = append(want, addrText(a))
	}
	slices.Sort(want)
	if got := showTable(t, tbl); !slices.Equal(got, want) {
		t.Errorf("pfctl shows %v, want %v", got, want)
	}

	fb, err = h.AddAddrs(tbl, []pf.Addr{addrs[0], addr("198.51.100.9"), addr("192.0.2.7"), addr("192.0.2.7")})
	wantFb := []pf.Feedback{pf.FeedbackNone, pf.FeedbackConflict, pf.FeedbackAdded, pf.FeedbackDuplicate}
	if err != nil || !slices.Equal(fb, wantFb) {
		t.Errorf("add of a present address, a negation, and a duplicate: feedback %v, error %v; want %v", fb, err, wantFb)
	}

	fb, err = h.DeleteAddrs(tbl, []pf.Addr{addrs[0], addrs[0], addr("192.0.2.200"), addr("!192.0.2.7")})
	wantFb = []pf.Feedback{pf.FeedbackDeleted, pf.FeedbackDuplicate, pf.FeedbackNone, pf.FeedbackConflict}
	if err != nil || !slices.Equal(fb, wantFb) {
		t.Errorf("delete feedback %v, error %v; want %v", fb, err, wantFb)
	}
	if got := showTable(t, tbl); slices.Contains(got, addrText(addrs[0])) {
		t.Errorf("pfctl still shows %v after delete: %v", addrs[0], got)
	}

	// The table holds addrs[1:] and 192.0.2.7.
	n, err := h.ClearAddrs(tbl)
	if err != nil || n != len(addrs) {
		t.Errorf("clear: %d deleted, error %v; want %d", n, err, len(addrs))
	}
	if got := showTable(t, tbl); len(got) != 0 {
		t.Errorf("pfctl shows %v after clear, want nothing", got)
	}
}

func TestPfTablePfctlWritesThenRead(t *testing.T) {
	requireE2E(t)
	h := openPf(t)
	tbl := pf.Table{Anchor: pfAnchor, Name: "e2e-r"}
	flushAnchorTables(t, pfAnchor)

	entries := []string{"192.0.2.1", "!192.0.2.2", "198.51.100.0/24", "2001:db8::/32", "!2001:db8::5"}
	pfctl(t, append([]string{"-a", pfAnchor, "-t", tbl.Name, "-T", "add"}, entries...)...)

	got, err := h.Addrs(tbl)
	if err != nil {
		t.Fatalf("addrs: %v", err)
	}
	gotText := make([]string, 0, len(got))
	for _, a := range got {
		gotText = append(gotText, addrText(a))
	}
	slices.Sort(gotText)
	if want := showTable(t, tbl); !slices.Equal(gotText, want) {
		t.Errorf("Addrs = %v, pfctl shows %v", gotText, want)
	}

	// An empty table exists.
	pfctl(t, "-a", pfAnchor, "-t", tbl.Name, "-T", "flush")
	if got, err := h.Addrs(tbl); err != nil || len(got) != 0 {
		t.Errorf("addrs of an empty table: %v, %v; want no addresses and no error", got, err)
	}
}

func TestPfTableNotFound(t *testing.T) {
	requireE2E(t)
	h := openPf(t)
	flushAnchorTables(t, pfAnchor)
	pfctl(t, "-a", pfAnchor, "-t", "e2e-other", "-T", "add", "192.0.2.1")

	for _, tbl := range []pf.Table{
		{Anchor: pfAnchor, Name: "e2e-missing"},
		{Anchor: pfAnchor + "-missing", Name: "e2e-missing"},
	} {
		if _, err := h.Addrs(tbl); !errors.Is(err, pf.ErrNotFound) {
			t.Errorf("Addrs(%v): %v, want ErrNotFound", tbl, err)
		}
		if _, err := h.AddAddrs(tbl, []pf.Addr{addr("192.0.2.1")}); !errors.Is(err, pf.ErrNotFound) {
			t.Errorf("AddAddrs(%v): %v, want ErrNotFound", tbl, err)
		}
		if _, err := h.DeleteAddrs(tbl, []pf.Addr{addr("192.0.2.1")}); !errors.Is(err, pf.ErrNotFound) {
			t.Errorf("DeleteAddrs(%v): %v, want ErrNotFound", tbl, err)
		}
		if _, err := h.ClearAddrs(tbl); !errors.Is(err, pf.ErrNotFound) {
			t.Errorf("ClearAddrs(%v): %v, want ErrNotFound", tbl, err)
		}
	}
}

// TestPfKillStates checks that KillStates ends the states to its prefix,
// as "pfctl -k" does, and keeps the others.
func TestPfKillStates(t *testing.T) {
	requireE2E(t)
	h := openPf(t)
	otherReference(t)
	loadAnchor(t, rulesAnchor, "pass out proto udp to 198.18.22.0/24 keep state\n")

	hit := netip.MustParseAddrPort("198.18.22.9:9")
	kept := netip.MustParseAddrPort("198.18.22.10:9")
	for _, dst := range []netip.AddrPort{hit, kept} {
		if err := udpExchange(t, dst); !errors.Is(err, errNoAnswer) {
			t.Fatalf("UDP to %s: %v, want no answer", dst, err)
		}
	}
	states := pfctl(t, "-s", "state")
	if !strings.Contains(states, hit.String()) || !strings.Contains(states, kept.String()) {
		t.Fatalf("no states to %s and %s after the sends:\n%s", hit, kept, states)
	}
	if err := h.KillStates(netip.PrefixFrom(hit.Addr(), 32)); err != nil {
		t.Fatalf("kill: %v", err)
	}
	states = pfctl(t, "-s", "state")
	if strings.Contains(states, hit.String()) {
		t.Errorf("a state to %s stays after KillStates:\n%s", hit, states)
	}
	if !strings.Contains(states, kept.String()) {
		t.Errorf("KillStates ended the state to %s, which is not in the prefix:\n%s", kept, states)
	}
}

// rulesAnchor is below com.apple/, so the main ruleset evaluates its
// rules. The tests of pfbackend also load the rules of another tool here.
const rulesAnchor = "com.apple/900.ifbound-e2e-pf"

// The benchmarks compare each operation with the pfctl command that it
// replaces. Run them in the guest:
//
//	e2e.test -test.run '^$' -test.bench 'Pf' -test.benchmem

func BenchmarkPfAddAddrs(b *testing.B) {
	h := openPf(b)
	tbl := pf.Table{Anchor: pfAnchor, Name: "e2e-bench"}
	flushAnchorTables(b, pfAnchor)
	if err := h.CreateTable(tbl); err != nil {
		b.Fatal(err)
	}
	a := []pf.Addr{addr("198.51.100.8")}
	b.Run("ioctl", func(b *testing.B) {
		for b.Loop() {
			if _, err := h.AddAddrs(tbl, a); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("pfctl", func(b *testing.B) {
		for b.Loop() {
			pfctl(b, "-a", tbl.Anchor, "-t", tbl.Name, "-T", "add", "198.51.100.8")
		}
	})
}

func BenchmarkPfKillStates(b *testing.B) {
	h := openPf(b)
	dst := netip.MustParsePrefix("198.18.23.9/32")
	b.Run("ioctl", func(b *testing.B) {
		for b.Loop() {
			if err := h.KillStates(dst); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("pfctl", func(b *testing.B) {
		for b.Loop() {
			pfctl(b, "-k", "0.0.0.0/0", "-k", dst.String())
		}
	})
}
