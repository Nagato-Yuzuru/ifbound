package daemon_test

import (
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// writeHosts replaces the host file. Each call sets a new modification
// time, so the daemon sees a change also when the size is the same.
func (h *harness) writeHosts(content string) {
	h.t.Helper()
	if err := os.WriteFile(h.hosts, []byte(content), 0o600); err != nil {
		h.t.Fatalf("write host file: %v", err)
	}
	h.touchHosts()
}

func (h *harness) touchHosts() {
	h.t.Helper()
	h.hostsWrites++
	mod := time.Date(2026, 1, 1, 0, 0, h.hostsWrites, 0, time.UTC)
	if err := os.Chtimes(h.hosts, mod, mod); err != nil {
		h.t.Fatalf("set host file time: %v", err)
	}
}

func (h *harness) warnings() []string {
	h.logs.mu.Lock()
	defer h.logs.mu.Unlock()
	var out []string
	for _, m := range h.logs.msgs {
		if strings.HasPrefix(m, "WARN ") {
			out = append(out, m)
		}
	}
	return out
}

// A host entry for a protected name, as the first name or as an alias,
// is in the table at the next convergence. The entries with the same
// first name come too: mDNSResponder answers the alias as a CNAME to
// that name. An entry for an unprotected name does nothing.
func TestHostEntriesGoIntoTables(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.wantState(daemon.StateReady)

		h.writeHosts("10.1.1.1 www.example.net\n" +
			"10.1.1.2 cdn.test example.com\n" +
			"10.1.1.3 cdn.test\n" +
			"10.1.1.4 other.test\n" +
			"10.1.1.5 a.ads.example www.example.net\n")
		heal()

		h.wantState(daemon.StateReady)
		for _, want := range []struct {
			table policy.Name
			addr  string
		}{
			{"web", "10.1.1.1"}, {"web", "10.1.1.2"}, {"web", "10.1.1.3"}, {"web", "10.1.1.5"},
			{"ads", "10.1.1.5"},
		} {
			if !h.hasEntry(want.table, host(want.addr)) {
				t.Errorf("%s table = %v, want %s", want.table, h.world.Tables()[want.table], want.addr)
			}
		}
		for _, table := range []policy.Name{"web", "ads"} {
			if h.hasEntry(table, host("10.1.1.4")) {
				t.Errorf("%s table has the address of an unprotected name", table)
			}
		}
		if h.hasEntry("ads", host("10.1.1.1")) {
			t.Error("ads table has the address of a name of web only")
		}
		if got := h.saved("web"); len(got) != 0 {
			t.Errorf("snapshot has host addresses %v, want none", got)
		}
	})
}

func TestHostEntryRemovalRemovesAddress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.writeHosts("10.1.1.1 www.example.net\n10.1.1.2 example.com\n")
		heal()

		h.writeHosts("10.1.1.2 example.com\n")
		heal()

		if h.hasEntry("web", host("10.1.1.1")) {
			t.Error("web table keeps the address of a removed host entry")
		}
		if !h.hasEntry("web", host("10.1.1.2")) {
			t.Error("web table lost the address of a kept host entry")
		}

		if err := os.Remove(h.hosts); err != nil {
			t.Fatal(err)
		}
		heal()

		h.wantState(daemon.StateReady)
		if h.hasEntry("web", host("10.1.1.2")) {
			t.Error("web table keeps a host address after the file is gone")
		}
	})
}

// A host address that DNS also gave stays when the host entry goes away:
// the address book still has it.
func TestHostEntryRemovalKeepsLearnedAddress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.writeHosts("10.1.1.1 example.com\n")
		heal()
		if err := h.observe(obs("example.com", "10.1.1.1")); err != nil {
			t.Fatalf("Observe: %v", err)
		}

		h.writeHosts("")
		heal()

		if !h.hasEntry("web", host("10.1.1.1")) {
			t.Error("web table lost a learned address with the host entry")
		}
	})
}

// A configuration change maps the host file again, also when the file
// did not change.
func TestHostEntriesFollowConfiguration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.writeHosts("10.1.1.1 mail.example.org\n")
		heal()
		if h.hasEntry("mail", host("10.1.1.1")) {
			t.Fatal("mail table exists before the policy does")
		}

		if err := h.d.Reconfigure(t.Context(), parse(t, configV2)); err != nil {
			t.Fatalf("Reconfigure: %v", err)
		}

		if !h.hasEntry("mail", host("10.1.1.1")) {
			t.Errorf("mail table = %v, want the host address", h.world.Tables()["mail"])
		}
	})
}

// A host file that exists but cannot be read is a problem that does not
// void enforcement. The addresses of the last good read stay until a
// read succeeds.
func TestHostFileReadErrorDegradesAndKeepsAddresses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.writeHosts("10.1.1.1 example.com\n")
		heal()

		// A directory: the stat and the open succeed, the read fails.
		if err := os.Remove(h.hosts); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(h.hosts, 0o700); err != nil {
			t.Fatal(err)
		}
		heal()

		st := h.wantState(daemon.StateDegraded)
		if !slices.ContainsFunc(st.Reasons, func(r string) bool { return strings.Contains(r, "host file") }) {
			t.Errorf("reasons = %q, want the host file error", st.Reasons)
		}
		if !h.hasEntry("web", host("10.1.1.1")) {
			t.Error("web table lost the host address of the last good read")
		}
		if err := h.observe(obs("example.com", "10.2.2.2")); err != nil {
			t.Errorf("Observe in Degraded: %v, want an ack", err)
		}

		if err := os.Remove(h.hosts); err != nil {
			t.Fatal(err)
		}
		h.writeHosts("10.1.1.3 example.com\n")
		heal()

		h.wantState(daemon.StateReady)
		if h.hasEntry("web", host("10.1.1.1")) || !h.hasEntry("web", host("10.1.1.3")) {
			t.Errorf("web table = %v, want the address of the new read only", h.world.Tables()["web"])
		}
	})
}

func TestMissingHostFileIsNoProblem(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		heal()

		h.wantState(daemon.StateReady)
		if w := h.warnings(); len(w) != 0 {
			t.Errorf("warnings = %q, want none", w)
		}
	})
}

// A line with a name that ifbound cannot read is a warning when the
// name is at or below a protected name, and silent otherwise.
func TestUnrepresentableHostLines(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.writeHosts("10.1.1.1 x..other.test\n" +
			"10.1.1.2 x..www.EXAMPLE.net.\n")
		heal()

		w := h.warnings()
		if len(w) != 1 || !strings.Contains(w[0], "line=2") || !strings.Contains(w[0], "x..www.EXAMPLE.net.") {
			t.Errorf("warnings = %q, want one for line 2", w)
		}
		h.wantState(daemon.StateReady)
	})
}

// Traffic to a loopback or unspecified address does not leave the host,
// so a host entry with one blocks nothing. A block of it would stop
// local services, ifbound-dns too.
func TestHostLoopbackAddressesAreNotBlocked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.writeHosts("127.0.0.1 local.example.net\n::1 local.example.net\n0.0.0.0 zero.example.net\n:: zero.example.net\n")
		heal()

		for _, addr := range []string{"127.0.0.1", "::1", "0.0.0.0", "::"} {
			if h.hasEntry("web", host(addr)) {
				t.Errorf("web table has %s", addr)
			}
		}
	})
}

// mDNSResponder follows a CNAME chain across lines: example.com is an
// alias of f.test, and f.test is an alias of g.test.
func TestHostAliasChain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.writeHosts("10.0.0.2 g.test f.test\n10.0.0.1 f.test example.com\n10.0.0.3 g.test\n10.0.0.4 h.test g.test\n")
		heal()

		for _, addr := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"} {
			if !h.hasEntry("web", host(addr)) {
				t.Errorf("web table = %v, want %s", h.world.Tables()["web"], addr)
			}
		}
	})
}

// A restart while the host file cannot be read keeps the host addresses
// that the last run put in the tables.
func TestHostAddressesSurviveRestartWithUnreadableFile(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		if err := h.observe(obs("example.com", "10.9.9.9")); err != nil {
			t.Fatalf("Observe: %v", err)
		}
		h.writeHosts("10.1.1.1 example.com\n")
		heal()
		h.stop()
		if err := os.Remove(h.hosts); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(h.hosts, 0o700); err != nil {
			t.Fatal(err)
		}

		h = start(t, h.world, h.inv, h.snapshot, parse(t, configV1))
		defer h.stop()

		h.wantState(daemon.StateDegraded)
		if !h.hasEntry("web", host("10.1.1.1")) {
			t.Error("web table lost a host address of the last run")
		}
	})
}

// A restart without learned addresses in the snapshot adopts the kernel
// entries, but not the host addresses: they leave with their entries.
func TestAdoptionSkipsHostAddresses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		h.writeHosts("10.1.1.1 example.com\n")
		heal()
		h.stop()
		if err := os.Remove(h.snapshot); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}

		h = start(t, h.world, h.inv, h.snapshot, parse(t, configV1))
		defer h.stop()
		if !h.hasEntry("web", host("10.1.1.1")) {
			t.Fatal("web table lost the host address at the restart")
		}
		if got := h.saved("web"); len(got) != 0 {
			t.Errorf("snapshot = %v, want no host address", got)
		}

		h.writeHosts("")
		heal()
		if h.hasEntry("web", host("10.1.1.1")) {
			t.Error("web table keeps the host address after its entry went away")
		}
	})
}

// After a read error, each pass reads again, and the state follows the
// file: a stat error that goes away, and an unreadable file that is
// removed.
func TestHostFileRecovers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.writeHosts("10.1.1.1 example.com\n")
		heal()
		content, err := os.ReadFile(h.hosts)
		if err != nil {
			t.Fatal(err)
		}
		saved := h.hosts + ".saved"
		if err := os.Rename(h.hosts, saved); err != nil {
			t.Fatal(err)
		}
		// A symlink to itself: the stat fails.
		if err := os.Symlink(h.hosts, h.hosts); err != nil {
			t.Fatal(err)
		}
		heal()
		h.wantState(daemon.StateDegraded)

		// The same file as before comes back: same content, same time.
		if err := os.Remove(h.hosts); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(saved, h.hosts); err != nil {
			t.Fatal(err)
		}
		heal()
		h.wantState(daemon.StateReady)
		if len(content) == 0 || !h.hasEntry("web", host("10.1.1.1")) {
			t.Error("web table lost the host address")
		}

		if err := os.Remove(h.hosts); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(h.hosts, 0o700); err != nil {
			t.Fatal(err)
		}
		heal()
		h.wantState(daemon.StateDegraded)
		if err := os.Remove(h.hosts); err != nil {
			t.Fatal(err)
		}
		heal()
		h.wantState(daemon.StateReady)
	})
}

// A FIFO can block an open, and the loop must not wait for it.
func TestHostFileNotRegular(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		if err := syscall.Mkfifo(h.hosts, 0o600); err != nil {
			t.Fatal(err)
		}
		heal()

		h.wantState(daemon.StateDegraded)
	})
}

// A failure that lasts gives one warning, and a line that ifbound cannot
// read gives one warning per read of the file, not one per pass.
func TestHostWarningsDoNotRepeat(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.writeHosts("10.1.1.2 x..www.example.net\n")
		for range 3 {
			heal()
		}
		if w := h.warnings(); len(w) != 1 {
			t.Errorf("warnings = %q, want one", w)
		}

		if err := os.Remove(h.hosts); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(h.hosts, 0o700); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			heal()
		}
		failed := 0
		for _, w := range h.warnings() {
			if strings.Contains(w, "host file read failed") {
				failed++
			}
		}
		if failed != 1 {
			t.Errorf("read-failure warnings = %d, want 1", failed)
		}
	})
}
