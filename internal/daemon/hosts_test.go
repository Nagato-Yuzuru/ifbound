package daemon_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/hostsfile"
	"github.com/Nagato-Yuzuru/ifbound/internal/hostsfile/hostsfs"
	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// fakeHosts is a host file in memory. Each change sets a new version, so
// the daemon sees a change also when the content is the same.
type fakeHosts struct {
	mu      sync.Mutex
	exists  bool
	content string
	writes  int
	// readErr fails Read, like a file that Version finds and that cannot
	// be read. versionErr fails Version.
	readErr, versionErr error
	// onRead, when set, runs once at the end of the next Read, with the
	// lock held. It models a writer that changes the file during a read.
	onRead func(f *fakeHosts)
}

func (f *fakeHosts) Version() (hostsfile.Version, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.versionErr != nil {
		return hostsfile.Version{}, f.versionErr
	}
	if !f.exists {
		return hostsfile.Version{}, nil
	}
	return hostsfile.Version{Exists: true, ModNano: int64(f.writes), Size: int64(len(f.content))}, nil
}

func (f *fakeHosts) Read(v hostsfile.Version) (hostsfile.Hosts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !v.Exists {
		return hostsfile.Hosts{}, nil
	}
	if f.readErr != nil {
		return hostsfile.Hosts{}, f.readErr
	}
	hosts, err := hostsfile.Parse(strings.NewReader(f.content))
	if hook := f.onRead; hook != nil {
		f.onRead = nil
		hook(f)
	}
	return hosts, err
}

func (f *fakeHosts) set(exists bool, content string, readErr error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exists, f.content, f.readErr, f.versionErr = exists, content, readErr, nil
	f.writes++
}

// writeHosts replaces the host file.
func (h *harness) writeHosts(content string) { h.hosts.set(true, content, nil) }

// removeHosts removes the host file. A missing file is a good read.
func (h *harness) removeHosts() { h.hosts.set(false, "", nil) }

// breakHosts makes a host file that exists and that Read cannot read.
func (h *harness) breakHosts() { h.hosts.set(true, "", errReadHosts) }

// failVersion makes Version fail, and failVersion(nil) ends it. The file
// stays as it was.
func (f *fakeHosts) failVersion(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.versionErr = err
}

// failHostsVersion is failVersion on the host file of the daemon.
func (h *harness) failHostsVersion(err error) { h.hosts.failVersion(err) }

// hostsFailures are the two ways that a host file fails: Version cannot
// tell its state, and Version finds it and Read cannot read it.
var hostsFailures = []struct {
	name string
	fail func(h *harness)
}{
	{"read error", func(h *harness) { h.breakHosts() }},
	{"version error", func(h *harness) { h.failHostsVersion(errReadHosts) }},
}

var errReadHosts = errors.New("read host file failed")

// warnings returns the warnings, without the state changes: each start
// is degraded until its first probe reaches ifbound-dns.
func (h *harness) warnings() []string {
	h.logs.mu.Lock()
	defer h.logs.mu.Unlock()
	var out []string
	for _, m := range h.logs.msgs {
		if strings.HasPrefix(m, "WARN ") && !strings.HasPrefix(m, "WARN state changed") {
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

		h.removeHosts()
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

// A configuration change while the snapshot does not load maps the host
// file again under the new configuration.
func TestConfigChangeWhileStartingMapsTheHostFileAgain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newUnloadableSpec(t, configV1)
		s.hosts = &fakeHosts{}
		s.hosts.set(true, "10.1.1.1 mail.example.org\n", nil)
		h := launch(t, s)
		defer h.stop()
		h.wantState(daemon.StateStarting)

		if err := h.d.Reconfigure(t.Context(), parse(t, configV2)); err == nil {
			t.Fatal("Reconfigure = nil, want the snapshot error")
		}
		h.wantState(daemon.StateStarting)
		if err := os.Remove(s.snapshot); err != nil {
			t.Fatal(err)
		}
		heal()
		h.status()
		if !h.hasEntry("mail", host("10.1.1.1")) {
			t.Errorf("mail table = %v, want the host address", h.world.Tables()["mail"])
		}
	})
}

// A host file that exists but cannot be read is a problem that does not
// void enforcement. The addresses of the last good read stay until a
// read succeeds.
func TestHostFileReadErrorDegradesAndKeepsAddresses(t *testing.T) {
	for _, tt := range hostsFailures {
		t.Run(tt.name, func(t *testing.T) { testHostFileFailureKeepsAddresses(t, tt.fail) })
	}
}

func testHostFileFailureKeepsAddresses(t *testing.T, fail func(*harness)) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.writeHosts("10.1.1.1 example.com\n")
		heal()

		fail(h)
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

		if w := h.warnings(); len(w) != 1 {
			t.Errorf("warnings = %q, want one for line 2", w)
		}
		evs := h.logs.events("host file lines have a protected name that ifbound cannot read")
		if len(evs) != 1 {
			t.Fatalf("events = %v, want one", evs)
		}
		got := evs[0].attrs
		want := []string{"line 2: x..www.EXAMPLE.net."}
		if lines, ok := got[logattr.HostsLines].Any().([]string); !ok || !slices.Equal(lines, want) {
			t.Errorf("%s = %v, want %q", logattr.HostsLines, got[logattr.HostsLines], want)
		}
		h.wantState(daemon.StateReady)
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
	for _, tt := range hostsFailures {
		t.Run(tt.name, func(t *testing.T) { testHostAddressesSurviveRestart(t, tt.fail) })
	}
}

func testHostAddressesSurviveRestart(t *testing.T, fail func(*harness)) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		if err := h.observe(obs("example.com", "10.9.9.9")); err != nil {
			t.Fatalf("Observe: %v", err)
		}
		h.writeHosts("10.1.1.1 example.com\n")
		heal()
		h.stop()
		fail(h)

		h = launch(t, h.spec)
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
		if err := os.Remove(bookPath(h.snapshot)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}

		h = launch(t, h.spec)
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

// After a failure, each pass reads again, and the state follows the
// file: a Version error that goes away, and an unreadable file that is
// removed.
func TestHostFileRecovers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.writeHosts("10.1.1.1 example.com\n")
		heal()
		h.failHostsVersion(errReadHosts)
		heal()
		h.wantState(daemon.StateDegraded)

		// The same file as before comes back: the same Version.
		h.failHostsVersion(nil)
		heal()
		h.wantState(daemon.StateReady)
		if !h.hasEntry("web", host("10.1.1.1")) {
			t.Error("web table lost the host address")
		}

		h.breakHosts()
		heal()
		h.wantState(daemon.StateDegraded)
		h.removeHosts()
		heal()
		h.wantState(daemon.StateReady)
	})
}

// A Version error before the first good read is a problem, not an empty
// good read.
func TestHostFileVersionErrorDegrades(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.failHostsVersion(errReadHosts)
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

		h.breakHosts()
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

// A restart with a host file that is now missing removes the host
// addresses of the last run: a missing file is a good read, and the first
// pass reads it although its Version is the zero Version. The snapshot
// has a learned address, so the daemon adopts nothing from the kernel.
func TestHostAddressesLeaveWhenTheFileIsMissingAtRestart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		if err := h.observe(obs("example.com", "10.9.9.9")); err != nil {
			t.Fatalf("Observe: %v", err)
		}
		h.writeHosts("10.1.1.1 example.com\n")
		heal()
		h.stop()
		h.removeHosts()

		h = launch(t, h.spec)
		defer h.stop()

		h.wantState(daemon.StateReady)
		if h.hasEntry("web", host("10.1.1.1")) {
			t.Error("web table keeps a host address of the last run after the file went away")
		}
		if !h.hasEntry("web", host("10.9.9.9")) {
			t.Error("web table lost a learned address")
		}
	})
}

// A writer that changes the file during a read leaves a Version that
// moved. The daemon drops that read and reads again at the next pass.
func TestHostVersionMovesDuringReadDiscardsTheRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, configV1)
		defer h.stop()
		h.writeHosts("10.1.1.1 example.com\n")
		heal()

		h.hosts.mu.Lock()
		h.hosts.content, h.hosts.writes = "", h.hosts.writes+1 // a torn file
		h.hosts.onRead = func(f *fakeHosts) {
			f.content = "10.1.1.2 example.com\n"
			f.writes++
		}
		h.hosts.mu.Unlock()
		heal()
		if !h.hasEntry("web", host("10.1.1.1")) {
			t.Error("web table applied a read that the writer moved under")
		}

		heal()
		if !h.hasEntry("web", host("10.1.1.2")) || h.hasEntry("web", host("10.1.1.1")) {
			t.Errorf("web table = %v, want the address of the finished file only", h.world.Tables()["web"])
		}
		h.wantState(daemon.StateReady)
	})
}

// The daemon works with the real reader: its Version is stable while the
// file does not change, so a read is not dropped for ever.
func TestHostEntriesFromTheFileSystemReader(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hosts")
		if err := os.WriteFile(path, []byte("10.1.1.1 example.com\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		spec := newSpec(t, configV1)
		spec.reader = hostsfs.Reader{Path: path}
		h := launch(t, spec)
		defer h.stop()
		heal()

		h.wantState(daemon.StateReady)
		if !h.hasEntry("web", host("10.1.1.1")) {
			t.Errorf("web table = %v, want the address of the file", h.world.Tables()["web"])
		}
	})
}
