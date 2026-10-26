package macresolver

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

var listen = netip.MustParseAddrPort("127.0.0.1:10053")

type fakeConfig struct {
	entries []ConfigEntry
	err     error
	calls   int
}

func (f *fakeConfig) Resolvers(context.Context) ([]ConfigEntry, error) {
	f.calls++
	return f.entries, f.err
}

type fixture struct {
	r    *Resolver
	conf *fakeConfig
	dir  string
}

// newFixture returns a Resolver on a directory that does not exist yet.
func newFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{
		conf: &fakeConfig{},
		dir:  filepath.Join(t.TempDir(), "resolver"),
	}
	f.r = New(f.dir, f.conf)
	return f
}

func domain(t *testing.T, s string) policy.Domain {
	t.Helper()
	d, err := policy.ParseDomain(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (f fixture) write(t *testing.T, d string, server netip.AddrPort) {
	t.Helper()
	if err := f.r.Write(t.Context(), reconcile.ResolverEntry{Domain: domain(t, d), Server: server}); err != nil {
		t.Fatalf("Write %s: %v", d, err)
	}
}

func (f fixture) read(t *testing.T) reconcile.ResolverState {
	t.Helper()
	st, err := f.r.Read(t.Context())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return st
}

// put creates a file in the directory, as another tool would.
func (f fixture) put(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(f.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f fixture) content(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWriteRendersTypedEntry(t *testing.T) {
	tests := []struct {
		server netip.AddrPort
		want   string
	}{
		{listen, Marker + "\nnameserver 127.0.0.1\nport 10053\n"},
		{netip.MustParseAddrPort("[::1]:53"), Marker + "\nnameserver ::1\nport 53\n"},
		{netip.MustParseAddrPort("127.0.0.1:65535"), Marker + "\nnameserver 127.0.0.1\nport 65535\n"},
	}
	for _, tt := range tests {
		t.Run(tt.server.String(), func(t *testing.T) {
			f := newFixture(t)
			f.write(t, "example.test", tt.server)
			if got := f.content(t, "example.test"); got != tt.want {
				t.Errorf("file content = %q, want %q", got, tt.want)
			}
			fi, err := os.Stat(filepath.Join(f.dir, "example.test"))
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o644 {
				t.Errorf("file mode = %v, want 0644", fi.Mode().Perm())
			}
			st := f.read(t)
			want := []reconcile.ResolverEntry{{Domain: domain(t, "example.test"), Server: tt.server}}
			if !reflect.DeepEqual(st.Entries, want) {
				t.Errorf("Read entries = %+v, want %+v", st.Entries, want)
			}
		})
	}
}

func TestWriteRefusesInvalidEntry(t *testing.T) {
	tests := map[string]reconcile.ResolverEntry{
		"zero domain": {Server: listen},
		"zero server": {Domain: domain(t, "example.test")},
		"port 0":      {Domain: domain(t, "example.test"), Server: netip.MustParseAddrPort("127.0.0.1:0")},
		"zoned":       {Domain: domain(t, "example.test"), Server: netip.AddrPortFrom(netip.MustParseAddr("fe80::1%lo0"), 53)},
	}
	for name, e := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			err := f.r.Write(t.Context(), e)
			if !errors.Is(err, errInvalidEntry) {
				t.Errorf("Write = %v, want an error that wraps errInvalidEntry", err)
			}
			if _, err := os.Stat(f.dir); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("directory exists after a refused write: %v", err)
			}
		})
	}
}

func TestWriteCreatesDirectory(t *testing.T) {
	f := newFixture(t)
	f.write(t, "example.test", listen)
	fi, err := os.Stat(f.dir)
	if err != nil {
		t.Fatalf("directory after Write: %v", err)
	}
	if !fi.IsDir() {
		t.Fatalf("%s is not a directory", f.dir)
	}
}

func TestReadReportsOnlyMarkedFiles(t *testing.T) {
	f := newFixture(t)
	f.write(t, "example.test", listen)
	f.put(t, "foreign.test", "nameserver 192.0.2.1\n")
	f.put(t, "Upper.test", Marker+"\nnameserver 127.0.0.1\nport 10053\n")
	f.put(t, tempPrefix+"123", Marker+"\nnameserver 127.0.0.1\n")
	if err := os.Mkdir(filepath.Join(f.dir, "dir.test"), 0o755); err != nil {
		t.Fatal(err)
	}
	st := f.read(t)
	want := []reconcile.ResolverEntry{{Domain: domain(t, "example.test"), Server: listen}}
	if !reflect.DeepEqual(st.Entries, want) {
		t.Errorf("Read entries = %+v, want %+v", st.Entries, want)
	}
}

func TestReadWithoutDirectory(t *testing.T) {
	f := newFixture(t)
	st := f.read(t)
	if len(st.Entries) != 0 || len(st.Problems) != 0 {
		t.Errorf("Read = %+v, want an empty state", st)
	}
}

// A marked file with changed content is an ifbound file with a zero
// server: its server is not the one that Write gave.
func TestReadReportsChangedFileWithoutServer(t *testing.T) {
	tests := map[string]string{
		"extra line":  Marker + "\nnameserver 127.0.0.1\nport 10053\nnameserver 192.0.2.1\n",
		"no port":     Marker + "\nnameserver 127.0.0.1\n",
		"bad address": Marker + "\nnameserver localhost\nport 10053\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.put(t, "example.test", content)
			st := f.read(t)
			want := []reconcile.ResolverEntry{{Domain: domain(t, "example.test")}}
			if !reflect.DeepEqual(st.Entries, want) {
				t.Fatalf("Read entries = %+v, want %+v (zero server)", st.Entries, want)
			}
			// The marker makes the file an ifbound file, so Write repairs it.
			f.write(t, "example.test", listen)
			if got, want := f.content(t, "example.test"), Marker+"\nnameserver 127.0.0.1\nport 10053\n"; got != want {
				t.Errorf("content after Write = %q, want %q", got, want)
			}
		})
	}
}

// foreignFiles are files that ifbound does not manage. Only a Marker on
// the first line makes a file an ifbound file.
var foreignFiles = map[string]string{
	"no marker":    "nameserver 192.0.2.1\n",
	"marker later": "nameserver 192.0.2.1\n" + Marker + "\n",
	"empty":        "",
}

func TestWriteRefusesForeignFile(t *testing.T) {
	for name, foreign := range foreignFiles {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.put(t, "example.test", foreign)
			err := f.r.Write(t.Context(), reconcile.ResolverEntry{Domain: domain(t, "example.test"), Server: listen})
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("Write = %v, want an error that wraps ErrConflict", err)
			}
			if got := f.content(t, "example.test"); got != foreign {
				t.Errorf("foreign file changed to %q", got)
			}
			if st := f.read(t); len(st.Entries) != 0 {
				t.Errorf("Read entries = %+v, want none", st.Entries)
			}
		})
	}
}

// A file that appears after Write checked the name is not replaced.
func TestReplaceKeepsFileThatAppeared(t *testing.T) {
	f := newFixture(t)
	const foreign = "nameserver 192.0.2.1\n"
	f.put(t, "example.test", foreign)
	data, err := render(reconcile.ResolverEntry{Domain: domain(t, "example.test"), Server: listen})
	if err != nil {
		t.Fatal(err)
	}
	err = f.r.replace(filepath.Join(f.dir, "example.test"), data, false)
	if !errors.Is(err, ErrConflict) {
		t.Errorf("replace = %v, want an error that wraps ErrConflict", err)
	}
	if got := f.content(t, "example.test"); got != foreign {
		t.Errorf("foreign file changed to %q", got)
	}
	ents, err := os.ReadDir(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Errorf("directory holds %d files, want only the foreign file", len(ents))
	}
}

func TestWriteRefusesFileThatIsNotRegular(t *testing.T) {
	tests := map[string]func(t *testing.T, path string){
		"directory": func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, path string) {
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte(Marker+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, create := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			if err := os.MkdirAll(f.dir, 0o755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.dir, "example.test")
			create(t, path)
			err := f.r.Write(t.Context(), reconcile.ResolverEntry{Domain: domain(t, "example.test"), Server: listen})
			if !errors.Is(err, ErrConflict) {
				t.Errorf("Write = %v, want an error that wraps ErrConflict", err)
			}
			if err := f.r.Remove(t.Context(), domain(t, "example.test")); err != nil {
				t.Errorf("Remove = %v, want nil", err)
			}
			if _, err := os.Lstat(path); err != nil {
				t.Errorf("Remove deleted a file that ifbound does not manage: %v", err)
			}
		})
	}
}

func TestRemoveKeepsForeignFile(t *testing.T) {
	for name, foreign := range foreignFiles {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.put(t, "example.test", foreign)
			if err := f.r.Remove(t.Context(), domain(t, "example.test")); err != nil {
				t.Fatalf("Remove = %v, want nil", err)
			}
			if got := f.content(t, "example.test"); got != foreign {
				t.Errorf("foreign file changed to %q", got)
			}
		})
	}
}

func TestRemoveTwice(t *testing.T) {
	f := newFixture(t)
	f.write(t, "example.test", listen)
	f.write(t, "www.example.test", listen)
	for i := range 2 {
		if err := f.r.Remove(t.Context(), domain(t, "example.test")); err != nil {
			t.Fatalf("Remove %d = %v, want nil", i+1, err)
		}
	}
	want := []reconcile.ResolverEntry{{Domain: domain(t, "www.example.test"), Server: listen}}
	if st := f.read(t); !reflect.DeepEqual(st.Entries, want) {
		t.Errorf("Read entries = %+v, want %+v", st.Entries, want)
	}
}

func TestRemoveWithoutDirectory(t *testing.T) {
	f := newFixture(t)
	if err := f.r.Remove(t.Context(), domain(t, "example.test")); err != nil {
		t.Errorf("Remove = %v, want nil", err)
	}
}

// An identical Write does not touch the file: each change can make macOS
// flush its DNS cache.
func TestWriteSameEntryTwiceChangesNothing(t *testing.T) {
	f := newFixture(t)
	f.write(t, "example.test", listen)
	path := filepath.Join(f.dir, "example.test")
	old := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	f.write(t, "example.test", listen)
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(old) || !os.SameFile(before, after) {
		t.Errorf("an identical write changed the file: modification time %v, want %v", after.ModTime(), old)
	}
}

func TestWriteNewServerReplacesEntry(t *testing.T) {
	f := newFixture(t)
	f.write(t, "example.test", listen)
	other := netip.MustParseAddrPort("127.0.0.1:10054")
	f.write(t, "example.test", other)
	st := f.read(t)
	want := []reconcile.ResolverEntry{{Domain: domain(t, "example.test"), Server: other}}
	if !reflect.DeepEqual(st.Entries, want) {
		t.Errorf("Read entries = %+v, want %+v (new server)", st.Entries, want)
	}
}

func TestWriteRemovesStaleTemporaryFiles(t *testing.T) {
	f := newFixture(t)
	f.put(t, tempPrefix+"123", Marker+"\n")
	f.write(t, "example.test", listen)
	ents, err := os.ReadDir(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if !reflect.DeepEqual(names, []string{"example.test"}) {
		t.Errorf("directory holds %v, want only example.test", names)
	}
}

func TestWriteErrorWhenDirectoryNotWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory mode")
	}
	f := newFixture(t)
	if err := os.Mkdir(f.dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { // lets TempDir remove the tree
		if err := os.Chmod(f.dir, 0o755); err != nil {
			t.Error(err)
		}
	})
	err := f.r.Write(t.Context(), reconcile.ResolverEntry{Domain: domain(t, "example.test"), Server: listen})
	if !errors.Is(err, ErrCannotWrite) {
		t.Errorf("Write = %v, want an error that wraps ErrCannotWrite", err)
	}
}

func TestRemoveErrorWhenDirectoryNotWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory mode")
	}
	f := newFixture(t)
	f.write(t, "example.test", listen)
	if err := os.Chmod(f.dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { // lets TempDir remove the tree
		if err := os.Chmod(f.dir, 0o755); err != nil {
			t.Error(err)
		}
	})
	err := f.r.Remove(t.Context(), domain(t, "example.test"))
	if !errors.Is(err, ErrCannotWrite) {
		t.Errorf("Remove = %v, want an error that wraps ErrCannotWrite", err)
	}
}

func TestWriteErrorWhenParentMissing(t *testing.T) {
	r := New(filepath.Join(t.TempDir(), "missing", "resolver"), &fakeConfig{})
	err := r.Write(t.Context(), reconcile.ResolverEntry{Domain: domain(t, "example.test"), Server: listen})
	if !errors.Is(err, ErrCannotWrite) {
		t.Errorf("Write = %v, want an error that wraps ErrCannotWrite", err)
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		errno syscall.Errno
		want  error
	}{
		{syscall.EACCES, ErrCannotWrite},
		{syscall.EPERM, ErrCannotWrite},
		{syscall.EROFS, ErrCannotWrite},
		{syscall.ENOENT, ErrCannotWrite},
		{syscall.ENOSPC, errFile},
		{syscall.ENOTDIR, errFile},
	}
	for _, tt := range tests {
		t.Run(tt.errno.Error(), func(t *testing.T) {
			err := classify(&fs.PathError{Op: "rename", Path: "/etc/resolver/x", Err: tt.errno})
			if !errors.Is(err, tt.want) {
				t.Errorf("classify(%v) = %v, want an error that wraps %v", tt.errno, err, tt.want)
			}
			if errors.Is(err, tt.errno) {
				t.Errorf("classify(%v) = %v; the errno must not be in the error chain", tt.errno, err)
			}
		})
	}
}

// scutilConf parses resolver blocks in the format of "scutil --dns".
func scutilConf(t *testing.T, blocks ...string) []ConfigEntry {
	t.Helper()
	text := "DNS configuration\n"
	for i, b := range blocks {
		text += "\nresolver #" + strconv.Itoa(i+1) + "\n" + b
	}
	conf, err := parseScutil([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return conf
}

// Resolver blocks for the configuration fixtures. ifboundFile is the block
// that the file of example.test with server listen gives.
const (
	defaultBlock = "  nameserver[0] : 192.0.2.1\n  flags    : Request A records, Request AAAA records\n"
	ifboundFile  = "  domain   : example.test\n  nameserver[0] : 127.0.0.1\n  port     : 10053\n" +
		"  flags    : Request A records, Request AAAA records\n"
)

func domains(ds []policy.Domain) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.String()
	}
	return out
}

func TestReadReportsResolversAtOrBelowEntries(t *testing.T) {
	f := newFixture(t)
	f.write(t, "example.test", listen)
	f.write(t, "cdn.example.net", listen)
	f.conf.entries = scutilConf(t,
		defaultBlock,
		ifboundFile,
		"  domain   : cdn.example.net\n  nameserver[0] : 127.0.0.1\n  port     : 10053\n",
		// a more specific file
		"  domain   : www.example.test\n  nameserver[0] : 127.0.0.1\n  port     : 10054\n",
		// a deeper supplemental resolver of a VPN
		"  domain   : a.b.cdn.example.net\n  nameserver[0] : 10.0.0.53\n  flags    : Supplemental, Request A records\n  order    : 102200\n",
		// not below an entry: label boundary, and two domains above
		"  domain   : badexample.test\n  nameserver[0] : 10.0.0.53\n",
		"  domain   : test\n  nameserver[0] : 10.0.0.53\n",
		"  domain   : example.net\n  nameserver[0] : 10.0.0.53\n",
	)
	st := f.read(t)
	if got, want := domains(st.Shadowed), []string{"a.b.cdn.example.net", "www.example.test"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Shadowed = %v, want %v", got, want)
	}
	if len(st.Problems) != 2 {
		t.Errorf("problems = %+v, want 2", st.Problems)
	}
	for i, sub := range []string{"takes a.b.cdn.example.net ", "takes www.example.test "} {
		if i < len(st.Problems) && (!strings.Contains(st.Problems[i].Text, sub) || st.Problems[i].Voids) {
			t.Errorf("problem %d = %+v, want text with %q that does not void enforcement", i, st.Problems[i], sub)
		}
	}
}

// Another resolver for the same domain as an entry is a problem: macOS can
// send the queries for the domain to it, whatever its order.
func TestReadReportsSameDomainResolver(t *testing.T) {
	const foreignFile = "  domain   : example.test\n  nameserver[0] : 127.0.0.1\n  port     : 10054\n"
	tests := []struct {
		name    string
		blocks  []string
		problem bool
	}{
		{"only the ifbound file", []string{defaultBlock, ifboundFile}, false},
		{"foreign file listed first", []string{foreignFile, ifboundFile}, true},
		{"foreign file listed after", []string{ifboundFile, foreignFile}, true},
		{"ifbound file not listed", []string{defaultBlock, foreignFile}, true},
		{"ifbound file not listed, no other resolver", []string{defaultBlock}, false},
		{"same address, other port", []string{ifboundFile, "  domain   : example.test\n  nameserver[0] : 127.0.0.1\n"}, true},
		{"ifbound server and one more", []string{
			ifboundFile,
			"  domain   : example.test\n  nameserver[0] : 127.0.0.1\n  nameserver[1] : 192.0.2.1\n  port     : 10053\n",
		}, true},
		{"unreadable server", []string{ifboundFile, "  domain   : example.test\n  nameserver[0] : fe80::1%\n  port     : 10053\n"}, true},
		{"case and final dot", []string{ifboundFile, "  domain   : Example.Test.\n  nameserver[0] : 192.0.2.1\n"}, true},
		{"supplemental with a higher order", []string{
			ifboundFile,
			"  domain   : example.test\n  nameserver[0] : 10.0.0.53\n  flags    : Supplemental, Request A records\n  order    : 102200\n",
		}, true},
		{"supplemental with the same order", []string{
			ifboundFile,
			"  domain   : example.test\n  nameserver[0] : 127.0.0.1\n  port     : 10053\n  flags    : Supplemental, Request A records\n",
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			f.write(t, "example.test", listen)
			f.conf.entries = scutilConf(t, tt.blocks...)
			st := f.read(t)
			if len(st.Entries) != 1 {
				t.Errorf("entries = %+v, want example.test", st.Entries)
			}
			wantShadowed := []string{}
			if tt.problem {
				wantShadowed = []string{"example.test"}
			}
			if got := domains(st.Shadowed); !reflect.DeepEqual(got, wantShadowed) {
				t.Errorf("Shadowed = %v, want %v", got, wantShadowed)
			}
			if (len(st.Problems) == 1) != tt.problem || len(st.Problems) > 1 {
				t.Errorf("problems = %+v, want a problem: %v", st.Problems, tt.problem)
			}
		})
	}
}

// The file of an entry below another entry is an ifbound file, not a
// resolver that shadows the other entry.
func TestReadOwnEntryBelowEntryIsNotForeign(t *testing.T) {
	f := newFixture(t)
	f.write(t, "example.test", listen)
	f.write(t, "cdn.www.example.test", listen)
	f.conf.entries = scutilConf(t, ifboundFile,
		"  domain   : cdn.www.example.test\n  nameserver[0] : 127.0.0.1\n  port     : 10053\n")
	st := f.read(t)
	if len(st.Problems) != 0 || len(st.Shadowed) != 0 {
		t.Errorf("problems = %+v, Shadowed = %v; want none", st.Problems, st.Shadowed)
	}
}

func TestReadWithoutEntriesSkipsConfiguration(t *testing.T) {
	f := newFixture(t)
	f.put(t, "www.example.test", "nameserver 192.0.2.1\n")
	f.conf.entries = []ConfigEntry{{Domain: "www.example.test", Servers: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, Port: 53}}
	st := f.read(t)
	if len(st.Entries) != 0 || len(st.Problems) != 0 || f.conf.calls != 0 {
		t.Errorf("Read = %+v after %d configuration reads; want an empty state and no read", st, f.conf.calls)
	}
}

// Without the configuration, Read still returns the entries and reports
// the cause as a problem.
func TestReadReportsConfigurationErrorAsProblem(t *testing.T) {
	f := newFixture(t)
	f.write(t, "example.test", listen)
	f.conf.err = errConfig
	st := f.read(t)
	want := []reconcile.ResolverEntry{{Domain: domain(t, "example.test"), Server: listen}}
	if !reflect.DeepEqual(st.Entries, want) {
		t.Errorf("entries = %+v, want %+v ", st.Entries, want)
	}
	if len(st.Problems) != 1 || st.Problems[0].Voids || !strings.Contains(st.Problems[0].Text, errConfig.Error()) {
		t.Errorf("problems = %+v, want one problem that does not void enforcement and names the cause", st.Problems)
	}
}

func TestReadFailsOnDoneContext(t *testing.T) {
	f := newFixture(t)
	f.write(t, "example.test", listen)
	f.conf.err = errConfig
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.r.Read(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Read = %v, want an error that wraps context.Canceled", err)
	}
}

// The Reconciler drives the Resolver through the SysResolver contract: a
// second convergence with the same inputs writes nothing, and a file that
// ifbound does not manage gives a convergence error, which keeps the
// enforcement installed (Degraded, not Unenforced).
func TestReconcilerConvergesOnDirectory(t *testing.T) {
	f := newFixture(t)
	world := reconciletest.NewWorld()
	rec := reconcile.Reconciler{
		Compiler:  reconciletest.Compiler{},
		Backend:   world.Backend(),
		Resolver:  f.r,
		Inventory: reconciletest.NewInventory(),
	}
	in := reconcile.Inputs{Apexes: []policy.Domain{domain(t, "example.test")}, Listen: listen}

	rep, err := rec.Converge(t.Context(), in)
	if err != nil {
		t.Fatalf("first Converge: %v", err)
	}
	st := f.read(t)
	var got []string
	for _, e := range st.Entries {
		got = append(got, e.Domain.String())
	}
	if want := []string{"example.test", "use-application-dns.net"}; !reflect.DeepEqual(got, want) {
		t.Errorf("entries after the first convergence = %v, want %v", got, want)
	}

	if rep, err = rec.Converge(t.Context(), in); err != nil || rep.Writes != 0 {
		t.Errorf("second Converge = %d writes, %v; want 0 writes and no error", rep.Writes, err)
	}

	in.Apexes = append(in.Apexes, domain(t, "foreign.test"))
	f.put(t, "foreign.test", "nameserver 192.0.2.1\n")
	rep, err = rec.Converge(t.Context(), in)
	if !errors.Is(err, ErrConflict) {
		t.Errorf("Converge with a foreign file = %v, want an error that wraps ErrConflict", err)
	}
	if rep.Installed == "" {
		t.Errorf("Converge with a foreign file: Installed is empty; the conflict must not void enforcement")
	}
}

// A resolver below a new entry that exists before the first convergence
// is reported by the second convergence: the first one reads before it
// writes the entry. Write never reports it, so the write counts as done.
func TestReconcilerReportsPreexistingShadowOnSecondConvergence(t *testing.T) {
	f := newFixture(t)
	f.conf.entries = scutilConf(t, defaultBlock, "  domain   : www.example.test\n  nameserver[0] : 192.0.2.1\n")
	rec := reconcile.Reconciler{
		Compiler:  reconciletest.Compiler{},
		Backend:   reconciletest.NewWorld().Backend(),
		Resolver:  f.r,
		Inventory: reconciletest.NewInventory(),
	}
	in := reconcile.Inputs{Apexes: []policy.Domain{domain(t, "example.test")}, Listen: listen}

	rep, err := rec.Converge(t.Context(), in)
	if err != nil || len(rep.Problems) != 0 {
		t.Errorf("first Converge = %+v, %v; want no problem and no error", rep.Problems, err)
	}

	rep, err = rec.Converge(t.Context(), in)
	if err != nil || rep.Writes != 0 {
		t.Fatalf("second Converge = %d writes, %v; want 0 writes and no error", rep.Writes, err)
	}
	if len(rep.Problems) != 1 || !strings.Contains(rep.Problems[0].Text, "www.example.test") {
		t.Errorf("second Converge problems = %+v, want one that names www.example.test", rep.Problems)
	}
	if got := domains(f.read(t).Shadowed); !reflect.DeepEqual(got, []string{"www.example.test"}) {
		t.Errorf("Shadowed = %v, want [www.example.test]", got)
	}
}
