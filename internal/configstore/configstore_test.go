package configstore

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

const (
	validA = "[dns]\nupstream = [\"tls://9.9.9.9@dns.quad9.net\"]\n[[policy]]\nname = \"a\"\nto = [\"a.example\"]\nonly_via = []\n"
	validB = "[dns]\nupstream = [\"tls://9.9.9.9@dns.quad9.net\"]\n[[policy]]\nname = \"b\"\nto = [\"b.example\"]\nonly_via = [\"utun*\"]\n"
	// unreachable parses but fails the apply check: the upstream is
	// inside a destination of a policy that allows no interface.
	unreachable = "[dns]\nupstream = [\"tls://9.9.9.9@dns.quad9.net\"]\n[[policy]]\nname = \"c\"\nto = [\"9.9.9.0/24\"]\nonly_via = []\n"
	// syntaxError does not parse.
	syntaxError = "[dns\n"
)

func TestStoreThenLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	stored, sd, err := Store(path, []byte(validA), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	loaded, ld, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if sd != ld || sd != sha256.Sum256([]byte(validA)) {
		t.Errorf("digests: store %v, load %v, want the SHA-256 of the input", sd, ld)
	}
	if !reflect.DeepEqual(stored, loaded) {
		t.Errorf("loaded config differs from stored config\nstore %#v\n load %#v", stored, loaded)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode() != 0o640 {
		t.Errorf("mode = %v, want -rw-r-----", fi.Mode())
	}
	assertOnlyFile(t, path)
}

// TestStoreSetsGroup stores with a group that the file would not get
// without the chown.
func TestStoreSetsGroup(t *testing.T) {
	dir := t.TempDir()
	probe := filepath.Join(dir, "probe")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(probe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(probe); err != nil {
		t.Fatal(err)
	}
	defaultGID := int(fi.Sys().(*syscall.Stat_t).Gid)
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	gid := -1
	for _, g := range groups {
		if g != defaultGID {
			gid = g
			break
		}
	}
	if gid < 0 {
		t.Skipf("the test process has no group other than %d, so the chown cannot change the group", defaultGID)
	}
	path := filepath.Join(dir, "config.toml")
	if _, _, err := Store(path, []byte(validA), gid); err != nil {
		t.Fatal(err)
	}
	fi, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := int(fi.Sys().(*syscall.Stat_t).Gid); got != gid {
		t.Errorf("gid = %d, want %d (default %d)", got, gid, defaultGID)
	}
}

func TestDigestString(t *testing.T) {
	d := Digest(sha256.Sum256(nil))
	const want = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if d.String() != want {
		t.Errorf("String = %q, want %q", d, want)
	}
}

func TestStoreInvalidKeepsOldFile(t *testing.T) {
	tests := []struct {
		name, data string
	}{
		{"syntax error", syntaxError},
		{"unreachable upstream", unreachable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if _, _, err := Store(path, []byte(validA), -1); err != nil {
				t.Fatal(err)
			}
			_, _, err := Store(path, []byte(tt.data), -1)
			var fe *policy.FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("error = %v, want a *policy.FieldError", err)
			}
			assertContent(t, path, validA)
			assertOnlyFile(t, path)
		})
	}
}

func TestStoreFailedRenameKeepsOldFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if _, _, err := Store(path, []byte(validA), -1); err != nil {
		t.Fatal(err)
	}
	errCrash := errors.New("crash before rename")
	failRename := func(oldpath, _ string) error {
		// The temporary file is complete and next to path.
		if filepath.Dir(oldpath) != filepath.Dir(path) {
			t.Errorf("temporary file %q is not in the directory of %q", oldpath, path)
		}
		assertContent(t, oldpath, validB)
		return errCrash
	}
	if _, _, err := store(path, []byte(validB), -1, failRename); !errors.Is(err, errCrash) {
		t.Fatalf("error = %v, want %v", err, errCrash)
	}
	assertContent(t, path, validA)
	assertOnlyFile(t, path)
}

// TestStoreNotDurable fails the directory sync after a good rename. The
// new file is in place, so Store returns the new config with the error.
func TestStoreNotDurable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can open a directory without the read bit")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	renameThenLock := func(oldpath, newpath string) error {
		if err := os.Rename(oldpath, newpath); err != nil {
			return err
		}
		// Without the read bit, the open for the directory sync fails.
		return os.Chmod(dir, 0o300)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:errcheck // the cleanup of TempDir reports a failure
	cfg, d, err := store(path, []byte(validB), -1, renameThenLock)
	if !errors.Is(err, ErrNotDurable) {
		t.Fatalf("error = %v, want %v", err, ErrNotDurable)
	}
	if len(cfg.Policies) != 1 || cfg.Policies[0].Name != "b" || d != sha256.Sum256([]byte(validB)) {
		t.Errorf("store returned %v and %v, want the new config and its digest", cfg, d)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	assertContent(t, path, validB)
}

func TestStoreRemovesStaleTemps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	for _, name := range []string{"config.toml.tmp-123", "config.toml.tmp-"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := Store(path, []byte(validA), -1); err != nil {
		t.Fatal(err)
	}
	assertOnlyFile(t, path)
}

// TestLoadAcceptsWhatApplyRejects stores a file that an earlier version
// accepted and the apply check of this version rejects. Load must still
// load it: a daemon that cannot start leaves destinations unblocked.
func TestLoadAcceptsWhatApplyRejects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(unreachable), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err != nil {
		t.Errorf("Load = %v, want nil", err)
	}
}

func TestLoadNotApplied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if _, _, err := Load(path); !errors.Is(err, ErrNotApplied) {
		t.Errorf("error = %v, want %v", err, ErrNotApplied)
	}
}

func TestLoadRefuses(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.toml")
	if err := os.WriteFile(good, []byte(validA), 0o640); err != nil {
		t.Fatal(err)
	}
	notDir := filepath.Join(dir, "file")
	if err := os.WriteFile(notDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		setup func(path string) error
		path  string // relative to dir, or absolute; empty means a new "config.toml"
		want  error  // the error must wrap it; nil means any error
	}{
		{"missing directory", nil, "no-such-dir/config.toml", fs.ErrNotExist},
		{"directory is a file", nil, "file/config.toml", nil},
		{"dangling symlink", func(p string) error { return os.Symlink(filepath.Join(dir, "gone.toml"), p) }, "", errBadFile},
		{"symlink to a valid file", func(p string) error { return os.Symlink(good, p) }, "", errBadFile},
		{"directory", func(p string) error { return os.Mkdir(p, 0o700) }, "", errBadFile},
		{"fifo", func(p string) error { return syscall.Mkfifo(p, 0o640) }, "", errBadFile},
		{"device", nil, "/dev/null", errBadFile},
		{"group can write", func(p string) error { return writeMode(p, 0o660) }, "", errBadFile},
		{"others can write", func(p string) error { return writeMode(p, 0o642) }, "", errBadFile},
		{"syntax error", func(p string) error { return os.WriteFile(p, []byte(syntaxError), 0o640) }, "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			switch {
			case filepath.IsAbs(tt.path):
				path = tt.path
			case tt.path != "":
				path = filepath.Join(dir, tt.path)
			}
			if tt.setup != nil {
				if err := tt.setup(path); err != nil {
					t.Fatal(err)
				}
			}
			err := loadWithin(t, path)
			if err == nil || errors.Is(err, ErrNotApplied) || tt.want != nil && !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want an error that wraps %v and is not %v", err, tt.want, ErrNotApplied)
			}
		})
	}
}

// loadWithin returns the error of Load. It fails the test when Load
// blocks, as it would on a FIFO without a writer.
func loadWithin(t *testing.T, path string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, _, err := Load(path)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Load blocks")
		return nil
	}
}

// writeMode writes a valid config with exactly mode perm.
func writeMode(path string, perm fs.FileMode) error {
	if err := os.WriteFile(path, []byte(validA), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, perm)
}

func assertContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("file changed\n got %q\nwant %q", got, want)
	}
}

// assertOnlyFile checks that no temporary file stays next to path.
func assertOnlyFile(t *testing.T, path string) {
	t.Helper()
	ents, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != filepath.Base(path) {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %q, want only %q", names, filepath.Base(path))
	}
}
