package hostsfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/hostsfile"
)

var _ daemon.HostsReader = Reader{}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMissingFileIsAGoodReadWithNoEntries(t *testing.T) {
	r := Reader{Path: filepath.Join(t.TempDir(), "hosts")}

	v, err := r.Version()
	if err != nil || v != (hostsfile.Version{}) {
		t.Fatalf("Version = %+v, %v, want the zero Version and no error", v, err)
	}
	h, err := r.Read(v)
	if err != nil || len(h.Entries) != 0 {
		t.Errorf("Read = %+v, %v, want no entries and no error", h, err)
	}
}

func TestReadParsesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	write(t, path, "10.1.1.1 example.com\n")
	r := Reader{Path: path}

	v, err := r.Version()
	if err != nil || !v.Exists || v.Size != int64(len("10.1.1.1 example.com\n")) {
		t.Fatalf("Version = %+v, %v", v, err)
	}
	h, err := r.Read(v)
	if err != nil || len(h.Entries) != 1 {
		t.Errorf("Read = %+v, %v, want one entry", h, err)
	}
}

func TestVersionChangesWithTheModificationTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	write(t, path, "10.1.1.1 example.com\n")
	r := Reader{Path: path}
	before, err := r.Version()
	if err != nil {
		t.Fatal(err)
	}

	write(t, path, "10.1.1.2 example.com\n")
	mod := time.Unix(0, before.ModNano).Add(time.Second)
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}

	after, err := r.Version()
	if err != nil || after == before {
		t.Errorf("Version = %+v, %v, want a change from %+v", after, err, before)
	}
}

// A directory is not a regular file. The error is in Version, so Read
// never opens it.
func TestVersionRefusesADirectory(t *testing.T) {
	if _, err := (Reader{Path: t.TempDir()}).Version(); !errors.Is(err, errNotRegular) {
		t.Errorf("Version error = %v, want ErrNotRegular", err)
	}
}

// The file went away between Version and Read.
func TestReadOfAFileThatWentAway(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	write(t, path, "10.1.1.1 example.com\n")
	r := Reader{Path: path}
	v, err := r.Version()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	if _, err := r.Read(v); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Read error = %v, want ErrNotExist", err)
	}
}

// A symlink to itself: the stat fails.
func TestVersionErrorOfASymlinkLoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.Symlink(path, path); err != nil {
		t.Fatal(err)
	}

	if _, err := (Reader{Path: path}).Version(); err == nil {
		t.Error("Version of a symlink loop gave no error")
	}
}

// A FIFO can block an open, and the loop must not wait for it.
func TestVersionRefusesAFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := (Reader{Path: path}).Version(); !errors.Is(err, errNotRegular) {
		t.Errorf("Version error = %v, want ErrNotRegular", err)
	}
}

// The daemon drops a read when the Version moves during it, so Version
// must not move while the file stays, also across a Read.
func TestVersionIsStableWhileTheFileStays(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	write(t, path, "10.1.1.1 example.com\n")
	r := Reader{Path: path}

	v1, err := r.Version()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(v1); err != nil {
		t.Fatal(err)
	}
	v2, err := r.Version()
	if err != nil || v1 != v2 {
		t.Errorf("Version after Read = %+v, %v, want %+v", v2, err, v1)
	}

	write(t, path, "10.1.1.2 example.org.test\n")
	v3, err := r.Version()
	if err != nil || v3 == v1 {
		t.Errorf("Version after a change = %+v, %v, want a change from %+v", v3, err, v1)
	}
}

// A Reader that nobody set up must not look like a missing file.
func TestVersionRefusesAPathThatIsNotAbsolute(t *testing.T) {
	for _, path := range []string{"", "hosts", "etc/hosts"} {
		if _, err := (Reader{Path: path}).Version(); !errors.Is(err, errBadPath) {
			t.Errorf("Version of %q: error = %v, want errBadPath", path, err)
		}
	}
}

func TestNotRegularErrorNamesThePath(t *testing.T) {
	dir := t.TempDir()
	_, err := (Reader{Path: dir}).Version()
	if err == nil || !strings.Contains(err.Error(), dir) {
		t.Errorf("error = %v, want the path %s", err, dir)
	}
}
