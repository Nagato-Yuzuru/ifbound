package enforcementlock_test

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/enforcementlock"
)

// holderEnv makes the test binary a lock holder: it takes the lock at the
// path in the variable, prints a line, and holds the lock until its stdin
// closes.
const holderEnv = "IFBOUND_TEST_LOCK_HOLDER"

func TestHelperHolder(t *testing.T) {
	path := os.Getenv(holderEnv)
	if path == "" {
		t.Skip("runs only as the lock holder of TestHeldByAnotherProcess")
	}
	l, err := enforcementlock.Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close() //nolint:errcheck // the process exits next, which releases the lock
	if _, err := os.Stdout.WriteString("held\n"); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, os.Stdin) //nolint:errcheck // any end of stdin ends the hold
}

func TestHeldByAnotherProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enforcement.lock")
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHelperHolder$")
	cmd.Env = append(os.Environ(), holderEnv+"="+path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "held\n" {
		t.Fatalf("holder said %q, %v; want held", line, err)
	}

	if l, err := enforcementlock.Acquire(path); !errors.Is(err, enforcementlock.ErrHeld) {
		if l != nil {
			_ = l.Close() //nolint:errcheck // the test fails already
		}
		t.Fatalf("Acquire while another process holds the lock = %v, want ErrHeld", err)
	}

	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("holder: %v", err)
	}
	l, err := enforcementlock.Acquire(path)
	if err != nil {
		t.Fatalf("Acquire after the holder exited = %v, want the lock", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHeldInTheSameProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enforcement.lock")
	first, err := enforcementlock.Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enforcementlock.Acquire(path); !errors.Is(err, enforcementlock.ErrHeld) {
		t.Errorf("second Acquire = %v, want ErrHeld", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := enforcementlock.Acquire(path)
	if err != nil {
		t.Fatalf("Acquire after Close = %v, want the lock", err)
	}
	if err := again.Close(); err != nil {
		t.Fatal(err)
	}
}

// Both entry points refuse a symbolic link at the lock name with ErrSymlink.
// The link is dangling or points to a file that exists, also inside the
// root, which os.Root alone follows. Neither call creates or locks the
// target.
func TestSymlinkIsRefused(t *testing.T) {
	for _, tt := range []struct {
		name           string
		targetExists   bool
		acquireThrough func(dir, name string) (*enforcementlock.Lock, error)
	}{
		{"Acquire, dangling link", false, func(dir, name string) (*enforcementlock.Lock, error) {
			return enforcementlock.Acquire(filepath.Join(dir, name))
		}},
		{"Acquire, link to a file", true, func(dir, name string) (*enforcementlock.Lock, error) {
			return enforcementlock.Acquire(filepath.Join(dir, name))
		}},
		{"AcquireIn, dangling link", false, acquireIn},
		{"AcquireIn, link to a file", true, acquireIn},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "target")
			if tt.targetExists {
				if err := os.WriteFile(target, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink("target", filepath.Join(dir, "lock")); err != nil {
				t.Fatal(err)
			}
			l, err := tt.acquireThrough(dir, "lock")
			if err == nil {
				_ = l.Close() //nolint:errcheck // the test fails already
			}
			if !errors.Is(err, enforcementlock.ErrSymlink) {
				t.Errorf("error = %v, want ErrSymlink", err)
			}
			if _, err := os.Lstat(target); tt.targetExists == errors.Is(err, os.ErrNotExist) {
				t.Errorf("target exists = %v after the call, want %v: %v", !errors.Is(err, os.ErrNotExist), tt.targetExists, err)
			}
		})
	}
}

func acquireIn(dir, name string) (*enforcementlock.Lock, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close() //nolint:errcheck // a read-only handle in a test
	return enforcementlock.AcquireIn(root, name)
}

// AcquireIn takes one file name. A path could pass through a link.
func TestAcquireInRefusesPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", ".", "..", "sub/lock", "../lock"} {
		if l, err := acquireIn(dir, name); err == nil {
			_ = l.Close() //nolint:errcheck // the test fails already
			t.Errorf("AcquireIn(%q) = nil, want an error", name)
		}
	}
}

func TestAcquireInHeldInTheSameProcess(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close() //nolint:errcheck // a read-only handle in a test
	first, err := enforcementlock.AcquireIn(root, "lock")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close() //nolint:errcheck // the test ends next
	if _, err := enforcementlock.AcquireIn(root, "lock"); !errors.Is(err, enforcementlock.ErrHeld) {
		t.Errorf("second AcquireIn = %v, want ErrHeld", err)
	}
}
