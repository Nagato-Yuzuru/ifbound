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

// A symbolic link at the path is refused: Acquire neither creates nor
// locks its target.
func TestSymlinkIsRefused(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, "enforcement.lock")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if l, err := enforcementlock.Acquire(path); err == nil {
		_ = l.Close() //nolint:errcheck // the test fails already
		t.Fatal("Acquire through a symbolic link = nil, want an error")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the target of the link exists after Acquire: %v", err)
	}
}
