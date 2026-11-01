// Package testenv decides whether the current host can run an end-to-end
// test. RunOnDisposableHost gates the whole test binary. The Require
// functions gate one test: when a requirement is not met, the test skips
// with a reason. In strict mode (IFBOUND_E2E_STRICT=1, set by CI and the VM
// task), an unmet requirement is a failure instead, so that a broken
// environment cannot pass as a skip.
package testenv

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
)

const (
	// DisposableMarker marks a host whose state a test can change: a CI
	// runner or a disposable VM. End-to-end tests change pf, interfaces,
	// routes, /etc/resolver, and the writer lock, so they never run on a
	// host without this file. The VM task and the CI job create it; nothing
	// creates it on a development host. Any process can set an environment
	// variable by mistake, but only root can create this file.
	DisposableMarker = "/var/db/ifbound-e2e-disposable"
	// EnvStrict turns every unmet requirement into a failure.
	EnvStrict = "IFBOUND_E2E_STRICT"
)

var errMarkerOwner = errors.New("its owner is not root")

// Runner is the part of *testing.M that RunOnDisposableHost uses.
type Runner interface{ Run() int }

// RunOnDisposableHost runs the tests of m only when DisposableMarker exists
// and root owns it, and returns the exit code for os.Exit. Call it from
// TestMain, so that no test and no helper process of the binary can reach
// the host before the check. On another host it runs no test: it exits 0,
// or 1 in strict mode.
func RunOnDisposableHost(m Runner) int {
	return runOnDisposableHost(m, DisposableMarker, os.Getenv(EnvStrict) == "1", os.Stderr)
}

func runOnDisposableHost(m Runner, marker string, strict bool, w io.Writer) int {
	if err := checkMarker(marker); err != nil {
		// The text does not tell the reader to create the marker, because
		// on a development host that is the mistake this check stops.
		//nolint:errcheck // the exit code carries the result; a lost line changes nothing
		_, _ = fmt.Fprintf(w, "e2e: this host is not marked disposable (%v).\n"+
			"The tests change pf, interfaces, routes, /etc/resolver, and the writer lock.\n"+
			"Run them with `mise run vm:e2e` or in CI. No test ran.\n", err)
		if strict {
			return 1
		}
		return 0
	}
	return m.Run()
}

// checkMarker returns an error unless the file at path exists and uid 0
// owns it.
func checkMarker(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("marker: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return fmt.Errorf("marker %s: %w", path, errMarkerOwner)
	}
	return nil
}

// RequireOS skips the test unless runtime.GOOS is goos.
func RequireOS(t testing.TB, goos string) {
	t.Helper()
	if runtime.GOOS != goos {
		unmet(t, "requires GOOS="+goos+", have "+runtime.GOOS)
	}
}

// RequireRoot skips the test unless the process runs as root.
func RequireRoot(t testing.TB) {
	t.Helper()
	if os.Geteuid() != 0 {
		unmet(t, "requires root")
	}
}

// RequireCommand skips the test unless name is in PATH.
func RequireCommand(t testing.TB, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		unmet(t, "requires command "+name+": "+err.Error())
	}
}

func unmet(t testing.TB, reason string) {
	t.Helper()
	if os.Getenv(EnvStrict) == "1" {
		t.Fatalf("environment requirement not met in strict mode: %s", reason)
	}
	t.Skip(reason)
}
