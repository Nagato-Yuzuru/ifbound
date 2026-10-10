// Package testenv decides whether the current host can run an end-to-end
// test. When a requirement is not met, the test skips with a reason. In
// strict mode (IFBOUND_E2E_STRICT=1, set by CI and the VM task), the test
// fails instead, so that a broken environment cannot pass as a skip.
package testenv

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
)

const (
	// EnvDisposable marks a host whose network state a test can change: a CI
	// runner or a disposable VM. End-to-end tests change pf and interfaces,
	// so they never run on a host without this mark.
	EnvDisposable = "IFBOUND_E2E_DISPOSABLE"
	// EnvStrict turns every unmet requirement into a failure.
	EnvStrict = "IFBOUND_E2E_STRICT"
)

// RequireDisposableHost skips the test unless EnvDisposable is "1".
func RequireDisposableHost(t testing.TB) {
	t.Helper()
	if os.Getenv(EnvDisposable) != "1" {
		unmet(t, EnvDisposable+"=1 is not set; run through `mise run vm:e2e` or CI")
	}
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
