//go:build e2e && darwin

package e2e

import (
	"errors"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/pfbackend"
	"github.com/Nagato-Yuzuru/ifbound/pf"
)

// pfctlToken matches the line that "pfctl -E" prints to stderr.
var pfctlToken = regexp.MustCompile(`Token : (\d+)`)

// startRef takes a reference with the package. The cleanup gives the
// reference back, unless the test did it before.
func startRef(t *testing.T, h *pf.Handle) uint64 {
	t.Helper()
	tok, err := h.StartRef()
	if err != nil {
		t.Fatalf("StartRef: %v", err)
	}
	t.Cleanup(func() { dropRef(t, h, tok) })
	return tok
}

// pfctlStartRef takes a reference with "pfctl -E". The cleanup gives the
// reference back.
func pfctlStartRef(t *testing.T, h *pf.Handle) uint64 {
	t.Helper()
	m := pfctlToken.FindStringSubmatch(pfctl(t, "-E"))
	if m == nil {
		t.Fatal("pfctl -E printed no token")
	}
	tok, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		t.Fatalf("token %q: %v", m[1], err)
	}
	t.Cleanup(func() { dropRef(t, h, tok) })
	return tok
}

// dropRef gives a reference back. A reference that is gone already is
// not an error.
func dropRef(t *testing.T, h *pf.Handle, tok uint64) {
	t.Helper()
	if err := h.StopRef(tok); err != nil && !errors.Is(err, pf.ErrNotFound) {
		t.Errorf("StopRef(%d): %v", tok, err)
	}
}

// checkPfStateRestored fails the test when pf is not in the state that it
// has now at the end of the test. The test gives back its references, so
// pf must return to this state without help. The check reads the status
// from the kernel, because t.Context is done in a cleanup.
func checkPfStateRestored(t *testing.T, h *pf.Handle) {
	t.Helper()
	was := pfEnabled(t)
	t.Cleanup(func() {
		s, err := h.Status()
		if err != nil {
			t.Errorf("status: %v", err)
			return
		}
		if s.Running != was {
			t.Errorf("pf enabled = %v at the end, want %v as at the start", s.Running, was)
		}
	})
}

// findRef returns the reference with the token tok.
func findRef(t *testing.T, h *pf.Handle, tok uint64) (pf.Ref, bool) {
	t.Helper()
	refs, err := h.Refs()
	if err != nil {
		t.Fatalf("Refs: %v", err)
	}
	for _, r := range refs {
		if r.Token == tok {
			return r, true
		}
	}
	return pf.Ref{}, false
}

// pfctlHasRef reports whether "pfctl -s References" lists the token.
func pfctlHasRef(t *testing.T, tok uint64) bool {
	t.Helper()
	for line := range strings.Lines(pfctl(t, "-s", "References")) {
		if slices.Contains(strings.Fields(line), strconv.FormatUint(tok, 10)) {
			return true
		}
	}
	return false
}

// pfctlRun runs pfctl and returns its output and its error, so that a test
// can expect a failure.
func pfctlRun(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	return exec.CommandContext(t.Context(), pfbackend.Path, args...).CombinedOutput()
}

func TestPfStartRefSeenByPfctl(t *testing.T) {
	requireE2E(t)
	h := openPf(t)
	checkPfStateRestored(t, h)

	tok := startRef(t, h)
	if tok == 0 {
		t.Fatal("StartRef returned the token 0")
	}
	if !pfEnabled(t) {
		t.Error("pf is disabled after StartRef")
	}
	if !pfctlHasRef(t, tok) {
		t.Errorf("pfctl -s References does not list token %d:\n%s", tok, pfctl(t, "-s", "References"))
	}
	r, ok := findRef(t, h, tok)
	if !ok {
		t.Fatalf("Refs does not list token %d", tok)
	}
	if r.PID != os.Getpid() {
		t.Errorf("PID = %d, want %d", r.PID, os.Getpid())
	}
	if r.Process == "" {
		t.Error("Process is empty")
	}
	if age := time.Since(r.Created); age < -time.Minute || age > time.Minute {
		t.Errorf("Created = %v, which is %v from now", r.Created, age)
	}
}

func TestPfRefsSeesPfctlToken(t *testing.T) {
	requireE2E(t)
	h := openPf(t)
	checkPfStateRestored(t, h)

	tok := pfctlStartRef(t, h)
	r, ok := findRef(t, h, tok)
	if !ok {
		t.Fatalf("Refs does not list the token %d of pfctl -E", tok)
	}
	if r.Process != "pfctl" {
		t.Errorf("Process = %q, want pfctl", r.Process)
	}
	if !pfctlHasRef(t, tok) {
		t.Errorf("pfctl -s References does not list its own token %d", tok)
	}
}

func TestPfStopRefLikePfctl(t *testing.T) {
	requireE2E(t)
	h := openPf(t)
	checkPfStateRestored(t, h)

	ours := startRef(t, h)
	theirs := pfctlStartRef(t, h)

	for _, tok := range []uint64{ours, theirs} {
		if _, ok := findRef(t, h, tok); !ok {
			t.Fatalf("Refs does not list token %d among two references", tok)
		}
	}

	// StopRef takes a token of pfctl, and "pfctl -X" takes a token of the
	// package: the kernel does not care who took the reference.
	if err := h.StopRef(theirs); err != nil {
		t.Fatalf("StopRef(%d): %v", theirs, err)
	}
	pfctl(t, "-X", strconv.FormatUint(ours, 10))
	for _, tok := range []uint64{ours, theirs} {
		if _, ok := findRef(t, h, tok); ok {
			t.Errorf("Refs still lists token %d", tok)
		}
		if pfctlHasRef(t, tok) {
			t.Errorf("pfctl -s References still lists token %d", tok)
		}
	}

	// A second give-back fails in both tools.
	if err := h.StopRef(theirs); !errors.Is(err, pf.ErrNotFound) {
		t.Errorf("StopRef of a token that is gone: got %v, want ErrNotFound", err)
	}
	if out, err := pfctlRun(t, "-X", strconv.FormatUint(theirs, 10)); err == nil {
		t.Errorf("pfctl -X of a token that is gone succeeded: %s", out)
	}
}

// TestPfStopRefLast checks that pf stops with its last reference, as with
// "pfctl -X".
func TestPfStopRefLast(t *testing.T) {
	requireE2E(t)
	h := openPf(t)
	checkPfStateRestored(t, h)
	if pfEnabled(t) {
		t.Skip("pf is enabled before the test, so a reference does not enable it")
	}

	a := startRef(t, h)
	b := startRef(t, h)
	if err := h.StopRef(a); err != nil {
		t.Fatalf("StopRef(%d): %v", a, err)
	}
	if !pfEnabled(t) {
		t.Error("pf stopped with a reference left")
	}
	if err := h.StopRef(b); err != nil {
		t.Fatalf("StopRef(%d): %v", b, err)
	}
	if pfEnabled(t) {
		t.Error("pf runs after the last reference went")
	}
	s, err := h.Status()
	if err != nil || s.Running {
		t.Errorf("Status = %+v, %v; want pf stopped", s, err)
	}
}

func TestPfStopRefUnknownToken(t *testing.T) {
	requireE2E(t)
	h := openPf(t)
	checkPfStateRestored(t, h)

	tok := startRef(t, h) // pf is enabled, so the kernel looks the token up.
	if err := h.StopRef(tok + 1); !errors.Is(err, pf.ErrNotFound) {
		t.Errorf("StopRef of an unknown token with pf enabled: got %v, want ErrNotFound", err)
	}
	if _, ok := findRef(t, h, tok); !ok {
		t.Error("the failed StopRef removed another reference")
	}
}
