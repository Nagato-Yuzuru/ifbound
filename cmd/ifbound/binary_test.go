package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These tests run the real binary: exit codes of cobra's own commands,
// completion output, and the signal and resource behavior of apply.

type process struct {
	code           int
	stdout, stderr string
}

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "ifbound")
	out, err := exec.CommandContext(t.Context(), "go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func runBinary(t *testing.T, bin string, args ...string) process {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	var ee *exec.ExitError
	if err := cmd.Run(); err != nil && !errors.As(err, &ee) {
		t.Fatal(err)
	}
	return process{cmd.ProcessState.ExitCode(), out.String(), errOut.String()}
}

func TestBinary(t *testing.T) {
	bin := buildBinary(t)
	t.Run("usage errors exit 2", func(t *testing.T) { checkUsageExits(t, bin) })
	t.Run("valid commands do not exit 2", func(t *testing.T) { checkValidExits(t, bin) })
	t.Run("completion", func(t *testing.T) { checkCompletion(t, bin) })
	t.Run("endless file", func(t *testing.T) { checkEndlessFile(t, bin) })
	t.Run("interrupt ends a blocked read", func(t *testing.T) { checkInterruptOnFIFO(t, bin) })
}

func checkUsageExits(t *testing.T, bin string) {
	t.Helper()
	for _, args := range [][]string{
		{"completion", "zhs"},
		{"completion", "bash", "extra"},
		{"completion", "--nope"},
		{"help", "nope"},
		{"help", "apply", "extra"},
		{"nope"},
		{"--nope"},
		{"apply", "--nope"},
		{"apply", "a.toml", "b.toml"},
		{"version", "x"},
		{"version", "--nope"},
	} {
		got := runBinary(t, bin, args...)
		if got.code != 2 {
			t.Errorf("%q: exit %d, want 2 (stderr %q)", args, got.code, got.stderr)
		}
		if strings.Contains(got.stdout, "Usage:") {
			t.Errorf("%q: a usage error printed help to stdout", args)
		}
	}
}

func checkValidExits(t *testing.T, bin string) {
	t.Helper()
	missing := filepath.Join(t.TempDir(), "missing.toml")
	for _, args := range [][]string{
		{}, {"--help"}, {"-h"}, {"--version"}, {"help"}, {"help", "apply"},
		{"apply", "--help"}, {"version", "--help"},
		{"completion"}, {"completion", "bash"}, {"completion", "zsh"},
		{"completion", "fish"}, {"completion", "powershell"},
		{"apply", missing},
	} {
		if got := runBinary(t, bin, args...); got.code == 2 {
			t.Errorf("%q: a valid command exits 2 (stderr %q)", args, got.stderr)
		}
	}
}

func checkCompletion(t *testing.T, bin string) {
	t.Helper()
	tests := []struct {
		args      []string
		directive string
		entries   []string
	}{
		{[]string{"__complete", "apply", ""}, ":8", []string{"toml"}},
		{[]string{"__complete", "apply", "a.toml", ""}, ":4", nil},
		{[]string{"__complete", "version", ""}, ":4", nil},
		{[]string{"__complete", "version", "x", ""}, ":4", nil},
	}
	for _, tt := range tests {
		got := runBinary(t, bin, tt.args...)
		lines := strings.Split(strings.TrimRight(got.stdout, "\n"), "\n")
		directive, entries := lines[len(lines)-1], lines[:len(lines)-1]
		if got.code != 0 || directive != tt.directive || strings.Join(entries, ",") != strings.Join(tt.entries, ",") {
			t.Errorf("%q: exit %d, directive %q, entries %q; want %q and %q", tt.args, got.code, directive, entries, tt.directive, tt.entries)
		}
	}
}

func checkEndlessFile(t *testing.T, bin string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), bin, "apply", "/dev/zero")
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	done := make(chan struct{})
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = cmd.Wait(); close(done) }() //nolint:errcheck // the exit status is read from ProcessState
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill() //nolint:errcheck // the process may be gone
		<-done
		t.Fatal("apply /dev/zero did not end in 5 s")
	}
	if cmd.ProcessState.ExitCode() != 1 || !strings.Contains(errOut.String(), "file too large") {
		t.Errorf("exit %d, stderr %q, want 1 and the size error", cmd.ProcessState.ExitCode(), errOut.String())
	}
	if rusage, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok && rusage.Maxrss > maxRSSBytes {
		t.Errorf("max RSS %d, want a bounded read", rusage.Maxrss)
	}
}

// maxRSSBytes bounds the memory of a bounded read. Maxrss is in bytes on
// darwin and in KiB on linux; the bound is loose for both.
const maxRSSBytes = 64 << 20

func checkInterruptOnFIFO(t *testing.T, bin string) {
	t.Helper()
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	cmd := exec.CommandContext(t.Context(), bin, "apply", fifo)
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }() //nolint:errcheck // the exit status is read from ProcessState
	// No writer exists, so the open blocks. The wait gives main time to
	// install its signal handler.
	select {
	case <-done:
		t.Fatalf("ended before the interrupt: %q", errOut.String())
	case <-time.After(500 * time.Millisecond):
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill() //nolint:errcheck // the process may be gone
		<-done
		t.Fatal("the interrupt did not end the blocked read in 3 s")
	}
	ws, _ := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if code := cmd.ProcessState.ExitCode(); ws.Signaled() || code == 0 || code == exitLost {
		t.Errorf("exit %d, signaled %v, want a normal non-zero exit that is not %d", code, ws.Signaled(), exitLost)
	}
}
