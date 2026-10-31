package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

const validConfig = "[dns]\nupstream = [\"tls://1.1.1.1@a.b\"]\n\n" +
	"[[policy]]\nname = \"p\"\nto = [\"example.com\"]\nonly_via = []\n"

// fakeDaemon answers on the sockets that serve it. It records the files
// that reach Apply. With block set, Apply signals on reached and waits for
// its context.
type fakeDaemon struct {
	status   ipc.StatusReport
	applyErr error
	block    bool
	reached  chan struct{}
	// release, when set, replaces the context as the end of the wait: the
	// handler then ignores its deadline, as a stuck daemon does.
	release chan struct{}

	mu      sync.Mutex
	applied [][]byte
}

func (f *fakeDaemon) Status(context.Context) (ipc.StatusReport, error) { return f.status, nil }

func (f *fakeDaemon) Apply(ctx context.Context, cfg []byte) (ipc.StatusReport, error) {
	f.mu.Lock()
	f.applied = append(f.applied, cfg)
	f.mu.Unlock()
	if f.block {
		f.reached <- struct{}{}
		if f.release != nil {
			<-f.release
			return f.status, nil
		}
		<-ctx.Done()
		return ipc.StatusReport{}, ctx.Err()
	}
	return f.status, f.applyErr
}

func (f *fakeDaemon) appliedFiles() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied
}

// socketPath returns a short path: a unix socket path has a small limit.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ifb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) }) //nolint:errcheck // temp dir; a leftover is harmless
	return filepath.Join(dir, "s.sock")
}

func uid() uint32 { return uint32(os.Getuid()) } //nolint:gosec // uid is never negative on unix

func serve(t *testing.T, srv *ipc.Server, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background()) }()
	t.Cleanup(func() {
		_ = srv.Close() //nolint:errcheck // the result of Serve is checked below
		if err := <-done; err != nil {
			t.Errorf("Serve returned %v", err)
		}
	})
}

// serveAdmin serves f on an admin socket and returns a client for it.
func serveAdmin(t *testing.T, f *fakeDaemon) *ipc.ControlClient {
	t.Helper()
	path := socketPath(t)
	srv, err := ipc.ListenAdmin(ipc.AdminConfig{Path: path, Handler: f, UIDs: []uint32{uid()}})
	serve(t, srv, err)
	return ipc.NewControlClient(path, uid())
}

// serveStatus serves f on a status socket and returns a client for it.
func serveStatus(t *testing.T, f *fakeDaemon) *ipc.ControlClient {
	t.Helper()
	path := socketPath(t)
	srv, err := ipc.ListenStatus(ipc.StatusConfig{Path: path, Handler: f})
	serve(t, srv, err)
	return ipc.NewControlClient(path, uid())
}

// rawServer runs handle for each connection on a new socket. The tests use
// it for replies that the real server never sends.
func rawServer(t *testing.T, handle func(net.Conn)) *ipc.ControlClient {
	t.Helper()
	path := socketPath(t)
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = c.Close() }() //nolint:errcheck // test connection
				handle(c)
			})
		}
	})
	t.Cleanup(func() {
		_ = ln.Close() //nolint:errcheck // the accept loop ends on the error
		wg.Wait()
	})
	return ipc.NewControlClient(path, uid())
}

// readRequest reads one frame from c.
func readRequest(c net.Conn) error {
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return err
	}
	_, err := io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint32(hdr[:])))
	return err
}

// otherVersionReply answers every request with an ack of protocol 2.
func otherVersionReply(c net.Conn) {
	if readRequest(c) != nil {
		return
	}
	payload := []byte(`{"v":2,"type":"ack"}`)
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(payload))) //nolint:gosec // tiny
	_, _ = c.Write(append(frame, payload...))                         //nolint:errcheck // the client may be gone
}

// closeAfterRequest reads the request and closes with no reply.
func closeAfterRequest(c net.Conn) { _ = readRequest(c) } //nolint:errcheck // the close is the test

type result struct {
	code           int
	stdout, stderr string
}

func execute(t *testing.T, d deps, args ...string) result {
	t.Helper()
	return executeCtx(t.Context(), t, d, args...)
}

func executeCtx(ctx context.Context, t *testing.T, d deps, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	d.stdout, d.stderr = &out, &errOut
	code := run(ctx, args, d)
	return result{code, out.String(), errOut.String()}
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func ready() *fakeDaemon { return &fakeDaemon{status: ipc.StatusReport{State: ipc.StateReady}} }

func TestApplyExitCodes(t *testing.T) {
	tests := []struct {
		name  string
		state ipc.State
		want  int
	}{
		{"ready", ipc.StateReady, 0},
		{"degraded", ipc.StateDegraded, 3},
		{"unenforced", ipc.StateUnenforced, 4},
		{"starting", ipc.StateStarting, 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeDaemon{status: ipc.StatusReport{State: tt.state, Reasons: []string{"why"}}}
			file := writeFile(t, validConfig)

			got := execute(t, deps{admin: serveAdmin(t, f)}, "apply", file)

			if got.code != tt.want {
				t.Errorf("exit = %d, want %d (stderr %q)", got.code, tt.want, got.stderr)
			}
			if files := f.appliedFiles(); len(files) != 1 || string(files[0]) != validConfig {
				t.Errorf("server got %q, want the file once", files)
			}
			if want := "state: " + tt.state.String(); !strings.Contains(got.stdout, want) {
				t.Errorf("stdout = %q, want %q in it", got.stdout, want)
			}
			if got.stderr != "" {
				t.Errorf("stderr = %q, want empty: the state code prints no error", got.stderr)
			}
		})
	}
}

func TestApplyDefaultFile(t *testing.T) {
	f := ready()
	file := writeFile(t, validConfig)

	got := execute(t, deps{admin: serveAdmin(t, f), inputConfig: file}, "apply")

	if got.code != 0 || len(f.appliedFiles()) != 1 {
		t.Errorf("exit = %d, applied %d files, want 0 and 1 (stderr %q)", got.code, len(f.appliedFiles()), got.stderr)
	}
}

func TestApplyBadFileDoesNotCallTheServer(t *testing.T) {
	tests := []struct {
		name, config, want string
	}{
		{
			"parse error",
			"[dns]\nupstream = [\"tls://1.1.1.1@a.b\"]\n[[policy]]\nname = \"p\"\nto = [\"bad host\"]\nonly_via = []\n",
			"policy[0].to[0]",
		},
		{
			// DNS can never reach the upstream: the policy allows no interface.
			"upstream check",
			"[dns]\nupstream = [\"tls://1.1.1.1@a.b\"]\n[[policy]]\nname = \"p\"\nto = [\"1.1.1.0/24\"]\nonly_via = []\n",
			"upstream",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := ready()
			file := writeFile(t, tt.config)

			got := execute(t, deps{admin: serveAdmin(t, f)}, "apply", file)

			if got.code != 1 {
				t.Errorf("exit = %d, want 1", got.code)
			}
			if n := len(f.appliedFiles()); n != 0 {
				t.Errorf("server got %d calls, want 0", n)
			}
			if !strings.Contains(got.stderr, file) || !strings.Contains(got.stderr, tt.want) {
				t.Errorf("stderr = %q, want the file name and %q", got.stderr, tt.want)
			}
		})
	}
}

func TestApplyMissingFileNamesThePathOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "none.toml")

	got := execute(t, deps{}, "apply", path)

	if got.code != 1 || strings.Count(got.stderr, path) != 1 {
		t.Errorf("exit = %d, stderr %q, want 1 and the path once", got.code, got.stderr)
	}
}

func TestApplyFileSizeLimit(t *testing.T) {
	pad := func(n int) string { return validConfig + "#" + strings.Repeat("x", n-len(validConfig)-1) }

	t.Run("largest file that fits in a frame", func(t *testing.T) {
		f := ready()
		got := execute(t, deps{admin: serveAdmin(t, f)}, "apply", writeFile(t, pad(maxConfigBytes)))
		if got.code != 0 || len(f.appliedFiles()) != 1 {
			t.Errorf("exit = %d, stderr %q, want 0 and one call", got.code, got.stderr)
		}
	})
	t.Run("one byte more", func(t *testing.T) {
		f := ready()
		got := execute(t, deps{admin: serveAdmin(t, f)}, "apply", writeFile(t, pad(maxConfigBytes+1)))
		if got.code != 1 || !strings.Contains(got.stderr, "file too large (max ") || len(f.appliedFiles()) != 0 {
			t.Errorf("exit = %d, stderr %q, want 1 and the size error", got.code, got.stderr)
		}
	})
	t.Run("endless device", func(t *testing.T) {
		got := execute(t, deps{}, "apply", "/dev/zero")
		if got.code != 1 || !strings.Contains(got.stderr, "file too large") {
			t.Errorf("exit = %d, stderr %q, want 1 and the size error", got.code, got.stderr)
		}
	})
}

func TestApplyReadEndsOnInterrupt(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	// Opening the other end lets the reading goroutine return at the end.
	t.Cleanup(func() {
		if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = w.Close() //nolint:errcheck // test cleanup
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	got := executeCtx(ctx, t, deps{}, "apply", fifo)

	if got.code != 1 || !strings.Contains(got.stderr, "deadline exceeded") {
		t.Errorf("exit = %d, stderr %q, want 1 after the context ended", got.code, got.stderr)
	}
}

func TestApplyRefusedByServer(t *testing.T) {
	f := &fakeDaemon{applyErr: errors.New("upstream 1.1.1.1 is blocked by policy p")}

	got := execute(t, deps{admin: serveAdmin(t, f)}, "apply", writeFile(t, validConfig))

	if got.code != 1 || !strings.Contains(got.stderr, "upstream 1.1.1.1 is blocked by policy p") {
		t.Errorf("exit = %d, stderr %q, want 1 and the reason of the server", got.code, got.stderr)
	}
}

func TestApplyFailureHints(t *testing.T) {
	file := writeFile(t, validConfig)

	t.Run("nothing listens", func(t *testing.T) {
		c := ipc.NewControlClient(socketPath(t), uid())
		got := execute(t, deps{admin: c}, "apply", file)
		if got.code != 1 || !strings.Contains(got.stderr, "is ifboundd running") {
			t.Errorf("exit = %d, stderr %q, want 1 and the hint", got.code, got.stderr)
		}
	})
	t.Run("server of another uid", func(t *testing.T) {
		f := ready()
		path := socketPath(t)
		srv, err := ipc.ListenAdmin(ipc.AdminConfig{Path: path, Handler: f, UIDs: []uint32{uid()}})
		serve(t, srv, err)
		got := execute(t, deps{admin: ipc.NewControlClient(path, uid()+1)}, "apply", file)
		if got.code != 1 || strings.Contains(got.stderr, "ifbound status") {
			t.Errorf("exit = %d, stderr %q, want 1 and no lost-reply text", got.code, got.stderr)
		}
		if n := len(f.appliedFiles()); n != 0 {
			t.Errorf("server got %d calls, want 0", n)
		}
	})
	t.Run("socket closed to the caller", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("root connects to any socket")
		}
		path := socketPath(t)
		srv, err := ipc.ListenAdmin(ipc.AdminConfig{Path: path, Handler: ready(), UIDs: []uint32{uid()}})
		serve(t, srv, err)
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
		got := execute(t, deps{admin: ipc.NewControlClient(path, uid())}, "apply", file)
		if got.code != 1 || !strings.Contains(got.stderr, "run as root") {
			t.Errorf("exit = %d, stderr %q, want 1 and the root hint", got.code, got.stderr)
		}
	})
	t.Run("reply of another protocol", func(t *testing.T) {
		got := execute(t, deps{admin: rawServer(t, otherVersionReply)}, "apply", file)
		if got.code != 1 || !strings.Contains(got.stderr, "ifbound version") {
			t.Errorf("exit = %d, stderr %q, want 1 and the version hint", got.code, got.stderr)
		}
	})
}

func TestApplyLostReplyExits6(t *testing.T) {
	file := writeFile(t, validConfig)
	const want = "can have applied the file"

	t.Run("connection closed after the request", func(t *testing.T) {
		got := execute(t, deps{admin: rawServer(t, closeAfterRequest)}, "apply", file)
		if got.code != 6 || !strings.Contains(got.stderr, want) || !strings.Contains(got.stderr, "ifbound status") {
			t.Errorf("exit = %d, stderr %q, want 6 and the warning", got.code, got.stderr)
		}
	})
	t.Run("interrupt while the daemon works", func(t *testing.T) {
		f := &fakeDaemon{block: true, reached: make(chan struct{}, 1)}
		c := serveAdmin(t, f)
		ctx, cancel := context.WithCancel(t.Context())
		go func() {
			<-f.reached
			cancel()
		}()
		got := executeCtx(ctx, t, deps{admin: c}, "apply", file)
		if got.code != 6 || !strings.Contains(got.stderr, want) {
			t.Errorf("exit = %d, stderr %q, want 6 and the warning", got.code, got.stderr)
		}
	})
}

func TestPrintStatus(t *testing.T) {
	r := ipc.StatusReport{
		State:         ipc.StateDegraded,
		Reasons:       []string{"resolver conflict"},
		Warnings:      []ipc.Warning{{Source: "config", Text: "a warning"}},
		Policies:      []ipc.PolicyCount{{Name: "work", Addrs: 3}},
		RetainRestart: true,
		Config:        "abc",
	}
	var b bytes.Buffer

	if err := printStatus(&b, r); err != nil {
		t.Fatal(err)
	}

	want := "state: degraded\nreason: resolver conflict\nwarning: config: a warning\n" +
		"policy work: 3 learned addresses\nretain changes after a restart of ifboundd\nconfig: abc\n"
	if b.String() != want {
		t.Errorf("printStatus = %q, want %q", b.String(), want)
	}
}

type failWriter struct{ writes int }

func (w *failWriter) Write([]byte) (int, error) {
	w.writes++
	return 0, errors.New("broken pipe")
}

func TestApplyKeepsTheStateCodeWhenStdoutFails(t *testing.T) {
	w := &failWriter{}
	r := ipc.StatusReport{State: ipc.StateUnenforced, Reasons: []string{"a", "b", "c"}}
	d := deps{admin: serveAdmin(t, &fakeDaemon{status: r}), stdout: w}
	var errOut bytes.Buffer
	d.stderr = &errOut

	code := run(t.Context(), []string{"apply", writeFile(t, validConfig)}, d)

	if code != 4 {
		t.Errorf("exit = %d, want 4", code)
	}
	if w.writes != 1 || strings.Count(errOut.String(), "broken pipe") != 1 {
		t.Errorf("writes = %d, stderr %q, want one write and the error once", w.writes, errOut.String())
	}
}

func TestUsageErrorsExit2(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"unknown verb", []string{"frobnicate"}},
		{"unknown flag", []string{"apply", "--nope"}},
		{"too many files", []string{"apply", "a.toml", "b.toml"}},
		{"version with argument", []string{"version", "x"}},
		{"unknown shell", []string{"completion", "zhs"}},
		{"shell with argument", []string{"completion", "bash", "extra"}},
		{"unknown help topic", []string{"help", "nope"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := execute(t, deps{}, tt.args...)
			if got.code != 2 {
				t.Errorf("exit = %d, want 2 (stdout %q, stderr %q)", got.code, got.stdout, got.stderr)
			}
			if got.stderr == "" || strings.Contains(got.stderr, "Usage:") {
				t.Errorf("stderr = %q, want one error line and no usage text", got.stderr)
			}
		})
	}
}

// TestCobraChecksArgumentsAndFlagsBeforeThePreRunHook pins the order of
// cobra that run relies on to tell a usage error from a runtime error.
func TestCobraChecksArgumentsAndFlagsBeforeThePreRunHook(t *testing.T) {
	for _, tt := range []struct {
		name    string
		args    []string
		wantRun bool
	}{
		{"bad flag", []string{"leaf", "--nope"}, false},
		{"bad argument count", []string{"leaf", "a", "b"}, false},
		{"valid", []string{"leaf", "a"}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var hook bool
			root := &cobra.Command{
				Use:               "root",
				SilenceUsage:      true,
				SilenceErrors:     true,
				PersistentPreRunE: func(*cobra.Command, []string) error { hook = true; return nil },
			}
			root.AddCommand(&cobra.Command{Use: "leaf", Args: cobra.MaximumNArgs(1), RunE: func(*cobra.Command, []string) error { return nil }})
			root.SetArgs(tt.args)

			err := root.Execute()

			if hook != tt.wantRun || (err == nil) != tt.wantRun {
				t.Errorf("hook ran = %v, err = %v; want hook ran = %v", hook, err, tt.wantRun)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	status := func(daemon string) *fakeDaemon { return &fakeDaemon{status: ipc.StatusReport{Daemon: daemon}} }
	tests := []struct {
		name       string
		d          func(t *testing.T) deps
		wantOut    string
		wantStderr string
	}{
		{"same version", func(t *testing.T) deps { return deps{public: serveStatus(t, status("v1")), version: "v1"} },
			"ifbound v1\nifboundd v1\n", ""},
		{"admin socket", func(t *testing.T) deps { return deps{public: serveAdmin(t, status("v1")), version: "v1"} },
			"ifbound v1\nifboundd v1\n", ""},
		{"differing version", func(t *testing.T) deps { return deps{public: serveStatus(t, status("v2")), version: "v1"} },
			"ifbound v1\nifboundd v2\nwarning: ifbound v1 and ifboundd v2 differ\n", ""},
		{"daemon without a version", func(t *testing.T) deps { return deps{public: serveStatus(t, status("")), version: "v1"} },
			"ifbound v1\nifboundd: version unknown\n", ""},
		{"daemon down", func(t *testing.T) deps {
			return deps{public: ipc.NewControlClient(socketPath(t), uid()), version: "v1"}
		}, "ifbound v1\nifboundd: not reachable", ""},
		{"daemon of another protocol", func(t *testing.T) deps {
			return deps{public: rawServer(t, otherVersionReply), version: "v1"}
		}, "ifbound v1\nifboundd: speaks another protocol", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := execute(t, tt.d(t), "version")
			if got.code != 0 || !strings.HasPrefix(got.stdout, tt.wantOut) || got.stderr != tt.wantStderr {
				t.Errorf("got %+v, want exit 0 and stdout starting %q", got, tt.wantOut)
			}
			if strings.Contains(tt.name, "another protocol") && !strings.Contains(got.stdout, "ifbound and ifboundd differ") {
				t.Errorf("stdout = %q, want the mismatch warning", got.stdout)
			}
			if strings.Contains(tt.name, "down") && strings.Contains(got.stdout, "differ") {
				t.Errorf("stdout = %q, want no mismatch warning", got.stdout)
			}
		})
	}
}

func TestVersionFlag(t *testing.T) {
	got := execute(t, deps{version: "v9"}, "--version")

	if got.code != 0 || got.stdout != "ifbound v9\n" {
		t.Errorf("got %+v, want exit 0 and \"ifbound v9\"", got)
	}
}

func TestCompletionScripts(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			got := execute(t, deps{}, "completion", shell)
			if got.code != 0 || got.stdout == "" {
				t.Errorf("exit = %d, %d bytes of script, want 0 and a script (stderr %q)", got.code, len(got.stdout), got.stderr)
			}
		})
	}
}

func TestFileCompletion(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"apply offers toml files", []string{"__complete", "apply", ""}, "toml\n:8\n"},
		{"apply offers nothing after one file", []string{"__complete", "apply", "a.toml", ""}, ":4\n"},
		{"version offers no files", []string{"__complete", "version", ""}, ":4\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := execute(t, deps{}, tt.args...)
			if got.code != 0 || !strings.HasPrefix(got.stdout, tt.want) {
				t.Errorf("exit = %d, stdout %q, want it to start with %q", got.code, got.stdout, tt.want)
			}
		})
	}
}

func TestHelpGolden(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("testdata", "help.golden"))
	if err != nil {
		t.Fatal(err)
	}

	got := execute(t, deps{version: "v1", inputConfig: "/etc/ifbound/config.toml"}, "--help")

	if got.code != 0 || got.stdout != string(want) {
		t.Errorf("--help changed (exit %d). Update testdata/help.golden when the change is meant.\ngot:\n%s", got.code, got.stdout)
	}
}

func TestUnapplied(t *testing.T) {
	sum := sha256.Sum256([]byte(validConfig))
	digest := hex.EncodeToString(sum[:])
	file := writeFile(t, validConfig)
	tests := []struct {
		name, path, applied string
		want                bool
	}{
		{"same bytes", file, digest, false},
		{"changed file", file, strings.Repeat("0", 64), true},
		{"nothing applied", file, "", true},
		{"no input file", filepath.Join(t.TempDir(), "none.toml"), digest, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unapplied(tt.path, tt.applied)
			if err != nil || got != tt.want {
				t.Errorf("unapplied = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
}
