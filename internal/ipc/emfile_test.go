package ipc

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestHelperEMFILEServer runs a real server, then uses up its file
// descriptors on command. It runs only in a child process. The parent
// drives it through stdin and reads its markers on stdout.
func TestHelperEMFILEServer(t *testing.T) {
	path := os.Getenv("IPC_HELPER_EMFILE")
	if path == "" {
		t.Skip("child process only")
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv, err := Listen(ServerConfig{Path: path, Handler: handlerFunc(ack), AllowedUIDs: []uint32{self()}, Logger: logger})
	if err != nil {
		fmt.Println("CHILD-ERR", err)
		return
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(context.Background()) }()

	release, err := exhaustDescriptors()
	if err != nil {
		fmt.Println("CHILD-ERR", err)
		return
	}
	fmt.Println("READY")
	in := bufio.NewScanner(os.Stdin)
	in.Scan() // RELEASE
	select {
	case err := <-served:
		fmt.Println("SERVE-RETURNED-EARLY", err)
		return
	default:
	}
	release()
	fmt.Println("RELEASED")
	in.Scan()       // QUIT
	_ = srv.Close() //nolint:errcheck // the child exits next; the parent checks the Serve result below
	fmt.Println("SERVE-END", <-served)
}

// exhaustDescriptors lowers the soft limit and opens files until EMFILE. The
// returned function undoes both.
func exhaustDescriptors() (func(), error) {
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &old); err != nil {
		return nil, fmt.Errorf("getrlimit: %w", err)
	}
	lim := old
	lim.Cur = 64
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return nil, fmt.Errorf("setrlimit: %w", err)
	}
	var fill []*os.File
	for {
		f, err := os.Open(os.DevNull)
		if err != nil {
			if !errors.Is(err, syscall.EMFILE) {
				return nil, fmt.Errorf("open: %w", err)
			}
			break
		}
		fill = append(fill, f)
	}
	return func() {
		for _, f := range fill {
			_ = f.Close() //nolint:errcheck // frees a filler descriptor; nothing reads it
		}
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &old) //nolint:errcheck // lowering was allowed, so the restore cannot be refused; the child exits next
	}, nil
}

// markers reads the child's stdout lines.
type markers struct {
	lines chan string
	seen  strings.Builder
}

func (m *markers) waitFor(t *testing.T, marker string) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case l, ok := <-m.lines:
			if !ok {
				t.Fatalf("child exited before %s\n%s", marker, m.seen.String())
			}
			m.seen.WriteString(l + "\n")
			if strings.HasPrefix(l, marker) {
				return
			}
		case <-deadline:
			t.Fatalf("no %s from child\n%s", marker, m.seen.String())
		}
	}
}

// TestAcceptSurvivesRealEMFILE puts a real server under descriptor
// exhaustion. Serve must keep running, back off 5 ms doubling up to 1 s, and
// serve again when the pressure ends.
func TestAcceptSurvivesRealEMFILE(t *testing.T) {
	path := shortPath(t)
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHelperEMFILEServer$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), "IPC_HELPER_EMFILE="+path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	m := &markers{lines: make(chan string, 100)}
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			m.lines <- sc.Text()
		}
		close(m.lines)
	}()
	m.waitFor(t, "READY")

	c := NewClient(path, self())
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	if _, err := c.Report(ctx, Observation{QName: "a.test."}); err == nil {
		t.Fatal("Report acked while the server had no free descriptor: the pressure is not real")
	}
	cancel()
	keepConnecting(t, path, 2500*time.Millisecond) // lets the backoff reach its cap

	if _, err := io.WriteString(stdin, "RELEASE\n"); err != nil {
		t.Fatalf("writing RELEASE: %v", err)
	}
	m.waitFor(t, "RELEASED")
	if _, err := c.Report(t.Context(), Observation{QName: "a.test."}); err != nil {
		t.Errorf("Report after the pressure ended: %v", err)
	}
	if _, err := io.WriteString(stdin, "QUIT\n"); err != nil {
		t.Fatalf("writing QUIT: %v", err)
	}
	m.waitFor(t, "SERVE-END <nil>")
	if err := cmd.Wait(); err != nil {
		t.Errorf("helper exit: %v", err)
	}

	checkBackoff(t, stderr.String())
}

// keepConnecting dials for d. On darwin a queued connection is dropped when
// accept fails, so connections must keep arriving to wake the listener.
func keepConnecting(t *testing.T, path string, d time.Duration) {
	t.Helper()
	var pending []net.Conn
	defer func() {
		for _, c := range pending {
			_ = c.Close() //nolint:errcheck // the server may have dropped it already
		}
	}()
	dialer := net.Dialer{Timeout: 100 * time.Millisecond}
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(20 * time.Millisecond) { // pacing, not synchronization
		if c, err := dialer.DialContext(t.Context(), "unix", path); err == nil {
			pending = append(pending, c)
		}
	}
}

var delayRE = regexp.MustCompile(`accept failed; retrying.*delay=(\S+)`)

// checkBackoff checks the logged delays: 5 ms first, doubling, 1 s cap.
func checkBackoff(t *testing.T, log string) {
	t.Helper()
	var delays []time.Duration
	for _, m := range delayRE.FindAllStringSubmatch(log, -1) {
		d, err := time.ParseDuration(m[1])
		if err != nil {
			t.Fatal(err)
		}
		delays = append(delays, d)
	}
	if len(delays) == 0 {
		t.Fatalf("no accept failure was logged:\n%s", log)
	}
	want := acceptBackoffMin
	for i, d := range delays {
		if d != want {
			t.Fatalf("delay[%d] = %v, want %v (all: %v)", i, d, want, delays)
		}
		want = min(want*2, acceptBackoffMax)
	}
	if delays[len(delays)-1] != acceptBackoffMax {
		t.Errorf("backoff never reached the cap: %v", delays)
	}
}
