//go:build e2e && darwin

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/hostsfile"
	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/pfbackend"
	"github.com/Nagato-Yuzuru/ifbound/internal/pfrules"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
	"github.com/Nagato-Yuzuru/ifbound/internal/syslookup"
)

// noHosts is a host file that is missing.
type noHosts struct{}

func (noHosts) Version() (hostsfile.Version, error)             { return hostsfile.Version{}, nil }
func (noHosts) Read(hostsfile.Version) (hostsfile.Hosts, error) { return hostsfile.Hosts{}, nil }

// noLookup is a system resolver that finds no name.
type noLookup struct{}

func (noLookup) Resolve(_ context.Context, name string) ([]netip.Addr, error) {
	return nil, fmt.Errorf("resolve %s: %w", name, syslookup.ErrNotFound)
}

// lockedBuffer is a bytes.Buffer that is safe for concurrent use.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// waitLog polls the log until it holds want, and fails the test after
// limit. The daemon tells the end of a convergence only in its log, so
// the test polls it.
func waitLog(t *testing.T, logs *lockedBuffer, want string, limit time.Duration) {
	t.Helper()
	start := time.Now()
	for !strings.Contains(logs.String(), want) {
		if time.Since(start) > limit {
			t.Fatalf("no %q in the log after %v", want, limit)
		}
		// A real-time wait: the log gives no event to wait on.
		time.Sleep(10 * time.Millisecond)
	}
}

// waitLoadedID polls b until LoadedID gives want, and fails the test
// after limit. pf sends no event when a ruleset changes, so the test
// polls the kernel, as the watcher does.
func waitLoadedID(t *testing.T, b *pfbackend.Backend, want string, limit time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	for {
		id, err := b.LoadedID(t.Context())
		if err != nil {
			t.Fatalf("LoadedID: %v", err)
		}
		if id == want {
			return time.Since(start)
		}
		if time.Since(start) > limit {
			t.Fatalf("LoadedID = %q after %v, want %q", id, limit, want)
		}
		// A real-time wait: no event tells that pf changed. 10 ms keeps
		// the error of the measured time small.
		time.Sleep(10 * time.Millisecond)
	}
}

// TestDaemonWatcherRepairsAFlushedMainRuleset runs ifboundd on the real
// pf, and flushes the main ruleset as some VPN clients do. The watcher
// of the daemon finds the change at its next poll, and the convergence
// adds the entry rule again. The flush comes soon after the start, so
// the first self-heal, SelfHealInterval after the start, comes after
// the poll: the repair is the one of the watcher, as the log shows.
func TestDaemonWatcherRepairsAFlushedMainRuleset(t *testing.T) {
	restoreMain(t)
	b, _ := newPfBackend(t)
	h := openPf(t)
	const config = "[dns]\nupstream = [\"tls://1.1.1.1@a.example\"]\n" +
		"[[policy]]\nname = \"e2e-watch\"\nto = [\"192.0.2.15\"]\nonly_via = []\n"
	rs := compilePolicies(t, "[[policy]]\nname = \"e2e-watch\"\nto = [\"192.0.2.15\"]\nonly_via = []\n")
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs lockedBuffer
	d := daemon.New(daemon.Config{
		ConfigPath: cfgPath,
		ConfigGID:  -1,
		AddrStore:  filepath.Join(dir, "addrbook"),
		Hosts:      noHosts{},
		Platform: reconcile.Reconciler{
			Compiler:  pfrules.Compiler{},
			Guard:     reconcile.NewGuard(b),
			Resolver:  reconciletest.NewWorld().Resolver(),
			Inventory: reconciletest.NewInventory(),
		},
		Lookup: noLookup{},
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	started := time.Now()
	go func() { done <- d.Run(ctx) }()
	// Before the Unload of the Backend: the cleanups run in reverse
	// order.
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})

	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("the log of the daemon:\n%s", logs.String())
		}
	})

	// The flush must come after the end of the first convergence: a
	// change during a convergence is taken as expected (see
	// reconcile.Guard.Changed).
	waitLog(t, &logs, logattr.ConvergeTrigger+"="+logattr.TriggerStart, 10*time.Second)
	requireLoadedID(t, b, rs.ID())
	pfctl(t, "-F", "rules")
	flushed := time.Now()
	if since := flushed.Sub(started); since > daemon.SelfHealInterval-2*daemon.WatchPeriod {
		t.Fatalf("the flush came %v after the start; the first self-heal can come before the poll", since)
	}
	took := waitLoadedID(t, b, rs.ID(), 2*daemon.WatchPeriod)
	t.Logf("the entry was back %v after the flush", took)
	requireEntry(t, h)
	// The convergence logs its event after its last read of pf, so the
	// event can come after the entry.
	waitLog(t, &logs, logattr.ConvergeTrigger+"="+logattr.TriggerFirewallChanged, 2*daemon.WatchPeriod)
	if !strings.Contains(logs.String(), "firewall changed outside ifbound") {
		t.Error("the log shows no firewall change")
	}
}
