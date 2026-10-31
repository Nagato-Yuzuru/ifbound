//go:build e2e && darwin

package e2e

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/enforcementlock"
	"github.com/Nagato-Yuzuru/ifbound/internal/layout"
	"github.com/Nagato-Yuzuru/ifbound/internal/macresolver"
	"github.com/Nagato-Yuzuru/ifbound/internal/pfbackend"
	"github.com/Nagato-Yuzuru/ifbound/internal/pfrules"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
	"github.com/Nagato-Yuzuru/ifbound/internal/teardown"
)

// These tests install the enforcement of one policy into pf and
// /etc/resolver, then tear it down with the real platform parts and the
// writer lock of the host.

var errStop = errors.New("injected stop")

// stopRunner fails each pfctl call that stop accepts and runs the others.
type stopRunner struct {
	pfbackend.Runner
	stop func(args []string) bool
}

func (r stopRunner) Run(ctx context.Context, stdin []byte, args ...string) (pfbackend.Output, error) {
	if r.stop(args) {
		return pfbackend.Output{Stderr: []byte("injected stop\n")}, errStop
	}
	return r.Runner.Run(ctx, stdin, args...)
}

// stopResolver fails each Remove.
type stopResolver struct{ reconcile.SysResolver }

func (stopResolver) Remove(context.Context, policy.Domain) error { return errStop }

// newTeardown returns a teardown on a new Backend, as a new process of
// uninstall has.
func newTeardown(run pfbackend.Runner, res reconcile.SysResolver) teardown.Teardown {
	return teardown.Teardown{
		Lock:     layout.EnforcementLock,
		Backend:  pfbackend.New(run, time.Now, slog.New(slog.DiscardHandler)),
		Resolver: res,
	}
}

func hostResolver() *macresolver.Resolver {
	return macresolver.New(macresolver.Dir, macresolver.Scutil{})
}

// enforce installs a table with entries, the ruleset, and a resolver
// entry, as ifboundd does. A cleanup tears the host down again.
func enforce(t *testing.T) {
	t.Helper()
	requireE2E(t)
	requireResolverE2E(t)
	t.Cleanup(func() {
		// t.Context is already canceled when cleanups run.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := newTeardown(pfbackend.Exec{Path: pfbackend.Path}, hostResolver()).Run(ctx); err != nil {
			t.Errorf("cleanup teardown: %v", err)
		}
	})
	apex, err := policy.ParseDomain("ifbound-e2e-" + nonce(t) + ".test")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.ParseBytes([]byte("[dns]\nupstream = [\"tls://1.1.1.1@a.example\"]\n" +
		"[[policy]]\nname = \"e2e-td\"\nto = [\"192.0.2.0/24\", \"*." + apex.String() + "\"]\nonly_via = []\n"))
	if err != nil {
		t.Fatal(err)
	}
	b := pfbackend.New(pfbackend.Exec{Path: pfbackend.Path}, time.Now, slog.New(slog.DiscardHandler))
	rec := reconcile.Reconciler{
		Compiler:  pfrules.Compiler{},
		Backend:   b,
		Resolver:  hostResolver(),
		Inventory: reconciletest.NewInventory(),
	}
	in := reconcile.Inputs{
		Policies: cfg.Policies,
		Book:     noAddrs{},
		Apexes:   []policy.Domain{apex},
		Listen:   netip.MustParseAddrPort("127.0.0.1:10053"),
	}
	if _, err := rec.Converge(t.Context(), in); err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if got := pfctlStdout(t, "-a", pfbackend.Anchor, "-sT"); !strings.Contains(got, "e2e-td") {
		t.Fatalf("tables after Converge = %q, want e2e-td", got)
	}
	if len(markerFiles(t)) == 0 {
		t.Fatal("no marker file in /etc/resolver after Converge")
	}
}

// pfctlStdout runs pfctl and returns its stdout only: pfctl writes notes
// such as "No ALTQ support in kernel" to stderr.
func pfctlStdout(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), pfbackend.Path, args...).Output()
	if err != nil {
		t.Fatalf("pfctl %s: %v", strings.Join(args, " "), err)
	}
	return string(out)
}

// markerFiles returns the files in /etc/resolver that start with the
// marker line of ifbound.
func markerFiles(t *testing.T) []string {
	t.Helper()
	des, err := os.ReadDir(macresolver.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, de := range des {
		if !de.Type().IsRegular() {
			continue
		}
		path := filepath.Join(macresolver.Dir, de.Name())
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		s := bufio.NewScanner(f)
		if s.Scan() && s.Text() == macresolver.Marker {
			out = append(out, path)
		}
		_ = f.Close() //nolint:errcheck // a read-only file; the scan result is the one to check
	}
	return out
}

// requireTornDown checks the state after uninstall: no rule and no table
// in the anchor, the references of before only, and no marker file.
func requireTornDown(t *testing.T, refs []string) {
	t.Helper()
	if got := strings.TrimSpace(pfctlStdout(t, "-a", pfbackend.Anchor, "-sr")); got != "" {
		t.Errorf("anchor rules after the teardown:\n%s", got)
	}
	if got := strings.TrimSpace(pfctlStdout(t, "-a", pfbackend.Anchor, "-sT")); got != "" {
		t.Errorf("anchor tables after the teardown:\n%s", got)
	}
	if got := references(t); !slices.Equal(got, refs) {
		t.Errorf("pf references after the teardown = %v, want %v", got, refs)
	}
	if got := markerFiles(t); len(got) != 0 {
		t.Errorf("marker files after the teardown: %v", got)
	}
}

func TestTeardownRemovesTheEnforcement(t *testing.T) {
	refs := references(t)
	enforce(t)
	if err := newTeardown(pfbackend.Exec{Path: pfbackend.Path}, hostResolver()).Run(t.Context()); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	requireTornDown(t, refs)
}

// A stop at each step, then a second teardown in a new process, finishes
// the teardown. Between the two, another tool takes a pf reference, and
// pf can give it the value that ifbound released. That reference stays.
func TestTeardownFinishesAfterAStop(t *testing.T) {
	has := func(words ...string) func([]string) bool {
		return func(args []string) bool {
			return !slices.ContainsFunc(words, func(w string) bool { return !slices.Contains(args, w) })
		}
	}
	never := func([]string) bool { return false }
	stops := []struct {
		name     string
		pf       func([]string) bool
		resolver bool
	}{
		{name: "at the read of the references", pf: has("-s", "References")},
		{name: "at the token release", pf: has("-X")},
		{name: "after the token release", pf: has(pfbackend.Anchor, "-F", "rules")},
		{name: "after the rules flush", pf: has(pfbackend.Anchor, "-F", "Tables")},
		{name: "at the resolver removal", pf: never, resolver: true},
	}
	for _, s := range stops {
		t.Run(s.name, func(t *testing.T) {
			refs := references(t)
			enforce(t)
			mine := slices.DeleteFunc(references(t), func(tok string) bool { return slices.Contains(refs, tok) })
			var res reconcile.SysResolver = hostResolver()
			if s.resolver {
				res = stopResolver{res}
			}
			first := newTeardown(stopRunner{Runner: pfbackend.Exec{Path: pfbackend.Path}, stop: s.pf}, res)
			// The Backend keeps the cause of a pfctl failure in the text only.
			if err := first.Run(t.Context()); err == nil || !strings.Contains(err.Error(), errStop.Error()) {
				t.Fatalf("teardown with a stop = %v, want the injected stop", err)
			}
			other := otherReference(t)
			if slices.Contains(mine, other) {
				t.Logf("pf gave the other tool the value %s, which ifbound held", other)
			}
			refs = append(refs, other)
			slices.Sort(refs)
			if err := newTeardown(pfbackend.Exec{Path: pfbackend.Path}, hostResolver()).Run(t.Context()); err != nil {
				t.Fatalf("second teardown: %v", err)
			}
			requireTornDown(t, refs)
		})
	}
}

// otherReference takes a pf reference as another tool does, and gives it
// back in a cleanup.
func otherReference(t *testing.T) string {
	t.Helper()
	out := pfctl(t, "-E")
	_, tok, ok := strings.Cut(out, "Token : ")
	tok = strings.TrimSpace(tok)
	if !ok || tok == "" {
		t.Fatalf("no token in the output of pfctl -E:\n%s", out)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, pfbackend.Path, "-X", tok).CombinedOutput(); err != nil {
			t.Errorf("pfctl -X %s: %v: %s", tok, err, out)
		}
	})
	return tok
}

// The teardown loads no ruleset, so it does not enable a pf that the user
// disabled.
func TestTeardownKeepsADisabledPfDisabled(t *testing.T) {
	enforce(t)
	pfctl(t, "-d") // the user disables pf; this drops every token
	if err := newTeardown(pfbackend.Exec{Path: pfbackend.Path}, hostResolver()).Run(t.Context()); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if got := pfctlStdout(t, "-s", "info"); !strings.Contains(got, "Status: Disabled") {
		t.Errorf("pf after the teardown of a disabled pf:\n%s", got)
	}
	requireTornDown(t, nil)
}

// lockHolderEnv makes the test binary a holder of the writer lock: it
// takes the lock, prints a line, and holds the lock until its stdin
// closes.
const lockHolderEnv = "IFBOUND_E2E_LOCK_HOLDER"

func TestHelperLockHolder(t *testing.T) {
	if os.Getenv(lockHolderEnv) == "" {
		t.Skip("runs only as the lock holder of TestTeardownWhileTheLockIsHeld")
	}
	l, err := enforcementlock.Acquire(layout.EnforcementLock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close() //nolint:errcheck // the process exits next, which releases the lock
	if _, err := os.Stdout.WriteString("held\n"); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, os.Stdin) //nolint:errcheck // any end of stdin ends the hold
}

// A teardown while another process holds the writer lock fails and
// changes nothing.
func TestTeardownWhileTheLockIsHeld(t *testing.T) {
	enforce(t)
	rules := pfctlStdout(t, "-a", pfbackend.Anchor, "-sr")
	tables := pfctlStdout(t, "-a", pfbackend.Anchor, "-sT")
	refs := references(t)
	markers := markerFiles(t)

	holder := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHelperLockHolder$")
	holder.Env = append(os.Environ(), lockHolderEnv+"=1")
	stdin, err := holder.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close() //nolint:errcheck // the holder exits at the end of stdin
		_ = holder.Wait() //nolint:errcheck // the holder only holds the lock
	})
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "held\n" {
		t.Fatalf("lock holder said %q, %v; want held", line, err)
	}

	err = newTeardown(pfbackend.Exec{Path: pfbackend.Path}, hostResolver()).Run(t.Context())
	if !errors.Is(err, enforcementlock.ErrHeld) {
		t.Fatalf("teardown while another process holds the lock = %v, want ErrHeld", err)
	}
	if pfctlStdout(t, "-a", pfbackend.Anchor, "-sr") != rules || pfctlStdout(t, "-a", pfbackend.Anchor, "-sT") != tables {
		t.Errorf("the anchor changed during a teardown that did not get the lock")
	}
	if got := references(t); !slices.Equal(got, refs) {
		t.Errorf("pf references = %v, want %v", got, refs)
	}
	if got := markerFiles(t); !slices.Equal(got, markers) {
		t.Errorf("marker files = %v, want %v", got, markers)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
}
