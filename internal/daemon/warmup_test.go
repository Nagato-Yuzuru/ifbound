package daemon_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
	"github.com/Nagato-Yuzuru/ifbound/internal/syslookup"
)

// warmCall is one lookup that the daemon sent to the system resolver.
type warmCall struct {
	name string
	// routed tells whether an applied resolver entry sent the lookup to
	// ifbound-dns.
	routed bool
}

// warmNet is the system resolver and ifbound-dns of the warm-up tests. A
// probe name that an applied entry routes to ifbound-dns is reported to
// the daemon. Another name runs hook, when set. Otherwise it gets the
// addresses of answers, and, when routed, ifbound-dns reports them to the
// daemon first.
type warmNet struct {
	world   *reconciletest.World
	listen  netip.AddrPort
	d       *daemon.Daemon
	answers map[string][]netip.Addr
	hook    func(ctx context.Context, name string) ([]netip.Addr, error)

	mu       sync.Mutex
	calls    []warmCall
	inFlight int
	most     int
	reports  map[string]error
}

func newWarmNet(world *reconciletest.World, listen netip.AddrPort) *warmNet {
	return &warmNet{world: world, listen: listen, answers: map[string][]netip.Addr{}, reports: map[string]error{}}
}

func (n *warmNet) Resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	routed := routes(n.world.AppliedResolverEntries(), name, n.listen)
	probe := ipc.IsProbe(name)
	n.mu.Lock()
	n.calls = append(n.calls, warmCall{name: name, routed: routed})
	if !probe {
		n.inFlight++
		n.most = max(n.most, n.inFlight)
	}
	hook := n.hook
	n.mu.Unlock()
	if probe {
		if routed {
			n.d.ProbeSeen(name)
		}
		return nil, fmt.Errorf("resolve %s: %w", name, syslookup.ErrNotFound)
	}
	defer func() {
		n.mu.Lock()
		n.inFlight--
		n.mu.Unlock()
	}()
	if hook != nil {
		return hook(ctx, name)
	}
	addrs := n.answers[name]
	if routed && len(addrs) > 0 {
		o := ipc.Observation{QName: name, Addrs: addrs, TTL: time.Minute}
		_, err := n.d.Observe(ctx, o)
		n.mu.Lock()
		n.reports[name] = err
		n.mu.Unlock()
	}
	return addrs, nil
}

// counts returns how often the daemon resolved each name that is not a
// probe name.
func (n *warmNet) counts() map[string]int {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := map[string]int{}
	for _, c := range n.calls {
		if !ipc.IsProbe(c.name) {
			out[c.name]++
		}
	}
	return out
}

// unrouted returns the names that are not probe names and that the
// daemon resolved while no applied entry sent them to ifbound-dns.
func (n *warmNet) unrouted() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	for _, c := range n.calls {
		if !ipc.IsProbe(c.name) && !c.routed {
			out = append(out, c.name)
		}
	}
	return out
}

func (n *warmNet) load() (inFlight, most int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.inFlight, n.most
}

// logRecords keeps every log record.
type logRecords struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (l *logRecords) Enabled(context.Context, slog.Level) bool { return true }

func (l *logRecords) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recs = append(l.recs, r.Clone())
	return nil
}

func (l *logRecords) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logRecords) WithGroup(string) slog.Handler      { return l }

// warnings returns, for each of names, the number of records at level
// Warn or higher whose message or attributes contain the name.
func (l *logRecords) warnings(names ...string) map[string]int {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]int{}
	for _, r := range l.recs {
		if r.Level < slog.LevelWarn {
			continue
		}
		text := r.Message
		r.Attrs(func(a slog.Attr) bool {
			text += " " + a.Value.String()
			return true
		})
		for _, n := range names {
			if strings.Contains(text, n) {
				out[n]++
			}
		}
	}
	return out
}

type warmHarness struct {
	t        *testing.T
	world    *reconciletest.World
	inv      *reconciletest.Inventory
	net      *warmNet
	log      *logRecords
	d        *daemon.Daemon
	snapshot string
	stop     func()
}

// startWarm runs a daemon with the system resolver net, and waits until
// every goroutine blocks.
func startWarm(t *testing.T, world *reconciletest.World, snapshot, cfgText string, net *warmNet) *warmHarness {
	t.Helper()
	log := &logRecords{}
	inv := reconciletest.NewInventory(en0)
	d := daemon.New(daemon.Config{
		ConfigPath: storeConfig(t, t.TempDir(), cfgText),
		ConfigGID:  -1,
		Snapshot:   snapshot,
		// No host file: the tests here do not depend on the host file of the machine.
		HostsFile: filepath.Join(filepath.Dir(snapshot), "hosts"),
		Platform: reconcile.Reconciler{
			Compiler:  reconciletest.Compiler{},
			Backend:   world.Backend(),
			Resolver:  world.Resolver(),
			Inventory: inv,
		},
		Lookup: net,
		Logger: slog.New(log),
	})
	net.d = d
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	synctest.Wait()
	stop := func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	}
	return &warmHarness{t: t, world: world, inv: inv, net: net, log: log, d: d, snapshot: snapshot, stop: stop}
}

// state returns the state of the daemon. The call must not wait: the
// loop serves it at once, or the daemon is stuck.
func (h *warmHarness) state() daemon.State {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(h.t.Context(), time.Second)
	defer cancel()
	st, err := h.d.Status(ctx)
	if err != nil {
		h.t.Fatalf("Status: %v", err)
	}
	return st.State
}

func (h *warmHarness) wantState(want daemon.State) {
	h.t.Helper()
	if got := h.state(); got != want {
		h.t.Fatalf("state = %v, want %v", got, want)
	}
}

func (h *warmHarness) wantCounts(want map[string]int) {
	h.t.Helper()
	if got := h.net.counts(); !maps.Equal(got, want) {
		h.t.Errorf("warm-up lookups = %v, want %v", got, want)
	}
}

// reconfigureTo applies one configuration for each prefix in turn, with
// the names seqNames(prefix, 10).
func (h *warmHarness) reconfigureTo(prefixes ...string) {
	h.t.Helper()
	for _, p := range prefixes {
		if err := h.d.Reconfigure(h.t.Context(), warmConfig(h.t, seqNames(p, 10)...)); err != nil {
			h.t.Fatal(err)
		}
		synctest.Wait()
	}
}

// warmConfig is one policy "web" with the destinations to.
func warmConfig(t *testing.T, to ...string) policy.Config {
	t.Helper()
	return parse(t, warmText(to...))
}

// warmText is the text of warmConfig.
func warmText(to ...string) string {
	return header + fmt.Sprintf(`
[[policy]]
name = "web"
to = ["%s"]
only_via = ["en0"]
`, strings.Join(to, `", "`))
}

// seqNames returns n names: prefix0.example, prefix1.example, and so on.
func seqNames(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%d.example", prefix, i)
	}
	return out
}

func once(names ...string) map[string]int {
	out := make(map[string]int, len(names))
	for _, n := range names {
		out[n] = 1
	}
	return out
}

func snapshotPath(t *testing.T) string { return t.TempDir() + "/addrbook.json" }

// holdLookups holds lookups until release closes. With honorCtx, a held
// lookup also ends with its ctx.
type holdLookups struct {
	release  chan struct{}
	honorCtx bool
}

func newHold(honorCtx bool) *holdLookups {
	return &holdLookups{release: make(chan struct{}), honorCtx: honorCtx}
}

func (g *holdLookups) hook(ctx context.Context, _ string) ([]netip.Addr, error) {
	var done <-chan struct{}
	if g.honorCtx {
		done = ctx.Done()
	}
	select {
	case <-g.release:
		return nil, nil
	case <-done:
		return nil, ctx.Err()
	}
}

// getaddrinfo models the system call behind syslookup.Resolver: Resolve
// returns when its ctx ends, and the call goes on until release closes.
type getaddrinfo struct {
	release chan struct{}

	mu      sync.Mutex
	running int
	most    int
}

func (g *getaddrinfo) hook(ctx context.Context, _ string) ([]netip.Addr, error) {
	done := make(chan struct{})
	g.mu.Lock()
	g.running++
	g.most = max(g.most, g.running)
	g.mu.Unlock()
	go func() {
		<-g.release
		g.mu.Lock()
		g.running--
		g.mu.Unlock()
		close(done)
	}()
	select {
	case <-done:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestWarmUpResolvesExactlyTheListedNames(t *testing.T) {
	many := seqNames("m", 3*daemon.WarmUpConcurrency+1)
	tests := []struct {
		name string
		cfg  string
		want map[string]int
	}{
		{
			name: "every kind of destination, duplicates across policies",
			cfg: header + `
[[policy]]
name = "web"
to = ["a.example", "*.b.example", "192.0.2.1", "198.51.100.0/24", "2001:db8::1", "2001:db8::/32", "c.example"]
only_via = ["en0"]

[[policy]]
name = "ads"
to = ["a.example", "*.c.example", "*.b.example", "d.example"]
deny_via = ["@tunnel"]
`,
			want: once("a.example", "b.example", "c.example", "d.example"),
		},
		{
			name: "addresses only",
			cfg: header + `
[[policy]]
name = "web"
to = ["192.0.2.1", "198.51.100.0/24", "2001:db8::/32"]
only_via = ["en0"]
`,
			want: map[string]int{},
		},
		{
			name: "one suffix",
			cfg: header + `
[[policy]]
name = "web"
to = ["*.one.example"]
only_via = ["en0"]
`,
			want: once("one.example"),
		},
		{
			name: "more names than the bound",
			cfg:  header + "\n[[policy]]\nname = \"web\"\nto = [\"" + strings.Join(many, `", "`) + "\"]\nonly_via = [\"en0\"]\n",
			want: once(many...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				world := reconciletest.NewWorld()
				cfg := parse(t, tt.cfg)
				h := startWarm(t, world, snapshotPath(t), tt.cfg, newWarmNet(world, cfg.DNS.Listen))
				defer h.stop()
				h.wantState(daemon.StateReady)
				h.wantCounts(tt.want)
			})
		})
	}
}

func TestWarmUpRunsOnlyWhileTheDaemonAcks(t *testing.T) {
	names := []string{"s1.example", "s2.example"}
	t.Run("starting", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			world := reconciletest.NewWorld()
			snapshot := snapshotPath(t)
			if err := os.WriteFile(snapshot, []byte("not json"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfgText := warmText(names...)
			cfg := parse(t, cfgText)
			h := startWarm(t, world, snapshot, cfgText, newWarmNet(world, cfg.DNS.Listen))
			defer h.stop()
			for range 3 {
				heal()
				h.wantState(daemon.StateStarting)
			}
			h.wantCounts(map[string]int{})

			if err := os.Remove(snapshot); err != nil {
				t.Fatal(err)
			}
			heal()
			h.wantState(daemon.StateReady)
			h.wantCounts(once(names...))
		})
	})
	t.Run("unenforced", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			world := reconciletest.NewWorld()
			world.SetProblems([]reconcile.Problem{pfDisabled}, nil)
			cfgText := warmText(names...)
			cfg := parse(t, cfgText)
			h := startWarm(t, world, snapshotPath(t), cfgText, newWarmNet(world, cfg.DNS.Listen))
			defer h.stop()
			for range 3 {
				heal()
				h.wantState(daemon.StateUnenforced)
			}
			h.wantCounts(map[string]int{})

			world.SetProblems(nil, nil)
			heal()
			h.wantState(daemon.StateReady)
			h.wantCounts(once(names...))
		})
	})
	t.Run("configuration change while unenforced", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			world := reconciletest.NewWorld()
			cfgText := warmText("old.example")
			cfg := parse(t, cfgText)
			h := startWarm(t, world, snapshotPath(t), cfgText, newWarmNet(world, cfg.DNS.Listen))
			defer h.stop()
			h.wantState(daemon.StateReady)
			h.wantCounts(once("old.example"))

			world.SetProblems([]reconcile.Problem{pfDisabled}, nil)
			if err := h.d.Reconfigure(t.Context(), warmConfig(t, "new.example")); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			h.wantState(daemon.StateUnenforced)
			heal()
			h.wantCounts(once("old.example"))

			world.SetProblems(nil, nil)
			heal()
			h.wantState(daemon.StateReady)
			h.wantCounts(once("old.example", "new.example"))
		})
	})
	t.Run("degraded", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			world := reconciletest.NewWorld()
			world.SetProblems(nil, []reconcile.Problem{conflict})
			cfgText := warmText(names...)
			cfg := parse(t, cfgText)
			h := startWarm(t, world, snapshotPath(t), cfgText, newWarmNet(world, cfg.DNS.Listen))
			defer h.stop()
			h.wantState(daemon.StateDegraded)
			h.wantCounts(once(names...))
		})
	})
}

func TestWarmUpStopsWhenEnforcementEndsAndStartsAgain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		names := seqNames("n", 6)
		world := reconciletest.NewWorld()
		cfgText := warmText(names...)
		cfg := parse(t, cfgText)
		net := newWarmNet(world, cfg.DNS.Listen)
		hold := newHold(true)
		net.hook = hold.hook
		h := startWarm(t, world, snapshotPath(t), cfgText, net)
		defer h.stop()
		h.wantState(daemon.StateReady)

		// An interface change converges before the held lookups reach
		// WarmUpTimeout.
		world.SetProblems([]reconcile.Problem{pfDisabled}, nil)
		h.inv.Set(en0, utun0)
		time.Sleep(daemon.InterfaceDebounce)
		synctest.Wait()
		h.wantState(daemon.StateUnenforced)
		h.wantCounts(once(names[:daemon.WarmUpConcurrency]...))

		close(hold.release)
		world.SetProblems(nil, nil)
		heal()
		h.wantState(daemon.StateReady)
		want := once(names...)
		for _, n := range names[:daemon.WarmUpConcurrency] {
			want[n] = 2 // the warm-up starts again from its first name
		}
		h.wantCounts(want)
	})
}

func TestWarmUpRestartsAfterConfigChange(t *testing.T) {
	t.Run("after a finished warm-up", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			world := reconciletest.NewWorld()
			cfgText := warmText("keep.example", "gone.example")
			cfg := parse(t, cfgText)
			h := startWarm(t, world, snapshotPath(t), cfgText, newWarmNet(world, cfg.DNS.Listen))
			defer h.stop()
			h.wantState(daemon.StateReady)
			h.wantCounts(once("keep.example", "gone.example"))

			if err := h.d.Reconfigure(t.Context(), warmConfig(t, "keep.example", "new.example")); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			h.wantCounts(map[string]int{"keep.example": 2, "gone.example": 1, "new.example": 1})
		})
	})
	t.Run("during a warm-up", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			before := seqNames("n", 2*daemon.WarmUpConcurrency)
			world := reconciletest.NewWorld()
			cfgText := warmText(before...)
			cfg := parse(t, cfgText)
			net := newWarmNet(world, cfg.DNS.Listen)
			hold := newHold(true)
			net.hook = hold.hook
			h := startWarm(t, world, snapshotPath(t), cfgText, net)
			defer h.stop()
			h.wantState(daemon.StateReady)
			h.wantCounts(once(before[:daemon.WarmUpConcurrency]...))

			if err := h.d.Reconfigure(t.Context(), warmConfig(t, before[0], "m1.example")); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			close(hold.release)
			synctest.Wait()

			want := once(before[:daemon.WarmUpConcurrency]...)
			want[before[0]] = 2
			want["m1.example"] = 1
			h.wantCounts(want)
		})
	})
}

// A lookup goes to ifbound-dns only after the system applies the resolver
// entry of its name. The warm-up waits for a probe that proves this, and
// it tries again when the entry applies later than the probe budget.
func TestWarmUpWaitsUntilTheResolverEntriesApply(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		world := reconciletest.NewWorld()
		world.SetResolverDelay(true)
		names := []string{"n1.example", "n2.example", "new.other"}
		cfgText := warmText(names[:2]...)
		cfg := parse(t, cfgText)
		net := newWarmNet(world, cfg.DNS.Listen)
		for i, n := range names {
			net.answers[n] = []netip.Addr{netip.AddrFrom4([4]byte{203, 0, 113, byte(20 + i)})}
		}
		h := startWarm(t, world, snapshotPath(t), cfgText, net)
		defer h.stop()
		// No probe can pass before the entries apply.
		h.wantState(daemon.StateDegraded)

		// The entries apply only after more than one probe budget.
		for range 3 {
			heal()
		}
		h.wantCounts(map[string]int{})
		world.SettleResolver()
		heal()
		heal()
		h.wantCounts(once(names[:2]...))
		h.wantState(daemon.StateReady)

		if err := h.d.Reconfigure(t.Context(), warmConfig(t, names...)); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		h.wantCounts(map[string]int{"n1.example": 2, "n2.example": 2})
		world.SettleResolver()
		heal()
		h.wantCounts(map[string]int{"n1.example": 2, "n2.example": 2, "new.other": 1})

		if got := net.unrouted(); len(got) > 0 {
			t.Errorf("lookups of %v did not go to ifbound-dns", got)
		}
		for i, n := range names {
			a := netip.AddrFrom4([4]byte{203, 0, 113, byte(20 + i)})
			if !slices.Contains(world.Tables()["web"], host(a.String())) {
				t.Errorf("%s: address %v not learned", n, a)
			}
		}
		// One warning for each name whose probe failed, not one for each
		// try.
		got := h.log.warnings(names...)
		if want := once(names[:2]...); !maps.Equal(got, want) {
			t.Errorf("warnings = %v, want %v", got, want)
		}
	})
}

func TestWarmUpConcurrencyBound(t *testing.T) {
	t.Run("one warm-up", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			names := seqNames("c", 3*daemon.WarmUpConcurrency)
			world := reconciletest.NewWorld()
			cfgText := warmText(names...)
			cfg := parse(t, cfgText)
			net := newWarmNet(world, cfg.DNS.Listen)
			hold := newHold(false)
			net.hook = hold.hook
			h := startWarm(t, world, snapshotPath(t), cfgText, net)
			defer h.stop()
			if n, _ := net.load(); n != daemon.WarmUpConcurrency {
				t.Errorf("%d lookups in flight, want %d", n, daemon.WarmUpConcurrency)
			}
			close(hold.release)
			synctest.Wait()
			if _, most := net.load(); most != daemon.WarmUpConcurrency {
				t.Errorf("at most %d lookups at one time, want %d", most, daemon.WarmUpConcurrency)
			}
			h.wantCounts(once(names...))
		})
	})
	t.Run("a timed-out lookup frees its slot", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			names := seqNames("t", daemon.WarmUpConcurrency+1)
			world := reconciletest.NewWorld()
			cfgText := warmText(names...)
			cfg := parse(t, cfgText)
			net := newWarmNet(world, cfg.DNS.Listen)
			hold := newHold(true) // never released: each lookup ends at its timeout
			net.hook = hold.hook
			h := startWarm(t, world, snapshotPath(t), cfgText, net)
			defer h.stop()
			h.wantCounts(once(names[:daemon.WarmUpConcurrency]...))

			time.Sleep(daemon.WarmUpTimeout - time.Millisecond)
			synctest.Wait()
			h.wantCounts(once(names[:daemon.WarmUpConcurrency]...))
			time.Sleep(time.Millisecond)
			synctest.Wait()
			h.wantCounts(once(names...))
			close(hold.release)
		})
	})
}

func TestWarmUpConcurrencyBoundAcrossConfigChanges(t *testing.T) {
	t.Run("lookups that ignore their ctx", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			world := reconciletest.NewWorld()
			cfgText := warmText(seqNames("a", 10)...)
			cfg := parse(t, cfgText)
			net := newWarmNet(world, cfg.DNS.Listen)
			hold := newHold(false) // a lookup that ignores its ctx
			net.hook = hold.hook
			h := startWarm(t, world, snapshotPath(t), cfgText, net)
			defer h.stop()
			h.reconfigureTo("b", "c", "d")
			if _, most := net.load(); most > daemon.WarmUpConcurrency {
				t.Errorf("at most %d lookups at one time, want at most %d", most, daemon.WarmUpConcurrency)
			}
			close(hold.release)
			synctest.Wait()
			if _, most := net.load(); most > daemon.WarmUpConcurrency {
				t.Errorf("at most %d lookups at one time, want at most %d", most, daemon.WarmUpConcurrency)
			}
			want := once(seqNames("d", 10)...)
			maps.Copy(want, once(seqNames("a", daemon.WarmUpConcurrency)...))
			h.wantCounts(want)
		})
	})
	// Resolve returns when its ctx ends, but the system lookup goes on
	// (see syslookup.Resolver).
	t.Run("a stopped warm-up does not end its system lookups", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			world := reconciletest.NewWorld()
			cfgText := warmText(seqNames("a", 10)...)
			cfg := parse(t, cfgText)
			net := newWarmNet(world, cfg.DNS.Listen)
			g := &getaddrinfo{release: make(chan struct{})}
			net.hook = g.hook
			h := startWarm(t, world, snapshotPath(t), cfgText, net)
			defer h.stop()
			defer close(g.release)
			h.reconfigureTo("b", "c", "d")
			g.mu.Lock()
			defer g.mu.Unlock()
			if g.most != daemon.WarmUpConcurrency {
				t.Errorf("at most %d system lookups at one time, want %d", g.most, daemon.WarmUpConcurrency)
			}
		})
	})
}

// Each call has a one-second budget; the loop must serve it with no delay
// while the slow lookup is still in flight.
func TestSlowWarmUpLookupDelaysNoReport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		world := reconciletest.NewWorld()
		cfgText := warmText("slow.example", "fast.example")
		cfg := parse(t, cfgText)
		net := newWarmNet(world, cfg.DNS.Listen)
		var (
			mu      sync.Mutex
			started bool
			ended   bool
		)
		net.hook = func(ctx context.Context, name string) ([]netip.Addr, error) {
			if name != "slow.example" {
				return nil, nil
			}
			mu.Lock()
			started = true
			mu.Unlock()
			<-ctx.Done()
			mu.Lock()
			ended = true
			mu.Unlock()
			return nil, ctx.Err()
		}
		h := startWarm(t, world, snapshotPath(t), cfgText, net)
		defer h.stop()
		inFlight := func() bool {
			mu.Lock()
			defer mu.Unlock()
			return started && !ended
		}
		if !inFlight() {
			t.Fatal("the slow lookup is not in flight at the start of the measurement")
		}

		t0 := time.Now()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if _, err := h.d.Observe(ctx, obs("fast.example", "203.0.113.7")); err != nil {
			t.Fatalf("Observe = %v, want the ack", err)
		}
		if _, err := h.d.Status(ctx); err != nil {
			t.Fatalf("Status = %v", err)
		}
		if d := time.Since(t0); d != 0 {
			t.Errorf("the calls took %v while a warm-up lookup was slow, want no delay", d)
		}
		if !inFlight() {
			t.Error("the slow lookup ended before the end of the measurement")
		}
	})
}

// The slow lookups belong to a stopped warm-up and ignore their ctx.
func TestHeldLookupsOfAStoppedWarmUpDelayNoReport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		world := reconciletest.NewWorld()
		cfgText := warmText(seqNames("h", 6)...)
		cfg := parse(t, cfgText)
		net := newWarmNet(world, cfg.DNS.Listen)
		hold := newHold(false) // a lookup that ignores its ctx
		net.hook = hold.hook
		h := startWarm(t, world, snapshotPath(t), cfgText, net)
		defer h.stop()
		defer close(hold.release)

		t0 := time.Now()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if err := h.d.Reconfigure(ctx, warmConfig(t, "new.example")); err != nil {
			t.Fatalf("Reconfigure = %v", err)
		}
		if _, err := h.d.Observe(ctx, obs("new.example", "203.0.113.8")); err != nil {
			t.Fatalf("Observe = %v, want the ack", err)
		}
		if _, err := h.d.Status(ctx); err != nil {
			t.Fatalf("Status = %v", err)
		}
		if d := time.Since(t0); d != 0 {
			t.Errorf("the calls took %v while the stopped warm-up held lookups, want no delay", d)
		}
		if n, _ := net.load(); n != daemon.WarmUpConcurrency {
			t.Errorf("%d lookups in flight at the end of the measurement, want %d held", n, daemon.WarmUpConcurrency)
		}
	})
}

// The names after a failed name are still resolved, and only the failed
// name is logged.
func TestWarmUpLogsAndSkipsAFailedName(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		names := append([]string{"bad.example"}, seqNames("ok", 2*daemon.WarmUpConcurrency)...)
		world := reconciletest.NewWorld()
		cfgText := warmText(names...)
		cfg := parse(t, cfgText)
		net := newWarmNet(world, cfg.DNS.Listen)
		// The other names wait until the failure of bad.example is
		// complete, so the names after it start only after the failure.
		hold := newHold(false)
		net.hook = func(ctx context.Context, name string) ([]netip.Addr, error) {
			if name == "bad.example" {
				return nil, fmt.Errorf("resolve %s: %w", name, syslookup.ErrUnavailable)
			}
			return hold.hook(ctx, name)
		}
		h := startWarm(t, world, snapshotPath(t), cfgText, net)
		defer h.stop()
		close(hold.release)
		synctest.Wait()
		h.wantState(daemon.StateReady)
		h.wantCounts(once(names...))

		got := h.log.warnings(names...)
		if got["bad.example"] != 1 {
			t.Errorf("warnings that name bad.example = %d, want 1", got["bad.example"])
		}
		for _, n := range names[1:] {
			if got[n] != 0 {
				t.Errorf("warnings that name %s = %d, want 0: its lookup succeeded", n, got[n])
			}
		}
	})
}

// "No such name" and the end of the lookup budget are no failure: the
// name can have no addresses, and the system lookup and its report can
// complete after the budget.
func TestWarmUpWarnsNotForANameWithoutAnswer(t *testing.T) {
	tests := []struct {
		name string
		hook func(ctx context.Context, name string) ([]netip.Addr, error)
	}{
		{"no such name", func(_ context.Context, name string) ([]netip.Addr, error) {
			return nil, fmt.Errorf("resolve %s: %w", name, syslookup.ErrNotFound)
		}},
		{"lookup budget ends", func(ctx context.Context, name string) ([]netip.Addr, error) {
			<-ctx.Done()
			return nil, fmt.Errorf("resolve %s: %w", name, ctx.Err())
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				world := reconciletest.NewWorld()
				cfgText := warmText("*.quiet.example")
				cfg := parse(t, cfgText)
				net := newWarmNet(world, cfg.DNS.Listen)
				net.hook = tt.hook
				h := startWarm(t, world, snapshotPath(t), cfgText, net)
				defer h.stop()
				time.Sleep(daemon.WarmUpTimeout)
				synctest.Wait()
				h.wantCounts(once("quiet.example"))
				if n := h.log.warnings("quiet.example")["quiet.example"]; n != 0 {
					t.Errorf("%d warnings for quiet.example, want 0", n)
				}
			})
		})
	}
}

func TestWarmUpWritesNothingAndItsReportsTakeTheNormalPath(t *testing.T) {
	addr := netip.MustParseAddr("203.0.113.10")
	t.Run("no report, no write", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			world := reconciletest.NewWorld()
			cfgText := warmText(seqNames("w", 6)...)
			cfg := parse(t, cfgText)
			net := newWarmNet(world, cfg.DNS.Listen)
			hold := newHold(false)
			net.hook = hold.hook
			h := startWarm(t, world, snapshotPath(t), cfgText, net)
			defer h.stop()
			h.wantState(daemon.StateReady)
			writes := world.Writes()
			snap := readOrEmpty(t, h.snapshot)
			close(hold.release)
			synctest.Wait()
			h.wantCounts(once(seqNames("w", 6)...))
			if got := world.Writes(); got != writes {
				t.Errorf("platform writes = %d after the warm-up, want %d", got, writes)
			}
			if after := readOrEmpty(t, h.snapshot); after != snap {
				t.Error("the snapshot changed during a warm-up without reports")
			}
		})
	})
	t.Run("a routed lookup is reported and learned", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			world := reconciletest.NewWorld()
			cfgText := warmText("learn.example")
			cfg := parse(t, cfgText)
			net := newWarmNet(world, cfg.DNS.Listen)
			net.answers["learn.example"] = []netip.Addr{addr}
			h := startWarm(t, world, snapshotPath(t), cfgText, net)
			defer h.stop()
			h.wantState(daemon.StateReady)
			net.mu.Lock()
			rep, ok := net.reports["learn.example"]
			net.mu.Unlock()
			if !ok || rep != nil {
				t.Fatalf("report of learn.example: sent %v, result %v; want an acked report", ok, rep)
			}
			if !slices.Contains(world.Tables()["web"], host(addr.String())) {
				t.Errorf("table web = %v, want %v", world.Tables()["web"], addr)
			}
		})
	})
}

// readOrEmpty returns the content of the file at path, or "" when it does
// not exist.
func readOrEmpty(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return string(b)
}
