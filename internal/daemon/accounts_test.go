package daemon_test

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/daemon"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile/reconciletest"
)

// configScoped limits web to two users and two groups, and mail to bob.
const configScoped = header + `
[[policy]]
name = "web"
to = ["example.com", "192.0.2.10"]
only_via = ["en0"]
scope = { users = ["alice", "carol"], groups = ["staff", "admin"] }

[[policy]]
name = "mail"
to = ["mail.example.org"]
deny_via = ["@tunnel"]
scope = { users = ["bob"] }
`

// The owner lines of configScoped with the ids of newAccounts.
var (
	webOwners = []string{"web user alice 501", "web user carol 503", "web group admin 80", "web group staff 20"}
	mailOwner = "mail user bob 502"
)

// scopeCompiler is reconciletest.Compiler that also writes one line for
// each account of a scope: "owner <policy> <kind> <name> <id>". As the
// real Compiler, it drops the whole scope of a policy when the accounts
// do not know one of its names: the policy then gets no owner line, and
// a problem names the unknown accounts.
type scopeCompiler struct{}

func (scopeCompiler) Compile(policies []policy.Policy, ifaces []reconcile.Interface, accounts reconcile.Accounts) (reconcile.Ruleset, error) {
	rs, err := reconciletest.Compiler{}.Compile(policies, ifaces, accounts)
	if err != nil {
		return reconcile.Ruleset{}, err
	}
	body := rs.Body()
	var problems []reconcile.Problem
	for _, p := range policies {
		var lines, unknown []string
		for _, kind := range []struct {
			name  string
			names []policy.Account
			ids   map[string]uint32
		}{{"user", p.Scope.Users(), accounts.Users}, {"group", p.Scope.Groups(), accounts.Groups}} {
			for _, a := range kind.names {
				id, ok := kind.ids[a.String()]
				if !ok {
					unknown = append(unknown, kind.name+" "+a.String())
					continue
				}
				lines = append(lines, fmt.Sprintf("owner %s %s %s %d\n", p.Name, kind.name, a, id))
			}
		}
		if len(unknown) > 0 {
			problems = append(problems, reconcile.Problem{Text: fmt.Sprintf("policy %s: unknown %s", p.Name, strings.Join(unknown, ", "))})
			continue
		}
		for _, l := range lines {
			body = append(body, l...)
		}
	}
	return reconcile.NewRuleset(body, problems...), nil
}

// fakeAccounts is a daemon.AccountReader. A name in fail gets that error.
// While hang is set, each lookup waits until release closes it.
type fakeAccounts struct {
	mu     sync.Mutex
	users  map[string]uint32
	groups map[string]uint32
	fail   map[string]error // by "user <name>" or "group <name>"
	hang   chan struct{}
	delay  time.Duration // of each lookup
	// inWork and maxInWork count the lookups that run at one time.
	inWork, maxInWork int
}

func newAccounts() *fakeAccounts {
	return &fakeAccounts{
		users:  map[string]uint32{"alice": 501, "bob": 502, "carol": 503, "dave": 504},
		groups: map[string]uint32{"staff": 20, "admin": 80},
		fail:   map[string]error{},
	}
}

func (f *fakeAccounts) LookupUser(name string) (uint32, bool, error) {
	return f.lookup("user", name, func() map[string]uint32 { return f.users })
}

func (f *fakeAccounts) LookupGroup(name string) (uint32, bool, error) {
	return f.lookup("group", name, func() map[string]uint32 { return f.groups })
}

func (f *fakeAccounts) lookup(kind, name string, known func() map[string]uint32) (uint32, bool, error) {
	f.mu.Lock()
	f.inWork++
	f.maxInWork = max(f.maxInWork, f.inWork)
	hang, delay := f.hang, f.delay
	f.mu.Unlock()
	if hang != nil {
		<-hang
	}
	time.Sleep(delay)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inWork--
	if err := f.fail[kind+" "+name]; err != nil {
		return 0, false, err
	}
	id, ok := known()[name]
	return id, ok, nil
}

func (f *fakeAccounts) setUser(name string, id uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[name] = id
}

func (f *fakeAccounts) deleteUser(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.users, name)
}

// setFail makes the lookup of one name fail with err; nil ends it.
func (f *fakeAccounts) setFail(kindName string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[kindName] = err
}

// hangLookups makes each lookup from now on wait. The returned function
// lets the lookups go on.
func (f *fakeAccounts) hangLookups() (release func()) {
	ch := make(chan struct{})
	f.mu.Lock()
	f.hang = ch
	f.mu.Unlock()
	return func() {
		f.mu.Lock()
		f.hang = nil
		f.mu.Unlock()
		close(ch)
	}
}

func (f *fakeAccounts) setDelay(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delay = d
}

func (f *fakeAccounts) concurrency() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxInWork
}

func newScopedHarness(t *testing.T, cfgText string, accounts daemon.AccountReader) *harness {
	t.Helper()
	world := reconciletest.NewWorld()
	return startWith(t, world, world.Backend(), reconciletest.NewInventory(en0),
		filepath.Join(t.TempDir(), "addrbook.json"), cfgText, accounts)
}

// owners returns the owner lines of the loaded ruleset, sorted.
func (h *harness) owners() []string {
	var out []string
	for line := range strings.Lines(string(h.world.Ruleset().Body())) {
		if rest, ok := strings.CutPrefix(line, "owner "); ok {
			out = append(out, strings.TrimSuffix(rest, "\n"))
		}
	}
	slices.Sort(out)
	return out
}

func (h *harness) wantOwners(want ...string) {
	h.t.Helper()
	want = slices.Sorted(slices.Values(want))
	if got := h.owners(); !slices.Equal(got, want) {
		h.t.Errorf("owner lines = %q, want %q", got, want)
	}
}

func (h *harness) stateChanges() int {
	h.logs.mu.Lock()
	defer h.logs.mu.Unlock()
	n := 0
	for _, m := range h.logs.msgs {
		if strings.Contains(m, "state changed") {
			n++
		}
	}
	return n
}

func hasReason(st daemon.Status, part string) bool {
	return slices.ContainsFunc(st.Reasons, func(r string) bool { return strings.Contains(r, part) })
}

func with(base []string, more ...string) []string { return append(slices.Clone(base), more...) }

// The ids of every account of every scope go to the Compiler, and the
// loaded ruleset has them.
func TestScopeAccountsReachTheRuleset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newScopedHarness(t, configScoped, newAccounts())
		defer h.stop()
		h.wantState(daemon.StateReady)
		h.wantOwners(with(webOwners, mailOwner)...)
	})
}

// A new id comes in at the next self-heal and gives a new ruleset, which
// the daemon loads. A configuration change reads the accounts at once.
func TestChangedAccountIDReloadsTheRuleset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		accts := newAccounts()
		h := newScopedHarness(t, configScoped, accts)
		defer h.stop()
		h.wantState(daemon.StateReady)
		before := h.world.Ruleset().ID()

		accts.setUser("carol", 603)
		heal()
		h.wantState(daemon.StateReady)
		h.wantOwners("web user alice 501", "web user carol 603", "web group admin 80", "web group staff 20", mailOwner)
		if h.world.Ruleset().ID() == before {
			t.Errorf("the ruleset ID did not change after the id of carol changed")
		}

		cfg := parse(t, strings.Replace(configScoped, `users = ["bob"]`, `users = ["dave"]`, 1))
		if err := h.d.Reconfigure(t.Context(), cfg); err != nil {
			t.Fatalf("Reconfigure: %v", err)
		}
		synctest.Wait()
		h.wantState(daemon.StateReady)
		h.wantOwners("web user alice 501", "web user carol 603", "web group admin 80", "web group staff 20", "mail user dave 504")
	})
}

// An account that goes away drops the scope that names it, and the state
// shows it. The other scopes keep their ids, and reports are still
// acknowledged.
func TestGoneAccountDropsOnlyItsScope(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		accts := newAccounts()
		h := newScopedHarness(t, configScoped, accts)
		defer h.stop()
		h.wantState(daemon.StateReady)

		accts.deleteUser("bob")
		heal()
		st := h.wantState(daemon.StateDegraded)
		if !hasReason(st, "policy mail: unknown user bob") {
			t.Errorf("reasons = %q, want the unknown user bob", st.Reasons)
		}
		h.wantOwners(webOwners...)
		if err := h.observe(obs("example.com", "192.0.2.80")); err != nil {
			t.Errorf("Observe in StateDegraded: %v", err)
		}

		accts.setUser("bob", 502)
		heal()
		h.wantState(daemon.StateReady)
		h.wantOwners(with(webOwners, mailOwner)...)
	})
}

// A name whose lookup fails keeps its last good id; every other name
// takes its new id. The reason gives the count, the log gives the name.
func TestFailedLookupKeepsOnlyItsLastID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		accts := newAccounts()
		h := newScopedHarness(t, configScoped, accts)
		defer h.stop()
		h.wantState(daemon.StateReady)

		accts.setFail("group admin", fmt.Errorf("buffer too small: %w", reconciletest.ErrInjected))
		accts.setUser("alice", 601)
		heal()
		st := h.wantState(daemon.StateDegraded)
		if !hasReason(st, "lookup of 1 user and group accounts failed") {
			t.Errorf("reasons = %q, want the failed lookup", st.Reasons)
		}
		if w := strings.Join(h.warnings(), "\n"); !strings.Contains(w, "admin") || !strings.Contains(w, reconciletest.ErrInjected.Error()) {
			t.Errorf("warnings = %q, want the name and the cause of the failed lookup", w)
		}
		h.wantOwners("web user alice 601", "web user carol 503", "web group admin 80", "web group staff 20", mailOwner)

		accts.setFail("group admin", nil)
		heal()
		h.wantState(daemon.StateReady)
	})
}

// A name whose lookup fails before it ever had an id drops its scope. A
// read where every lookup fails keeps the whole last snapshot.
func TestFailedLookupWithoutAnIDDropsItsScope(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		accts := newAccounts()
		accts.setFail("user bob", reconciletest.ErrInjected)
		h := newScopedHarness(t, configScoped, accts)
		defer h.stop()
		st := h.wantState(daemon.StateDegraded)
		if !hasReason(st, "policy mail: unknown user bob") || !hasReason(st, "lookup of 1 user") {
			t.Errorf("reasons = %q, want the dropped scope of mail and the failed lookup", st.Reasons)
		}
		h.wantOwners(webOwners...)

		for _, n := range []string{"user alice", "user bob", "user carol", "group staff", "group admin"} {
			accts.setFail(n, reconciletest.ErrInjected)
		}
		accts.setUser("alice", 601)
		heal()
		h.wantState(daemon.StateDegraded)
		h.wantOwners(webOwners...)
	})
}

// Failures that move from name to name keep the reason text the same,
// so the state does not change at each self-heal.
func TestFlakyLookupsKeepTheReasonStable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		accts := newAccounts()
		h := newScopedHarness(t, configScoped, accts)
		defer h.stop()
		h.wantState(daemon.StateReady)
		before, warnedBefore := h.stateChanges(), len(h.warnings())

		names := []string{"user alice", "user carol", "group staff", "group admin"}
		for i := range 12 {
			accts.setFail(names[(i+3)%4], nil)
			accts.setFail(names[i%4], reconciletest.ErrInjected)
			heal()
		}
		if n := h.stateChanges() - before; n != 1 {
			t.Errorf("%d state changes in 12 self-heals with one failed lookup each, want 1", n)
		}
		// One for the failed lookup. h.warnings has no state changes.
		if w := h.warnings()[warnedBefore:]; len(w) != 1 {
			t.Errorf("warnings = %q, want the first failure", w)
		}
	})
}

// A lookup that hangs blocks neither reports, nor Status, nor Reconfigure,
// nor a new interface. After AccountReadTimeout the state shows the hung
// read. Further triggers start no second read. When the lookup returns,
// its result applies.
func TestHungLookupDoesNotBlockTheLoop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		accts := newAccounts()
		h := newScopedHarness(t, configScoped, accts)
		defer h.stop()
		h.wantState(daemon.StateReady)

		release := accts.hangLookups()
		accts.setUser("alice", 601)
		heal() // the read starts and hangs
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		_, err := h.d.Observe(ctx, obs("example.com", "192.0.2.80"))
		cancel()
		if err != nil {
			t.Errorf("Observe during a hung lookup: %v", err)
		}
		h.inv.Set(en0, utun0)
		time.Sleep(daemon.InterfaceDebounce)
		synctest.Wait()
		if !strings.Contains(string(h.world.Ruleset().Body()), "iface utun0") {
			t.Errorf("a new interface did not reach the ruleset during a hung lookup")
		}
		time.Sleep(daemon.AccountReadTimeout)
		synctest.Wait()
		st := h.wantState(daemon.StateDegraded)
		if !hasReason(st, "account read takes longer than") {
			t.Errorf("reasons = %q, want the hung read", st.Reasons)
		}
		if err := h.d.Reconfigure(t.Context(), parse(t, configScoped)); err != nil {
			t.Errorf("Reconfigure during a hung lookup: %v", err)
		}
		for range 5 {
			heal()
		}
		h.wantOwners(with(webOwners, mailOwner)...)

		release()
		synctest.Wait()
		h.wantState(daemon.StateReady)
		h.wantOwners("web user alice 601", "web user carol 503", "web group admin 80", "web group staff 20", mailOwner)
		if n := accts.concurrency(); n != 1 {
			t.Errorf("%d lookups ran at one time, want 1", n)
		}
	})
}

// A directory that is always slower than AccountReadTimeout keeps one
// stable problem, and the ids of each late read still apply.
func TestSlowDirectoryKeepsOneProblem(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		accts := newAccounts()
		h := newScopedHarness(t, configScoped, accts)
		defer h.stop()
		h.wantState(daemon.StateReady)

		accts.setDelay(2 * time.Second) // five names: 10 s for each read
		accts.setUser("alice", 601)
		for range 6 {
			heal()
		}
		before := h.stateChanges()
		for range 12 {
			heal()
		}
		st := h.wantState(daemon.StateDegraded)
		if !hasReason(st, "account read takes longer than") {
			t.Errorf("reasons = %q, want the slow read", st.Reasons)
		}
		if n := h.stateChanges() - before; n != 0 {
			t.Errorf("%d state changes in one minute with a slow directory, want 0", n)
		}
		h.wantOwners("web user alice 601", "web user carol 503", "web group admin 80", "web group staff 20", mailOwner)

		accts.setDelay(0)
		for range 3 {
			heal()
		}
		h.wantState(daemon.StateReady)
	})
}

// The first convergence does not wait for the accounts: it installs the
// ruleset with every scope dropped (fail closed). The read then applies.
func TestStartDoesNotWaitForTheAccounts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		accts := newAccounts()
		release := accts.hangLookups()
		h := newScopedHarness(t, configScoped, accts)
		defer h.stop()
		st := h.wantState(daemon.StateDegraded)
		if !hasReason(st, "accounts are not read yet") {
			t.Errorf("reasons = %q, want the accounts not read yet", st.Reasons)
		}
		if h.world.Ruleset().ID() == "" {
			t.Fatalf("no ruleset is installed while the account read hangs")
		}
		h.wantOwners()

		release()
		synctest.Wait()
		h.wantState(daemon.StateReady)
		h.wantOwners(with(webOwners, mailOwner)...)
	})
}

// Run returns while a lookup hangs.
func TestRunReturnsDuringAHungLookup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		accts := newAccounts()
		h := newScopedHarness(t, configScoped, accts)
		h.wantState(daemon.StateReady)
		release := accts.hangLookups()
		heal()
		h.stop()
		release() // the lookup returns after Run, and its goroutine ends
	})
}

// Without a reader, the daemon knows no account: each scope is dropped,
// and the state says why.
func TestNoAccountReaderDropsEveryScope(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newScopedHarness(t, configScoped, nil)
		defer h.stop()
		st := h.wantState(daemon.StateDegraded)
		if !hasReason(st, "no account reader") {
			t.Errorf("reasons = %q, want no account reader", st.Reasons)
		}
		h.wantOwners()
	})
}
