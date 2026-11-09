package pfbackend_test

// Tests of Unload against the kernel model: give back the token, then
// flush the rules and the tables of the anchor.

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/pfbackend"
)

// unloadOrder returns the StopRef and -F calls in the order that they ran.
func unloadOrder(calls [][]string) []string {
	var out []string
	for _, c := range calls {
		switch {
		case slices.Contains(c, "DIOCSTOPREF"):
			out = append(out, "DIOCSTOPREF")
		case slices.Contains(c, "-F"):
			out = append(out, strings.Join(c, " "))
		}
	}
	return out
}

func TestUnloadRemovesTheEnforcement(t *testing.T) {
	r := newRig(t)
	if _, err := r.k.enableRef(); err != nil { // another tool: pfctl -E
		t.Fatal(err)
	}
	other := r.k.refs[0]
	mustLoad(t, r, compileRS(t, testPolicies))
	if err := r.b.AddEntries(t.Context(), "bing", pfx("192.0.2.1/32")); err != nil {
		t.Fatal(err)
	}
	from := len(r.k.calls)
	if err := r.b.Unload(t.Context()); err != nil {
		t.Fatalf("Unload: %v", err)
	}
	want := []string{"DIOCSTOPREF", "-a " + ifb + " -F rules", "-a " + ifb + " -F Tables"}
	if got := unloadOrder(r.k.calls[from:]); !slices.Equal(got, want) {
		t.Errorf("Unload ran %v, want %v: the token goes back before the flush", got, want)
	}
	if rules := r.k.rules[ifb]; len(rules) != 0 {
		t.Errorf("anchor rules after Unload = %v, want none", rules)
	}
	if tables := r.k.tables[ifb]; len(tables) != 0 {
		t.Errorf("anchor tables after Unload = %v, want none", tables)
	}
	if !r.k.enabled || !slices.Equal(r.k.refs, []string{other}) {
		t.Errorf("after Unload: enabled %v refs %v; want pf enabled with the other reference only", r.k.enabled, r.k.refs)
	}
	if st := mustRead(t, r); st.Ruleset != "" || len(st.Tables) != 0 {
		t.Errorf("Read after Unload = ruleset %q tables %v, want none", st.Ruleset, st.Tables)
	}
}

// A Load that fails after StartRef holds a token that no label has.
// Unload in the same process gives it back.
func TestUnloadAfterAFailedLoad(t *testing.T) {
	r := newRig(t)
	mustLoad(t, r, compileRS(t, testPolicies))
	r.k.fail = func(args []string) bool { return slices.Contains(args, "-f") }
	if err := r.b.Load(t.Context(), compileRS(t, "")); err == nil {
		t.Fatal("Load with a failing pfctl -f = nil, want an error")
	}
	r.k.fail = nil
	if err := r.b.Unload(t.Context()); err != nil {
		t.Fatalf("Unload: %v", err)
	}
	if len(r.k.refs) != 0 || r.k.enabled {
		t.Errorf("after Unload: refs %v enabled %v, want no reference", r.k.refs, r.k.enabled)
	}
}

// A stop at any step of Unload, then an Unload in a new process, removes
// the enforcement and gives back the token of ifbound only. Between the
// two, another tool takes a reference, and pf can give it the value
// that ifbound released.
func TestUnloadResumesAfterAStop(t *testing.T) {
	for _, step := range [][]string{{"DIOCGETSTARTERS"}, {"DIOCSTOPREF"}, {"-F", "rules"}, {"-F", "Tables"}} {
		name := strings.Join(step, " ")
		t.Run(name, func(t *testing.T) { unloadAfterAStop(t, step, false) })
		t.Run(name+", another reference", func(t *testing.T) { unloadAfterAStop(t, step, true) })
	}
}

func unloadAfterAStop(t *testing.T, step []string, other bool) {
	r := newRig(t)
	var keep []string
	if other {
		if _, err := r.k.enableRef(); err != nil {
			t.Fatal(err)
		}
		keep = slices.Clone(r.k.refs)
	}
	mustLoad(t, r, compileRS(t, testPolicies))
	if err := r.b.AddEntries(t.Context(), "bing", pfx("192.0.2.1/32")); err != nil {
		t.Fatal(err)
	}
	r.k.fail = func(args []string) bool {
		return !slices.ContainsFunc(step, func(w string) bool { return !slices.Contains(args, w) })
	}
	if err := r.b.Unload(t.Context()); err == nil {
		t.Fatalf("Unload with a stop at %v = nil, want an error", step)
	}
	r.k.fail = nil
	r.clk.t = r.clk.t.Add(time.Minute)
	if _, err := r.k.enableRef(); err != nil { // a later tool: pfctl -E
		t.Fatal(err)
	}
	keep = append(keep, r.k.refs[len(r.k.refs)-1])
	again := pfbackend.New(r.k, r.k, r.clk.now, slog.New(slog.DiscardHandler))
	if err := again.Unload(t.Context()); err != nil {
		t.Fatalf("second Unload: %v", err)
	}
	if len(r.k.rules[ifb]) != 0 || len(r.k.tables[ifb]) != 0 {
		t.Errorf("after the second Unload: rules %v tables %v, want none", r.k.rules[ifb], r.k.tables[ifb])
	}
	if !slices.Equal(r.k.refs, keep) || !r.k.enabled {
		t.Errorf("after the second Unload: refs %v enabled %v, want refs %v of the other tools", r.k.refs, r.k.enabled, keep)
	}
}

// After Unload gave back the token of ifbound, pf can give the same value
// to another tool. A stale label then names the value of that tool, with
// another creation time, and Unload leaves it.
func TestUnloadLeavesAReusedTokenValue(t *testing.T) {
	r := newRig(t)
	mustLoad(t, r, compileRS(t, testPolicies))
	mine := r.k.refs[0]
	r.k.fail = func(args []string) bool { return slices.Contains(args, "-F") }
	if err := r.b.Unload(t.Context()); err == nil {
		t.Fatal("Unload with a failing flush = nil, want an error")
	}
	r.k.fail = nil
	r.clk.t = r.clk.t.Add(time.Minute)
	if _, err := r.k.enableRef(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.k.refs, []string{mine}) {
		t.Fatalf("the other tool got %v, want the reused value %s", r.k.refs, mine)
	}
	again := pfbackend.New(r.k, r.k, r.clk.now, slog.New(slog.DiscardHandler))
	if err := again.Unload(t.Context()); err != nil {
		t.Fatalf("second Unload: %v", err)
	}
	if !r.k.enabled || !slices.Equal(r.k.refs, []string{mine}) {
		t.Errorf("after the second Unload: enabled %v refs %v; want the reference of the other tool", r.k.enabled, r.k.refs)
	}
}

// The first Unload gives back the reference of ifbound and stops before
// the flush, so the token rule stays. In the same second another tool
// takes a reference, and pf gives it the released value. The value and
// the creation time in the label then match that reference, and only the
// pid differs. A restarted Unload leaves the reference and removes the
// rules.
func TestUnloadAfterARestartLeavesAReusedValueOfTheSameSecond(t *testing.T) {
	r := newRig(t)
	mustLoad(t, r, compileRS(t, testPolicies))
	mine := r.k.refs[0]
	born := r.k.born[mine]
	r.k.fail = func(args []string) bool { return slices.Contains(args, "-F") }
	if err := r.b.Unload(t.Context()); err == nil {
		t.Fatal("Unload with a failing flush = nil, want an error")
	}
	r.k.fail = nil
	if _, err := r.k.enableRef(); err != nil { // another tool: pfctl -E, in the same second
		t.Fatal(err)
	}
	if !slices.Equal(r.k.refs, []string{mine}) || !r.k.born[mine].Equal(born) {
		t.Fatalf("the other tool got %v created %v, want the reused value %s created %v", r.k.refs, r.k.born[mine], mine, born)
	}
	r.k.pid++ // the restarted process
	again := pfbackend.New(r.k, r.k, r.clk.now, slog.New(slog.DiscardHandler))
	if err := again.Unload(t.Context()); err != nil {
		t.Fatalf("second Unload: %v", err)
	}
	if !r.k.enabled || !slices.Equal(r.k.refs, []string{mine}) {
		t.Errorf("after the second Unload: enabled %v refs %v; want the reference of the other tool", r.k.enabled, r.k.refs)
	}
	if len(r.k.rules[ifb]) != 0 {
		t.Errorf("anchor rules after the second Unload = %v, want none", r.k.rules[ifb])
	}
}

// An old token that Load cannot give back stays known and in the labels.
// The next Load tries again, and a restarted Backend reads the tokens
// from the labels, and Unload gives them back.
func TestLoadKeepsAnOldTokenThatDidNotGoBack(t *testing.T) {
	r := newRig(t)
	mustLoad(t, r, compileRS(t, testPolicies))
	old := r.k.refs[0]
	r.k.fail = func(args []string) bool { return slices.Contains(args, "DIOCSTOPREF") }
	mustLoad(t, r, compileRS(t, testPolicies))
	r.k.fail = nil
	if got := r.log.errorTypes(); !slices.Equal(got, []string{logattr.ErrorTypePFToken}) {
		t.Errorf("warnings with error.type = %q, want one %s", got, logattr.ErrorTypePFToken)
	}
	if len(r.k.refs) != 2 {
		t.Fatalf("refs after a Load whose StopRef failed = %v, want the old and the new token", r.k.refs)
	}
	if got := strings.Join(r.k.rules[ifb], "\n"); !strings.Contains(got, "ifbound-token:"+old+".") {
		t.Errorf("the anchor has no label for the old token %s:\n%s", old, got)
	}
	r.clk.t = r.clk.t.Add(time.Minute)
	mustLoad(t, r, compileRS(t, testPolicies)) // the next Load tries again
	if len(r.k.refs) != 1 || slices.Contains(r.k.refs, old) {
		t.Errorf("refs after the next Load = %v, want only the newest: the old token %s goes back", r.k.refs, old)
	}
	r.k.fail = func(args []string) bool { return slices.Contains(args, "DIOCSTOPREF") }
	mustLoad(t, r, compileRS(t, testPolicies))
	r.k.fail = nil
	again := pfbackend.New(r.k, r.k, r.clk.now, slog.New(slog.DiscardHandler))
	if err := again.Unload(t.Context()); err != nil {
		t.Fatalf("Unload: %v", err)
	}
	if len(r.k.refs) != 0 || r.k.enabled {
		t.Errorf("after Unload: refs %v enabled %v, want no reference", r.k.refs, r.k.enabled)
	}
}

// A Load that fails after it took a new token gives the token back. When
// that fails too, the Backend warns and keeps the token.
func TestFailedLoadWarnsWhenItCannotGiveBackItsToken(t *testing.T) {
	r := newRig(t)
	r.k.fail = func(args []string) bool { return slices.Contains(args, "DIOCSTOPREF") || slices.Contains(args, "-f") }
	if err := r.b.Load(t.Context(), compileRS(t, testPolicies)); err == nil {
		t.Fatal("Load with a failing pfctl -f: nil error")
	}
	r.k.fail = nil
	if got := r.log.errorTypes(); !slices.Equal(got, []string{logattr.ErrorTypePFToken}) {
		t.Errorf("warnings with error.type = %q, want one %s", got, logattr.ErrorTypePFToken)
	}
}

// ctxRunner is the kernel model behind a pfctl that fails when its
// context is done, as exec.CommandContext does.
type ctxRunner struct{ k *kernel }

func (c ctxRunner) Run(ctx context.Context, stdin []byte, args ...string) (pfbackend.Output, error) {
	if err := ctx.Err(); err != nil {
		return pfbackend.Output{Stderr: []byte("signal: killed\n")}, err
	}
	return c.k.Run(ctx, stdin, args...)
}

// A cancel between StartRef and the load of the anchor leaves a token
// that no label holds. Load gives it back.
func TestLoadGivesBackTheNewTokenAfterACancel(t *testing.T) {
	r := newRig(t)
	b := pfbackend.New(ctxRunner{r.k}, r.k, r.clk.now, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	r.k.fail = func(args []string) bool {
		if slices.Contains(args, "DIOCSTARTREF") {
			cancel()
		}
		return false
	}
	if err := b.Load(ctx, compileRS(t, testPolicies)); err == nil {
		t.Fatal("Load with a cancel after StartRef = nil, want an error")
	}
	if len(r.k.refs) != 0 || r.k.enabled {
		t.Errorf("after the canceled Load: refs %v enabled %v, want the new token given back", r.k.refs, r.k.enabled)
	}
}

// Unload does not use the context of the caller: a canceled caller still
// removes the enforcement.
func TestUnloadWithACanceledContext(t *testing.T) {
	r := newRig(t)
	b := pfbackend.New(ctxRunner{r.k}, r.k, r.clk.now, slog.New(slog.DiscardHandler))
	if err := b.Load(t.Context(), compileRS(t, testPolicies)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := b.Unload(ctx); err != nil {
		t.Fatalf("Unload with a canceled context: %v", err)
	}
	if len(r.k.refs) != 0 || len(r.k.rules[ifb]) != 0 {
		t.Errorf("after Unload: refs %v rules %v, want none", r.k.refs, r.k.rules[ifb])
	}
}
