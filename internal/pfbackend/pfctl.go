package pfbackend

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Nagato-Yuzuru/ifbound/pf"
)

// Path is the absolute path of pfctl on macOS. /sbin is not always in
// PATH.
const Path = "/sbin/pfctl"

// pfctlWait is the upper bound of one pfctl call. It is a backstop: the
// caller passes its own budget as the deadline of ctx.
const pfctlWait = 10 * time.Second

// Output is what one pfctl call printed.
type Output struct {
	Stdout []byte
	Stderr []byte
}

// Runner runs pfctl. Run gives stdin to the command, or no input when
// stdin is nil. The error is not nil when the command did not start or
// exited with a status other than 0; Output then holds what the command
// printed before.
type Runner interface {
	Run(ctx context.Context, stdin []byte, args ...string) (Output, error)
}

// Exec runs the pfctl binary at Path. The zero value is not usable.
type Exec struct {
	Path string
}

var _ Runner = Exec{}

// Run implements Runner.
func (e Exec) Run(ctx context.Context, stdin []byte, args ...string) (Output, error) {
	ctx, cancel := context.WithTimeout(ctx, pfctlWait)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.Path, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return Output{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, err
}

// The sentinel rule carries the ruleset ID into the kernel. pfctl
// rewrites the rules that it loads (it expands lists, reorders quick
// blocks, and writes numeric IDs), so the ID cannot be computed again
// from the rules that the kernel prints. A label keeps its text. A label
// holds at most 63 bytes, so the 32-byte digest goes in as 43 characters
// of unpadded base64url. A token rule carries one pf reference of ifbound
// in the same way: "<value>.<unix seconds>.<pid>" in decimal. The prefix
// and the two dots take 16 bytes, a uint64 value at most 20, and a pid
// that fits in int32 at most 10, so the label fits for each creation
// time below 10^17 seconds.
//
// The rules match only packets with the tag sentinelTag, and no rule
// sets that tag: every tag of a policy starts with "ifbound.". So the
// rules never block a packet.
const (
	labelPrefix = "ifbound-ruleset:"
	tokenPrefix = "ifbound-token:"
	sentinelTag = "ifbound-id"
	digestSize  = 32
)

// sentinel returns the sentinel rule for a ruleset ID.
func sentinel(id string) (string, error) {
	sum, err := hex.DecodeString(id)
	if err != nil || len(sum) != digestSize {
		return "", fmt.Errorf("%w: %q", errRulesetID, id)
	}
	return labelRule(labelPrefix + base64.RawURLEncoding.EncodeToString(sum)), nil
}

// token is a pf reference of ifbound. pf gives a released value again,
// also to another process at once, so only the value with the creation
// time and the pid of the process that took the reference names one
// reference.
type token struct {
	value   uint64
	created int64 // Unix time in seconds, as the kernel keeps it
	pid     int
}

// is reports whether r is the reference of t.
func (t token) is(r pf.Ref) bool {
	return t.value == r.Token && t.created == r.Created.Unix() && t.pid == r.PID
}

// tokenRule returns the token rule for a pf token.
func tokenRule(t token) string {
	return labelRule(tokenPrefix + strconv.FormatUint(t.value, 10) + "." +
		strconv.FormatInt(t.created, 10) + "." + strconv.Itoa(t.pid))
}

func labelRule(label string) string {
	return `block drop out quick tagged "` + sentinelTag + `" label "` + label + `"` + "\n"
}

// parseRules reads the filter rules of the anchor. It returns the
// ruleset ID from the sentinel rule, and the tokens from the token rules.
//
// The ID is "" when there is not exactly one valid sentinel rule. Foreign
// is true when a rule is not one that the ruleset of ifbound writes at
// the top level: a block rule, or an anchor rule that calls an anchor
// directly below (see subAnchorCall). A block rule that another tool adds
// only blocks more, so it does not change the ID.
func parseRules(rules []pf.Rule) (id string, tokens []token, foreign bool) {
	var ids []string
	for _, r := range rules {
		if r.AnchorCall != "" && !subAnchorCall(r.AnchorCall) || r.AnchorCall == "" && r.Action != pf.ActionDrop {
			foreign = true
		}
		if id, ok := labelID(r.Label); ok {
			ids = append(ids, id)
		}
		if tok, ok := labelToken(r.Label); ok {
			tokens = append(tokens, tok)
		}
	}
	if len(ids) != 1 {
		return "", tokens, foreign
	}
	return ids[0], tokens, foreign
}

// subAnchorCall reports whether an anchor call in the ifbound anchor, as
// pf_anchor_copyout gives it, calls one anchor directly below. readAnchor
// checks that these anchors hold no rule. Another call can go out of the
// ifbound anchor, or be a wildcard call ("*"), so pf can evaluate a rule
// that Read does not check.
func subAnchorCall(call string) bool {
	return call != "*" && !strings.Contains(call, "/")
}

// labelID returns the ruleset ID in the label of a sentinel rule. A
// label that does not decode to a digest gives no ID.
func labelID(label string) (string, bool) {
	text, ok := strings.CutPrefix(label, labelPrefix)
	if !ok {
		return "", false
	}
	sum, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil || len(sum) != digestSize {
		return "", false
	}
	return hex.EncodeToString(sum), true
}

// labelToken returns the pf token in the label of a token rule.
func labelToken(label string) (token, bool) {
	text, ok := strings.CutPrefix(label, tokenPrefix)
	if !ok {
		return token{}, false
	}
	f := strings.Split(text, ".")
	if len(f) != 3 || !isDigits(f[0]) || !isDigits(f[1]) || !isDigits(f[2]) {
		return token{}, false
	}
	value, err1 := strconv.ParseUint(f[0], 10, 64)
	created, err2 := strconv.ParseInt(f[1], 10, 64)
	pid, err3 := strconv.ParseInt(f[2], 10, 32)
	if err1 != nil || err2 != nil || err3 != nil {
		return token{}, false
	}
	return token{value: value, created: created, pid: int(pid)}, true
}

func isDigits(s string) bool {
	return s != "" && !strings.ContainsFunc(s, func(r rune) bool { return r < '0' || r > '9' })
}

// parseNames reads one name per line, as "pfctl -sT" prints tables and
// "pfctl -sA" prints anchors.
func parseNames(out []byte) []string {
	var names []string
	for line := range strings.Lines(string(out)) {
		if n := strings.TrimSpace(line); n != "" {
			names = append(names, n)
		}
	}
	return names
}

// parseEntries reads the output of "pfctl -T show". Each line is an
// address or a prefix, with "!" before a negated entry. A host entry
// becomes a full-length prefix.
func parseEntries(out []byte) (entries, negated []netip.Prefix, err error) {
	for line := range strings.Lines(string(out)) {
		text := strings.TrimSpace(line)
		if text == "" {
			continue
		}
		neg := false
		if rest, ok := strings.CutPrefix(text, "!"); ok {
			neg, text = true, rest
		}
		p, err := parseEntry(text)
		if err != nil {
			return nil, nil, err
		}
		if neg {
			negated = append(negated, p)
		} else {
			entries = append(entries, p)
		}
	}
	return entries, negated, nil
}

func parseEntry(text string) (netip.Prefix, error) {
	if strings.Contains(text, "/") {
		p, err := netip.ParsePrefix(text)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%w: table entry %q", errOutput, text)
		}
		return p, nil
	}
	a, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: table entry %q", errOutput, text)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// parseSkipped reads the output of "pfctl -sI -v" and returns the
// interfaces and groups that "set skip" covers.
func parseSkipped(out []byte) []string {
	var names []string
	for line := range strings.Lines(string(out)) {
		if name, ok := strings.CutSuffix(strings.TrimSpace(line), " (skip)"); ok {
			names = append(names, name)
		}
	}
	return names
}

// ruleWords splits a rule that pfctl printed into words. A word that
// starts with a quote runs to the next quote that no backslash escapes,
// and keeps its quotes. So a word in a quoted string, such as the text of
// a label, is not a keyword of the rule.
func ruleWords(rule string) []string {
	var words []string
	for rest := strings.TrimSpace(rule); rest != ""; {
		end := strings.IndexFunc(rest, unicode.IsSpace)
		if rest[0] == '"' {
			end = quoteEnd(rest)
		}
		if end < 0 {
			end = len(rest)
		}
		words = append(words, rest[:end])
		rest = strings.TrimLeftFunc(rest[end:], unicode.IsSpace)
	}
	return words
}

// quoteEnd returns the index after the quote that closes the quoted
// string at the start of s, or len(s) when no quote closes it.
func quoteEnd(s string) int {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return len(s)
}

// passQuick reports whether a rule with the words that ruleWords gives
// passes a packet and ends the evaluation.
func passQuick(words []string) bool {
	return len(words) > 0 && words[0] == "pass" && slices.Contains(words, "quick")
}

// anchorRule returns the anchor call of an anchor rule with the words
// that ruleWords gives, as pf keeps it (pf_anchor_copyout), and whether
// the rule is quick. ok is false when pfctl prints no anchor name.
func anchorRule(words []string) (call string, quick, ok bool) {
	if len(words) < 2 || words[0] != "anchor" {
		return "", false, false
	}
	call, ok = strings.CutPrefix(words[1], `"`)
	if ok {
		call, ok = strings.CutSuffix(call, `"`)
	}
	if !ok || call == "" {
		return "", false, false
	}
	return call, slices.Contains(words[2:], "quick"), true
}

// callTarget returns the anchor that an anchor call in the anchor from
// refers to, as pf_anchor_setup reads the call: a path that starts with
// "/" is absolute, each "../" goes up one anchor, and other paths are
// below from. wildcard is true when the call ends with "/*": pf then
// evaluates the anchors directly below path, and not path.
func callTarget(from, call string) (path string, wildcard bool) {
	if abs, ok := strings.CutPrefix(call, "/"); ok {
		path = abs
	} else {
		path = from
		for {
			rest, ok := strings.CutPrefix(call, "../")
			if !ok {
				break
			}
			call = rest
			path = path[:max(strings.LastIndex(path, "/"), 0)]
		}
		if path != "" {
			path += "/"
		}
		path += call
	}
	// pf_anchor_copyout prints a wildcard call of an anchor above as
	// "..//*", so the path can end with "/" here.
	path, wildcard = strings.CutSuffix(path, "/*")
	return strings.TrimSuffix(path, "/"), wildcard
}

// routesWithState reports whether a rule with the words that ruleWords
// gives routes packets to an interface (route-to, dup-to, fastroute) and
// keeps state: pfctl prints "no state" for a rule without state.
// reply-to is not in the list: pf routes with it only the packets of the
// other direction than the rule, and for an outbound packet that is the
// state of an inbound connection, which passes the packet on each
// interface also without the route.
func routesWithState(words []string) bool {
	routes := slices.ContainsFunc(words, func(w string) bool {
		return w == "route-to" || w == "dup-to" || w == "fastroute"
	})
	for i := 1; routes && i < len(words); i++ {
		if words[i-1] == "no" && words[i] == "state" {
			return false
		}
	}
	return routes
}

// ifaceLists holds the interface lists of the ifbound rules, by table.
// allowed holds the interfaces of the tag anchor rules of an only_via
// policy. denied holds the interfaces of the block rules that name them:
// the first block rule of only_via and the rule of deny_via. problem is
// not "" when a rule has a form that pfrules does not write.
type ifaceLists struct {
	allowed, denied map[string][]string
	problem         string
}

// parseIfaceLists reads the rules of the ifbound anchor that pfctl
// printed. pfctl prints a rule with a list as one rule per item, and it
// prints names without quotes; the loaded form, with lists in braces and
// quotes, gives the same result. The block rules without a table (the
// sentinel and token rules) and the block rules for each interface except
// one ("on ! lo0") hold no list.
func parseIfaceLists(rules []string) ifaceLists {
	l := ifaceLists{allowed: map[string][]string{}, denied: map[string][]string{}}
	for _, r := range rules {
		words := ruleWords(r)
		on, negated := ruleIfaces(words)
		table := ruleTable(words)
		switch {
		case len(words) > 0 && words[0] == "block":
			if table != "" && on != nil && !negated {
				l.denied[table] = append(l.denied[table], on...)
			}
		case len(words) > 0 && words[0] == "anchor" && slices.Contains(words, "tag"):
			if table == "" || on == nil || negated {
				l.problem = fmt.Sprintf("the anchor rule %q has no interface list or no table", r)
				return l
			}
			l.allowed[table] = append(l.allowed[table], on...)
		default:
			l.problem = fmt.Sprintf("the rule %q is not a rule that ifbound writes", r)
			return l
		}
	}
	return l
}

// ruleIfaces returns the interfaces after "on" in a rule with the words
// that ruleWords gives, and whether "!" negates them. The result is nil
// when the rule has no "on".
func ruleIfaces(words []string) (ifaces []string, negated bool) {
	i := slices.Index(words, "on")
	if i < 0 {
		return nil, false
	}
	rest := words[i+1:]
	if len(rest) > 0 && rest[0] == "!" {
		negated, rest = true, rest[1:]
	}
	if len(rest) == 0 {
		return nil, negated
	}
	if rest[0] != "{" {
		return []string{strings.Trim(rest[0], `"`)}, negated
	}
	for _, w := range rest[1:] {
		if w == "}" {
			return ifaces, negated
		}
		ifaces = append(ifaces, strings.Trim(w, `"`))
	}
	return nil, negated
}

// ruleTable returns the table after "to" in a rule with the words that
// ruleWords gives, or "" when the destination is not a table.
func ruleTable(words []string) string {
	i := slices.Index(words, "to")
	if i < 0 || i+1 == len(words) || !strings.HasPrefix(words[i+1], "<") {
		return ""
	}
	return strings.Trim(words[i+1], `<>"`)
}

// unsafeRoute returns why a route rule with state, with the words that
// ruleWords gives, can let a protected packet leave on an interface that
// a policy does not allow, or "" when it cannot.
//
// The ifbound rules are quick blocks, and a quick pass before them is a
// Problem of its own. So a route rule decides only a packet that the
// ifbound rules passed on its first interface, and a route to an
// interface that each policy allows cannot leak it. An interface is
// allowed when it is in the allowed list of each only_via policy with a
// list, and in no denied list. So an only_via policy with a list does not
// allow an interface that is in no list: it can be an interface that
// appeared after the compile. With only deny_via policies, such an
// interface is not denied, and the ifbound rules pass its packets also
// without a route. When no policy has a list, unsafeRoute reports no
// route: an only_via policy without interfaces blocks its packets on each
// interface except lo0.
func (l ifaceLists) unsafeRoute(words []string) string {
	if l.problem != "" {
		return "Read cannot read the interface lists of the ifbound rules: " + l.problem
	}
	if len(l.allowed) == 0 && len(l.denied) == 0 {
		return ""
	}
	targets, ok := routeTargets(words)
	if !ok {
		return "Read cannot tell the interface that it routes to"
	}
	for _, t := range targets {
		if !l.safe(t) {
			return "it routes to " + t + ", which an ifbound policy does not allow"
		}
	}
	return ""
}

// safe reports whether each policy allows the interface iface.
func (l ifaceLists) safe(iface string) bool {
	for _, d := range l.denied {
		if slices.Contains(d, iface) {
			return false
		}
	}
	for _, a := range l.allowed {
		if !slices.Contains(a, iface) {
			return false
		}
	}
	return true
}

// routeTargets returns the interfaces of the route-to and dup-to pools of
// a rule with the words that ruleWords gives. ok is false for fastroute,
// which takes the interface from the routing table, and for a pool that
// routeTargets cannot read.
func routeTargets(words []string) (ifaces []string, ok bool) {
	for i, w := range words {
		switch w {
		case "fastroute":
			return nil, false
		case "route-to", "dup-to":
			pool, ok := poolIfaces(words[i+1:])
			if !ok {
				return nil, false
			}
			ifaces = append(ifaces, pool...)
		}
	}
	return ifaces, true
}

// poolIfaces returns the interface of each member of the pool at the
// start of words, as pfctl prints a pool (print_pool): "en0",
// "(en0 192.0.2.1)", or a list in braces such as
// "{ (en0 192.0.2.1), (utun3 10.0.0.1) }". The address of a member can be
// a table. ok is false when the pool has another form.
func poolIfaces(words []string) (ifaces []string, ok bool) {
	braces := len(words) > 0 && words[0] == "{"
	if braces {
		words = words[1:]
	}
	depth := 0
	for _, w := range words {
		switch {
		case depth > 0:
		case braces && w == "}":
			return ifaces, len(ifaces) > 0
		default:
			name := strings.TrimSuffix(strings.TrimPrefix(w, "("), ",")
			if name == "" || strings.ContainsAny(name, `(){}<>,!"`) {
				return nil, false
			}
			ifaces = append(ifaces, name)
		}
		depth += strings.Count(w, "(") - strings.Count(w, ")")
		if depth < 0 {
			return nil, false
		}
		if !braces && depth == 0 {
			return ifaces, true
		}
	}
	return nil, false
}

// natPass reports whether a NAT rule that pfctl printed passes the
// packets that it translates. pf.conf(5): "If the pass modifier is given,
// packets matching the translation rule are passed without inspecting the
// filter rules".
func natPass(rule string) bool {
	f := strings.Fields(rule)
	return len(f) > 1 && (f[0] == "nat" || f[0] == "binat") && f[1] == "pass"
}

// refersToApple reports whether a printed rule of the main ruleset makes
// pf evaluate the anchors below com.apple for every packet. pf.conf(5):
// "When parameters are used, the anchor rule is only evaluated for
// matching packets".
func refersToApple(rule string) bool {
	rest, ok := strings.CutPrefix(rule, `anchor "`+appleAnchor+`/*"`)
	rest = strings.TrimSpace(rest)
	return ok && (rest == "" || rest == "all")
}

// stateAddr reads one address field of a state line.
func stateAddr(field string) (netip.Addr, bool) {
	field = strings.Trim(field, "()")
	if host, _, ok := strings.Cut(field, "["); ok {
		field = host
	} else if host, _, ok := strings.Cut(field, ":"); ok && strings.Count(field, ":") == 1 {
		field = host
	}
	a, err := netip.ParseAddr(field)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.WithZone(""), true
}

// stderrText makes the stderr of pfctl fit in one error line. It drops
// the notes that pfctl prints on every call.
func stderrText(stderr []byte) string {
	var lines []string
	for line := range strings.Lines(string(stderr)) {
		line = strings.TrimSpace(line)
		if line == "" || noise(line) {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "; ")
}

// complained reports whether pfctl printed an error on stderr. Some
// errors do not change the exit status.
func complained(stderr []byte) bool {
	for line := range strings.Lines(string(stderr)) {
		if strings.HasPrefix(line, "pfctl: ") && !noise(strings.TrimSpace(line)) {
			return true
		}
	}
	return false
}

func noise(line string) bool {
	return line == "No ALTQ support in kernel" || line == "ALTQ related functions disabled" ||
		strings.HasPrefix(line, "pfctl: Use of -f option") ||
		line == "present in the main ruleset added by the system at startup." ||
		line == "See /etc/pf.conf for further details."
}

var errOutput = errors.New("unexpected pfctl output")
