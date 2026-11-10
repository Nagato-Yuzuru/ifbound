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
