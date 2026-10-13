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
	"strings"
	"time"
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
// of unpadded base64url. A second sentinel rule carries the pf token of
// ifbound in the same way.
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

// tokenRule returns the sentinel rule for a pf token. A token is a
// decimal number of at most 20 digits.
func tokenRule(token string) string { return labelRule(tokenPrefix + token) }

func labelRule(label string) string {
	return `block drop out quick tagged "` + sentinelTag + `" label "` + label + `"` + "\n"
}

// parseRuleset reads the output of "pfctl -a <anchor>/* -sr": the rules
// of the anchor, each referenced sub-anchor with its rules between braces,
// recursively. It returns the ruleset ID from the sentinel rule, and the
// token from the token rule ("" when there is not exactly one).
//
// The ID is "" when there is not exactly one valid sentinel rule, or when
// the output holds a rule that the ruleset of ifbound does not write: a
// rule in a sub-anchor, or a rule at the top level that is not a block or
// an anchor rule. pf prints the rules of a sub-anchor indented below its
// anchor rule. A block rule that another tool adds only blocks more, so
// it does not change the ID.
func parseRuleset(out []byte) (id, token string) {
	var ids, tokens []string
	foreign := false
	for line := range strings.Lines(string(out)) {
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "", line == "}":
		case line[0] == ' ' || line[0] == '\t':
			foreign = true
		case !strings.HasPrefix(line, "block ") && !strings.HasPrefix(line, "anchor "):
			foreign = true
		default:
			if id, ok := labelID(line); ok {
				ids = append(ids, id)
			}
			if tok, ok := labelToken(line); ok {
				tokens = append(tokens, tok)
			}
		}
	}
	if len(tokens) == 1 {
		token = tokens[0]
	}
	if len(ids) != 1 || foreign {
		return "", token
	}
	return ids[0], token
}

// labelID returns the ruleset ID in the label of a sentinel rule. A
// label that does not decode to a digest gives no ID.
func labelID(rule string) (string, bool) {
	_, rest, ok := strings.Cut(rule, `label "`+labelPrefix)
	if !ok {
		return "", false
	}
	text, _, ok := strings.Cut(rest, `"`)
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
func labelToken(rule string) (string, bool) {
	_, rest, ok := strings.Cut(rule, `label "`+tokenPrefix)
	if !ok {
		return "", false
	}
	text, _, ok := strings.Cut(rest, `"`)
	if !ok || text == "" || strings.ContainsFunc(text, func(r rune) bool { return r < '0' || r > '9' }) {
		return "", false
	}
	return text, true
}

// tokenGone reports whether the stderr of "pfctl -X" says that pf does
// not hold the token: "pf not enabled" when pf is disabled (which drops
// every token), and "pf: token invalid" for a token that pf does not
// know.
func tokenGone(stderr []byte) bool {
	return bytes.Contains(stderr, []byte("pf not enabled")) || bytes.Contains(stderr, []byte("token invalid"))
}

// parseStatus reads whether pf is enabled from "pfctl -s info".
func parseStatus(out []byte) (bool, error) {
	for line := range strings.Lines(string(out)) {
		rest, ok := strings.CutPrefix(line, "Status: ")
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(rest, "Enabled"):
			return true, nil
		case strings.HasPrefix(rest, "Disabled"):
			return false, nil
		}
		return false, fmt.Errorf("%w: status line %q", errOutput, strings.TrimSpace(line))
	}
	return false, fmt.Errorf("%w: no status line in pfctl -s info", errOutput)
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

// parseConflicts reads the stdout of "pfctl -v -T add" and returns the
// entries that conflict with a negated entry for the same address. Each
// line is a feedback letter, a space, a space or "!", and the address.
// "Y" marks a conflict. pfctl prints no line for an entry that is
// already present.
func parseConflicts(out []byte) ([]netip.Prefix, error) {
	var conflicts []netip.Prefix
	for line := range strings.Lines(string(out)) {
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		if len(line) < 4 || line[1] != ' ' || (line[2] != ' ' && line[2] != '!') {
			return nil, fmt.Errorf("%w: table feedback %q", errOutput, line)
		}
		p, err := parseEntry(line[3:])
		if err != nil {
			return nil, err
		}
		if line[0] == 'Y' {
			conflicts = append(conflicts, p)
		}
	}
	return conflicts, nil
}

// parseToken reads the reference token from the stderr of "pfctl -E".
func parseToken(stderr []byte) (string, error) {
	for line := range strings.Lines(string(stderr)) {
		if tok, ok := strings.CutPrefix(strings.TrimSpace(line), "Token : "); ok && tok != "" {
			return tok, nil
		}
	}
	return "", fmt.Errorf("%w: no token in the output of pfctl -E", errOutput)
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

// passQuick reports whether a rule that pfctl printed passes a packet
// and ends the evaluation.
func passQuick(rule string) bool {
	f := strings.Fields(rule)
	return len(f) > 0 && f[0] == "pass" && slices.Contains(f, "quick")
}

// anchorRule returns the anchor path of a printed anchor rule, without a
// trailing "/*".
func anchorRule(rule string) (string, bool) {
	rest, ok := strings.CutPrefix(rule, `anchor "`)
	if !ok {
		return "", false
	}
	name, _, ok := strings.Cut(rest, `"`)
	if !ok || name == "" {
		return "", false
	}
	return strings.TrimSuffix(name, "/*"), true
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

// parseStates reads the output of "pfctl -s state" and returns every
// address in it. A line prints the addresses of one state, an IPv4
// address with ":port" and an IPv6 address with "[port]", for example
//
//	ALL udp 192.168.64.14:59130 -> 192.168.64.200:38457 -> 192.0.2.11:9       SINGLE:NO_TRAFFIC
//	ALL udp ::1[63006] -> ::1[9999]       SINGLE:NO_TRAFFIC
//
// ok is false when a line holds no address.
func parseStates(out []byte) (addrs []netip.Addr, ok bool) {
	for line := range strings.Lines(string(out)) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		found := false
		for f := range strings.FieldsSeq(line) {
			if a, ok := stateAddr(f); ok {
				addrs = append(addrs, a)
				found = true
			}
		}
		if !found {
			return nil, false
		}
	}
	return addrs, true
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
