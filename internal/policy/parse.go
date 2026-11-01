package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// The reasons that Parse and Config.CheckUpstreams report. Each syntax
// or validation error is a *FieldError that wraps one of them.
var (
	errSyntax         = errors.New("cannot decode")
	errUnknownKey     = errors.New("unknown key")
	errPolicyShape    = errors.New("must be an array of tables: use [[policy]]")
	errUpstreamEmpty  = errors.New("must list at least one upstream")
	errUpstreamMany   = errors.New("must list at most 15 upstreams: the CoreDNS forward plugin accepts no more")
	errUpstreamForm   = errors.New("must have the form tls://<ip>[:port]@<server-name>")
	errBadAddress     = errors.New("invalid address")
	errNotLoopback    = errors.New("listen address must be a loopback address (127.0.0.0/8 or ::1): the resolver entries send protected lookups to it, and any other address can bypass ifbound-dns")
	errPortZero       = errors.New("port must not be zero")
	errZoned          = errors.New("zoned address is not allowed")
	errMappedPrefix   = errors.New("IPv4-mapped IPv6 prefix must have at least 96 bits")
	errBadDuration    = errors.New("invalid duration")
	errNotPositive    = errors.New("must be greater than zero")
	errBadName        = errors.New("policy name must be 1 to 24 bytes of [a-z0-9_-], starting with a letter or digit")
	errNameDuplicate  = errors.New("duplicate policy name")
	errToEmpty        = errors.New("must list at least one destination")
	errBadDomain      = errors.New("invalid domain")
	errNonASCII       = errors.New("domain must be ASCII: use the punycode form")
	errBadDestination = errors.New("invalid destination")
	errViaConflict    = errors.New("exactly one of only_via and deny_via is required")
	errDenyEmpty      = errors.New("deny_via must not be empty: the policy would have no effect")
	errBadSelector    = errors.New("invalid interface selector")
	errUnknownClass   = errors.New("unknown interface class")
	errScopeEmpty     = errors.New("scope must list at least one user or group: the policy would apply to no traffic")
	errBadAccount     = errors.New("user or group name must be 1 to 32 bytes of [A-Za-z0-9_.-], starting with a letter or \"_\"")
	errUnreachable    = errors.New("ifbound-dns can never reach an upstream")
)

// FieldError reports a configuration fault at one field. Field is the
// path in the file, for example "policy[1].to[0]". It is empty when the
// fault is not tied to a field, such as a TOML syntax error.
//
// Line and Column give the place of the fault in the file. Both start at 1.
// Column counts bytes, not characters. For a syntax error at the end of a
// line in a file with CRLF line ends, go-toml counts the "\r" in the column.
// Both are zero when the place is unknown. Parse sets them. An error
// from Config.CheckUpstreams has no place until the caller runs Locate on
// the file text, because a Config does not keep the text.
type FieldError struct {
	Field  string
	Err    error
	Line   int
	Column int

	// path is Field as a list of steps. Field can be the same text for two
	// paths, such as a key "a.b" and the key b in the table a. Locate uses
	// path, so it finds the right one.
	path fieldPath
}

func (e *FieldError) Error() string {
	if e.Field == "" {
		return e.Err.Error()
	}
	// The path can hold raw key bytes: quote it so it cannot forge log lines.
	return strconv.Quote(e.Field) + ": " + e.Err.Error()
}

func (e *FieldError) Unwrap() error { return e.Err }

// at puts field in front of the field path of err.
func at(field string, err error) error {
	p := literal(field)
	var fe *FieldError
	if !errors.As(err, &fe) {
		return newFieldError(p, err)
	}
	p = append(p, fe.path...)
	return &FieldError{Field: p.String(), Err: fe.Err, Line: fe.Line, Column: fe.Column, path: p}
}

type rawConfig struct {
	DNS      rawDNS      `toml:"dns"`
	AddrBook rawAddrBook `toml:"addrbook"`
	Policy   []rawPolicy `toml:"policy"`
}

type rawDNS struct {
	Listen   *string  `toml:"listen"`
	Upstream []string `toml:"upstream"`
}

type rawAddrBook struct {
	Retain *string `toml:"retain"`
}

// rawPolicy uses pointers to slices so that an absent key (nil) differs
// from an empty array (non-nil, length zero).
type rawPolicy struct {
	Name    string    `toml:"name"`
	To      []string  `toml:"to"`
	OnlyVia *[]string `toml:"only_via"`
	DenyVia *[]string `toml:"deny_via"`
	Scope   *rawScope `toml:"scope"`
}

type rawScope struct {
	Users  []string `toml:"users"`
	Groups []string `toml:"groups"`
}

// ParseBytes parses a configuration file. See Parse.
func ParseBytes(b []byte) (Config, error) {
	return Parse(bytes.NewReader(b))
}

// Parse reads a TOML configuration and validates it.
//
// A read failure returns the reader's error. Any other failure is a
// *FieldError. Parse accepts only keys spelled exactly as documented:
// the TOML decoder matches keys without regard to case, so Parse checks
// the key set itself before it decodes into typed values.
func Parse(r io.Reader) (Config, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return Config{}, fmt.Errorf("reading config: %w", err)
	}
	idx := newIndex(b)
	cfg, err := parse(b, idx)
	var fe *FieldError
	if errors.As(err, &fe) {
		fe.locateIn(idx)
	}
	return cfg, err
}

func parse(b []byte, idx *index) (Config, error) {
	// The decoder reports a duplicate key without its parent path, so the
	// index reports it first, with the full path.
	if dup := idx.dup; dup != nil {
		return Config{}, dup
	}
	var tree map[string]any
	if err := toml.Unmarshal(b, &tree); err != nil {
		return Config{}, decodeError(err)
	}
	if err := checkKeys(tree); err != nil {
		return Config{}, err
	}
	var raw rawConfig
	dec := toml.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return Config{}, decodeError(err)
	}
	return raw.validate()
}

// decodeError turns a decoder failure into this package's vocabulary.
// The decoder's own error stays out of the %w chain. The decoder gives the
// place of its error, so decodeError keeps it.
func decodeError(err error) error {
	var derr *toml.DecodeError
	if errors.As(err, &derr) {
		line, col := derr.Position()
		return &FieldError{
			Field:  strings.Join(derr.Key(), "."),
			Err:    fmt.Errorf("%w: %v", errSyntax, err),
			Line:   line,
			Column: col,
		}
	}
	return &FieldError{Err: fmt.Errorf("%w: %v", errSyntax, err)}
}

// checkKeys rejects every key that is not spelled exactly as the schema
// says, and every value of the wrong type. It works on the generic tree,
// where the array indices are known, so each error names its exact path.
// It also requires [[policy]] to be an array of tables.
func checkKeys(tree map[string]any) error {
	if err := checkTable(nil, tree, "dns", "addrbook", "policy"); err != nil {
		return err
	}
	if v, ok := tree["dns"]; ok {
		if err := checkTableValue(literal("dns"), v, map[string]fieldKind{"listen": kindString, "upstream": kindStrings}); err != nil {
			return err
		}
	}
	if v, ok := tree["addrbook"]; ok {
		if err := checkTableValue(literal("addrbook"), v, map[string]fieldKind{"retain": kindString}); err != nil {
			return err
		}
	}
	pol, present := tree["policy"]
	if !present {
		return nil
	}
	list, ok := pol.([]any)
	if !ok {
		return newFieldError(literal("policy"), errPolicyShape)
	}
	for i, e := range list {
		path := literal("policy").add(idxSeg(i))
		kinds := map[string]fieldKind{"name": kindString, "to": kindStrings, "only_via": kindStrings, "deny_via": kindStrings, "scope": kindTable}
		if err := checkTableValue(path, e, kinds); err != nil {
			return err
		}
		if scope, ok := e.(map[string]any)["scope"]; ok {
			if err := checkTableValue(path.add(keySeg("scope")), scope, map[string]fieldKind{"users": kindStrings, "groups": kindStrings}); err != nil {
				return err
			}
		}
	}
	return nil
}

func typeError(want string) error {
	return fmt.Errorf("%w: must be %s", errSyntax, want)
}

type fieldKind int

const (
	kindString fieldKind = iota
	kindStrings
	// kindTable is a nested table. checkTableValue checks only that the
	// value is a table: the caller checks its keys.
	kindTable
)

// checkTableValue checks that v is a table that holds only the keys in
// kinds, each with its kind of value. path is the table's own path.
// Several keys can be wrong; the error names the first in key order.
func checkTableValue(path fieldPath, v any, kinds map[string]fieldKind) error {
	m, ok := v.(map[string]any)
	if !ok {
		return newFieldError(path, typeError("a table"))
	}
	keys := slices.Sorted(maps.Keys(kinds))
	if err := checkTable(path, m, keys...); err != nil {
		return err
	}
	for _, k := range keys {
		val, ok := m[k]
		if !ok {
			continue
		}
		field := path.add(keySeg(k))
		switch kinds[k] {
		case kindString:
			if _, isStr := val.(string); !isStr {
				return newFieldError(field, typeError("a string"))
			}
			continue
		case kindTable:
			if _, isTable := val.(map[string]any); !isTable {
				return newFieldError(field, typeError("a table"))
			}
			continue
		case kindStrings: // checked below
		}
		list, isList := val.([]any)
		if !isList {
			return newFieldError(field, typeError("an array of strings"))
		}
		for i, e := range list {
			if _, isStr := e.(string); !isStr {
				return newFieldError(field.add(idxSeg(i)), typeError("a string"))
			}
		}
	}
	return nil
}

func checkTable(path fieldPath, m map[string]any, allowed ...string) error {
	var unknown []string
	for k := range m {
		if !slices.Contains(allowed, k) {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	slices.Sort(unknown) // the same file always gives the same error
	return newFieldError(path.add(keySeg(unknown[0])), errUnknownKey)
}

func (raw rawConfig) validate() (Config, error) {
	var cfg Config
	var err error
	if cfg.DNS, err = raw.DNS.validate(); err != nil {
		return Config{}, at("dns", err)
	}
	if cfg.AddrBook, err = raw.AddrBook.validate(); err != nil {
		return Config{}, at("addrbook", err)
	}
	seen := make(map[Name]struct{}, len(raw.Policy))
	for i, rp := range raw.Policy {
		field := fmt.Sprintf("policy[%d]", i)
		p, err := rp.validate()
		if err != nil {
			return Config{}, at(field, err)
		}
		if _, dup := seen[p.Name]; dup {
			return Config{}, at(field, at("name", fmt.Errorf("%w: %q", errNameDuplicate, p.Name)))
		}
		seen[p.Name] = struct{}{}
		cfg.Policies = append(cfg.Policies, p)
	}
	return cfg, nil
}

// maxUpstreams is the number of upstreams that the CoreDNS forward plugin
// accepts. A [dns] with more could not start ifbound-dns.
const maxUpstreams = 15

func (d rawDNS) validate() (DNS, error) {
	listen := DefaultListen
	if d.Listen != nil {
		listen = *d.Listen
	}
	ap, err := netip.ParseAddrPort(listen)
	if err != nil {
		return DNS{}, at("listen", fmt.Errorf("%w: %q", errBadAddress, listen))
	}
	if ap, err = normalizeAddrPort(ap); err != nil {
		return DNS{}, at("listen", err)
	}
	// VMs reach ifbound-dns through the gateway DNS proxy of the host, so
	// a loopback address serves them too.
	if !ap.Addr().IsLoopback() {
		return DNS{}, at("listen", fmt.Errorf("%w: %q", errNotLoopback, listen))
	}
	if len(d.Upstream) == 0 {
		return DNS{}, at("upstream", errUpstreamEmpty)
	}
	if len(d.Upstream) > maxUpstreams {
		return DNS{}, at("upstream", errUpstreamMany)
	}
	out := DNS{Listen: ap}
	for i, s := range d.Upstream {
		u, err := parseUpstream(s)
		if err != nil {
			return DNS{}, at(fmt.Sprintf("upstream[%d]", i), err)
		}
		out.Upstream = append(out.Upstream, u)
	}
	return out, nil
}

func normalizeAddrPort(ap netip.AddrPort) (netip.AddrPort, error) {
	if ap.Port() == 0 {
		return netip.AddrPort{}, errPortZero
	}
	a, err := normalizeAddr(ap.Addr())
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(a, ap.Port()), nil
}

// parseUpstream parses "tls://<ip>[:port]@<server-name>". An IPv6 address
// takes brackets.
func parseUpstream(s string) (Upstream, error) {
	rest, ok := strings.CutPrefix(s, "tls://")
	if !ok {
		return Upstream{}, fmt.Errorf("%w: %q", errUpstreamForm, s)
	}
	hostPort, name, ok := strings.Cut(rest, "@")
	if !ok {
		return Upstream{}, fmt.Errorf("%w: %q", errUpstreamForm, s)
	}
	// A port follows the last colon that comes after any closing bracket.
	if strings.LastIndex(hostPort, ":") <= strings.LastIndex(hostPort, "]") {
		hostPort += ":" + strconv.Itoa(DefaultDoTPort)
	}
	ap, err := netip.ParseAddrPort(hostPort)
	if err != nil {
		return Upstream{}, fmt.Errorf("%w: %q", errBadAddress, rest)
	}
	if ap, err = normalizeAddrPort(ap); err != nil {
		return Upstream{}, err
	}
	d, err := ParseDomain(name)
	if err != nil {
		return Upstream{}, err
	}
	return Upstream{Addr: ap, ServerName: d}, nil
}

func (a rawAddrBook) validate() (AddrBook, error) {
	if a.Retain == nil {
		return AddrBook{Retain: DefaultRetain}, nil
	}
	d, err := parseDuration(*a.Retain)
	if err != nil {
		return AddrBook{}, at("retain", fmt.Errorf("%w: %q", err, *a.Retain))
	}
	if d <= 0 {
		return AddrBook{}, at("retain", errNotPositive)
	}
	return AddrBook{Retain: d}, nil
}

// parseDuration accepts the Go syntax and a whole number of days ("7d").
func parseDuration(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		const day = int64(24 * time.Hour)
		n, err := strconv.ParseInt(days, 10, 64)
		if err != nil || n > math.MaxInt64/day || n < math.MinInt64/day {
			return 0, errBadDuration
		}
		return time.Duration(n * day), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, errBadDuration
	}
	return d, nil
}

func (rp rawPolicy) validate() (Policy, error) {
	name, err := parseName(rp.Name)
	if err != nil {
		return Policy{}, at("name", err)
	}
	if len(rp.To) == 0 {
		return Policy{}, at("to", errToEmpty)
	}
	p := Policy{Name: name}
	seen := make(map[Destination]struct{}, len(rp.To))
	for i, s := range rp.To {
		d, err := ParseDestination(s)
		if err != nil {
			return Policy{}, at(fmt.Sprintf("to[%d]", i), err)
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		p.To = append(p.To, d)
	}
	if p.Constraint, err = rp.constraint(); err != nil {
		return Policy{}, err
	}
	if rp.Scope != nil {
		if p.Scope, err = rp.Scope.validate(); err != nil {
			return Policy{}, at("scope", err)
		}
	}
	return p, nil
}

func (rs rawScope) validate() (Scope, error) {
	users, err := parseAccounts(rs.Users)
	if err != nil {
		return Scope{}, at("users", err)
	}
	groups, err := parseAccounts(rs.Groups)
	if err != nil {
		return Scope{}, at("groups", err)
	}
	return NewScope(users, groups)
}

func parseAccounts(in []string) ([]Account, error) {
	var out []Account
	for i, s := range in {
		a, err := ParseAccount(s)
		if err != nil {
			return nil, at(fmt.Sprintf("[%d]", i), err)
		}
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out, nil
}

func (rp rawPolicy) constraint() (Constraint, error) {
	switch {
	case rp.OnlyVia != nil && rp.DenyVia == nil:
		sels, err := parseSelectors(*rp.OnlyVia)
		if err != nil {
			return nil, at("only_via", err)
		}
		return NewOnlyVia(sels...), nil
	case rp.DenyVia != nil && rp.OnlyVia == nil:
		sels, err := parseSelectors(*rp.DenyVia)
		if err != nil {
			return nil, at("deny_via", err)
		}
		c, err := NewDenyVia(sels...)
		if err != nil {
			return nil, at("deny_via", err)
		}
		return c, nil
	default:
		return nil, at("only_via/deny_via", errViaConflict)
	}
}

func parseSelectors(in []string) ([]InterfaceSelector, error) {
	out := make([]InterfaceSelector, 0, len(in))
	seen := make(map[InterfaceSelector]struct{}, len(in))
	for i, s := range in {
		sel, err := ParseInterfaceSelector(s)
		if err != nil {
			return nil, at(fmt.Sprintf("[%d]", i), err)
		}
		if _, dup := seen[sel]; dup {
			continue
		}
		seen[sel] = struct{}{}
		out = append(out, sel)
	}
	return out, nil
}
