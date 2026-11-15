package core

import (
	"slices"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/configstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/matcher"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
	"github.com/Nagato-Yuzuru/ifbound/internal/reconcile"
)

// Config is the configuration state: exactly one of Unconfigured and
// Configured. Every Configured state converges. While its book is not
// loaded, the convergence is add-only.
//
//sumtype:decl
type Config interface{ isConfig() }

// Unconfigured: the daemon has no configuration. It does not converge,
// so it keeps the platform state that it found. Err is the error of the
// load of the stored configuration, or nil before that load.
type Unconfigured struct{ Err error }

// Configured: the daemon has the configuration Active, and the address
// book is in the state Book.
type Configured struct {
	Active Active
	Book   Book
}

func (Unconfigured) isConfig() {}
func (Configured) isConfig()   {}

// Active is the configuration that the daemon uses, with what the daemon
// derives from it. A new configuration replaces it as a whole. Do not
// change its fields.
type Active struct {
	Config policy.Config
	// Digest is the digest of the stored file of Config, or zero.
	Digest  configstore.Digest
	Matcher *matcher.Matcher
	Apexes  []policy.Domain
	// Upstream is the error of the upstream check for Config, or nil.
	Upstream error
	Warnings []policy.Warning
	// Gen counts the configurations from 1. A warm-up and a host file
	// mapping belong to the generation that they started with.
	Gen uint64
}

// ConfigRead is the result of a read of the configuration: the load of
// the stored file at start, or a configuration that Apply stored. Err is
// the error of the load at start; the daemon then has no configuration.
// Digest is the digest of the stored file, or zero when no file holds
// Config.
type ConfigRead struct {
	At     time.Time
	Config policy.Config
	Digest configstore.Digest
	Err    error
}

func (e ConfigRead) at() time.Time { return e.At }

// Config returns the configuration state.
func (s State) Config() Config {
	if s.config == nil {
		return Unconfigured{}
	}
	return s.config
}

// Retain returns the retain of the book: the retain of the first good
// configuration. It is zero before that configuration.
func (s State) Retain() time.Duration { return s.retain }

// applyConfig makes the configuration of ev the active one. A good read
// asks for a convergence in every book state, and for a read of the
// accounts that its scopes name. A configured daemon keeps its book: the
// book keeps the entries of removed policies until a convergence
// installs the new ruleset. A failed read changes only a daemon without
// a configuration. It returns the trigger of the convergence, or "".
func (s State) applyConfig(ev ConfigRead, out []Effect) (State, []Effect, string) {
	before := s.Config()
	if ev.Err != nil {
		if _, ok := before.(Unconfigured); ok {
			s.config = Unconfigured{Err: ev.Err}
		}
		return s, out, ""
	}
	trigger := logattr.TriggerConfig
	var book Book = BookLoading{}
	switch c := before.(type) {
	case Unconfigured:
		if c.Err == nil && s.gen == 0 {
			trigger = logattr.TriggerStart
		}
	case Configured:
		book = c.Book
	}
	if s.gen == 0 {
		s.retain = ev.Config.AddrBook.Retain
	}
	s.gen++
	m := matcher.New(ev.Config.Policies)
	s.config = Configured{
		Active: Active{
			Config:   ev.Config,
			Digest:   ev.Digest,
			Matcher:  m,
			Apexes:   m.Apexes(),
			Upstream: ev.Config.CheckUpstreams(),
			Warnings: ev.Config.Warnings(),
			Gen:      s.gen,
		},
		Book: book,
	}
	s.selfTest = selfTestNone
	if len(WarmUpNames(ev.Config)) > 0 {
		s.selfTest = selfTestNotRun
	}
	s, out = s.readAccounts(out)
	return s, out, trigger
}

// WarmUpNames returns the names that the warm-up resolves: each exact
// destination and the domain of each suffix destination, once each, in
// the order of the configuration.
func WarmUpNames(cfg policy.Config) []policy.Domain {
	var out []policy.Domain
	seen := make(map[policy.Domain]bool)
	for _, p := range cfg.Policies {
		for _, dest := range p.To {
			var name policy.Domain
			switch d := dest.(type) {
			case policy.ExactDomain:
				name = d.Domain()
			case policy.DomainSuffix:
				name = d.Domain()
			case policy.IPAddr, policy.CIDR:
				continue // not a name
			}
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

// scopeNames returns the user names and the group names that the scopes
// of the policies list, each sorted and without duplicates.
func scopeNames(policies []policy.Policy) (users, groups []string) {
	for _, p := range policies {
		for _, u := range p.Scope.Users() {
			users = append(users, u.String())
		}
		for _, g := range p.Scope.Groups() {
			groups = append(groups, g.String())
		}
	}
	slices.Sort(users)
	slices.Sort(groups)
	return slices.Compact(users), slices.Compact(groups)
}

// selfTest is the state of the self-test of ifbound-dns for one
// configuration.
type selfTest uint8

const (
	// selfTestNone: the configuration lists no name, so no query goes
	// to ifbound-dns, and there is nothing to test.
	selfTestNone selfTest = iota
	// selfTestNotRun: no warm-up pass under the configuration has ended,
	// and no probe reached ifbound-dns.
	selfTestNotRun
	// selfTestFailed: a warm-up pass ended, and no probe reached
	// ifbound-dns.
	selfTestFailed
	// selfTestPassed: a probe reached ifbound-dns under the
	// configuration.
	selfTestPassed
)

// SelfTestResult is the latest result of the warm-up: Proved is the
// configuration generation under which a probe reached ifbound-dns, and
// Missed the generation under which a whole pass ended with no such
// probe.
type SelfTestResult struct {
	At             time.Time
	Proved, Missed uint64
}

func (e SelfTestResult) at() time.Time { return e.At }

// applySelfTest takes the result of the warm-up. Only a result for the
// active configuration counts, and a pass is final for it. It returns
// the trigger of a convergence when the self-test changed, or "".
func (s State) applySelfTest(ev SelfTestResult) (State, string) {
	c, ok := s.Config().(Configured)
	if !ok {
		return s, ""
	}
	gen, before := c.Active.Gen, s.selfTest
	switch {
	case s.selfTest == selfTestNone || s.selfTest == selfTestPassed:
	case ev.Proved == gen:
		s.selfTest = selfTestPassed
	case ev.Missed == gen:
		s.selfTest = selfTestFailed
	}
	if s.selfTest == before {
		return s, ""
	}
	return s, logattr.TriggerSelfTest
}

// selfTestProblem returns the Problem of the self-test, if there is one.
// It does not void enforcement: without ifbound-dns, a protected name
// does not resolve.
func (s State) selfTestProblem() (reconcile.Problem, bool) {
	switch s.selfTest {
	case selfTestNotRun:
		return reconcile.Problem{Text: "ifbound-dns not connected: no probe reached it yet"}, true
	case selfTestFailed:
		return reconcile.Problem{Text: "ifbound-dns not connected: no probe reached it; the self-test tries again at each self-heal"}, true
	case selfTestNone, selfTestPassed:
		return reconcile.Problem{}, false
	default:
		return reconcile.Problem{Text: "unknown self-test state"}, true
	}
}
