// Package policy parses the ifbound configuration file into typed values.
//
// The parser is strict. It rejects any key it does not know, so a typo
// never turns into a silently missing rule. The package does no file or
// network I/O: the caller supplies the bytes.
//
// Parse is the only way to build a valid Config. The constructors build
// valid values for the sum types. The zero value of a sum-type variant
// (DenyVia{}, InterfaceClass{}, ExactDomain{} and so on) is invalid: the
// zero OnlyVia is the one exception, and it means "always blocked".
package policy

import (
	"net/netip"
	"slices"
	"time"
)

const (
	// DefaultListen is the DNS listen address when [dns] has no listen key.
	DefaultListen = "127.0.0.1:10053"
	// DefaultRetain is how long the address book keeps an entry when
	// [addrbook] has no retain key.
	DefaultRetain = 7 * 24 * time.Hour
	// DefaultDoTPort is the port of an upstream that names no port.
	DefaultDoTPort = 853
)

// Config is a parsed and validated configuration file.
type Config struct {
	DNS      DNS
	AddrBook AddrBook
	Policies []Policy // in file order
}

// DNS holds the [dns] table.
type DNS struct {
	Listen   netip.AddrPort // never port 0, never zoned
	Upstream []Upstream     // never empty
}

// Upstream is one DNS-over-TLS forwarder.
type Upstream struct {
	Addr netip.AddrPort // never port 0, never zoned
	// ServerName is the name that the TLS certificate must match.
	ServerName Domain
}

// AddrBook holds the [addrbook] table.
type AddrBook struct {
	Retain time.Duration // always greater than zero
}

// Name identifies a policy. Parse guarantees 1 to 24 bytes of
// [a-z0-9_-] that start with a letter or digit, and uniqueness inside one
// Config. The limit leaves room for the prefix that the firewall compiler
// adds to a pf table name.
type Name string

// Policy is one [[policy]] entry: traffic to any of To must obey Constraint.
// The zero Policy is not valid: its Constraint is nil. Use only the
// Policy values that Parse returns.
type Policy struct {
	Name       Name
	To         []Destination // never empty, no duplicates
	Constraint Constraint    // never nil
}

// Destination is what a policy matches. Build one with ParseDestination.
//
//sumtype:decl
type Destination interface{ isDestination() }

// ExactDomain matches one domain name.
type ExactDomain struct{ domain Domain }

// DomainSuffix matches the domain and every name below it (the pattern
// "*.x" matches x too).
type DomainSuffix struct{ domain Domain }

// IPAddr matches one IP address. The address is never IPv4-mapped IPv6
// and never zoned.
type IPAddr struct{ addr netip.Addr }

// CIDR matches every address in a prefix. The prefix is masked, never
// IPv4-mapped IPv6 and never zoned.
type CIDR struct{ prefix netip.Prefix }

// Domain returns the matched domain.
func (d ExactDomain) Domain() Domain { return d.domain }

// Domain returns the domain at the root of the suffix.
func (d DomainSuffix) Domain() Domain { return d.domain }

// Addr returns the matched address.
func (a IPAddr) Addr() netip.Addr { return a.addr }

// Prefix returns the matched prefix.
func (c CIDR) Prefix() netip.Prefix { return c.prefix }

func (ExactDomain) isDestination()  {}
func (DomainSuffix) isDestination() {}
func (IPAddr) isDestination()       {}
func (CIDR) isDestination()         {}

// InterfaceSelector names a set of network interfaces. Build one with
// ParseInterfaceSelector.
//
//sumtype:decl
type InterfaceSelector interface{ isInterfaceSelector() }

// InterfaceName selects one interface by exact name, for example "en0".
type InterfaceName struct{ name string }

// InterfaceGlob selects interfaces whose name matches a path.Match
// pattern, for example "utun*".
type InterfaceGlob struct{ pattern string }

// InterfaceClass selects a class of interface, for example "@tunnel".
// This package does not map a class to real interfaces.
type InterfaceClass struct{ class Class }

// Name returns the interface name.
func (n InterfaceName) Name() string { return n.name }

// Pattern returns the glob pattern.
func (g InterfaceGlob) Pattern() string { return g.pattern }

// Class returns the interface class. It is always a known Class.
func (c InterfaceClass) Class() Class { return c.class }

func (InterfaceName) isInterfaceSelector()  {}
func (InterfaceGlob) isInterfaceSelector()  {}
func (InterfaceClass) isInterfaceSelector() {}

// Class is a known interface class. The config spells it with a leading
// "@". The zero value is not a class.
type Class uint8

// The known interface classes.
const (
	ClassHardware Class = iota + 1
	ClassTunnel
)

// String returns the config spelling without the "@".
func (c Class) String() string {
	switch c {
	case ClassHardware:
		return "hardware"
	case ClassTunnel:
		return "tunnel"
	default:
		return "unknown"
	}
}

// Constraint limits the interfaces that matching traffic may use.
//
// A Constraint holds slices, so comparing two of them with == panics at
// run time. Use Equal instead. A comparable form would need the selector
// list encoded into a key, which makes the type harder to read for no
// current caller.
//
//sumtype:decl
type Constraint interface {
	isConstraint()
	// Selectors returns a copy of the selector list.
	Selectors() []InterfaceSelector
	// Equal reports whether c and other are the same variant with the
	// same selectors in the same order.
	Equal(other Constraint) bool
}

// OnlyVia allows matching traffic on the listed interfaces only. The zero
// value has no selector: the traffic is always blocked.
type OnlyVia struct{ selectors []InterfaceSelector }

// DenyVia forbids matching traffic on the listed interfaces. The list is
// never empty. Build one with NewDenyVia.
type DenyVia struct{ selectors []InterfaceSelector }

// NewOnlyVia returns an OnlyVia constraint. No selector means "always
// blocked".
func NewOnlyVia(selectors ...InterfaceSelector) OnlyVia {
	if len(selectors) == 0 {
		return OnlyVia{}
	}
	return OnlyVia{selectors: slices.Clone(selectors)}
}

// NewDenyVia returns a DenyVia constraint. It fails when the list is
// empty, because the constraint would then have no effect.
func NewDenyVia(selectors ...InterfaceSelector) (DenyVia, error) {
	if len(selectors) == 0 {
		return DenyVia{}, errDenyEmpty
	}
	return DenyVia{selectors: slices.Clone(selectors)}, nil
}

func (OnlyVia) isConstraint() {}
func (DenyVia) isConstraint() {}

// Selectors returns a copy of the selector list.
func (o OnlyVia) Selectors() []InterfaceSelector { return slices.Clone(o.selectors) }

// Selectors returns a copy of the selector list.
func (d DenyVia) Selectors() []InterfaceSelector { return slices.Clone(d.selectors) }

// Equal implements Constraint.
func (o OnlyVia) Equal(other Constraint) bool {
	x, ok := other.(OnlyVia)
	return ok && slices.Equal(o.selectors, x.selectors)
}

// Equal implements Constraint.
func (d DenyVia) Equal(other Constraint) bool {
	x, ok := other.(DenyVia)
	return ok && slices.Equal(d.selectors, x.selectors)
}
