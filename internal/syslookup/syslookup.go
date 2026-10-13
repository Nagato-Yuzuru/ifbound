// Package syslookup resolves a name through the macOS system resolver
// (mDNSResponder), as an application does.
//
// The lookup goes through mDNSResponder, so its answer also goes into the
// mDNSResponder cache. A later lookup of the same name by another process
// then gets the same addresses from that cache. A DNS client that sends
// its own queries, such as the pure-Go resolver of the net package, does
// not fill that cache and is thus not a replacement.
//
// On darwin, Resolve calls libSystem getaddrinfo through the net package.
// The net package does this without cgo: it calls libSystem through its
// own trampolines. The net package can also select its pure-Go resolver,
// for example with GODEBUG=netdns=go. Resolve uses a private net.Resolver
// whose Dial always fails, so that selection gives an error, and the
// pure-Go resolver sends no query. getaddrinfo never calls Dial.
//
// On other systems, and with the netgo build tag, Resolve returns an
// error that wraps errors.ErrUnsupported. A fallback to another resolver
// would not fill the mDNSResponder cache, and that cache is the purpose
// of this package.
package syslookup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Errors of Resolve. A done context gives an error that wraps the context
// error. Each error other than ErrNotFound means that the lookup failed
// and tells nothing about the name.
var (
	// ErrNotFound means that getaddrinfo gave no addresses and reported
	// "no such name" (EAI_NONAME), and mDNSResponder accepts connections.
	// getaddrinfo reports EAI_NONAME also when the upstream server failed
	// (SERVFAIL) and for some other failures that it does not tell apart.
	// So ErrNotFound does not prove that the name has no addresses: do not
	// use it as a reason to unblock or to trust an empty answer.
	ErrNotFound = errors.New("no addresses for the name")
	// ErrUnavailable means that the lookup found no addresses and the
	// mDNSResponder socket does not accept connections. getaddrinfo then
	// reports "no such name" although no resolver answered.
	ErrUnavailable = errors.New("mDNSResponder is not available")
)

var (
	errInvalidName = errors.New("invalid name")
	errLookup      = errors.New("system resolver lookup failed")
	errGoResolver  = errors.New("the pure-Go resolver of the net package is in use, not the system resolver")
)

// maxWait is the upper bound of one Resolve call. It is a backstop: the
// caller passes its own budget as the deadline of ctx.
const maxWait = 5 * time.Second

// Resolver resolves names through the system resolver. The zero value is
// ready to use.
type Resolver struct{}

// absName returns name as an absolute DNS name. An absolute name gets no
// search domains, and a name that looks like an IP address literal (such
// as the CNAME target "192.0.2.1.") goes to the resolver as a DNS name.
func absName(name string) (string, error) {
	if name == "" || name == "." {
		return "", fmt.Errorf("resolve %q: %w", name, errInvalidName)
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name, nil
}

// classify turns a lookup error into the error set of Resolve. probe
// checks that mDNSResponder accepts connections. libSystem reports "no
// such name" also when it cannot reach mDNSResponder, so a not-found
// result is ErrNotFound only when probe succeeds. The net package gives
// the same error for an upstream SERVFAIL, so ErrNotFound can stand for
// one (see ErrNotFound).
func classify(ctx context.Context, name string, err error, probe func(context.Context) error) error {
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("resolve %s: %w", name, cerr)
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		return fmt.Errorf("resolve %s: %w: %v", name, errLookup, err)
	}
	if perr := probe(ctx); perr != nil {
		return fmt.Errorf("resolve %s: %w: no addresses, and %v", name, ErrUnavailable, perr)
	}
	return fmt.Errorf("resolve %s: %w", name, ErrNotFound)
}

// Normalize returns addrs in the form that Resolve gives: IPv4 addresses
// in their 4-byte form, sorted, with no duplicates. This is also the form
// of the address lists of the DNS plugin. The net package can give an
// IPv4 address in its IPv4-mapped IPv6 form. Normalize does not change
// addrs.
func Normalize(addrs []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, len(addrs))
	for i, a := range addrs {
		out[i] = a.Unmap()
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}
