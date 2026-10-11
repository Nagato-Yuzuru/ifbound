//go:build darwin && !netgo

package syslookup

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
)

// mdnsSocket is the socket where mDNSResponder accepts client requests.
const mdnsSocket = "/var/run/mDNSResponder"

// Resolve asks the system resolver for the A and AAAA records of name and
// returns the addresses in the form of Normalize. A name without a final
// dot gets one, so search domains do not apply.
//
// Resolve honors ctx. The caller sets its budget as the deadline of ctx;
// Resolve also stops after maxWait as a backstop. When Resolve returns
// before getaddrinfo returns, the call continues on its own goroutine and
// OS thread until getaddrinfo returns. The net package limits the number
// of such calls in one process (at most 500, less with a low
// RLIMIT_NOFILE). When all slots are in use, a new call waits for a slot
// or for ctx.
//
// Errors: see ErrNotFound and ErrUnavailable. A done context gives an
// error that wraps ctx.Err().
func (Resolver) Resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	fqdn, err := absName(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()
	// On darwin, the net package prefers libSystem getaddrinfo to its own
	// DNS client, and getaddrinfo does not call Dial. Only the pure-Go
	// resolver calls Dial, and then the lookup fails before a query goes
	// out.
	var dialed atomic.Bool
	r := &net.Resolver{Dial: func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, errGoResolver
	}}
	addrs, err := r.LookupNetIP(ctx, "ip", fqdn)
	if dialed.Load() {
		return nil, fmt.Errorf("resolve %s: %w", fqdn, errGoResolver)
	}
	if err != nil {
		return nil, classify(ctx, fqdn, err, probeMDNS)
	}
	return Normalize(addrs), nil
}

// probeMDNS connects to the mDNSResponder socket and closes the
// connection at once.
func probeMDNS(ctx context.Context) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", mdnsSocket)
	if err != nil {
		return err
	}
	return c.Close()
}
