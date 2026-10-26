package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// ProbeInterval is the time between two probe names of one probe.
const ProbeInterval = 50 * time.Millisecond

// errProbe means that ifbound-dns reported no probe name below the domain
// in the time budget of the probe: the queries for the domain do not go
// to ifbound-dns, or not yet.
var errProbe = errors.New("daemon: probe not seen by ifbound-dns")

// probeWait is one probe of one domain: the probe names that it sent, and
// a channel that closes when ifbound-dns reports one of them.
type probeWait struct {
	seen   chan struct{}
	closed bool
	names  []string
}

// probe resolves a new probe name below domain every ProbeInterval until
// ifbound-dns reports one of the names, or ctx ends. A report of an
// earlier name of the same probe also counts: it can arrive late. It runs
// on the goroutine of the caller. The caller sets the budget: a ctx
// without a deadline is an error at once, so that no probe runs without
// a bound.
func (d *Daemon) probe(ctx context.Context, domain policy.Domain) error {
	if _, ok := ctx.Deadline(); !ok {
		return fmt.Errorf("%w: %s: ctx has no deadline", errProbe, domain)
	}
	w := &probeWait{seen: make(chan struct{})}
	defer d.dropProbe(w)
	for {
		name, err := probeName(domain)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", errProbe, domain, err)
		}
		d.addProbe(w, name)
		// Only the report of ifbound-dns counts, so the answer and the
		// error tell nothing here.
		_, _ = d.cfg.Lookup.Resolve(ctx, name) //nolint:errcheck // only the ifbound-dns report counts
		select {
		case <-w.seen:
			return nil
		default:
		}
		select {
		case <-w.seen:
			return nil
		case <-ctx.Done():
			return fmt.Errorf("%w: %s: %v", errProbe, domain, ctx.Err())
		case <-time.After(ProbeInterval):
		}
	}
}

// probeName returns a new probe name below domain, in canonical form. The
// nonce is random, so no cache holds an answer for the name, and no other
// process can send it before the daemon does.
func probeName(domain policy.Domain) (string, error) {
	var b [8]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails
	n, err := dnsname.Parse(ipc.ProbePrefix + hex.EncodeToString(b[:]) + "." + domain.String())
	if err != nil {
		return "", fmt.Errorf("probe name: %w", err)
	}
	return n.String(), nil
}

func (d *Daemon) addProbe(w *probeWait, name string) {
	d.probesMu.Lock()
	defer d.probesMu.Unlock()
	w.names = append(w.names, name)
	d.probes[name] = w
}

func (d *Daemon) dropProbe(w *probeWait) {
	d.probesMu.Lock()
	defer d.probesMu.Unlock()
	for _, n := range w.names {
		delete(d.probes, n)
	}
}

// ProbeSeen implements ipc.ProbeHandler: ifbound-dns got the probe name
// qname. A name that no probe waits for, a malformed one included, has no
// effect. ProbeSeen never waits for the loop.
func (d *Daemon) ProbeSeen(qname string) {
	n, err := dnsname.Parse(qname)
	if err != nil {
		return
	}
	d.probesMu.Lock()
	defer d.probesMu.Unlock()
	if w := d.probes[n.String()]; w != nil && !w.closed {
		w.closed = true
		close(w.seen)
	}
}
