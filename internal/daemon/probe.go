package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// probeWait is one probe of one alias: the probe names that it sent, and
// a channel that closes when ifbound-dns reports one of them.
type probeWait struct {
	seen   chan struct{}
	closed bool
	names  []string
}

// prove probes the entry of each alias in turn, on the goroutine of the
// caller. The probes share the budget of ctx less AckReserve. The entries
// were written together, so the system applies them together, and the
// probes after the first one usually succeed at once.
func (d *Daemon) prove(ctx context.Context, aliases []alias) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(ipc.DefaultTimeout)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline.Add(-AckReserve))
	defer cancel()
	for _, a := range aliases {
		if err := d.probe(ctx, a.domain); err != nil {
			return err
		}
	}
	return nil
}

// probe resolves a new probe name below domain every ProbeInterval until
// ifbound-dns reports one of the names, or ctx ends. A report of an
// earlier name of the same probe also counts: it can arrive late.
func (d *Daemon) probe(ctx context.Context, domain policy.Domain) error {
	w := &probeWait{seen: make(chan struct{})}
	defer d.dropProbe(w)
	for {
		name, err := probeName(domain)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrAliasProbe, domain, err)
		}
		d.addProbe(w, name)
		// Only the report of ifbound-dns counts, so the answer and the
		// error tell nothing here.
		_, _ = d.cfg.Lookup.Resolve(ctx, name)
		select {
		case <-w.seen:
			return nil
		default:
		}
		select {
		case <-w.seen:
			return nil
		case <-ctx.Done():
			return fmt.Errorf("%w: %s: %v", ErrAliasProbe, domain, ctx.Err())
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
