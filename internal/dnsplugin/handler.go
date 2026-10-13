package dnsplugin

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

var (
	errNoReply    = errors.New("next plugin claimed a reply but wrote none")
	errTwoReplies = errors.New("next plugin wrote more than one reply")
	errRawWrite   = errors.New("next plugin wrote raw bytes")
	errLateWrite  = errors.New("next plugin wrote after it returned")
	errLateAck    = errors.New("ack came after the deadline")
	errUnreadable = errors.New("reply does not survive the wire format")
)

// reporter sends an observation to ifboundd. A nil return means ifboundd
// acknowledged it. Report must return when ctx ends; *ipc.Client does.
type reporter interface {
	Report(ctx context.Context, o ipc.Observation) error
}

// prober tells ifboundd that a probe name reached ifbound-dns. Report
// must return when ctx ends, and it must not share the in-flight slots of
// reporter; *ipc.Client does both.
type prober interface {
	ReportProbe(ctx context.Context, qname string) error
}

// handler holds back the reply of the next plugin until ifboundd has the
// addresses and alias names in it.
type handler struct {
	next     plugin.Handler
	reporter reporter
	probes   prober
	timeout  time.Duration
}

// Name implements plugin.Handler.
func (h *handler) Name() string { return name }

// ServeDNS implements plugin.Handler. The rule is: every A, AAAA, and SVCB or
// HTTPS hint address that the client gets, in any section, is reported first
// under the qname, together with every alias name in the reply (see
// observation). Otherwise the client gets SERVFAIL. A reply without an
// address and without an alias goes out without a report.
//
// The handler answers the resolver.arpa zone of the DDR probe and the
// Firefox canary domain itself (see localRcode). Those queries do not go to the next plugin.
//
// A probe name of ifboundd (see ipc.IsProbe) also stays here: the handler
// sends it to ifboundd and then answers NXDOMAIN. The probe proves to
// ifboundd that the system resolver sends the queries for the alias to
// ifbound-dns, so it must not go upstream, and the report comes before
// the reply: ifboundd has it when the system resolver returns.
//
// The handler inspects the reply as the client will decode it: it packs the
// reply when the next plugin writes it, unpacks those bytes, reports the
// addresses and aliases in the result, and sends that result. Thus a Go
// value that packs to a different record type cannot carry an address past
// the report, and a change to the message after the write has no effect.
//
// SERVFAIL follows the CoreDNS contract: ServeDNS writes nothing and returns
// dns.RcodeServerFailure, and the server writes the error reply.
func (h *handler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// A plugin below can change the question in place (rewrite does). The
	// report and the server's error reply must carry the question that the
	// client asked.
	qname := (&request.Request{Req: r}).QName()
	if ipc.IsProbe(qname) {
		return h.serveProbe(ctx, w, r, qname)
	}
	if rcode, ok := localRcode(qname); ok {
		// No plugin below sees the query, so no upstream answer can tell
		// the client to go around ifbound-dns. The reply has no address
		// and no alias, so it needs no report.
		if err := w.WriteMsg(localReply(r, rcode)); err != nil {
			return dns.RcodeServerFailure, plugin.Error(name, err)
		}
		return rcode, nil
	}
	question := slices.Clone(r.Question)
	defer func() { r.Question = question }()

	cw := &captureWriter{ResponseWriter: w}
	rcode, err := plugin.NextOrFailure(name, h.next, ctx, cw, r)
	wire, cerr := cw.close()
	if cerr != nil {
		return dns.RcodeServerFailure, plugin.Error(name, errors.Join(cerr, err))
	}
	if wire == nil {
		if plugin.ClientWrite(rcode) {
			return dns.RcodeServerFailure, plugin.Error(name, errors.Join(errNoReply, err))
		}
		return rcode, err // the server writes the error reply; it has no address
	}

	reply := new(dns.Msg)
	if uerr := reply.Unpack(wire); uerr != nil {
		return dns.RcodeServerFailure, plugin.Error(name, fmt.Errorf("%w: %v", errUnreadable, uerr))
	}
	obs, found, oerr := observation(qname, reply)
	if oerr != nil {
		return dns.RcodeServerFailure, plugin.Error(name, oerr)
	}
	if found {
		if rerr := h.report(ctx, obs); rerr != nil {
			return dns.RcodeServerFailure, plugin.Error(name, rerr)
		}
	}

	if werr := w.WriteMsg(reply); werr != nil {
		return dns.RcodeServerFailure, plugin.Error(name, errors.Join(werr, err))
	}
	if !plugin.ClientWrite(rcode) {
		// The reply is written now. An rcode that says "not written" would
		// make the server write a second reply.
		rcode = dns.RcodeSuccess
	}
	return rcode, err
}

// serveProbe reports a probe name and answers it with NXDOMAIN. A failed
// report does not change the answer: ifboundd only counts the report.
// The error goes to the server log.
func (h *handler) serveProbe(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, qname string) (int, error) {
	pctx, cancel := context.WithTimeout(ctx, h.timeout)
	perr := h.probes.ReportProbe(pctx, qname)
	cancel()
	if err := w.WriteMsg(localReply(r, dns.RcodeNameError)); err != nil {
		return dns.RcodeServerFailure, plugin.Error(name, errors.Join(err, perr))
	}
	if perr != nil {
		return dns.RcodeNameError, plugin.Error(name, perr)
	}
	return dns.RcodeNameError, nil
}

// report waits for the ack at most h.timeout, and less when ctx ends first.
func (h *handler) report(ctx context.Context, o ipc.Observation) error {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	if err := h.reporter.Report(ctx, o); err != nil {
		return err
	}
	// A reporter that ignores ctx can return nil after the deadline. That
	// is not an ack in time, so the reply does not go out. This check does
	// not make the wait shorter: only a reporter that honors ctx does that.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", errLateAck, err)
	}
	return nil
}

// captureWriter keeps the reply of the next plugin in wire form and passes
// no write through. The handler writes the reply itself after the report.
type captureWriter struct {
	dns.ResponseWriter

	mu      sync.Mutex
	wire    []byte
	written bool
	err     error
	closed  bool
}

// WriteMsg packs m. The packed bytes are the snapshot that the handler
// inspects and sends.
func (c *captureWriter) WriteMsg(m *dns.Msg) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.closed:
		return errLateWrite
	case c.written:
		c.err = errTwoReplies
		return c.err
	}
	c.written = true
	wire, err := m.Pack()
	if err != nil {
		c.err = fmt.Errorf("%w: %v", errUnreadable, err)
		return c.err
	}
	c.wire = wire
	return nil
}

// Write refuses raw bytes. The plugins in front of an upstream write a
// dns.Msg.
func (c *captureWriter) Write([]byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.err = errRawWrite
	}
	return 0, errRawWrite
}

// close ends the capture and returns the packed reply, or nil when the next
// plugin wrote none. Later writes fail.
func (c *captureWriter) close() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return c.wire, c.err
}
