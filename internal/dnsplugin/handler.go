package dnsplugin

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
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
	errQuestions  = errors.New("query does not have exactly one question")
	errNoSubReply = errors.New("next plugin wrote no reply to a query of the plugin")
	errIncomplete = errors.New("CNAME chain cannot be completed")
)

// chaseTimeout bounds the queries for the rest of a CNAME chain that
// stops early in the upstream reply. forward waits up to 2 s for each
// attempt (its read timeout) and does not stop an attempt when the
// context ends; it gives up after 5 s. A budget of 5 s thus lets a
// query survive one lost packet: one attempt that times out, and one
// more. The ack wait (defaultTimeout) comes on top. Only a reply whose
// chain stops before its end needs these queries.
const chaseTimeout = 5 * time.Second

// reporter sends an observation to ifboundd. A nil error means ifboundd
// acknowledged it, and the Ack tells if the name is protected. Report
// must return when ctx ends; *ipc.Client does.
type reporter interface {
	Report(ctx context.Context, o ipc.Observation) (ipc.Ack, error)
}

// prober tells ifboundd that a probe name reached ifbound-dns. Report
// must return when ctx ends, and it must not share the in-flight slots of
// reporter; *ipc.Client does both.
type prober interface {
	ReportProbe(ctx context.Context, qname string) error
}

// handler holds back the reply of the next plugin until ifboundd has the
// addresses in it.
type handler struct {
	next     plugin.Handler
	reporter reporter
	probes   prober
	timeout  time.Duration
	// key makes and checks the synthetic names. All handlers of the
	// process share it (see clients).
	key *tagKey
}

// Name implements plugin.Handler.
func (h *handler) Name() string { return name }

// ServeDNS implements plugin.Handler. The rule is: every A, AAAA, and SVCB or
// HTTPS hint address that the client gets, in any section, is reported first
// under the qname (see observation). Otherwise the client gets SERVFAIL.
//
// The handler works in two phases. First it reports the reply of the next
// plugin. A reply without an address and without a name that a client
// follows (see followsName) needs no report and goes out as it is, so a
// negative answer passes also while ifboundd is down. When the ack says
// that the qname is not protected, the client gets the reply of the next
// plugin byte for byte: the plugin sends no other query for it. When the
// ack says protected, the client gets the flattened reply (see flatten):
// it has no alias name of the qname, so the client never looks up an
// alias outside the resolver entry of the protected name. To flatten, the
// plugin first asks for the rest of a CNAME chain that stops early (see
// exchange.complete), and it reports the addresses that the flattened
// reply adds before it sends that reply. When the plugin cannot flatten
// the reply, the client gets SERVFAIL.
//
// A synthetic name (see synth.go) goes to exchange.serveSynthetic.
//
// The handler answers the resolver.arpa zone of the DDR probe and the
// Firefox canary domain itself (see localRcode). Those queries do not go to the next plugin.
//
// A probe name of ifboundd (see ipc.IsProbe) also stays here: the handler
// sends it to ifboundd and then answers NXDOMAIN. The probe proves to
// ifboundd that the system resolver sends the queries for its domain to
// ifbound-dns, so it must not go upstream, and the report comes before
// the reply: ifboundd has it when the system resolver returns.
//
// The handler inspects the reply as the client will decode it: it packs the
// reply when the next plugin writes it, unpacks those bytes, reports the
// addresses in the result, and sends that result. Thus a Go
// value that packs to a different record type cannot carry an address past
// the report, and a change to the message after the write has no effect.
// The server writes the reply through a writer that truncates it to the
// size limit of the client. A truncation only removes records, so the
// report still covers every address that reaches the client.
//
// SERVFAIL follows the CoreDNS contract: ServeDNS writes nothing and returns
// dns.RcodeServerFailure, and the server writes the error reply. After a
// write, ServeDNS returns the rcode of the written reply, or success for
// an rcode that tells the server to write an error reply itself.
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
		// the client to go around ifbound-dns. The reply has no address,
		// so it needs no report.
		return h.writeLocal(w, r, rcode)
	}
	if len(r.Question) != 1 {
		return dns.RcodeServerFailure, plugin.Error(name, errQuestions)
	}
	question := slices.Clone(r.Question)
	defer func() { r.Question = question }()
	x := &exchange{h: h, w: w, r: r, q: question[0]}
	syn, isSyn, err := h.key.parse(qname)
	switch {
	case err != nil:
		return dns.RcodeServerFailure, plugin.Error(name, err)
	case isSyn:
		return x.serveSynthetic(ctx, syn)
	}

	nr, cerr := x.ask(ctx, r)
	switch {
	case cerr != nil:
		return dns.RcodeServerFailure, plugin.Error(name, cerr)
	case nr.msg == nil && plugin.ClientWrite(nr.rcode):
		return dns.RcodeServerFailure, plugin.Error(name, errors.Join(errNoReply, nr.err))
	case nr.msg == nil:
		return nr.rcode, nr.err // the server writes the error reply; it has no address
	}

	out, aerr := x.answer(ctx, nr.msg)
	if aerr != nil {
		return dns.RcodeServerFailure, plugin.Error(name, aerr)
	}
	if werr := w.WriteMsg(out); werr != nil {
		return dns.RcodeServerFailure, plugin.Error(name, errors.Join(werr, nr.err))
	}
	return writtenRcode(out), nr.err
}

// writtenRcode is the rcode that ServeDNS returns after it wrote m. An
// rcode that says "not written" would make the server write a second
// reply, so it becomes success, as in the acl plugin.
func writtenRcode(m *dns.Msg) int {
	if !plugin.ClientWrite(m.Rcode) {
		return dns.RcodeSuccess
	}
	return m.Rcode
}

// exchange is one client query. q is the question as the client asked it:
// a plugin below can change r.Question in place.
type exchange struct {
	h *handler
	w dns.ResponseWriter
	r *dns.Msg
	q dns.Question
}

// answer reports reply and returns the reply for the client: reply itself
// when the name is not protected, else its flattened form.
func (x *exchange) answer(ctx context.Context, reply *dns.Msg) (*dns.Msg, error) {
	obs, err := observation(x.q.Name, reply)
	if err != nil {
		return nil, err
	}
	if len(obs.Addrs) == 0 && !followsName(reply) {
		return reply, nil // nothing to block, and nothing to flatten
	}
	ack, err := x.h.report(ctx, obs)
	switch {
	case err != nil:
		return nil, err
	case !ack.Protected:
		return reply, nil
	}
	flat, err := x.flatten(ctx, x.q.Name, reply)
	if err != nil {
		return nil, err
	}
	if err := x.reportAdded(ctx, x.q.Name, obs.Addrs, flat); err != nil {
		return nil, err
	}
	return flat, nil
}

// reportAdded reports under name the addresses of flat that are not in
// reported: the addresses that the queries for the rest of the chain
// gave. Without such an address, it reports nothing.
func (x *exchange) reportAdded(ctx context.Context, name string, reported []netip.Addr, flat *dns.Msg) error {
	obs, err := observation(name, flat)
	if err != nil {
		return err
	}
	obs.Addrs = slices.DeleteFunc(obs.Addrs, func(a netip.Addr) bool { return slices.Contains(reported, a) })
	if len(obs.Addrs) == 0 {
		return nil
	}
	_, err = x.h.report(ctx, obs)
	return err
}

// serveSynthetic answers a synthetic name: it asks the next plugin for the
// target, flattens the reply below the synthetic name, and reports the
// addresses under the origin that the name comes from. The reply is
// flattened also when the ack says that the origin is not protected: the
// synthetic name exists only in flattened form.
func (x *exchange) serveSynthetic(ctx context.Context, syn synthetic) (int, error) {
	origin, err := x.h.key.reportName(syn.origin)
	if err != nil {
		return dns.RcodeServerFailure, plugin.Error(name, err)
	}
	if rcode, ok := localRcode(syn.target); ok {
		// The target must not go upstream for the same reasons as the
		// name itself (see localRcode).
		return x.h.writeLocal(x.w, x.r, rcode)
	}
	// The query for the target takes the place of the query of the
	// client, so it gets the same time as a query of the client: no
	// deadline of the plugin.
	q := x.q
	q.Name = syn.target
	up, err := x.resolve(ctx, q)
	if err != nil {
		return dns.RcodeServerFailure, plugin.Error(name, err)
	}
	flat, err := x.flatten(ctx, syn.target, up)
	if err != nil {
		return dns.RcodeServerFailure, plugin.Error(name, err)
	}
	obs, err := observation(origin, flat)
	if err != nil {
		return dns.RcodeServerFailure, plugin.Error(name, err)
	}
	if len(obs.Addrs) > 0 {
		if _, err := x.h.report(ctx, obs); err != nil {
			return dns.RcodeServerFailure, plugin.Error(name, err)
		}
	}
	if err := x.w.WriteMsg(flat); err != nil {
		return dns.RcodeServerFailure, plugin.Error(name, err)
	}
	return writtenRcode(flat), nil
}

// flatten completes the chain of m from start, flattens it for the client
// question, and returns the result as the client decodes it.
func (x *exchange) flatten(ctx context.Context, start string, m *dns.Msg) (*dns.Msg, error) {
	cctx, cancel := context.WithTimeout(ctx, chaseTimeout)
	defer cancel()
	full, err := x.complete(cctx, start, m)
	if err != nil {
		return nil, err
	}
	flat, err := flatten(x.h.key, x.q.Name, start, x.q.Qtype, full)
	if err != nil {
		return nil, err
	}
	flat.Id = x.r.Id
	flat.Question = []dns.Question{x.q}
	wire, err := flat.Pack()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errUnreadable, err)
	}
	out := new(dns.Msg)
	if err := out.Unpack(wire); err != nil {
		return nil, fmt.Errorf("%w: %v", errUnreadable, err)
	}
	out.Compress = flat.Compress
	return out, nil
}

// complete asks the next plugin for the rest of the chain of m from start
// until m answers the chain end (see pendingName). Each answer must
// extend the chain, and the chain has at most maxChainLinks links, so the
// loop ends.
//
// A reply without a record for the end and without a SOA is NODATA. A
// truncated reply makes m truncated: the client then asks again over
// TCP, and the next plugin asks the rest over TCP too.
func (x *exchange) complete(ctx context.Context, start string, m *dns.Msg) (*dns.Msg, error) {
	for range maxChainLinks + 1 {
		end, pending, err := pendingName(start, x.q.Qtype, m)
		if err != nil || !pending {
			return m, err
		}
		sub, err := x.resolve(ctx, dns.Question{Name: end, Qtype: x.q.Qtype, Qclass: x.q.Qclass})
		switch {
		case err != nil:
			return nil, err
		case sub.Truncated:
			out := m.Copy()
			out.Truncated = true
			return out, nil
		case sub.Rcode != dns.RcodeSuccess && sub.Rcode != dns.RcodeNameError:
			return nil, fmt.Errorf("%w: reply for %s has rcode %s", errIncomplete, end, dns.RcodeToString[sub.Rcode])
		}
		next := merge(m, sub)
		if again, pending, _ := pendingName(start, x.q.Qtype, next); pending && sameName(again, end) {
			return next, nil // NODATA without a SOA
		}
		m = next
	}
	return nil, errChainTooLong
}

// resolve asks the next plugin q with the flags and EDNS options of the
// client request, and returns the reply as the client would decode it.
func (x *exchange) resolve(ctx context.Context, q dns.Question) (*dns.Msg, error) {
	sub := x.r.Copy()
	sub.Id = dns.Id()
	sub.Question = []dns.Question{q}
	nr, cerr := x.ask(ctx, sub)
	switch {
	case cerr != nil:
		return nil, cerr
	case nr.msg == nil:
		return nil, fmt.Errorf("%w: %s, rcode %s: %v", errNoSubReply, q.Name, dns.RcodeToString[nr.rcode], nr.err)
	case ctx.Err() != nil:
		return nil, fmt.Errorf("%w: %s: %w", errIncomplete, q.Name, ctx.Err())
	}
	return nr.msg, nil
}

// nextReply is what the next plugin did with one query.
type nextReply struct {
	msg   *dns.Msg // as the client decodes it; nil when it wrote none
	rcode int
	err   error
}

// ask runs the next plugin for req. The error is a broken write of the
// next plugin (see captureWriter), joined with the error of the next
// plugin.
func (x *exchange) ask(ctx context.Context, req *dns.Msg) (nextReply, error) {
	cw := &captureWriter{ResponseWriter: x.w}
	rcode, err := plugin.NextOrFailure(name, x.h.next, ctx, cw, req)
	msg, cerr := cw.reply()
	if cerr != nil {
		return nextReply{}, errors.Join(cerr, err)
	}
	return nextReply{msg: msg, rcode: rcode, err: err}, nil
}

// writeLocal answers r with rcode and no records (see localReply).
func (h *handler) writeLocal(w dns.ResponseWriter, r *dns.Msg, rcode int) (int, error) {
	if err := w.WriteMsg(localReply(r, rcode)); err != nil {
		return dns.RcodeServerFailure, plugin.Error(name, err)
	}
	return rcode, nil
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
func (h *handler) report(ctx context.Context, o ipc.Observation) (ipc.Ack, error) {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	ack, err := h.reporter.Report(ctx, o)
	if err != nil {
		return ipc.Ack{}, err
	}
	// A reporter that ignores ctx can return nil after the deadline. That
	// is not an ack in time, so the reply does not go out. This check does
	// not make the wait shorter: only a reporter that honors ctx does that.
	if err := ctx.Err(); err != nil {
		return ipc.Ack{}, fmt.Errorf("%w: %w", errLateAck, err)
	}
	return ack, nil
}

// captureWriter keeps the reply of the next plugin in wire form and passes
// no write through. The handler writes the reply itself after the report.
type captureWriter struct {
	dns.ResponseWriter

	mu       sync.Mutex
	wire     []byte
	compress bool
	written  bool
	err      error
	closed   bool
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
	c.compress = m.Compress
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

// reply ends the capture and returns the reply as the client decodes it,
// or nil when the next plugin wrote none. The reply keeps the compression
// flag of the next plugin, so an unchanged reply packs to the same bytes.
func (c *captureWriter) reply() (*dns.Msg, error) {
	wire, err := c.close()
	if err != nil || wire == nil {
		return nil, err
	}
	m := new(dns.Msg)
	if err := m.Unpack(wire); err != nil {
		return nil, fmt.Errorf("%w: %v", errUnreadable, err)
	}
	m.Compress = c.compress
	return m, nil
}
