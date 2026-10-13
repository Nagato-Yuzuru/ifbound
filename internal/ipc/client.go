package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

var (
	// ErrUnavailable means the client could not reach ifboundd or lost the
	// connection before it got a reply.
	ErrUnavailable = errors.New("ipc: server unavailable")
	// ErrRejected means ifboundd refused the observation.
	ErrRejected = errors.New("ipc: observation rejected")
)

// DefaultTimeout bounds a Report call whose context has no deadline.
const DefaultTimeout = 5 * time.Second

// Observation is one DNS answer.
type Observation struct {
	QName   string
	Addrs   []netip.Addr
	TTL     time.Duration
	Aliases []Alias
}

// Alias is a name that the answer points the client to: a CNAME target or
// an HTTPS or SVCB TargetName. The client can send a follow-up query for
// it. Name has the presentation form that the client decodes; the package
// does not canonicalize it. TTL is the largest TTL among the records that
// point to the name.
type Alias struct {
	Name string
	TTL  time.Duration
}

// Client reports observations to ifboundd. It is safe for concurrent use.
// The in-flight limit is per Client, so a process should create one Client
// and share it.
// Each call uses its own connection, so a broken connection never affects
// the next call.
type Client struct {
	path      string
	serverUID uint32
	inflight  chan struct{}
	probes    chan struct{}
}

const (
	// maxInFlight bounds the Reports that run at once. It stays below the
	// smallest common listen backlog (128), so a burst waits in the client
	// and does not overflow the server queue.
	maxInFlight = 32
	// maxProbesInFlight bounds the ReportProbe calls that run at once.
	// Probes have their own slots: while ifboundd waits for a probe, the
	// Report that waits for its ack holds a report slot, and all report
	// slots can be held so. A probe that needed one of them would wait for
	// itself.
	maxProbesInFlight = 8
)

// NewClient returns a client for the socket at path. It trusts a reply only
// from a server that runs as serverUID. Production passes 0.
func NewClient(path string, serverUID uint32) *Client {
	return &Client{
		path:      path,
		serverUID: serverUID,
		inflight:  make(chan struct{}, maxInFlight),
		probes:    make(chan struct{}, maxProbesInFlight),
	}
}

// Report sends o and waits for the ack. It returns nil only after an ack.
// The error set is: ErrUnavailable (no connection, lost connection),
// ErrRejected (the server refused; the message has the reason), ErrProtocol
// (malformed reply), ErrFrameTooLarge, and the context error when ctx ends.
// Without a ctx deadline, DefaultTimeout applies. At most maxInFlight calls
// run at once; a call that waits for a slot ends with the ctx error when ctx
// ends. The server honors waits of up to 30 seconds. A server that runs as
// another uid than the expected one gives ErrUnavailable.
func (c *Client) Report(ctx context.Context, o Observation) error {
	return c.exchange(ctx, c.inflight, o.QName, func(ctx context.Context) envelope { return newObserveEnvelope(ctx, o) })
}

// ReportProbe tells ifboundd that the probe name qname reached
// ifbound-dns (see ProbePrefix). It returns nil after ifboundd has
// recorded the name. ifboundd answers a probe at once, and a probe never
// waits for a report slot, so a ReportProbe ends also while every Report
// waits for ifboundd. The errors and the deadline are those of Report. At
// most maxProbesInFlight calls run at once.
func (c *Client) ReportProbe(ctx context.Context, qname string) error {
	return c.exchange(ctx, c.probes, qname, func(context.Context) envelope {
		return envelopeOf(typeProbe, probeBody{QName: qname})
	})
}

// exchange sends one request on its own connection, in one of slots, and
// reads the reply.
func (c *Client) exchange(ctx context.Context, slots chan struct{}, qname string, req func(context.Context) envelope) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}

	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	case <-ctx.Done():
		return fmt.Errorf("reporting %s: %w", qname, ctx.Err())
	}
	err := c.roundTrip(ctx, req(ctx))
	if err != nil && ctx.Err() != nil {
		return fmt.Errorf("reporting %s: %w", qname, ctx.Err())
	}
	return err
}

func (c *Client) roundTrip(ctx context.Context, req envelope) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer func() { _ = conn.Close() }() // read-only use after the reply; nothing to flush

	uid, err := peerUID(conn)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if uid != c.serverUID {
		return fmt.Errorf("%w: server runs as uid %d, want %d", ErrUnavailable, uid, c.serverUID)
	}

	// The context is the only source of deadlines. This keeps the context
	// error and the I/O error in the same order.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if err := writeFrame(conn, req); err != nil {
		return wrapIO(err)
	}
	reply, err := readFrame(conn)
	if err != nil {
		return wrapIO(err)
	}
	return interpretReply(reply)
}

func newObserveEnvelope(ctx context.Context, o Observation) envelope {
	addrs := make([]string, len(o.Addrs))
	for i, a := range o.Addrs {
		addrs[i] = a.String()
	}
	var aliases []aliasBody
	for _, a := range o.Aliases {
		aliases = append(aliases, aliasBody{Name: a.Name, TTLSeconds: ttlSeconds(a.TTL)})
	}
	body := observeBody{
		QName:      o.QName,
		Addrs:      addrs,
		TTLSeconds: ttlSeconds(o.TTL),
		Aliases:    aliases,
	}
	// Report sets a deadline, so ctx always has one.
	dl, _ := ctx.Deadline()
	body.TimeoutMS = min(max(time.Until(dl).Milliseconds(), 1), MaxTimeout.Milliseconds())
	return envelopeOf(typeObserve, body)
}

func ttlSeconds(d time.Duration) uint32 {
	return uint32(min(max(d/time.Second, 0), 1<<32-1)) //nolint:gosec // clamped to the uint32 range
}

// wrapIO keeps protocol errors visible and maps transport failures to
// ErrUnavailable.
func wrapIO(err error) error {
	if errors.Is(err, ErrFrameTooLarge) || errors.Is(err, ErrProtocol) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}

func interpretReply(env envelope) error {
	if env.Version != protocolVersion {
		return fmt.Errorf("%w: reply version %d", ErrProtocol, env.Version)
	}
	switch env.Type {
	case typeAck:
		return nil
	case typeReject:
		var b rejectBody
		if err := json.Unmarshal(env.Body, &b); err != nil {
			return fmt.Errorf("%w: reject body: %v", ErrProtocol, err)
		}
		return fmt.Errorf("%w: %s", ErrRejected, b.Reason)
	default:
		return fmt.Errorf("%w: reply type %q", ErrProtocol, env.Type)
	}
}
