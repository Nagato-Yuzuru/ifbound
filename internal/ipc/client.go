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
	// ErrNoReply means the client sent the whole request and got no reply:
	// the connection was lost, or the context ended while the client
	// waited. The server can have acted on the request. An error with
	// ErrNoReply also has ErrUnavailable, unless the context ended. An
	// error from before the send never has ErrNoReply.
	ErrNoReply = errors.New("ipc: request sent, no reply")
	// ErrRejected means ifboundd refused the request. The error text has
	// the reason.
	ErrRejected = errors.New("ipc: request rejected")
)

// DefaultTimeout bounds a Report call whose context has no deadline.
const DefaultTimeout = 2 * time.Second

// Observation is one DNS answer.
type Observation struct {
	QName string
	Addrs []netip.Addr
	TTL   time.Duration
}

// Ack is the reply of ifboundd to an observation that it accepted.
type Ack struct {
	// Protected is true when the qname matches at least one policy.
	// ifbound-dns then changes the reply so that no alias name of the
	// qname reaches the client (see package dnsplugin).
	Protected bool
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
	// Probes have their own slots: a burst of Reports can hold every report
	// slot, and a probe must not wait behind them, because ifboundd waits
	// for the probe with a short budget.
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

// Report sends o and waits for the ack. It returns a nil error only with
// an ack. The error set is: ErrUnavailable (no connection, lost
// connection), ErrRejected (the server refused; the message has the
// reason), ErrProtocol (malformed reply, an ack without the protected
// flag, or a server of another protocol version), ErrFrameTooLarge, and
// the context error when ctx ends. Without a ctx deadline,
// DefaultTimeout applies. At most maxInFlight calls run at once; a call
// that waits for a slot ends with the ctx error when ctx ends. The server
// honors waits of up to 30 seconds. A server that runs as another uid
// than the expected one gives ErrUnavailable.
func (c *Client) Report(ctx context.Context, o Observation) (Ack, error) {
	body, err := c.exchange(ctx, c.inflight, o.QName, func(ctx context.Context) envelope { return newObserveEnvelope(ctx, o) })
	if err != nil {
		return Ack{}, err
	}
	return decodeAck(body)
}

// ReportProbe tells ifboundd that the probe name qname reached
// ifbound-dns (see ProbePrefix). It returns nil after ifboundd has
// recorded the name. ifboundd answers a probe at once, and a probe never
// waits for a report slot, so a ReportProbe ends also while every Report
// waits for ifboundd. The errors and the deadline are those of Report. At
// most maxProbesInFlight calls run at once.
func (c *Client) ReportProbe(ctx context.Context, qname string) error {
	_, err := c.exchange(ctx, c.probes, qname, func(context.Context) envelope {
		return envelopeOf(typeProbe, probeBody{QName: qname})
	})
	return err
}

// exchange sends one request on its own connection, in one of slots, and
// reads the reply. It returns the body of the ack.
func (c *Client) exchange(ctx context.Context, slots chan struct{}, qname string, req func(context.Context) envelope) (json.RawMessage, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}

	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	case <-ctx.Done():
		return nil, fmt.Errorf("reporting %s: %w", qname, ctx.Err())
	}
	body, err := c.roundTrip(ctx, req(ctx))
	if err != nil && ctx.Err() != nil {
		return nil, fmt.Errorf("reporting %s: %w", qname, ctx.Err())
	}
	return body, err
}

func (c *Client) roundTrip(ctx context.Context, req envelope) (json.RawMessage, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer func() { _ = conn.Close() }() //nolint:errcheck // read-only use after the reply; nothing to flush
	return exchangeOn(ctx, conn, c.serverUID, protocolVersion, req)
}

// exchangeOn sends req on conn and returns the body of the ack. The
// server must run as serverUID, and its reply must have the given
// protocol version.
func exchangeOn(ctx context.Context, conn net.Conn, serverUID uint32, version int, req envelope) (json.RawMessage, error) {
	uid, err := peerUID(conn)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if uid != serverUID {
		return nil, fmt.Errorf("%w: server runs as uid %d, want %d", ErrUnavailable, uid, serverUID)
	}

	// The context is the only source of deadlines. This keeps the context
	// error and the I/O error in the same order.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) }) //nolint:errcheck // a closed conn needs no wake-up; the read already failed
	defer stop()

	if err := writeFrame(conn, req); err != nil {
		return nil, wrapIO(err)
	}
	reply, err := readFrame(conn)
	if err != nil {
		err = wrapIO(err)
		if errors.Is(err, ErrUnavailable) {
			err = fmt.Errorf("%w: %w", ErrNoReply, err)
		}
		return nil, err
	}
	return interpretReply(reply, version)
}

func newObserveEnvelope(ctx context.Context, o Observation) envelope {
	addrs := make([]string, len(o.Addrs))
	for i, a := range o.Addrs {
		addrs[i] = a.String()
	}
	body := observeBody{
		QName:      o.QName,
		Addrs:      addrs,
		TTLSeconds: ttlSeconds(o.TTL),
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

// interpretReply returns the body of an ack, and an error for every
// other reply. A reply of another version than version is an error also
// when it is an ack: its body can mean something else.
func interpretReply(env envelope, version int) (json.RawMessage, error) {
	if env.Version != version {
		return nil, fmt.Errorf("%w: reply version %d", ErrProtocol, env.Version)
	}
	switch env.Type {
	case typeAck:
		return env.Body, nil
	case typeReject:
		var b rejectBody
		if err := json.Unmarshal(env.Body, &b); err != nil {
			return nil, fmt.Errorf("%w: reject body: %v", ErrProtocol, err)
		}
		return nil, fmt.Errorf("%w: %s", ErrRejected, b.Reason)
	default:
		return nil, fmt.Errorf("%w: reply type %q", ErrProtocol, env.Type)
	}
}

// decodeAck reads the body of the ack to an observation. An ack without
// the protected flag is a protocol error, so the caller fails closed.
func decodeAck(body json.RawMessage) (Ack, error) {
	var b ackBody
	if err := json.Unmarshal(body, &b); err != nil {
		return Ack{}, fmt.Errorf("%w: ack body: %v", ErrProtocol, err)
	}
	if b.Protected == nil {
		return Ack{}, fmt.Errorf("%w: ack without the protected flag", ErrProtocol)
	}
	return Ack{Protected: *b.Protected}, nil
}
