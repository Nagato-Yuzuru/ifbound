package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"time"
)

const (
	// statusSocketMode lets every local user ask for the status.
	statusSocketMode = 0o666
	// adminSocketMode lets only the owner (root) connect.
	adminSocketMode = 0o600
	// statusConns bounds the connections that the status socket serves at
	// once. Every local user can take them, so no other socket uses them.
	statusConns = 4
	// adminConns bounds the connections that the admin socket serves at
	// once.
	adminConns = 2
	// controlConnTimeout is the one deadline for a connection on the
	// status socket and on the admin socket: read, handler, and write.
	controlConnTimeout = 5 * time.Second
	// controlReplyMargin is the time between the end of the handler
	// context and the end of the wait: the reply goes out in it.
	controlReplyMargin = 500 * time.Millisecond
	// controlWait bounds a ControlClient call whose context has no
	// deadline. It is longer than controlConnTimeout, so the client gets
	// every reply that the server sends before its deadline.
	controlWait = controlConnTimeout + time.Second
	// maxAdminReasonLen bounds the reason of a rejection on the admin
	// socket. A parse error names the bad value last, so the reason must
	// not stop at maxReasonLen. JSON can write one byte as 6 ("\u0000"), so
	// the longest reason still fits in a frame.
	maxAdminReasonLen = 64 << 10
)

var (
	// ErrDenied means the socket file does not let the uid of the caller
	// connect. The admin socket is open only to root.
	ErrDenied = errors.New("ipc: socket not open to this uid")

	errNoConfig  = errors.New("apply without config")
	errApplyLate = errors.New("apply not started: the client deadline is too near or passed")
)

// StatusHandler serves the Status requests of the CLI. An error becomes a
// rejection, and the client gets its text.
type StatusHandler interface {
	// Status returns the current status. The server calls it for each
	// request of each local user, with no rate limit. So Status must answer
	// from data at hand and must not wait for the report path. ctx ends
	// before the connection deadline, with time left for the reply.
	Status(ctx context.Context) (StatusReport, error)
}

// ControlHandler serves the requests on the admin socket.
type ControlHandler interface {
	StatusHandler
	// Apply validates and stores cfg, then reconfigures. A refused cfg
	// changes nothing. ctx ends before the client stops waiting, with time
	// left for the reply. Apply must not store cfg after ctx ends.
	Apply(ctx context.Context, cfg []byte) (StatusReport, error)
}

// StatusConfig configures ListenStatus.
type StatusConfig struct {
	// Path is the socket path.
	Path string
	// Handler serves each request. It must not be nil.
	Handler StatusHandler
	// Logger receives connection-level events. Nil discards them.
	Logger *slog.Logger
}

// AdminConfig configures ListenAdmin.
type AdminConfig struct {
	// Path is the socket path. Production uses /var/run/ifbound/admin.sock.
	Path string
	// Handler serves each request. It must not be nil.
	Handler ControlHandler
	// UIDs lists the peer uids that the server serves. Production passes
	// [0]. The server closes every other connection without a reply. An
	// empty list admits no peer.
	UIDs []uint32
	// Logger receives connection-level events. Nil discards them.
	Logger *slog.Logger
}

// ListenStatus binds the status socket and sets its mode to 0666. Every
// local user can connect, and the socket serves only Status. It has its
// own 4 connection slots, and a connection has a deadline of 5 seconds.
// It logs the events that a peer can cause at Debug. The lock, the stale
// socket, and Close work as in Listen.
func ListenStatus(cfg StatusConfig) (*Server, error) {
	if cfg.Handler == nil {
		return nil, errNilHandler
	}
	return listenSpec(cfg.Path, spec{
		mode:    statusSocketMode,
		conns:   statusConns,
		timeout: controlConnTimeout,
		version: controlVersion,
		admit:   anyUID,
		routes:  map[string]route{typeStatus: statusRoute(cfg.Handler)},
		cut:     func(reason string) string { return cutText(reason, maxReasonLen) },
		peerLvl: slog.LevelDebug,
		log:     cfg.Logger,
	})
}

// ListenAdmin binds the admin socket and sets its mode to 0600. The caller
// runs as root, so only root can connect, and the server serves only the
// peers in UIDs. The socket serves Status and Apply. It has its own 2
// connection slots: connections on the status socket never take them.
// The handler is not separate: a Status handler that is slow for the
// status socket is slow here too. A connection has a deadline of 5
// seconds. The lock, the stale socket, and Close work as in Listen.
func ListenAdmin(cfg AdminConfig) (*Server, error) {
	if cfg.Handler == nil {
		return nil, errNilHandler
	}
	return listenSpec(cfg.Path, spec{
		mode:    adminSocketMode,
		conns:   adminConns,
		timeout: controlConnTimeout,
		version: controlVersion,
		admit:   uidIn(cfg.UIDs),
		routes: map[string]route{
			typeStatus: statusRoute(cfg.Handler),
			typeApply:  applyRoute(cfg.Handler),
		},
		cut:     func(reason string) string { return cutText(reason, maxAdminReasonLen) },
		peerLvl: slog.LevelWarn,
		log:     cfg.Logger,
	})
}

// handlerContext returns the context of a control handler. It ends
// controlReplyMargin before the connection deadline, or before limit when
// limit is earlier, so the reply can still reach the client.
func handlerContext(ctx context.Context, limit time.Time) (context.Context, context.CancelFunc) {
	end, _ := ctx.Deadline() // serveConn always sets the connection deadline
	if !limit.IsZero() && limit.Before(end) {
		end = limit
	}
	return context.WithDeadline(ctx, end.Add(-controlReplyMargin))
}

func statusRoute(h StatusHandler) route {
	return func(ctx context.Context, _ envelope) (any, error) {
		ctx, cancel := handlerContext(ctx, time.Time{})
		defer cancel()
		rep, err := h.Status(ctx)
		if err != nil {
			return nil, err
		}
		return boundStatus(rep), nil
	}
}

// applyRoute calls the handler only while the client still waits: a
// request that waited in the backlog after its client gave up changes
// nothing.
func applyRoute(h ControlHandler) route {
	return func(ctx context.Context, req envelope) (any, error) {
		cfg, deadline, err := decodeApply(req.Body)
		if err != nil {
			return nil, err
		}
		ctx, cancel := handlerContext(ctx, deadline)
		defer cancel()
		if ctx.Err() != nil {
			return nil, errApplyLate
		}
		rep, err := h.Apply(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return boundStatus(rep), nil
	}
}

// applyBody carries the configuration file.
type applyBody struct {
	Config []byte `json:"config"`
	// DeadlineMS is the end of the client wait, in Unix milliseconds.
	// Client and server run on the same host and read the same clock.
	DeadlineMS int64 `json:"deadline_unix_ms"`
}

// decodeApply reads an apply body. A missing or empty config is an error:
// it must not read as a configuration without policies.
func decodeApply(raw json.RawMessage) ([]byte, time.Time, error) {
	var b applyBody
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, time.Time{}, fmt.Errorf("malformed apply body: %w", err)
	}
	if len(b.Config) == 0 {
		return nil, time.Time{}, errNoConfig
	}
	// A missing deadline reads as 1970, so applyRoute refuses it as late.
	return b.Config, time.UnixMilli(b.DeadlineMS), nil
}

// ControlClient sends the requests of the CLI to the status socket or to
// the admin socket. It is safe for concurrent use. Each call uses its own
// connection.
type ControlClient struct {
	path      string
	serverUID uint32
}

// NewControlClient returns a client for the socket at path. It trusts a
// reply only from a server that runs as serverUID. Production passes 0.
func NewControlClient(path string, serverUID uint32) *ControlClient {
	return &ControlClient{path: path, serverUID: serverUID}
}

// Status returns the status of ifboundd. The error set is:
// ErrUnavailable (no connection, lost connection, or a server that runs
// as another uid than the expected one), ErrDenied (the socket file does
// not let the caller connect), ErrRejected (the server refused; the
// message has the reason), ErrProtocol (malformed reply, a status out of
// bounds, or a server of another protocol version), ErrFrameTooLarge, and
// the context error when ctx ends. Without a ctx deadline, the call waits
// at most 6 seconds.
func (c *ControlClient) Status(ctx context.Context) (StatusReport, error) {
	return c.call(ctx, func(context.Context) envelope {
		return envelopeIn(controlVersion, typeStatus, nil)
	})
}

// Apply sends the configuration file cfg to the admin socket and returns
// the status after ifboundd applied it. The errors are those of Status.
// A parse error of cfg is an ErrRejected with the text of the parse
// error. The status socket rejects Apply. An empty cfg is an error, and
// Apply then sends nothing.
//
// The request carries the end of the wait. The server does not start an
// Apply that cannot end before it. So when Apply returns an error that is
// not a reply of the server (ErrUnavailable, ErrDenied, or the context
// error), a request that reaches the server later does not apply cfg. A
// request that the server started in time can have applied cfg: Status
// shows the hash of the applied configuration. The error has ErrNoReply
// exactly when the client sent the whole request: then the server can
// have applied cfg. A dial failure, a wrong server uid, and a context
// that ended before the send never have it.
func (c *ControlClient) Apply(ctx context.Context, cfg []byte) (StatusReport, error) {
	if len(cfg) == 0 {
		return StatusReport{}, errNoConfig
	}
	return c.call(ctx, func(ctx context.Context) envelope {
		dl, _ := ctx.Deadline() // call sets a deadline
		return envelopeIn(controlVersion, typeApply, applyBody{Config: cfg, DeadlineMS: dl.UnixMilli()})
	})
}

func (c *ControlClient) call(ctx context.Context, req func(context.Context) envelope) (StatusReport, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, controlWait)
		defer cancel()
	}
	env := req(ctx)
	body, err := c.roundTrip(ctx, env)
	if err != nil {
		if ctx.Err() != nil {
			if errors.Is(err, ErrNoReply) {
				return StatusReport{}, fmt.Errorf("requesting %s: %w: %w", env.Type, ctx.Err(), ErrNoReply)
			}
			return StatusReport{}, fmt.Errorf("requesting %s: %w", env.Type, ctx.Err())
		}
		return StatusReport{}, err
	}
	return decodeStatus(body)
}

func (c *ControlClient) roundTrip(ctx context.Context, req envelope) (json.RawMessage, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.path)
	switch {
	case errors.Is(err, fs.ErrPermission):
		return nil, fmt.Errorf("%w: %v", ErrDenied, err)
	case err != nil:
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer func() { _ = conn.Close() }() //nolint:errcheck // read-only use after the reply; nothing to flush
	return exchangeOn(ctx, conn, c.serverUID, controlVersion, req)
}
