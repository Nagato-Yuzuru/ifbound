package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	socketMode = 0o660
	// maxConns bounds the connections served at once. The server takes a
	// slot before Accept, so excess clients wait in the kernel backlog. It
	// is larger than maxInFlight + maxProbesInFlight: while the reports of
	// one Client fill their slots and wait, its probes still get a
	// connection.
	maxConns = 64
	// connTimeout is the one deadline for a whole connection: read, handler,
	// and write. It leaves room for the longest client wait.
	connTimeout = MaxTimeout + 10*time.Second

	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
	lockFileMode     = 0o600
)

var (
	// ErrAlreadyRunning means a live server owns the socket path.
	ErrAlreadyRunning = errors.New("ipc: server already running at socket path")
	// ErrNotSocket means the socket path names a file that is not a socket.
	ErrNotSocket = errors.New("ipc: socket path is not a socket")

	errNilHandler     = errors.New("ipc: nil handler")
	errAlreadyServing = errors.New("ipc: Serve already called")
	errInvalidQName   = errors.New("invalid qname")
	errInvalidAddr    = errors.New("invalid address")
	errInvalidTimeout = errors.New("invalid timeout_ms")
	errNoProbes       = errors.New("probes are not served")
)

// Handler decides what to do with an observation. The server parses and
// limits the input and does nothing else with it. Addresses are canonical:
// no zone, and IPv4-mapped IPv6 is unmapped. A nil error becomes an ack
// that carries the Ack. An error becomes a rejection, and the first 256
// bytes of its text go to the client. ctx ends when the client deadline
// passes or the server shuts down.
type Handler interface {
	Observe(ctx context.Context, o Observation) (Ack, error)
}

// ProbeHandler receives the probe names that ifbound-dns saw (see
// ProbePrefix). The server calls ProbeSeen on the connection goroutine and
// acks after it returns. ProbeSeen must not wait for a report: the
// reports can hold every other slot.
type ProbeHandler interface {
	ProbeSeen(qname string)
}

// ServerConfig configures Listen.
type ServerConfig struct {
	// Path is the socket path. The caller sets the owner and group.
	Path string
	// Handler receives each valid observation. It must not be nil.
	Handler Handler
	// Probes receives each valid probe name. When it is nil, the server
	// rejects probes.
	Probes ProbeHandler
	// AllowedUIDs lists the peer uids the server serves. The server closes
	// every other connection without a reply.
	AllowedUIDs []uint32
	// Logger receives connection-level events. Nil discards them.
	Logger *slog.Logger
}

// Server accepts connections on a unix socket. Create it with Listen,
// ListenStatus, or ListenAdmin, run it with Serve, and stop it with Close
// or by cancelling the Serve context. Each connection carries one request
// and one reply.
type Server struct {
	ln      net.Listener
	admit   uidCheck
	routes  map[string]route
	version int
	cut     func(reason string) string
	peerLvl slog.Level
	log     *slog.Logger
	// slots bounds the connections served at once. A test in this
	// package may replace it before Serve.
	slots chan struct{}

	// connTimeout is the one deadline for a connection. The spec of the
	// socket sets the production value; a test in this package may shorten
	// it before Serve.
	connTimeout time.Duration

	path string      // empty when the server does not own a file
	sock os.FileInfo // the socket file that this server created
	lock *os.File    // holds the flock for the server lifetime

	mu      sync.Mutex
	closed  bool
	serving bool
	cancel  context.CancelFunc
	conns   map[net.Conn]struct{}
}

// Listen binds the socket and sets its mode to 0660. The mode change follows
// the bind, so the parent directory must not be open to untrusted users.
//
// Listen takes an exclusive flock on a lock file next to the socket
// (Path + ".lock"). The server holds it until Close, and the lock file stays
// on disk. A held lock means a live server, and Listen returns
// ErrAlreadyRunning. A connect probe cannot tell this: a live server with a
// full accept queue refuses connects like a dead one. With the lock held, a
// socket at the path is stale and Listen removes it. A file that is not a
// socket is never removed: Listen returns ErrNotSocket. Close removes the
// path only while it still names the socket that this server created.
func Listen(cfg ServerConfig) (*Server, error) {
	if cfg.Handler == nil {
		return nil, errNilHandler
	}
	return listenSpec(cfg.Path, reportSpec(cfg))
}

// uidCheck reports whether a peer uid may pass.
type uidCheck func(uid uint32) bool

func anyUID(uint32) bool { return true }

// uidIn admits exactly the uids in the list. An empty list admits no uid.
func uidIn(uids []uint32) uidCheck {
	set := make(map[uint32]struct{}, len(uids))
	for _, uid := range uids {
		set[uid] = struct{}{}
	}
	return func(uid uint32) bool {
		_, ok := set[uid]
		return ok
	}
}

// route serves one message type. A nil error becomes an ack that carries
// body; a nil body gives an ack without a body. An error becomes a
// rejection. ctx ends at the connection deadline.
type route func(ctx context.Context, req envelope) (body any, err error)

// spec holds the settings that make a Server one kind of socket.
type spec struct {
	mode    os.FileMode   // of the socket file
	conns   int           // the connection slots
	timeout time.Duration // the one deadline for a connection
	version int           // of every request and reply
	admit   uidCheck      // runs before the server reads a frame
	routes  map[string]route
	// cut bounds the reason of a rejection.
	cut func(reason string) string
	// peerLvl is the log level of the events that a peer can cause, such
	// as a failed write of the reply. A socket that every local user can
	// open logs them at Debug, so a peer cannot flood the log.
	peerLvl slog.Level
	log     *slog.Logger
}

// reportSpec is the spec of the socket that ifbound-dns reports to.
func reportSpec(cfg ServerConfig) spec {
	return spec{
		mode:    socketMode,
		conns:   maxConns,
		timeout: connTimeout,
		version: protocolVersion,
		admit:   uidIn(cfg.AllowedUIDs),
		routes: map[string]route{
			typeObserve: func(ctx context.Context, req envelope) (any, error) {
				return observe(ctx, cfg.Handler, req)
			},
			typeProbe: func(_ context.Context, req envelope) (any, error) {
				return probe(cfg.Probes, req)
			},
		},
		cut:     cutReason,
		peerLvl: slog.LevelWarn,
		log:     cfg.Logger,
	}
}

// listenSpec takes the lock for path, then binds the socket of sp.
func listenSpec(path string, sp spec) (*Server, error) {
	lock, err := lockPath(path)
	if err != nil {
		return nil, err
	}
	s, err := bind(path, sp)
	if err != nil {
		_ = lock.Close() //nolint:errcheck // releases the flock; the bind error is the one to report
		return nil, err
	}
	s.lock = lock
	return s, nil
}

// lockPath takes the exclusive lock for path and returns the lock file.
func lockPath(path string) (*os.File, error) {
	name := path + ".lock"
	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, lockFileMode)
	if err != nil {
		return nil, fmt.Errorf("opening lock file %s: %w", name, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close() //nolint:errcheck // the lock error is the one to report
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s", ErrAlreadyRunning, path)
		}
		return nil, fmt.Errorf("locking %s: %w", name, err)
	}
	return f, nil
}

// bind removes a stale socket at path, binds, and sets the mode of sp.
// The caller holds the lock.
func bind(path string, sp spec) (*Server, error) {
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("inspecting %s: %w", path, err)
	case fi.Mode().Type() != os.ModeSocket:
		return nil, fmt.Errorf("%w: %s", ErrNotSocket, path)
	default:
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("removing stale socket %s: %w", path, err)
		}
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", path) // binding does not block; no caller context to honor
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", path, err)
	}
	// Close must not unlink by name: a newer socket may own the path by then.
	ln.(*net.UnixListener).SetUnlinkOnClose(false) //nolint:forcetypeassert // "unix" always gives *net.UnixListener
	if err := os.Chmod(path, sp.mode); err != nil {
		_ = ln.Close()      //nolint:errcheck // the chmod error is the one to report
		_ = os.Remove(path) //nolint:errcheck // the file is ours: bound just above
		return nil, fmt.Errorf("setting mode of %s: %w", path, err)
	}
	sock, err := os.Lstat(path)
	if err != nil {
		_ = ln.Close() //nolint:errcheck // the stat error is the one to report
		return nil, fmt.Errorf("inspecting %s: %w", path, err)
	}
	s := serverOf(ln, sp)
	s.path = path
	s.sock = sock
	return s, nil
}

// newServer returns a report server on ln that owns no socket file.
func newServer(ln net.Listener, cfg ServerConfig) *Server {
	return serverOf(ln, reportSpec(cfg))
}

func serverOf(ln net.Listener, sp spec) *Server {
	logger := sp.log
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Server{
		ln:      ln,
		admit:   sp.admit,
		routes:  sp.routes,
		version: sp.version,
		cut:     sp.cut,
		peerLvl: sp.peerLvl,
		log:     logger,
		slots:   make(chan struct{}, sp.conns),

		connTimeout: sp.timeout,
		conns:       make(map[net.Conn]struct{}),
	}
}

// Serve accepts connections until ctx ends or Close runs. It then closes the
// listener and every connection, waits for all handlers to return, and
// returns nil. A failing Accept (for example, out of file descriptors) does
// not stop it: Serve logs the error, backs off, and tries again. A second
// call returns an error.
func (s *Server) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.mu.Lock()
	if s.serving {
		s.mu.Unlock()
		return errAlreadyServing
	}
	s.serving = true
	s.cancel = cancel
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = s.Close() }) //nolint:errcheck // Close fails only if the listener is gone already
	defer stop()

	var wg sync.WaitGroup
	defer wg.Wait()
	defer func() { _ = s.Close() }() //nolint:errcheck // idempotent; closes live connections so wg.Wait returns

	var backoff time.Duration
	for {
		select {
		case s.slots <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		conn, err := s.ln.Accept()
		if err != nil {
			<-s.slots
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			backoff = min(max(backoff*2, acceptBackoffMin), acceptBackoffMax)
			s.log.Warn("accept failed; retrying", "err", err, "delay", backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil
			}
			continue
		}
		backoff = 0
		if !s.track(conn) {
			<-s.slots
			_ = conn.Close() //nolint:errcheck // server is closing; nothing was read
			continue
		}
		wg.Go(func() {
			defer func() { <-s.slots }()
			defer s.untrack(conn)
			s.serveConn(ctx, conn)
		})
	}
}

// Close stops the listener, ends handler contexts, closes all connections,
// removes the socket file if this server still owns it, and releases the
// lock. It is safe to
// call more than once.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	err := s.ln.Close()
	for c := range s.conns {
		_ = c.Close() //nolint:errcheck // unblocks the reader; the connection owner logs real errors
	}
	s.removeOwnSocket()
	if s.lock != nil {
		_ = s.lock.Close() //nolint:errcheck // releases the flock; the lock file stays on disk
	}
	if err != nil {
		return fmt.Errorf("closing listener: %w", err)
	}
	return nil
}

// removeOwnSocket unlinks the path only if it still holds our socket.
func (s *Server) removeOwnSocket() {
	if s.sock == nil {
		return
	}
	cur, err := os.Lstat(s.path)
	if err != nil || !os.SameFile(s.sock, cur) {
		return
	}
	if err := os.Remove(s.path); err != nil {
		s.log.Warn("removing socket failed", "err", err)
	}
}

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	_ = c.Close() //nolint:errcheck // may be closed by Close already
}

// serveConn reads one request, replies once, and returns. One deadline
// covers the whole connection.
func (s *Server) serveConn(ctx context.Context, c net.Conn) {
	uid, err := peerUID(c)
	if err != nil {
		s.log.Log(ctx, s.peerLvl, "peer credentials unavailable", "err", err)
		return
	}
	if !s.admit(uid) {
		s.log.Warn("peer uid not allowed", "uid", uid)
		return
	}
	deadline := time.Now().Add(s.connTimeout)
	_ = c.SetDeadline(deadline) //nolint:errcheck // fails only on a closed conn; the read reports it
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	req, err := readFrame(c)
	var reply envelope
	switch {
	case err == nil:
		reply = s.dispatch(ctx, req)
	case errors.Is(err, ErrFrameTooLarge), errors.Is(err, ErrProtocol):
		reply = s.reject(err.Error())
	default:
		if !errors.Is(err, io.EOF) {
			s.log.Debug("reading request failed", "err", err)
		}
		return
	}
	if err := writeFrame(c, reply); err != nil {
		s.log.Log(ctx, s.peerLvl, "writing reply failed", "err", err)
	}
}

func (s *Server) dispatch(ctx context.Context, req envelope) envelope {
	if req.Version != s.version {
		return s.reject(fmt.Sprintf("unsupported version %d", req.Version))
	}
	serve, ok := s.routes[req.Type]
	if !ok {
		return s.reject(fmt.Sprintf("unknown message type %q", req.Type))
	}
	body, err := serve(ctx, req)
	if err != nil {
		return s.reject(err.Error())
	}
	return envelopeIn(s.version, typeAck, body)
}

func (s *Server) reject(reason string) envelope {
	return envelopeIn(s.version, typeReject, rejectBody{Reason: s.cut(reason)})
}

func observe(ctx context.Context, h Handler, req envelope) (any, error) {
	obs, timeout, err := decodeObserve(req.Body)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ack, err := h.Observe(ctx, obs)
	if err != nil {
		return nil, err
	}
	return ackBody{Protected: &ack.Protected}, nil
}

func probe(p ProbeHandler, req envelope) (any, error) {
	if p == nil {
		return nil, errNoProbes
	}
	var b probeBody
	if err := json.Unmarshal(req.Body, &b); err != nil {
		return nil, fmt.Errorf("malformed probe body: %w", err)
	}
	if b.QName == "" || len(b.QName) > MaxQNameLen {
		return nil, fmt.Errorf("%w: length %d", errInvalidQName, len(b.QName))
	}
	p.ProbeSeen(b.QName)
	return nil, nil
}

func decodeObserve(raw []byte) (Observation, time.Duration, error) {
	var b observeBody
	if err := json.Unmarshal(raw, &b); err != nil {
		return Observation{}, 0, fmt.Errorf("malformed observe body: %w", err)
	}
	if b.TimeoutMS < 1 || b.TimeoutMS > MaxTimeout.Milliseconds() {
		return Observation{}, 0, fmt.Errorf("%w: %d", errInvalidTimeout, b.TimeoutMS)
	}
	if b.QName == "" || len(b.QName) > MaxQNameLen {
		return Observation{}, 0, fmt.Errorf("%w: length %d", errInvalidQName, len(b.QName))
	}
	addrs := make([]netip.Addr, len(b.Addrs))
	for i, s := range b.Addrs {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return Observation{}, 0, fmt.Errorf("%w: %.64q", errInvalidAddr, s)
		}
		addrs[i] = a.Unmap()
	}
	obs := Observation{
		QName: b.QName,
		Addrs: addrs,
		TTL:   time.Duration(b.TTLSeconds) * time.Second,
	}
	return obs, time.Duration(b.TimeoutMS) * time.Millisecond, nil
}
