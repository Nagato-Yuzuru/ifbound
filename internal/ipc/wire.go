// Package ipc carries DNS observations from ifbound-dns to ifboundd, and
// the requests of the CLI to ifboundd.
//
// ifbound-dns reports each DNS answer and waits for an ack before it replies
// to the application. Every failure is an error for the client, so the caller
// can turn it into SERVFAIL. The report server accepts a connection only from
// an allowed peer uid. Every server treats all input as untrusted.
//
// The wire format is a 4-byte big-endian length followed by a JSON envelope.
// The envelope has a protocol version and a message type. New message types
// can use the same frame.
//
// Each side accepts only its own protocol version. ifbound-dns and ifboundd
// are released together, so a version mismatch is an install error, and it
// must fail closed: a plugin that cannot read the ack would not know if the
// name is protected. Thus a change that a peer of the old version would
// misread increments the version. Version 3 added the protected flag to
// the ack of an observation.
//
// The CLI uses two more sockets, with the same frame and their own protocol
// version. The status socket (ListenStatus) is open to every local user and
// serves only Status. The admin socket (ListenAdmin) is open only to root and
// serves Status and Apply. Each socket has its own listener and its own
// connection slots: connections on one socket never take a slot of another.
// The handlers are not separate: they share the daemon, so the cost of a
// Status handler can still delay the work of the other handlers.
package ipc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	// MaxFrameSize is the largest accepted JSON payload, in bytes. It fits
	// the observation of the largest DNS-over-TCP message (64 KiB). The
	// densest address form is an ipv4hint: 4 octets for each address. So
	// one message has at most 16384 addresses, and each takes up to 18
	// JSON bytes (288 KiB). The qname adds at most 1.5 KiB.
	MaxFrameSize = 512 << 10
	// MaxQNameLen is the longest accepted qname, in bytes of presentation
	// text. A wire name has up to 255 octets, and the presentation form can
	// escape each octet as \DDD (4 bytes), so 1024 covers every valid name.
	// The package does not parse labels. The handler owns that check.
	MaxQNameLen = 1024
	// MaxTimeout is the largest handler deadline that the server honors.
	// Report clamps the deadline that it sends to this value.
	MaxTimeout = 30 * time.Second

	// maxReasonLen limits the text of a rejection. It keeps a reply far
	// below MaxFrameSize, whatever the peer sent.
	maxReasonLen = 256

	protocolVersion = 3
	// controlVersion is the protocol version of the status socket and the
	// admin socket. It changes independently of protocolVersion.
	controlVersion = 1

	typeObserve = "observe"
	typeProbe   = "probe"
	typeStatus  = "status"
	typeApply   = "apply"
	typeAck     = "ack"
	typeReject  = "reject"
)

var (
	// ErrFrameTooLarge means a frame is longer than MaxFrameSize.
	ErrFrameTooLarge = errors.New("ipc: frame too large")
	// ErrProtocol means a peer sent a frame that is not valid protocol.
	ErrProtocol = errors.New("ipc: protocol error")
)

type envelope struct {
	Version int             `json:"v"`
	Type    string          `json:"type"`
	Body    json.RawMessage `json:"body,omitempty"`
}

type observeBody struct {
	QName      string   `json:"qname"`
	Addrs      []string `json:"addrs"`
	TTLSeconds uint32   `json:"ttl_s"`
	// TimeoutMS is the time the client waits, from 1 to MaxTimeout. The
	// server gives the handler a context with this deadline.
	TimeoutMS int64 `json:"timeout_ms"`
}

// probeBody carries a probe name that reached ifbound-dns. See
// ProbePrefix.
type probeBody struct {
	QName string `json:"qname"`
}

// ackBody is the body of the ack to an observation. Protected is a
// pointer so that the client can refuse an ack without the flag: a
// missing flag must not read as "not protected".
type ackBody struct {
	Protected *bool `json:"protected"`
}

type rejectBody struct {
	Reason string `json:"reason"`
}

// envelopeOf builds an envelope of the report protocol. See envelopeIn.
func envelopeOf(typ string, body any) envelope {
	return envelopeIn(protocolVersion, typ, body)
}

// envelopeIn builds an envelope of the protocol version from one of this
// package's own body types. Those types always marshal, so a failure is a
// programming error. A nil body gives an envelope without a body.
func envelopeIn(version int, typ string, body any) envelope {
	env := envelope{Version: version, Type: typ}
	if body == nil {
		return env
	}
	raw, err := json.Marshal(body)
	if err != nil {
		panic("ipc: internal body does not marshal: " + err.Error())
	}
	env.Body = raw
	return env
}

// cutReason bounds the reason of a rejection on the report socket to
// maxReasonLen bytes.
func cutReason(reason string) string {
	if len(reason) > maxReasonLen {
		reason = strings.ToValidUTF8(reason[:maxReasonLen], "")
	}
	return reason
}

func writeFrame(w io.Writer, env envelope) error {
	payload, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("encoding frame: %w", err)
	}
	if len(payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf, uint32(len(payload))) //nolint:gosec // bounded by MaxFrameSize above
	copy(buf[4:], payload)
	// One Write keeps frames from interleaving on a shared connection.
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("writing frame: %w", err)
	}
	return nil
}

// readFrame reads one frame. It returns io.EOF only on a clean close before
// the first byte. An oversize length returns ErrFrameTooLarge without
// reading the body. A body that is not a valid envelope returns ErrProtocol.
func readFrame(r io.Reader) (envelope, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return envelope{}, io.EOF
		}
		return envelope{}, fmt.Errorf("reading frame header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrameSize {
		return envelope{}, ErrFrameTooLarge
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return envelope{}, fmt.Errorf("reading frame body: %w", err)
	}
	var env envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return envelope{}, fmt.Errorf("%w: malformed frame: %v", ErrProtocol, err)
	}
	return env, nil
}
