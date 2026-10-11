// Package ipc carries DNS observations from ifbound-dns to ifboundd.
//
// ifbound-dns reports each DNS answer and waits for an ack before it replies
// to the application. Every failure is an error for the client, so the caller
// can turn it into SERVFAIL. The server accepts a connection only from an
// allowed peer uid and treats all input as untrusted.
//
// The wire format is a 4-byte big-endian length followed by a JSON envelope.
// The envelope has a protocol version and a message type. New message types
// can use the same frame.
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
	// about 2400 IPv6 addresses, the largest DNS-over-TCP answer.
	MaxFrameSize = 128 << 10
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

	protocolVersion = 1

	typeObserve = "observe"
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

type rejectBody struct {
	Reason string `json:"reason"`
}

// envelopeOf builds an envelope from one of this package's own body types.
// Those types always marshal, so a failure is a programming error.
func envelopeOf(typ string, body any) envelope {
	env := envelope{Version: protocolVersion, Type: typ}
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

func rejectEnvelope(reason string) envelope {
	if len(reason) > maxReasonLen {
		reason = strings.ToValidUTF8(reason[:maxReasonLen], "")
	}
	return envelopeOf(typeReject, rejectBody{Reason: reason})
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
