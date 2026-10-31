// Package dnsconf renders the Corefile of ifbound-dns from the [dns]
// section of the applied configuration.
//
// The Corefile has no log plugin. The errors plugin consolidates every
// error into one count per interval, so no query name reaches the log: a
// log of each query is a privacy problem.
package dnsconf

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// maxSocketPath is the longest socket path that a macOS socket address
// holds: sun_path has 104 bytes and the last one is the terminator.
const maxSocketPath = 103

// Errors that New returns.
var (
	// ErrBadPath is the error for a path that a Corefile cannot carry.
	ErrBadPath = errors.New("path has a character that the Corefile cannot carry")
	// ErrSocketTooLong is the error for a socket path that is longer than
	// a socket address holds.
	ErrSocketTooLong = errors.New("socket path is too long")
)

// Renderer renders the Corefile for one socket and one CA file. The zero
// value is not usable: create it with New.
type Renderer struct {
	socket string // quoted
	caFile string // quoted; empty for the system roots
}

// New returns a Renderer. socket is the absolute path of the report
// socket of ifboundd. caFile is a CA file for the upstream TLS check; an
// empty caFile keeps the system roots, and only a test build of
// ifbound-dns passes a file.
//
// A path goes into the Corefile as a quoted token. So a space or a "#" in
// a path is safe. A path with a quote, a brace, or a control character
// fails with ErrBadPath: the quote and the brace start an escape or an
// environment variable in the Corefile, and a backslash at the end of the
// path would escape the closing quote. A socket path longer than 103 bytes
// fails with ErrSocketTooLong.
func New(socket, caFile string) (Renderer, error) {
	if err := checkPath(socket); err != nil {
		return Renderer{}, fmt.Errorf("socket %q: %w", socket, err)
	}
	if len(socket) > maxSocketPath {
		return Renderer{}, fmt.Errorf("%w: %d bytes, at most %d", ErrSocketTooLong, len(socket), maxSocketPath)
	}
	r := Renderer{socket: `"` + socket + `"`}
	if caFile != "" {
		if err := checkPath(caFile); err != nil {
			return Renderer{}, fmt.Errorf("CA file %q: %w", caFile, err)
		}
		r.caFile = `"` + caFile + `"`
	}
	return r, nil
}

func checkPath(p string) error {
	if strings.HasSuffix(p, `\`) {
		return fmt.Errorf("%w: ends with a backslash", ErrBadPath)
	}
	for _, c := range p {
		if c == '"' || c == '{' || c == '}' || unicode.IsControl(c) {
			return fmt.Errorf("%w: %q", ErrBadPath, c)
		}
	}
	return nil
}

// Corefile returns the Corefile for d. The server block listens on
// d.Listen only.
//
// Each upstream carries its own TLS server name in the form that CoreDNS
// reads: the name follows the address inside the brackets of an IPv6
// address (tls://[2001:db8::1%name]:853). The form tls://[2001:db8::1]:853%name
// makes CoreDNS dial a wrong address.
func (r Renderer) Corefile(d policy.DNS) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, ".:%d {\n", d.Listen.Port())
	fmt.Fprintf(&b, "\tbind %s\n", d.Listen.Addr())
	b.WriteString("\terrors {\n\t\tconsolidate 1m \".*\"\n\t}\n")
	fmt.Fprintf(&b, "\tifbound %s\n", r.socket)
	b.WriteString("\tcache\n")
	b.WriteString("\tforward .")
	for _, u := range d.Upstream {
		hostName := u.Addr.Addr().String() + "%" + u.ServerName.String()
		b.WriteString(" tls://" + net.JoinHostPort(hostName, strconv.Itoa(int(u.Addr.Port()))))
	}
	if r.caFile == "" {
		b.WriteString("\n")
	} else {
		fmt.Fprintf(&b, " {\n\t\ttls %s\n\t}\n", r.caFile)
	}
	b.WriteString("}\n")
	return []byte(b.String())
}
