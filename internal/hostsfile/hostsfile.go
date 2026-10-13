// Package hostsfile reads /etc/hosts as the readers of the file on macOS
// read it.
//
// Four readers use the file, and their dialects differ (see dialect):
//
//   - mDNSResponder answers first for the system resolver
//     (mDNSMacOSX.c, mDNSResponder-2600.140.3).
//   - The file module of Libinfo answers when mDNSResponder has no
//     answer (file_module.c, Libinfo-600).
//   - Chromium, and every Electron app, reads the file itself and
//     answers before the system resolver (net/dns/dns_hosts.cc).
//   - The pure-Go resolver of the Go net package, when a Go program
//     selects it (net/hosts.go).
//
// Other programs can read the file with their own code, for example with
// c-ares or with the hickory resolver. Their dialects are not examined:
// an entry that only such a reader uses can be missing.
//
// Parse gives the union of the entries of the readers. A name that any
// reader answers must be found, so an entry that only one reader uses is
// still an entry. When two readers read one address field to different
// addresses, both entries are in the result. An extra entry only blocks
// more. The package is pure: it reads an io.Reader and holds no state.
package hostsfile

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
)

// errRead is the error of Parse when the reader fails.
var errRead = errors.New("reading host file")

// Entry is the result of one host line as one reader reads it. Addr
// answers Name and each alias. mDNSResponder answers each alias as a
// CNAME to Name (mDNSMacOSX.c:5834-5850 and :5876).
type Entry struct {
	// Addr is valid and has no zone. An IPv4-mapped IPv6 address is the
	// IPv4 address: a dual-stack socket sends IPv4 packets to it, and the
	// kernel sends no packet to it from an IPV6_V6ONLY socket.
	Addr netip.Addr
	// Name is the first name of the line that the reader accepts and
	// dnsname can represent.
	Name dnsname.Name
	// Aliases are the other names of the line, in line order, without
	// duplicates and without Name. Aliases is nil when there are none.
	Aliases []dnsname.Name
}

func (e Entry) equal(o Entry) bool {
	return e.Addr == o.Addr && e.Name == o.Name && slices.Equal(e.Aliases, o.Aliases)
}

// Hosts is the content of a host file. Each Parse call returns new
// slices, so the caller owns them.
type Hosts struct {
	// Entries are in file order. An entry equal to one of the four
	// entries before it is dropped, so a line that the readers read the
	// same way gives one entry. A line that they read differently gives
	// more.
	Entries []Entry

	// Malformed counts the lines with text that a reader does not use: an
	// address that the reader refuses, an address without a name, or a
	// name that the reader refuses. A long comment counts too: the macOS
	// readers read its later chunks as lines of text (see dialect). The
	// readers differ, so an unusual but valid line often counts. The
	// count is for information only.
	Malformed int

	// Unrepresentable counts the lines with a name that a reader can use
	// but Name cannot represent: the root name, a name of 256 octets in
	// wire form, a name that Libinfo or the Go resolver compares as a
	// plain string but that is not a valid DNS name, or a name that
	// chromiumIDNA refuses. A query for such a name gets an answer from
	// the file that no Entry shows, so a count above zero is a possible
	// leak.
	Unrepresentable int
}

// Parse reads a host file from r.
//
// The content of the file is never an error. Each reader sees the file
// as a sequence of chunks (see dialect). So a line that is longer than a
// chunk does not stop the read, and text after a long comment can still
// be an entry.
//
// Parse differs from the readers only in the direction of more entries:
//
//   - A NUL byte at the start of a chunk stops both macOS readers. Parse
//     continues with the next chunk.
//   - Chromium reads nothing from a file over 32 MiB. Parse reads it.
//   - A line over 64 KiB stops the Go resolver. Parse reads on.
//   - Chromium uses the first address of a name for each address family
//     only. Parse keeps all.
//   - Separators at the start of a line are skipped, commas too.
//   - A name that a reader refuses is skipped alone. The macOS readers
//     drop the rest of the line, or the line.
//   - When the first name is skipped, the next name is Name.
//   - An interface name after "%" is not checked.
//
// Some names cannot be found. Hosts.Unrepresentable counts the lines
// that have them:
//
//   - A name of 256 octets in wire form, which mDNSResponder accepts.
//     dnsname cannot represent it.
//   - A name that Libinfo or the Go resolver compares as a plain string
//     but that is not a valid DNS name: an empty label, a label over 63
//     octets, or a name over 255 octets, for example "a..example". No
//     DNS query has such a name, but a program can look it up.
//   - The root name ".". mDNSResponder accepts it as the first name, and
//     the aliases of the line then are CNAMEs to the root name. Parse
//     skips the root name, so such an alias gets the address of its own
//     line only, and not the addresses of other lines whose first name is
//     the root name: for "1.2.3.4 . protected.example" and "5.6.7.8 .",
//     protected.example gets 1.2.3.4 but not 5.6.7.8.
//   - A name that needs IDNA, when golang.org/x/net/idna and the ICU of
//     Chromium map it differently, for example for a code point that one
//     Unicode version has and the other does not.
//
// A read error returns, together with an error, the entries of the lines
// before the error and the entries of the chunks of the unfinished line
// that a reader completed: a chunk is complete at chunkLen bytes, before
// its line ends.
func Parse(r io.Reader) (Hosts, error) {
	p := parser{seen: make(map[dnsname.Name]struct{})}
	views := [dedupeWindow]view{{dialect: mdnsResponder()}, {dialect: libinfo()}, {dialect: chromium()}, {dialect: goResolver()}}
	br := bufio.NewReader(r)
	for {
		seg, err := br.ReadSlice('\n')
		for i := range views {
			views[i].write(seg, p.addChunk)
		}
		switch {
		case err == nil:
			p.endLine()
		case errors.Is(err, bufio.ErrBufferFull):
			// The line continues in the next segment.
		case errors.Is(err, io.EOF):
			for i := range views {
				views[i].flush(p.addChunk)
			}
			p.endLine()
			return p.hosts, nil
		default:
			return p.hosts, fmt.Errorf("%w: %v", errRead, err)
		}
	}
}

// view cuts the bytes of the file into the chunks of one dialect, as
// fgets does.
type view struct {
	dialect
	buf []byte
}

// write adds p to the current chunk and calls emit for each chunk that
// is complete: it ends with a newline or has chunkLen bytes.
func (v *view) write(p []byte, emit func(*dialect, []byte)) {
	for len(p) > 0 {
		n := min(len(p), v.chunkLen-len(v.buf))
		for i, c := range p[:n] {
			if c == '\n' {
				n = i + 1
				break
			}
		}
		v.buf = append(v.buf, p[:n]...)
		p = p[n:]
		if len(v.buf) == v.chunkLen || v.buf[len(v.buf)-1] == '\n' {
			v.flush(emit)
		}
	}
}

// flush calls emit for the current chunk, if there is one.
func (v *view) flush(emit func(*dialect, []byte)) {
	if len(v.buf) > 0 {
		emit(&v.dialect, v.buf)
		v.buf = v.buf[:0]
	}
}

type parser struct {
	hosts Hosts
	// lineUnused and lineUnrepresentable are true when a reader dropped
	// a field of the current line, by kind.
	lineUnused, lineUnrepresentable bool
	fields                          []string
	// seen holds the names of the current entry. Parse uses it for one
	// entry at a time, so the duplicate check is linear in the line.
	seen map[dnsname.Name]struct{}
}

func (p *parser) endLine() {
	if p.lineUnused {
		p.hosts.Malformed++
	}
	if p.lineUnrepresentable {
		p.hosts.Unrepresentable++
	}
	p.lineUnused, p.lineUnrepresentable = false, false
}

// addChunk adds the entries of one chunk as d reads it. A comment or an
// address that is not valid ends the chunk.
func (p *parser) addChunk(d *dialect, chunk []byte) {
	text, ok := d.text(chunk)
	if !ok {
		return
	}
	for line := range d.lines(text) {
		var comment bool
		p.fields, comment = d.appendFields(p.fields[:0], line)
		addrOK := true
		if len(p.fields) > 0 {
			var e Entry
			e, addrOK = p.entry(d, p.fields)
			p.add(e)
		}
		if comment || !addrOK {
			break
		}
	}
}

// add appends e, if it is an entry. The readers read most lines to the
// same entry, one after the other, so an entry equal to one of the last
// dedupeWindow entries is dropped.
func (p *parser) add(e Entry) {
	if e.Name == (dnsname.Name{}) {
		return
	}
	entries := p.hosts.Entries
	for _, prev := range entries[max(0, len(entries)-dedupeWindow):] {
		if prev.equal(e) {
			return
		}
	}
	p.hosts.Entries = append(p.hosts.Entries, e)
}

// dedupeWindow is the number of readers, and so the length of the views
// of Parse: each reader reads a short line to one entry.
const dedupeWindow = 4

// entry reads the fields of one line as d does. It returns the entry, if
// the line has one, and whether the address is valid. It marks the line
// when a field is not used or cannot be represented.
func (p *parser) entry(d *dialect, fields []string) (e Entry, addrOK bool) {
	addr, ok := d.addr(fields[0])
	if !ok {
		p.lineUnused = true
		return Entry{}, false
	}
	clear(p.seen)
	var names []dnsname.Name
	for _, f := range fields[1:] {
		n, use := d.name(f)
		switch use {
		case nameUsed:
		case nameRefused:
			p.lineUnused = true
			continue
		case nameUnrepresentable:
			p.lineUnrepresentable = true
			continue
		default:
			panic("hostsfile: unknown name use")
		}
		if _, dup := p.seen[n]; dup {
			continue
		}
		p.seen[n] = struct{}{}
		names = append(names, n)
	}
	if len(names) == 0 {
		if len(fields) == 1 {
			p.lineUnused = true // an address without a name
		}
		return Entry{}, true
	}
	e = Entry{Addr: addr, Name: names[0]}
	if len(names) > 1 {
		e.Aliases = names[1:]
	}
	return e, true
}
