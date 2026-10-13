package hostsfile

import (
	"bytes"
	"iter"
	"net/netip"
	"strings"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
)

// dialect is how one reader of the host file reads it: how it cuts the
// file into lines and a line into fields, and how it reads the address
// field and the name fields. The first field of a line is the address,
// the others are names.
type dialect struct {
	// chunkLen is the most bytes that the reader reads as one unit. A
	// chunk ends after a newline or at chunkLen bytes, as fgets reads.
	chunkLen int
	// skip holds the bytes that make a chunk a comment when the chunk
	// starts with one of them.
	skip string
	// nulEndsLine is true when the reader uses strlen, so that a NUL byte
	// ends the chunk text.
	nulEndsLine bool
	// end is how the reader removes the line end from a chunk.
	end lineEnd
	// lineSeps holds the bytes that end a line inside a chunk.
	lineSeps string
	// seps holds the bytes that separate fields.
	seps string
	// comment is where "#" starts a comment.
	comment commentRule
	// addr reads the address field.
	addr func(string) (netip.Addr, bool)
	// name reads a name field.
	name func(string) (dnsname.Name, nameUse)
}

// nameUse tells how a reader uses a name field.
type nameUse int

const (
	// nameUsed: the reader uses the name, and Name represents it.
	nameUsed nameUse = iota
	// nameRefused: the reader does not use the field.
	nameRefused
	// nameUnrepresentable: the reader can use the name, but Name cannot
	// represent it. A query for the name is a possible leak.
	nameUnrepresentable
)

// lineEnd is a rule to remove the line end from a chunk.
type lineEnd int

const (
	// stripLineEnd removes the last byte when it is CR or LF, and then
	// once more.
	stripLineEnd lineEnd = iota
	// dropLastByte removes the last byte, whatever it is. A chunk without
	// a newline thus loses a byte of text.
	dropLastByte
	// keepLineEnd removes nothing. lineSeps then holds the newline.
	keepLineEnd
)

// commentRule is a rule for where "#" starts a comment. A comment goes to
// the end of the chunk.
type commentRule int

const (
	// commentFirstField: a first field that starts with "#".
	commentFirstField commentRule = iota
	// commentFieldStart: a field that starts with "#".
	commentFieldStart
	// commentAnywhere: any "#". It also ends the field before it.
	commentAnywhere
)

// mdnsResponder is the dialect of mDNSMacOSXParseEtcHosts in
// mDNSResponder-2600.140.3. It answers first on macOS.
func mdnsResponder() dialect {
	return dialect{
		chunkLen:    1024 - 1,     // ETCHOSTS_BUFSIZE, mDNSMacOSX.c:5591 and :5914
		skip:        "#\r\n",      // mDNSMacOSX.c:5918
		nulEndsLine: true,         // strlen, mDNSMacOSX.c:5921
		end:         stripLineEnd, // mDNSMacOSX.c:5924-5941
		seps:        " \t,",       // mDNSMacOSX.c:5733, :5773, :5799
		comment:     commentFieldStart,
		addr:        mdnsAddr,
		name:        mdnsName,
	}
}

// libinfo is the dialect of the hosts part of the Libinfo-600 file
// module. It answers when mDNSResponder has no answer.
//
// Libinfo skips a line that starts with "#" (file_module.c:1429) and has
// no other comment, so a name after "#" counts. A first field that starts
// with "#" after a separator is not an address, so the line has no entry
// in Libinfo either: commentFirstField gives the same entries.
//
// Libinfo compares a name as a plain string (file_module.c:1354), so the
// dialect reads it with literalName.
func libinfo() dialect {
	return dialect{
		chunkLen:    4096 - 1,     // _fsi_get_line, file_module.c:242 and :247
		skip:        "#",          // file_module.c:250 and :1429
		nulEndsLine: true,         // strlen, file_module.c:250
		end:         dropLastByte, // file_module.c:250
		seps:        " \t",        // _fsi_parse_host, file_module.c:1311
		comment:     commentFirstField,
		addr:        libinfoAddr,
		name:        literalName,
	}
}

// chromium is the dialect of the host file parser of Chromium
// (ParseHostsWithCommaMode, net/dns/dns_hosts.cc:132-176, with the macOS
// comma mode of :186-197). Chromium and every Electron app use it on
// macOS by default, before the system resolver.
//
// Chromium reads the whole file into memory and refuses a file over 32
// MiB (dns_hosts.cc:217-222). A chunk of that size is thus a whole line.
// CR and LF end a line (:49-53), and a NUL byte is a normal byte. A "#"
// ends the field before it (SkipToken, :100-109) and starts a comment.
// The comment, and an address that is not valid, skip the text up to the
// next LF, across a CR (SkipRestOfLine, :87).
func chromium() dialect {
	return dialect{
		chunkLen: 1 << 25, // kMaxHostsSize, dns_hosts.cc:218
		end:      keepLineEnd,
		lineSeps: "\r\n",
		seps:     " \t,",
		comment:  commentAnywhere,
		addr:     chromiumAddr,
		name:     chromiumName,
	}
}

// goResolver is the dialect of the pure-Go resolver of the Go net
// package (readHosts, net/hosts.go:52-115 in Go 1.27.2). A Go program uses
// it with Resolver.PreferGo, GODEBUG=netdns=go, or the netgo build tag;
// on macOS the default goes to the system resolver.
//
// It reads a line of at most 64 KiB (the buffer of file.readLine,
// net/parse.go:49 and :80); a longer line stops the read, and Parse
// continues instead. A "#" anywhere starts a comment (hosts.go:78-81).
// Space, tab, CR, and LF separate fields (getFields, hosts.go:82 and
// net/parse.go:123), so a CR is not a line end. The address is what
// netip.ParseAddr accepts, with an IPv6 zone (hosts.go:18-24). A name is
// a plain string, so the dialect reads it with literalName.
func goResolver() dialect {
	return dialect{
		chunkLen: 64 << 10,
		end:      keepLineEnd,
		lineSeps: "\n",
		seps:     " \r\t",
		comment:  commentAnywhere,
		addr:     goAddr,
		name:     literalName,
	}
}

// text returns the text that the reader parses from chunk, and false
// when the reader parses nothing from it.
func (d *dialect) text(chunk []byte) (string, bool) {
	if len(chunk) == 0 || strings.IndexByte(d.skip, chunk[0]) >= 0 {
		return "", false
	}
	if d.nulEndsLine {
		chunk, _, _ = bytes.Cut(chunk, []byte{0})
		if len(chunk) == 0 {
			return "", false
		}
	}
	switch d.end {
	case stripLineEnd:
		for range 2 {
			if n := len(chunk); n > 0 && (chunk[n-1] == '\r' || chunk[n-1] == '\n') {
				chunk = chunk[:n-1]
			}
		}
	case dropLastByte:
		chunk = chunk[:len(chunk)-1]
	case keepLineEnd:
	default:
		panic("hostsfile: unknown line end rule")
	}
	return string(chunk), true
}

// lines returns the lines of a chunk text. A blank line, which holds only
// separators of the dialect and line ends, is not returned: the reader
// finds no field in it. A CR that ends a macOS chunk without a newline
// is a line end too, so that a blank CRLF line is not malformed.
func (d *dialect) lines(text string) iter.Seq[string] {
	blank := d.seps + "\r\n"
	return func(yield func(string) bool) {
		for line := range strings.FieldsFuncSeq(text, func(r rune) bool { return isIn(d.lineSeps, r) }) {
			if strings.Trim(line, blank) == "" {
				continue
			}
			if !yield(line) {
				return
			}
		}
	}
}

// appendFields appends the fields of line before a comment to dst. It
// reports whether the line has a comment.
func (d *dialect) appendFields(dst []string, line string) ([]string, bool) {
	first := len(dst)
	for f := range strings.FieldsFuncSeq(line, func(r rune) bool { return isIn(d.seps, r) }) {
		switch d.comment {
		case commentFirstField:
			if f[0] == '#' && len(dst) == first {
				return dst, true
			}
		case commentFieldStart:
			if f[0] == '#' {
				return dst, true
			}
		case commentAnywhere:
			if before, _, found := strings.Cut(f, "#"); found {
				if before != "" {
					dst = append(dst, before)
				}
				return dst, true
			}
		default:
			panic("hostsfile: unknown comment rule")
		}
		dst = append(dst, f)
	}
	return dst, false
}

// isIn reports whether r is one of the ASCII bytes of set.
func isIn(set string, r rune) bool {
	return r < 0x80 && strings.IndexByte(set, byte(r)) >= 0
}
