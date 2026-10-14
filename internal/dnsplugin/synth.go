package dnsplugin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// A synthetic name has the form <target>._ifb.<tag>.<origin>. The plugin
// puts it in place of an alias target of an HTTPS or SVCB record (see
// flatten). The name is below origin, so the client sends its query to
// the resolver entry of origin, and thus to ifbound-dns. The plugin then
// resolves target upstream and reports the addresses under origin.
//
// The tag is an HMAC of target and origin. Only the plugin can make a
// valid tag, so a local program cannot make the plugin resolve a name of
// its choice and make ifboundd block the addresses for the policies of
// origin.
const (
	// synthLabel is the label between target and tag. A name that has
	// it after its first label is reserved for synthetic names.
	synthLabel = "_ifb"
	// tagOctets is the length of the truncated HMAC: 128 bits. Base32
	// gives 26 letters and digits, one label.
	tagOctets = 16
	// maxWireLen is the longest name on the wire (RFC 1035 section 2.3.4).
	maxWireLen = 255
	// maxSynthTTL is the longest TTL, in seconds, of a record that has a
	// synthetic name. A restart makes a new key, and the names of the old
	// key then get SERVFAIL (see tagKey). The cap keeps such a name in a
	// client cache for at most 5 minutes.
	maxSynthTTL = 300
)

var (
	errBadTag   = errors.New("synthetic name with a tag that this process did not make")
	errLongName = errors.New("name longer than 255 octets")
)

// tagKey is the HMAC key of the tags. Each start of ifbound-dns makes a
// new key, so a synthetic name from an earlier run gets SERVFAIL. Its
// record expires in the client cache after at most maxSynthTTL, and the
// client then asks again for the origin and gets new names.
type tagKey struct {
	b [32]byte
}

func newTagKey() *tagKey {
	k := new(tagKey)
	_, _ = rand.Read(k.b[:]) // crypto/rand.Read never returns an error; it stops the program if the OS has no randomness
	return k
}

// tag returns the tag for target below origin. Both are canonical wire
// names. A wire name ends with its root octet, so the concatenation has
// one split only.
func (k *tagKey) tag(target, origin []byte) string {
	mac := hmac.New(sha256.New, k.b[:])
	mac.Write(target)
	mac.Write(origin)
	sum := mac.Sum(nil)[:tagOctets]
	return strings.ToLower(tagEncoding().EncodeToString(sum))
}

// tagEncoding is base32 without padding. The tag uses it in lower case:
// letters and digits only, so the label is a valid host name label.
func tagEncoding() *base32.Encoding { return base32.StdEncoding.WithPadding(base32.NoPadding) }

// synthName returns the synthetic name for target below owner. It is false
// when the name would be longer than maxWireLen, and for the root as
// owner: no policy protects the root, and parse needs an origin label.
func (k *tagKey) synthName(target, owner string) (string, bool) {
	tw, terr := canonicalWire(target)
	ow, oerr := canonicalWire(owner)
	if terr != nil || oerr != nil || len(ow) == 1 {
		return "", false
	}
	// The labels of target without its root octet, the synthLabel and
	// tag labels with their length octets, and owner.
	if len(tw)-1+1+len(synthLabel)+1+tagEncoding().EncodedLen(tagOctets)+len(ow) > maxWireLen {
		return "", false
	}
	return dns.Fqdn(target) + synthLabel + "." + k.tag(tw, ow) + "." + dns.Fqdn(owner), true
}

// synthetic is a valid synthetic name, split into its parts.
type synthetic struct {
	target string
	origin string
}

// parse splits qname. ok is false when qname is not a synthetic name.
// A name with synthLabel after its first label and no valid tag gives
// errBadTag: such a name must not go upstream. Tags compare without
// ASCII case, because a resolver can change the case of a query name.
func (k *tagKey) parse(qname string) (s synthetic, ok bool, err error) {
	raw, err := wireName(qname)
	if err != nil {
		// A name that does not pack is not synthetic. The next plugin
		// answers it.
		return synthetic{}, false, nil
	}
	canon := foldWire(raw)
	var offs []int
	for off := 0; canon[off] != 0; off += 1 + int(canon[off]) {
		offs = append(offs, off)
	}
	label := func(i int) string { return string(canon[offs[i]+1 : offs[i]+1+int(canon[offs[i]])]) }
	shaped := false
	for i := 1; i < len(offs); i++ {
		if label(i) != synthLabel {
			continue
		}
		shaped = true
		if i+2 >= len(offs) {
			continue // no tag, or no origin
		}
		target := append(canon[:offs[i]:offs[i]], 0)
		origin := canon[offs[i+2]:]
		if !hmac.Equal([]byte(k.tag(target, origin)), []byte(label(i+1))) {
			continue
		}
		t, _, terr := dns.UnpackDomainName(append(raw[:offs[i]:offs[i]], 0), 0)
		o, _, oerr := dns.UnpackDomainName(raw[offs[i+2]:], 0)
		if terr != nil || oerr != nil {
			return synthetic{}, false, fmt.Errorf("splitting %s: %w", qname, errors.Join(terr, oerr))
		}
		return synthetic{target: t, origin: o}, true, nil
	}
	if shaped {
		return synthetic{}, false, fmt.Errorf("%w: %s", errBadTag, qname)
	}
	return synthetic{}, false, nil
}

// reportName returns the name that a synthetic name reports under: the
// first origin that is not itself synthetic. A nested synthetic name comes
// from an alias target of a reply to a synthetic name.
func (k *tagKey) reportName(origin string) (string, error) {
	for {
		s, ok, err := k.parse(origin)
		if err != nil {
			return "", err
		}
		if !ok {
			return origin, nil
		}
		origin = s.origin // shorter each time, so the loop ends
	}
}

// wireName packs a presentation name in wire form, with its case.
func wireName(name string) ([]byte, error) {
	buf := make([]byte, maxWireLen+1)
	n, err := dns.PackDomainName(dns.Fqdn(name), buf, 0, nil, false)
	switch {
	case err != nil:
		return nil, fmt.Errorf("packing %q: %w", name, err)
	case n > maxWireLen: // PackDomainName does not check this limit
		return nil, fmt.Errorf("%w: %q", errLongName, name)
	}
	return buf[:n], nil
}

// canonicalWire is the wire form with ASCII letters in lower case. Two
// spellings of one name give the same bytes.
func canonicalWire(name string) ([]byte, error) {
	w, err := wireName(name)
	if err != nil {
		return nil, err
	}
	return foldWire(w), nil
}

// foldWire returns a copy of w with ASCII letters in lower case. A length
// octet is below 64, so it is never a letter.
func foldWire(w []byte) []byte {
	out := make([]byte, len(w))
	for i, c := range w {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}
