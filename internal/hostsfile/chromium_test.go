// chromeCompliant in this file is a port of IsCanonicalizedHostCompliant
// in the Chromium file net/base/url_util.cc (commit
// 2600dc0efdc944b3214d54302514fc3c1aa1522b), Copyright 2013 The Chromium
// Authors, under the BSD 3-Clause license; the full text is in
// LICENSES/BSD-3-Clause-Chromium.txt at the root of the repository, and
// NOTICE lists it.

package hostsfile

import (
	"encoding/json"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
)

// The corpus holds, for each field, the address and the URL host that a
// real Chrome makes from it. testdata/urlhost.py makes it; the file says
// how.
//
// chromiumAddr must accept exactly the fields that Chrome reads as an
// address, with the same address. A URL host goes through IDNA before the
// address parsers and a host file address does not, so the test uses only
// ASCII fields without "%" for addresses.
//
// chromiumName must accept every field whose Chrome host is a compliant
// name, with the same name. It must refuse every other field, except a
// field that needs IDNA: there chromiumIDNA skips the Bidi and ContextJ
// checks of Chrome, so it accepts more.
func TestChromiumMatchesChrome(t *testing.T) {
	t.Parallel()
	var addrs, names int
	records := readURLHostCorpus(t)
	for _, r := range records {
		if r.addr != nil {
			addrs++
		}
		if r.host != nil {
			names++
		}
		if !strings.ContainsFunc(r.field, func(c rune) bool { return c == '%' || c >= 0x80 }) {
			checkChromiumAddr(t, r.field, r.addr)
		}
		if !strings.Contains(r.field, ":") {
			checkChromiumName(t, r.field, r.host)
		}
	}
	if len(records) < 1000 || addrs < 1000 || names < 1000 {
		t.Fatalf("corpus has %d records, %d addresses, %d hosts", len(records), addrs, names)
	}
}

type urlHostRecord struct {
	field      string
	addr, host *string
}

func readURLHostCorpus(t *testing.T) []urlHostRecord {
	t.Helper()
	data, err := os.ReadFile("testdata/urlhost.tsv")
	if err != nil {
		t.Fatal(err)
	}
	var out []urlHostRecord
	for line := range strings.Lines(string(data)) {
		if strings.HasPrefix(line, "#chrome\t") {
			continue
		}
		var rec [3]*string
		f := strings.Split(strings.TrimSuffix(line, "\n"), "\t")
		if len(f) != len(rec) {
			t.Fatalf("bad corpus record %q", line)
		}
		for i := range rec {
			if err := json.Unmarshal([]byte(f[i]), &rec[i]); err != nil || (i == 0 && rec[i] == nil) {
				t.Fatalf("bad corpus record %q: %v", line, err)
			}
		}
		out = append(out, urlHostRecord{*rec[0], rec[1], rec[2]})
	}
	return out
}

func checkChromiumAddr(t *testing.T, field string, want *string) {
	t.Helper()
	got, ok := chromiumAddr(field)
	switch {
	case want == nil && ok:
		t.Errorf("chromiumAddr(%q) = %v, Chrome refuses it", field, got)
	case want != nil && !ok:
		t.Errorf("chromiumAddr(%q) refused, Chrome reads %s", field, *want)
	case want != nil && got != netip.MustParseAddr(*want).Unmap():
		t.Errorf("chromiumAddr(%q) = %v, Chrome reads %s", field, got, *want)
	}
}

// checkChromiumName checks chromiumName against the host of Chrome. The
// family and compliance checks of the test are separate from those of
// chromium.go: Chrome writes an IPv4 host as four decimal parts, and
// chromeCompliant is its own port of IsCanonicalizedHostCompliant.
func checkChromiumName(t *testing.T, field string, host *string) {
	t.Helper()
	var want dnsname.Name
	if host != nil && !dottedQuad.MatchString(*host) && chromeCompliant(*host) {
		var err error
		want, err = dnsname.Parse(*host)
		if err != nil {
			t.Fatal(err)
		}
	}
	got, use := chromiumName(field)
	_, _, idn := simpleHost(field)
	switch {
	case want == (dnsname.Name{}) && use == nameUsed && !idn:
		t.Errorf("chromiumName(%q) = %q, Chrome host %v is not a compliant name", field, got, deref(host))
	case want != (dnsname.Name{}) && got != want:
		t.Errorf("chromiumName(%q) = %q, %v; Chrome reads %q", field, got, use, want)
	}
}

var dottedQuad = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`)

// chromeCompliant is IsCanonicalizedHostCompliant
// (net/base/url_util.cc:377-415), written for the test apart from
// hostCompliant.
func chromeCompliant(host string) bool {
	if host == "" || len(host) > 254 || (host[len(host)-1] != '.' && len(host) == 254) {
		return false
	}
	alnum := func(c byte) bool {
		return strings.IndexByte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", c) >= 0
	}
	labelByte := func(c byte) bool { return alnum(c) || c == '-' || c == '_' }
	in, started, size := false, false, 0
	for i := range len(host) {
		c := host[i]
		size++
		switch {
		case !in:
			started, in = alnum(c), true
			if !labelByte(c) {
				return false
			}
		case c == '.':
			in = false
			if size > 64 || size == 1 {
				return false
			}
			size = 0
		case !labelByte(c):
			return false
		}
	}
	return size <= 63 && started
}

func deref(s *string) string {
	if s == nil {
		return "<refused>"
	}
	return *s
}
