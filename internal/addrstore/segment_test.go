package addrstore

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

func netipMust(s string) netip.Addr { return netip.MustParseAddr(s) }

// A record gives back what it was written from, for each address kind
// and for the longest policy name.
func TestRecordRoundTrip(t *testing.T) {
	long := policy.Name(strings.Repeat("p", policy.MaxNameLen))
	for _, k := range []key{
		{"web", addr("192.0.2.1")},
		{long, addr("2001:db8::1")},
	} {
		st := stamp{seen: t0.Add(90 * time.Second).UnixNano(), expiry: t0.Add(retain + 90*time.Second).UnixNano()}
		r, err := recordOf(k, st)
		if err != nil {
			t.Fatalf("recordOf(%v): %v", k, err)
		}
		got, ok, err := decodeRecord(r.appendTo(nil))
		if err != nil || !ok {
			t.Fatalf("decode(%v) = %v, %v", k, ok, err)
		}
		if got != r {
			t.Errorf("decode = %+v, want %+v", got, r)
		}
		if gotSt := got.stamp(0); gotSt.expiry < st.expiry+int64(renewAfter) {
			t.Errorf("%v: loaded expiry %v is before the written one + renewAfter", k, time.Unix(0, gotSt.expiry))
		}
	}
}

// writeSegment writes a segment of day with recs, and returns its bytes.
func writeSegment(t *testing.T, path, name string, day int64, recs ...lease) []byte {
	t.Helper()
	data := header(day)
	for _, r := range recs {
		data = r.appendTo(data)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return data
}

func leaseAt(t *testing.T, p policy.Name, a string, at time.Time) lease {
	t.Helper()
	r, err := recordOf(key{p, addr(a)}, stamp{seen: at.UnixNano(), expiry: at.Add(retain).UnixNano()})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var t0Day = t0.Unix() / 86400

// A bad record with a good one after it is damage: Open skips only that
// record, keeps the others, and Damage names its place.
func TestDamagedRecordIsSkippedAndReported(t *testing.T) {
	path := bookDir(t)
	name := segName(t0Day, 0)
	data := writeSegment(t, path, name, t0Day,
		leaseAt(t, "web", "192.0.2.1", t0), leaseAt(t, "web", "192.0.2.2", t0), leaseAt(t, "web", "192.0.2.3", t0))
	off := headerLen + recordLen // the second record
	data[off+30] ^= 0xff
	if err := os.WriteFile(filepath.Join(path, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := openCounted(t, path, "")
	if got := strs(s.Addrs("web")); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.3"}) {
		t.Errorf("web = %v, want the two good records", got)
	}
	err := s.Damage()
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "offset 88") {
		t.Errorf("Damage = %v, want ErrCorrupt at %s offset %d", err, name, off)
	}
	if _, err := Read(path, retain); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Read = %v, want ErrCorrupt", err)
	}
}

// A segment with a bad header is damage; the other segments load.
func TestDamagedHeaderLosesOnlyItsSegment(t *testing.T) {
	path := bookDir(t)
	bad := writeSegment(t, path, segName(t0Day, 0), t0Day, leaseAt(t, "web", "192.0.2.1", t0))
	bad[0] = 'X'
	if err := os.WriteFile(filepath.Join(path, segName(t0Day, 0)), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	writeSegment(t, path, segName(t0Day, 1), t0Day, leaseAt(t, "web", "192.0.2.2", t0))
	s, _ := openCounted(t, path, "")
	if got := strs(s.Addrs("web")); !slices.Equal(got, []string{"192.0.2.2"}) {
		t.Errorf("web = %v, want the record of the good segment", got)
	}
	if err := s.Damage(); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "header") {
		t.Errorf("Damage = %v, want a header error", err)
	}
	// The next append starts a new segment and does not touch the bad
	// one.
	record(t, s, "web", 0, t0, "192.0.2.3")
	if got := len(segments(t, path)); got != 3 {
		t.Errorf("%d segments, want 3", got)
	}
}

// A crash during an append leaves the records of the acknowledged groups
// and a part of the last group. Cut after each byte: a load keeps each
// acknowledged record and each complete record of the cut group, and
// reports no damage.
func TestTornTailAtEachByteIsNoDamage(t *testing.T) {
	acked := []lease{leaseAt(t, "web", "192.0.2.1", t0), leaseAt(t, "web", "192.0.2.2", t0)}
	cut := []lease{leaseAt(t, "web", "192.0.2.3", t0), leaseAt(t, "web", "2001:db8::3", t0)}
	full := header(t0Day)
	for _, r := range slices.Concat(acked, cut) {
		full = r.appendTo(full)
	}
	ackedLen := headerLen + len(acked)*recordLen
	for n := ackedLen; n <= len(full); n++ {
		seg := readSegment("s", full[:n], retain)
		if len(seg.damage) != 0 {
			t.Fatalf("cut at %d: damage %v", n, seg.damage)
		}
		if want := len(acked) + (n-ackedLen)/recordLen; len(seg.records) != want {
			t.Fatalf("cut at %d: %d records, want %d", n, len(seg.records), want)
		}
		// A torn record that reached the disk as zeros is the same.
		zeroed := slices.Concat(full[:n], make([]byte, len(full)-n))
		if seg := readSegment("s", zeroed, retain); len(seg.damage) != 0 || len(seg.records) < len(acked) {
			t.Fatalf("cut at %d with zeros: %d records, damage %v", n, len(seg.records), seg.damage)
		}
	}
	for n := range headerLen {
		if seg := readSegment(segName(t0Day, 0), full[:n], retain); len(seg.damage) != 0 || len(seg.records) != 0 {
			t.Fatalf("header cut at %d: %d records, damage %v", n, len(seg.records), seg.damage)
		}
	}
}

func TestSegmentNames(t *testing.T) {
	name := segName(t0Day, 12)
	if name != "2026-01-01.12.seg" {
		t.Errorf("segName = %q", name)
	}
	if day, seq, ok := parseSegName(name); !ok || day != t0Day || seq != 12 {
		t.Errorf("parseSegName(%q) = %d, %d, %v", name, day, seq, ok)
	}
	for _, bad := range []string{"lock", "2026-01-01.seg", "2026-01-01.01.seg", "2026-01-01.-1.seg", "x.0.seg", "2026-01-01.0.seg.tmp"} {
		if _, _, ok := parseSegName(bad); ok {
			t.Errorf("parseSegName(%q) accepted", bad)
		}
	}
}

// Any bytes give records or damage, never a panic, and each record that
// a load keeps has a key that the book can hold.
func FuzzReadSegment(f *testing.F) {
	good := header(t0Day)
	r, err := recordOf(key{"web", addr("192.0.2.1")}, stamp{seen: t0.UnixNano(), expiry: t0.Add(retain).UnixNano()})
	if err != nil {
		f.Fatal(err)
	}
	good = r.appendTo(good)
	f.Add(good)
	f.Add(good[:headerLen+10])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		seg := readSegment(segName(t0Day, 0), data, retain)
		for _, r := range seg.records {
			if r.policy == "" || len(r.policy) > policy.MaxNameLen || !r.addr.Valid() {
				t.Fatalf("bad record %+v", r)
			}
		}
		for _, err := range seg.damage {
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("damage %v does not wrap ErrCorrupt", err)
			}
		}
	})
}
