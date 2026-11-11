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
// and a part of the last group. Cut after each byte. In the last segment
// a load keeps each acknowledged record and each complete record of the
// cut group, reports no damage, and marks the cut. In an older segment
// the same bytes are damage, except a cut at a record boundary, which
// leaves no trace.
func TestCutEndIsACutWriteOnlyInTheLastSegment(t *testing.T) {
	acked := []lease{leaseAt(t, "web", "192.0.2.1", t0), leaseAt(t, "web", "192.0.2.2", t0)}
	cut := []lease{leaseAt(t, "web", "192.0.2.3", t0), leaseAt(t, "web", "2001:db8::3", t0)}
	full := header(t0Day)
	for _, r := range slices.Concat(acked, cut) {
		full = r.appendTo(full)
	}
	ackedLen := headerLen + len(acked)*recordLen
	for n := ackedLen; n <= len(full); n++ {
		checkCut(t, full, n, len(acked))
	}
	for n := range headerLen {
		if seg := readSegment(segName(t0Day, 0), full[:n], true, retain); len(seg.damage) != 0 || !seg.torn || seg.end != 0 {
			t.Fatalf("last, header cut at %d: torn %v, damage %v", n, seg.torn, seg.damage)
		}
		if seg := readSegment(segName(t0Day, 0), full[:n], false, retain); len(seg.damage) == 0 {
			t.Fatalf("older, header cut at %d: no damage", n)
		}
	}
}

// checkCut checks the load of full cut after n bytes, of which the first
// acked records are whole.
func checkCut(t *testing.T, full []byte, n, acked int) {
	t.Helper()
	ackedLen := headerLen + acked*recordLen
	complete := (n - ackedLen) / recordLen
	atBoundary := (n-headerLen)%recordLen == 0
	seg := readSegment("s", full[:n], true, retain)
	if len(seg.damage) != 0 || len(seg.records) != acked+complete {
		t.Fatalf("last, cut at %d: %d records, damage %v", n, len(seg.records), seg.damage)
	}
	if seg.torn == atBoundary || seg.torn && seg.end != ackedLen+complete*recordLen {
		t.Fatalf("last, cut at %d: torn %v, end %d", n, seg.torn, seg.end)
	}
	if seg := readSegment("s", full[:n], false, retain); (len(seg.damage) == 0) != atBoundary || seg.torn {
		t.Fatalf("older, cut at %d: damage %v, torn %v", n, seg.damage, seg.torn)
	}
	// A cut write that reached the disk as zeros is the same.
	zeroed := slices.Concat(full[:n], make([]byte, len(full)-n))
	if seg := readSegment("s", zeroed, true, retain); len(seg.damage) != 0 || len(seg.records) < acked {
		t.Fatalf("last, cut at %d with zeros: %d records, damage %v", n, len(seg.records), seg.damage)
	}
}

// A bad last record of an older segment is damage: an ack came after it.
// Open reports it and keeps the rest.
func TestBadEndOfAnOlderSegmentIsDamage(t *testing.T) {
	path := bookDir(t)
	old := writeSegment(t, path, segName(t0Day, 0), t0Day, leaseAt(t, "web", "192.0.2.1", t0), leaseAt(t, "web", "192.0.2.2", t0))
	old[len(old)-1] ^= 0xff
	if err := os.WriteFile(filepath.Join(path, segName(t0Day, 0)), old, 0o600); err != nil {
		t.Fatal(err)
	}
	writeSegment(t, path, segName(t0Day, 1), t0Day, leaseAt(t, "web", "192.0.2.3", t0))
	s, _ := openCounted(t, path, "")
	if err := s.Damage(); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), segName(t0Day, 0)) {
		t.Errorf("Damage = %v, want ErrCorrupt in %s", err, segName(t0Day, 0))
	}
	if s.Torn() {
		t.Error("Torn = true, want false: the last segment is whole")
	}
	if got := strs(s.Addrs("web")); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.3"}) {
		t.Errorf("web = %v, want the good records", got)
	}
}

// Open removes a cut write at the end of the last segment and makes that
// durable, so that the next load sees no cut there, also after a newer
// segment exists.
func TestCutWriteOfTheLastSegmentIsRepaired(t *testing.T) {
	path := bookDir(t)
	name := segName(t0Day, 0)
	data := writeSegment(t, path, name, t0Day, leaseAt(t, "web", "192.0.2.1", t0), leaseAt(t, "web", "192.0.2.2", t0))
	whole := len(data)
	data = leaseAt(t, "web", "192.0.2.3", t0).appendTo(data)[:whole+recordLen/2]
	if err := os.WriteFile(filepath.Join(path, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := openCounted(t, path, "")
	if !s.Torn() || s.Damage() != nil {
		t.Fatalf("Torn = %v, Damage = %v; want true, nil", s.Torn(), s.Damage())
	}
	if fi, err := os.Stat(filepath.Join(path, name)); err != nil || fi.Size() != int64(whole) {
		t.Fatalf("size after the repair = %v, %v; want %d", fi.Size(), err, whole)
	}
	record(t, s, "web", 0, t0, "192.0.2.9") // a newer segment
	s = reopen(t, s, path, retain)
	if s.Torn() || s.Damage() != nil {
		t.Errorf("after the reopen: Torn = %v, Damage = %v; want false, nil", s.Torn(), s.Damage())
	}
}

// A failed append takes back what it wrote: a later load finds no trace
// of the group that got no ack, also when a newer segment follows.
func TestFailedAppendTakesBackItsRecords(t *testing.T) {
	path := bookDir(t)
	s, c := openCounted(t, path, "")
	record(t, s, "web", 0, t0, "192.0.2.1")
	c.set(func(c *syncs) { c.fail = errInjected })
	if err := commitOne(s, "web", "192.0.2.2"); !errors.Is(err, errInjected) {
		t.Fatalf("commit = %v, want the injected error", err)
	}
	c.set(func(c *syncs) { c.fail = nil })
	record(t, s, "web", 0, t0, "192.0.2.3")
	s = reopen(t, s, path, retain)
	if s.Damage() != nil || s.Torn() {
		t.Errorf("Damage = %v, Torn = %v; want nil, false", s.Damage(), s.Torn())
	}
	if got := strs(s.Addrs("web")); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.3"}) {
		t.Errorf("web = %v, want only the acknowledged addresses", got)
	}
	// A failed first append of a segment removes the segment.
	s2, c2 := openCounted(t, bookDir(t), "")
	c2.set(func(c *syncs) { c.fail = errInjected })
	if err := commitOne(s2, "web", "192.0.2.4"); !errors.Is(err, errInjected) {
		t.Fatalf("first commit = %v, want the injected error", err)
	}
	if got := segments(t, s2.dir.root.Name()); len(got) != 0 {
		t.Errorf("segments after a failed first append = %v, want none", got)
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
	f.Add(good, true)
	f.Add(good[:headerLen+10], true)
	f.Add(good[:headerLen+10], false)
	f.Add([]byte{}, false)
	f.Fuzz(func(t *testing.T, data []byte, last bool) {
		seg := readSegment(segName(t0Day, 0), data, last, retain)
		for _, r := range seg.records {
			if r.policy == "" || len(r.policy) > policy.MaxNameLen || !r.addr.Valid() {
				t.Fatalf("bad record %+v", r)
			}
		}
		if seg.torn && (!last || seg.end > len(data)) {
			t.Fatalf("torn %v, end %d of %d bytes, last %v", seg.torn, seg.end, len(data), last)
		}
		for _, err := range seg.damage {
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("damage %v does not wrap ErrCorrupt", err)
			}
		}
	})
}
