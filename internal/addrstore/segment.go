package addrstore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io/fs"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// The file format. A book is a directory of segments and a lock file. A
// segment is an append-only file named "YYYY-MM-DD.N.seg": the UTC day
// of its first write and a sequence number for that day. It starts with
// a header and holds records after it. All integers are big-endian.
//
// Header (headerLen bytes):
//
//	0   8  magic "IFBLEASE"
//	8   2  format version (formatVersion)
//	10  2  reserved, zero
//	12  4  the UTC day of the name, as days since the Unix epoch
//	16  12 reserved, zero
//	28  4  CRC-32C of bytes 0 to 27
//
// Record (recordLen bytes), one lease:
//
//	0   24 policy name, ASCII, zero-padded (policy.MaxNameLen)
//	24  16 address, netip.Addr.As16
//	40  1  family: 4 for an IPv4 address (in its IPv4-mapped form at
//	       24), 6 for an IPv6 address. A load checks it against the
//	       address. blockable.Addr holds no IPv4-mapped IPv6 address.
//	41  3  reserved, zero
//	44  4  write time, minutes since the Unix epoch
//	48  4  hold, minutes: the entry is kept until write time + hold
//	52  4  CRC-32C of bytes 0 to 51
//
// A record has a fixed size, so the file has no length field: record n
// is always at headerLen + n*recordLen, and a damaged record cannot hide
// the records after it.
const (
	headerLen     = 32
	recordLen     = 56
	formatVersion = 1
	segSuffix     = ".seg"
	lockName      = "lock"
	dayLayout     = "2006-01-02"
)

const magic = "IFBLEASE"

// crc returns the CRC-32C of b. crc32.MakeTable makes the Castagnoli
// table one time only.
func crc(b []byte) uint32 { return crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli)) }

// The ways that a record or a header is not in the file format.
var (
	errBadCRC      = errors.New("bad checksum")
	errBadName     = errors.New("bad policy name")
	errBadFamily   = errors.New("bad address family")
	errBadReserved = errors.New("reserved bytes not zero")
	errBadMagic    = errors.New("not a segment")
	errBadVersion  = errors.New("unknown format version")
)

// lease is one record on disk.
type lease struct {
	policy policy.Name
	addr   blockable.Addr
	minute uint32 // write time, minutes since the Unix epoch
	hold   uint32 // minutes after the write time
}

// recordOf returns the record that keeps st: its write time is the
// minute of st.seen, and its hold reaches at least st.expiry. It returns
// an error that wraps ErrTimeRange when the fields cannot hold st, and
// ErrLongPolicy for a name that does not fit.
func recordOf(k key, st stamp) (lease, error) {
	if len(k.policy) > policy.MaxNameLen {
		return lease{}, fmt.Errorf("%w: %q", ErrLongPolicy, k.policy)
	}
	minNanos := int64(time.Minute)
	if st.seen < 0 || st.seen/minNanos > math.MaxUint32 || st.expiry < st.seen {
		return lease{}, fmt.Errorf("%w: last seen %v, expiry %v", ErrTimeRange, time.Unix(0, st.seen), time.Unix(0, st.expiry))
	}
	at := st.seen / minNanos
	hold := (st.expiry - at*minNanos + minNanos - 1) / minNanos
	if hold > math.MaxUint32 {
		return lease{}, fmt.Errorf("%w: hold of %v", ErrTimeRange, time.Duration(st.expiry-st.seen))
	}
	return lease{k.policy, k.addr, uint32(at), uint32(hold)}, nil
}

// stamp returns the entry that r gives with the floor retain: kept until
// the write time + renewAfter + the larger of the hold and retain.
// renewAfter covers the refreshes that Touch keeps in memory only. The
// result is never earlier than the expiry that recordOf got.
func (r lease) stamp(retain time.Duration) stamp {
	seen := int64(r.minute) * int64(time.Minute)
	hold := max(time.Duration(r.hold)*time.Minute, retain)
	return stamp{seen: seen, expiry: seen + int64(renewAfter) + int64(hold)}
}

func (r lease) key() key { return key{r.policy, r.addr} }

func (r lease) appendTo(b []byte) []byte {
	start := len(b)
	b = append(b, make([]byte, recordLen)...)
	rec := b[start:]
	copy(rec[0:policy.MaxNameLen], r.policy)
	ip := r.addr.Addr()
	a16 := ip.As16()
	copy(rec[24:40], a16[:])
	rec[40] = 6
	if ip.Is4() {
		rec[40] = 4
	}
	binary.BigEndian.PutUint32(rec[44:48], r.minute)
	binary.BigEndian.PutUint32(rec[48:52], r.hold)
	binary.BigEndian.PutUint32(rec[52:56], crc(rec[:52]))
	return b
}

// decodeRecord returns the record in b (recordLen bytes). The bool is
// false for a record whose address blockable.New refuses.
func decodeRecord(b []byte) (lease, bool, error) {
	if binary.BigEndian.Uint32(b[52:56]) != crc(b[:52]) {
		return lease{}, false, errBadCRC
	}
	rawName := b[0:policy.MaxNameLen]
	n := bytes.IndexByte(rawName, 0)
	if n < 0 {
		n = len(rawName)
	}
	if n == 0 || bytes.ContainsFunc(rawName[n:], func(r rune) bool { return r != 0 }) {
		return lease{}, false, errBadName
	}
	if b[41] != 0 || b[42] != 0 || b[43] != 0 {
		return lease{}, false, errBadReserved
	}
	ip := netip.AddrFrom16([16]byte(b[24:40]))
	switch b[40] {
	case 4:
		if !ip.Is4In6() {
			return lease{}, false, errBadFamily
		}
		ip = ip.Unmap()
	case 6:
		if ip.Is4In6() {
			return lease{}, false, errBadFamily
		}
	default:
		return lease{}, false, errBadFamily
	}
	a, ok := blockable.New(ip)
	return lease{
		policy: policy.Name(rawName[:n]),
		addr:   a,
		minute: binary.BigEndian.Uint32(b[44:48]),
		hold:   binary.BigEndian.Uint32(b[48:52]),
	}, ok, nil
}

func header(day int64) []byte {
	h := make([]byte, headerLen)
	copy(h[0:8], magic)
	binary.BigEndian.PutUint16(h[8:10], formatVersion)
	binary.BigEndian.PutUint32(h[12:16], uint32(day))
	binary.BigEndian.PutUint32(h[28:32], crc(h[:28]))
	return h
}

func checkHeader(h []byte) error {
	switch {
	case binary.BigEndian.Uint32(h[28:32]) != crc(h[:28]):
		return errBadCRC
	case string(h[0:8]) != magic:
		return errBadMagic
	case binary.BigEndian.Uint16(h[8:10]) != formatVersion:
		return errBadVersion
	}
	return nil
}

// segName returns the name of segment seq of day.
func segName(day int64, seq int) string {
	return time.Unix(day*86400, 0).UTC().Format(dayLayout) + "." + strconv.Itoa(seq) + segSuffix
}

// parseSegName returns the day and the sequence number of a segment
// name, and false for a name that is not one.
func parseSegName(name string) (day int64, seq int, ok bool) {
	base, found := strings.CutSuffix(name, segSuffix)
	if !found {
		return 0, 0, false
	}
	date, num, found := strings.Cut(base, ".")
	if !found {
		return 0, 0, false
	}
	t, err := time.Parse(dayLayout, date)
	if err != nil {
		return 0, 0, false
	}
	seq, err = strconv.Atoi(num)
	if err != nil || seq < 0 || strconv.Itoa(seq) != num {
		return 0, 0, false
	}
	return t.Unix() / 86400, seq, true
}

// segment is what a load found in one segment.
type segment struct {
	name    string
	records []lease
	// bound is the latest expiry that a record of the segment can give:
	// after it, the segment holds nothing that a load keeps.
	bound int64
	// damage is the error for each place that is not in the file format,
	// with ErrCorrupt in its chain.
	damage []error
}

// readSegment parses the bytes of one segment. A run of bad records and
// a part record at the end are a write that never completed: no ack
// came after it, so it is not damage. A bad record with a good one after
// it is damage, and so is a bad header.
func readSegment(name string, data []byte, retain time.Duration) segment {
	seg := segment{name: name}
	if len(data) < headerLen {
		// A creation that never completed: no ack came after it.
		seg.bound = nameBound(name, retain)
		return seg
	}
	if err := checkHeader(data[:headerLen]); err != nil {
		seg.bound = nameBound(name, retain)
		seg.damage = append(seg.damage, fmt.Errorf("%w: segment %s: header: %v", ErrCorrupt, name, err))
		return seg
	}
	var pending []error // bad records since the last good one
	for off := headerLen; off+recordLen <= len(data); off += recordLen {
		r, ok, err := decodeRecord(data[off : off+recordLen])
		if err != nil {
			pending = append(pending, fmt.Errorf("%w: segment %s offset %d: %v", ErrCorrupt, name, off, err))
			continue
		}
		seg.damage = append(seg.damage, pending...)
		pending = nil
		seg.bound = max(seg.bound, r.stamp(retain).expiry)
		if ok {
			seg.records = append(seg.records, r)
		}
	}
	return seg
}

// nameBound is the bound of a segment whose records cannot be read: the
// end of the day of its name + renewAfter + retain.
func nameBound(name string, retain time.Duration) int64 {
	day, _, _ := parseSegName(name)
	return (day+1)*86400*int64(time.Second) + int64(renewAfter) + int64(retain)
}

// segDir is the directory of a book. Only the committer uses it after
// Open.
type segDir struct {
	root *os.Root
	lock *os.File
	// sync makes a file durable: F_FULLFSYNC on darwin. A test replaces it.
	sync func(*os.File) error

	cur  *os.File // the segment that takes appends; nil before the first one
	name string
	day  int64
	size int64

	bounds map[string]int64 // the bound of each segment, for gc
}

// openDir opens the book directory at path, creates it when it is
// missing, and takes its lock.
func openDir(path string) (*segDir, error) {
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close() //nolint:errcheck // a read-only handle to resolve the book directory
	base := filepath.Base(path)
	if err := parent.Mkdir(base, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	if fi, err := parent.Lstat(base); err != nil {
		return nil, err
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("%w: %s is not a directory", ErrBadPath, path)
	}
	root, err := parent.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	lock, err := root.OpenFile(lockName, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		_ = root.Close() //nolint:errcheck // the open error is the one to report
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close() //nolint:errcheck // the lock error is the one to report
		_ = root.Close() //nolint:errcheck // the lock error is the one to report
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s", ErrLocked, path)
		}
		return nil, err
	}
	return &segDir{root: root, lock: lock, sync: (*os.File).Sync, bounds: make(map[string]int64)}, nil
}

// load reads every segment of the directory, in name order.
func loadSegments(root *os.Root, retain time.Duration) ([]segment, error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	ents, err := dir.ReadDir(-1)
	_ = dir.Close() //nolint:errcheck // a read-only directory handle
	if err != nil {
		return nil, err
	}
	var segs []segment
	for _, e := range ents {
		if _, _, ok := parseSegName(e.Name()); !ok || !e.Type().IsRegular() {
			continue
		}
		data, err := root.ReadFile(e.Name())
		if err != nil {
			return nil, err
		}
		segs = append(segs, readSegment(e.Name(), data, retain))
	}
	return segs, nil
}

// append writes recs at the end of the segment for day, and makes them
// durable. It starts a new segment for a later day, at the first append,
// and after a failed append: the state of a file after a failed write or
// sync is not known. A new segment also syncs the directory, so that its
// name is durable. day is never earlier than the segment in use.
func (d *segDir) append(recs []lease, day int64, retain time.Duration) error {
	var buf []byte
	if d.cur != nil && day > d.day {
		d.closeCur()
	}
	fresh := d.cur == nil
	if fresh {
		if err := d.create(max(day, d.day)); err != nil {
			return err
		}
		buf = header(d.day)
	}
	var bound int64
	for _, r := range recs {
		buf = r.appendTo(buf)
		bound = max(bound, r.stamp(retain).expiry)
	}
	if _, err := d.cur.WriteAt(buf, d.size); err != nil {
		d.closeCur()
		return err
	}
	if err := d.sync(d.cur); err != nil {
		d.closeCur()
		return err
	}
	if fresh {
		if err := d.syncDir(); err != nil {
			d.closeCur()
			return err
		}
	}
	d.size += int64(len(buf))
	d.bounds[d.name] = max(d.bounds[d.name], bound)
	return nil
}

// create makes the next free segment of day the one in use.
func (d *segDir) create(day int64) error {
	for seq := 0; ; seq++ {
		name := segName(day, seq)
		f, err := d.root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		d.cur, d.name, d.day, d.size = f, name, day, 0
		return nil
	}
}

func (d *segDir) closeCur() {
	if d.cur != nil {
		_ = d.cur.Close() //nolint:errcheck // each record in it was synced, or its group failed; a close error loses nothing
		d.cur = nil
	}
}

func (d *segDir) syncDir() error {
	f, err := d.root.Open(".")
	if err != nil {
		return err
	}
	err = d.sync(f)
	return errors.Join(err, f.Close())
}

// gc removes each segment, but the one in use, whose bound is before
// now: none of its records gives an entry that is still kept. retain
// adds to the bound of a record at the next load, so the bounds use the
// retain of the load or more.
func (d *segDir) gc(now int64) error {
	var errs []error
	for name, b := range d.bounds {
		if b >= now || (d.cur != nil && name == d.name) {
			continue
		}
		if err := d.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
			continue
		}
		delete(d.bounds, name)
	}
	return errors.Join(errs...)
}

func (d *segDir) close() error {
	d.closeCur()
	// Closing the lock file releases the lock.
	return errors.Join(d.lock.Close(), d.root.Close())
}
