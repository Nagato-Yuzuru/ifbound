package pf

import (
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"
)

var errPrefix = errors.New("prefix is not valid")

// Table names a table in an anchor. Anchor "" is the main ruleset.
type Table struct {
	Anchor string
	Name   string
}

func (t Table) String() string {
	if t.Anchor == "" {
		return t.Name
	}
	return t.Anchor + ":" + t.Name
}

// Addr is a table entry. A negated entry exempts its addresses from the
// table.
type Addr struct {
	Prefix  netip.Prefix
	Negated bool
}

// Feedback is the result of a table operation for one address.
type Feedback uint8

// The results that AddAddrs and DeleteAddrs return.
const (
	// FeedbackNone: the operation changed nothing. The table holds the
	// address already (add), or it does not hold it (delete).
	FeedbackNone Feedback = pfrFbNone
	// FeedbackAdded: the operation added the address.
	FeedbackAdded Feedback = pfrFbAdded
	// FeedbackDeleted: the operation deleted the address.
	FeedbackDeleted Feedback = pfrFbDeleted
	// FeedbackConflict: the table holds the same prefix with the other
	// negation. The operation changed nothing.
	FeedbackConflict Feedback = pfrFbConflict
	// FeedbackDuplicate: the address occurs before in the same call. The
	// operation changed nothing for this occurrence.
	FeedbackDuplicate Feedback = pfrFbDuplicate
)

func (f Feedback) String() string {
	switch f {
	case FeedbackNone:
		return "none"
	case FeedbackAdded:
		return "added"
	case FeedbackDeleted:
		return "deleted"
	case FeedbackConflict:
		return "conflict"
	case FeedbackDuplicate:
		return "duplicate"
	default:
		return fmt.Sprintf("Feedback(%d)", uint8(f))
	}
}

// CreateTable creates the table t, and its anchor when necessary. The
// table persists when no rule refers to it. A table that exists already is
// not an error.
func (h *Handle) CreateTable(t Table) error {
	var tbl pfrTable
	if err := t.encode(&tbl); err != nil {
		return fmt.Errorf("pf: creating table %s: %w", t, err)
	}
	tbl.Flags = pfrTflagPersist
	io := pfiocTable{
		Buffer: (*byte)(unsafe.Pointer(&tbl)),
		Esize:  int32(unsafe.Sizeof(tbl)),
		Size:   1,
	}
	if err := h.ioctl(diocRAddTables, unsafe.Pointer(&io)); err != nil {
		return fmt.Errorf("pf: creating table %s: %w", t, mapErrno(err, syscall.ESRCH))
	}
	return nil
}

// AddAddrs adds addrs to the table t. The result holds one Feedback for
// each address, in the order of addrs: FeedbackAdded, FeedbackNone,
// FeedbackConflict, or FeedbackDuplicate. The error wraps ErrNotFound when
// the table does not exist. With no addrs, AddAddrs does not call the
// kernel and returns no error, also for a missing table.
func (h *Handle) AddAddrs(t Table, addrs []Addr) ([]Feedback, error) {
	fb, err := h.changeAddrs(diocRAddAddrs, t, addrs)
	if err != nil {
		return nil, fmt.Errorf("pf: adding to table %s: %w", t, err)
	}
	return fb, nil
}

// DeleteAddrs deletes addrs from the table t. The result holds one
// Feedback for each address, in the order of addrs: FeedbackDeleted,
// FeedbackNone, FeedbackConflict, or FeedbackDuplicate. The error wraps
// ErrNotFound when the table does not exist. With no addrs, DeleteAddrs
// does not call the kernel and returns no error, also for a missing table.
func (h *Handle) DeleteAddrs(t Table, addrs []Addr) ([]Feedback, error) {
	fb, err := h.changeAddrs(diocRDelAddrs, t, addrs)
	if err != nil {
		return nil, fmt.Errorf("pf: deleting from table %s: %w", t, err)
	}
	return fb, nil
}

func (h *Handle) changeAddrs(req uint, t Table, addrs []Addr) ([]Feedback, error) {
	var io pfiocTable
	if err := t.encode(&io.Table); err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, nil
	}
	buf := make([]pfrAddr, len(addrs))
	for i, a := range addrs {
		if err := a.encode(&buf[i]); err != nil {
			return nil, err
		}
	}
	io.Buffer = (*byte)(unsafe.Pointer(&buf[0]))
	io.Esize = int32(unsafe.Sizeof(buf[0]))
	io.Size = int32(len(buf))
	io.Flags = pfrFlagFeedback
	if err := h.ioctl(req, unsafe.Pointer(&io)); err != nil {
		return nil, mapErrno(err, syscall.ESRCH)
	}
	fb := make([]Feedback, len(buf))
	for i := range buf {
		fb[i] = Feedback(buf[i].Fback)
	}
	return fb, nil
}

// ClearAddrs deletes every address of the table t and returns the number
// it deleted. The error wraps ErrNotFound when the table does not exist.
func (h *Handle) ClearAddrs(t Table) (int, error) {
	var io pfiocTable
	if err := t.encode(&io.Table); err != nil {
		return 0, fmt.Errorf("pf: clearing table %s: %w", t, err)
	}
	if err := h.ioctl(diocRClrAddrs, unsafe.Pointer(&io)); err != nil {
		return 0, fmt.Errorf("pf: clearing table %s: %w", t, mapErrno(err, syscall.ESRCH))
	}
	return int(io.Ndel), nil
}

// Addrs returns the addresses of the table t. The error wraps ErrNotFound
// when the table does not exist, so Addrs also tells whether a table
// exists.
func (h *Handle) Addrs(t Table) ([]Addr, error) {
	var io pfiocTable
	if err := t.encode(&io.Table); err != nil {
		return nil, fmt.Errorf("pf: reading table %s: %w", t, err)
	}
	var buf []pfrAddr
	// The kernel copies nothing and reports the count when the buffer is
	// too small. The table can grow between two calls, so try again.
	for {
		io.Size = int32(len(buf))
		io.Esize = int32(unsafe.Sizeof(pfrAddr{}))
		io.Buffer = nil
		if len(buf) > 0 {
			io.Buffer = (*byte)(unsafe.Pointer(&buf[0]))
		}
		if err := h.ioctl(diocRGetAddrs, unsafe.Pointer(&io)); err != nil {
			return nil, fmt.Errorf("pf: reading table %s: %w", t, mapErrno(err, syscall.ESRCH))
		}
		if int(io.Size) <= len(buf) {
			break
		}
		buf = make([]pfrAddr, io.Size)
	}
	addrs := make([]Addr, 0, io.Size)
	for _, a := range buf[:io.Size] {
		addr, err := decodeAddr(&a)
		if err != nil {
			return nil, fmt.Errorf("pf: reading table %s: %w", t, err)
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

func (t Table) encode(dst *pfrTable) error {
	if t.Name == "" {
		return errName
	}
	if err := setName(dst.Anchor[:], t.Anchor); err != nil {
		return err
	}
	return setName(dst.Name[:], t.Name)
}

func (a Addr) encode(dst *pfrAddr) error {
	if !a.Prefix.IsValid() {
		return fmt.Errorf("%s: %w", a.Prefix, errPrefix)
	}
	p := a.Prefix.Masked()
	dst.U = p.Addr().As16()
	if p.Addr().Is4() {
		v4 := p.Addr().As4()
		dst.U = [16]byte{}
		copy(dst.U[:], v4[:])
	}
	dst.Af = afOf(p.Addr())
	dst.Net = uint8(p.Bits())
	if a.Negated {
		dst.Not = 1
	}
	return nil
}

func decodeAddr(a *pfrAddr) (Addr, error) {
	var ip netip.Addr
	switch a.Af {
	case afInet:
		ip = netip.AddrFrom4([4]byte(a.U[:4]))
	case afInet6:
		ip = netip.AddrFrom16(a.U)
	default:
		return Addr{}, fmt.Errorf("address family %d: %w", a.Af, errPrefix)
	}
	p, err := ip.Prefix(int(a.Net))
	if err != nil {
		return Addr{}, fmt.Errorf("%s/%d: %w", ip, a.Net, errPrefix)
	}
	return Addr{Prefix: p, Negated: a.Not != 0}, nil
}

func afOf(a netip.Addr) uint8 {
	if a.Is4() {
		return afInet
	}
	return afInet6
}
