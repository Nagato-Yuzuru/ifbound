package pf

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// Version identifies the active rules of a ruleset. Compare two Versions
// with ==: when the rules change, the Version changes. A load of the same
// rules also gives a new Version.
type Version struct {
	// Ticket is the ticket of the active rules. A load, an insert
	// (DIOCINSERTRULE), and each change with DIOCCHANGERULE give a new
	// ticket. The two counters of the kernel can give an old ticket
	// again after a mix of loads and changes (pf_ioctl.c), so Count is
	// part of the Version.
	Ticket uint32
	// Count is the number of rules.
	Count uint32
}

// Version returns the Version of the active rules of rs. It reads no
// rule: it costs one ioctl. The error wraps ErrNotFound when the anchor
// does not exist.
func (h *Handle) Version(rs Ruleset) (Version, error) {
	var r pfiocRule
	if err := r.set(rs); err != nil {
		return Version{}, fmt.Errorf("pf: reading the version of %s: %w", rs, err)
	}
	if err := h.ioctl(diocGetRules, unsafe.Pointer(&r)); err != nil {
		return Version{}, fmt.Errorf("pf: reading the version of %s: %w", rs, mapErrno(err, syscall.EINVAL))
	}
	return Version{Ticket: r.u32(offIocRuleTicket), Count: r.u32(offIocRuleNr)}, nil
}

// InsertAnchorCall adds the rule `anchor "<call>" all label "<label>"`
// before the first filter rule of the anchor. Anchor "" is the main
// ruleset. A relative call is relative to the anchor. It does not load
// the ruleset: the other rules stay as they are. The error wraps
// ErrNotFound when the anchor does not exist, and ErrChanged when
// another process changed the rules or the address pool at the same time.
func (h *Handle) InsertAnchorCall(anchor, call, label string) error {
	if err := h.insertAnchorCall(anchor, call, label); err != nil {
		return fmt.Errorf("pf: adding a call of %q to %s: %w", call, Ruleset{Anchor: anchor}, err)
	}
	return nil
}

func (h *Handle) insertAnchorCall(anchor, call, label string) error {
	// DIOCCHANGERULE adds a rule only with the ticket of the address
	// pool buffer, also when the rule has no address pool.
	var pa pfiocPooladdr
	if err := h.ioctl(diocBeginAddrs, unsafe.Pointer(&pa)); err != nil {
		return mapErrno(err, 0)
	}
	rs := Ruleset{Anchor: anchor}
	ticket, err := h.changeTicket(rs)
	if err != nil {
		return err
	}
	var r pfiocRule
	if err := r.set(rs); err != nil {
		return err
	}
	if err := setName(r.b[offIocRuleAnchorCall:offIocRuleRule], call); err != nil {
		return err
	}
	if err := setName(r.b[offIocRuleRule+offRuleLabel:][:ruleLabelSize], label); err != nil {
		return err
	}
	r.setU32(offIocRuleAction, pfChangeAddHead)
	r.setU32(offIocRuleTicket, ticket)
	r.setU32(offIocRulePoolTicket, pa.u32(offPooladdrTicket))
	if err := h.ioctl(diocChangeRule, unsafe.Pointer(&r)); err != nil {
		return changeErr(err)
	}
	return nil
}

// RemoveLabeled removes each filter rule of the anchor whose label is
// label, and returns the number of rules that it removed. The error wraps
// ErrNotFound when the anchor does not exist, and ErrChanged when another
// process changed the rules at the same time.
func (h *Handle) RemoveLabeled(anchor, label string) (int, error) {
	rs := Ruleset{Anchor: anchor}
	n := 0
	for {
		removed, err := h.removeFirstLabeled(rs, label)
		if err != nil {
			return n, fmt.Errorf("pf: removing the rules with label %q from %s: %w", label, rs, err)
		}
		if !removed {
			return n, nil
		}
		n++
	}
}

// removeFirstLabeled removes the first filter rule of rs with the label.
// It takes the change ticket before it reads the rules: a change between
// the read and the removal then makes the removal fail, so the rule
// number is never stale.
func (h *Handle) removeFirstLabeled(rs Ruleset, label string) (bool, error) {
	ticket, err := h.changeTicket(rs)
	if err != nil {
		return false, err
	}
	readTicket, rules, err := h.rulesWithTicket(rs)
	if err != nil {
		return false, err
	}
	if readTicket != ticket {
		return false, ErrChanged
	}
	for nr, rule := range rules {
		if rule.Label != label {
			continue
		}
		var r pfiocRule
		if err := r.set(rs); err != nil {
			return false, err
		}
		r.setU32(offIocRuleAction, pfChangeRemove)
		r.setU32(offIocRuleTicket, ticket)
		r.setU32(offIocRuleNr, uint32(nr))
		if err := h.ioctl(diocChangeRule, unsafe.Pointer(&r)); err != nil {
			return false, changeErr(err)
		}
		return true, nil
	}
	return false, nil
}

// changeTicket returns a ticket for DIOCCHANGERULE. The kernel makes a new
// active ticket for each request, so the request changes the Version of
// rs.
func (h *Handle) changeTicket(rs Ruleset) (uint32, error) {
	var r pfiocRule
	if err := r.set(rs); err != nil {
		return 0, err
	}
	r.setU32(offIocRuleAction, pfChangeGetTicket)
	if err := h.ioctl(diocChangeRule, unsafe.Pointer(&r)); err != nil {
		// pf_find_ruleset gives EINVAL for a missing anchor.
		return 0, mapErrno(err, syscall.EINVAL)
	}
	return r.u32(offIocRuleTicket), nil
}

// changeErr maps the error of a DIOCCHANGERULE change. The kernel answers
// EINVAL for a stale rule ticket and EBUSY for a stale pool ticket: both
// mean that another process changed pf at the same time.
func changeErr(err error) error {
	if errors.Is(err, syscall.EINVAL) {
		return ErrChanged
	}
	return mapErrno(err, 0)
}

// pfiocPooladdr is struct pfioc_pooladdr. It holds a struct pf_pooladdr
// with kernel pointers, so the package reads it as bytes.
type pfiocPooladdr struct {
	_ [0]uint32 // the alignment of the C struct
	b [sizeofPfiocPooladdr]byte
}

func (p *pfiocPooladdr) u32(off int) uint32 {
	return *(*uint32)(unsafe.Pointer(&p.b[off]))
}
