package pf

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var errKind = errors.New("ruleset kind is not valid")

// RulesetKind selects one of the rulesets of an anchor.
type RulesetKind int

// The rulesets of an anchor. The zero value is RulesetFilter.
const (
	RulesetFilter RulesetKind = iota
	RulesetScrub
	RulesetNAT
	RulesetBINAT
	RulesetRDR
	RulesetDummynet
)

func (k RulesetKind) String() string {
	switch k {
	case RulesetFilter:
		return "filter"
	case RulesetScrub:
		return "scrub"
	case RulesetNAT:
		return "nat"
	case RulesetBINAT:
		return "binat"
	case RulesetRDR:
		return "rdr"
	case RulesetDummynet:
		return "dummynet"
	default:
		return fmt.Sprintf("RulesetKind(%d)", int(k))
	}
}

// action returns an action that the kernel maps to the ruleset of k.
func (k RulesetKind) action() (uint8, error) {
	switch k {
	case RulesetFilter:
		return pfPass, nil
	case RulesetScrub:
		return pfScrub, nil
	case RulesetNAT:
		return pfNat, nil
	case RulesetBINAT:
		return pfBinat, nil
	case RulesetRDR:
		return pfRdr, nil
	case RulesetDummynet:
		return pfDummynet, nil
	default:
		return 0, fmt.Errorf("%s: %w", k, errKind)
	}
}

// Ruleset names one ruleset of an anchor. Anchor "" is the main ruleset.
type Ruleset struct {
	Anchor string
	Kind   RulesetKind
}

func (rs Ruleset) String() string {
	return fmt.Sprintf("%s rules of %q", rs.Kind, rs.Anchor)
}

// Action is the action of a rule.
type Action uint8

// Actions, as the kernel defines them.
const (
	ActionPass         Action = pfPass
	ActionDrop         Action = pfDrop
	ActionScrub        Action = pfScrub
	ActionNoScrub      Action = pfNoScrub
	ActionNAT          Action = pfNat
	ActionNoNAT        Action = pfNoNat
	ActionBINAT        Action = pfBinat
	ActionNoBINAT      Action = pfNoBinat
	ActionRDR          Action = pfRdr
	ActionNoRDR        Action = pfNoRdr
	ActionSynproxyDrop Action = pfSynproxyDrop
	ActionDummynet     Action = pfDummynet
	ActionNoDummynet   Action = pfNoDummynet
	ActionNAT64        Action = pfNat64
	ActionNoNAT64      Action = pfNoNat64
)

func (a Action) String() string {
	switch a {
	case ActionPass:
		return "pass"
	case ActionDrop:
		return "drop"
	case ActionScrub:
		return "scrub"
	case ActionNoScrub:
		return "no scrub"
	case ActionNAT:
		return "nat"
	case ActionNoNAT:
		return "no nat"
	case ActionBINAT:
		return "binat"
	case ActionNoBINAT:
		return "no binat"
	case ActionRDR:
		return "rdr"
	case ActionNoRDR:
		return "no rdr"
	case ActionSynproxyDrop:
		return "synproxy drop"
	case ActionDummynet:
		return "dummynet"
	case ActionNoDummynet:
		return "no dummynet"
	case ActionNAT64:
		return "nat64"
	case ActionNoNAT64:
		return "no nat64"
	default:
		return fmt.Sprintf("Action(%d)", uint8(a))
	}
}

// Rule is the part of a rule that this package reads.
type Rule struct {
	Action Action
	Label  string
	// AnchorCall is the anchor that the rule evaluates, or "" when the
	// rule is not an anchor rule. An absolute path starts with "/"; a
	// relative path is relative to the anchor of the rule.
	AnchorCall string
}

// Rules returns the active rules of rs, in order. The error wraps
// ErrChanged when the ruleset changed during the read: read again. It
// wraps ErrNotFound when the anchor does not exist.
func (h *Handle) Rules(rs Ruleset) ([]Rule, error) {
	rules, err := h.rules(rs)
	if err != nil {
		return nil, fmt.Errorf("pf: reading %s: %w", rs, err)
	}
	return rules, nil
}

// rules reads the ticket and the count of the ruleset, then each rule
// with that ticket. The kernel returns EBUSY for a rule when the ticket is
// not the ticket of the active rules (pf_ioctl.c, DIOCGETRULE).
func (h *Handle) rules(rs Ruleset) ([]Rule, error) {
	var r pfiocRule
	if err := r.set(rs); err != nil {
		return nil, err
	}
	if err := h.ioctl(diocGetRules, unsafe.Pointer(&r)); err != nil {
		return nil, mapErrno(err, syscall.EINVAL)
	}
	ticket, n := r.u32(offIocRuleTicket), r.u32(offIocRuleNr)
	rules := make([]Rule, 0, n)
	for nr := range n {
		if err := r.set(rs); err != nil {
			return nil, err
		}
		r.setU32(offIocRuleTicket, ticket)
		r.setU32(offIocRuleNr, nr)
		if err := h.ioctl(diocGetRule, unsafe.Pointer(&r)); err != nil {
			return nil, mapErrno(err, syscall.EINVAL)
		}
		rules = append(rules, Rule{
			Action:     Action(r.b[offIocRuleRule+offRuleAction]),
			Label:      cString(r.b[offIocRuleRule+offRuleLabel:][:ruleLabelSize]),
			AnchorCall: cString(r.b[offIocRuleAnchorCall:offIocRuleRule]),
		})
	}
	return rules, nil
}

// Anchors returns the names of the child anchors of the anchor. Anchor ""
// is the main ruleset. The error wraps ErrNotFound when the anchor does
// not exist.
func (h *Handle) Anchors(anchor string) ([]string, error) {
	var rs pfiocRuleset
	if err := setName(rs.Path[:], anchor); err != nil {
		return nil, fmt.Errorf("pf: reading anchors of %q: %w", anchor, err)
	}
	if err := h.ioctl(diocGetRulesets, unsafe.Pointer(&rs)); err != nil {
		return nil, fmt.Errorf("pf: reading anchors of %q: %w", anchor, mapErrno(err, syscall.EINVAL))
	}
	n := rs.Nr
	names := make([]string, 0, n)
	for i := range n {
		rs.Nr = i
		if err := h.ioctl(diocGetRuleset, unsafe.Pointer(&rs)); err != nil {
			return nil, fmt.Errorf("pf: reading anchors of %q: %w", anchor, mapErrno(err, syscall.EINVAL))
		}
		names = append(names, cString(rs.Name[:]))
	}
	return names, nil
}

// pfiocRule is struct pfioc_rule. It holds a struct pf_rule, which has
// kernel pointers and anonymous structs that cgo -godefs cannot name, so
// the package reads it as bytes at the offsets in zdefs.go.
type pfiocRule struct {
	_ [0]uint64 // the alignment of the C struct
	b [sizeofPfiocRule]byte
}

// set clears r and selects the ruleset rs.
func (r *pfiocRule) set(rs Ruleset) error {
	act, err := rs.Kind.action()
	if err != nil {
		return err
	}
	clear(r.b[:])
	if err := setName(r.b[offIocRuleAnchor:offIocRuleAnchorCall], rs.Anchor); err != nil {
		return err
	}
	// The kernel selects the ruleset from the action of the rule.
	r.b[offIocRuleRule+offRuleAction] = act
	return nil
}

func (r *pfiocRule) u32(off int) uint32 {
	return *(*uint32)(unsafe.Pointer(&r.b[off]))
}

func (r *pfiocRule) setU32(off int, v uint32) {
	*(*uint32)(unsafe.Pointer(&r.b[off])) = v
}
