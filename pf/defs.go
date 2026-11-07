//go:build ignore

// Input of cgo -godefs. The go:generate directive in pf.go turns it into
// zdefs.go. The headers come from the XNU source in xnu/; NOTICE names the
// release.

package pf

/*
#include <stddef.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/pfvar.h>

// struct pf_rule holds kernel pointers and anonymous structs, which
// -godefs cannot name. The package reads it as bytes at these offsets.
enum {
	sizeofPfRule = sizeof(struct pf_rule),
	offRuleLabel = offsetof(struct pf_rule, label),
	offRuleAction = offsetof(struct pf_rule, action),
	sizeofPfiocRule = sizeof(struct pfioc_rule),
	offIocRuleAction = offsetof(struct pfioc_rule, action),
	offIocRuleTicket = offsetof(struct pfioc_rule, ticket),
	offIocRuleNr = offsetof(struct pfioc_rule, nr),
	offIocRuleAnchor = offsetof(struct pfioc_rule, anchor),
	offIocRuleAnchorCall = offsetof(struct pfioc_rule, anchor_call),
	offIocRuleRule = offsetof(struct pfioc_rule, rule),
};
*/
import "C"

type pfrTable C.struct_pfr_table
type pfrAddr C.struct_pfr_addr
type pfiocTable C.struct_pfioc_table
type pfiocRuleset C.struct_pfioc_ruleset
type pfAddrWrap C.struct_pf_addr_wrap
type pfiocStateAddrKill C.struct_pfioc_state_addr_kill
type pfiocStateKill C.struct_pfioc_state_kill
type pfStatus C.struct_pf_status

const (
	sizeofPfRule         = C.sizeofPfRule
	offRuleLabel         = C.offRuleLabel
	offRuleAction        = C.offRuleAction
	sizeofPfiocRule      = C.sizeofPfiocRule
	offIocRuleAction     = C.offIocRuleAction
	offIocRuleTicket     = C.offIocRuleTicket
	offIocRuleNr         = C.offIocRuleNr
	offIocRuleAnchor     = C.offIocRuleAnchor
	offIocRuleAnchorCall = C.offIocRuleAnchorCall
	offIocRuleRule       = C.offIocRuleRule
	ruleLabelSize        = C.PF_RULE_LABEL_SIZE
)

const (
	diocGetStatus   = C.DIOCGETSTATUS
	diocGetRules    = C.DIOCGETRULES
	diocGetRule     = C.DIOCGETRULE
	diocKillStates  = C.DIOCKILLSTATES
	diocGetRulesets = C.DIOCGETRULESETS
	diocGetRuleset  = C.DIOCGETRULESET
	diocRAddTables  = C.DIOCRADDTABLES
	diocRClrAddrs   = C.DIOCRCLRADDRS
	diocRAddAddrs   = C.DIOCRADDADDRS
	diocRDelAddrs   = C.DIOCRDELADDRS
	diocRGetAddrs   = C.DIOCRGETADDRS
)

const (
	afInet  = C.AF_INET
	afInet6 = C.AF_INET6

	pfrFlagFeedback = C.PFR_FLAG_FEEDBACK
	pfrTflagPersist = C.PFR_TFLAG_PERSIST

	pfrFbNone      = C.PFR_FB_NONE
	pfrFbAdded     = C.PFR_FB_ADDED
	pfrFbDeleted   = C.PFR_FB_DELETED
	pfrFbDuplicate = C.PFR_FB_DUPLICATE
	pfrFbConflict  = C.PFR_FB_CONFLICT

	pfPass         = C.PF_PASS
	pfDrop         = C.PF_DROP
	pfScrub        = C.PF_SCRUB
	pfNoScrub      = C.PF_NOSCRUB
	pfNat          = C.PF_NAT
	pfNoNat        = C.PF_NONAT
	pfBinat        = C.PF_BINAT
	pfNoBinat      = C.PF_NOBINAT
	pfRdr          = C.PF_RDR
	pfNoRdr        = C.PF_NORDR
	pfSynproxyDrop = C.PF_SYNPROXY_DROP
	pfDummynet     = C.PF_DUMMYNET
	pfNoDummynet   = C.PF_NODUMMYNET
	pfNat64        = C.PF_NAT64
	pfNoNat64      = C.PF_NONAT64
)
