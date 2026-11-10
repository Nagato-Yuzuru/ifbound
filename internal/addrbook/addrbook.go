// Package addrbook reads the address book snapshot that earlier versions
// of ifboundd wrote as a JSON file. The address book is now in
// addrstore, which merges the snapshot with Read at each open where the
// file exists.
package addrbook

import (
	"time"

	"github.com/Nagato-Yuzuru/ifbound/internal/blockable"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// Entry is one resolved address of one policy, as the snapshot stores
// it.
type Entry struct {
	Policy   policy.Name
	Addr     blockable.Addr
	LastSeen time.Time
	// TTL is the TTL of the last answer.
	TTL time.Duration
	// Expiry is the last instant at which the entry is still kept.
	Expiry time.Time
}
