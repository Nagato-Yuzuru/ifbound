package dnsplugin

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

var (
	errBadAddr        = errors.New("malformed address")
	errTooManyAliases = errors.New("too many alias names")
)

// observation collects every address in every section of m under qname. A
// record off the CNAME chain of qname counts too: reporting too much blocks
// too much, which is safe, but an unreported address would leak.
//
// The TTL is the smallest TTL of the records that carry the addresses and
// of the CNAME records that the walk from qname follows, or zero when m has
// no address. An address record that the plugin cannot read is an error.
//
// It also collects the alias names in m: every name that the client can
// reach from qname through CNAME records, and every SVCB or HTTPS
// TargetName that is not the owner of its record (see aliasSet). The
// qname and the root are never aliases. The client can send a follow-up
// query for an alias by that name, and that query does not come to this
// plugin. So a reply with an alias and no address is reported too, and
// found is false only when m has no address and no alias. A reply with
// more aliases than ipc.MaxAliases is an error: a report without some of
// them would leave those names unprotected.
//
// m must be a message unpacked from wire form. Then every A, AAAA, SVCB, and
// HTTPS record has its own Go type, and no address or alias hides in a
// generic or mistyped value.
func observation(qname string, m *dns.Msg) (o ipc.Observation, found bool, err error) {
	ttl := uint32(math.MaxUint32)
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			addrs, err := rrAddrs(rr)
			if err != nil {
				return ipc.Observation{}, false, fmt.Errorf("%s record of %s: %w",
					dns.TypeToString[rr.Header().Rrtype], rr.Header().Name, err)
			}
			if len(addrs) > 0 {
				o.Addrs = append(o.Addrs, addrs...)
				ttl = min(ttl, rr.Header().Ttl)
			}
		}
	}
	aliases := newAliasSet(qname)
	followed := aliases.walkCNAMEs(qname, m.Answer)
	aliases.addTargets(m)
	o.Aliases = aliases.list
	if len(o.Addrs) == 0 && len(o.Aliases) == 0 {
		return ipc.Observation{}, false, nil
	}
	if len(o.Aliases) > ipc.MaxAliases {
		return ipc.Observation{}, false, fmt.Errorf("%w: %d, limit %d",
			errTooManyAliases, len(o.Aliases), ipc.MaxAliases)
	}
	o.QName = qname
	if len(o.Addrs) > 0 {
		slices.SortFunc(o.Addrs, netip.Addr.Compare)
		o.Addrs = slices.Compact(o.Addrs)
		for _, c := range followed {
			ttl = min(ttl, c.Hdr.Ttl)
		}
		o.TTL = time.Duration(ttl) * time.Second
	}
	return o, true, nil
}

// aliasSet collects the alias names of one reply. The names keep the
// presentation form that the client decodes. Names that differ only in
// ASCII case are one alias: the first form stays, with the largest TTL of
// the records that point to the name. The client can cache the alias for
// as long as the longest of those records.
type aliasSet struct {
	list []ipc.Alias
	// at maps a canonical name to its index in list. The value -1 marks a
	// name that is never an alias: the qname and the root.
	at map[string]int
}

func newAliasSet(qname string) *aliasSet {
	return &aliasSet{at: map[string]int{dns.CanonicalName(qname): -1, ".": -1}}
}

// add records name with the TTL of the record that points to it.
func (s *aliasSet) add(name string, ttl uint32) {
	d := time.Duration(ttl) * time.Second
	key := dns.CanonicalName(name)
	if i, ok := s.at[key]; ok {
		if i >= 0 {
			s.list[i].TTL = max(s.list[i].TTL, d)
		}
		return
	}
	s.at[key] = len(s.list)
	s.list = append(s.list, ipc.Alias{Name: name, TTL: d})
}

// walkCNAMEs adds every name that the client can reach from qname through
// the CNAME records in answer. A name can have more than one CNAME record,
// and the client can follow each of them, so the walk is breadth-first
// over all of them. Names match without regard to ASCII case. The walk
// also goes on from a name that is not an alias, such as the root. Each
// name is walked once, so a loop ends. walkCNAMEs returns every CNAME
// record that it followed.
func (s *aliasSet) walkCNAMEs(qname string, answer []dns.RR) []*dns.CNAME {
	byOwner := map[string][]*dns.CNAME{}
	for _, rr := range answer {
		if c, ok := rr.(*dns.CNAME); ok {
			owner := dns.CanonicalName(c.Hdr.Name)
			byOwner[owner] = append(byOwner[owner], c)
		}
	}
	var followed []*dns.CNAME
	start := dns.CanonicalName(qname)
	seen := map[string]bool{start: true}
	for queue := []string{start}; len(queue) > 0; queue = queue[1:] {
		for _, c := range byOwner[queue[0]] {
			followed = append(followed, c)
			s.add(c.Target, c.Hdr.Ttl)
			if target := dns.CanonicalName(c.Target); !seen[target] {
				seen[target] = true
				queue = append(queue, target)
			}
		}
	}
	return followed
}

// addTargets adds each SVCB or HTTPS TargetName in any section of m that
// is not the owner of its record.
func (s *aliasSet) addTargets(m *dns.Msg) {
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			target := svcbTarget(rr)
			if target == "" || dns.CanonicalName(target) == dns.CanonicalName(rr.Header().Name) {
				continue
			}
			s.add(target, rr.Header().Ttl)
		}
	}
}

// svcbTarget returns the TargetName of an SVCB or HTTPS record, or "" for
// another type.
func svcbTarget(rr dns.RR) string {
	switch rr := rr.(type) {
	case *dns.SVCB:
		return rr.Target
	case *dns.HTTPS:
		return rr.Target
	}
	return ""
}

// rrAddrs returns the addresses that rr gives to a client.
func rrAddrs(rr dns.RR) ([]netip.Addr, error) {
	switch rr := rr.(type) {
	case *dns.A:
		return ipAddrs(rr.A)
	case *dns.AAAA:
		return ipAddrs(rr.AAAA)
	case *dns.SVCB:
		return hintAddrs(rr.Value)
	case *dns.HTTPS:
		return hintAddrs(rr.Value)
	}
	return nil, nil
}

func hintAddrs(kvs []dns.SVCBKeyValue) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, kv := range kvs {
		var hint []net.IP
		switch kv := kv.(type) {
		case *dns.SVCBIPv4Hint:
			hint = kv.Hint
		case *dns.SVCBIPv6Hint:
			hint = kv.Hint
		}
		addrs, err := ipAddrs(hint...)
		if err != nil {
			return nil, err
		}
		out = append(out, addrs...)
	}
	return out, nil
}

func ipAddrs(ips ...net.IP) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, fmt.Errorf("%w: %d bytes", errBadAddr, len(ip))
		}
		out = append(out, a.Unmap())
	}
	return out, nil
}
