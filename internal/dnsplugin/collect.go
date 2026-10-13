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

var errBadAddr = errors.New("malformed address")

// observation collects every address in every section of m under qname. A
// record off the CNAME chain of qname counts too: reporting too much blocks
// too much, which is safe, but an unreported address would leak.
//
// The TTL is the smallest TTL of the records that carry the addresses and
// of the CNAME records that the walk from qname follows (see
// followedCNAMEs). found is false when m has no address. An address record
// that the plugin cannot read is an error.
//
// m must be a message unpacked from wire form. Then every A, AAAA, SVCB, and
// HTTPS record has its own Go type, and no address hides in a generic or
// mistyped value.
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
	if len(o.Addrs) == 0 {
		return ipc.Observation{}, false, nil
	}
	slices.SortFunc(o.Addrs, netip.Addr.Compare)
	o.Addrs = slices.Compact(o.Addrs)
	o.QName = qname
	for _, c := range followedCNAMEs(qname, m.Answer) {
		ttl = min(ttl, c.Hdr.Ttl)
	}
	o.TTL = time.Duration(ttl) * time.Second
	return o, true, nil
}

// followedCNAMEs returns every CNAME record in answer that the client can
// follow from qname. A name can have more than one CNAME record, and the
// client can follow each of them, so the walk is breadth-first over all
// of them. Names match without regard to ASCII case. Each name is walked
// once, so a loop ends.
func followedCNAMEs(qname string, answer []dns.RR) []*dns.CNAME {
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
			if target := dns.CanonicalName(c.Target); !seen[target] {
				seen[target] = true
				queue = append(queue, target)
			}
		}
	}
	return followed
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
