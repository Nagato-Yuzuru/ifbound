package dnsplugin

import (
	"bytes"
	"errors"
	"math"
	"slices"

	"github.com/miekg/dns"
)

// maxChainLinks is the most CNAME records that the plugin follows from
// the qname. Resolvers stop at a similar depth: BIND stops after 16
// restarts, and Unbound after 11. The limit also bounds the queries that
// complete a chain (see handler.complete).
const maxChainLinks = 16

var (
	errCNAMELoop    = errors.New("CNAME loop")
	errChainTooLong = errors.New("CNAME chain is longer than the limit")
	errCNAMEFork    = errors.New("name has CNAME records with different targets")
)

// chain is the CNAME chain from a start name in an answer section.
type chain struct {
	// end is the target of the last link, as the reply spells it. It is
	// the start name when there is no link.
	end   string
	links int
	// ttl is the smallest TTL of the links, and math.MaxUint32 without a
	// link.
	ttl uint32
}

// walk follows the CNAME records from start. Names match without regard
// to ASCII case. A name may have the same CNAME record more than once, as
// after a merge of replies (see merge). Two different targets for one
// name, a loop, or more than maxChainLinks links is an error: a client can
// follow such a chain in a way that the plugin does not see. A query for
// the CNAME type follows no link.
func walk(start string, qtype uint16, answer []dns.RR) (chain, error) {
	c := chain{end: start, ttl: math.MaxUint32}
	if qtype == dns.TypeCNAME {
		return c, nil
	}
	byOwner := map[string][]*dns.CNAME{}
	for _, rr := range answer {
		if cn, ok := rr.(*dns.CNAME); ok {
			owner := dns.CanonicalName(cn.Hdr.Name)
			byOwner[owner] = append(byOwner[owner], cn)
		}
	}
	seen := map[string]bool{dns.CanonicalName(start): true}
	for {
		links := byOwner[dns.CanonicalName(c.end)]
		if len(links) == 0 {
			return c, nil
		}
		next := links[0].Target
		for _, l := range links {
			if !sameName(l.Target, next) {
				return chain{}, errCNAMEFork
			}
			c.ttl = min(c.ttl, l.Hdr.Ttl)
		}
		c.links++
		key := dns.CanonicalName(next)
		switch {
		case c.links > maxChainLinks:
			return chain{}, errChainTooLong
		case seen[key]:
			return chain{}, errCNAMELoop
		}
		seen[key] = true
		c.end = next
	}
}

// finalRecords returns the records of answer that answer qtype at end.
// CNAME and DNAME records are links, and DNSSEC records do not survive a
// change of owner, so none of them is a final record.
func finalRecords(end string, qtype uint16, answer []dns.RR) []dns.RR {
	var out []dns.RR
	for _, rr := range answer {
		t := rr.Header().Rrtype
		switch t {
		case dns.TypeCNAME, dns.TypeDNAME, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeOPT:
			continue
		}
		if (qtype == dns.TypeANY || t == qtype) && sameName(rr.Header().Name, end) {
			out = append(out, rr)
		}
	}
	return out
}

// pendingName returns the end of the chain from start when m does not
// answer it: the chain has a link, no final record, and neither NXDOMAIN
// nor a SOA marks the end as negative. Then the upstream resolver did not
// follow the chain to its end, and the plugin must ask for the rest (see
// handler.complete). A truncated reply is not pending: the client asks
// again over TCP.
func pendingName(start string, qtype uint16, m *dns.Msg) (string, bool, error) {
	c, err := walk(start, qtype, m.Answer)
	switch {
	case err != nil:
		return "", false, err
	case c.links == 0, m.Truncated, m.Rcode != dns.RcodeSuccess, hasSOA(m.Ns),
		len(finalRecords(c.end, qtype, m.Answer)) > 0:
		return "", false, nil
	}
	return c.end, true, nil
}

// merge returns m with the reply sub to the query for the pending end of
// its chain. The answers add up. The rcode and the authority section are
// those of sub, because they describe the end of the chain. The
// additional section stays that of m: it has the OPT record of the reply
// to the client.
func merge(m, sub *dns.Msg) *dns.Msg {
	out := m.Copy()
	out.Answer = append(out.Answer, sub.Copy().Answer...)
	out.Ns = sub.Copy().Ns
	out.Rcode = sub.Rcode
	return out
}

// flatten returns the reply that a client of a protected name gets
// instead of m. owner is the name in the question of the client. start is
// the name that m answers: owner, or the target of a synthetic name.
// Rules:
//
//   - The CNAME chain from start goes away, with every DNAME record. The
//     final records at its end (see finalRecords) get owner as their
//     owner. When the chain has a link, each final record gets the
//     smallest TTL of the links and the final records, so no record
//     lives longer than the chain that it came from.
//   - An HTTPS record keeps all its parameters. A TargetName of "." stays:
//     it now means owner. A TargetName that is the old owner becomes ".",
//     which means the same. Any other TargetName except owner becomes the
//     synthetic name below owner (see tagKey.synthName). The TargetName of
//     HTTPS is not the identity of the service (RFC 9460 section 2.5), so
//     the change keeps the meaning. A record whose synthetic name would
//     be too long goes away, and the rest of the answer stays: an HTTPS
//     record is optional, and the client falls back to A and AAAA.
//   - An SVCB record whose TargetName is not "." or owner goes away. For
//     SVCB, the TargetName can be the TLS identity of the service (RFC
//     9461 for DNS servers), so a synthetic name would break it. Thus a
//     client cannot find an encrypted resolver for a protected name, which
//     is intended.
//   - Every other answer record goes away: it names a name that the
//     client did not ask for.
//   - Without an answer record, the authority section keeps only its SOA
//     records, with the TTL and the negative TTL capped to the chain TTL.
//     With an answer record, the authority section is empty.
//   - The additional section keeps only the OPT record.
//   - Each record that has a synthetic name, as owner or as TargetName,
//     has a TTL of at most maxSynthTTL.
//   - When the reply changes, the AD bit is cleared: the plugin removes
//     the signatures and changes owners, so nothing in the new reply was
//     validated.
//
// The rcode stays. So a chain that ends in NXDOMAIN gives NXDOMAIN for
// owner. Thus no alias of owner remains. Known gap: the final records of a
// type whose data names another host, such as SRV, MX, NS, and NAPTR,
// keep those names. Many protocols check TLS against such a name, so the
// plugin cannot rename it, and the client looks it up as a name of its
// own. flatten is the single place of these rules; the caller adds the
// question and the ID of the client.
func flatten(k *tagKey, owner, start string, qtype uint16, m *dns.Msg) (*dns.Msg, error) {
	c, err := walk(start, qtype, m.Answer)
	if err != nil {
		return nil, err
	}
	finals := finalRecords(c.end, qtype, m.Answer)
	ttl := c.ttl // the cap of each record; math.MaxUint32 is no cap
	if c.links > 0 {
		for _, f := range finals {
			ttl = min(ttl, f.Header().Ttl)
		}
	}
	synthetic := !sameName(start, owner)
	if synthetic {
		ttl = min(ttl, maxSynthTTL)
	}
	rename := !sameName(c.end, owner)

	out := &dns.Msg{MsgHdr: m.MsgHdr, Compress: m.Compress, Question: slices.Clone(m.Question)}
	for _, f := range finals {
		r := dns.Copy(f)
		h := r.Header()
		if rename {
			h.Name = owner
		}
		h.Ttl = min(h.Ttl, ttl) // with a link, ttl is the TTL of every final record
		if k.retarget(r, f.Header().Name, owner) {
			out.Answer = append(out.Answer, r)
		}
	}
	if len(out.Answer) == 0 {
		out.Ns = soaRecords(m.Ns, ttl)
	}
	for _, rr := range m.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			out.Extra = append(out.Extra, dns.Copy(rr))
		}
	}
	if !sameOnWire(m, out) {
		out.AuthenticatedData = false
	}
	return out, nil
}

// retarget changes the TargetName of an HTTPS or SVCB record r that moved
// from oldOwner to owner (see flatten). It is false when r must go away.
// Other records stay as they are.
func (k *tagKey) retarget(r dns.RR, oldOwner, owner string) bool {
	var s *dns.SVCB
	switch v := r.(type) {
	case *dns.SVCB:
		s = v
	case *dns.HTTPS:
		s = &v.SVCB
	default:
		return true
	}
	switch {
	case s.Target == "":
		// miekg/dns unpacks a record with empty rdata as a value with
		// no target. The client cannot read such a record.
		return false
	case s.Target == ".", sameName(s.Target, owner):
		return true
	case s.Hdr.Rrtype == dns.TypeSVCB:
		return false
	case sameName(s.Target, oldOwner):
		s.Target = "."
		return true
	}
	name, ok := k.synthName(s.Target, owner)
	if !ok {
		return false
	}
	s.Target = name
	s.Hdr.Ttl = min(s.Hdr.Ttl, maxSynthTTL)
	return true
}

// soaRecords returns copies of the SOA records in ns. The TTL and the
// MINIMUM field, which sets the negative TTL (RFC 2308 section 5), are at
// most ttl.
func soaRecords(ns []dns.RR, ttl uint32) []dns.RR {
	var out []dns.RR
	for _, rr := range ns {
		if soa, ok := rr.(*dns.SOA); ok {
			c := *soa // all fields are values, so this is a full copy
			c.Hdr.Ttl = min(c.Hdr.Ttl, ttl)
			c.Minttl = min(c.Minttl, ttl)
			out = append(out, &c)
		}
	}
	return out
}

func hasSOA(ns []dns.RR) bool {
	return slices.ContainsFunc(ns, func(rr dns.RR) bool { return rr.Header().Rrtype == dns.TypeSOA })
}

// sameName compares two names without regard to ASCII case. The names
// come from unpacked messages, so one octet has one spelling.
func sameName(a, b string) bool { return dns.CanonicalName(a) == dns.CanonicalName(b) }

// followsName reports whether a client follows a name in m to another
// lookup: a CNAME or DNAME target, or an HTTPS or SVCB TargetName that is
// not "." or its own owner. Such a reply needs the protected flag even
// without an address, because flattening removes the name.
func followsName(m *dns.Msg) bool {
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			switch v := rr.(type) {
			case *dns.CNAME, *dns.DNAME:
				return true
			case *dns.HTTPS:
				if v.Target != "." && !sameName(v.Target, v.Hdr.Name) {
					return true
				}
			case *dns.SVCB:
				if v.Target != "." && !sameName(v.Target, v.Hdr.Name) {
					return true
				}
			}
		}
	}
	return false
}

// sameOnWire reports whether a and b pack to the same bytes, which means
// that a client decodes the same message.
func sameOnWire(a, b *dns.Msg) bool {
	pa, errA := a.Pack()
	pb, errB := b.Pack()
	return errA == nil && errB == nil && bytes.Equal(pa, pb)
}
