package dnsplugin

import "github.com/miekg/dns"

const (
	// ddrZone holds the DDR probe _dns.resolver.arpa. (RFC 9462). An
	// upstream answer for the probe names the encrypted DNS service of the
	// upstream. A client that upgrades to that service sends its queries
	// around ifbound-dns.
	ddrZone = "resolver.arpa."
	// canaryName is the Firefox canary domain. NXDOMAIN for it tells
	// Firefox not to switch on its own DNS over HTTPS. This applies only
	// when the query reaches ifbound-dns, which needs a resolver entry for
	// the name. The plugin does not decide that routing.
	canaryName = "use-application-dns.net."
)

// localRcode returns the rcode that ifbound-dns answers qname with itself,
// and false when the query goes to the next plugin.
//
// Every name at or below ddrZone gets NODATA for every type. ifbound-dns
// has no Designated Resolver. RFC 9462 section 4 says that such a resolver
// SHOULD return NODATA for queries to the resolver.arpa zone, and section
// 6.1 says that a forwarder SHOULD NOT forward queries for resolver.arpa or
// its subdomains upstream.
//
// qname must be in the form that miekg/dns unpacks from the wire, which
// writes printable bytes as they are (see observation). Thus a name such as
// \095dns.resolver.arpa. does not occur. The match is on whole labels
// without ASCII case, so a label with an escaped dot does not match. A name
// without the final dot matches as the same name with it.
func localRcode(qname string) (int, bool) {
	qname = dns.Fqdn(qname)
	switch {
	case dns.IsSubDomain(ddrZone, qname):
		return dns.RcodeSuccess, true
	case dns.IsSubDomain(canaryName, qname):
		return dns.RcodeNameError, true
	}
	return 0, false
}

// localReply is the reply to r with rcode and no records. It has no SOA:
// ifbound-dns is not authoritative for these zones and has no true SOA to
// give. Without a SOA, the client does not cache the negative answer (RFC
// 2308 section 5). The next query comes here again, and that costs one
// local reply.
//
// RA is set: for the client, ifbound-dns is a recursive resolver.
func localReply(r *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg).SetRcode(r, rcode)
	m.RecursionAvailable = true
	return m
}
