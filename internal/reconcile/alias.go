package reconcile

import (
	"errors"
	"fmt"

	"golang.org/x/net/publicsuffix"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// Errors that AliasEntry returns.
var (
	// ErrAliasNotDomain means that an alias does not obey the domain rules
	// of the configuration.
	ErrAliasNotDomain = errors.New("alias is not a valid domain")
	// ErrAliasPublicSuffix means that an alias is a public suffix, for
	// example "com", "co.uk", or "github.io". An entry for it would send
	// the queries for every name below it to ifbound-dns.
	ErrAliasPublicSuffix = errors.New("alias is a public suffix")
)

// firefoxCanary is the canary domain of Firefox. Firefox turns off its
// DNS-over-HTTPS when the system resolver answers this name with no
// address.
const firefoxCanary = "use-application-dns.net"

// AliasEntry decides whether a learned alias can get a resolver entry,
// and returns the domain of that entry. The alias must obey the domain
// rules of the configuration (policy.ParseDomain) and must not be a
// public suffix. The public suffix list includes its implicit "*" rule,
// so a name of one label, such as "local" or "test", is refused.
//
// The canonical text of a name with a byte that the domain rules refuse
// holds that byte or an escape, and ParseDomain refuses both. So the
// domain names the same node as the alias, and it is safe as one path
// component: it has no "/" and no empty label.
//
// The error wraps ErrAliasNotDomain or ErrAliasPublicSuffix.
func AliasEntry(n dnsname.Name) (policy.Domain, error) {
	d, err := policy.ParseDomain(n.String())
	if err != nil {
		return policy.Domain{}, fmt.Errorf("%w: %v", ErrAliasNotDomain, err)
	}
	if suffix, _ := publicsuffix.PublicSuffix(d.String()); suffix == d.String() {
		return policy.Domain{}, fmt.Errorf("%w: %s", ErrAliasPublicSuffix, d)
	}
	return d, nil
}

// canaryDomain returns firefoxCanary as a domain.
func canaryDomain() policy.Domain {
	d, err := policy.ParseDomain(firefoxCanary)
	if err != nil {
		panic("reconcile: invalid canary domain: " + err.Error())
	}
	return d
}
