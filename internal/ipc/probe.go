package ipc

import (
	"strings"

	"github.com/Nagato-Yuzuru/ifbound/internal/dnsname"
)

// ProbePrefix starts the first label of a probe name. To prove that the
// queries for a domain go to ifbound-dns, ifboundd resolves
// "<ProbePrefix><nonce>.<domain>" through the system resolver. When the
// query reaches ifbound-dns, the plugin answers it itself and sends the
// name with Client.ReportProbe. The nonce is lower-case and new for each
// probe, so no cache can answer it.
const ProbePrefix = "ifbound-probe-"

// IsProbe reports whether qname is a probe name: a name of two or more
// labels whose first label starts with ProbePrefix. It ignores ASCII
// case. A malformed name is not a probe name.
func IsProbe(qname string) bool {
	labels, err := dnsname.Split(qname)
	if err != nil || len(labels) < 2 {
		return false
	}
	return strings.HasPrefix(labels[0], ProbePrefix) // Split folds ASCII case
}
