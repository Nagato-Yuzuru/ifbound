package core

import (
	"strings"

	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// configText is a configuration with one policy, and the scope that
// users and groups give. With neither, the policy has no scope.
func configText(users, groups []string) string {
	text := `
[dns]
listen = "127.0.0.1:53553"
upstream = ["tls://1.1.1.1@cloudflare-dns.com"]
[addrbook]
retain = "1h"
[[policy]]
name = "web"
to = ["example.com", "*.example.net", "192.0.2.10"]
deny_via = ["en1"]
`
	if len(users) == 0 && len(groups) == 0 {
		return text
	}
	return text + "scope = { users = [" + quoted(users) + "], groups = [" + quoted(groups) + "] }\n"
}

func quoted(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = `"` + n + `"`
	}
	return strings.Join(q, ", ")
}

// scoped returns the configuration of configText. It panics on a parse
// error: the text is fixed by the test.
func scoped(users, groups []string) policy.Config {
	cfg, err := policy.ParseBytes([]byte(configText(users, groups)))
	if err != nil {
		panic(err)
	}
	return cfg
}
