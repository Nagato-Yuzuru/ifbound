package dnsplugin

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	_ "github.com/coredns/coredns/plugin/bind"
	_ "github.com/coredns/coredns/plugin/hosts"
	_ "github.com/coredns/coredns/plugin/rewrite"
	"github.com/miekg/dns"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

// registerOnce registers the plugin for the whole test binary: caddy
// accepts a plugin name only once per process.
var registerOnce = sync.OnceValue(func() error {
	return register(&clients{serverUID: selfUID()})
})

// rewriteCorefile makes a client name app.corp.example reach hosts as
// app.cdn.example. rewrite changes the request question in place.
const rewriteCorefile = `.:0 {
    bind 127.0.0.1
    ifbound SOCK
    rewrite name suffix .corp.example. .cdn.example. answer auto
    hosts {
        192.0.2.7 app.cdn.example
    }
}
`

// startCoreDNS runs a real CoreDNS server with corefile and returns its
// address. SOCK in corefile becomes the socket of srv.
func startCoreDNS(t *testing.T, corefile, sock string) string {
	t.Helper()
	if err := registerOnce(); err != nil {
		t.Fatal(err)
	}
	dnsserver.Quiet = true
	inst, err := caddy.Start(caddy.CaddyfileInput{
		Contents:       []byte(strings.ReplaceAll(corefile, "SOCK", sock)),
		Filepath:       "Corefile",
		ServerTypeName: "dns",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := inst.Stop(); err != nil {
			t.Error(err)
		}
	})
	return inst.Servers()[0].LocalAddr().String()
}

func ask(t *testing.T, addr, qname string) *dns.Msg {
	t.Helper()
	r, err := dns.Exchange(new(dns.Msg).SetQuestion(qname, dns.TypeA), addr)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRewrittenQueryIsReportedUnderTheClientQName(t *testing.T) {
	seen := make(chan ipc.Observation, 1)
	sock := socketPath(t)
	startServerAt(t, sock, observeFunc(func(_ context.Context, o ipc.Observation) error {
		seen <- o
		return nil
	}))
	addr := startCoreDNS(t, rewriteCorefile, sock)

	r := ask(t, addr, "app.corp.example.")
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("client got %v", r)
	}
	select {
	case o := <-seen:
		if o.QName != "app.corp.example." {
			t.Errorf("report qname = %q, want the client qname app.corp.example.", o.QName)
		}
		requireReported(t, r, o.Addrs)
	default:
		t.Fatal("client got a reply without a report")
	}
}

func TestServfailAfterRewriteCarriesTheClientQuestion(t *testing.T) {
	sock := socketPath(t) // no server: every report fails
	addr := startCoreDNS(t, rewriteCorefile, sock)

	r := ask(t, addr, "app.corp.example.")
	if r.Rcode != dns.RcodeServerFailure || len(r.Answer) != 0 {
		t.Errorf("client got %v, want SERVFAIL without answers", r)
	}
	if len(r.Question) != 1 || r.Question[0].Name != "app.corp.example." {
		t.Errorf("question = %v, want app.corp.example.", r.Question)
	}
}
