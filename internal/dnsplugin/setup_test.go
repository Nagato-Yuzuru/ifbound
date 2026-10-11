package dnsplugin

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    directive
		wantErr error // nil with wantMsg empty: success
		wantMsg string
	}{
		{name: "default timeout", input: "ifbound /run/ifbound.sock",
			want: directive{socket: "/run/ifbound.sock", timeout: 2 * time.Second}},
		{name: "timeout", input: "ifbound /run/ifbound.sock 500ms",
			want: directive{socket: "/run/ifbound.sock", timeout: 500 * time.Millisecond}},
		{name: "largest timeout", input: "ifbound /run/ifbound.sock 30s",
			want: directive{socket: "/run/ifbound.sock", timeout: 30 * time.Second}},
		{name: "no socket", input: "ifbound", wantMsg: "Wrong argument count"},
		{name: "extra argument", input: "ifbound /run/ifbound.sock 1s more", wantMsg: "Wrong argument count"},
		{name: "relative socket", input: "ifbound run/ifbound.sock", wantErr: errRelativePath},
		{name: "zero timeout", input: "ifbound /run/ifbound.sock 0s", wantErr: errBadTimeout},
		{name: "negative timeout", input: "ifbound /run/ifbound.sock -1s", wantErr: errBadTimeout},
		{name: "timeout above the server limit", input: "ifbound /run/ifbound.sock 30001ms", wantErr: errBadTimeout},
		{name: "timeout not a duration", input: "ifbound /run/ifbound.sock 2", wantErr: errBadTimeout},
		{name: "block", input: "ifbound /run/ifbound.sock {\ntimeout 1s\n}", wantErr: errBlock},
		{name: "twice in a block", input: "ifbound /run/a.sock\nifbound /run/b.sock", wantErr: plugin.ErrOnce},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parse(caddy.NewTestController("dns", tt.input))
			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("err = %v, want %v", err, tt.wantErr)
				}
			case tt.wantMsg != "":
				if err == nil || !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("err = %v, want one with %q", err, tt.wantMsg)
				}
			case err != nil:
				t.Errorf("err = %v", err)
			case got != tt.want:
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSetupSharesOneClientPerSocket(t *testing.T) {
	var cs clients
	handlerOf := func(input string) *handler {
		t.Helper()
		c := caddy.NewTestController("dns", input)
		if err := cs.setup(c); err != nil {
			t.Fatal(err)
		}
		chain := dnsserver.GetConfig(c).Plugin
		if len(chain) != 1 {
			t.Fatalf("plugins = %d, want 1", len(chain))
		}
		h, ok := chain[0](nil).(*handler)
		if !ok {
			t.Fatalf("plugin is %T, want *handler", chain[0](nil))
		}
		return h
	}
	a := handlerOf("ifbound /run/a.sock 1s")
	b := handlerOf("ifbound /run/a.sock")
	b2 := handlerOf("ifbound /run/./x/../a.sock")
	c := handlerOf("ifbound /run/c.sock")
	if a.reporter != b.reporter || a.reporter != b2.reporter {
		t.Error("server blocks that name the same socket got different clients")
	}
	if a.reporter == c.reporter {
		t.Error("different sockets share a client")
	}
	if a.timeout != time.Second || b.timeout != defaultTimeout {
		t.Errorf("timeouts = %s, %s; want 1s, %s", a.timeout, b.timeout, defaultTimeout)
	}
}

func TestSetupErrorNamesThePlugin(t *testing.T) {
	err := new(clients).setup(caddy.NewTestController("dns", "ifbound relative.sock"))
	if !errors.Is(err, errRelativePath) || !strings.HasPrefix(err.Error(), "plugin/ifbound: ") {
		t.Errorf("err = %v, want plugin/ifbound: ... %v", err, errRelativePath)
	}
}

// pristineDirectives returns the CoreDNS directive list without ifbound.
// Another test in this binary may have registered the plugin already.
func pristineDirectives() []string {
	return slices.DeleteFunc(slices.Clone(dnsserver.Directives), func(d string) bool { return d == name })
}

func TestWithDirectivePutsOnlyNonAnsweringDirectivesFirst(t *testing.T) {
	// The oracle: CoreDNS v1.14.7 directives that set up the server, change
	// only the request context or transport, or observe the reply.
	nonAnswering := []string{
		"root", "metadata", "geoip", "cancel", "proxyproto", "quic", "grpc_server",
		"https", "https3", "timeouts", "multisocket", "reload", "nsid", "bufsize",
		"bind", "debug", "trace", "ready", "health", "pprof", "shed", "prometheus",
		"errors", "log", "dnstap",
	}
	in := pristineDirectives()
	before := slices.Clone(in)
	dirs, err := withDirective(in)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(in, before) {
		t.Error("withDirective changed its input")
	}
	at := slices.Index(dirs, name)
	for _, d := range dirs[:at] {
		if !slices.Contains(nonAnswering, d) {
			t.Errorf("%s runs before ifbound and is not known to be non-answering", d)
		}
	}
	if i := slices.Index(dirs, "cache"); i <= at {
		t.Errorf("cache at %d, ifbound at %d; want ifbound first", i, at)
	}
}

func TestWithDirectiveRefusesAnAnswerSourceFirst(t *testing.T) {
	for _, d := range []string{"whoami", "chaos", "any", "template", "hosts", "unknown"} {
		t.Run(d, func(t *testing.T) {
			dirs := pristineDirectives()
			dirs = slices.DeleteFunc(dirs, func(s string) bool { return s == d })
			dirs = slices.Insert(dirs, slices.Index(dirs, directiveAnchor), d)
			if _, err := withDirective(dirs); !errors.Is(err, errAnswerFirst) {
				t.Errorf("err = %v, want %v", err, errAnswerFirst)
			}
		})
	}
	if _, err := withDirective([]string{"cache", "forward"}); !errors.Is(err, errNoAnchor) {
		t.Errorf("without %s: err = %v, want %v", directiveAnchor, err, errNoAnchor)
	}
}
