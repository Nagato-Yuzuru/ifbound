// Package dnsplugin is the ifbound CoreDNS plugin. It reports the addresses
// in every DNS reply to ifboundd and lets the reply go to the application
// only after ifboundd acknowledges. Every failure becomes SERVFAIL, so no
// address reaches an application before the kernel can block it.
//
// The plugin does not read policies. It reports every reply that carries an
// address, and ifboundd decides what matches.
package dnsplugin

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

const (
	// name is the Corefile directive and the plugin name.
	name = "ifbound"
	// directiveAnchor is the directive that ifbound goes before. "local" is
	// the first directive that can write an answer; dns64, rewrite, and cache
	// follow. withDirective checks that no directive above it can answer.
	directiveAnchor = "local"

	// defaultTimeout is the default wait for the ack. The socket is local,
	// so an ack takes milliseconds. The wait stays well below the usual
	// 5-second stub resolver timeout.
	defaultTimeout = 2 * time.Second
)

var (
	errNoAnchor     = errors.New("dnsplugin: directive " + directiveAnchor + " not found")
	errAnswerFirst  = errors.New("dnsplugin: a directive that may answer runs before " + directiveAnchor)
	errRelativePath = errors.New("socket path is not absolute")
	errBadTimeout   = errors.New("invalid timeout")
	errBlock        = errors.New("ifbound takes no block")
)

// Register adds the ifbound directive to CoreDNS. The ifbound-dns binary
// calls it once from main, before it starts CoreDNS. A second call panics in
// caddy.RegisterPlugin.
//
// Register places ifbound before every plugin that can write an answer, so
// cache hits and synthesized answers are reported too.
//
// The registration owns one ipc.Client for each socket path. All server
// blocks and all reloads that name the same path share that Client, so its
// in-flight limit holds for the whole process. The registration lives in the
// setup closure that caddy keeps, so the package has no global state.
//
// The plugin trusts only an ifboundd that runs as uid 0. The directive
// cannot change that, so a Corefile cannot make the plugin trust another
// peer.
func Register() error { return register(new(clients)) }

func register(cs *clients) error {
	dirs, err := withDirective(dnsserver.Directives)
	if err != nil {
		return err
	}
	dnsserver.Directives = dirs
	plugin.Register(name, cs.setup)
	return nil
}

// withDirective returns dirs with ifbound inserted before directiveAnchor.
// Every directive above that position must be one that cannot write an
// answer, so that a new CoreDNS release cannot put an answer source in
// front of ifbound without notice.
func withDirective(dirs []string) ([]string, error) {
	// These directives set up the server, change only the request context
	// or transport, or observe the reply. None of them writes an address.
	nonAnswering := []string{
		"root", "metadata", "geoip", "cancel", "proxyproto", "quic", "grpc_server",
		"https", "https3", "timeouts", "multisocket", "reload", "nsid", "bufsize",
		"bind", "debug", "trace", "ready", "health", "pprof", "shed", "prometheus",
		"errors", "log", "dnstap",
	}
	i := slices.Index(dirs, directiveAnchor)
	if i < 0 {
		return nil, errNoAnchor
	}
	for _, d := range dirs[:i] {
		if !slices.Contains(nonAnswering, d) {
			return nil, fmt.Errorf("%w: %s", errAnswerFirst, d)
		}
	}
	return slices.Insert(slices.Clone(dirs), i, name), nil
}

// clients holds the shared ipc.Client for each socket path. The zero value
// is ready to use and trusts a server that runs as uid 0.
type clients struct {
	serverUID uint32

	mu     sync.Mutex
	byPath map[string]*ipc.Client
}

func (cs *clients) get(path string) *ipc.Client {
	path = filepath.Clean(path)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if c, ok := cs.byPath[path]; ok {
		return c
	}
	if cs.byPath == nil {
		cs.byPath = make(map[string]*ipc.Client)
	}
	c := ipc.NewClient(path, cs.serverUID)
	cs.byPath[path] = c
	return c
}

func (cs *clients) setup(c *caddy.Controller) error {
	d, err := parse(c)
	if err != nil {
		return plugin.Error(name, err)
	}
	rep := cs.get(d.socket)
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return &handler{next: next, reporter: rep, timeout: d.timeout}
	})
	return nil
}

// directive is the parsed form of `ifbound <socket path> [timeout]`.
type directive struct {
	socket  string
	timeout time.Duration
}

func parse(c *caddy.Controller) (directive, error) {
	c.Next() // the directive name
	args := c.RemainingArgs()
	if c.NextBlock() {
		return directive{}, errBlock
	}
	if c.Next() {
		return directive{}, plugin.ErrOnce
	}
	if len(args) < 1 || len(args) > 2 {
		return directive{}, c.ArgErr()
	}
	d := directive{socket: args[0], timeout: defaultTimeout}
	if !filepath.IsAbs(d.socket) {
		return directive{}, fmt.Errorf("%w: %q", errRelativePath, d.socket)
	}
	if len(args) == 2 {
		t, err := time.ParseDuration(args[1])
		if err != nil {
			return directive{}, fmt.Errorf("%w: %v", errBadTimeout, err)
		}
		if t <= 0 || t > ipc.MaxTimeout {
			return directive{}, fmt.Errorf("%w: %s is not in (0, %s]", errBadTimeout, t, ipc.MaxTimeout)
		}
		d.timeout = t
	}
	return d, nil
}
