// Command ifbound-dns is the DNS process of ifbound: CoreDNS with the
// ifbound plugin. It runs as the unprivileged _ifbound user.
//
// It reads the stored configuration once at start and renders a Corefile
// from its [dns] section. It checks the stored file at an interval. When
// the Corefile would differ, it exits with status 0, and launchd starts it
// again with the new configuration. If it cannot load the stored
// configuration at start, it exits with an error and protected names fail
// closed.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	_ "github.com/coredns/coredns/plugin/bind"
	_ "github.com/coredns/coredns/plugin/cache"
	_ "github.com/coredns/coredns/plugin/errors"
	_ "github.com/coredns/coredns/plugin/forward"
	"github.com/spf13/cobra"

	"github.com/Nagato-Yuzuru/ifbound/internal/configstore"
	"github.com/Nagato-Yuzuru/ifbound/internal/dnsconf"
	"github.com/Nagato-Yuzuru/ifbound/internal/dnsplugin"
	"github.com/Nagato-Yuzuru/ifbound/internal/layout"
	"github.com/Nagato-Yuzuru/ifbound/internal/logattr"
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// checkInterval is how often the process reads the stored configuration.
const checkInterval = 5 * time.Second

// serviceName is the service.name of the start event.
const serviceName = "ifbound-dns"

// errExitLogged marks an error that the exit event holds already, so
// main does not write it again.
var errExitLogged = errors.New("exit event logged")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	err := newCommand().ExecuteContext(ctx)
	stop()
	if err != nil {
		if !errors.Is(err, errExitLogged) {
			fmt.Fprintln(os.Stderr, "ifbound-dns:", err)
		}
		os.Exit(1)
	}
}

func newCommand() *cobra.Command {
	l := layout.Default()
	cmd := &cobra.Command{
		Use:           "ifbound-dns",
		Short:         "DNS process of ifbound",
		Args:          cobra.NoArgs,
		Version:       buildVersion(),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := dnsplugin.Register(); err != nil {
				return err
			}
			t := time.NewTicker(checkInterval)
			defer t.Stop()
			// One JSON object for each event on stderr. launchd collects
			// stderr. The CoreDNS plugins write through the log package,
			// and SetDefault sends its lines to the same handler.
			logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
			slog.SetDefault(logger)
			if err := run(cmd.Context(), l, upstreamCA(), t.C, logger); err != nil {
				return fmt.Errorf("%w: %w", errExitLogged, err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&l.StateDir, "state-dir", l.StateDir, "directory of the stored configuration")
	cmd.Flags().StringVar(&l.RunDir, "run-dir", l.RunDir, "directory of the sockets")
	return cmd
}

func buildVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "devel"
}

// run starts CoreDNS from the stored configuration. It returns nil when
// ctx ends or when the stored [dns] section changes at a tick, and an error
// when the start fails. The caller registers the plugin: CoreDNS accepts a
// plugin name once per process.
//
// It writes the start event before any step can fail, with the digest
// of the stored configuration when it loads, so that a process that fails
// at start still names its build. It writes the exit event when it returns, also
// after a failure.
func run(ctx context.Context, l layout.Layout, caFile string, ticks <-chan time.Time, logger *slog.Logger) (err error) {
	reason, errType := logattr.ExitStopped, ""
	defer func() { logExit(ctx, logger, reason, errType, err) }()

	// Both steps run before the start event, so that it can name the
	// digest. Their errors are handled after it, in this order.
	renderer, rerr := dnsconf.New(l.ReportSocket(), caFile)
	cfg, digest, lerr := configstore.Load(l.StoredConfig())
	start := []slog.Attr{
		slog.String(logattr.ServiceName, serviceName),
		slog.String(logattr.ServiceVersion, buildVersion()),
	}
	if lerr == nil {
		start = append(start, slog.String(logattr.ConfigDigest, digest.String()))
	}
	logger.LogAttrs(ctx, slog.LevelInfo, "start", start...)
	if rerr != nil {
		errType = logattr.ErrorTypePath
		return rerr
	}
	if caFile != "" {
		logger.LogAttrs(ctx, slog.LevelWarn, "a test CA replaces the system roots for the upstream check", slog.String(logattr.FilePath, caFile))
	}
	if lerr != nil {
		errType = logattr.ErrorTypeConfigFile
		return lerr
	}
	corefile := renderer.Corefile(cfg.DNS)
	dnsserver.Quiet = true
	inst, err := caddy.Start(caddy.CaddyfileInput{
		Contents:       corefile,
		Filepath:       "Corefile",
		ServerTypeName: "dns",
	})
	if err != nil {
		errType = logattr.ErrorTypeCoreDNS
		return fmt.Errorf("start CoreDNS: %w", err)
	}
	defer func() {
		// The callbacks make the errors plugin write its pending count.
		err = errors.Join(append([]error{err}, inst.ShutdownCallbacks()...)...)
		if err != nil {
			errType = logattr.ErrorTypeCoreDNS
		}
		_ = inst.Stop() //nolint:errcheck // Stop always returns nil
	}()
	if watch(ctx, ticks, l.StoredConfig(), renderer.Corefile, corefile, logger) {
		reason = logattr.ExitConfigChanged
	}
	return nil
}

// logExit writes the exit event. A non-nil err makes the reason
// logattr.ExitFailed, and errType is its error.type.
func logExit(ctx context.Context, logger *slog.Logger, reason, errType string, err error) {
	if err == nil {
		logger.LogAttrs(ctx, slog.LevelInfo, "exit", slog.String(logattr.ExitReason, reason))
		return
	}
	logger.LogAttrs(ctx, slog.LevelError, "exit", slog.String(logattr.ExitReason, logattr.ExitFailed),
		slog.String(logattr.ErrorType, errType), slog.String(logattr.ExceptionMessage, err.Error()))
}

// watch returns when ctx ends or when, at a tick, the Corefile of the
// stored configuration differs from current. It reports whether the
// Corefile changed. A stored file that it cannot load does not stop the
// process: the stored file is always valid, so a failed read is a
// transient fault. watch logs each change between readable and
// unreadable once.
func watch(ctx context.Context, ticks <-chan time.Time, path string, render func(policy.DNS) []byte, current []byte, logger *slog.Logger) bool {
	var unreadable bool
	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticks:
		}
		cfg, _, err := configstore.Load(path)
		if err != nil {
			if !unreadable {
				logger.LogAttrs(ctx, slog.LevelError, "cannot read the stored configuration; keeping the running one",
					slog.String(logattr.FilePath, path),
					slog.String(logattr.ErrorType, logattr.ErrorTypeConfigFile), slog.String(logattr.ExceptionMessage, err.Error()))
			}
			unreadable = true
			continue
		}
		if unreadable {
			logger.LogAttrs(ctx, slog.LevelInfo, "the stored configuration is readable again", slog.String(logattr.FilePath, path))
			unreadable = false
		}
		if !bytes.Equal(render(cfg.DNS), current) {
			return true
		}
	}
}
