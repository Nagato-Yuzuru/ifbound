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
	"github.com/Nagato-Yuzuru/ifbound/internal/policy"
)

// checkInterval is how often the process reads the stored configuration.
const checkInterval = 5 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	err := newCommand().ExecuteContext(ctx)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ifbound-dns:", err)
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
			return run(cmd.Context(), l, upstreamCA(), t.C, slog.New(slog.NewTextHandler(os.Stderr, nil)))
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
func run(ctx context.Context, l layout.Layout, caFile string, ticks <-chan time.Time, logger *slog.Logger) (err error) {
	renderer, err := dnsconf.New(l.ReportSocket(), caFile)
	if err != nil {
		return err
	}
	if caFile != "" {
		logger.Warn("a test CA replaces the system roots for the upstream check", "file", caFile)
	}
	cfg, _, err := configstore.Load(l.StoredConfig())
	if err != nil {
		return err
	}
	corefile := renderer.Corefile(cfg.DNS)
	dnsserver.Quiet = true
	inst, err := caddy.Start(caddy.CaddyfileInput{
		Contents:       corefile,
		Filepath:       "Corefile",
		ServerTypeName: "dns",
	})
	if err != nil {
		return fmt.Errorf("start CoreDNS: %w", err)
	}
	defer func() {
		// The callbacks make the errors plugin write its pending count.
		err = errors.Join(append([]error{err}, inst.ShutdownCallbacks()...)...)
		_ = inst.Stop() //nolint:errcheck // Stop always returns nil
	}()
	watch(ctx, ticks, l.StoredConfig(), renderer.Corefile, corefile, logger)
	return nil
}

// watch returns when ctx ends or when, at a tick, the Corefile of the
// stored configuration differs from current. A stored file that it cannot
// load does not stop the process: the stored file is always valid, so a
// failed read is a transient fault. watch logs each change between
// readable and unreadable once.
func watch(ctx context.Context, ticks <-chan time.Time, path string, render func(policy.DNS) []byte, current []byte, logger *slog.Logger) {
	var unreadable bool
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
		}
		cfg, _, err := configstore.Load(path)
		if err != nil {
			if !unreadable {
				logger.Error("cannot read the stored configuration; keeping the running one", "err", err)
			}
			unreadable = true
			continue
		}
		if unreadable {
			logger.Info("the stored configuration is readable again")
			unreadable = false
		}
		if !bytes.Equal(render(cfg.DNS), current) {
			logger.Info("the [dns] section changed; exiting so that launchd starts a new process")
			return
		}
	}
}
