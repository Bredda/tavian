// Command tavian is the Tavian gateway.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bredda/tavian/internal/auth"
	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/egress"
	"github.com/bredda/tavian/internal/meter"
	"github.com/bredda/tavian/internal/provider/openai"
	"github.com/bredda/tavian/internal/server"
	"github.com/bredda/tavian/internal/version"
)

const usage = `Usage: tavian <command> [flags]

Commands:
  serve      Run the gateway
  validate   Check a configuration file and exit
  keygen     Generate an API key and the hash to put in the configuration
  version    Print the version

Run "tavian <command> -h" for command flags.
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:], stdout, stderr)
	case "validate":
		return cmdValidate(args[1:], stdout, stderr)
	case "keygen":
		return cmdKeygen(stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, "tavian", version.String())
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "tavian: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func configFlag(fs *flag.FlagSet) *string {
	def := os.Getenv("TAVIAN_CONFIG")
	if def == "" {
		def = "tavian.yaml"
	}
	return fs.String("config", def, "path to the configuration file (env TAVIAN_CONFIG)")
}

func cmdKeygen(stdout, stderr io.Writer) int {
	key, hash, err := auth.GenerateKey()
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return 1
	}
	fmt.Fprintf(stdout, "key:  %s\nhash: %s\n", key, hash)
	fmt.Fprintln(stderr, "\nStore the key now, it cannot be recovered. Put only the hash in the configuration (api_keys[].hash).")
	return 0
}

func cmdValidate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, raw, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return 1
	}
	snap, err := config.Compile(cfg, raw, os.Getenv)
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return 1
	}
	fmt.Fprintf(stdout, "ok: revision=%s profile=%s backends=%d models=%d api_keys=%d\n",
		snap.Revision, snap.Profile, len(snap.Backends), len(snap.Models), len(snap.Keys))
	return 0
}

func cmdServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, raw, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return 1
	}
	snap, err := config.Compile(cfg, raw, os.Getenv)
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return 1
	}
	log := newLogger(stdout, cfg.Log)

	holder := &config.Holder{}
	holder.Store(snap)

	guard, err := egress.New(cfg.Profile, holder, cfg.Egress.InternalCIDRs)
	if err != nil {
		log.Error("egress guard", "error", err)
		return 1
	}
	metrics := server.NewMetrics()
	deps := server.Deps{
		Snap:     holder,
		Auth:     auth.APIKeyAuthenticator{Snap: holder},
		Provider: openai.New(guard.HTTPClient(cfg.Limits.UpstreamHeaderTimeout), "tavian/"+version.String()),
		Sink:     meter.LogSink{Log: log},
		Log:      log,
		Metrics:  metrics,
	}

	data := &http.Server{
		Addr:              cfg.Listen.Data,
		Handler:           server.NewDataHandler(deps),
		ReadHeaderTimeout: cfg.Limits.ReadHeaderTimeout,
		IdleTimeout:       120 * time.Second,
		// No WriteTimeout: streamed completions can legitimately last minutes.
	}
	admin := &http.Server{
		Addr:              cfg.Listen.Admin,
		Handler:           server.NewAdminHandler(holder, metrics),
		ReadHeaderTimeout: cfg.Limits.ReadHeaderTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// SIGHUP reloads the configuration. A reload that fails validation leaves
	// the last known good snapshot in place (ADR-0003).
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			reload(log, *path, cfg.Profile, holder)
		}
	}()

	errc := make(chan error, 2)
	for name, srv := range map[string]*http.Server{"data": data, "admin": admin} {
		go func() {
			log.Info("listening", "listener", name, "addr", srv.Addr)
			if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s listener: %w", name, err)
			}
		}()
	}
	log.Info("tavian started",
		"version", version.String(), "profile", snap.Profile, "revision", snap.Revision,
		"backends", len(snap.Backends), "models", len(snap.Models))

	code := 0
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		log.Error("server failed", "error", err)
		code = 1
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Limits.ShutdownGrace)
	defer cancel()
	for _, srv := range []*http.Server{data, admin} {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error("shutdown", "error", err)
			code = 1
		}
	}
	return code
}

func reload(log *slog.Logger, path string, running config.Profile, holder *config.Holder) {
	cfg, raw, err := config.Load(path)
	if err == nil && cfg.Profile != running {
		err = fmt.Errorf("profile changed from %q to %q: restart required", running, cfg.Profile)
	}
	var snap *config.Snapshot
	if err == nil {
		snap, err = config.Compile(cfg, raw, os.Getenv)
	}
	if err != nil {
		log.Error("configuration reload rejected, keeping current revision",
			"current", holder.Load().Revision, "error", err)
		return
	}
	holder.Store(snap)
	log.Info("configuration reloaded", "revision", snap.Revision,
		"backends", len(snap.Backends), "models", len(snap.Models))
}

func newLogger(w io.Writer, c config.LogConfig) *slog.Logger {
	var level slog.Level
	if err := level.UnmarshalText([]byte(c.Level)); err != nil {
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if c.Format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}
