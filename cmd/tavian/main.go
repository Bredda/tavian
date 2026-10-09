// Command tavian is the Tavian gateway.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/bredda/tavian/internal/auth"
	"github.com/bredda/tavian/internal/chain"
	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/egress"
	"github.com/bredda/tavian/internal/meter"
	"github.com/bredda/tavian/internal/outbox"
	"github.com/bredda/tavian/internal/provider/openai"
	"github.com/bredda/tavian/internal/quota"
	"github.com/bredda/tavian/internal/rollup"
	"github.com/bredda/tavian/internal/server"
	"github.com/bredda/tavian/internal/spool"
	"github.com/bredda/tavian/internal/store"
	"github.com/bredda/tavian/internal/version"
)

const usage = `Usage: tavian <command> [flags]

Commands:
  serve      Run the gateway
  validate   Check a configuration file and exit
  migrate    Apply pending database migrations and exit
  policy     Test policies against fixtures: tavian policy test
  keygen     Generate an API key and the hash to put in the configuration
  audit-keygen  Generate the key that signs the seals of the audit chain
  verify-audit  Check the audit chain, its seals and the records it covers
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
	case "migrate":
		return cmdMigrate(args[1:], stdout, stderr)
	case "policy":
		return cmdPolicy(args[1:], stdout, stderr)
	case "keygen":
		return cmdKeygen(stdout, stderr)
	case "audit-keygen":
		return cmdAuditKeygen(args[1:], stdout, stderr)
	case "verify-audit":
		return cmdVerifyAudit(args[1:], stdout, stderr)
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
	for _, w := range append(snap.Policy.Warnings(), snap.Warnings...) {
		fmt.Fprintln(stderr, "warning:", w)
	}
	fmt.Fprintf(stdout, "ok: revision=%s profile=%s backends=%d models=%d api_keys=%d policies=%d\n",
		snap.Revision, snap.Profile, len(snap.Backends), len(snap.Models), len(snap.Keys), len(snap.Policy.Names()))
	return 0
}

func cmdMigrate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, raw, err := config.Load(*path)
	if err == nil && cfg.Database.URLEnv == "" {
		err = errors.New("database.url_env is not set in the configuration")
	}
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	snap, err := config.Compile(cfg, raw, os.Getenv)
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return 1
	}
	holder := &config.Holder{}
	holder.Store(snap)
	st, err := openStore(ctx, cfg, holder)
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return 1
	}
	defer st.Close()
	applied, err := st.Migrate(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return 1
	}
	if len(applied) == 0 {
		fmt.Fprintln(stdout, "database schema is up to date")
	} else {
		fmt.Fprintf(stdout, "applied migrations: %v\n", applied)
	}
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
	metrics.WatchAPIKeys(holder, time.Now)
	logKeyExpiries(log, snap, time.Now())
	logInspection(log, snap)
	logPolicies(log, snap)
	var authn auth.Authenticator = auth.APIKeyAuthenticator{Snap: holder}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var (
		sink    meter.Sink = meter.LogSink{Log: log}
		audit   meter.Admitter
		st      *store.Store
		flushed = make(chan struct{})

		stopFlush = func() {}
		// the outbox consumers run until the servers are drained
		stopWorkers = func() {}
		workersDone = make(chan struct{})
	)
	if cfg.Database.URLEnv == "" {
		log.Warn("no database configured: usage events are only logged, not stored (development mode)")
		close(flushed)
		close(workersDone)
	} else {
		var outbox *meter.OutboxSink
		st, outbox, err = openStorage(ctx, cfg.Database, guard, snap, raw, log)
		if err != nil {
			log.Error("storage", "error", err)
			return 1
		}
		defer st.Close()
		sink, audit = outbox, outbox
		metrics.WatchStorage(outbox.Up, outbox.Spool.Size, outbox.Rejected)
		// The replay loop outlives the signal context: in-flight requests
		// still emit events while the servers drain.
		var flushCtx context.Context
		flushCtx, stopFlush = context.WithCancel(context.Background())
		defer stopFlush()
		go func() {
			defer close(flushed)
			outbox.Run(flushCtx)
		}()

		var workersCtx context.Context
		workersCtx, stopWorkers = context.WithCancel(context.Background())
		defer stopWorkers()
		if err := startWorkers(workersCtx, cfg, st, metrics, log, workersDone); err != nil {
			log.Error("outbox workers", "error", err)
			return 1
		}
	}

	if cfg.OIDC.Issuer != "" {
		verifier := auth.NewJWTVerifier(cfg.OIDC, guard.HTTPClient(15*time.Second), log)
		go verifier.Run(ctx)
		authn = auth.Chain{
			APIKey: authn,
			OIDC:   auth.OIDCAuthenticator{Snap: holder, Verifier: verifier},
		}
		metrics.WatchOIDC(func() float64 { return verifier.KeysAge().Seconds() })
		log.Info("OIDC enabled", "issuer", cfg.OIDC.Issuer, "audience", cfg.OIDC.Audience, "mappings", len(cfg.OIDC.Mappings))
	}

	// quota counters live for the life of the process; after a restart the
	// day's token counts are rebuilt from what the database recorded
	qstore := quota.NewStore(nil)
	if st != nil {
		if err := seedQuotas(ctx, log, st, qstore, snap); err != nil {
			log.Error("quotas", "error", err)
			return 1
		}
	}

	deps := server.Deps{
		Quota:    qstore,
		Snap:     holder,
		Auth:     authn,
		Provider: openai.New(guard.HTTPClient(cfg.Limits.UpstreamHeaderTimeout), "tavian/"+version.String()),
		Sink:     sink,
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
		Handler:           server.NewAdminHandler(holder, metrics, audit),
		ReadHeaderTimeout: cfg.Limits.ReadHeaderTimeout,
	}

	// SIGHUP reloads the configuration. A reload that fails validation leaves
	// the last known good snapshot in place (ADR-0003).
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			reload(ctx, log, *path, cfg, holder, st, qstore)
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
	// Requests are done: stop the replay loop and let it empty the spool once.
	stopFlush()
	<-flushed
	stopWorkers()
	<-workersDone
	return code
}

// seedQuotas gives the daily token counters and monthly budget counters of the
// scopes that have a limit the usage recorded so far. Counters that already count are left alone.
func seedQuotas(ctx context.Context, log *slog.Logger, st *store.Store, qs *quota.Store, snap *config.Snapshot) error {
	n, err := rollup.Seed(ctx, st.Pool(), qs, rollup.Scopes{
		Daily: snap.Policy.Scopes(quota.TokensPerDay), Monthly: snap.Policy.Scopes(quota.BudgetEUR),
	}, time.Now())
	if err != nil {
		return fmt.Errorf("rebuilding today's token counts and this month's spending (the limits would start from zero): %w", err)
	}
	if n > 0 {
		log.Info("daily token and monthly budget counters rebuilt from recorded usage", "counters", n)
	}
	return nil
}

// startWorkers runs the consumers of the outbox (the audit chain, the hourly
// usage sums) and the pruner that applies retention. done is closed when they
// have stopped.
func startWorkers(ctx context.Context, cfg *config.Config, st *store.Store, metrics *server.Metrics, log *slog.Logger, done chan struct{}) error {
	sealer := &chain.Sealer{SealEveryEvents: cfg.Audit.SealEveryEvents, SealEvery: cfg.Audit.SealEvery}
	if k := cfg.Audit.SigningKeyFile; k != "" {
		signer, err := chain.LoadSigner(k)
		if err != nil {
			return err
		}
		sealer.Signer = signer
		log.Info("audit chain will be sealed", "key_id", signer.KeyID(), "every_events", cfg.Audit.SealEveryEvents, "every", cfg.Audit.SealEvery)
	} else {
		log.Warn("audit.signing_key_file is not set: decision records are chained but the chain is not sealed, so whoever can write to the database could rewrite it undetected (see `tavian audit-keygen`)")
	}
	runner := &outbox.Runner{
		Pool: st.Pool(), Log: log, PollEvery: cfg.Workers.PollInterval, BatchSize: cfg.Workers.BatchSize,
		OnCycle: metrics.ObserveConsumer,
	}
	runner.Add(sealer)
	runner.Add(rollup.Consumer{Log: log})
	if err := runner.Register(ctx); err != nil {
		return err
	}
	metrics.WatchAudit(sealer.Stats, time.Now)

	keep := cfg.Outbox.Retention.Keep()
	pruner := &outbox.Pruner{
		Pool: st.Pool(), Log: log, Keep: keep, Every: cfg.Outbox.PruneEvery,
		OnPruned: metrics.ObservePruned, OnError: metrics.ObservePruneError,
	}
	log.Info("outbox retention", "usage_days", *cfg.Outbox.Retention.UsageDays, "decision_days", *cfg.Outbox.Retention.DecisionDays, "every", cfg.Outbox.PruneEvery)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runner.Run(ctx)
	}()
	if len(keep) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pruner.Run(ctx)
		}()
	}
	go func() {
		wg.Wait()
		close(done)
	}()
	return nil
}

// openStore connects to PostgreSQL through an egress guard of its own; used by
// commands that do not run the gateway.
func openStore(ctx context.Context, cfg *config.Config, holder *config.Holder) (*store.Store, error) {
	guard, err := egress.New(cfg.Profile, holder, cfg.Egress.InternalCIDRs)
	if err != nil {
		return nil, err
	}
	return connectStore(ctx, cfg.Database, guard)
}

// connectStore declares the database endpoints to the guard (always internal)
// and connects through it.
func connectStore(ctx context.Context, db config.DatabaseConfig, guard *egress.Guard) (*store.Store, error) {
	url := os.Getenv(db.URLEnv)
	endpoints, err := store.Endpoints(url)
	if err != nil {
		return nil, err
	}
	guard.Pin(endpoints...)
	return store.Open(ctx, url, guard.DialContext)
}

// openStorage connects, insists on an up-to-date schema, records the running
// configuration revision and prepares the usage-event sink.
func openStorage(ctx context.Context, db config.DatabaseConfig, guard *egress.Guard, snap *config.Snapshot, raw []byte, log *slog.Logger) (*store.Store, *meter.OutboxSink, error) {
	st, err := connectStore(ctx, db, guard)
	if err != nil {
		return nil, nil, err
	}
	if err := st.CheckSchema(ctx); err != nil {
		st.Close()
		return nil, nil, err
	}
	sp, err := spool.Open(db.SpoolDir, db.SpoolMaxBytes)
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	if err := saveRevision(ctx, st, snap, raw); err != nil {
		st.Close()
		return nil, nil, err
	}
	if n := sp.Size(); n > 0 {
		log.Info("usage events from a previous run are waiting in the spool", "bytes", n)
	}
	return st, &meter.OutboxSink{Store: st, Spool: sp, Log: log, Timeout: db.EmitTimeout}, nil
}

func saveRevision(ctx context.Context, st *store.Store, snap *config.Snapshot, raw []byte) error {
	var policies []byte
	if len(snap.PolicySources) > 0 {
		var err error
		if policies, err = json.Marshal(snap.PolicySources); err != nil {
			return fmt.Errorf("encode policies: %w", err)
		}
	}
	return st.SaveRevision(ctx, store.Revision{
		ID: snap.Revision, Profile: string(snap.Profile), YAML: raw, Version: version.String(), Policies: policies,
	})
}

// reload recompiles the configuration file. The new revision is recorded in
// the database before it goes live, so every usage event can be traced back to
// a stored configuration; if that fails, or anything fails validation, the
// current revision stays.
func reload(ctx context.Context, log *slog.Logger, path string, running *config.Config, holder *config.Holder, st *store.Store, qs *quota.Store) {
	cfg, raw, err := config.Load(path)
	if err == nil && cfg.Profile != running.Profile {
		err = fmt.Errorf("profile changed from %q to %q: restart required", running.Profile, cfg.Profile)
	}
	if err == nil && cfg.Database != running.Database {
		err = errors.New("database settings changed: restart required")
	}
	if err == nil && (cfg.Audit != running.Audit || cfg.Workers != running.Workers || !reflect.DeepEqual(cfg.Outbox, running.Outbox)) {
		err = errors.New("audit, workers or outbox settings changed: restart required")
	}
	if err == nil && !sameOIDCConnection(cfg.OIDC, running.OIDC) {
		err = errors.New("oidc settings other than mappings changed: restart required")
	}
	var snap *config.Snapshot
	if err == nil {
		snap, err = config.Compile(cfg, raw, os.Getenv)
	}
	if err == nil && st != nil {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = saveRevision(rctx, st, snap, raw)
		if err == nil && qs != nil {
			// a policy added now may limit a scope that has been using tokens all day
			err = seedQuotas(rctx, log, st, qs, snap)
		}
		cancel()
	}
	if err != nil {
		log.Error("configuration reload rejected, keeping current revision",
			"current", holder.Load().Revision, "error", err)
		return
	}
	holder.Store(snap)
	logKeyExpiries(log, snap, time.Now())
	logInspection(log, snap)
	logPolicies(log, snap)
	log.Info("configuration reloaded", "revision", snap.Revision,
		"backends", len(snap.Backends), "models", len(snap.Models))
}

// logInspection says how content inspection is set up, and warns about the
// settings that weaken it.
func logInspection(log *slog.Logger, snap *config.Snapshot) {
	in := snap.Inspector
	if !in.Enabled() {
		log.Warn("content inspection is disabled: requests are served without being inspected")
		return
	}
	if in.EphemeralKey() {
		log.Warn("inspection.fingerprint_key_env is not set: finding fingerprints use a random key and only correlate within this process run")
	}
	log.Info("content inspection enabled", "detectors", len(in.Detectors()))
}

// logPolicies names the policies in force and repeats any warning about them.
func logPolicies(log *slog.Logger, snap *config.Snapshot) {
	for _, w := range snap.Policy.Warnings() {
		log.Warn("policy warning", "warning", w)
	}
	for _, w := range snap.Warnings {
		log.Warn("configuration warning", "warning", w)
	}
	log.Info("policies loaded", "policies", snap.Policy.Names())
}

// keyExpiryWarning is how far ahead keys that are about to expire are named in
// the logs.
const keyExpiryWarning = 14 * 24 * time.Hour

// logKeyExpiries names the API keys that have expired or will soon, at startup
// and on each reload; the metrics only count them.
func logKeyExpiries(log *slog.Logger, snap *config.Snapshot, now time.Time) {
	e := snap.KeyExpiries(now, keyExpiryWarning)
	if len(e.Expired) > 0 {
		log.Warn("API keys past their expires_at are refused", "keys", e.Expired)
	}
	if len(e.Soon) > 0 {
		log.Warn("API keys expire within 14 days", "keys", e.Soon)
	}
}

// sameOIDCConnection compares everything about the OIDC setup that is fixed at
// startup, i.e. all of it except the group mappings.
func sameOIDCConnection(a, b config.OIDCConfig) bool {
	a.Mappings, b.Mappings = nil, nil
	return reflect.DeepEqual(a, b)
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
