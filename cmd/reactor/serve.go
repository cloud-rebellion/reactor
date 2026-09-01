package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bright-interaction/reactor/internal/auth"
	"github.com/bright-interaction/reactor/internal/autoscale"
	"github.com/bright-interaction/reactor/internal/codegen"
	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/dispatcher"
	"github.com/bright-interaction/reactor/internal/flarereport"
	"github.com/bright-interaction/reactor/internal/graph"

	"github.com/bright-interaction/reactor/internal/catalog"
	"github.com/bright-interaction/reactor/internal/knowledge"
	"github.com/bright-interaction/reactor/internal/mcp"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/notifier"
	"github.com/bright-interaction/reactor/internal/oauth"
	"github.com/bright-interaction/reactor/internal/postmortem"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/rotators"
	"github.com/bright-interaction/reactor/internal/runlogs"
	"github.com/bright-interaction/reactor/internal/runtime/cancelreg"
	"github.com/bright-interaction/reactor/internal/runtime/cron"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/supervisor"
	"github.com/bright-interaction/reactor/internal/runtime/webhook"
	"github.com/bright-interaction/reactor/internal/server"
	"github.com/bright-interaction/reactor/internal/vault"
)

// cmdServe is the daemon entrypoint. Boots every component the runtime
// needs and blocks until SIGINT/SIGTERM. Components started:
//
//   - HTTP server (status pages + webhook + signal routes)
//   - Cron driver (active cron-kind triggers)
//   - Scheduler (Sleep/AwaitSignal resume + signal expiry)
//   - Rotation runner (auto-rotates credentials on schedule)
//
// The supervisor itself is spawned per-run by the dispatcher; nothing
// runs at boot beyond what's wired here.
func cmdServe(ctx context.Context, log *slog.Logger, args []string) error {
	cfg, err := parseServeFlags(args)
	if err != nil {
		return err
	}
	// Error reporting to Flare (no-op unless FLARE_DSN is set; the DSN is
	// injected by the Hephaestus flare-provision deploy step).
	flarereport.InitFlare("reactor", Version)
	deps, err := openServeDeps(ctx, log, cfg)
	if err != nil {
		return err
	}
	defer deps.db.Close()
	srv := buildHTTPServer(log, cfg, deps)
	return runServeLoop(ctx, log, cfg, deps, srv)
}

// serveConfig holds every parsed flag value. parseServeFlags is the
// only function that touches the flag.FlagSet, env vars, and master
// key resolution; everything else reads from this struct.
type serveConfig struct {
	dbURL             string
	addr              string
	tlsCert           string
	tlsKey            string
	root              string
	masterKey         []byte
	previousMasterKey []byte
	tickInterval      time.Duration
	rotationInterval  time.Duration
	cronReload        time.Duration
	drainTimeout      time.Duration
	aclPermissive     bool
	cgroupRoot        string
	insecureNoAuth    bool

	// mode is "local" (single-node, execute in-process) or "distributed"
	// (enqueue runs for `reactor worker` processes to claim). Distributed
	// mode requires Postgres.
	mode string

	// autoscale enables the worker autoscaler on the leader (distributed
	// mode only). Off by default -- a self-replicating system is opt-in.
	autoscale bool
}

// distributed reports whether the daemon runs in queue mode.
func (c *serveConfig) distributed() bool { return c.mode == "distributed" }

// parseServeFlags fills a serveConfig from CLI args + env vars,
// resolves the master key, and validates the bare minimum (db URL +
// root). Migrations are deliberately not run here so a flag-parse
// failure doesn't half-migrate the schema.
func parseServeFlags(args []string) (*serveConfig, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL (sqlite://path or postgres://...)")
	addr := fs.String("addr", ":7777", "HTTP listen address")
	tlsCert := fs.String("tls-cert", envFirst("REACTOR_TLS_CERT", "ARACHNE_TLS_CERT"), "path to TLS cert (PEM); empty = plain HTTP")
	tlsKey := fs.String("tls-key", envFirst("REACTOR_TLS_KEY", "ARACHNE_TLS_KEY"), "path to TLS key (PEM); both --tls-cert and --tls-key must be set together")
	root := fs.String("root", defaultRoot(), "Reactor state directory (workflows/ + master.key)")
	masterKeyFile := fs.String("master-key-file", "", "path to a 64-hex-char master key (default <root>/master.key)")
	masterKeyHex := fs.String("master-key", envFirst("REACTOR_MASTER_KEY", "ARACHNE_MASTER_KEY"), "32-byte hex master key (overrides --master-key-file)")
	tickInterval := fs.Duration("scheduler-tick", 5*time.Second, "scheduler poll interval")
	rotationInterval := fs.Duration("rotation-tick", time.Hour, "rotation runner tick interval")
	cronReload := fs.Duration("cron-reload", 30*time.Second, "interval at which the cron driver re-syncs the triggers table; 0 disables live-reload")
	drainTimeout := fs.Duration("drain-timeout", time.Duration(envIntFirst("REACTOR_DRAIN_TIMEOUT", "ARACHNE_DRAIN_TIMEOUT", 30))*time.Second, "max time to wait for in-flight workflows to finish on SIGINT before force-cancelling")
	aclPermissive := fs.Bool("vault-acl-permissive", os.Getenv("REACTOR_VAULT_ACL_PERMISSIVE") == "1", "when set, an empty workflow_secret_grants table allows every fetch (legacy v0 behaviour). Default (strict) denies on empty so an operator must explicitly grant per workflow.")
	cgroupRoot := fs.String("cgroup-root", os.Getenv("REACTOR_CGROUP_ROOT"), "when set (typical: /sys/fs/cgroup), each workflow subprocess lands in a per-run cgroup v2 with memory.max + pids.max. Falls back to prlimit-only when the path isn't a cgroup v2 mount or the daemon lacks write perms.")
	insecureNoAuth := fs.Bool("insecure-no-auth", os.Getenv("REACTOR_INSECURE_NO_AUTH") == "1", "EXPLICIT opt-in to run the dashboard with no authentication when REACTOR_BASIC_AUTH_USER / REACTOR_BASIC_AUTH_PASSWORD_SHA256 are unset. Default (false) fails closed with HTTP 503 until creds are configured.")
	mode := fs.String("mode", envFirstOr("local", "REACTOR_MODE"), "execution mode: 'local' (single-node, run workflows in-process) or 'distributed' (enqueue runs for `reactor worker` processes; requires Postgres)")
	autoscale := fs.Bool("autoscale", os.Getenv("REACTOR_AUTOSCALE") == "1", "distributed mode only: the leader spawns/stops `reactor worker` processes to track queue depth (bounded by REACTOR_AUTOSCALE_MAX, default 4). Off by default.")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return nil, err
	}
	if *dbURL == "" {
		return nil, errors.New("missing --db (or REACTOR_DB_URL env var)")
	}
	if *root == "" {
		return nil, errors.New("missing --root (and HOME unset)")
	}
	if *mode != "local" && *mode != "distributed" {
		return nil, fmt.Errorf("invalid --mode %q (want local or distributed)", *mode)
	}
	if *mode == "distributed" && !isPostgresURL(*dbURL) {
		return nil, errors.New("--mode distributed requires a postgres:// database (SQLite can't back multiple worker processes)")
	}
	masterHex, err := loadMasterKey(*masterKeyHex, *masterKeyFile, *root)
	if err != nil {
		return nil, err
	}
	masterKey, err := decodeMasterKey(masterHex)
	if err != nil {
		return nil, err
	}
	// Optional previous master key for a rotation window: set both
	// REACTOR_MASTER_KEY (new) and REACTOR_MASTER_KEY_PREVIOUS (old) and the
	// vault lazily re-encrypts each secret under the new key on read.
	var previousMasterKey []byte
	if prevHex := envFirst("REACTOR_MASTER_KEY_PREVIOUS", "ARACHNE_MASTER_KEY_PREVIOUS"); prevHex != "" {
		previousMasterKey, err = decodeMasterKey(prevHex)
		if err != nil {
			return nil, fmt.Errorf("REACTOR_MASTER_KEY_PREVIOUS: %w", err)
		}
	}
	return &serveConfig{
		dbURL:             *dbURL,
		addr:              *addr,
		tlsCert:           *tlsCert,
		tlsKey:            *tlsKey,
		root:              *root,
		masterKey:         masterKey,
		previousMasterKey: previousMasterKey,
		tickInterval:      *tickInterval,
		rotationInterval:  *rotationInterval,
		cronReload:        *cronReload,
		drainTimeout:      *drainTimeout,
		aclPermissive:     *aclPermissive,
		cgroupRoot:        *cgroupRoot,
		insecureNoAuth:    *insecureNoAuth,
		mode:              *mode,
		autoscale:         *autoscale,
	}, nil
}

// envFirstOr returns the first set env var among keys, or def.
func envFirstOr(def string, keys ...string) string {
	if v := envFirst(keys...); v != "" {
		return v
	}
	return def
}

// isPostgresURL reports whether a DB URL targets Postgres.
func isPostgresURL(u string) bool {
	return strings.HasPrefix(u, "postgres://") || strings.HasPrefix(u, "postgresql://")
}

// serveDeps holds every wired runtime component. openServeDeps is the
// only function that opens DB connections and constructs these; the
// caller (cmdServe) takes ownership of deps.db.Close() via defer.
type serveDeps struct {
	db         *sql.DB
	journal    *journal.Journal
	credRepo   *credentials.Repo
	vaultStore *vault.Store
	oauthStore *oauth.Store
	registry   *registry.FileRegistry
	knowStore  *knowledge.Store
	pmGen      *postmortem.Generator
	logBuffer  *runlogs.Buffer
	metrics    *server.Metrics
	dispatcher *dispatcher.Dispatcher
	receiver   *webhook.Receiver
	cronDriver *cron.Driver
	scheduler  *supervisor.Scheduler
	cancels    *cancelreg.Registry
	rotRunner  *rotators.Runner
	graph      *graph.Graph
	mcpSrv     *mcp.Server
	wfGen      server.WorkflowGenerator
	notifier   *notifier.Notifier
	authStore  *auth.Store
}

// openServeDeps runs migrations + opens the DB + wires every runtime
// component. The order matters: migrations before Open so the schema
// is current before any engine binds; vault after credentials so the
// engine bridge is set up; graph build is best-effort (a startup
// failure logs but doesn't block boot).
func openServeDeps(ctx context.Context, log *slog.Logger, cfg *serveConfig) (*serveDeps, error) {
	log.Info("serve: running migrations", "db", redactDB(cfg.dbURL))
	if err := migrate.Up(ctx, log, cfg.dbURL); err != nil {
		return nil, fmt.Errorf("serve: migrate: %w", err)
	}
	db, engine, err := migrate.Open(cfg.dbURL)
	if err != nil {
		return nil, fmt.Errorf("serve: open db: %w", err)
	}
	jEngine := journal.EngineSQLite
	credEngine := credentials.EngineSQLite
	vaultEngine := vault.SQLEngineSQLite
	if engine == migrate.EnginePostgres {
		jEngine = journal.EnginePostgres
		credEngine = credentials.EnginePostgres
		vaultEngine = vault.SQLEnginePostgres
	}
	j := journal.New(db, jEngine)
	// Local mode only: a fresh single-node process owns no in-flight
	// supervisors, so any run still marked "running" is orphaned from a
	// prior crash; fail it. In DISTRIBUTED mode this must NOT run -- a
	// serve restart would fail runs that healthy workers are actively
	// executing. There, dead-worker runs are requeued by the lease reaper
	// (ReapExpiredLeases) instead, which resumes them rather than failing.
	if !cfg.distributed() {
		if n, rErr := j.ReapOrphanedRuns(ctx); rErr != nil {
			db.Close()
			return nil, fmt.Errorf("serve: recover local orphaned runs: %w", rErr)
		} else if n > 0 {
			log.Info("serve: classified orphaned local runs", "count", n)
		}
	}
	credRepo := credentials.New(db, credEngine)
	authEngine := auth.EngineSQLite
	if engine == migrate.EnginePostgres {
		authEngine = auth.EnginePostgres
	}
	authStore := auth.New(db, authEngine, buildMFAOptions(log, cfg.masterKey)...)
	vaultStore, err := vault.NewStore(vault.NewSQLBackend(db, vaultEngine), cfg.masterKey, cfg.previousMasterKey)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("serve: vault: %w", err)
	}
	oauthEngine := oauth.EngineSQLite
	if engine == migrate.EnginePostgres {
		oauthEngine = oauth.EnginePostgres
	}
	oauthStore := oauth.New(db, oauthEngine, cfg.masterKey)
	// Teach the generic OAuth flow each provider's quirks (token-exchange auth
	// style, extra authorize params) from the service catalog, so adding a
	// provider that needs HTTP Basic or extra params is a catalog entry, not a
	// code change.
	oauthStore.ProfileFor = func(id string) oauth.Profile {
		if svc, ok := catalog.ByID(id); ok {
			return oauth.Profile{TokenAuthStyle: svc.TokenAuthStyle, AuthParams: svc.AuthParams}
		}
		return oauth.Profile{}
	}
	reg := registry.New(filepath.Join(cfg.root, "workflows"))

	knowStore, err := knowledge.New(filepath.Join(cfg.root, "knowledge"))
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("serve: knowledge: %w", err)
	}
	knowStore.Git = &codegen.GitCommitter{}

	pmGen := buildPostMortemGenerator(log, j, knowStore)
	logBuffer := runlogs.New(1000, 10*time.Minute)
	// Persist each run's log tail to the DB when it terminates so it
	// survives the in-memory ring's grace window (the dashboard + MCP read
	// it back). Best-effort: a failed write logs but doesn't block.
	logBuffer.OnClose = func(runID string, lines []string) {
		if err := j.SaveRunLogs(context.Background(), runID, lines); err != nil {
			log.Warn("serve: persist run logs failed", "run_id", runID, "err", err)
		}
	}
	metrics := server.NewMetrics()
	notif := buildNotifier(log, cfg, j, vaultStore)

	cancels := cancelreg.New()
	disp := buildDispatcher(log, cfg, j, vaultStore, reg, metrics, logBuffer, pmGen, notif)
	disp.Cancels = cancels
	// Distributed mode: every dispatcher (the serve daemon AND each worker)
	// enqueues instead of executing in-process. Triggers enqueue; workers
	// claim + ExecuteRun; a worker's chained dispatch enqueues for another
	// worker to pick up. Only ExecuteRun actually runs a subprocess.
	disp.Enqueue = cfg.distributed()
	// Workflows resolve `oauth:<connection-id>` secrets to a fresh OAuth token.
	// Set on the template before schedTemplate copies it so resumed runs (and
	// the scheduler) get it too.
	disp.Sup.OAuthTokens = oauthStore
	receiver := &webhook.Receiver{
		Journal: j,
		Vault:   vaultStore,
		Disp:    disp,
		Log:     log,
	}
	cronDriver := &cron.Driver{
		Journal:        j,
		Disp:           disp,
		Log:            log,
		ReloadInterval: cfg.cronReload,
	}
	if strings.HasPrefix(cfg.dbURL, "postgres://") || strings.HasPrefix(cfg.dbURL, "postgresql://") {
		cronDriver.Listener = &cron.PgListener{DSN: cfg.dbURL, Log: log}
		log.Info("serve: cron pg LISTEN/NOTIFY subscriber enabled")
	}
	// The scheduler resumes suspended runs by re-spawning a supervisor, so
	// it needs the SAME template the dispatcher uses (Vault, ACLPermissive,
	// resource Limits) plus the log sink, otherwise resumed runs would run
	// with default ACL + no limits + no log tail. OnTerminal routes a
	// resumed run's REAL terminal status through the same notifier + chain
	// path the first spawn used (the first spawn only ever terminated as
	// "suspended").
	schedTemplate := disp.Sup
	schedTemplate.LogSink = logBuffer.Append
	scheduler := &supervisor.Scheduler{
		Journal:            j,
		Vault:              vaultStore,
		Log:                log,
		BinaryPath:         reg.BinaryPath,
		ArtifactPath:       reg.ArtifactPath,
		TickInterval:       cfg.tickInterval,
		SupervisorTemplate: schedTemplate,
		Cancels:            cancels,
		Enqueue:            cfg.distributed(),
		OnTerminal: func(ctx context.Context, ti supervisor.TerminalInfo) {
			releaseAdmission := disp.HoldTerminalAdmission()
			defer releaseAdmission()
			handleRunTerminal(ctx, log, notif, j, disp, logBuffer, dispatcher.TerminalEvent{
				RunID:        ti.RunID,
				WorkflowID:   ti.WorkflowID,
				WorkflowSlug: ti.WorkflowSlug,
				Status:       ti.Status,
				TriggerKind:  ti.TriggerKind,
				ErrorText:    ti.ErrorText,
				DryRun:       ti.DryRun,
			})
		},
	}
	rotRunner := &rotators.Runner{
		Repo:         credRepo,
		Vault:        vaultStore,
		Log:          log,
		TickInterval: cfg.rotationInterval,
	}
	graphBuilder := &graph.Builder{Journal: j, Credentials: credRepo, Knowledge: knowStore}
	gGraph, gErr := graphBuilder.Build(ctx)
	if gErr != nil {
		log.Warn("serve: graph build failed at startup", "err", gErr)
	}
	mcpSrv := &mcp.Server{
		Info: mcp.ServerInfo{
			Name:    "reactor",
			Version: Version,
		},
		Journal:     j,
		Credentials: credRepo,
		Knowledge:   knowStore,
		Graph:       gGraph,
		Log:         log,
		StateRoot:   cfg.root,
	}
	wfGen := buildWorkflowGenerator(log, cfg)
	return &serveDeps{
		db:         db,
		journal:    j,
		credRepo:   credRepo,
		vaultStore: vaultStore,
		oauthStore: oauthStore,
		registry:   reg,
		knowStore:  knowStore,
		pmGen:      pmGen,
		logBuffer:  logBuffer,
		metrics:    metrics,
		dispatcher: disp,
		receiver:   receiver,
		cronDriver: cronDriver,
		scheduler:  scheduler,
		cancels:    cancels,
		rotRunner:  rotRunner,
		graph:      gGraph,
		mcpSrv:     mcpSrv,
		wfGen:      wfGen,
		notifier:   notif,
		authStore:  authStore,
	}, nil
}

// runRetentionLoop periodically drops ephemeral rows that would otherwise
// grow without bound: expired sessions and old webhook idempotency
// records. Both sweep methods existed but had no caller (the audit's
// "zero callers" finding). Run/step history is deliberately NOT purged
// here: deleting an operator's run history is a product decision, not a
// silent default. Tick hourly; sweep once immediately on boot.
func runRetentionLoop(ctx context.Context, log *slog.Logger, deps *serveDeps) {
	webhookRetain := time.Duration(envIntFirst("REACTOR_WEBHOOK_DEDUP_RETAIN_HOURS", "", 720)) * time.Hour
	// Run-history retention is OPT-IN (0 = keep forever, the historical
	// default): deleting run history is a product/GDPR decision, not a silent
	// one. When set, finished runs older than N days are purged.
	runRetentionDays := envIntFirst("REACTOR_RUN_RETENTION_DAYS", "", 0)
	sweep := func() {
		if n, err := deps.authStore.SweepExpiredSessions(ctx); err != nil {
			log.Warn("serve: sweep expired sessions failed", "err", err)
		} else if n > 0 {
			log.Info("serve: swept expired sessions", "count", n)
		}
		if n, err := deps.authStore.SweepExpiredChallenges(ctx); err != nil {
			log.Warn("serve: sweep expired webauthn challenges failed", "err", err)
		} else if n > 0 {
			log.Info("serve: swept expired webauthn challenges", "count", n)
		}
		if err := deps.journal.PurgeOldWebhookDeliveries(ctx, webhookRetain); err != nil {
			log.Warn("serve: purge old webhook deliveries failed", "err", err)
		}
		if runRetentionDays > 0 {
			cutoff := time.Now().UTC().Add(-time.Duration(runRetentionDays) * 24 * time.Hour)
			if n, err := deps.journal.PurgeTerminalRunsOlderThan(ctx, cutoff); err != nil {
				log.Warn("serve: run retention purge failed", "err", err)
			} else if n > 0 {
				log.Info("serve: purged old runs (retention)", "count", n, "older_than_days", runRetentionDays)
			}
		}
	}
	sweep()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep()
		}
	}
}

// runCancelWatcher honours cross-process cancellation requests. The CLI
// and MCP run outside the daemon, so they set runs.cancel_requested; this
// loop observes that flag and either cancels the live subprocess (running
// here) or finalizes a suspended run so the scheduler never resumes it.
// In-daemon dashboard cancels go straight through the registry, so this
// is the backstop for the cross-process path + the running->suspended
// race. Polls every 2s (well under the prompt-cache window) so cancels
// feel near-instant without hammering the DB.
func runCancelWatcher(ctx context.Context, log *slog.Logger, deps *serveDeps) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	tick := func() {
		ids, err := deps.journal.ListCancelRequestedActive(ctx)
		if err != nil {
			log.Warn("serve: cancel watcher list failed", "err", err)
			return
		}
		for _, id := range ids {
			if deps.cancels.Cancel(id) {
				log.Info("serve: cancelled live run on request", "run_id", id)
				continue
			}
			// Not executing here. Only finalize when no distributed lease is
			// present; another worker's live claim must persist cancellation
			// with its exact owner token.
			if _, err := deps.journal.FinalizeCancelIfUnleased(ctx, id); err != nil {
				log.Warn("serve: finalize cancel failed", "run_id", id, "err", err)
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// runCanceller is the server's RunCanceller: it records the request in the
// DB (so it survives + works for suspended runs) and, when the run is
// executing on this daemon, cancels it in-process for instant feedback.
type runCanceller struct {
	j       *journal.Journal
	cancels *cancelreg.Registry
}

func (c runCanceller) Cancel(ctx context.Context, runID string) (string, error) {
	outcome, err := c.j.RequestRunCancel(ctx, runID)
	if err != nil {
		return outcome, err
	}
	if outcome == journal.CancelRequested {
		// Running: kill the live subprocess now if it is ours; the watcher
		// is the backstop if it is not (or for a later race).
		c.cancels.Cancel(runID)
	}
	return outcome, nil
}

// buildPostMortemGenerator requires explicit diagnostic-egress opt-in as well
// as an Anthropic credential. The dispatcher gracefully skips generation when
// either condition is absent.
func buildPostMortemGenerator(log *slog.Logger, j *journal.Journal, knowStore *knowledge.Store) *postmortem.Generator {
	if !aiPostmortemEnabled() {
		log.Info("serve: post-mortem auto-generation disabled (explicit AI egress opt-in not set)")
		return nil
	}
	anth, err := codegen.NewAnthropicFromEnv()
	if err != nil {
		log.Info("serve: post-mortem auto-generation disabled (ANTHROPIC_API_KEY not set)")
		return nil
	}
	log.Info("serve: post-mortem auto-generation enabled (identifiers are redacted and Step errors synthesized before egress)")
	return &postmortem.Generator{
		Anthropic: anth,
		Journal:   j,
		Knowledge: knowStore,
		Log:       log,
	}
}

// buildDispatcher wires the dispatcher + supervisor template. Pulled
// out so the run-loop wiring is one focused block; the OnLog +
// OnTerminal + OnDeadLetter callbacks live here so the lifecycle
// rules are colocated.
func buildDispatcher(
	log *slog.Logger,
	cfg *serveConfig,
	j *journal.Journal,
	vaultStore *vault.Store,
	reg *registry.FileRegistry,
	metrics *server.Metrics,
	logBuffer *runlogs.Buffer,
	pmGen *postmortem.Generator,
	notif *notifier.Notifier,
) *dispatcher.Dispatcher {
	// Declare disp up-front so the OnTerminal closure can call
	// disp.Dispatch when chain-firing downstream workflows. The
	// dispatcher's lifecycle methods are safe to call against the
	// same instance that invoked OnTerminal: Dispatch spawns a
	// fresh inFlight goroutine which the drain path will wait on.
	disp := &dispatcher.Dispatcher{
		Journal:       j,
		Resolver:      &dispatcher.SQLResolver{Journal: j},
		BinaryPath:    reg.BinaryPath,
		ArtifactPath:  reg.ArtifactPath,
		Log:           log,
		Counters:      metrics,
		MaxConcurrent: envIntFirst("REACTOR_MAX_CONCURRENT_RUNS", "", 32),
		Sup: supervisor.Supervisor{
			Vault:            vaultStore,
			ACLPermissive:    cfg.aclPermissive,
			SignalSigningKey: cfg.masterKey,
			Limits: supervisor.ResourceLimits{
				CgroupRoot: cfg.cgroupRoot,
			},
		},
		OnLog: func(runID, line string) {
			logBuffer.Append(runID, line)
		},
	}
	disp.OnTerminal = func(ctx context.Context, ev dispatcher.TerminalEvent) {
		releaseAdmission := disp.HoldTerminalAdmission()
		defer releaseAdmission()
		handleRunTerminal(ctx, log, notif, j, disp, logBuffer, ev)
	}
	if pmGen != nil {
		disp.OnDeadLetter = func(ctx context.Context, runID string) {
			id, err := pmGen.Generate(ctx, runID)
			if err != nil {
				log.Warn("serve: post-mortem generation failed", "run_id", runID, "err", err)
				return
			}
			log.Info("serve: post-mortem written", "run_id", runID, "entry_id", id)
		}
	}
	return disp
}

// buildNotifier returns a Notifier with Slack + generic-webhook + email
// senders registered. The dashboard URL (used to render "Open run"
// buttons in alert bodies) is read from REACTOR_DASHBOARD_URL with a
// fallback to the listen addr; operators behind a reverse proxy set
// the env var explicitly.
func buildNotifier(log *slog.Logger, cfg *serveConfig, j *journal.Journal, vaultStore *vault.Store) *notifier.Notifier {
	dashURL := envFirst("REACTOR_DASHBOARD_URL")
	if dashURL == "" {
		dashURL = "http://" + cfg.addr
	}
	return notifier.New(j, log).
		WithSender(notifier.NewSlackSender()).
		WithSender(notifier.NewWebhookSender()).
		WithSender(notifier.NewEmailSender()).
		WithDashboardURL(dashURL).
		// Resolve channel credential references (SMTP password, webhook
		// auth header) from the vault at send time so they never sit in
		// config_json plaintext.
		WithSecretResolver(func(ctx context.Context, credentialID string) (string, error) {
			sec, err := vaultStore.Get(ctx, credentialID)
			if err != nil {
				return "", err
			}
			return string(sec.Reveal()), nil
		})
}

// buildWorkflowGenerator returns the server-side adapter wrapping
// codegen.Generator when ANTHROPIC_API_KEY is set; otherwise nil so
// Mount skips the /generate route.
func buildWorkflowGenerator(log *slog.Logger, cfg *serveConfig) server.WorkflowGenerator {
	anth, err := codegen.NewAnthropicFromEnv()
	if err != nil {
		log.Info("serve: dashboard codegen prompt bar disabled (ANTHROPIC_API_KEY not set)")
		return nil
	}
	log.Info("serve: dashboard codegen prompt bar enabled")
	return generatorAdapter{gen: &codegen.Generator{
		Anthropic:    anth,
		Log:          log,
		WorkflowsDir: filepath.Join(cfg.root, "generated-workflows"),
		MaxRetries:   3,
	}}
}

// buildHTTPServer assembles the server.Server with every capability
// wired. Capabilities the daemon has are passed in; nil-valued
// optional fields are left as zero values so Mount's per-feature
// helpers skip their corresponding route groups.
func buildHTTPServer(log *slog.Logger, cfg *serveConfig, deps *serveDeps) *server.Server {
	srv := &server.Server{
		Journal:        deps.journal,
		Credentials:    deps.credRepo,
		OAuth:          deps.oauthStore,
		Vault:          deps.vaultStore,
		Rotator:        deps.rotRunner,
		Generator:      deps.wfGen,
		MCPHandler:     deps.mcpSrv,
		Metrics:        deps.metrics,
		ManualDispatch: deps.dispatcher,
		Notifier:       deps.notifier,
		Auth:           deps.authStore,
		DLQRetry:       deps.dispatcher,
		RunCanceller:   runCanceller{j: deps.journal, cancels: deps.cancels},
		KnowledgeWrite: knowledgeAdapter{store: deps.knowStore, log: log},
		WorkflowRegister: workflowRegistrarAdapter{
			registry:  deps.registry,
			journal:   deps.journal,
			root:      cfg.root,
			committer: &codegen.GitCommitter{},
			log:       log,
		},
		State:         cfg.root,
		Registry:      deps.registry,
		Knowledge:     deps.knowStore,
		Graph:         deps.graph,
		Webhook:       deps.receiver,
		Log:           log,
		Version:       Version,
		WorkflowsRoot: filepath.Join(cfg.root, "workflows"),
		CodeValidator: editValidator{},
		CodeCommitter: &codegen.GitCommitter{},
		LogBuffer:     deps.logBuffer,
		BasicAuth: server.BasicAuthConfig{
			User:           envFirst("REACTOR_BASIC_AUTH_USER", "ARACHNE_BASIC_AUTH_USER"),
			PasswordSHA256: envFirst("REACTOR_BASIC_AUTH_PASSWORD_SHA256", "ARACHNE_BASIC_AUTH_PASSWORD_SHA256"),
			AllowNoAuth:    cfg.insecureNoAuth,
			Realm:          "reactor",
		},
		RateLimit: server.RateLimitConfig{
			Burst:  envIntFirst("REACTOR_RATE_BURST", "ARACHNE_RATE_BURST", 60),
			Refill: envFloatFirst("REACTOR_RATE_REFILL", "ARACHNE_RATE_REFILL", 10),
		},
		// Force the session cookie's Secure flag when the daemon sits
		// behind a TLS-terminating proxy (r.TLS is nil there). Opt in via
		// REACTOR_SECURE_COOKIES=1 or simply by configuring an https
		// dashboard URL. Direct-TLS deploys get Secure regardless.
		SecureCookies: os.Getenv("REACTOR_SECURE_COOKIES") == "1" ||
			strings.HasPrefix(envFirst("REACTOR_DASHBOARD_URL"), "https://"),
	}
	if srv.BasicAuth.User == "" && srv.BasicAuth.PasswordSHA256 == "" && !cfg.insecureNoAuth {
		log.Warn("serve: dashboard auth credentials not configured; HTTP routes (except /healthz + /webhook/* + /signal/*) will return 503 until REACTOR_BASIC_AUTH_USER + REACTOR_BASIC_AUTH_PASSWORD_SHA256 are set or --insecure-no-auth is passed")
	}
	if cfg.insecureNoAuth {
		// The wide-open state is the one that most deserves a warning, yet it
		// used to log nothing. Make it LOUD on every boot so an inherited
		// REACTOR_INSECURE_NO_AUTH=1 (an env-file typo, a copied base config)
		// cannot silently serve the whole dashboard, including every admin
		// mutation, with no authentication.
		log.Error("serve: SECURITY: insecure-no-auth is ACTIVE (--insecure-no-auth or REACTOR_INSECURE_NO_AUTH=1). The dashboard is served with NO authentication and all admin mutations are reachable unauthenticated. Use this ONLY in a trusted local/dev context; unset it for any shared or production deploy.")
	}
	// Bridge the legacy env-var BasicAuth into the users table: when creds are
	// configured and no matching user exists yet, seed them as the first admin.
	// SessionAuth then resolves a BasicAuth request to that admin (a "signed-in"
	// identity), which is what the session-gated write/build routes require
	// (upload, codegen, triggers). Without this a basic-auth-only deploy can
	// authenticate but never reach the dashboard's create surfaces. Idempotent.
	if srv.BasicAuth.User != "" && srv.BasicAuth.PasswordSHA256 != "" {
		if created, err := deps.authStore.EnsureAdminWithPHC(context.Background(), srv.BasicAuth.User, srv.BasicAuth.PasswordSHA256); err != nil {
			log.Warn("serve: could not seed admin user from BasicAuth env", "err", err)
		} else if created {
			log.Info("serve: seeded admin user from REACTOR_BASIC_AUTH_* so dashboard write/build routes are reachable", "user", srv.BasicAuth.User)
		}
	}
	return srv
}

// readContainerMemoryMax returns the daemon's own cgroup v2 memory.max
// (the container memory limit) as a string of bytes, "max" when unlimited,
// or "" when it can't be read (non-cgroup-v2 host, file absent). Used by the
// memory self-check to report the actual outer fence instead of guessing.
func readContainerMemoryMax() string {
	b, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// runServeLoop starts every long-running goroutine, waits for SIGINT/
// SIGTERM, and drains in-flight runs before returning. The shutdown
// order matters: stop trigger sources first so no new runs land, then
// drain the dispatcher, then wait for the goroutines.
func runServeLoop(ctx context.Context, log *slog.Logger, cfg *serveConfig, deps *serveDeps, srv *server.Server) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigCh
		log.Info("serve: signal received, shutting down", "signal", s.String())
		cancel()
	}()

	var wg sync.WaitGroup
	wg.Add(4)
	// HTTP + enqueue + cancel + retention run on EVERY instance.
	go func() {
		defer wg.Done()
		runCancelWatcher(runCtx, log, deps)
	}()
	go func() {
		defer wg.Done()
		runRetentionLoop(runCtx, log, deps)
	}()
	go func() {
		defer wg.Done()
		runDaemonComponent(log, "http_server", func() error {
			return srv.RunWithTLS(runCtx, cfg.addr, server.TLSConfig{CertFile: cfg.tlsCert, KeyFile: cfg.tlsKey})
		})
	}()
	// Scheduler + cron + rotation are single-leader: in distributed mode an
	// advisory lock elects one instance to run them so resumes/crons/
	// rotations don't fire on every daemon. In local mode this instance is
	// the leader immediately.
	go func() {
		defer wg.Done()
		runLeaderTasks(runCtx, log, cfg, deps)
	}()

	log.Info("serve: ready",
		"addr", cfg.addr, "root", cfg.root,
		"scheduler_tick", cfg.tickInterval.String(),
		"rotation_tick", cfg.rotationInterval.String(),
		"cron_reload", cfg.cronReload.String())

	// Memory-enforcement self-check. RLIMIT_AS can't bound a Go heap (it
	// crashes the child at startup), so per-workflow memory is capped ONLY by
	// cgroup v2 memory.max (needs --cgroup-root + delegation). When that's
	// off, the fence is the daemon's own container memory limit. Report the
	// actual state: WARN loudly only if memory is truly unbounded, else note
	// the container limit that bounds it.
	if runtime.GOOS == "linux" && cfg.cgroupRoot == "" {
		switch limit := readContainerMemoryMax(); {
		case limit == "" || limit == "max":
			log.Warn("serve: workflow memory is UNBOUNDED (no --cgroup-root AND no container memory limit); a runaway workflow can exhaust the host. Set a container memory limit (e.g. docker --memory) or --cgroup-root=/sys/fs/cgroup with cgroup v2 delegation for per-workflow memory.max.")
		default:
			log.Info("serve: per-workflow memory limiting is off; total memory is bounded by the container limit", "container_memory_max_bytes", limit,
				"hint", "for per-workflow caps, set --cgroup-root=/sys/fs/cgroup with cgroup v2 delegation")
		}
	}

	<-runCtx.Done()
	// Close scheduler admission before observing counts. Stop is idempotent and
	// runLeaderTasks also invokes it; the mutex gate makes this serialize with a
	// dispatch whose context check passed just before shutdown.
	deps.scheduler.Stop()
	deps.dispatcher.Stop()
	// Sample scheduler first: its terminal hook hands off to dispatcher before
	// decrementing its own count. Once scheduler is zero, the subsequent
	// dispatcher sample sees every child admitted by that handoff.
	scheduled, dispatched := deps.scheduler.InFlight(), deps.dispatcher.InFlight()
	if dispatched+scheduled > 0 {
		log.Info("serve: draining in-flight runs",
			"dispatcher_count", dispatched, "scheduler_count", scheduled,
			"timeout", cfg.drainTimeout.String())
		if err := drainServeExecutions(deps, cfg.drainTimeout); err != nil {
			// Drain timed out: kill the remaining subprocesses so they
			// don't orphan and so they stop touching the DB we are about
			// to close (deps.db.Close runs after this returns). Then give
			// them a short bounded window to persist a recoverable
			// infrastructure stop.
			admissions := deps.dispatcher.CancelAdmissions(cancelreg.ErrInfrastructureShutdown)
			killed := deps.cancels.CancelAllWithCause(cancelreg.ErrInfrastructureShutdown)
			log.Warn("serve: drain timed out; interrupted in-flight runs", "killed", killed, "admissions", admissions, "err", err)
			if killed+admissions > 0 {
				_ = drainServeExecutions(deps, 5*time.Second)
			}
		} else {
			log.Info("serve: drain complete")
		}
	}
	wg.Wait()
	log.Info("serve: shutdown complete")
	return nil
}

// drainServeExecutions waits on both entry paths that can own a workflow
// subprocess. Scheduler admission must be closed before calling it; otherwise a
// zero observation could race a due dispatch entering immediately afterward.
func drainServeExecutions(deps *serveDeps, timeout time.Duration) error {
	started := time.Now()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		scheduled, dispatched := deps.scheduler.InFlight(), deps.dispatcher.InFlight()
		if dispatched+scheduled == 0 {
			return nil
		}
		if timeout > 0 && time.Since(started) >= timeout {
			return fmt.Errorf("serve: drain timed out after %s with dispatcher=%d scheduler=%d in flight",
				timeout, dispatched, scheduled)
		}
		<-ticker.C
	}
}

// runAutoscaler builds + runs the worker autoscaler. The substrate is chosen
// with REACTOR_AUTOSCALE_SPAWNER (process|docker|kubernetes|command); see
// buildSpawner. Bounded by REACTOR_AUTOSCALE_MAX.
func runAutoscaler(ctx context.Context, log *slog.Logger, cfg *serveConfig, deps *serveDeps) {
	spawner, err := buildSpawner(log, cfg)
	if err != nil {
		log.Error("serve: autoscaler disabled", "err", err)
		return
	}
	ctrl := autoscale.New(autoscale.Config{
		Min:            envIntFirst("REACTOR_AUTOSCALE_MIN", "", 0),
		Max:            envIntFirst("REACTOR_AUTOSCALE_MAX", "", 4),
		QueuePerWorker: envIntFirst("REACTOR_AUTOSCALE_QUEUE_PER_WORKER", "", 20),
	}, spawner, deps.journal, log)
	ctrl.Run(ctx)
}

// buildSpawner selects the autoscaler substrate from REACTOR_AUTOSCALE_SPAWNER:
//
//	process     (default) re-exec this binary as `reactor worker` on THIS host.
//	docker      `docker run` a worker container   (needs REACTOR_WORKER_IMAGE).
//	kubernetes  `kubectl create` a worker Job      (needs REACTOR_WORKER_IMAGE).
//	command     run operator shell commands (REACTOR_AUTOSCALE_SPAWN_CMD/_STOP_CMD).
//
// Everything except `process` is dependency-free: Reactor shells out to the
// operator's own docker/kubectl/whatever CLI rather than linking the Docker or
// Kubernetes SDKs, so one mechanism covers every orchestrator and pins no
// client version. process is the default because it needs zero external setup.
func buildSpawner(log *slog.Logger, cfg *serveConfig) (autoscale.Spawner, error) {
	concurrency := strconv.Itoa(envIntFirst("REACTOR_WORKER_CONCURRENCY", "", runtime.NumCPU()))
	substrate := strings.ToLower(strings.TrimSpace(envFirstOr("process", "REACTOR_AUTOSCALE_SPAWNER")))
	switch substrate {
	case "process":
		self, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("process spawner: cannot find own binary: %w", err)
		}
		args := []string{"worker", "--db", cfg.dbURL, "--root", cfg.root, "--concurrency", concurrency}
		log.Info("serve: autoscaler substrate = process (same-host child processes)")
		return autoscale.NewProcessSpawner(self, args, os.Environ(), log), nil

	case "docker":
		image := os.Getenv("REACTOR_WORKER_IMAGE")
		if image == "" {
			return nil, fmt.Errorf("docker spawner needs REACTOR_WORKER_IMAGE")
		}
		spawn := []string{"docker", "run", "-d", "--rm", "--label", "reactor-worker=1"}
		spawn = append(spawn, strings.Fields(os.Getenv("REACTOR_AUTOSCALE_DOCKER_ARGS"))...)
		spawn = append(spawn, image, "worker", "--db", cfg.dbURL, "--root", cfg.root, "--concurrency", concurrency)
		stop := []string{"docker", "stop", "{id}"}
		log.Info("serve: autoscaler substrate = docker", "image", image)
		return autoscale.NewCommandSpawner(spawn, stop, os.Environ(), log), nil

	case "kubernetes", "k8s":
		image := os.Getenv("REACTOR_WORKER_IMAGE")
		if image == "" {
			return nil, fmt.Errorf("kubernetes spawner needs REACTOR_WORKER_IMAGE")
		}
		ns := envFirstOr("default", "REACTOR_AUTOSCALE_K8S_NAMESPACE")
		spawn := []string{"kubectl", "create", "--namespace", ns, "-f", "-", "-o", "name"}
		stop := []string{"kubectl", "delete", "--namespace", ns, "--ignore-not-found", "{id}"}
		sp := autoscale.NewCommandSpawner(spawn, stop, os.Environ(), log)
		sp.SpawnStdin = []byte(k8sWorkerJobManifest(image, ns, cfg, concurrency))
		log.Info("serve: autoscaler substrate = kubernetes", "image", image, "namespace", ns)
		return sp, nil

	case "command":
		spawnCmd := os.Getenv("REACTOR_AUTOSCALE_SPAWN_CMD")
		if spawnCmd == "" {
			return nil, fmt.Errorf("command spawner needs REACTOR_AUTOSCALE_SPAWN_CMD")
		}
		spawn := []string{"sh", "-c", spawnCmd}
		var stop []string
		if stopCmd := os.Getenv("REACTOR_AUTOSCALE_STOP_CMD"); stopCmd != "" {
			stop = []string{"sh", "-c", stopCmd}
		}
		log.Info("serve: autoscaler substrate = command (operator-supplied)")
		return autoscale.NewCommandSpawner(spawn, stop, os.Environ(), log), nil

	default:
		return nil, fmt.Errorf("unknown REACTOR_AUTOSCALE_SPAWNER %q (want process|docker|kubernetes|command)", substrate)
	}
}

// k8sWorkerJobManifest builds the Job YAML piped to `kubectl create -f -`.
// generateName makes each Job unique; ttlSecondsAfterFinished garbage-collects
// finished Jobs. If REACTOR_AUTOSCALE_K8S_DB_SECRET is set the DB URL is read
// from that Secret (kept out of the manifest) and passed via the kubelet's
// $(VAR) arg expansion; otherwise it is inlined.
func k8sWorkerJobManifest(image, ns string, cfg *serveConfig, concurrency string) string {
	envBlock, dbArg := "", cfg.dbURL
	if secret := os.Getenv("REACTOR_AUTOSCALE_K8S_DB_SECRET"); secret != "" {
		key := envFirstOr("db-url", "REACTOR_AUTOSCALE_K8S_DB_SECRET_KEY")
		envBlock = fmt.Sprintf(`
          env:
            - name: REACTOR_DB
              valueFrom:
                secretKeyRef:
                  name: %s
                  key: %s`, secret, key)
		dbArg = "$(REACTOR_DB)"
	}
	return fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata:
  generateName: reactor-worker-
  namespace: %s
  labels:
    app: reactor-worker
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 120
  template:
    metadata:
      labels:
        app: reactor-worker
    spec:
      restartPolicy: Never
      containers:
        - name: worker
          image: %s%s
          args: ["worker", "--db", "%s", "--root", "%s", "--concurrency", "%s"]
`, ns, image, envBlock, dbArg, cfg.root, concurrency)
}

// leaderLockKey is the fixed Postgres advisory-lock key that elects the
// single instance allowed to run the scheduler + cron + rotation in
// distributed mode. Arbitrary but stable across the fleet.
const leaderLockKey = 0x4152414348 // "ARACH"

// runLeaderTasks runs the single-leader background loops (scheduler, cron
// driver, rotation runner). In distributed mode it first blocks on a
// Postgres advisory lock so only one serve instance runs them; followers
// wait here and take over if the leader dies (the lock auto-releases when
// the holding connection drops). In local mode it is leader immediately.
func runLeaderTasks(ctx context.Context, log *slog.Logger, cfg *serveConfig, deps *serveDeps) {
	if cfg.distributed() {
		conn, err := deps.db.Conn(ctx)
		if err != nil {
			log.Error("serve: leadership conn failed; not running scheduler/cron", "err", err)
			return
		}
		defer conn.Close()
		log.Info("serve: waiting for scheduler/cron leadership (advisory lock)")
		// Blocking acquire. Respects ctx: on shutdown the driver cancels
		// the waiting query so a follower exits cleanly.
		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", leaderLockKey); err != nil {
			log.Info("serve: gave up waiting for leadership", "err", err)
			return
		}
		defer func() {
			_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", leaderLockKey)
		}()
		log.Info("serve: acquired scheduler/cron leadership")
	}

	if err := deps.cronDriver.Start(ctx); err != nil {
		log.Warn("serve: cron driver failed to start (continuing)", "err", err)
	}
	var lwg sync.WaitGroup
	lwg.Add(2)
	go func() {
		defer lwg.Done()
		runDaemonComponent(log, "scheduler", func() error { return deps.scheduler.Run(ctx) })
	}()
	go func() {
		defer lwg.Done()
		runDaemonComponent(log, "rotation_runner", func() error { return deps.rotRunner.Run(ctx) })
	}()
	// Worker autoscaler: leader-only, distributed-mode-only, opt-in. Spawns
	// + stops `reactor worker` processes to track queue depth.
	if cfg.distributed() && cfg.autoscale {
		lwg.Add(1)
		go func() {
			defer lwg.Done()
			runAutoscaler(ctx, log, cfg, deps)
		}()
	}
	<-ctx.Done()
	deps.cronDriver.Stop()
	deps.scheduler.Stop()
	deps.rotRunner.Stop()
	lwg.Wait()
}

// Adapter types live in adapters.go (editValidator, generatorAdapter,
// knowledgeAdapter, workflowRegistrarAdapter). See that file for the
// thin shims that bridge codegen + knowledge + registry packages onto
// the server.* interfaces.

// envFirst reads the first non-empty value from the provided env vars.
// Used to migrate from the legacy ARACHNE_* prefix to REACTOR_* without
// breaking running deployments: callers pass the canonical key first
// and the deprecated key second. Logs a one-time deprecation warning
// when the legacy key resolves the value.
// buildMFAOptions assembles the auth.Store MFA options. TOTP encryption key is
// derived from the daemon master key (so no new required secret; TOTP is simply
// unavailable when the master key is unset). WebAuthn passkeys need the relying
// party domain: taken from REACTOR_WEBAUTHN_RP_ID / _RP_ORIGIN, else derived
// from REACTOR_DASHBOARD_URL. When neither yields a domain, passkeys stay off
// and the /security page says so.
func buildMFAOptions(log *slog.Logger, masterKey []byte) []auth.Option {
	var opts []auth.Option
	if key := auth.DeriveMFAKey(masterKey); key != nil {
		opts = append(opts, auth.WithMFAKey(key))
	} else {
		log.Info("serve: TOTP disabled (no master key set; passkeys still work)")
	}
	rpOrigin := envFirst("REACTOR_WEBAUTHN_RP_ORIGIN")
	if rpOrigin == "" {
		rpOrigin = envFirst("REACTOR_DASHBOARD_URL")
	}
	rpID := envFirst("REACTOR_WEBAUTHN_RP_ID")
	if rpID == "" {
		rpID = auth.RPIDFromOrigin(rpOrigin)
	}
	if rpID == "" || rpOrigin == "" {
		log.Info("serve: WebAuthn passkeys disabled (set REACTOR_WEBAUTHN_RP_ID + REACTOR_WEBAUTHN_RP_ORIGIN, or REACTOR_DASHBOARD_URL)")
		return opts
	}
	wa, err := auth.NewWebAuthn(rpID, "Reactor", []string{rpOrigin})
	if err != nil {
		log.Warn("serve: WebAuthn passkeys disabled (invalid config)", "err", err)
		return opts
	}
	opts = append(opts, auth.WithWebAuthn(wa))
	log.Info("serve: WebAuthn passkeys enabled", "rp_id", rpID, "rp_origin", rpOrigin)
	return opts
}

func envFirst(keys ...string) string {
	for i, k := range keys {
		if v := os.Getenv(k); v != "" {
			if i > 0 {
				warnDeprecatedEnv(k, keys[0])
			}
			return v
		}
	}
	return ""
}

func envIntFirst(canonical, legacy string, def int) int {
	if v := envFirst(canonical, legacy); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envFloatFirst(canonical, legacy string, def float64) float64 {
	if v := envFirst(canonical, legacy); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

var deprecatedEnvOnce sync.Map

func warnDeprecatedEnv(legacy, canonical string) {
	if _, loaded := deprecatedEnvOnce.LoadOrStore(legacy, true); loaded {
		return
	}
	fmt.Fprintf(os.Stderr, "reactor: %s is deprecated; rename to %s before v0.3\n", legacy, canonical)
}

// envInt reads an env var as int, falling back to def when missing or
// unparseable. Used for the rate-limit knobs so operators can tune
// without changing flag names.
func envInt(key string, def int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

// envFloat reads an env var as float64 with a fallback.
func envFloat(key string, def float64) float64 {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return def
	}
	return f
}

// loadMasterKey resolves the master key from (in order): explicit
// --master-key flag, --master-key-file flag, ARACHNE_MASTER_KEY env, then
// <root>/master.key. Returns the hex string with whitespace trimmed.
func loadMasterKey(hexFlag, file, root string) (string, error) {
	if hexFlag != "" {
		return strings.TrimSpace(hexFlag), nil
	}
	candidate := file
	if candidate == "" {
		candidate = filepath.Join(root, "master.key")
	}
	data, err := os.ReadFile(candidate)
	if err != nil {
		return "", fmt.Errorf("serve: read master key %s: %w (run `reactor init` first?)", candidate, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// runDaemonComponent invokes fn under a deferred panic recovery so a single
// crash in a long-running daemon goroutine (scheduler, rotation_runner,
// http_server) cannot silently kill that subsystem without a log line. The
// runtime context cancellation is the normal shutdown path; a panic is the
// pathological one we want to surface. Mirrors the dockyard + mithras
// runWorker pattern shipped 2026-05-21. Non-Canceled errors are still
// logged at Error so an unexpected exit is visible without grepping.
func runDaemonComponent(log *slog.Logger, name string, fn func() error) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("serve: component panicked",
				"component", name,
				"panic", r,
				"stack", string(debug.Stack()),
			)
		}
	}()
	if err := fn(); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("serve: component exited", "component", name, "err", err)
	}
}
