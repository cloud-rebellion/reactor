package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/bright-interaction/reactor/internal/catalog"
	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/knowledge"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/oauth"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runlogs"
	"github.com/bright-interaction/reactor/internal/runtime/cancelreg"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/server"
	"github.com/bright-interaction/reactor/internal/vault"
)

// openWorkerDeps wires only what the distributed claim/execution loop uses.
// The serving daemon owns migrations, the knowledge corpus, graph, codegen,
// MCP, and trigger drivers. A scaled worker must be able to mount immutable
// workflow artifacts read-only and connect with a DML-only database role.
func openWorkerDeps(ctx context.Context, log *slog.Logger, cfg *serveConfig) (*serveDeps, error) {
	if cfg == nil || !cfg.distributed() {
		return nil, fmt.Errorf("worker: distributed configuration is required")
	}
	if err := validatePrivateStateRoot(cfg.root); err != nil {
		return nil, fmt.Errorf("worker: state root: %w", err)
	}
	artifactRoot := cfg.executionArtifactRoot()
	if cfg.workerArtifactRoot != "" {
		if err := validateWorkerArtifactRoot(artifactRoot); err != nil {
			return nil, fmt.Errorf("worker: artifact root: %w", err)
		}
	}
	db, engine, err := migrate.Open(cfg.dbURL)
	if err != nil {
		return nil, fmt.Errorf("worker: open db: %w", err)
	}
	if engine != migrate.EnginePostgres {
		db.Close()
		return nil, fmt.Errorf("worker: distributed execution requires PostgreSQL")
	}
	if err := migrate.CheckCurrent(ctx, db, engine); err != nil {
		db.Close()
		return nil, fmt.Errorf("worker: schema: %w", err)
	}
	j := journal.New(db, journal.EnginePostgres)
	if err := j.EnablePayloadEncryption(ctx, cfg.masterKey, cfg.previousMasterKey); err != nil {
		db.Close()
		return nil, fmt.Errorf("worker: journal payload key: %w", err)
	}
	credRepo := credentials.New(db, credentials.EnginePostgres)
	vaultStore, err := vault.NewStore(vault.NewSQLBackend(db, vault.SQLEnginePostgres), cfg.masterKey, cfg.previousMasterKey)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("worker: vault: %w", err)
	}
	oauthStore := oauth.New(db, oauth.EnginePostgres, cfg.masterKey)
	oauthStore.ProfileFor = func(id string) oauth.Profile {
		if svc, ok := catalog.ByID(id); ok {
			return oauth.Profile{TokenAuthStyle: svc.TokenAuthStyle, AuthParams: svc.AuthParams}
		}
		return oauth.Profile{}
	}
	reg := registry.New(filepath.Join(artifactRoot, "workflows"))
	logBuffer := runlogs.New(1000, 10*time.Minute)
	logBuffer.OnClose = func(runID string, lines []string) {
		if err := j.SaveRunLogs(context.Background(), runID, lines); err != nil {
			log.Warn("worker: persist run logs failed", "run_id", runID, "err", err)
		}
	}
	metrics := server.NewMetrics()
	notif := buildNotifier(log, cfg, j, credRepo, vaultStore)
	cancels := cancelreg.New()
	// The runner itself belongs to the serving daemon. If an active command
	// chain exists, keep its durable terminal effect pending for that daemon's
	// recovery loop rather than acknowledging an unavailable handoff.
	commandChains := &commandChainDispatcher{Journal: j, TenantID: cfg.mcpTenant, Log: log}
	var pmGen = buildPostMortemGenerator(log, j, nil)
	if pmGen != nil {
		// Opted-in AI post-mortems still need a writable shared knowledge root.
		// Ordinary execution never creates or seeds it on a worker.
		knowStore, err := knowledge.New(filepath.Join(cfg.root, "knowledge"))
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("worker: opted-in post-mortem knowledge root: %w", err)
		}
		pmGen.Knowledge = knowStore
	}
	disp := buildDispatcher(log, cfg, j, vaultStore, reg, metrics, logBuffer, pmGen, notif,
		func() commandChainFire { return commandChains })
	disp.Cancels = cancels
	disp.Enqueue = true
	disp.Sup.OAuthTokens = oauthStore
	return &serveDeps{
		db: db, journal: j, credRepo: credRepo, vaultStore: vaultStore,
		oauthStore: oauthStore, registry: reg, pmGen: pmGen,
		logBuffer: logBuffer, metrics: metrics, dispatcher: disp,
		cancels: cancels, notifier: notif, commandChains: commandChains,
	}, nil
}

// validateWorkerArtifactRoot never creates the path: a missing shared mount
// must stop the worker before it registers a heartbeat or claims queue rows.
func validateWorkerArtifactRoot(root string) error {
	if !validAbsoluteMountPath(root) {
		return fmt.Errorf("REACTOR_WORKER_ARTIFACT_ROOT must be a clean absolute path")
	}
	for _, path := range []string{root, filepath.Join(root, "workflows")} {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%s must be a real directory", path)
		}
	}
	return nil
}
