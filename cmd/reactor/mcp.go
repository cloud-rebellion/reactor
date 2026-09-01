package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/bright-interaction/reactor/internal/codegen"
	"github.com/bright-interaction/reactor/internal/graph"
	"github.com/bright-interaction/reactor/internal/knowledge"
	"github.com/bright-interaction/reactor/internal/mcp"
	"github.com/bright-interaction/reactor/internal/postmortem"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/supervisor"
)

// cmdMCP dispatches the mcp subcommand group.
//
//	reactor mcp stdio    [--db <url>] [--allow-write]
//	reactor mcp install  --client <name> [--allow-write] [--apply]
//
// Stdio mode reads JSON-RPC 2.0 requests from stdin and writes
// responses to stdout, line-delimited. Suitable as a Claude / Codex /
// Continue.dev tool source. --allow-write registers the
// dispatch_workflow + knowledge-write + post-mortem tools.
//
// Install prints (or, with --apply, writes) the JSON snippet the named
// MCP client expects for reactor. Targets every common client out of
// the box so external users get a one-liner from `docker run` to a
// connected AI client.
func cmdMCP(ctx context.Context, log *slog.Logger, args []string) error {
	if len(args) == 0 {
		return errors.New("mcp: missing subcommand (stdio | install)")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "stdio":
		return cmdMCPStdio(ctx, log, rest)
	case "install":
		return cmdMCPInstall(rest)
	default:
		return fmt.Errorf("mcp: unknown subcommand %q (want stdio | install)", sub)
	}
}

func cmdMCPStdio(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("mcp stdio", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL")
	root := fs.String("root", defaultRoot(), "Reactor state directory (workflows/ + master.key); required when --allow-write is set")
	masterKeyFile := fs.String("master-key-file", "", "path to a 64-hex-char master key (default <root>/master.key); required for synchronous SQLite --allow-write dispatch")
	masterKeyHex := fs.String("master-key", envFirst("REACTOR_MASTER_KEY", "ARACHNE_MASTER_KEY"), "32-byte hex master key (overrides --master-key-file); required for synchronous SQLite --allow-write dispatch")
	allowWrite := fs.Bool("allow-write", false, "register write tools (dispatch_workflow). Default off.")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if *dbURL == "" {
		return errors.New("mcp stdio: missing --db (or $REACTOR_DB_URL)")
	}

	j, jClose, err := openJournal(*dbURL)
	if err != nil {
		return err
	}
	defer jClose()
	credRepo, cClose, err := openCredentials(*dbURL)
	if err != nil {
		return err
	}
	defer cClose()

	// Knowledge corpus + runtime graph. Both work in read-only mode
	// without --allow-write so an external AI client can call
	// reactor_search_knowledge and reactor_query_graph immediately
	// after install. Write tools (add/revise/postmortem) only register
	// when --allow-write is passed; that gate matches the existing
	// Dispatch != nil convention.
	var kStore *knowledge.Store
	var gGraph *graph.Graph
	if *root != "" {
		ks, err := knowledge.New(filepath.Join(*root, "knowledge"))
		if err != nil {
			log.Warn("mcp: knowledge unavailable", "err", err)
		} else {
			ks.Git = &codegen.GitCommitter{}
			kStore = ks
		}
	}
	builder := &graph.Builder{Journal: j, Credentials: credRepo, Knowledge: kStore}
	if g, err := builder.Build(ctx); err == nil {
		gGraph = g
	} else {
		log.Warn("mcp: graph build failed", "err", err)
	}

	srv := &mcp.Server{
		Info: mcp.ServerInfo{
			Name:    "reactor",
			Version: Version,
		},
		Journal:     j,
		Credentials: credRepo,
		Knowledge:   kStore,
		Graph:       gGraph,
		Log:         log,
		// State root enables the reactor_create_workflow authoring tool under
		// --allow-write so an MCP client builds workflows without shelling out
		// to the CLI. Only active alongside the write surface (Dispatch).
		StateRoot: *root,
	}

	// Wire reactor_record_postmortem only with explicit diagnostic-egress
	// opt-in, an Anthropic API key, and a knowledge corpus. Possessing the key
	// alone is not consent to send run diagnostics to an external model.
	if aiPostmortemEnabled() && kStore != nil {
		if anth, anthErr := codegen.NewAnthropicFromEnv(); anthErr == nil {
			pmGen := &postmortem.Generator{
				Anthropic: anth,
				Journal:   j,
				Knowledge: kStore,
				Log:       log,
			}
			srv.PostMortem = pmGen.Generate
		}
	}
	if *allowWrite {
		if *root == "" {
			return errors.New("mcp stdio: --root required when --allow-write is set")
		}
		reg := registry.New(filepath.Join(*root, "workflows"))
		if mcpDispatchUsesWorkerQueue(j.Engine()) {
			// PostgreSQL is Reactor's distributed topology. MCP must enqueue an
			// artifact-pinned run for the normal leased worker instead of creating
			// an unleased running row owned by this one-shot stdio process. A client
			// disconnect or MCP crash therefore cannot strand the run in "running".
			srv.Dispatch = func(ctx context.Context, slug string, payload json.RawMessage) (string, error) {
				wfID, runID, meta, err := prepareMCPDispatch(ctx, j, slug, payload)
				if err != nil {
					return "", err
				}
				if _, err := createMCPPinnedRun(ctx, j, reg, runID, wfID, slug, meta, true); err != nil {
					return "", fmt.Errorf("dispatch_workflow: immutable workflow artifact unavailable: %w", err)
				}
				return runID, nil
			}
		} else {
			// SQLite is the explicit single-process development topology. Keep the
			// synchronous behavior so a one-shot MCP request cannot exit while its
			// local subprocess is still running.
			masterHex, err := loadMasterKey(*masterKeyHex, *masterKeyFile, *root)
			if err != nil {
				return err
			}
			store, vaultCloser, err := openVaultStore(*dbURL, masterHex)
			if err != nil {
				return err
			}
			defer vaultCloser()
			srv.Dispatch = func(ctx context.Context, slug string, payload json.RawMessage) (string, error) {
				wfID, runID, meta, err := prepareMCPDispatch(ctx, j, slug, payload)
				if err != nil {
					return "", err
				}
				binary, err := createMCPPinnedRun(ctx, j, reg, runID, wfID, slug, meta, false)
				if err != nil {
					return "", fmt.Errorf("dispatch_workflow: immutable workflow artifact unavailable: %w", err)
				}
				signKey, _ := decodeMasterKey(masterHex)
				sup := supervisor.Supervisor{
					BinaryPath: binary, WorkflowSlug: slug, RunID: runID, Mode: "live",
					Journal: j, Vault: store, Log: log, Input: meta, SignalSigningKey: signKey,
				}
				status, err := func() (s string, e error) {
					defer func() {
						if r := recover(); r != nil {
							e = fmt.Errorf("panic in run %s: %v", runID, r)
						}
					}()
					return sup.Run(ctx)
				}()
				if err != nil {
					return runID, fmt.Errorf("dispatch_workflow: run %s status=%s err=%w", runID, status, err)
				}
				if ctx.Err() != nil {
					return runID, fmt.Errorf("dispatch_workflow: run %s status=%s err=%w", runID, status, ctx.Err())
				}
				return runID, nil
			}
		}
	}

	log.Info("mcp: stdio listener starting", "db", redactDB(*dbURL), "allow_write", *allowWrite)
	return srv.Serve(ctx, os.Stdin, os.Stdout)
}

func mcpDispatchUsesWorkerQueue(engine journal.Engine) bool {
	return engine == journal.EnginePostgres
}

func prepareMCPDispatch(ctx context.Context, j *journal.Journal, slug string, payload json.RawMessage) (workflowID, runID string, meta json.RawMessage, err error) {
	wfID, err := defaultTenantWorkflowID(ctx, j, slug)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			return "", "", nil, fmt.Errorf("dispatch_workflow: unknown slug %q", slug)
		}
		return "", "", nil, err
	}
	if enabled, enabledErr := j.IsWorkflowEnabled(ctx, wfID); enabledErr == nil && !enabled {
		return "", "", nil, fmt.Errorf("dispatch_workflow: workflow %q is disabled; enable it before running", slug)
	}
	if quotaErr := j.CheckWorkflowEnqueueAllowed(ctx, wfID); quotaErr != nil {
		var quota *journal.QuotaError
		if errors.As(quotaErr, &quota) {
			return "", "", nil, quotaErr
		}
		// Match Dispatcher: infrastructure failures in an admission check fail
		// open, while an authoritative quota response refuses the run.
	}
	if allowed, limit, rateErr := j.CheckWorkflowRateLimit(ctx, wfID); rateErr == nil && !allowed {
		return "", "", nil, fmt.Errorf("dispatch_workflow: workflow %q rate limit reached (%d run(s)/minute)", slug, limit)
	}
	runID, err = newMCPRunID()
	if err != nil {
		return "", "", nil, err
	}
	meta = payload
	if len(meta) == 0 {
		meta = json.RawMessage(`{}`)
	}
	return wfID, runID, meta, nil
}

// createMCPPinnedRun gives the MCP allow-write path the same execution fence as
// dispatcher.Dispatch: resolve and verify the current immutable artifact, then
// write the run and both pins in one INSERT. Distributed PostgreSQL deployments
// create a queued run for normal lease ownership; SQLite development runs use
// the explicit synchronous running state. No row is created on fence failure.
func createMCPPinnedRun(ctx context.Context, j *journal.Journal, reg *registry.FileRegistry, runID, workflowID, slug string, meta json.RawMessage, queued bool) (string, error) {
	v, err := j.CurrentWorkflowVersionRecord(ctx, workflowID)
	if err != nil {
		return "", err
	}
	probe := journal.RunInfo{
		WorkflowID: workflowID, WorkflowVersion: v.Version, WorkflowArtifactSHA256: v.ArtifactSHA256,
	}
	if _, err := j.ValidateRunWorkflowArtifact(ctx, probe); err != nil {
		return "", err
	}
	binary, err := reg.ArtifactPath(slug, v.ArtifactSHA256)
	if err != nil {
		return "", fmt.Errorf("%w: immutable artifact failed verification", journal.ErrWorkflowArtifactFence)
	}
	if queued {
		err = j.CreateQueuedRunPinned(ctx, runID, workflowID, "manual", meta, v.Version, v.ArtifactSHA256)
	} else {
		err = j.CreateRunPinned(ctx, runID, workflowID, "manual", meta, v.Version, v.ArtifactSHA256)
	}
	if err != nil {
		return "", err
	}
	return binary, nil
}

// newMCPRunID returns a "run_" + 16 hex chars id, mirroring the
// dispatcher's format. Stays inline so MCP doesn't need an exported
// helper from the dispatcher package.
func newMCPRunID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	hexChars := "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexChars[c>>4]
		out[i*2+1] = hexChars[c&0x0f]
	}
	return "run_" + string(out), nil
}
