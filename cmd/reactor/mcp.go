package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bright-interaction/reactor/internal/codegen"
	"github.com/bright-interaction/reactor/internal/dispatcher"
	"github.com/bright-interaction/reactor/internal/graph"
	"github.com/bright-interaction/reactor/internal/knowledge"
	"github.com/bright-interaction/reactor/internal/mcp"
	"github.com/bright-interaction/reactor/internal/postmortem"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/supervisor"
	"github.com/bright-interaction/reactor/internal/workflowproof"
)

const maxMCPPinnedDAGBytes = 256 << 10

// cmdMCP dispatches the mcp subcommand group. HTTP is the canonical transport:
// the long-running `reactor serve` daemon mounts Streamable HTTP at /mcp, and
// `reactor mcp install` registers that URL with an MCP client.
//
// `reactor mcp stdio` remains an explicit compatibility path for older local
// clients. New installations must use the HTTP endpoint so all clients share
// one authenticated daemon, dispatcher, vault, and rate-limit boundary.
//
// Install prints (or, with --apply, writes) the JSON snippet the named
// MCP client expects for reactor. Targets every common client out of
// the box so external users get a one-liner from `docker run` to a
// connected AI client.
func cmdMCP(ctx context.Context, log *slog.Logger, args []string) error {
	if len(args) == 0 {
		return errors.New("mcp: HTTP is served by `reactor serve`; use `mcp install --client <name>` or `mcp check --url <endpoint>` (stdio is legacy and explicit)")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "stdio":
		return cmdMCPStdio(ctx, log, rest)
	case "install":
		return cmdMCPInstall(rest)
	case "check":
		return cmdMCPCheck(ctx, rest)
	default:
		return fmt.Errorf("mcp: unknown subcommand %q (want install, check; stdio is legacy and explicit)", sub)
	}
}

type mcpCheckResult struct {
	Protocol string
	Name     string
	Version  string
}

// cmdMCPCheck performs one read-only initialize handshake against the HTTP
// endpoint. It deliberately reports status and server identity only; response
// bodies from an auth proxy or upstream are never echoed to the terminal.
func cmdMCPCheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mcp check", flag.ContinueOnError)
	endpoint := fs.String("url", envFirstOr("http://127.0.0.1:7777/mcp", "REACTOR_MCP_URL"), "daemon MCP HTTP endpoint")
	token := fs.String("token", "", "legacy bearer value; prefer --token-env so it stays out of process arguments")
	tokenEnv := fs.String("token-env", "REACTOR_MCP_TOKEN", "environment variable containing the bearer token")
	timeout := fs.Duration("timeout", 10*time.Second, "maximum time for the initialize handshake")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if *timeout <= 0 || *timeout > 2*time.Minute {
		return errors.New("mcp check: --timeout must be between 1s and 2m")
	}
	if err := validateMCPEndpoint(*endpoint); err != nil {
		return err
	}
	bearer, err := mcpCheckBearer(*token, *tokenEnv)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: *timeout}
	result, err := checkMCP(ctx, *endpoint, bearer, client)
	if err != nil {
		return err
	}
	fmt.Printf("MCP check passed: %s (%s, protocol %s)\n", result.Name, result.Version, result.Protocol)
	return nil
}

func mcpCheckBearer(explicit, tokenEnv string) (string, error) {
	if !validEnvName(tokenEnv) {
		return "", errors.New("mcp check: --token-env must be a valid environment variable name")
	}
	if explicit != "" {
		return explicit, nil
	}
	return os.Getenv(tokenEnv), nil
}

func checkMCP(ctx context.Context, endpoint, token string, client *http.Client) (mcpCheckResult, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	// This is an exact endpoint probe carrying an MCP bearer. A redirect can
	// validate a different service and Go may forward Authorization to a
	// same-host or subdomain target. Copy the caller's transport/timeouts, but
	// never follow a redirect or mutate a shared client used elsewhere.
	exactClient := *client
	exactClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": mcp.ProtocolVersion,
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "reactor-mcp-check", "version": Version},
		},
	})
	if err != nil {
		return mcpCheckResult{}, errors.New("mcp check: could not build initialize request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return mcpCheckResult{}, errors.New("mcp check: invalid endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	// Match the transport marker emitted by an MCP client after initialize.
	// The daemon accepts an omitted header for backwards compatibility, but the
	// connection probe should exercise the same explicit version contract as
	// Stage/Mesh-style HTTP registrations so a proxy or gateway cannot report a
	// false-positive compatibility check.
	req.Header.Set(mcp.MCPProtocolVersionHeader, mcp.ProtocolVersion)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := exactClient.Do(req)
	if err != nil {
		return mcpCheckResult{}, fmt.Errorf("mcp check: request failed: %w", err)
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, 256<<10)
	raw, readErr := io.ReadAll(limited)
	if readErr != nil {
		return mcpCheckResult{}, errors.New("mcp check: response could not be read")
	}
	if resp.StatusCode != http.StatusOK {
		return mcpCheckResult{}, fmt.Errorf("mcp check: endpoint returned HTTP %d", resp.StatusCode)
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  struct {
			Protocol string `json:"protocolVersion"`
			Server   struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"serverInfo"`
		} `json:"result"`
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return mcpCheckResult{}, errors.New("mcp check: endpoint returned invalid JSON-RPC")
	}
	if envelope.Error != nil {
		return mcpCheckResult{}, fmt.Errorf("mcp check: initialize returned JSON-RPC error %d", envelope.Error.Code)
	}
	if envelope.JSONRPC != "2.0" || string(envelope.ID) != "1" {
		return mcpCheckResult{}, errors.New("mcp check: initialize response has an invalid JSON-RPC envelope")
	}
	if envelope.Result.Protocol == "" || envelope.Result.Server.Name == "" {
		return mcpCheckResult{}, errors.New("mcp check: initialize response omitted server identity")
	}
	if envelope.Result.Protocol != mcp.ProtocolVersion {
		return mcpCheckResult{}, fmt.Errorf("mcp check: incompatible protocol %q (want %q)", envelope.Result.Protocol, mcp.ProtocolVersion)
	}
	if envelope.Result.Server.Name != "reactor" {
		return mcpCheckResult{}, errors.New("mcp check: endpoint is not Reactor")
	}
	return mcpCheckResult{Protocol: envelope.Result.Protocol, Name: envelope.Result.Server.Name, Version: envelope.Result.Server.Version}, nil
}

func cmdMCPStdio(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("mcp stdio", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL")
	root := fs.String("root", defaultRoot(), "Reactor state directory (workflows/ + master.key); required when a write scope is set")
	masterKeyFile := fs.String("master-key-file", "", "path to a 64-hex-char master key (default <root>/master.key); required for synchronous SQLite dispatch")
	masterKeyHex := fs.String("master-key", envFirst("REACTOR_MASTER_KEY", "ARACHNE_MASTER_KEY"), "32-byte hex master key (overrides --master-key-file); required for synchronous SQLite dispatch")
	allowWrite := fs.Bool("allow-write", false, "legacy: enable all MCP write scopes (prefer the explicit --allow-authoring/--allow-dispatch/--allow-secrets flags)")
	allowAuthoring := fs.Bool("allow-authoring", false, "enable workflow validation and creation tools")
	allowTriggers := fs.Bool("allow-triggers", false, "enable trigger management tools")
	allowNotifications := fs.Bool("allow-notifications", false, "enable notification routing tools")
	allowDispatch := fs.Bool("allow-dispatch", false, "enable workflow dispatch and cancellation tools")
	allowSecrets := fs.Bool("allow-secrets", false, "enable vault grant/revoke tools")
	allowKnowledge := fs.Bool("allow-knowledge", false, "enable knowledge corpus write tools")
	allowDiagnostics := fs.Bool("allow-diagnostics", false, "enable AI post-mortem egress tools")
	allowDataExport := fs.Bool("allow-data-export", false, "enable exact run-input reads and bulk tenant export")
	allowDataLifecycle := fs.Bool("allow-data-lifecycle", false, "enable explicitly confirmed tenant run-history erasure")
	allowArtifactPublication := fs.Bool("allow-artifact-publication", false, "enable exact-version artifact publication requests to distributed workers")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if *dbURL == "" {
		return errors.New("mcp stdio: missing --db (or $REACTOR_DB_URL)")
	}
	runCtx, cancelMCP := context.WithCancel(ctx)
	defer cancelMCP()

	j, jClose, err := openJournal(*dbURL)
	if err != nil {
		return err
	}
	defer jClose()
	var journalMasterHex string
	var journalMasterKey []byte
	hasPayloadKey, err := j.HasPayloadKey(ctx)
	if err != nil {
		return err
	}
	if hasPayloadKey || *allowWrite || *allowDispatch {
		journalMasterHex, err = loadMasterKey(*masterKeyHex, *masterKeyFile, *root)
		if err != nil {
			return err
		}
		journalMasterKey, err = decodeMasterKey(journalMasterHex)
		if err != nil {
			return err
		}
		var previous []byte
		if prevHex := envFirst("REACTOR_MASTER_KEY_PREVIOUS", "ARACHNE_MASTER_KEY_PREVIOUS"); prevHex != "" {
			previous, err = decodeMasterKey(prevHex)
			if err != nil {
				return fmt.Errorf("REACTOR_MASTER_KEY_PREVIOUS: %w", err)
			}
		}
		if *allowWrite || *allowDispatch {
			err = j.EnablePayloadEncryption(ctx, journalMasterKey, previous)
		} else {
			err = j.LoadPayloadEncryption(ctx, journalMasterKey, previous)
		}
		if err != nil {
			return fmt.Errorf("mcp stdio: journal payload key: %w", err)
		}
	}
	credRepo, cClose, err := openCredentials(*dbURL)
	if err != nil {
		return err
	}
	defer cClose()

	// Knowledge corpus + runtime graph. Both work in read-only mode
	// without any write scope so an external AI client can call
	// reactor_search_knowledge and reactor_query_graph immediately
	// after install. Write tools (add/revise/postmortem) only register
	// when --allow-knowledge or --allow-diagnostics is passed; each capability
	// is independently scoped on the Server.
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
		// --allow-authoring so an MCP client builds workflows without shelling
		// out to the CLI.
		StateRoot: *root,
		// The explicit local compatibility command has no HTTP identity. Its
		// separate opt-in flag is the operator authorization for publication.
		ArtifactPublicationAuthorized: func(context.Context) bool { return *allowWrite || *allowArtifactPublication },
		Scopes: mcpStdioWriteScopes(
			*allowWrite,
			*allowAuthoring,
			*allowTriggers,
			*allowNotifications,
			*allowDispatch,
			*allowSecrets,
			*allowKnowledge,
			*allowDiagnostics,
			*allowDataExport,
			*allowDataLifecycle,
			*allowArtifactPublication,
		),
	}
	var graphRefreshMu sync.Mutex
	srv.GraphRefresh = func(refreshCtx context.Context) error {
		graphRefreshMu.Lock()
		defer graphRefreshMu.Unlock()
		next, err := builder.Build(refreshCtx)
		if err != nil {
			return err
		}
		if gGraph == nil {
			gGraph = next
			srv.Graph = gGraph
			return nil
		}
		gGraph.ReplaceFrom(next)
		return nil
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
			srv.PostMortem = func(pmCtx context.Context, runID string) (string, error) {
				return pmGen.GenerateForTenant(pmCtx, runID, srv.TenantID)
			}
		}
	}
	var mcpDispatcher *dispatcher.Dispatcher
	var closeMCPVault func()
	if *allowWrite || *allowDispatch {
		if *root == "" {
			return errors.New("mcp stdio: --root required when --allow-dispatch is set")
		}
		reg := registry.New(filepath.Join(*root, "workflows"))
		// SQLite is the explicit single-process development topology and needs
		// the vault for local execution. PostgreSQL queues through the same
		// dispatcher, so the leased worker owns execution after this process
		// returns.
		var vaultReader supervisor.VaultReader
		if !mcpDispatchUsesWorkerQueue(j.Engine()) {
			store, vaultCloser, err := openVaultStore(*dbURL, journalMasterHex)
			if err != nil {
				return err
			}
			vaultReader = store
			closeMCPVault = vaultCloser
		}
		mcpDispatcher = &dispatcher.Dispatcher{
			Journal:               j,
			Resolver:              &dispatcher.SQLResolver{Journal: j},
			ArtifactPath:          reg.ArtifactPath,
			ArtifactPathForTenant: reg.TenantArtifactPath,
			IntegrityCheck: func(ctx context.Context, slug string, version journal.WorkflowVersion) error {
				tenant, err := j.WorkflowTenant(ctx, version.WorkflowID)
				if err != nil {
					return fmt.Errorf("resolve workflow tenant for source proof: %w", err)
				}
				return workflowproof.ValidateVersionForTenant(*root, slug, tenant, version)
			},
			Log:           log,
			MaxConcurrent: envIntFirst("REACTOR_MAX_CONCURRENT_RUNS", "", 32),
			Enqueue:       mcpDispatchUsesWorkerQueue(j.Engine()),
			Sup: supervisor.Supervisor{
				Vault:            vaultReader,
				SignalSigningKey: journalMasterKey,
				Limits: supervisor.ResourceLimits{
					CgroupRoot:    os.Getenv("REACTOR_CGROUP_ROOT"),
					RequireCgroup: os.Getenv("REACTOR_REQUIRE_WORKFLOW_CGROUP") == "1",
				},
			},
		}
		srv.RetryDeadLetter = mcpDispatcher.RetryDeadLetter
		srv.TestDispatch = func(ctx context.Context, slug string, payload json.RawMessage) (string, error) {
			wfID, err := defaultTenantWorkflowID(ctx, j, slug)
			if err != nil {
				if errors.Is(err, journal.ErrNotFound) {
					return "", fmt.Errorf("test_workflow: unknown slug %q", slug)
				}
				return "", err
			}
			trg := journal.Trigger{WorkflowID: wfID, Kind: journal.TriggerManual, Config: json.RawMessage(`{}`), State: "active"}
			return mcpDispatcher.DispatchTest(ctx, trg, payload)
		}
		srv.Dispatch = func(ctx context.Context, slug string, payload json.RawMessage) (string, error) {
			wfID, err := defaultTenantWorkflowID(ctx, j, slug)
			if err != nil {
				if errors.Is(err, journal.ErrNotFound) {
					return "", fmt.Errorf("dispatch_workflow: unknown slug %q", slug)
				}
				return "", err
			}
			trg := journal.Trigger{
				WorkflowID: wfID,
				Kind:       journal.TriggerManual,
				Config:     json.RawMessage(`{}`),
				State:      "active",
			}
			return mcpDispatcher.DispatchManual(ctx, trg, payload)
		}
		srv.DispatchIdempotent = func(ctx context.Context, slug string, payload json.RawMessage, key string) (string, error) {
			wfID, err := defaultTenantWorkflowID(ctx, j, slug)
			if err != nil {
				if errors.Is(err, journal.ErrNotFound) {
					return "", fmt.Errorf("dispatch_workflow: unknown slug %q", slug)
				}
				return "", err
			}
			trg := journal.Trigger{WorkflowID: wfID, Kind: journal.TriggerManual, Config: json.RawMessage(`{}`), State: "active"}
			return mcpDispatcher.DispatchManualIdempotent(ctx, trg, payload, key)
		}
	}
	defer func() {
		if mcpDispatcher != nil {
			if err := mcpDispatcher.Drain(30 * time.Second); err != nil {
				// A one-shot stdio process must not close its DB or vault while a
				// local supervisor still owns a run. Cancel the run context and
				// give the supervisor one bounded finalization window.
				cancelMCP()
				if cancelErr := mcpDispatcher.Drain(5 * time.Second); cancelErr != nil {
					log.Warn("mcp: dispatcher drain timed out after cancellation", "err", cancelErr)
				}
			}
		}
		cancelMCP()
		if closeMCPVault != nil {
			closeMCPVault()
		}
	}()

	log.Info("mcp: stdio listener starting", "db", redactDB(*dbURL), "allow_write", *allowWrite)
	return srv.Serve(runCtx, os.Stdin, os.Stdout)
}

// mcpStdioWriteScopes keeps the explicit compatibility transport's capability
// contract aligned with the HTTP daemon. The legacy --allow-write switch is
// intentionally retained as an all-scopes compatibility alias, including
// exact data export, while each capability is opt-in for least-privilege clients.
func mcpStdioWriteScopes(allowWrite, authoring, triggers, notifications, dispatch, secrets, knowledge, diagnostics, dataExport, dataLifecycle bool, artifactPublication ...bool) *mcp.WriteScopes {
	publish := len(artifactPublication) > 0 && artifactPublication[0]
	return &mcp.WriteScopes{
		Authoring:           allowWrite || authoring,
		Triggers:            allowWrite || triggers,
		Notifications:       allowWrite || notifications,
		Dispatch:            allowWrite || dispatch,
		Secrets:             allowWrite || secrets,
		Knowledge:           allowWrite || knowledge,
		Diagnostics:         allowWrite || diagnostics,
		DataExport:          allowWrite || dataExport,
		DataLifecycle:       allowWrite || dataLifecycle,
		ArtifactPublication: allowWrite || publish,
	}
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
		// A policy lookup failure is not evidence of an unlimited tenant. Keep
		// the explicit stdio compatibility path aligned with the HTTP dispatcher's
		// fail-closed admission boundary.
		return "", "", nil, fmt.Errorf("dispatch_workflow: quota admission check failed: %w", quotaErr)
	}
	if allowed, limit, rateErr := j.CheckWorkflowRateLimit(ctx, wfID); rateErr != nil {
		return "", "", nil, fmt.Errorf("dispatch_workflow: rate-limit admission check failed: %w", rateErr)
	} else if !allowed {
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
	v, err := j.CurrentWorkflowVersionRecordBounded(ctx, workflowID, maxMCPPinnedDAGBytes)
	if err != nil {
		return "", err
	}
	if v.DAGTruncated {
		return "", fmt.Errorf("workflow version %d DAG is %d bytes and exceeds the bounded MCP dispatch projection", v.Version, v.DAGBytes)
	}
	probe := journal.RunInfo{
		WorkflowID: workflowID, WorkflowVersion: v.Version, WorkflowArtifactSHA256: v.ArtifactSHA256,
	}
	if _, err := j.ValidateRunWorkflowArtifact(ctx, probe); err != nil {
		return "", err
	}
	tenant, err := j.WorkflowTenant(ctx, workflowID)
	if err != nil {
		return "", fmt.Errorf("resolve workflow tenant: %w", err)
	}
	binary, err := reg.TenantArtifactPath(tenant, slug, v.ArtifactSHA256)
	if err != nil {
		return "", fmt.Errorf("%w: immutable artifact failed verification", journal.ErrWorkflowArtifactFence)
	}
	if queued {
		err = j.CreateQueuedRunPinnedIfEnabled(ctx, runID, workflowID, "manual", meta, v.Version, v.ArtifactSHA256)
	} else {
		err = j.CreateRunPinnedIfEnabled(ctx, runID, workflowID, "manual", meta, v.Version, v.ArtifactSHA256)
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
