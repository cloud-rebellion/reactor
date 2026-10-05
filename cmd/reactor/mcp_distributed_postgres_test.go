package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/go-chi/chi/v5"
)

// TestPostgresHTTPMCPDistributedWorkerLifecycle crosses the real HTTP MCP,
// journal, and separate worker boundaries with one workflow and one run. It
// uses an isolated schema in an explicitly named local test database, so it
// never runs against a shared or production queue by accident.
func TestPostgresHTTPMCPDistributedWorkerLifecycle(t *testing.T) {
	t.Setenv(aiPostmortemEnabledEnv, "")
	setMCPAcceptanceSDK(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dbURL, cleanup := isolatedMCPWorkerPostgresURL(t, ctx)
	defer cleanup()

	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	masterKey := bytes.Repeat([]byte{0x47}, 32)
	cfg := &serveConfig{
		dbURL: dbURL, root: root, masterKey: masterKey, mode: "distributed",
		mcpToken: "distributed-test-token", mcpTenant: "acme",
		mcpAuthoring: true, mcpDispatch: true,
	}
	serveDeps, err := openServeDeps(ctx, log, cfg)
	if err != nil {
		t.Fatalf("open PostgreSQL serve dependencies: %v", err)
	}
	defer serveDeps.db.Close()
	router := chi.NewRouter()
	buildHTTPServer(log, cfg, serveDeps).Mount(router)
	httpServer := startInMemoryHTTPServer(t, router)
	defer httpServer.Close()
	endpoint := httpServer.Endpoint() + "/mcp"
	client := httpServer.Client()
	const slug = "distributed-mcp-worker"
	dag := map[string]any{"steps": []any{map[string]any{"name": "record", "kind": "step"}}}
	created := httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_create_workflow", map[string]any{
		"slug": slug, "main_go": mcpAcceptanceWorkflowSource(slug), "dag": dag,
	})
	if created.IsError {
		t.Fatalf("HTTP MCP create: %+v", created)
	}
	var createReceipt struct {
		WorkflowID string `json:"id"`
		Version    int    `json:"version"`
		Artifact   string `json:"artifact_sha256"`
	}
	if err := json.Unmarshal([]byte(created.Text), &createReceipt); err != nil || createReceipt.WorkflowID == "" || createReceipt.Version != 1 || createReceipt.Artifact == "" {
		t.Fatalf("incomplete create receipt: %s, %v", created.Text, err)
	}
	reviewed := httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_review_workflow", map[string]any{"slug": slug})
	if reviewed.IsError || !strings.Contains(reviewed.Text, `"artifact_status":"verified"`) {
		t.Fatalf("HTTP MCP review: %+v", reviewed)
	}
	enabled := httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_set_workflow_state", map[string]any{
		"slug": slug, "state": "enabled", "expected_state": "disabled", "expected_version": createReceipt.Version,
	})
	if enabled.IsError || !strings.Contains(enabled.Text, `"enabled":true`) {
		t.Fatalf("HTTP MCP enable: %+v", enabled)
	}
	dispatched := httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_dispatch_workflow", map[string]any{
		"slug": slug, "payload": map[string]any{"test": "distributed"}, "idempotency_key": "distributed-test-once",
	})
	if dispatched.IsError {
		t.Fatalf("HTTP MCP dispatch: %+v", dispatched)
	}
	var dispatchReceipt struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal([]byte(dispatched.Text), &dispatchReceipt); err != nil || dispatchReceipt.RunID == "" {
		t.Fatalf("incomplete dispatch receipt: %s, %v", dispatched.Text, err)
	}
	queued, err := serveDeps.journal.GetRun(ctx, dispatchReceipt.RunID)
	if err != nil || queued.Status != "queued" || queued.WorkflowArtifactSHA256 != createReceipt.Artifact {
		t.Fatalf("MCP dispatch did not queue exact artifact: run=%+v err=%v", queued, err)
	}

	// A worker keeps its private state root separate from the read-only mounted
	// artifact tree. Both binary lookup and source proof must use the mount.
	workerRoot := t.TempDir()
	workerArtifactRoot := t.TempDir()
	copyWorkerArtifactTree(t, filepath.Join(root, "workflows"), filepath.Join(workerArtifactRoot, "workflows"))
	if err := os.Chmod(workerArtifactRoot, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(workerArtifactRoot, 0o700) })
	if err := os.Chmod(workerRoot, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(workerRoot, 0o700) })
	workerCfg := &serveConfig{dbURL: dbURL, root: workerRoot, workerArtifactRoot: workerArtifactRoot, masterKey: masterKey, mode: "distributed"}
	workerDeps, err := openWorkerDeps(ctx, log, workerCfg)
	if err != nil {
		t.Fatalf("open separate worker dependencies: %v", err)
	}
	defer workerDeps.db.Close()
	if workerDeps.mcpSrv != nil || workerDeps.knowStore != nil {
		t.Fatal("worker initialized authoring or knowledge services")
	}
	if _, err := os.Stat(filepath.Join(workerRoot, "knowledge")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("worker wrote a knowledge directory under read-only root: %v", err)
	}
	workerCtx, stopWorker := context.WithCancel(ctx)
	workerDone := make(chan error, 1)
	go func() {
		workerDone <- runWorkerLoop(workerCtx, log, workerDeps, workerOpts{
			concurrency: 1, leaseTTL: 30 * time.Second,
			pollInterval: 25 * time.Millisecond, drainTimeout: 5 * time.Second,
		})
	}()
	workerStopped := false
	defer func() {
		stopWorker()
		if !workerStopped {
			select {
			case err := <-workerDone:
				if err != nil && !errors.Is(err, context.Canceled) {
					t.Errorf("worker shutdown: %v", err)
				}
			case <-time.After(7 * time.Second):
				t.Error("worker did not stop after cancellation")
			}
		}
	}()

	deadline := time.Now().Add(20 * time.Second)
	for {
		run, err := serveDeps.journal.GetRun(ctx, dispatchReceipt.RunID)
		if err != nil {
			t.Fatalf("read distributed run: %v", err)
		}
		if run.Status == "succeeded" {
			if run.TenantID != "acme" || run.WorkflowVersion != createReceipt.Version || run.WorkflowArtifactSHA256 != createReceipt.Artifact {
				t.Fatalf("worker changed run identity: %+v", run)
			}
			break
		}
		if run.Status == "failed" || run.Status == "failed_dlq" || time.Now().After(deadline) {
			t.Fatalf("separate worker did not finish queued run: %+v", run)
		}
		select {
		case err := <-workerDone:
			workerStopped = true
			t.Fatalf("worker exited before terminal run: %v", err)
		case <-time.After(25 * time.Millisecond):
		}
	}
	steps, err := serveDeps.journal.ListSteps(ctx, dispatchReceipt.RunID)
	if err != nil || len(steps) != 1 || steps[0].Status != "succeeded" {
		t.Fatalf("distributed worker Step receipts = %+v, err=%v", steps, err)
	}
	stopWorker()
	select {
	case err := <-workerDone:
		workerStopped = true
		if err != nil {
			t.Fatalf("worker graceful shutdown: %v", err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("worker did not drain after completed run")
	}
}

func copyWorkerArtifactTree(t *testing.T, source, dest string) {
	t.Helper()
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular workflow artifact entry %q", rel)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
	if err != nil {
		t.Fatalf("copy exact workflow artifact set to worker root: %v", err)
	}
}

func isolatedMCPWorkerPostgresURL(t *testing.T, ctx context.Context) (string, func()) {
	t.Helper()
	raw := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if raw == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL to a dedicated loopback PostgreSQL test database")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") ||
		(u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") ||
		!strings.Contains(strings.ToLower(strings.Trim(u.Path, "/")), "test") {
		t.Fatal("REACTOR_TEST_POSTGRES_URL must name a loopback PostgreSQL database containing test")
	}
	base, engine, err := migrate.Open(raw)
	if err != nil || engine != migrate.EnginePostgres {
		t.Fatalf("open test PostgreSQL: %v", err)
	}
	schema := fmt.Sprintf("mcp_worker_%d", time.Now().UnixNano())
	if _, err := base.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		base.Close()
		t.Fatalf("create isolated PostgreSQL schema: %v", err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	cleanup := func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := base.ExecContext(cleanCtx, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Errorf("drop isolated PostgreSQL schema: %v", err)
		}
		base.Close()
	}
	return u.String(), cleanup
}
