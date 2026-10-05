package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/autoscale"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/go-chi/chi/v5"
)

var workerArtifactConfigTestKey = reactorTestMasterKey

func workerArtifactServeArgs(t *testing.T, more ...string) []string {
	t.Helper()
	privateRoot := t.TempDir()
	if err := os.Chmod(privateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	args := []string{"--db", "postgres://reactor@127.0.0.1/reactor", "--root", privateRoot,
		"--master-key", workerArtifactConfigTestKey, "--mode", "distributed"}
	return append(args, more...)
}

func TestDistributedServeWorkerArtifactRootIndependentOfAutoscaler(t *testing.T) {
	for _, tc := range []struct {
		name      string
		spawner   string
		autoscale bool
	}{
		{name: "manual"},
		{name: "process", spawner: "process", autoscale: true},
		{name: "docker", spawner: "docker", autoscale: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("REACTOR_WORKER_ARTIFACT_ROOT", "")
			t.Setenv("REACTOR_AUTOSCALE_SPAWNER", tc.spawner)
			t.Setenv("REACTOR_WORKER_IMAGE", "reactor:test")
			t.Setenv("REACTOR_WORKER_CONCURRENCY", "2")
			t.Setenv("REACTOR_AUTOSCALE_FLEET_ID", "reactor-artifact-test")
			artifactRoot := filepath.Join(t.TempDir(), "artifacts")
			args := workerArtifactServeArgs(t, "--worker-artifact-root", artifactRoot)
			if tc.autoscale {
				args = append(args, "--autoscale")
			}
			cfg, err := parseServeFlags(args)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.queueArtifactRoot != artifactRoot {
				t.Fatalf("daemon worker artifact root = %q, want %q", cfg.queueArtifactRoot, artifactRoot)
			}
			if !tc.autoscale {
				return
			}
			spawner, err := buildSpawner(slog.Default(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			var argv []string
			switch sp := spawner.(type) {
			case *autoscale.ProcessSpawner:
				argv = sp.Args
			case *autoscale.CommandSpawner:
				argv = sp.SpawnArgv
			default:
				t.Fatalf("unexpected spawner %T", spawner)
			}
			if !containsAdjacentArgv(argv, "--artifact-root", artifactRoot) {
				t.Fatalf("managed worker lacks exact artifact path: %v", argv)
			}
		})
	}
}

func TestDistributedServeWorkerArtifactRootUsesEnvironmentAndRejectsBadPaths(t *testing.T) {
	root := filepath.Join(t.TempDir(), "artifacts")
	t.Setenv("REACTOR_WORKER_ARTIFACT_ROOT", root)
	cfg, err := parseServeFlags(workerArtifactServeArgs(t))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.queueArtifactRoot != root {
		t.Fatalf("environment worker artifact root = %q; want %q", cfg.queueArtifactRoot, root)
	}
	for _, bad := range []string{"relative-artifacts", root + string(os.PathSeparator) + "..", "/mnt/artifacts\ninjected"} {
		if _, err := parseServeFlags(workerArtifactServeArgs(t, "--worker-artifact-root", bad)); err == nil || !strings.Contains(err.Error(), "clean absolute path") {
			t.Fatalf("bad artifact root %q accepted: %v", bad, err)
		}
	}
}

func TestDistributedServeKeepsUnconfiguredSameTreeCompatibility(t *testing.T) {
	t.Setenv("REACTOR_WORKER_ARTIFACT_ROOT", "")
	args := workerArtifactServeArgs(t)
	cfg, err := parseServeFlags(args)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.queueArtifactRoot != "" {
		t.Fatalf("unconfigured distributed serve = root %q; want legacy same-tree mode", cfg.queueArtifactRoot)
	}
	// An operator can also opt into an explicit proof when the worker and
	// authoring roots are the same durable tree.
	cfg, err = parseServeFlags(append(args, "--worker-artifact-root", cfg.root))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.queueArtifactRoot != cfg.root {
		t.Fatalf("explicit same-tree worker proof = root %q, want %q", cfg.queueArtifactRoot, cfg.root)
	}
}

func TestDistributedServeWorkerArtifactRootStartupAndWiring(t *testing.T) {
	t.Setenv("REACTOR_WORKER_ARTIFACT_ROOT", "")
	root := filepath.Join(t.TempDir(), "worker-artifacts")
	cfg, err := parseServeFlags(workerArtifactServeArgs(t, "--worker-artifact-root", root, "--insecure-no-auth"))
	if err != nil {
		t.Fatal(err)
	}
	// Root validation runs before any database migration or connection.
	cfg.dbURL = "sqlite://" + filepath.Join(t.TempDir(), "reactor.db")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := openServeDeps(context.Background(), log, cfg); err == nil || !strings.Contains(err.Error(), "serve: worker artifact root") {
		t.Fatalf("missing worker tree accepted at startup: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "workflows"), 0o700); err != nil {
		t.Fatal(err)
	}
	deps, err := openServeDeps(context.Background(), log, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer deps.db.Close()
	if deps.dispatcher.QueueArtifactCheck == nil || deps.scheduler.QueueArtifactCheck == nil ||
		deps.mcpSrv.WorkerArtifactRoot != root || buildHTTPServer(log, cfg, deps).WorkerArtifactRoot != root {
		t.Fatal("worker storage proof was not wired to dispatcher, scheduler, MCP, and dashboard")
	}

	const slug, workflowID = "manual-worker-artifact-gate", "wf_manual_worker_artifact_gate"
	binary := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(binary, []byte("compiled-workflow"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := deps.registry.PublishArtifact(slug, binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := deps.registry.ClaimTenant(slug, journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	source := []byte(mcpAcceptanceWorkflowSource(slug))
	dag := json.RawMessage(mcpAcceptanceDAG)
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"main.go": source, "dag.json": dag}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(sourceDir, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := registry.BuildSourceManifest(files, []string{"main.go"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, registry.SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	codeHash, manifestHash := sha256.Sum256(source), sha256.Sum256(manifest)
	if err := deps.journal.CreateWorkflowInTenantWithArtifactDisabled(context.Background(), workflowID, slug,
		hex.EncodeToString(codeHash[:])[:16], "0.1.0", artifact.Digest, dag,
		journal.DefaultTenant, hex.EncodeToString(manifestHash[:])); err != nil {
		t.Fatal(err)
	}
	srv := buildHTTPServer(log, cfg, deps)
	router := chi.NewRouter()
	srv.Mount(router)
	enable := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "http://localhost/workflows/"+slug+"/enable", nil)
		request.Header.Set("Origin", "http://localhost")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	if got := enable(); got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), "distributed worker storage") {
		t.Fatalf("enable without worker copy = %d %q", got.Code, got.Body.String())
	}
	if enabled, err := deps.journal.IsWorkflowEnabled(context.Background(), workflowID); err != nil || enabled {
		t.Fatalf("missing worker copy activated workflow: enabled=%t, err=%v", enabled, err)
	}
	// Simulate a previously enabled workflow: dispatch must still check worker
	// storage before creating a queued run, even if activation was bypassed.
	if err := deps.journal.SetWorkflowEnabled(context.Background(), workflowID, true); err != nil {
		t.Fatal(err)
	}
	trigger := journal.Trigger{WorkflowID: workflowID, Kind: journal.TriggerManual}
	if runID, err := deps.dispatcher.DispatchManual(context.Background(), trigger, []byte(`{}`)); runID != "" || err == nil || !strings.Contains(err.Error(), "worker artifact is unavailable for queue admission") {
		t.Fatalf("dispatch without worker copy = run %q, err %v", runID, err)
	}
	if queued, err := deps.journal.CountQueued(context.Background()); err != nil || queued != 0 {
		t.Fatalf("unpublished worker artifact queued %d runs: %v", queued, err)
	}
	copyWorkerArtifactTree(t, filepath.Join(cfg.root, "workflows"), filepath.Join(root, "workflows"))
	if got := enable(); got.Code != http.StatusSeeOther {
		t.Fatalf("enable with exact worker copy = %d %q", got.Code, got.Body.String())
	}
	if runID, err := deps.dispatcher.DispatchManual(context.Background(), trigger, []byte(`{}`)); err != nil || runID == "" {
		t.Fatalf("dispatch with exact worker copy = run %q, err %v", runID, err)
	}
	if queued, err := deps.journal.CountQueued(context.Background()); err != nil || queued != 1 {
		t.Fatalf("published worker artifact queued %d runs: %v", queued, err)
	}
}

func TestKubernetesWorkerArtifactRootFlagCannotDisagreeWithPVCMount(t *testing.T) {
	t.Setenv("REACTOR_AUTOSCALE_SPAWNER", "kubernetes")
	t.Setenv("REACTOR_WORKER_IMAGE", "reactor:test")
	t.Setenv("REACTOR_AUTOSCALE_K8S_DB_SECRET", "reactor-db")
	t.Setenv("REACTOR_AUTOSCALE_K8S_MASTER_KEY_SECRET", "reactor-key")
	t.Setenv("REACTOR_AUTOSCALE_K8S_ARTIFACT_PVC", "reactor-artifacts")
	t.Setenv("REACTOR_WORKER_ARTIFACT_ROOT", "/mnt/reactor-artifacts")
	t.Setenv("REACTOR_AUTOSCALE_FLEET_ID", "reactor-artifact-test")
	setKubernetesWorkerResources(t)
	_, err := parseServeFlags(workerArtifactServeArgs(t, "--autoscale", "--worker-artifact-root", "/mnt/different"))
	if err == nil || !strings.Contains(err.Error(), "must match REACTOR_WORKER_ARTIFACT_ROOT") {
		t.Fatalf("Kubernetes daemon/worker mount mismatch accepted: %v", err)
	}
}

func containsAdjacentArgv(args []string, key, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key && args[i+1] == value {
			return true
		}
	}
	return false
}
