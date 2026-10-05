package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runlogs"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/server"
)

func TestKubernetesServeRejectsMissingWorkerArtifactMountBeforeDatabaseWork(t *testing.T) {
	privateRoot := t.TempDir()
	if err := os.Chmod(privateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &serveConfig{
		root: privateRoot, queueArtifactRoot: filepath.Join(t.TempDir(), "missing-mount"),
		dbURL: "sqlite://" + filepath.Join(t.TempDir(), "must-not-create.db"),
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := openServeDeps(context.Background(), log, cfg); err == nil || !strings.Contains(err.Error(), "serve: worker artifact root") {
		t.Fatalf("missing worker artifact mount was accepted: %v", err)
	}
}

func TestKubernetesWorkerArtifactGateRejectsQueueUntilExactTreeIsPublished(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "reactor.db")
	if err := migrate.Up(ctx, log, dbURL); err != nil {
		t.Fatal(err)
	}
	db, _, err := migrate.Open(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j := journal.New(db, journal.EngineSQLite)
	localRoot, workerRoot := t.TempDir(), t.TempDir()
	reg := registry.New(filepath.Join(localRoot, "workflows"))
	compiled := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(compiled, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	const slug = "kubernetes-artifact-gate"
	artifact, err := reg.PublishArtifact(slug, compiled)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.ClaimTenant(slug, journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	mainSource := []byte(mcpAcceptanceWorkflowSource(slug))
	dag := []byte(mcpAcceptanceDAG)
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"main.go": mainSource, "dag.json": dag}
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
	codeDigest := sha256.Sum256(mainSource)
	manifestDigest := sha256.Sum256(manifest)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_kubernetes_artifact_gate", slug,
		hex.EncodeToString(codeDigest[:])[:16], "0.1.0", artifact.Digest, json.RawMessage(dag),
		journal.DefaultTenant, hex.EncodeToString(manifestDigest[:])); err != nil {
		t.Fatal(err)
	}
	cfg := &serveConfig{root: localRoot, queueArtifactRoot: workerRoot, mode: "distributed"}
	disp := buildDispatcher(log, cfg, j, nil, reg, server.NewMetrics(), runlogs.New(1000, time.Minute), nil, nil)
	disp.Enqueue = true
	trigger := journal.Trigger{WorkflowID: "wf_kubernetes_artifact_gate", Kind: journal.TriggerManual}
	if runID, err := disp.DispatchManual(ctx, trigger, []byte(`{}`)); runID != "" || err == nil || !strings.Contains(err.Error(), "worker artifact is unavailable for queue admission") {
		t.Fatalf("dispatch without worker artifact = run %q, err %v", runID, err)
	}
	if queued, err := j.CountQueued(ctx); err != nil || queued != 0 {
		t.Fatalf("missing worker artifact queued %d runs: %v", queued, err)
	}
	copyWorkerArtifactTree(t, filepath.Join(localRoot, "workflows"), filepath.Join(workerRoot, "workflows"))
	if runID, err := disp.DispatchManual(ctx, trigger, []byte(`{}`)); err != nil || runID == "" {
		t.Fatalf("dispatch after exact worker artifact publication = run %q, err %v", runID, err)
	}
	if queued, err := j.CountQueued(ctx); err != nil || queued != 1 {
		t.Fatalf("published worker artifact queued %d runs: %v", queued, err)
	}
}
