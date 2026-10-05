package dispatcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/supervisor"
	"github.com/bright-interaction/reactor/internal/workflowproof"
)

func TestServeWiredIntegrityProofRejectsEmptyVisualDAGBeforeQueue(t *testing.T) {
	ctx := context.Background()
	j := newJournal(t)
	root := t.TempDir()
	reg := registry.New(filepath.Join(root, "workflows"))
	binary := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(binary, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("empty-dispatch-flow", binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.ClaimTenant("empty-dispatch-flow", journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mainGo := []byte("package main\nfunc main() {}\n")
	dag := []byte(`{}`)
	for name, contents := range map[string][]byte{"main.go": mainGo, "dag.json": dag} {
		if err := os.WriteFile(filepath.Join(sourceDir, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := registry.BuildSourceManifest(map[string][]byte{"main.go": mainGo, "dag.json": dag})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, registry.SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mainGo)
	codeHash := hex.EncodeToString(sum[:])[:16]
	manifestSum := sha256.Sum256(manifest)
	manifestHash := hex.EncodeToString(manifestSum[:])
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_empty_dispatch_flow", "empty-dispatch-flow", codeHash, "0.1.0", artifact.Digest, json.RawMessage(dag), journal.DefaultTenant, manifestHash); err != nil {
		t.Fatal(err)
	}
	checks := 0
	d := &Dispatcher{
		Journal: j, Resolver: &SQLResolver{Journal: j}, ArtifactPathForTenant: reg.TenantArtifactPath,
		IntegrityCheck: func(ctx context.Context, slug string, version journal.WorkflowVersion) error {
			checks++
			return workflowproof.ValidateVersionForTenant(root, slug, journal.DefaultTenant, version)
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Enqueue: true,
	}
	runID, err := d.DispatchManual(ctx, journal.Trigger{WorkflowID: "wf_empty_dispatch_flow", Kind: journal.TriggerManual}, json.RawMessage(`{}`))
	if runID != "" || !errors.Is(err, journal.ErrWorkflowArtifactFence) || !strings.Contains(err.Error(), "no executable nodes") || checks != 1 {
		t.Fatalf("empty visual flow dispatch run=%q err=%v checks=%d, want one pre-queue artifact fence", runID, err, checks)
	}
	if queued, err := j.CountQueued(ctx); err != nil || queued != 0 {
		t.Fatalf("empty visual flow queued=%d err=%v", queued, err)
	}
}

func TestDispatchIntegrityCheckRunsBeforeQueueAndRejectsUnverifiedVersion(t *testing.T) {
	ctx := context.Background()
	j := newJournal(t)
	createExecutableWorkflow(t, j, "wf_integrity", "integrity")
	called := false
	d := &Dispatcher{
		Journal:  j,
		Resolver: &SQLResolver{Journal: j},
		ArtifactPath: func(_, _ string) (string, error) {
			return "/immutable/workflow", nil
		},
		IntegrityCheck: func(_ context.Context, slug string, version journal.WorkflowVersion) error {
			called = true
			if slug != "integrity" || version.Version != 1 || version.ArtifactSHA256 != testArtifactSHA256 {
				t.Fatalf("integrity callback received slug=%q version=%+v", slug, version)
			}
			return &journal.WorkflowArtifactFenceError{
				WorkflowID: "wf_integrity", Version: version.Version,
				PinnedDigest: version.ArtifactSHA256, Reason: "retained source unavailable",
			}
		},
		Sup: supervisor.Supervisor{Vault: noopVault{}},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Enqueue: true,
	}

	runID, err := d.DispatchManual(ctx,
		journal.Trigger{WorkflowID: "wf_integrity", Kind: journal.TriggerManual}, []byte(`{"safe":true}`))
	if runID != "" || !errors.Is(err, journal.ErrWorkflowArtifactFence) {
		t.Fatalf("dispatch with unverified retained source = run %q err %v, want no run and artifact fence", runID, err)
	}
	if !called {
		t.Fatal("dispatch did not invoke the integrity callback")
	}
	if n, countErr := j.CountQueued(ctx); countErr != nil || n != 0 {
		t.Fatalf("integrity failure queued %d runs (err=%v)", n, countErr)
	}
}

func TestDispatchIdempotentReplaySkipsIntegrityCheck(t *testing.T) {
	ctx := context.Background()
	j := newJournal(t)
	createExecutableWorkflow(t, j, "wf_integrity_replay", "integrity-replay")
	checks := 0
	d := &Dispatcher{
		Journal:  j,
		Resolver: &SQLResolver{Journal: j},
		ArtifactPath: func(_, _ string) (string, error) {
			return "/immutable/workflow", nil
		},
		IntegrityCheck: func(context.Context, string, journal.WorkflowVersion) error {
			checks++
			return nil
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Enqueue: true,
	}
	trig := journal.Trigger{WorkflowID: "wf_integrity_replay", Kind: journal.TriggerManual}
	first, err := d.DispatchManualIdempotent(ctx, trig, json.RawMessage(`{"attempt":1}`), "integrity-replay-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.DispatchManualIdempotent(ctx, trig, json.RawMessage(`{"attempt":1}`), "integrity-replay-1")
	if err != nil || second != first {
		t.Fatalf("idempotent replay = %q err %v, want original %q", second, err, first)
	}
	if checks != 1 {
		t.Fatalf("integrity callback called %d times for one durable dispatch, want 1", checks)
	}
}

func TestExecuteRunIntegrityFenceFailsOwnedRunBeforeSpawn(t *testing.T) {
	ctx := context.Background()
	j := newJournal(t)
	createExecutableWorkflow(t, j, "wf_integrity_worker", "integrity-worker")
	if err := j.CreateQueuedRunPinned(ctx, "run_integrity_worker", "wf_integrity_worker", "manual", json.RawMessage(`{}`), 1, testArtifactSHA256); err != nil {
		t.Fatal(err)
	}
	claims, err := j.ClaimQueuedRuns(ctx, "integrity-worker", 1, time.Minute)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim = %+v, %v", claims, err)
	}
	callbackCalled := false
	d := &Dispatcher{
		Journal:  j,
		Resolver: &SQLResolver{Journal: j},
		ArtifactPath: func(_, digest string) (string, error) {
			if digest != testArtifactSHA256 {
				t.Fatalf("artifact lookup digest = %q", digest)
			}
			return "/immutable/workflow", nil
		},
		IntegrityCheck: func(_ context.Context, slug string, version journal.WorkflowVersion) error {
			callbackCalled = true
			if slug != "integrity-worker" || version.Version != 1 {
				t.Fatalf("integrity callback received slug=%q version=%+v", slug, version)
			}
			return &journal.WorkflowArtifactFenceError{
				WorkflowID: "wf_integrity_worker", Version: 1,
				PinnedDigest: testArtifactSHA256, Reason: "retained source/DAG mismatch",
			}
		},
		Sup: supervisor.Supervisor{Vault: noopVault{}},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	err = d.ExecuteRun(ctx, "run_integrity_worker", claims[0].Owner)
	if !errors.Is(err, journal.ErrWorkflowArtifactFence) {
		t.Fatalf("ExecuteRun integrity failure = %v, want artifact fence", err)
	}
	if !callbackCalled {
		t.Fatal("worker execution did not invoke the integrity callback")
	}
	run, getErr := j.GetRun(ctx, "run_integrity_worker")
	if getErr != nil {
		t.Fatal(getErr)
	}
	if run.Status != "failed" || run.FinishedAt.IsZero() {
		t.Fatalf("integrity-fenced run = %+v, want terminal failed status", run)
	}
}
