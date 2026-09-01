package dispatcher

import (
	"context"
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
)

func artifactScript(t *testing.T, marker, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "workflow")
	body := "#!/bin/sh\nprintf '%s' '" + value + "' > '" + marker + "'\n"
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestQueuedRunExecutesPinnedV1AfterV2Activation(t *testing.T) {
	ctx := context.Background()
	j := newJournal(t)
	reg := registry.New(filepath.Join(t.TempDir(), "workflows"))
	marker := filepath.Join(t.TempDir(), "executed")

	v1, err := reg.PublishArtifact("signing", artifactScript(t, marker, "v1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_signing", "signing", "source-v1", "0.1.0", v1.Digest, json.RawMessage(`{"version":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.ActivateArtifact("signing", v1.Digest); err != nil {
		t.Fatal(err)
	}
	d := &Dispatcher{
		Journal: j, Resolver: &SQLResolver{Journal: j}, ArtifactPath: reg.ArtifactPath,
		Sup: supervisor.Supervisor{Vault: noopVault{}},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Enqueue: true,
	}
	runID, err := d.DispatchWebhook(ctx, journal.Trigger{WorkflowID: "wf_signing", Kind: journal.TriggerWebhook}, []byte(`{"customer":"safe"}`))
	if err != nil {
		t.Fatal(err)
	}

	// Activate a genuinely different executable and version after the v1 run is
	// durable. The worker must resolve the historical v1 digest, not current v2.
	v2, err := reg.PublishArtifact("signing", artifactScript(t, marker, "v2"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_signing", "0.1.0", "source-v2", v2.Digest, json.RawMessage(`{"version":2}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.ActivateArtifact("signing", v2.Digest); err != nil {
		t.Fatal(err)
	}
	ids, err := j.ClaimQueuedRuns(ctx, "worker", 1, time.Minute)
	if err != nil || len(ids) != 1 || ids[0].RunID != runID {
		t.Fatalf("claim = %v, %v", ids, err)
	}
	if err := d.ExecuteRun(ctx, runID, ids[0].Owner); err != nil {
		t.Fatalf("ExecuteRun: %v", err)
	}
	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("pinned artifact did not execute: %v", err)
	}
	if string(got) != "v1" {
		t.Fatalf("executed %q, want queued run's immutable v1", got)
	}
	run, err := j.GetRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if run.WorkflowVersion != 1 || run.WorkflowArtifactSHA256 != v1.Digest {
		t.Fatalf("run pins drifted after v2 activation: %+v", run)
	}
}

func TestUnavailablePinnedArtifactRetainsOwnedRunWithoutSpawn(t *testing.T) {
	ctx := context.Background()
	j := newJournal(t)
	reg := registry.New(filepath.Join(t.TempDir(), "workflows"))
	marker := filepath.Join(t.TempDir(), "must-not-exist")
	v1, err := reg.PublishArtifact("signing", artifactScript(t, marker, "unsafe"))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_signing", "signing", "h", "0.1.0", v1.Digest, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	d := &Dispatcher{
		Journal: j, Resolver: &SQLResolver{Journal: j}, ArtifactPath: reg.ArtifactPath,
		Sup: supervisor.Supervisor{Vault: noopVault{}},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Enqueue: true,
	}
	runID, err := d.DispatchWebhook(ctx, journal.Trigger{WorkflowID: "wf_signing", Kind: journal.TriggerWebhook}, nil)
	if err != nil {
		t.Fatal(err)
	}
	artifactPath, err := reg.ArtifactPath("signing", v1.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(artifactPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	claims, err := j.ClaimQueuedRuns(ctx, "worker", 1, time.Minute)
	if err != nil || len(claims) != 1 {
		t.Fatal(err)
	}
	if err := d.ExecuteRun(ctx, runID, claims[0].Owner); err == nil || errors.Is(err, journal.ErrWorkflowArtifactFence) {
		t.Fatalf("ExecuteRun unavailable artifact = %v, want recoverable availability error", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("tampered artifact spawned; marker stat = %v", err)
	}
	run, _ := j.GetRun(ctx, runID)
	if run.Status != "running" || !run.FinishedAt.IsZero() {
		t.Fatalf("artifact availability failure terminalized run: %+v", run)
	}
	logs, err := j.GetRunLogs(ctx, runID)
	if err != nil || len(logs) != 0 {
		t.Fatalf("availability failure wrote permanent-fence log = %v, %v", logs, err)
	}
	if err := j.ExtendLease(ctx, runID, claims[0].Owner, -time.Minute); err != nil {
		t.Fatalf("availability failure lost exact lease: %v", err)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("availability failure was not requeued after expiry: n=%d err=%v", n, err)
	}
	if run, err := j.GetRun(ctx, runID); err != nil || run.Status != "queued" || !run.FinishedAt.IsZero() {
		t.Fatalf("requeued artifact availability run = %+v, %v", run, err)
	}
}

func TestPersistedArtifactDigestMismatchFailsOwnedRunTerminally(t *testing.T) {
	ctx := context.Background()
	j := newJournal(t)
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_signing", "signing", "h", "0.1.0", testArtifactSHA256, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	mismatchedDigest := strings.Repeat("b", 64)
	if err := j.CreateQueuedRunPinned(ctx, "run_digest_mismatch", "wf_signing", "webhook", json.RawMessage(`{}`), 1, mismatchedDigest); err != nil {
		t.Fatal(err)
	}
	claims, err := j.ClaimQueuedRuns(ctx, "worker-mismatch", 1, time.Minute)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim mismatch run = %+v, %v", claims, err)
	}
	lookupCalled := false
	d := &Dispatcher{
		Journal:  j,
		Resolver: &SQLResolver{Journal: j},
		ArtifactPath: func(_, _ string) (string, error) {
			lookupCalled = true
			return "", nil
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := d.ExecuteRun(ctx, "run_digest_mismatch", claims[0].Owner); !errors.Is(err, journal.ErrWorkflowArtifactFence) {
		t.Fatalf("ExecuteRun persisted digest mismatch = %v, want permanent fence", err)
	}
	if lookupCalled {
		t.Fatal("persisted digest mismatch reached node artifact lookup")
	}
	if run, err := j.GetRun(ctx, "run_digest_mismatch"); err != nil || run.Status != "failed" || run.FinishedAt.IsZero() {
		t.Fatalf("persisted digest mismatch state = %+v, %v", run, err)
	}
	if err := j.ExtendLease(ctx, "run_digest_mismatch", claims[0].Owner, time.Minute); !errors.Is(err, journal.ErrLeaseOwnershipLost) {
		t.Fatalf("permanent digest fence retained lease: %v", err)
	}
}

func TestUnpinnedRunFailsBeforeArtifactLookup(t *testing.T) {
	ctx := context.Background()
	j := newJournal(t)
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_signing", "signing", "h", "0.1.0", testArtifactSHA256, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateQueuedRun(ctx, "legacy_run", "wf_signing", "webhook", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	claims, err := j.ClaimQueuedRuns(ctx, "worker", 1, time.Minute)
	if err != nil || len(claims) != 1 {
		t.Fatal(err)
	}
	lookupCalled := false
	d := &Dispatcher{
		Journal: j, Resolver: &SQLResolver{Journal: j},
		ArtifactPath: func(_, _ string) (string, error) { lookupCalled = true; return "", nil },
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := d.ExecuteRun(ctx, "legacy_run", claims[0].Owner); !errors.Is(err, journal.ErrWorkflowArtifactFence) {
		t.Fatalf("ExecuteRun unpinned = %v, want fence", err)
	}
	if lookupCalled {
		t.Fatal("unpinned run reached artifact lookup")
	}
}
