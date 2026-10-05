package journal

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// TestWorkflowEnabledRoundTrip proves SetWorkflowEnabled actually flips the
// flag IsWorkflowEnabled reads (the dispatch gate the audit found
// cosmetic), and that the engine-aware boolValue binding works.
func TestWorkflowEnabledRoundTrip(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_e", "enabled-demo", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}

	// Default is enabled.
	if ok, err := j.IsWorkflowEnabled(ctx, "wf_e"); err != nil || !ok {
		t.Fatalf("fresh workflow should be enabled: ok=%v err=%v", ok, err)
	}
	// Disable -> reads back disabled.
	if err := j.SetWorkflowEnabled(ctx, "wf_e", false); err != nil {
		t.Fatal(err)
	}
	if ok, err := j.IsWorkflowEnabled(ctx, "wf_e"); err != nil || ok {
		t.Fatalf("disabled workflow should read disabled: ok=%v err=%v", ok, err)
	}
	// Re-enable.
	if err := j.SetWorkflowEnabled(ctx, "wf_e", true); err != nil {
		t.Fatal(err)
	}
	if ok, err := j.IsWorkflowEnabled(ctx, "wf_e"); err != nil || !ok {
		t.Fatalf("re-enabled workflow should read enabled: ok=%v err=%v", ok, err)
	}
	// Unknown workflow.
	if _, err := j.IsWorkflowEnabled(ctx, "wf_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown workflow should return ErrNotFound, got %v", err)
	}
}

func TestWorkflowEnabledFenceRejectsStaleState(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_fenced", "fenced", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.SetWorkflowEnabledIfState(ctx, "wf_fenced", false, true); err != nil {
		t.Fatalf("first fenced state change: %v", err)
	}
	if err := j.SetWorkflowEnabledIfState(ctx, "wf_fenced", true, true); !errors.Is(err, ErrWorkflowStateConflict) {
		t.Fatalf("stale state change = %v, want ErrWorkflowStateConflict", err)
	}
	if enabled, err := j.IsWorkflowEnabled(ctx, "wf_fenced"); err != nil || enabled {
		t.Fatalf("stale state change altered workflow: enabled=%v err=%v", enabled, err)
	}
}

func TestPinnedLiveAdmissionIsAtomicWithEnabledState(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_admission", "admission", "h", "0.1.0", digest, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_admission", false); err != nil {
		t.Fatal(err)
	}

	if err := j.CreateRunPinnedIfEnabled(ctx, "run_disabled_local", "wf_admission", "manual", json.RawMessage(`{}`), 1, digest); !errors.Is(err, ErrWorkflowDisabled) {
		t.Fatalf("disabled local admission = %v, want ErrWorkflowDisabled", err)
	}
	if err := j.CreateQueuedRunPinnedIfEnabled(ctx, "run_disabled_queue", "wf_admission", "manual", json.RawMessage(`{}`), 1, digest); !errors.Is(err, ErrWorkflowDisabled) {
		t.Fatalf("disabled queued admission = %v, want ErrWorkflowDisabled", err)
	}
	payloadHash := inputSHA256([]byte(`{}`))
	if _, _, err := j.CreateRunPinnedIdempotentIfEnabled(ctx, "run_disabled_idem", "wf_admission", "manual", []byte(`{}`), 1, digest, "idem-disabled", payloadHash); !errors.Is(err, ErrWorkflowDisabled) {
		t.Fatalf("disabled idempotent local admission = %v, want ErrWorkflowDisabled", err)
	}
	if _, _, err := j.CreateQueuedRunPinnedIdempotentIfEnabled(ctx, "run_disabled_idem_queue", "wf_admission", "manual", []byte(`{}`), 1, digest, "idem-disabled-queue", payloadHash); !errors.Is(err, ErrWorkflowDisabled) {
		t.Fatalf("disabled idempotent queued admission = %v, want ErrWorkflowDisabled", err)
	}
	if runs, err := j.ListRuns(ctx, RunFilter{WorkflowID: "wf_admission", Limit: 20}); err != nil {
		t.Fatal(err)
	} else if len(runs) != 0 {
		t.Fatalf("disabled admission created %d run(s)", len(runs))
	}

	if err := j.SetWorkflowEnabled(ctx, "wf_admission", true); err != nil {
		t.Fatal(err)
	}
	first, created, err := j.CreateRunPinnedIdempotentIfEnabled(ctx, "run_enabled_idem", "wf_admission", "manual", []byte(`{}`), 1, digest, "idem-enabled", payloadHash)
	if err != nil || !created || first != "run_enabled_idem" {
		t.Fatalf("enabled idempotent admission = id=%q created=%v err=%v", first, created, err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_admission", false); err != nil {
		t.Fatal(err)
	}
	// A retry receipt remains readable while disabled; it must not start a
	// second run or turn a successful prior dispatch into a kill-switch error.
	replay, created, err := j.CreateRunPinnedIdempotentIfEnabled(ctx, "run_should_not_be_created", "wf_admission", "manual", []byte(`{}`), 1, digest, "idem-enabled", payloadHash)
	if err != nil || created || replay != first {
		t.Fatalf("disabled idempotent replay = id=%q created=%v err=%v; want %q/false/nil", replay, created, err, first)
	}
}

func TestWorkflowEnabledFenceRejectsStaleReviewedVersion(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	digestA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_version_fenced", "version-fenced", "h1", "0.1.0", digestA, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.SetWorkflowEnabledIfStateAndVersion(ctx, "wf_version_fenced", false, true, 1); err != nil {
		t.Fatalf("initial version-fenced disable: %v", err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifactIfDisabled(ctx, "wf_version_fenced", "0.1.0", "h2", digestB, json.RawMessage(`{"steps":[]}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.SetWorkflowEnabledIfVersion(ctx, "wf_version_fenced", true, 1); !errors.Is(err, ErrWorkflowVersionConflict) {
		t.Fatalf("stale version activation = %v, want ErrWorkflowVersionConflict", err)
	}
	if enabled, err := j.IsWorkflowEnabled(ctx, "wf_version_fenced"); err != nil || enabled {
		t.Fatalf("stale version activation changed state: enabled=%v err=%v", enabled, err)
	}
	if err := j.SetWorkflowEnabledIfStateAndVersion(ctx, "wf_version_fenced", true, false, 2); err != nil {
		t.Fatalf("current version activation: %v", err)
	}
	if enabled, err := j.IsWorkflowEnabled(ctx, "wf_version_fenced"); err != nil || !enabled {
		t.Fatalf("current version activation did not enable workflow: enabled=%v err=%v", enabled, err)
	}
}

func TestDeleteWorkflowIfDisabledAndVersionRejectsStaleRevision(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_delete_version", "delete-version", "h1", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_delete_version", false); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifactIfDisabled(ctx, "wf_delete_version", "0.1.0", "h2", "", json.RawMessage(`{"steps":[]}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.DeleteWorkflowIfDisabledAndVersion(ctx, "wf_delete_version", 1); !errors.Is(err, ErrWorkflowVersionConflict) {
		t.Fatalf("stale workflow deletion = %v, want ErrWorkflowVersionConflict", err)
	}
	if err := j.DeleteWorkflowIfDisabledAndVersion(ctx, "wf_delete_version", 2); err != nil {
		t.Fatalf("current workflow deletion: %v", err)
	}
}
