package journal

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestRunInputFingerprintPersistsAcrossDispatchPaths(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const workflowID = "wf_input_fingerprint"
	const artifact = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := j.CreateWorkflowWithArtifact(ctx, workflowID, "input-fingerprint", "code", "0.1.0", artifact, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	payload := json.RawMessage(`{"customer":"opaque","amount":7}`)
	want := inputSHA256(payload)

	if err := j.CreateRunPinned(ctx, "run_input_local", workflowID, "manual", payload, 1, artifact); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateQueuedRunPinned(ctx, "run_input_queue", workflowID, "manual", payload, 1, artifact); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRunPinnedIfEnabled(ctx, "run_input_local_enabled", workflowID, "manual", payload, 1, artifact); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateQueuedRunPinnedIfEnabled(ctx, "run_input_queue_enabled", workflowID, "manual", payload, 1, artifact); err != nil {
		t.Fatal(err)
	}

	for _, runID := range []string{"run_input_local", "run_input_queue", "run_input_local_enabled", "run_input_queue_enabled"} {
		got, err := j.GetRun(ctx, runID)
		if err != nil {
			t.Fatalf("get %s: %v", runID, err)
		}
		if got.InputSHA256 != want {
			t.Fatalf("run %s input hash = %q, want %q", runID, got.InputSHA256, want)
		}
	}
	listed, err := j.ListRuns(ctx, RunFilter{WorkflowID: workflowID, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 4 {
		t.Fatalf("listed runs = %d, want 4", len(listed))
	}
	for _, run := range listed {
		if run.InputSHA256 != want {
			t.Fatalf("listed run %s input hash = %q, want %q", run.ID, run.InputSHA256, want)
		}
		if len(run.InputSHA256) != 64 || strings.Trim(run.InputSHA256, "0123456789abcdef") != "" {
			t.Fatalf("listed run %s input hash is not an opaque lowercase SHA-256: %q", run.ID, run.InputSHA256)
		}
	}
}
