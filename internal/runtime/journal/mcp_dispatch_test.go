package journal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestMCPDispatchIdempotencyBindsPayloadAndRun(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_idem", "idem", "hash", "0.1.0", digest, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}

	payloadOne := []byte(`{"value":1}`)
	payloadTwo := []byte(`{"value":2}`)
	hashOne, hashTwo := inputSHA256(payloadOne), inputSHA256(payloadTwo)
	first, created, err := j.CreateRunPinnedIdempotent(ctx, "run_first", "wf_idem", "manual", payloadOne, 1, digest, "operator-1", hashOne)
	if err != nil || !created || first != "run_first" {
		t.Fatalf("first idempotent insert = id %q created %v err %v", first, created, err)
	}
	second, created, err := j.CreateRunPinnedIdempotent(ctx, "run_second", "wf_idem", "manual", payloadOne, 1, digest, "operator-1", hashOne)
	if err != nil || created || second != "run_first" {
		t.Fatalf("replay = id %q created %v err %v", second, created, err)
	}
	if _, _, err := j.CreateRunPinnedIdempotent(ctx, "run_other", "wf_idem", "manual", payloadTwo, 1, digest, "operator-1", hashTwo); !errors.Is(err, ErrMCPDispatchIdempotencyConflict) {
		t.Fatalf("payload mismatch = %v, want ErrMCPDispatchIdempotencyConflict", err)
	}
	if _, err := j.GetRun(ctx, "run_second"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("idempotent replay created a second run: %v", err)
	}
}

func TestMCPQueuedDispatchIdempotencyReplaysSameRun(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_queue_idem", "queue-idem", "hash", "0.1.0", digest, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"value":1}`)
	payloadHash := inputSHA256(payload)
	first, created, err := j.CreateQueuedRunPinnedIdempotent(ctx, "run_queue_first", "wf_queue_idem", "manual", payload, 1, digest, "operator-queue-1", payloadHash)
	if err != nil || !created || first != "run_queue_first" {
		t.Fatalf("first queued insert = id %q created %v err %v", first, created, err)
	}
	second, created, err := j.CreateQueuedRunPinnedIdempotent(ctx, "run_queue_second", "wf_queue_idem", "manual", payload, 1, digest, "operator-queue-1", payloadHash)
	if err != nil || created || second != first {
		t.Fatalf("queued replay = id %q created %v err %v", second, created, err)
	}
}

func TestMCPDispatchRejectsInputHashMismatch(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const digest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_hash_mismatch", "hash-mismatch", "hash", "0.1.0", digest, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	_, _, err := j.CreateRunPinnedIdempotent(ctx, "run_hash_mismatch", "wf_hash_mismatch", "manual", []byte(`{"value":1}`), 1, digest, "operator-hash-mismatch", strings.Repeat("a", 64))
	if !errors.Is(err, ErrMCPDispatchInputHashMismatch) {
		t.Fatalf("mismatched payload hash = %v, want ErrMCPDispatchInputHashMismatch", err)
	}
	if _, err := j.GetRun(ctx, "run_hash_mismatch"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mismatched hash inserted a run: %v", err)
	}
}
