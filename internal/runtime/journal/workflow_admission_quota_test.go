package journal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPinnedAdmissionEnforcesQueueQuotaInsideInsertTransaction(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_atomic_queue", "atomic-queue", "h", "0.1.0", digest, json.RawMessage(`{}`), "atomic"); err != nil {
		t.Fatal(err)
	}
	if err := j.UpsertTenant(ctx, Tenant{TenantID: "atomic", MaxQueuedRuns: 1}); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateQueuedRunPinnedIfEnabled(ctx, "run_atomic_queue_1", "wf_atomic_queue", "manual", json.RawMessage(`{}`), 1, digest); err != nil {
		t.Fatalf("first queued run: %v", err)
	}
	err := j.CreateQueuedRunPinnedIfEnabled(ctx, "run_atomic_queue_2", "wf_atomic_queue", "manual", json.RawMessage(`{}`), 1, digest)
	var quota *QuotaError
	if !errors.As(err, &quota) || quota.TenantID != "atomic" || !strings.Contains(quota.Reason, "queue full") {
		t.Fatalf("second queued run = %v, want atomic queue QuotaError", err)
	}
}

func TestPinnedAdmissionEnforcesWorkflowRateInsideInsertTransaction(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_atomic_rate", "atomic-rate", "h", "0.1.0", digest, json.RawMessage(`{}`), "default"); err != nil {
		t.Fatal(err)
	}
	if err := j.SetWorkflowRateLimit(ctx, "wf_atomic_rate", 1); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRunPinnedIfEnabled(ctx, "run_atomic_rate_1", "wf_atomic_rate", "manual", json.RawMessage(`{}`), 1, digest); err != nil {
		t.Fatalf("first running run: %v", err)
	}
	err := j.CreateRunPinnedIfEnabled(ctx, "run_atomic_rate_2", "wf_atomic_rate", "manual", json.RawMessage(`{}`), 1, digest)
	var rate *WorkflowRateLimitError
	if !errors.As(err, &rate) || rate.WorkflowID != "wf_atomic_rate" || rate.Limit != 1 {
		t.Fatalf("second running run = %v, want WorkflowRateLimitError", err)
	}
}

func TestPinnedLocalAdmissionEnforcesTenantConcurrency(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const digest = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_atomic_concurrency", "atomic-concurrency", "h", "0.1.0", digest, json.RawMessage(`{}`), "atomic-concurrency"); err != nil {
		t.Fatal(err)
	}
	if err := j.UpsertTenant(ctx, Tenant{TenantID: "atomic-concurrency", MaxConcurrentRuns: 1}); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRunPinnedIfEnabled(ctx, "run_atomic_concurrency_1", "wf_atomic_concurrency", "manual", json.RawMessage(`{}`), 1, digest); err != nil {
		t.Fatalf("first local run: %v", err)
	}
	err := j.CreateRunPinnedIfEnabled(ctx, "run_atomic_concurrency_2", "wf_atomic_concurrency", "manual", json.RawMessage(`{}`), 1, digest)
	var quota *QuotaError
	if !errors.As(err, &quota) || quota.TenantID != "atomic-concurrency" || !strings.Contains(quota.Reason, "concurrency full") {
		t.Fatalf("second local run = %v, want concurrency QuotaError", err)
	}
}

func TestPinnedAdmissionIdempotentReplayBypassesNewQuotaCheck(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const digest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_atomic_idem", "atomic-idem", "h", "0.1.0", digest, json.RawMessage(`{}`), "atomic-idem"); err != nil {
		t.Fatal(err)
	}
	if err := j.UpsertTenant(ctx, Tenant{TenantID: "atomic-idem", MaxQueuedRuns: 1}); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"value":1}`)
	hash := inputSHA256(payload)
	first, created, err := j.CreateQueuedRunPinnedIdempotentIfEnabled(ctx, "run_atomic_idem_1", "wf_atomic_idem", "manual", payload, 1, digest, "same-key", hash)
	if err != nil || !created || first != "run_atomic_idem_1" {
		t.Fatalf("first idempotent queue = id=%q created=%v err=%v", first, created, err)
	}
	replay, created, err := j.CreateQueuedRunPinnedIdempotentIfEnabled(ctx, "run_atomic_idem_2", "wf_atomic_idem", "manual", payload, 1, digest, "same-key", hash)
	if err != nil || created || replay != first {
		t.Fatalf("idempotent replay = id=%q created=%v err=%v", replay, created, err)
	}
}
