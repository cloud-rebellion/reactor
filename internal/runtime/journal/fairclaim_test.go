package journal

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// mkWorkflowTenant inserts a workflow owned by tenantID (CreateWorkflow always
// uses 'default').
func mkWorkflowTenant(t *testing.T, j *Journal, ctx context.Context, wfID, tenantID string) {
	t.Helper()
	if _, err := j.db.ExecContext(ctx, j.bind(
		`INSERT INTO workflows (id, tenant_id, slug, code_hash, sdk_version, dag_json) VALUES ($1,$2,$3,$4,$5,$6)`),
		wfID, tenantID, wfID+"-slug", "h", "0.1.0", outputArg(json.RawMessage(`{}`), j.engine)); err != nil {
		t.Fatal(err)
	}
}

func tenantOf(t *testing.T, j *Journal, ctx context.Context, ids []RunLease) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for _, claim := range ids {
		counts[runTenant(t, j, ctx, claim.RunID)]++
	}
	return counts
}

// TestFairClaimInterleavesTenants: tenant "a" floods the queue first, tenant
// "b" enqueues last. FIFO would serve all of a before any b; the fair claim
// must interleave so b is not starved.
func TestFairClaimInterleavesTenants(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	mkWorkflowTenant(t, j, ctx, "wf_a", "a")
	mkWorkflowTenant(t, j, ctx, "wf_b", "b")

	// a's five runs are all created BEFORE b's two.
	for i := 0; i < 5; i++ {
		if err := j.CreateQueuedRun(ctx, "a"+itoa(i), "wf_a", "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := j.CreateQueuedRun(ctx, "b"+itoa(i), "wf_b", "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}

	ids, err := j.ClaimQueuedRuns(ctx, "w1", 4, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 4 {
		t.Fatalf("claimed %d, want 4", len(ids))
	}
	counts := tenantOf(t, j, ctx, ids)
	// Fair interleave of [a:5, b:2] taking 4 => a,b,a,b => 2 each. The key
	// property: b (enqueued last) is served, not starved behind a's backlog.
	if counts["b"] != 2 {
		t.Fatalf("tenant b claimed %d of 4, want 2 (fair interleave); counts=%v", counts["b"], counts)
	}
	if counts["a"] != 2 {
		t.Fatalf("tenant a claimed %d of 4, want 2; counts=%v", counts["a"], counts)
	}
}

// TestClaimRespectsConcurrencyCap: a tenant at its max_concurrent_runs gets no
// further runs claimed; raising the cap lets exactly the budget through.
func TestClaimRespectsConcurrencyCap(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	mkWorkflowTenant(t, j, ctx, "wf_c", "capped")
	if err := j.UpsertTenant(ctx, Tenant{TenantID: "capped", MaxConcurrentRuns: 1}); err != nil {
		t.Fatal(err)
	}
	// One already running (fills the cap of 1).
	if err := j.CreateRun(ctx, "c_run", "wf_c", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := j.CreateQueuedRun(ctx, "cq"+itoa(i), "wf_c", "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}

	// Budget = cap(1) - running(1) = 0 -> nothing claimable for capped.
	ids, err := j.ClaimQueuedRuns(ctx, "w1", 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if c := tenantOf(t, j, ctx, ids)["capped"]; c != 0 {
		t.Fatalf("capped claimed %d at cap, want 0", c)
	}

	// Raise the cap to 3: budget = 3 - 1 = 2 -> exactly two claimable.
	if err := j.UpsertTenant(ctx, Tenant{TenantID: "capped", MaxConcurrentRuns: 3}); err != nil {
		t.Fatal(err)
	}
	ids, err = j.ClaimQueuedRuns(ctx, "w2", 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if c := tenantOf(t, j, ctx, ids)["capped"]; c != 2 {
		t.Fatalf("capped claimed %d with budget 2, want 2", c)
	}
}

// TestClaimSkipsDisabledTenant: a disabled tenant's queued runs are never
// claimed.
func TestClaimSkipsDisabledTenant(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	mkWorkflowTenant(t, j, ctx, "wf_d", "off")
	if err := j.UpsertTenant(ctx, Tenant{TenantID: "off", Disabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateQueuedRun(ctx, "d0", "wf_d", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	ids, err := j.ClaimQueuedRuns(ctx, "w1", 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if c := tenantOf(t, j, ctx, ids)["off"]; c != 0 {
		t.Fatalf("disabled tenant claimed %d, want 0", c)
	}
}

func TestClaimSkipsDisabledWorkflowUntilReenabled(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_paused_queue", "paused-queue", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateQueuedRun(ctx, "run_paused_queue", "wf_paused_queue", "webhook", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_paused_queue", false); err != nil {
		t.Fatal(err)
	}
	if claims, err := j.ClaimQueuedRuns(ctx, "worker", 1, time.Minute); err != nil || len(claims) != 0 {
		t.Fatalf("disabled workflow claim = %v, %v; want none", claims, err)
	}
	if run, err := j.GetRun(ctx, "run_paused_queue"); err != nil || run.Status != "queued" {
		t.Fatalf("disabled workflow queue state = %+v, %v", run, err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_paused_queue", true); err != nil {
		t.Fatal(err)
	}
	if claims, err := j.ClaimQueuedRuns(ctx, "worker", 1, time.Minute); err != nil || len(claims) != 1 || claims[0].RunID != "run_paused_queue" {
		t.Fatalf("reenabled workflow claim = %v, %v", claims, err)
	}
}
