package journal

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestCountClaimableQueuedMatchesAdmissionPolicy(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	for _, tenantID := range []string{"active", "capped", "disabled"} {
		mkWorkflowTenant(t, j, ctx, "wf_"+tenantID, tenantID)
	}
	for _, runID := range []string{"active_a", "active_b"} {
		if err := j.CreateQueuedRun(ctx, runID, "wf_active", "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.CreateRun(ctx, "capped_running", "wf_capped", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	for _, runID := range []string{"capped_a", "capped_b"} {
		if err := j.CreateQueuedRun(ctx, runID, "wf_capped", "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.CreateQueuedRun(ctx, "disabled_a", "wf_disabled", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.UpsertTenant(ctx, Tenant{TenantID: "capped", MaxConcurrentRuns: 1}); err != nil {
		t.Fatal(err)
	}
	if err := j.UpsertTenant(ctx, Tenant{TenantID: "disabled", Disabled: true}); err != nil {
		t.Fatal(err)
	}
	assertCounts := func(raw, claimable int) {
		t.Helper()
		gotRaw, err := j.CountQueued(ctx)
		if err != nil || gotRaw != raw {
			t.Fatalf("raw queued = %d, %v; want %d", gotRaw, err, raw)
		}
		gotClaimable, err := j.CountClaimableQueued(ctx)
		if err != nil || gotClaimable != claimable {
			t.Fatalf("claimable queued = %d, %v; want %d", gotClaimable, err, claimable)
		}
	}
	assertCounts(5, 2) // Two active runs; capped and disabled tenants cannot claim.
	if err := j.SetWorkflowEnabled(ctx, "wf_active", false); err != nil {
		t.Fatal(err)
	}
	assertCounts(5, 0)
	if err := j.SetWorkflowEnabled(ctx, "wf_active", true); err != nil {
		t.Fatal(err)
	}
	if err := j.UpsertTenant(ctx, Tenant{TenantID: "capped", MaxConcurrentRuns: 2}); err != nil {
		t.Fatal(err)
	}
	assertCounts(5, 3) // One capped-tenant slot opened.
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE runs SET cancel_requested = $1 WHERE id = $2`), j.boolValue(true), "active_a"); err != nil {
		t.Fatal(err)
	}
	assertCounts(4, 2)
}

func TestQueuedTenantMismatchIsNotClaimedOrCounted(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	mkWorkflowTenant(t, j, ctx, "wf_owner", "owner")
	older := j.formatTime(time.Now().UTC().Add(-time.Hour))
	// These malformed rows are older than the valid row in the same
	// workflow. A pre-filter LIMIT would hide that later claimable work.
	for i := 0; i < 32; i++ {
		_, err := j.db.ExecContext(ctx, j.bind(`INSERT INTO runs
			(id, workflow_id, tenant_id, trigger_kind, trigger_meta, status, created_at)
			VALUES ($1, $2, $3, 'manual', '{}', 'queued', $4)`),
			fmt.Sprintf("wrong_%02d", i), "wf_owner", "other", older)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := j.CreateQueuedRun(ctx, "valid_later", "wf_owner", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if raw, err := j.CountQueued(ctx); err != nil || raw != 33 {
		t.Fatalf("raw queued = %d, %v; want 33 retained rows", raw, err)
	}
	if n, err := j.CountClaimableQueued(ctx); err != nil || n != 1 {
		t.Fatalf("claimable queued = %d, %v; want only valid run", n, err)
	}
	if n, err := j.CountClaimableQueuedUpTo(ctx, 1); err != nil || n != 1 {
		t.Fatalf("bounded claimable queued = %d, %v; want one", n, err)
	}
	if _, err := j.CountClaimableQueuedUpTo(ctx, 0); err == nil {
		t.Fatal("nonpositive saturation was accepted")
	}
	claims, err := j.ClaimQueuedRuns(ctx, "tenant-fence", 1, time.Minute)
	if err != nil || len(claims) != 1 || claims[0].RunID != "valid_later" {
		t.Fatalf("claim = %+v, %v; want valid_later only", claims, err)
	}
}
