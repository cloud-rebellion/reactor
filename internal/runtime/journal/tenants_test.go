package journal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEnqueueQuotaGate(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	mkWorkflowTenant(t, j, ctx, "wf_q", "q")

	// No tenant row yet -> unlimited, allowed.
	if err := j.CheckWorkflowEnqueueAllowed(ctx, "wf_q"); err != nil {
		t.Fatalf("no-row tenant should pass, got %v", err)
	}

	mustRefuse := func(want string) {
		t.Helper()
		err := j.CheckWorkflowEnqueueAllowed(ctx, "wf_q")
		var qe *QuotaError
		if !errors.As(err, &qe) {
			t.Fatalf("want *QuotaError, got %v", err)
		}
		if qe.TenantID != "q" || !strings.Contains(qe.Reason, want) {
			t.Fatalf("QuotaError = %+v, want reason containing %q", qe, want)
		}
	}

	// Disabled -> refused.
	if err := j.UpsertTenant(ctx, Tenant{TenantID: "q", Disabled: true}); err != nil {
		t.Fatal(err)
	}
	mustRefuse("disabled")

	// Queue cap of 1, one already queued -> refused.
	if err := j.UpsertTenant(ctx, Tenant{TenantID: "q", MaxQueuedRuns: 1}); err != nil {
		t.Fatal(err)
	}
	if err := j.CheckWorkflowEnqueueAllowed(ctx, "wf_q"); err != nil {
		t.Fatalf("empty queue under cap should pass, got %v", err)
	}
	if err := j.CreateQueuedRun(ctx, "q0", "wf_q", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	mustRefuse("queue full")

	// Monthly quota of 1 on a HARD-cap plan, one run already created this
	// month -> refused.
	if err := j.UpsertTenant(ctx, Tenant{TenantID: "q", MonthlyRunQuota: 1, HardCap: true}); err != nil {
		t.Fatal(err)
	}
	mustRefuse("monthly")

	// Same quota but SOFT cap -> allowed (the excess bills as overage).
	if err := j.UpsertTenant(ctx, Tenant{TenantID: "q", MonthlyRunQuota: 1, HardCap: false}); err != nil {
		t.Fatal(err)
	}
	if err := j.CheckWorkflowEnqueueAllowed(ctx, "wf_q"); err != nil {
		t.Fatalf("soft cap should allow past the monthly quota, got %v", err)
	}
}

func TestTenantStoreCRUD(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	// 'default' is seeded unlimited by the migration.
	def, err := j.GetTenant(ctx, "default")
	if err != nil {
		t.Fatalf("default tenant missing: %v", err)
	}
	if def.MaxConcurrentRuns != 0 || def.Disabled {
		t.Fatalf("default should be unlimited+enabled, got %+v", def)
	}

	if _, err := j.GetTenant(ctx, "nope"); !errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("want ErrTenantNotFound, got %v", err)
	}

	in := Tenant{TenantID: "acme", Name: "Acme", Plan: "pro", MaxConcurrentRuns: 5, MaxQueuedRuns: 100, MonthlyRunQuota: 10000}
	if err := j.UpsertTenant(ctx, in); err != nil {
		t.Fatal(err)
	}
	got, err := j.GetTenant(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Acme" || got.MaxConcurrentRuns != 5 || got.MaxQueuedRuns != 100 || got.MonthlyRunQuota != 10000 || got.Disabled {
		t.Fatalf("upsert/get mismatch: %+v", got)
	}

	// Update flips disabled + a quota.
	in.Disabled = true
	in.MaxConcurrentRuns = 2
	if err := j.UpsertTenant(ctx, in); err != nil {
		t.Fatal(err)
	}
	if got, _ = j.GetTenant(ctx, "acme"); !got.Disabled || got.MaxConcurrentRuns != 2 {
		t.Fatalf("update mismatch: %+v", got)
	}

	if list, err := j.ListTenants(ctx); err != nil || len(list) != 2 {
		t.Fatalf("list = %d tenants, err=%v", len(list), err)
	}

	if err := j.DeleteTenant(ctx, "default"); err == nil {
		t.Fatal("expected error deleting the default tenant")
	}
	if err := j.DeleteTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.GetTenant(ctx, "acme"); !errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("acme should be gone, got %v", err)
	}
}

func TestDeleteTenantRefusesDurableReferences(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.UpsertTenant(ctx, Tenant{TenantID: "retained", Disabled: true, MaxQueuedRuns: 3}); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_retained", "retained-flow", "h", "0.1.0", json.RawMessage(`{}`), "retained"); err != nil {
		t.Fatal(err)
	}
	if err := j.DeleteTenant(ctx, "retained"); !errors.Is(err, ErrTenantHasReferences) {
		t.Fatalf("delete with workflow = %v, want ErrTenantHasReferences", err)
	}
	got, err := j.GetTenant(ctx, "retained")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Disabled || got.MaxQueuedRuns != 3 {
		t.Fatalf("tenant policy changed after refused delete: %+v", got)
	}
}

func TestRunTenantDenormalized(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	// Workflow owned by tenant 'acme' (CreateWorkflow defaults to 'default',
	// so insert directly with the tenant set).
	if _, err := j.db.ExecContext(ctx, j.bind(
		`INSERT INTO workflows (id, tenant_id, slug, code_hash, sdk_version, dag_json) VALUES ($1,$2,$3,$4,$5,$6)`),
		"wf_acme", "acme", "acme-flow", "h", "0.1.0", outputArg(json.RawMessage(`{}`), j.engine)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflow(ctx, "wf_def", "def-flow", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}

	if err := j.CreateQueuedRun(ctx, "run_acme", "wf_acme", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_def", "wf_def", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}

	if got := runTenant(t, j, ctx, "run_acme"); got != "acme" {
		t.Fatalf("queued run tenant = %q, want acme", got)
	}
	if got := runTenant(t, j, ctx, "run_def"); got != "default" {
		t.Fatalf("run tenant = %q, want default", got)
	}

	if n, _ := j.CountQueuedForTenant(ctx, "acme"); n != 1 {
		t.Fatalf("acme queued = %d, want 1", n)
	}
	// newTestJournal seeds run_1 (running, default tenant), so default running
	// is the seed + run_def.
	if n, _ := j.CountRunningForTenant(ctx, "default"); n != 2 {
		t.Fatalf("default running = %d, want 2 (seed + run_def)", n)
	}
	if n, _ := j.CountRunningForTenant(ctx, "acme"); n != 0 {
		t.Fatalf("acme running = %d, want 0", n)
	}
	if n, _ := j.CountRunsSince(ctx, "acme", time.Now().Add(-time.Hour)); n != 1 {
		t.Fatalf("acme runs since = %d, want 1", n)
	}
}

func runTenant(t *testing.T, j *Journal, ctx context.Context, runID string) string {
	t.Helper()
	var tid string
	if err := j.db.QueryRowContext(ctx, j.bind(`SELECT tenant_id FROM runs WHERE id = $1`), runID).Scan(&tid); err != nil {
		t.Fatal(err)
	}
	return tid
}
