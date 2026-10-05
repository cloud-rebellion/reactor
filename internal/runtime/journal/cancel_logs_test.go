package journal

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func seedRun(t *testing.T, j *Journal, runID, status string) {
	t.Helper()
	ctx := context.Background()
	if err := j.CreateRun(ctx, runID, "wf_c", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if status != "running" {
		if err := j.SetRunStatus(ctx, runID, status); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRequestRunCancelOutcomes(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_c", "cancel-demo", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}

	// Running run -> requested + flagged + listed for the watcher.
	seedRun(t, j, "run_running", "running")
	if out, err := j.RequestRunCancel(ctx, "run_running"); err != nil || out != CancelRequested {
		t.Fatalf("running cancel = %q, %v; want requested", out, err)
	}
	ids, err := j.ListCancelRequestedActive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "run_running" {
		t.Fatalf("ListCancelRequestedActive = %v, want [run_running]", ids)
	}

	// Suspended run -> cancelled outright + pending schedule fired.
	seedRun(t, j, "run_susp", "suspended")
	if _, err := j.ScheduleSleep(ctx, "run_susp", "wait", time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if out, err := j.RequestRunCancel(ctx, "run_susp"); err != nil || out != CancelDone {
		t.Fatalf("suspended cancel = %q, %v; want cancelled", out, err)
	}
	if info, _ := j.GetRun(ctx, "run_susp"); info.Status != "cancelled" {
		t.Fatalf("suspended run status = %q, want cancelled", info.Status)
	}
	if due, _ := j.FindDueSchedules(ctx, time.Now().UTC(), 10); len(due) != 0 {
		t.Fatalf("cancelled run's schedule should be fired, got %d due", len(due))
	}

	// Queued run -> cancelled before any worker can claim it.
	if err := j.CreateQueuedRun(ctx, "run_queued", "wf_c", "webhook", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if out, err := j.RequestRunCancel(ctx, "run_queued"); err != nil || out != CancelDone {
		t.Fatalf("queued cancel = %q, %v; want cancelled", out, err)
	}
	if info, _ := j.GetRun(ctx, "run_queued"); info.Status != "cancelled" || info.FinishedAt.IsZero() {
		t.Fatalf("queued run cancellation not durable: %+v", info)
	}
	if claims, err := j.ClaimQueuedRuns(ctx, "worker", 10, time.Minute); err != nil || len(claims) != 0 {
		t.Fatalf("cancelled queued run was claimable: %v, %v", claims, err)
	}
	usage, err := j.TenantUsageSince(ctx, DefaultTenant, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if usage.Runs != 2 {
		t.Fatalf("operator cancellations were not metered: %+v", usage)
	}

	// Terminal run -> nothing to do.
	seedRun(t, j, "run_done", "running")
	if err := j.MarkRunFinished(ctx, "run_done", "succeeded"); err != nil {
		t.Fatal(err)
	}
	if out, err := j.RequestRunCancel(ctx, "run_done"); err != nil || out != CancelNotPossible {
		t.Fatalf("terminal cancel = %q, %v; want not_cancellable", out, err)
	}

	// Unknown run -> ErrNotFound.
	if _, err := j.RequestRunCancel(ctx, "run_nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown cancel err = %v, want ErrNotFound", err)
	}
}

func TestRequestRunCancelForTenantScopesMutation(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	for _, wf := range []struct {
		id     string
		tenant string
	}{
		{id: "wf_tenant_a", tenant: "tenant-a"},
		{id: "wf_tenant_b", tenant: "tenant-b"},
	} {
		if err := j.CreateWorkflow(ctx, wf.id, wf.id, "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE workflows SET tenant_id = $1 WHERE id = $2`), wf.tenant, wf.id); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.CreateRun(ctx, "run_tenant_b", "wf_tenant_b", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	for _, emptyTenant := range []string{"", "   "} {
		if out, err := j.RequestRunCancelForTenant(ctx, "run_tenant_b", emptyTenant); !errors.Is(err, ErrNotFound) || out != CancelNotPossible {
			t.Fatalf("empty tenant cancel = %q, %v; want not_cancellable + ErrNotFound", out, err)
		}
	}

	if out, err := j.RequestRunCancelForTenant(ctx, "run_tenant_b", "tenant-a"); !errors.Is(err, ErrNotFound) || out != CancelNotPossible {
		t.Fatalf("foreign cancel = %q, %v; want not_cancellable + ErrNotFound", out, err)
	}
	info, err := j.GetRun(ctx, "run_tenant_b")
	if err != nil {
		t.Fatal(err)
	}
	if info.Status != "running" || info.CancelRequested {
		t.Fatalf("foreign cancel mutated run: %+v", info)
	}

	if out, err := j.RequestRunCancelForTenant(ctx, "run_tenant_b", "tenant-b"); err != nil || out != CancelRequested {
		t.Fatalf("same-tenant cancel = %q, %v; want requested", out, err)
	}
	info, err = j.GetRun(ctx, "run_tenant_b")
	if err != nil {
		t.Fatal(err)
	}
	if !info.CancelRequested {
		t.Fatalf("same-tenant cancel did not set flag: %+v", info)
	}
}

func TestFinalizeCancel(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_c", "cancel-demo", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	seedRun(t, j, "run_x", "suspended")
	if _, err := j.ScheduleSleep(ctx, "run_x", "wait", time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := j.FinalizeCancel(ctx, "run_x"); err != nil {
		t.Fatal(err)
	}
	if info, _ := j.GetRun(ctx, "run_x"); info.Status != "cancelled" {
		t.Fatalf("status = %q, want cancelled", info.Status)
	}
	if due, _ := j.FindDueSchedules(ctx, time.Now().UTC(), 10); len(due) != 0 {
		t.Fatalf("schedule should be fired, %d due", len(due))
	}
	// Idempotent on a terminal run.
	if err := j.FinalizeCancel(ctx, "run_x"); err != nil {
		t.Fatalf("second finalize: %v", err)
	}
}

func TestRunLogsRoundTrip(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_c", "cancel-demo", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	seedRun(t, j, "run_logs", "running")

	if got, _ := j.GetRunLogs(ctx, "run_logs"); len(got) != 0 {
		t.Fatalf("no logs yet, got %v", got)
	}
	lines := []string{"line one", "line two", "line three"}
	if err := j.SaveRunLogs(ctx, "run_logs", lines); err != nil {
		t.Fatal(err)
	}
	got, err := j.GetRunLogs(ctx, "run_logs")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != "line one" || got[2] != "line three" {
		t.Fatalf("GetRunLogs = %v", got)
	}
	// Idempotent re-flush (the (run_id, seq) key swallows duplicates).
	if err := j.SaveRunLogs(ctx, "run_logs", lines); err != nil {
		t.Fatalf("re-save: %v", err)
	}
	if got, _ := j.GetRunLogs(ctx, "run_logs"); len(got) != 3 {
		t.Fatalf("re-save changed count: %v", got)
	}
	if err := j.SaveRunLogs(ctx, "run_logs", []string{"retry line"}); err != nil {
		t.Fatalf("save retry tail: %v", err)
	}
	if got, _ := j.GetRunLogs(ctx, "run_logs"); len(got) != 4 || got[3] != "retry line" {
		t.Fatalf("retry tail was not appended: %v", got)
	}
}
