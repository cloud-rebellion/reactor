package journal

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// seedDueSleeps creates a workflow + n suspended runs in tenantID, each with a
// due sleep. base controls wake_at ordering so a test can make one tenant's rows
// uniformly older than another's.
func seedDueSleeps(t *testing.T, j *Journal, tenantID string, n int, base time.Time) {
	t.Helper()
	ctx := context.Background()
	wf := "wf_" + tenantID
	if err := j.CreateWorkflowInTenant(ctx, wf, "flow-"+tenantID, "h", "0.1.0", json.RawMessage(`{}`), tenantID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		runID := fmt.Sprintf("run_%s_%d", tenantID, i)
		if err := j.CreateRun(ctx, runID, wf, "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := j.ScheduleSleep(ctx, runID, "wait", base.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
		// CreateRun inserts status 'running', but a run parked on a sleep is
		// 'suspended' in production (supervisor.go sets it when it suspends).
		// The fixture has to match, because the fair query counts only 'running'
		// against max_concurrent_runs: leaving these as 'running' would make a
		// sleeping run consume its own tenant's concurrency slot and no wake-up
		// could ever be granted.
		if _, err := j.db.ExecContext(ctx, j.bind(
			`UPDATE runs SET status = 'suspended' WHERE id = $1`), runID); err != nil {
			t.Fatal(err)
		}
	}
}

// TestFindDueSchedulesIsFairAcrossTenants is the starvation repro.
//
// The query was `WHERE fired = false AND wake_at <= now ORDER BY wake_at ASC
// LIMIT n`, with no tenant dimension at all. One tenant with a backlog of due
// sleeps older than everyone else's fills the entire batch on every tick, so no
// other tenant's suspended run resumes until that backlog drains.
//
// This is worse than queue starvation: these runs are already mid-execution, so
// from the other tenant's side their workflow has simply hung.
func TestFindDueSchedulesIsFairAcrossTenants(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	base := time.Now().UTC().Add(-2 * time.Hour)
	// The noisy tenant's sleeps are ALL older than the quiet one's.
	seedDueSleeps(t, j, "noisy", 60, base)
	seedDueSleeps(t, j, "quiet", 3, base.Add(time.Hour))

	due, err := j.FindDueSchedules(ctx, time.Now().UTC(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) == 0 {
		t.Fatal("nothing due; the fixture is wrong")
	}

	byTenant := map[string]int{}
	for _, s := range due {
		_, tenant, rerr := j.RunIdentity(ctx, s.RunID)
		if rerr != nil {
			t.Fatal(rerr)
		}
		byTenant[tenant]++
	}
	if byTenant["quiet"] == 0 {
		t.Fatalf("STARVATION: batch of %d is %d noisy / 0 quiet. The quiet tenant's suspended runs never resume while the noisy tenant has an older backlog.", len(due), byTenant["noisy"])
	}
	// The round-robin interleave should serve the small tenant COMPLETELY, not
	// just give it a token slot: it has 3 due rows and the batch holds 10, so
	// ranks 1-3 of both tenants fit and the noisy tenant takes the remainder.
	// Asserting only "> 0" would pass on a query that merely reordered slightly.
	if byTenant["quiet"] != 3 {
		t.Fatalf("quiet tenant got %d of its 3 due rows in a batch of %d (noisy=%d); the interleave is not round-robin",
			byTenant["quiet"], len(due), byTenant["noisy"])
	}
	if len(due) != 10 {
		t.Fatalf("batch size = %d, want the full limit of 10; fairness must not cost throughput", len(due))
	}
}

// TestFindDueSchedulesSkipsDisabledTenants pins the other half of the fairness
// contract the run queue already honours: a disabled tenant must not be
// scheduled. Resumption went through a different path from
// CheckWorkflowEnqueueAllowed, so disabling a tenant stopped new runs while its
// suspended ones kept waking up and executing.
func TestFindDueSchedulesSkipsDisabledTenants(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	base := time.Now().UTC().Add(-time.Hour)
	seedDueSleeps(t, j, "banned", 4, base)
	seedDueSleeps(t, j, "ok", 4, base.Add(time.Minute))

	if _, err := j.db.ExecContext(ctx, j.bind(
		`INSERT INTO tenants (tenant_id, disabled) VALUES ($1, $2)`), "banned", j.boolValue(true)); err != nil {
		t.Fatal(err)
	}

	due, err := j.FindDueSchedules(ctx, time.Now().UTC(), 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range due {
		_, tenant, rerr := j.RunIdentity(ctx, s.RunID)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if tenant == "banned" {
			t.Fatalf("a DISABLED tenant's suspended run was scheduled to resume (schedule %s, run %s); disabling stops new runs but not wake-ups", s.ID, s.RunID)
		}
	}
	if len(due) == 0 {
		t.Fatal("the enabled tenant got nothing; the filter is too aggressive")
	}
}

// Disabling one workflow is also an execution kill switch for work already
// parked on Sleep/AwaitSignal. The scheduler must leave the row pending and the
// run suspended, so a later re-enable resumes it instead of dropping it.
func TestFindDueSchedulesSkipsDisabledWorkflowUntilReenabled(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	seedDueSleeps(t, j, "paused", 1, time.Now().UTC().Add(-time.Hour))
	if err := j.SetWorkflowEnabled(ctx, "wf_paused", false); err != nil {
		t.Fatal(err)
	}
	due, err := j.FindDueSchedules(ctx, time.Now().UTC(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 0 {
		t.Fatalf("disabled workflow returned %d due schedules; want none", len(due))
	}
	// Also exercise the atomic claim gate directly. This models a scheduler
	// that selected the row just before the disable transaction committed.
	pending, err := j.FindLatestSleepSchedule(ctx, "run_paused_0", "wait")
	if err != nil {
		t.Fatal(err)
	}
	if claimed, err := j.ClaimScheduleResume(ctx, pending.ID, false); err != nil || claimed {
		t.Fatalf("disabled workflow direct resume claim = %v, %v; want false", claimed, err)
	}
	info, err := j.GetRun(ctx, "run_paused_0")
	if err != nil || info.Status != "suspended" {
		t.Fatalf("disabled workflow run changed = %+v, %v", info, err)
	}
	schedule, err := j.FindLatestSleepSchedule(ctx, "run_paused_0", "wait")
	if err != nil || schedule.Fired {
		t.Fatalf("disabled workflow schedule was consumed = %+v, %v", schedule, err)
	}

	if err := j.SetWorkflowEnabled(ctx, "wf_paused", true); err != nil {
		t.Fatal(err)
	}
	due, err = j.FindDueSchedules(ctx, time.Now().UTC(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].ID != schedule.ID {
		t.Fatalf("re-enabled workflow due schedules = %+v; want %s", due, schedule.ID)
	}
}

// TestFindDueSchedulesHonoursConcurrencyCap covers the quota bypass. Resumption
// never went through CheckWorkflowEnqueueAllowed, so a tenant could exceed
// max_concurrent_runs simply by having its workflows sleep: the cap applied to
// admission and not to wake-ups.
//
// Semantics: a capped tenant's wake-up is DELAYED, not dropped, and the
// round-robin interleave keeps that delay from becoming starvation. The column
// defaults to 0 (unlimited), so an install that never set a cap is unaffected,
// which is what makes this safe to turn on for everyone.
func TestFindDueSchedulesHonoursConcurrencyCap(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	base := time.Now().UTC().Add(-time.Hour)
	seedDueSleeps(t, j, "capped", 5, base)

	// Cap of 2, with one run already running, leaves room for exactly one wake-up.
	if _, err := j.db.ExecContext(ctx, j.bind(
		`INSERT INTO tenants (tenant_id, max_concurrent_runs) VALUES ($1, $2)`), "capped", 2); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_capped_live", "wf_capped", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(
		`UPDATE runs SET status = 'running' WHERE id = $1`), "run_capped_live"); err != nil {
		t.Fatal(err)
	}

	due, err := j.FindDueSchedules(ctx, time.Now().UTC(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 {
		t.Fatalf("capped tenant got %d wake-ups; cap is 2 with 1 already running, so exactly 1 fits. A tenant that can wake unlimited sleeps has no enforceable concurrency cap.", len(due))
	}

	// Unlimited (the default, 0) must be unaffected, or this change would throttle
	// every existing install.
	seedDueSleeps(t, j, "uncapped", 5, base)
	due2, err := j.FindDueSchedules(ctx, time.Now().UTC(), 10)
	if err != nil {
		t.Fatal(err)
	}
	got := 0
	for _, s := range due2 {
		if _, tenant, _ := j.RunIdentity(ctx, s.RunID); tenant == "uncapped" {
			got++
		}
	}
	if got != 5 {
		t.Fatalf("uncapped tenant got %d of 5 due rows; max_concurrent_runs=0 must mean unlimited", got)
	}
}
