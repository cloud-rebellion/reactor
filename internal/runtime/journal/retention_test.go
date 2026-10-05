package journal

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func setRunTimes(t *testing.T, j *Journal, ctx context.Context, runID string, ts time.Time) {
	t.Helper()
	v := j.formatTime(ts)
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE runs SET created_at = $1, finished_at = $2 WHERE id = $3`), v, v, runID); err != nil {
		t.Fatal(err)
	}
}

func TestPurgeTerminalRunsOlderThan(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	mkWorkflowTenant(t, j, ctx, "wf_r", "r")

	old := time.Now().UTC().Add(-30 * 24 * time.Hour)
	// Old finished run, with a dead_letter row (no FK cascade -> must be
	// deleted explicitly, otherwise the purge would FK-violate).
	if err := j.CreateRun(ctx, "old", "wf_r", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	_ = j.MarkRunFinished(ctx, "old", "failed_dlq")
	setRunTimes(t, j, ctx, "old", old)
	if _, err := j.db.ExecContext(ctx, j.bind(
		`INSERT INTO dead_letter (id, run_id, step_name, error_text, payload, moved_at) VALUES ($1,$2,$3,$4,$5,$6)`),
		"dl1", "old", "step", "boom", outputArg(json.RawMessage(`{}`), j.engine), j.now()); err != nil {
		t.Fatal(err)
	}
	// Recent finished run + a still-running run: both must survive.
	if err := j.CreateRun(ctx, "recent", "wf_r", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	_ = j.MarkRunFinished(ctx, "recent", "succeeded")
	if err := j.CreateRun(ctx, "live", "wf_r", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	setRunTimes(t, j, ctx, "live", old) // old, but still running -> not purged

	n, err := j.PurgeTerminalRunsOlderThan(ctx, time.Now().UTC().Add(-7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("purged %d, want 1 (only the old terminal run)", n)
	}
	survivors := map[string]bool{}
	for _, id := range []string{"old", "recent", "live"} {
		var x string
		err := j.db.QueryRowContext(ctx, j.bind(`SELECT id FROM runs WHERE id = $1`), id).Scan(&x)
		survivors[id] = err == nil
	}
	if survivors["old"] || !survivors["recent"] || !survivors["live"] {
		t.Fatalf("purge kept the wrong rows: %v", survivors)
	}
}

func TestRetentionPreservesUnresolvedMailSendUntilProviderAcceptanceIsRecorded(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 1, 3, "private-key", "input"); err != nil {
		t.Fatal(err)
	}
	admission, err := j.AdmitMailSend(ctx, "run_1", "", "send", 1, 1, "private-key", mailTestDigest,
		MailSendTarget{ProviderID: "google", ConnectionID: "conn_retention"})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, "run_1", "failed"); err != nil {
		t.Fatal(err)
	}
	setRunTimes(t, j, ctx, "run_1", time.Now().UTC().Add(-30*24*time.Hour))
	cutoff := time.Now().UTC().Add(-7 * 24 * time.Hour)
	if n, err := j.PurgeTerminalRunsOlderThan(ctx, cutoff); err != nil || n != 0 {
		t.Fatalf("unresolved send run purged: %d, %v", n, err)
	}
	if _, err := j.GetRun(ctx, "run_1"); err != nil {
		t.Fatalf("run with admitted mail send lost: %v", err)
	}
	if err := j.ConfirmMailSend(ctx, admission.IntentID, "google", "accepted-id"); err != nil {
		t.Fatal(err)
	}
	if n, err := j.PurgeTerminalRunsOlderThan(ctx, cutoff); err != nil || n != 1 {
		t.Fatalf("confirmed send run retention = %d, %v", n, err)
	}
	var remaining int
	if err := j.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mail_send_intents WHERE run_id = 'run_1'`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("orphaned send intents after retention = %d, %v", remaining, err)
	}
}

func TestPurgeTerminalRunsBatchesResumeAndKeepUsage(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	mkWorkflowTenant(t, j, ctx, "wf_retention_batch", "retention-batch")
	old := time.Now().UTC().Add(-30 * 24 * time.Hour)
	cutoff := time.Now().UTC().Add(-7 * 24 * time.Hour)
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("retention_old_%02d", i)
		if err := j.CreateRun(ctx, id, "wf_retention_batch", "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if _, err := j.RecordStepStart(ctx, id, "old-step", 1, "old-key", "old-hash"); err != nil {
				t.Fatal(err)
			}
			if _, err := j.db.ExecContext(ctx, j.bind(`INSERT INTO run_logs (run_id, seq, line) VALUES ($1,$2,$3)`), id, 1, "old log"); err != nil {
				t.Fatal(err)
			}
		}
		if err := j.MarkRunFinished(ctx, id, "succeeded"); err != nil {
			t.Fatal(err)
		}
		setRunTimes(t, j, ctx, id, old)
	}
	// A newer child of the oldest run must survive even when its parent is
	// removed in an earlier batch. Its lineage is detached in that batch.
	if err := j.CreateRun(ctx, "retention_child", "wf_retention_batch", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE runs SET parent_run_id = $1 WHERE id = $2`), "retention_old_00", "retention_child"); err != nil {
		t.Fatal(err)
	}
	var usageBefore int
	if err := j.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM run_usage WHERE tenant_id = 'retention-batch'`).Scan(&usageBefore); err != nil {
		t.Fatal(err)
	}
	if usageBefore != 5 {
		t.Fatalf("usage before purge = %d, want 5", usageBefore)
	}

	n, err := j.purgeTerminalRunsOlderThan(ctx, cutoff, 2, 1)
	if err != nil || n != 2 {
		t.Fatalf("first bounded purge = %d, %v; want two", n, err)
	}
	var remaining int
	if err := j.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs WHERE id LIKE 'retention_old_%'`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 3 {
		t.Fatalf("first batch left %d old runs, want 3", remaining)
	}
	for _, table := range []string{"steps", "run_logs", "terminal_effects"} {
		if err := j.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE run_id = 'retention_old_00'`).Scan(&remaining); err != nil || remaining != 0 {
			t.Fatalf("orphaned %s after first batch = %d, %v", table, remaining, err)
		}
	}
	var parent sql.NullString
	if err := j.db.QueryRowContext(ctx, `SELECT parent_run_id FROM runs WHERE id = 'retention_child'`).Scan(&parent); err != nil || parent.Valid {
		t.Fatalf("surviving child parent = %+v, %v; want detached", parent, err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if n, err := j.purgeTerminalRunsOlderThan(cancelled, cutoff, 2, 4); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled purge = %d, %v", n, err)
	}
	if err := j.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs WHERE id LIKE 'retention_old_%'`).Scan(&remaining); err != nil || remaining != 3 {
		t.Fatalf("cancelled purge changed remaining rows: %d, %v", remaining, err)
	}
	if n, err := j.purgeTerminalRunsOlderThan(ctx, cutoff, 2, 1); err != nil || n != 2 {
		t.Fatalf("resumed second batch = %d, %v", n, err)
	}
	if n, err := j.purgeTerminalRunsOlderThan(ctx, cutoff, 2, 1); err != nil || n != 1 {
		t.Fatalf("resumed final batch = %d, %v", n, err)
	}
	if n, err := j.purgeTerminalRunsOlderThan(ctx, cutoff, 2, 1); err != nil || n != 0 {
		t.Fatalf("idempotent purge = %d, %v", n, err)
	}
	if err := j.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM run_usage WHERE tenant_id = 'retention-batch'`).Scan(&remaining); err != nil || remaining != usageBefore {
		t.Fatalf("run usage after purge = %d, %v; want %d", remaining, err, usageBefore)
	}
	if _, err := j.GetRun(ctx, "retention_child"); err != nil {
		t.Fatalf("recent child was purged: %v", err)
	}
}

func TestRetentionBatchQueriesUseSQLiteIndexes(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	cut := j.formatTime(time.Now().UTC().Add(-7 * 24 * time.Hour))
	for _, tc := range []struct {
		name, query, index string
		args               []any
		ordered            bool
	}{
		{"workflow candidates", `SELECT id FROM runs INDEXED BY runs_terminal_retention_idx WHERE ` + terminalRunPredicate + ` ORDER BY COALESCE(finished_at, created_at), id LIMIT $2`, "runs_terminal_retention_idx", []any{cut, 128}, true},
		{"command candidates", `SELECT id FROM command_runs INDEXED BY command_runs_terminal_retention_idx WHERE ` + commandRunTerminalPredicate + ` ORDER BY COALESCE(finished_at, created_at), id LIMIT $2`, "command_runs_terminal_retention_idx", []any{cut, 128}, true},
		{"workflow children", `UPDATE runs SET parent_run_id = NULL WHERE parent_run_id IN ($1)`, "runs_parent_retention_idx", []any{"old-parent"}, false},
		{"command retries", `UPDATE command_runs SET retry_of = NULL WHERE retry_of IN ($1)`, "command_runs_retry_retention_idx", []any{"old-command"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := j.db.QueryContext(ctx, j.bind(`EXPLAIN QUERY PLAN `+tc.query), tc.args...)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var plan strings.Builder
			for rows.Next() {
				var id, parent, unused int
				var detail string
				if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
					t.Fatal(err)
				}
				plan.WriteString(detail)
				plan.WriteByte('\n')
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(plan.String(), tc.index) {
				t.Fatalf("query does not use %s; plan: %s", tc.index, plan.String())
			}
			if tc.ordered && strings.Contains(plan.String(), "TEMP B-TREE") {
				t.Fatalf("candidate query sorts beyond the retention index: %s", plan.String())
			}
		})
	}
}

func TestExportAndEraseTenant(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	mkWorkflowTenant(t, j, ctx, "wf_e", "erase-me")
	if err := j.CreateRun(ctx, "e1", "wf_e", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	_ = j.MarkRunFinished(ctx, "e1", "succeeded")
	if err := j.MoveStepToDeadLetter(ctx, "e1", "check", "failed", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check status","timeout_seconds":30,"expected_exit_code":0}]}`)
	command, err := j.CreateCommandAutomation(ctx, "erase-me", "cmd_e", "nightly-check", "Check host", "ops-host", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.AppendCommandAutomationVersion(ctx, "erase-me", command.ID, "alice", 1, definition); err != nil {
		t.Fatal(err)
	}

	// Export gathers the tenant's workflows + runs.
	exp, err := j.ExportTenantData(ctx, "erase-me", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(exp.Workflows) != 1 || len(exp.Runs) != 1 {
		t.Fatalf("export = %d workflows / %d runs, want 1/1", len(exp.Workflows), len(exp.Runs))
	}
	if len(exp.CommandAutomations) != 1 || len(exp.CommandAutomations[0].Versions) != 2 {
		t.Fatalf("command export = %+v, want one plan with two versions", exp.CommandAutomations)
	}

	// Erase removes the run history (+ usage), leaves other tenants alone.
	if err := j.CreateRun(ctx, "keep", "wf_1", "manual", json.RawMessage(`{}`)); err != nil { // wf_1 = seeded default tenant
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "active", "wf_1", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.EraseTenantData(ctx, "default"); err == nil || !errors.Is(err, ErrTenantErasureActive) {
		t.Fatalf("active tenant erasure error = %v, want ErrTenantErasureActive", err)
	}
	if err := j.MarkRunFinished(ctx, "active", "succeeded"); err != nil {
		t.Fatal(err)
	}
	er, err := j.EraseTenantData(ctx, "erase-me")
	if err != nil {
		t.Fatal(err)
	}
	if er.Runs != 1 || er.DeadLetters != 1 {
		t.Fatalf("erased runs=%d command_runs=%d dead_letters=%d, want 1/0/1", er.Runs, er.CommandRuns, er.DeadLetters)
	}
	if n, _ := j.CountRunningForTenant(ctx, "erase-me"); n != 0 {
		t.Fatalf("tenant still has runs after erase")
	}
	var keep string
	if err := j.db.QueryRowContext(ctx, j.bind(`SELECT id FROM runs WHERE id = 'keep'`)).Scan(&keep); err != nil {
		t.Fatal("erase wrongly removed another tenant's run")
	}
}

func TestCommandRunExportErasureAndTenantScope(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const tenantID = "command-history"
	definition := []byte(`{"steps":[{"name":"check","command":"echo command-value","purpose":"Check status","timeout_seconds":30,"expected_exit_code":0}]}`)
	plan, err := j.CreateCommandAutomation(ctx, tenantID, "cmd_history", "history-plan", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, plan)
	gate := sha256.Sum256([]byte("command-history-gates"))
	admission := boundCommandRunAdmission(t, tenantID, plan.ID, 1, definition, hex.EncodeToString(gate[:]), "alice")
	run, err := j.CreateCommandRun(ctx, tenantID, "cmd_history_run", plan.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimCommandRun(ctx, run.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	step, err := j.ClaimCommandRunStep(ctx, run.ID, "worker-a", claimed.ClaimToken, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.RecordCommandRunStepResult(ctx, run.ID, "worker-a", claimed.ClaimToken, 1, step.Attempt, 0, []byte("safe output"), nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := j.FinishCommandRun(ctx, run.ID, "worker-a", claimed.ClaimToken, CommandRunSucceeded, ""); err != nil {
		t.Fatal(err)
	}

	page, err := j.ExportTenantDataPage(ctx, tenantID, TenantExportPageOptions{
		WorkflowLimit: 1, CommandAutomationLimit: 1, CommandVersionLimit: 1, RunLimit: 1,
		CommandRunLimit: 1, CommandStepLimit: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.CommandRuns) != 1 || page.CommandRuns[0].Run.ID != run.ID || len(page.CommandRuns[0].Steps) != 1 || page.CommandRuns[0].Steps[0].CommandSHA256 == "" {
		t.Fatalf("command export page = %+v", page.CommandRuns)
	}
	raw, err := json.Marshal(page.CommandRuns)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "echo command-value") || strings.Contains(string(raw), "claim-token") {
		t.Fatalf("command export leaked command or claim data: %s", raw)
	}
	foreign, err := j.ExportTenantDataPage(ctx, "other-command-history", TenantExportPageOptions{
		WorkflowLimit: 1, CommandAutomationLimit: 1, CommandVersionLimit: 1, RunLimit: 1,
		CommandRunLimit: 1, CommandStepLimit: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(foreign.CommandRuns) != 0 {
		t.Fatalf("foreign command export leaked runs: %+v", foreign.CommandRuns)
	}
	// Keep a terminal run in another tenant so erasure proves the command-run
	// predicate is tenant-scoped as well as the legacy workflow-run predicate.
	foreignPlan, err := j.CreateCommandAutomation(ctx, "other-command-history", "cmd_history_other", "other-plan", "", "local", "bob", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, foreignPlan)
	foreignGate := sha256.Sum256([]byte("other-command-history-gates"))
	foreignRun, err := j.CreateCommandRun(ctx, "other-command-history", "cmd_history_other_run", foreignPlan.ID, 1, boundCommandRunAdmission(t, "other-command-history", foreignPlan.ID, 1, definition, hex.EncodeToString(foreignGate[:]), "bob"))
	if err != nil {
		t.Fatal(err)
	}
	foreignClaim, err := j.ClaimCommandRun(ctx, foreignRun.ID, "worker-b", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	foreignStep, err := j.ClaimCommandRunStep(ctx, foreignRun.ID, "worker-b", foreignClaim.ClaimToken, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.RecordCommandRunStepResult(ctx, foreignRun.ID, "worker-b", foreignClaim.ClaimToken, 1, foreignStep.Attempt, 0, nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := j.FinishCommandRun(ctx, foreignRun.ID, "worker-b", foreignClaim.ClaimToken, CommandRunSucceeded, ""); err != nil {
		t.Fatal(err)
	}
	activeRun, err := j.CreateCommandRun(ctx, tenantID, "cmd_history_active", plan.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := j.PreviewTenantErasure(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if preview.CommandRuns != 2 || preview.ActiveCommandRuns != 1 || preview.Erasable {
		t.Fatalf("command erasure preview = %+v", preview)
	}
	if _, err := j.EraseTenantData(ctx, tenantID); !errors.Is(err, ErrTenantErasureActive) {
		t.Fatalf("active command erasure = %v, want ErrTenantErasureActive", err)
	}
	activeClaim, err := j.ClaimCommandRun(ctx, activeRun.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.FinishCommandRun(ctx, activeRun.ID, "worker-a", activeClaim.ClaimToken, CommandRunCancelled, "operator cancelled"); err != nil {
		t.Fatal(err)
	}
	erasure, err := j.EraseTenantData(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if erasure.CommandRuns != 2 {
		t.Fatalf("command erasure = %+v, want two command runs", erasure)
	}
	if _, err := j.GetCommandRunForTenant(ctx, tenantID, run.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("command run survived erasure: %v", err)
	}
	if _, err := j.GetCommandAutomation(ctx, tenantID, plan.ID); err != nil {
		t.Fatalf("command plan should remain after run erasure: %v", err)
	}
	if _, err := j.GetCommandRunForTenant(ctx, "other-command-history", foreignRun.ID); err != nil {
		t.Fatalf("foreign command run was erased: %v", err)
	}
}

func TestPurgeTerminalRunsIncludesCommandRunHistory(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check status","timeout_seconds":30,"expected_exit_code":0}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "purge-command", "cmd_purge", "purge-plan", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, plan)
	gate := sha256.Sum256([]byte("purge-command-gates"))
	run, err := j.CreateCommandRun(ctx, "purge-command", "cmd_purge_run", plan.ID, 1, boundCommandRunAdmission(t, "purge-command", plan.ID, 1, definition, hex.EncodeToString(gate[:]), "alice"))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimCommandRun(ctx, run.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	step, err := j.ClaimCommandRunStep(ctx, run.ID, "worker-a", claimed.ClaimToken, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.RecordCommandRunStepResult(ctx, run.ID, "worker-a", claimed.ClaimToken, 1, step.Attempt, 0, nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := j.FinishCommandRun(ctx, run.ID, "worker-a", claimed.ClaimToken, CommandRunSucceeded, ""); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-30 * 24 * time.Hour)
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE command_runs SET created_at = $1, finished_at = $2 WHERE id = $3`), j.formatTime(old), j.formatTime(old), run.ID); err != nil {
		t.Fatal(err)
	}
	n, err := j.PurgeTerminalRunsOlderThan(ctx, time.Now().UTC().Add(-7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("purge removed %d rows, want one command run", n)
	}
	if _, err := j.GetCommandRunForTenant(ctx, "purge-command", run.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("purged command run still present: %v", err)
	}
}

func TestPurgeTerminalCommandRunsBatchesAndDetachesRetry(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check status","timeout_seconds":30,"expected_exit_code":0}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "retention-command-batch", "cmd_retention_batch", "retention-batch", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	old := j.formatTime(time.Now().UTC().Add(-30 * 24 * time.Hour))
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("cmd_retention_old_%02d", i)
		if _, err := j.db.ExecContext(ctx, j.bind(`INSERT INTO command_runs
			(id, tenant_id, automation_id, automation_version, definition_sha256, actor_id, admission_json, status, created_at, finished_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`),
			id, "retention-command-batch", plan.ID, 1, strings.Repeat("a", 64), "alice", "{}", CommandRunSucceeded, old, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`INSERT INTO command_runs
		(id, tenant_id, automation_id, automation_version, definition_sha256, actor_id, admission_json, status, retry_of, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`),
		"cmd_retention_retry", "retention-command-batch", plan.ID, 1, strings.Repeat("a", 64), "alice", "{}", CommandRunQueued, "cmd_retention_old_00", j.now(), j.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`INSERT INTO command_run_steps
		(run_id, step_seq, step_name, command_sha256, expected_exit_code, timeout_seconds, status, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`),
		"cmd_retention_old_00", 1, "check", strings.Repeat("b", 64), 0, 30, CommandRunStepSucceeded, j.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`INSERT INTO command_run_step_attempts
		(run_id, step_seq, attempt, claim_owner, claim_token, status, started_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`),
		"cmd_retention_old_00", 1, 1, "worker-a", "old-claim", CommandRunStepSucceeded, old, old); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().UTC().Add(-7 * 24 * time.Hour)
	if n, err := j.purgeTerminalRunsOlderThan(ctx, cutoff, 1, 1); err != nil || n != 1 {
		t.Fatalf("first command batch = %d, %v", n, err)
	}
	var remaining int
	if err := j.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM command_runs WHERE id LIKE 'cmd_retention_old_%'`).Scan(&remaining); err != nil || remaining != 2 {
		t.Fatalf("remaining command runs = %d, %v; want 2", remaining, err)
	}
	for _, table := range []string{"command_run_steps", "command_run_step_attempts"} {
		if err := j.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE run_id = 'cmd_retention_old_00'`).Scan(&remaining); err != nil || remaining != 0 {
			t.Fatalf("orphaned %s after first command batch = %d, %v", table, remaining, err)
		}
	}
	var retryOf sql.NullString
	if err := j.db.QueryRowContext(ctx, `SELECT retry_of FROM command_runs WHERE id = 'cmd_retention_retry'`).Scan(&retryOf); err != nil || retryOf.Valid {
		t.Fatalf("surviving retry lineage = %+v, %v; want detached", retryOf, err)
	}
	if n, err := j.purgeTerminalRunsOlderThan(ctx, cutoff, 1, 2); err != nil || n != 2 {
		t.Fatalf("resumed command batches = %d, %v", n, err)
	}
	if err := j.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM command_runs WHERE id = 'cmd_retention_retry'`).Scan(&remaining); err != nil || remaining != 1 {
		t.Fatalf("active retry survived = %d, %v; want 1", remaining, err)
	}
}

func TestPurgeDetachesSurvivingCommandRetryLineage(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check status","timeout_seconds":30,"expected_exit_code":0}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "purge-retry", "cmd_purge_retry", "purge-retry-plan", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, plan)
	gate := sha256.Sum256([]byte("purge-retry-gates"))
	admission := boundCommandRunAdmission(t, "purge-retry", plan.ID, 1, definition, hex.EncodeToString(gate[:]), "alice")
	source, err := j.CreateCommandRun(ctx, "purge-retry", "cmd_purge_retry_source", plan.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimCommandRun(ctx, source.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.FinishCommandRun(ctx, source.ID, "worker-a", claimed.ClaimToken, CommandRunFailed, "source failed"); err != nil {
		t.Fatal(err)
	}
	retry, err := j.CreateCommandRunWithRetryOf(ctx, "purge-retry", "cmd_purge_retry_survivor", plan.ID, 1, admission, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-30 * 24 * time.Hour)
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE command_runs SET created_at = $1, finished_at = $2 WHERE id = $3`), j.formatTime(old), j.formatTime(old), source.ID); err != nil {
		t.Fatal(err)
	}
	n, err := j.PurgeTerminalRunsOlderThan(ctx, time.Now().UTC().Add(-7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("purge removed %d rows, want one source command run", n)
	}
	if _, err := j.GetCommandRunForTenant(ctx, "purge-retry", source.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("purged retry source still present: %v", err)
	}
	retained, err := j.GetCommandRunForTenant(ctx, "purge-retry", retry.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retained.RetryOf != "" {
		t.Fatalf("surviving retry retained dangling lineage: %+v", retained)
	}
}

func TestTenantExportPropagatesUsageReadFailure(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const tenantID = "export-usage-error"
	if err := j.CreateWorkflowInTenant(ctx, "wf_export_usage_error", "export-usage-error", "h", "0.1.0", json.RawMessage(`{}`), tenantID); err != nil {
		t.Fatal(err)
	}

	// The export's workflow, command-plan, and run sections are readable even
	// when the metering ledger is unavailable. A successful export must not
	// silently turn that missing usage section into an all-zero receipt.
	if _, err := j.db.ExecContext(ctx, `DROP TABLE run_usage`); err != nil {
		t.Fatal(err)
	}
	page, err := j.ExportTenantDataPage(ctx, tenantID, TenantExportPageOptions{
		WorkflowLimit: 1, CommandAutomationLimit: 1, CommandVersionLimit: 1, RunLimit: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "export tenant usage") {
		t.Fatalf("paged export error = %v, want usage read failure", err)
	}
	if page.TenantID != "" || page.Usage.Runs != 0 {
		t.Fatalf("paged export returned partial receipt after usage failure: %+v", page)
	}
	legacy, err := j.ExportTenantData(ctx, tenantID, 100)
	if err == nil || !strings.Contains(err.Error(), "export tenant usage") {
		t.Fatalf("legacy export error = %v, want usage read failure", err)
	}
	if legacy.TenantID != "" || legacy.Usage.Runs != 0 {
		t.Fatalf("legacy export returned partial receipt after usage failure: %+v", legacy)
	}
}

func TestTenantErasureSerializesPinnedAdmissionAndLeavesWorkflowUsable(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const tenantID = "erase-order-tenant"
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_erase_order", "erase-order", "h", "0.1.0", digest, json.RawMessage(`{}`), tenantID); err != nil {
		t.Fatal(err)
	}

	// A run admitted before erasure is visible to the same transaction and
	// blocks the destructive operation. This is the dispatch-first ordering.
	if err := j.CreateRunPinnedIfEnabled(ctx, "run_before_erase", "wf_erase_order", "manual", json.RawMessage(`{}`), 1, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := j.EraseTenantData(ctx, tenantID); !errors.Is(err, ErrTenantErasureActive) {
		t.Fatalf("erase with an admitted run = %v, want ErrTenantErasureActive", err)
	}
	if err := j.MarkRunFinished(ctx, "run_before_erase", "succeeded"); err != nil {
		t.Fatal(err)
	}

	// Once the terminal history is erased, the retained workflow remains
	// enabled and a later event creates a new, post-erasure run. The workflow
	// lock in EraseTenantData is the same lock used by pinned live admission,
	// so a concurrent dispatch cannot commit inside the erase transaction.
	erased, err := j.EraseTenantData(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if erased.Runs == 0 {
		t.Fatalf("erasure removed no runs: %+v", erased)
	}
	if err := j.CreateRunPinnedIfEnabled(ctx, "run_after_erase", "wf_erase_order", "manual", json.RawMessage(`{}`), 1, digest); err != nil {
		t.Fatalf("post-erasure admission = %v", err)
	}
	if run, err := j.GetRun(ctx, "run_after_erase"); err != nil || run.TenantID != tenantID || run.Status != "running" {
		t.Fatalf("post-erasure run = %+v, %v", run, err)
	}
}

func TestRecordRunUsageAfterTenantErasureCannotRecreateUsage(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const tenantID = "meter-erased-tenant"
	if err := j.CreateWorkflowInTenant(ctx, "wf_meter_erased", "meter-erased", "h", "0.1.0", json.RawMessage(`{}`), tenantID); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_meter_erased", "wf_meter_erased", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, "run_meter_erased", "succeeded"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.EraseTenantData(ctx, tenantID); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordRunUsage(ctx, "run_meter_erased", "succeeded"); err == nil {
		t.Fatal("usage recorder accepted a run removed by tenant erasure")
	}
	var n int
	if err := j.db.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM run_usage WHERE tenant_id = $1`), tenantID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("late usage recorder recreated %d tenant usage row(s)", n)
	}
}

func TestPreviewTenantErasureIsScopedReadOnlyAndTracksActiveRuns(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	mkWorkflowTenant(t, j, ctx, "wf_preview", "preview-me")
	mkWorkflowTenant(t, j, ctx, "wf_preview_other", "other")
	if err := j.CreateRun(ctx, "preview_done", "wf_preview", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, "preview_done", "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(
		`INSERT INTO dead_letter (id, run_id, step_name, error_text, payload, moved_at) VALUES ($1,$2,$3,$4,$5,$6)`),
		"preview-dl", "preview_done", "step", "boom", outputArg(json.RawMessage(`{}`), j.engine), j.now()); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "preview_active", "wf_preview", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "other_run", "wf_preview_other", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}

	preview, err := j.PreviewTenantErasure(ctx, "preview-me")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Runs != 2 || preview.ActiveRuns != 1 || preview.DeadLetters != 1 || preview.Usage != 1 || preview.Erasable {
		t.Fatalf("preview with active run = %+v, want 2 runs/1 active/1 dead-letter/1 usage/not erasable", preview)
	}
	if n, err := j.CountRuns(ctx, RunFilter{TenantID: "preview-me"}); err != nil || n != 2 {
		t.Fatalf("preview mutated runs: count=%d err=%v", n, err)
	}

	if err := j.MarkRunFinished(ctx, "preview_active", "succeeded"); err != nil {
		t.Fatal(err)
	}
	preview, err = j.PreviewTenantErasure(ctx, "preview-me")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Runs != 2 || preview.ActiveRuns != 0 || !preview.Erasable {
		t.Fatalf("preview after finishing run = %+v, want 2 runs/0 active/erasable", preview)
	}
	other, err := j.PreviewTenantErasure(ctx, "other")
	if err != nil {
		t.Fatal(err)
	}
	if other.Runs != 1 || other.ActiveRuns != 1 || other.DeadLetters != 0 || other.Usage != 0 {
		t.Fatalf("preview leaked tenant rows: %+v", other)
	}
}
