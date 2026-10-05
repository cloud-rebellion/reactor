package journal

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

func TestCommandExecutionFieldsSealedScopedAndReadableAfterRestart(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_crypto_plan", "crypto-plan", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, plan)
	admission := boundCommandRunAdmission(t, "acme", plan.ID, 1, definition, strings.Repeat("a", 64), "alice")
	run, err := j.CreateCommandRun(ctx, "acme", "cmdrun_crypto", plan.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{0x5a}, 32)
	if err := j.EnablePayloadEncryption(ctx, master, nil); err != nil {
		t.Fatal(err)
	}
	claim, err := j.ClaimCommandRun(ctx, run.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	step, err := j.ClaimCommandRunStep(ctx, run.ID, "worker-a", claim.ClaimToken, 1)
	if err != nil {
		t.Fatal(err)
	}
	const stdout = "synthetic-out-å界"
	const stderr = "synthetic-err-界"
	const stepError = "synthetic-step-error"
	const runError = "synthetic-run-error"
	if err := j.AppendCommandRunStepOutput(ctx, run.ID, "worker-a", claim.ClaimToken, 1, step.Attempt, "stdout", []byte(stdout)); err != nil {
		t.Fatal(err)
	}
	if err := j.AppendCommandRunStepOutput(ctx, run.ID, "worker-a", claim.ClaimToken, 1, step.Attempt, "stderr", []byte(stderr)); err != nil {
		t.Fatal(err)
	}
	live, err := j.ListCommandRunStepsForTenant(ctx, "acme", run.ID)
	if err != nil || len(live) != 1 || live[0].StdoutText != stdout || live[0].StderrText != stderr {
		t.Fatalf("live output = %+v, %v", live, err)
	}
	if err := j.RecordCommandRunStepResult(ctx, run.ID, "worker-a", claim.ClaimToken, 1, step.Attempt, 1, nil, nil, stepError); err != nil {
		t.Fatal(err)
	}
	if err := j.FinishCommandRun(ctx, run.ID, "worker-a", claim.ClaimToken, CommandRunFailed, runError); err != nil {
		t.Fatal(err)
	}

	var storedRun string
	var runVersion, runBytes int
	if err := j.db.QueryRowContext(ctx, `SELECT error_text, error_crypto_version, error_plaintext_bytes FROM command_runs WHERE id = ?`, run.ID).Scan(&storedRun, &runVersion, &runBytes); err != nil {
		t.Fatal(err)
	}
	if runVersion != 1 || runBytes != len(runError) || strings.Contains(storedRun, runError) || !payloadcrypto.IsByteEnvelope([]byte(storedRun)) {
		t.Fatalf("unsafe run error: version=%d bytes=%d stored=%q", runVersion, runBytes, storedRun)
	}
	for _, table := range []string{"command_run_steps", "command_run_step_attempts"} {
		var out, errOut, errText string
		var outVersion, errOutVersion, errorVersion, errorBytes int
		q := `SELECT stdout_text, stderr_text, error_text, stdout_crypto_version, stderr_crypto_version, error_crypto_version, error_plaintext_bytes FROM ` + table + ` WHERE run_id = ? AND step_seq = 1`
		if err := j.db.QueryRowContext(ctx, q, run.ID).Scan(&out, &errOut, &errText, &outVersion, &errOutVersion, &errorVersion, &errorBytes); err != nil {
			t.Fatal(err)
		}
		if outVersion != 1 || errOutVersion != 1 || errorVersion != 1 || errorBytes != len(stepError) || strings.Contains(out, stdout) || strings.Contains(errOut, stderr) || strings.Contains(errText, stepError) || !payloadcrypto.IsByteEnvelope([]byte(out)) || !payloadcrypto.IsByteEnvelope([]byte(errOut)) || !payloadcrypto.IsByteEnvelope([]byte(errText)) {
			t.Fatalf("unsafe %s fields: versions=%d/%d/%d bytes=%d", table, outVersion, errOutVersion, errorVersion, errorBytes)
		}
	}
	reader := New(j.db, EngineSQLite)
	if err := reader.LoadPayloadEncryption(ctx, master, nil); err != nil {
		t.Fatal(err)
	}
	gotRun, err := reader.GetCommandRunForTenant(ctx, "acme", run.ID)
	if err != nil || gotRun.ErrorText != runError {
		t.Fatalf("restarted run = %+v, %v", gotRun, err)
	}
	gotSteps, err := reader.ListCommandRunStepsForTenant(ctx, "acme", run.ID)
	if err != nil || len(gotSteps) != 1 || gotSteps[0].StdoutText != stdout || gotSteps[0].StderrText != stderr || gotSteps[0].ErrorText != stepError {
		t.Fatalf("restarted step = %+v, %v", gotSteps, err)
	}
	page, err := reader.ReadCommandRunDiagnosticPageForTenant(ctx, "acme", run.ID, CommandDiagnosticStdout, 1, 1, 2, 5)
	if err != nil || !bytes.Equal(page.Content, []byte(stdout)[2:7]) || page.TotalBytes != len(stdout) {
		t.Fatalf("decrypted page = %+v, %v", page, err)
	}
	if _, err := reader.ReadCommandRunDiagnosticPageForTenant(ctx, "other", run.ID, CommandDiagnosticStdout, 1, 1, 0, 5); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign diagnostic = %v", err)
	}
	unkeyed := New(j.db, EngineSQLite)
	if _, err := unkeyed.GetCommandRunForTenant(ctx, "acme", run.ID); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed run read = %v", err)
	}
	if _, err := unkeyed.ListCommandRunStepsForTenant(ctx, "acme", run.ID); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed step read = %v", err)
	}
	if _, err := unkeyed.ReadCommandRunDiagnosticPageForTenant(ctx, "acme", run.ID, CommandDiagnosticStdout, 1, 1, 0, 5); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed diagnostic = %v", err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE command_run_steps SET stdout_text = ?, stdout_crypto_version = 0 WHERE run_id = ? AND step_seq = 1`, "old-writer-private", run.ID); err == nil {
		t.Fatal("old writer downgraded encrypted command stdout")
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE command_runs SET error_text = ?, error_crypto_version = 0, error_plaintext_bytes = NULL WHERE id = ?`, "old-writer-private", run.ID); err == nil {
		t.Fatal("old writer downgraded encrypted command error")
	}
	var attemptEnvelope string
	if err := j.db.QueryRowContext(ctx, `SELECT stdout_text FROM command_run_step_attempts WHERE run_id = ? AND step_seq = 1 AND attempt = 1`, run.ID).Scan(&attemptEnvelope); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE command_run_steps SET stdout_text = ? WHERE run_id = ? AND step_seq = 1`, attemptEnvelope, run.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ListCommandRunStepsForTenant(ctx, "acme", run.ID); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("cross-field tamper = %v", err)
	}
}

func TestCommandExecutionOldWriterFailsAfterKeyEvenOnLegacyRow(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_crypto_legacy", "crypto-legacy", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, plan)
	admission := boundCommandRunAdmission(t, "acme", plan.ID, 1, definition, strings.Repeat("b", 64), "alice")
	run, err := j.CreateCommandRun(ctx, "acme", "cmdrun_crypto_legacy", plan.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE command_run_steps SET stdout_text = ? WHERE run_id = ? AND step_seq = 1`, "historical-plaintext", run.ID); err != nil {
		t.Fatal(err)
	}
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x5b}, 32), nil); err != nil {
		t.Fatal(err)
	}
	steps, err := j.ListCommandRunStepsForTenant(ctx, "acme", run.ID)
	if err != nil || len(steps) != 1 || steps[0].StdoutText != "historical-plaintext" {
		t.Fatalf("legacy row read = %+v, %v", steps, err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE command_run_steps SET stdout_text = ? WHERE run_id = ? AND step_seq = 1`, "new-plaintext", run.ID); err == nil {
		t.Fatal("old writer added plaintext to legacy step after key initialization")
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE command_runs SET error_text = ? WHERE id = ?`, "new-error-plaintext", run.ID); err == nil {
		t.Fatal("old writer added plaintext parent error after key initialization")
	}
	claim, err := j.ClaimCommandRun(ctx, run.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(j.db, EngineSQLite).ClaimCommandRunStep(ctx, run.ID, "worker-a", claim.ClaimToken, 1); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed command step writer = %v", err)
	}
	var version int
	if err := j.db.QueryRowContext(ctx, `SELECT stdout_crypto_version FROM command_run_steps WHERE run_id = ?`, run.ID).Scan(&version); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	if version != 0 {
		t.Fatalf("historical row was falsely backfilled: version=%d", version)
	}
}

func TestCommandExecutionTerminalAndRecoveryErrorsAreSealed(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"first","command":"true","purpose":"First","timeout_seconds":30},{"name":"second","command":"true","purpose":"Second","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_crypto_closure", "crypto-closure", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, plan)
	admission := boundCommandRunAdmission(t, "acme", plan.ID, 1, definition, strings.Repeat("d", 64), "alice")
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x5d}, 32), nil); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ id, mode, reason string }{
		{"cmdrun_crypto_cancel", "cancel", "synthetic-cancel-reason"},
		{"cmdrun_crypto_reap", "reap", "command worker lease expired"},
		{"cmdrun_crypto_reject", "reject", "synthetic-reject-reason"},
	} {
		run, err := j.CreateCommandRun(ctx, "acme", tc.id, plan.ID, 1, admission)
		if err != nil {
			t.Fatal(err)
		}
		if tc.mode != "reject" {
			claim, err := j.ClaimCommandRun(ctx, run.ID, "worker-a", time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := j.ClaimCommandRunStep(ctx, run.ID, "worker-a", claim.ClaimToken, 1); err != nil {
				t.Fatal(err)
			}
		}
		switch tc.mode {
		case "cancel":
			if _, err := j.CancelCommandRunForTenant(ctx, "acme", run.ID, tc.reason); err != nil {
				t.Fatal(err)
			}
		case "reap":
			if _, err := j.db.ExecContext(ctx, `UPDATE command_runs SET lease_expires_at = ? WHERE id = ?`, j.formatTime(time.Now().Add(-time.Minute)), run.ID); err != nil {
				t.Fatal(err)
			}
			if n, err := j.ReapExpiredCommandRunLeases(ctx); err != nil || n != 1 {
				t.Fatalf("reaped=%d err=%v", n, err)
			}
		case "reject":
			if err := j.FailQueuedCommandRunForTenant(ctx, "acme", run.ID, tc.reason); err != nil {
				t.Fatal(err)
			}
		}
		var raw string
		var version, plainBytes int
		if err := j.db.QueryRowContext(ctx, `SELECT error_text, error_crypto_version, error_plaintext_bytes FROM command_run_steps WHERE run_id = ? AND step_seq = 1`, run.ID).Scan(&raw, &version, &plainBytes); err != nil {
			t.Fatal(err)
		}
		if version != 1 || plainBytes != len(tc.reason) || strings.Contains(raw, tc.reason) {
			t.Fatalf("%s step error not sealed: version=%d bytes=%d", tc.mode, version, plainBytes)
		}
		if tc.mode != "reject" {
			if err := j.db.QueryRowContext(ctx, `SELECT error_text, error_crypto_version, error_plaintext_bytes FROM command_run_step_attempts WHERE run_id = ? AND step_seq = 1 AND attempt = 1`, run.ID).Scan(&raw, &version, &plainBytes); err != nil {
				t.Fatal(err)
			}
			if version != 1 || plainBytes != len(tc.reason) || strings.Contains(raw, tc.reason) {
				t.Fatalf("%s attempt error not sealed: version=%d bytes=%d", tc.mode, version, plainBytes)
			}
		}
		steps, err := j.ListCommandRunStepsForTenant(ctx, "acme", run.ID)
		if err != nil || len(steps) != 2 || steps[0].ErrorText != tc.reason || steps[1].ErrorText != tc.reason {
			t.Fatalf("%s steps = %+v, %v", tc.mode, steps, err)
		}
	}
}
