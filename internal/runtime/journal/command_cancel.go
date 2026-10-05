package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// CancelCommandRunForTenant terminalizes one queued or running command run
// under its tenant fence. Clearing the claim token in the same transaction
// fences a worker that is still unwinding; the in-process command queue also
// cancels its sandbox context, while a worker in another generation is denied
// by the normal lease checks.
func (j *Journal) CancelCommandRunForTenant(ctx context.Context, tenantID, runID, reason string) (string, error) {
	tenantID = strings.TrimSpace(tenantID)
	runID = strings.TrimSpace(runID)
	if tenantID == "" || runID == "" {
		return CommandCancelNotPossible, ErrNotFound
	}
	boundReason := scrubBoundCommandError(strings.TrimSpace(reason))
	if boundReason == "" {
		boundReason = "command run cancelled by operator"
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("journal: begin command run cancel: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_runs SET updated_at = updated_at WHERE id = $1 AND tenant_id = $2`), runID, tenantID); err != nil {
			return "", fmt.Errorf("journal: lock command run cancel: %w", err)
		}
	}
	q := `SELECT status FROM command_runs WHERE id = $1 AND tenant_id = $2`
	if j.engine == EnginePostgres {
		q += ` FOR UPDATE`
	}
	var status string
	if err := tx.QueryRowContext(ctx, j.bind(q), runID, tenantID).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CommandCancelNotPossible, ErrNotFound
		}
		return "", fmt.Errorf("journal: read command run cancel: %w", err)
	}
	if status != CommandRunQueued && status != CommandRunRunning {
		return CommandCancelNotPossible, nil
	}
	if err := j.requireCommandPayloadKey(ctx, tx); err != nil {
		return "", err
	}
	runError, err := j.sealCommandField(tenantID, runID, 0, 0, "run_error", boundReason)
	if err != nil {
		return "", err
	}
	now := j.now()
	if err := j.closeCommandAttemptErrors(ctx, tx, tenantID, runID, CommandRunStepRunning, CommandRunStepCancelled, boundReason, now, "", ""); err != nil {
		return "", fmt.Errorf("journal: cancel command run attempts: %w", err)
	}
	if err := j.closeCommandStepErrors(ctx, tx, tenantID, runID, []string{CommandRunStepPending, CommandRunStepRunning}, CommandRunStepCancelled, boundReason, now, false); err != nil {
		return "", fmt.Errorf("journal: cancel command run steps: %w", err)
	}
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE command_runs SET status = $1, error_text = $2,
		error_crypto_version = $3, error_plaintext_bytes = $4,
		finished_at = $5, claim_owner = NULL, claim_token = NULL, lease_expires_at = NULL, updated_at = $6
		WHERE id = $7 AND tenant_id = $8 AND status = $9`), CommandRunCancelled, runError.Text,
		runError.Version, runError.PlainBytes, now, now, runID, tenantID, status)
	if err != nil {
		return "", fmt.Errorf("journal: cancel command run: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return CommandCancelNotPossible, nil
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("journal: commit command run cancel: %w", err)
	}
	return CommandCancelDone, nil
}

// FailQueuedCommandRunForTenant closes one still-queued command run under its
// tenant fence without claiming it for execution. It is the rejection path
// for stale or unsafe durable admissions: ClaimCommandRun intentionally
// refuses disabled plans and old versions, so a worker must still be able to
// terminalize the queued row instead of leaving recovery to retry it forever.
// A concurrent worker wins the row lock first and receives
// ErrCommandRunNotClaimable; this method never changes a running or terminal
// run.
func (j *Journal) FailQueuedCommandRunForTenant(ctx context.Context, tenantID, runID, reason string) error {
	tenantID = strings.TrimSpace(tenantID)
	runID = strings.TrimSpace(runID)
	if tenantID == "" || runID == "" {
		return ErrNotFound
	}
	boundReason := scrubBoundCommandError(strings.TrimSpace(reason))
	if boundReason == "" {
		boundReason = "command run rejected before execution"
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin queued command run rejection: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_runs SET updated_at = updated_at WHERE id = $1 AND tenant_id = $2`), runID, tenantID); err != nil {
			return fmt.Errorf("journal: lock queued command run rejection: %w", err)
		}
	}
	q := `SELECT status FROM command_runs WHERE id = $1 AND tenant_id = $2`
	if j.engine == EnginePostgres {
		q += ` FOR UPDATE`
	}
	var status string
	if err := tx.QueryRowContext(ctx, j.bind(q), runID, tenantID).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: read queued command run rejection: %w", err)
	}
	if status == CommandRunSucceeded || status == CommandRunFailed || status == CommandRunCancelled {
		return nil
	}
	if status != CommandRunQueued {
		return ErrCommandRunNotClaimable
	}
	if err := j.requireCommandPayloadKey(ctx, tx); err != nil {
		return err
	}
	runError, err := j.sealCommandField(tenantID, runID, 0, 0, "run_error", boundReason)
	if err != nil {
		return err
	}
	now := j.now()
	if err := j.closeCommandAttemptErrors(ctx, tx, tenantID, runID, CommandRunStepRunning, CommandRunStepCancelled, boundReason, now, "", ""); err != nil {
		return fmt.Errorf("journal: close rejected command run attempts: %w", err)
	}
	if err := j.closeCommandStepErrors(ctx, tx, tenantID, runID, []string{CommandRunStepPending, CommandRunStepRunning}, CommandRunStepCancelled, boundReason, now, false); err != nil {
		return fmt.Errorf("journal: close rejected command run steps: %w", err)
	}
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE command_runs SET status = $1, error_text = $2,
		error_crypto_version = $3, error_plaintext_bytes = $4,
		finished_at = $5, claim_owner = NULL, claim_token = NULL, lease_expires_at = NULL, updated_at = $6
		WHERE id = $7 AND tenant_id = $8 AND status = $9`), CommandRunFailed, runError.Text,
		runError.Version, runError.PlainBytes, now, now, runID, tenantID, CommandRunQueued)
	if err != nil {
		return fmt.Errorf("journal: fail queued command run: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrCommandRunNotClaimable
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit queued command run rejection: %w", err)
	}
	return nil
}

const (
	CommandCancelDone        = "cancelled"
	CommandCancelNotPossible = "not_cancellable"
)
