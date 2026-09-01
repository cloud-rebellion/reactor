package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const localRecoveryStepName = "__reactor_recovery__"

// RecoverLocalInterruptedRun durably classifies one unleased local run after
// its supervisor or daemon disappeared. Exact unused redrive authority is
// returned directly to failed_dlq. A recoverable durable checkpoint is parked
// as suspended behind one due synthetic schedule, which the normal scheduler
// consumes without re-running completed closures. Unknown hard crashes fail
// closed; a controlled infrastructure stop can set force=true because the host
// knows it killed the child and deliberately wants a clean restart from the
// workflow's durable boundaries.
func (j *Journal) RecoverLocalInterruptedRun(ctx context.Context, runID string, force bool) (string, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("journal: begin local interruption recovery: %w", err)
	}
	defer tx.Rollback()
	if err := lockRunForStepRepair(ctx, tx, j, runID); err != nil {
		return "", err
	}

	var (
		status          string
		cancelRequested any
	)
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT status, cancel_requested FROM runs WHERE id = $1`), runID).Scan(&status, &cancelRequested); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("journal: read local interrupted run: %w", err)
	}
	if status != "running" {
		if err := tx.Commit(); err != nil {
			return "", fmt.Errorf("journal: commit local recovery no-op: %w", err)
		}
		return status, nil
	}
	var leased int
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM leases WHERE run_id = $1`), runID).Scan(&leased); err != nil {
		return "", fmt.Errorf("journal: inspect local recovery lease: %w", err)
	}
	if leased != 0 {
		return "", fmt.Errorf("journal: local recovery refused for leased run %s", runID)
	}

	committedStatus := ""
	if parseBool(cancelRequested) {
		res, err := tx.ExecContext(ctx, j.bind(`UPDATE runs SET status = 'cancelled', finished_at = $1
			WHERE id = $2 AND status = 'running' AND cancel_requested = $3`),
			j.now(), runID, j.boolValue(true))
		if err != nil {
			return "", fmt.Errorf("journal: cancel local interrupted run: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return "", fmt.Errorf("journal: local interrupted cancellation changed concurrently")
		}
		if _, err := tx.ExecContext(ctx,
			j.bind(`UPDATE schedules SET fired = $1 WHERE run_id = $2 AND fired = $3`),
			j.boolValue(true), runID, j.boolValue(false)); err != nil {
			return "", fmt.Errorf("journal: fire local interrupted cancellation schedules: %w", err)
		}
		committedStatus = "cancelled"
	} else {
		restored, err := restorePendingRedriveTx(ctx, tx, j, runID)
		if err != nil {
			return "", err
		}
		if restored {
			if err := finishRecoveredRedriveTx(ctx, tx, j, runID); err != nil {
				return "", err
			}
			committedStatus = "failed_dlq"
		} else {
			pendingSchedule, err := hasPendingLocalExecutionScheduleTx(ctx, tx, j, runID)
			if err != nil {
				return "", err
			}
			recoverable, err := hasRecoverableStepAttemptTx(ctx, tx, j, runID)
			if err != nil {
				return "", err
			}
			if force || recoverable || pendingSchedule {
				if err := ensureLocalRecoveryScheduleTx(ctx, tx, j, runID); err != nil {
					return "", err
				}
				res, err := tx.ExecContext(ctx, j.bind(`UPDATE runs SET status = 'suspended'
					WHERE id = $1 AND status = 'running' AND cancel_requested = $2`),
					runID, j.boolValue(false))
				if err != nil {
					return "", fmt.Errorf("journal: suspend local interrupted run: %w", err)
				}
				if n, _ := res.RowsAffected(); n != 1 {
					return "", fmt.Errorf("journal: local interrupted run changed before scheduling")
				}
				committedStatus = "suspended"
			} else {
				res, err := tx.ExecContext(ctx, j.bind(`UPDATE runs SET status = 'failed', finished_at = $1
					WHERE id = $2 AND status = 'running' AND cancel_requested = $3`),
					j.now(), runID, j.boolValue(false))
				if err != nil {
					return "", fmt.Errorf("journal: fail unknown local orphan: %w", err)
				}
				if n, _ := res.RowsAffected(); n != 1 {
					return "", fmt.Errorf("journal: unknown local orphan changed concurrently")
				}
				committedStatus = "failed"
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("journal: commit local interruption recovery: %w", err)
	}
	if committedStatus != "suspended" {
		j.recordUsageBestEffort(ctx, runID, committedStatus)
	}
	return committedStatus, nil
}

func hasPendingLocalExecutionScheduleTx(ctx context.Context, tx *sql.Tx, j *Journal, runID string) (bool, error) {
	var one int
	err := tx.QueryRowContext(ctx, j.bind(`SELECT 1 FROM schedules
		WHERE run_id = $1 AND fired = $2 AND kind IN ($3, $4, $5) LIMIT 1`),
		runID, j.boolValue(false), KindSleep, KindSignal, KindRecovery).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("journal: inspect local recovery schedules: %w", err)
	}
	return true, nil
}

func hasRecoverableStepAttemptTx(ctx context.Context, tx *sql.Tx, j *Journal, runID string) (bool, error) {
	const q = `SELECT 1
		FROM steps s
		WHERE s.run_id = $1
		  AND s.status IN ($2, $3, $4)
		  AND NOT EXISTS (
			SELECT 1 FROM steps newer
			WHERE newer.run_id = s.run_id
			  AND newer.step_name = s.step_name
			  AND newer.seq = s.seq
			  AND newer.attempt > s.attempt
		  )
		LIMIT 1`
	var one int
	err := tx.QueryRowContext(ctx, j.bind(q), runID, StatusRunning, StatusRetrying, StatusDLQPending).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("journal: inspect local recoverable step attempt: %w", err)
	}
	return true, nil
}

func ensureLocalRecoveryScheduleTx(ctx context.Context, tx *sql.Tx, j *Journal, runID string) error {
	var existing, kind string
	err := tx.QueryRowContext(ctx, j.bind(`SELECT id, kind FROM schedules
		WHERE run_id = $1 AND fired = $2 AND kind IN ($3, $4, $5)
		ORDER BY created_at, id LIMIT 1`),
		runID, j.boolValue(false), KindSleep, KindSignal, KindRecovery).Scan(&existing, &kind)
	if err == nil {
		// A committed sleep/signal row is already the exact continuation
		// checkpoint. Do not add or retime a synthetic recovery row: doing so can
		// later wake an unrelated second wait after the original resume fires.
		if kind == KindRecovery {
			if _, err := tx.ExecContext(ctx, j.bind(`UPDATE schedules SET wake_at = $1 WHERE id = $2`), j.now(), existing); err != nil {
				return fmt.Errorf("journal: refresh local recovery schedule: %w", err)
			}
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("journal: inspect local recovery schedule: %w", err)
	}
	id, err := newID("sched_recover_")
	if err != nil {
		return err
	}
	const insert = `INSERT INTO schedules (id, run_id, step_name, seq, kind, wake_at, fired)
		VALUES ($1, $2, $3, 0, $4, $5, $6)`
	if _, err := tx.ExecContext(ctx, j.bind(insert),
		id, runID, localRecoveryStepName, KindRecovery, j.now(), j.boolValue(false)); err != nil {
		return fmt.Errorf("journal: insert local recovery schedule: %w", err)
	}
	return nil
}

// RecoverOwnedPendingDeadLetterRedrive atomically returns an unused exact
// redrive authorization to the operator queue. It is used when a leased worker
// cannot even start/handshake the workflow, before a newer StepStart proves
// execution began. The exact lease generation is released in the same commit;
// a stale worker can neither reopen the DLQ item nor delete its replacement's
// lease.
func (j *Journal) RecoverOwnedPendingDeadLetterRedrive(ctx context.Context, runID, owner string) (bool, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("journal: begin owned redrive recovery: %w", err)
	}
	defer tx.Rollback()
	if err := j.lockOwnedLease(ctx, tx, runID, owner); err != nil {
		return false, err
	}

	statusQ := `SELECT status FROM runs WHERE id = $1`
	if j.engine == EnginePostgres {
		statusQ += ` FOR UPDATE`
	}
	var status string
	if err := tx.QueryRowContext(ctx, j.bind(statusQ), runID).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, fmt.Errorf("journal: read owned redrive run: %w", err)
	}
	if status != "running" {
		return false, nil
	}
	recovered, err := restorePendingRedriveTx(ctx, tx, j, runID)
	if err != nil {
		return false, err
	}
	if !recovered {
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("journal: commit unused owned redrive recovery probe: %w", err)
		}
		return false, nil
	}
	if err := finishRecoveredRedriveTx(ctx, tx, j, runID); err != nil {
		return false, err
	}
	res, err := tx.ExecContext(ctx, j.bind(`DELETE FROM leases WHERE run_id = $1 AND worker_id = $2`), runID, owner)
	if err != nil {
		return false, fmt.Errorf("journal: release recovered redrive lease: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, fmt.Errorf("%w: recover redrive run=%s", ErrLeaseOwnershipLost, runID)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("journal: commit owned redrive recovery: %w", err)
	}
	j.recordUsageBestEffort(ctx, runID, "failed_dlq")
	return true, nil
}

// RecoverLocalPendingDeadLetterRedrive is the single-node counterpart. It
// restores only an exact authorization with no newer attempt, so a failure
// after StepStart never grants another operator execution window.
func (j *Journal) RecoverLocalPendingDeadLetterRedrive(ctx context.Context, runID string) (bool, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("journal: begin local redrive recovery: %w", err)
	}
	defer tx.Rollback()
	if err := lockRunForStepRepair(ctx, tx, j, runID); err != nil {
		return false, err
	}
	var status string
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT status FROM runs WHERE id = $1`), runID).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, fmt.Errorf("journal: read local redrive run: %w", err)
	}
	if status != "running" {
		return false, nil
	}
	recovered, err := restorePendingRedriveTx(ctx, tx, j, runID)
	if err != nil {
		return false, err
	}
	if !recovered {
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("journal: commit unused local redrive recovery probe: %w", err)
		}
		return false, nil
	}
	if err := finishRecoveredRedriveTx(ctx, tx, j, runID); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("journal: commit local redrive recovery: %w", err)
	}
	j.recordUsageBestEffort(ctx, runID, "failed_dlq")
	return true, nil
}

// restorePendingRedriveTx consumes only the exact CURRENT DLQ authorization
// and only while no newer attempt exists for that logical step. A nullable
// legacy DLQ has no proof that an old SDK did not already enter its closure,
// so it intentionally fails closed instead of granting duplicate execution.
func restorePendingRedriveTx(ctx context.Context, tx *sql.Tx, j *Journal, runID string) (bool, error) {
	var (
		stepName    string
		stepSeq     sql.NullInt64
		stepAttempt sql.NullInt64
	)
	const current = `SELECT step_name, step_seq, step_attempt FROM dead_letter
		WHERE run_id = $1
		ORDER BY CASE WHEN failure_order IS NULL THEN 1 ELSE 0 END,
			failure_order DESC, moved_at DESC, id DESC LIMIT 1`
	if err := tx.QueryRowContext(ctx, j.bind(current), runID).Scan(&stepName, &stepSeq, &stepAttempt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("journal: read current redrive recovery item: %w", err)
	}
	if !stepSeq.Valid || !stepAttempt.Valid {
		return false, nil
	}
	const restore = `UPDATE steps SET status = $1
		WHERE run_id = $2 AND step_name = $3 AND seq = $4 AND attempt = $5 AND status = $6
		  AND NOT EXISTS (
			SELECT 1 FROM steps newer
			WHERE newer.run_id = $7 AND newer.step_name = $8 AND newer.seq = $9
			  AND newer.attempt > $10
		  )`
	res, err := tx.ExecContext(ctx, j.bind(restore),
		StatusFailed, runID, stepName, stepSeq.Int64, stepAttempt.Int64, StatusRedrive,
		runID, stepName, stepSeq.Int64, stepAttempt.Int64,
	)
	if err != nil {
		return false, fmt.Errorf("journal: restore pending exact redrive: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func finishRecoveredRedriveTx(ctx context.Context, tx *sql.Tx, j *Journal, runID string) error {
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE runs SET status = $1, finished_at = $2
		WHERE id = $3 AND status = 'running'`), "failed_dlq", j.now(), runID)
	if err != nil {
		return fmt.Errorf("journal: restore recovered redrive run: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("journal: recovered redrive run changed concurrently")
	}
	return nil
}
