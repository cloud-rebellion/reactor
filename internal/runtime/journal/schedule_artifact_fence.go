package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// DeferScheduleArtifactAvailability keeps an execution-continuation schedule
// pending when its already-validated pinned executable is temporarily
// unavailable on this node. It applies equally to sleep, signal, and synthetic
// recovery rows: consuming any of them would strand the suspended run. The
// operator-visible marker is appended at most once and wake_at is pushed to
// retryAt, avoiding one durable log row per scheduler tick during an outage.
// The suspended run is locked with the schedule update, so cancellation or a
// competing resume cannot be overwritten.
func (j *Journal) DeferScheduleArtifactAvailability(ctx context.Context, scheduleID, runID string, retryAt time.Time) (bool, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("journal: begin scheduled artifact deferral: %w", err)
	}
	defer tx.Rollback()

	// Match ClaimScheduleResume/ClaimScheduleAndFailArtifactFence lock order:
	// schedule first, then parent run. Opposite order can deadlock a Postgres
	// scheduler artifact probe against a concurrent claim.
	if j.engine == EngineSQLite {
		res, err := tx.ExecContext(ctx, j.bind(`UPDATE schedules SET id = id WHERE id = $1`), scheduleID)
		if err != nil {
			return false, fmt.Errorf("journal: lock scheduled artifact deferral: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			if err := tx.Commit(); err != nil {
				return false, fmt.Errorf("journal: commit missing scheduled artifact deferral: %w", err)
			}
			return false, nil
		}
	}
	scheduleQ := `SELECT run_id, kind, fired FROM schedules WHERE id = $1`
	if j.engine == EnginePostgres {
		scheduleQ += ` FOR UPDATE`
	}
	var (
		scheduleRun  sql.NullString
		scheduleKind string
		fired        any
	)
	if err := tx.QueryRowContext(ctx, j.bind(scheduleQ), scheduleID).Scan(&scheduleRun, &scheduleKind, &fired); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("journal: read scheduled artifact deferral: %w", err)
	}
	validKind := scheduleKind == KindSleep || scheduleKind == KindSignal || scheduleKind == KindRecovery
	if !scheduleRun.Valid || scheduleRun.String != runID || !validKind || parseBool(fired) {
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("journal: commit obsolete scheduled artifact deferral: %w", err)
		}
		return false, nil
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
		return false, fmt.Errorf("journal: read scheduled artifact run: %w", err)
	}
	if status != "suspended" {
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("journal: commit obsolete scheduled artifact deferral: %w", err)
		}
		return false, nil
	}

	const deferSchedule = `UPDATE schedules SET wake_at = $1
		WHERE id = $2 AND run_id = $3 AND kind = $4 AND fired = $5`
	res, err := tx.ExecContext(ctx, j.bind(deferSchedule), j.formatTime(retryAt), scheduleID, runID, scheduleKind, j.boolValue(false))
	if err != nil {
		return false, fmt.Errorf("journal: defer scheduled artifact lookup: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("journal: commit missing scheduled artifact deferral: %w", err)
		}
		return false, nil
	}

	var marked int
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM run_logs
		WHERE run_id = $1 AND (kind = 'artifact_fence'
			OR (payload_crypto_version = 0 AND line = $2))`),
		runID, WorkflowArtifactFenceRunLog).Scan(&marked); err != nil {
		return false, fmt.Errorf("journal: inspect scheduled artifact marker: %w", err)
	}
	if marked == 0 {
		if err := appendArtifactFenceLog(ctx, tx, j, runID); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("journal: commit scheduled artifact deferral: %w", err)
	}
	return true, nil
}

// ClaimScheduleAndFailArtifactFence atomically consumes one selected schedule
// and terminalizes its still-suspended run when the pinned executable cannot be
// trusted/resolved. Any failure rolls back fired=true, so a crash or DB error
// cannot strand a suspended run behind a consumed schedule.
func (j *Journal) ClaimScheduleAndFailArtifactFence(ctx context.Context, scheduleID, runID string) (bool, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("journal: begin scheduled artifact fence: %w", err)
	}
	defer tx.Rollback()

	const claim = `UPDATE schedules SET fired = $1
		WHERE id = $2 AND run_id = $3 AND fired = $4`
	res, err := tx.ExecContext(ctx, j.bind(claim), j.boolValue(true), scheduleID, runID, j.boolValue(false))
	if err != nil {
		return false, fmt.Errorf("journal: claim artifact-fenced schedule: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, tx.Commit()
	}

	const failRun = `UPDATE runs SET status = $1, finished_at = $2
		WHERE id = $3 AND status = 'suspended'`
	res, err = tx.ExecContext(ctx, j.bind(failRun), "failed", j.now(), runID)
	if err != nil {
		return false, fmt.Errorf("journal: fail scheduled artifact-fenced run: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		// Cancellation/finalization won before this transaction. Retire the
		// schedule but do not overwrite that terminal state or emit a false log.
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("journal: retire obsolete artifact-fenced schedule: %w", err)
		}
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, j.bind(`UPDATE schedules SET fired = $1 WHERE run_id = $2 AND fired = $3`),
		j.boolValue(true), runID, j.boolValue(false)); err != nil {
		return false, fmt.Errorf("journal: consume schedules after scheduled artifact fence: %w", err)
	}
	// A durably suspended run has already released its worker lease. Do not
	// delete by run_id here: if corrupted/legacy state leaves a lease behind,
	// an unowned scheduler must never remove a newer worker generation.
	if err := appendArtifactFenceLog(ctx, tx, j, runID); err != nil {
		return false, err
	}
	// This scheduler path terminalizes a suspended run without going through a
	// supervisor/dispatcher callback. Persist the terminal handoff atomically so
	// the notification/chain recovery loop cannot miss the failed outcome.
	if err := j.enqueueTerminalEffectTx(ctx, tx, runID, "failed"); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("journal: commit scheduled artifact fence: %w", err)
	}
	j.recordUsageBestEffort(ctx, runID, "failed")
	return true, nil
}
