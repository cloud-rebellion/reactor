package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// FinalizeOwnedRun persists a distributed worker's outcome and releases the
// exact lease generation in one transaction. The lease row is locked before
// the run is touched, matching the reaper's lock order. A stale worker can
// therefore neither overwrite the replacement worker's status nor delete its
// lease.
func (j *Journal) FinalizeOwnedRun(ctx context.Context, runID, owner, status string) error {
	if owner == "" {
		return errors.New("journal: finalize owned run: empty lease owner")
	}
	switch status {
	case "succeeded", "failed", "failed_dlq", "cancelled", "suspended":
	default:
		return fmt.Errorf("journal: finalize owned run: invalid status %q", status)
	}

	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin owned run finalization: %w", err)
	}
	defer tx.Rollback()

	leaseDeadline, err := j.lockOwnedLease(ctx, tx, runID, owner)
	if err != nil {
		return err
	}

	statusQuery := `SELECT status FROM runs WHERE id = $1`
	if j.engine == EnginePostgres {
		statusQuery += ` FOR UPDATE`
	}
	var current string
	if err := tx.QueryRowContext(ctx, j.bind(statusQuery), runID).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: read owned run status: %w", err)
	}
	if current != "running" && current != status {
		return fmt.Errorf("journal: finalize owned run: run %s changed from running to %s", runID, current)
	}

	if current == "running" {
		var res sql.Result
		if status == "suspended" {
			res, err = tx.ExecContext(ctx, j.bind(`UPDATE runs SET status = $1 WHERE id = $2 AND status = 'running'`), status, runID)
			if err != nil {
				return fmt.Errorf("journal: suspend owned run: %w", err)
			}
		} else {
			res, err = tx.ExecContext(ctx, j.bind(`UPDATE runs SET status = $1, finished_at = $2 WHERE id = $3 AND status = 'running'`), status, j.now(), runID)
			if err != nil {
				return fmt.Errorf("journal: finish owned run: %w", err)
			}
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("journal: finalize owned run: run %s changed concurrently", runID)
		}
	}
	if status == "cancelled" {
		if _, err := tx.ExecContext(ctx,
			j.bind(`UPDATE schedules SET fired = $1 WHERE run_id = $2 AND fired = $3`),
			j.boolValue(true), runID, j.boolValue(false)); err != nil {
			return fmt.Errorf("journal: finalize owned cancellation schedules: %w", err)
		}
	}
	if status == "succeeded" {
		// Distributed DLQ redrives are queued and later finish here, outside the
		// request process that authorized them. Clear every historical item in
		// the same transaction as success so a crash cannot leave a false-active
		// operator alert after the run is durably healthy.
		if _, err := tx.ExecContext(ctx, j.bind(`DELETE FROM dead_letter WHERE run_id = $1`), runID); err != nil {
			return fmt.Errorf("journal: clear dead letters for owned success: %w", err)
		}
	}
	if current == "running" {
		if err := j.enqueueTerminalEffectTx(ctx, tx, runID, status); err != nil {
			return err
		}
	}

	res, err := tx.ExecContext(ctx, j.bind(`DELETE FROM leases WHERE run_id = $1 AND worker_id = $2`), runID, owner)
	if err != nil {
		return fmt.Errorf("journal: release finalized owned lease: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: finalize run=%s", ErrLeaseOwnershipLost, runID)
	}
	if err := checkOwnedLeaseDeadline(runID, leaseDeadline); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit owned run finalization: %w", err)
	}
	if status != "suspended" {
		j.recordUsageBestEffort(ctx, runID, status)
	}
	return nil
}

func (j *Journal) lockOwnedLease(ctx context.Context, tx *sql.Tx, runID, owner string) (time.Time, error) {
	var expiresAt time.Time
	if j.engine == EnginePostgres {
		err := tx.QueryRowContext(ctx, `SELECT expires_at FROM leases
			WHERE run_id = $1 AND worker_id = $2 FOR UPDATE`, runID, owner).Scan(&expiresAt)
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, fmt.Errorf("%w: lock run=%s", ErrLeaseOwnershipLost, runID)
		}
		if err != nil {
			return time.Time{}, fmt.Errorf("journal: lock owned lease: %w", err)
		}
	} else {
		// A no-op write acquires SQLite's single-writer lock before any run
		// state is inspected, matching the PostgreSQL lock order.
		var rawExpiry string
		err := tx.QueryRowContext(ctx, j.bind(`UPDATE leases SET worker_id = worker_id
			WHERE run_id = $1 AND worker_id = $2 RETURNING expires_at`), runID, owner).Scan(&rawExpiry)
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, fmt.Errorf("%w: lock run=%s", ErrLeaseOwnershipLost, runID)
		}
		if err != nil {
			return time.Time{}, fmt.Errorf("journal: lock owned lease: %w", err)
		}
		expiresAt, err = j.parseTime(rawExpiry)
		if err != nil {
			return time.Time{}, fmt.Errorf("journal: parse owned lease deadline: %w", err)
		}
	}

	// Ownership ends at the lease deadline, not when the reaper happens to
	// delete the row. Check the deadline after acquiring the row/writer lock:
	// a finalizer that waited behind another transaction must observe a lease
	// that expired or was renewed while it waited. Use the same application
	// clock as ClaimQueuedRuns, ExtendLease, and ReapExpiredLeases rather than
	// mixing in the database server's possibly different clock.
	if err := checkOwnedLeaseDeadline(runID, expiresAt); err != nil {
		return time.Time{}, err
	}
	return expiresAt, nil
}

// checkOwnedLeaseDeadline is also called immediately before committing each
// owned transaction. Later run/step locks may have made the work wait past
// the deadline even though the lease was live when lockOwnedLease returned.
// The captured deadline remains authoritative because the transaction holds
// the exact lease generation's lock through the commit attempt.
func checkOwnedLeaseDeadline(runID string, expiresAt time.Time) error {
	if !expiresAt.After(time.Now().UTC()) {
		return fmt.Errorf("%w: deadline run=%s", ErrLeaseOwnershipLost, runID)
	}
	return nil
}

// HasRecoverableStepAttempt reports whether the latest row for any logical
// step call is still running, has durably authorized a retry, or is waiting for
// its exact DLQ repair. A distributed supervisor uses this after an abnormal
// child exit: leaving the run leased lets expiry/reaping restart it from the
// durable boundary instead of turning a recoverable failure into terminal loss.
// Terminal succeeded/failed rows are deliberately excluded: a deterministic
// process error after a cached step must not create an infinite requeue loop.
func (j *Journal) HasRecoverableStepAttempt(ctx context.Context, runID string) (bool, error) {
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
	err := j.db.QueryRowContext(ctx, j.bind(q), runID, StatusRunning, StatusRetrying, StatusDLQPending).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("journal: inspect recoverable step attempt: %w", err)
	}
	return true, nil
}
