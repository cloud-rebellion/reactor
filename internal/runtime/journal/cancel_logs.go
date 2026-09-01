package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Run cancellation outcomes returned by RequestRunCancel.
const (
	// CancelDone means the run was cancelled outright (it was suspended,
	// so there was no live process to signal).
	CancelDone = "cancelled"
	// CancelRequested means the run is executing; the cancel flag is set
	// and the daemon's cancel watcher will kill the live subprocess.
	CancelRequested = "requested"
	// CancelNotPossible means the run is already terminal (or unknown).
	CancelNotPossible = "not_cancellable"
)

// RequestRunCancel asks for a run to stop, working from any process (the
// dashboard runs in-daemon, but the CLI + MCP do not, so cancellation is
// signalled through the DB). A suspended run is cancelled immediately and
// its pending schedules are fired so the scheduler never resumes it. A
// running run gets cancel_requested=true; the daemon's watcher observes
// that and cancels the live subprocess. A terminal run is a no-op.
func (j *Journal) RequestRunCancel(ctx context.Context, runID string) (string, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	// Serialize cancellation with queue claims/finalization. Without this lock a
	// queued row could be selected here, claimed by a worker, then overwritten
	// to cancelled while its child was already starting.
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE runs SET id = id WHERE id = $1`), runID); err != nil {
			return "", fmt.Errorf("journal: request cancel: lock run: %w", err)
		}
	}
	selectStatus := `SELECT status FROM runs WHERE id = $1`
	if j.engine == EnginePostgres {
		selectStatus += ` FOR UPDATE`
	}
	var status string
	err = tx.QueryRowContext(ctx, j.bind(selectStatus), runID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return CancelNotPossible, ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("journal: request cancel: %w", err)
	}

	switch status {
	case "queued", "suspended":
		if _, err := tx.ExecContext(ctx,
			j.bind(`UPDATE runs SET status = 'cancelled', finished_at = $1, cancel_requested = $2 WHERE id = $3 AND status = $4`),
			j.now(), j.boolValue(true), runID, status); err != nil {
			return "", fmt.Errorf("journal: request cancel: mark cancelled: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			j.bind(`UPDATE schedules SET fired = $1 WHERE run_id = $2 AND fired = $3`),
			j.boolValue(true), runID, j.boolValue(false)); err != nil {
			return "", fmt.Errorf("journal: request cancel: fire schedules: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return "", err
		}
		return CancelDone, nil
	case "running":
		if _, err := tx.ExecContext(ctx,
			j.bind(`UPDATE runs SET cancel_requested = $1 WHERE id = $2`),
			j.boolValue(true), runID); err != nil {
			return "", fmt.Errorf("journal: request cancel: set flag: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return "", err
		}
		return CancelRequested, nil
	default:
		return CancelNotPossible, nil
	}
}

// ListCancelRequestedActive returns the ids of non-terminal runs flagged
// for cancellation (running OR suspended). The daemon's cancel watcher
// polls this: a running run gets its live subprocess cancelled; a
// suspended run (e.g. one that suspended AFTER the flag was set) is
// finalized via FinalizeCancel.
func (j *Journal) ListCancelRequestedActive(ctx context.Context) ([]string, error) {
	const q = `SELECT id FROM runs WHERE status IN ('running','suspended') AND cancel_requested = $1`
	rows, err := j.db.QueryContext(ctx, j.bind(q), j.boolValue(true))
	if err != nil {
		return nil, fmt.Errorf("journal: list cancel-requested: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// FinalizeCancel marks a still-active run cancelled and fires its pending
// schedules so the scheduler never resumes it. Used by the cancel watcher
// for runs that aren't executing on this daemon (suspended, or a flagged
// run that suspended before the in-process cancel reached it). Idempotent:
// a terminal run is left untouched.
func (j *Journal) FinalizeCancel(ctx context.Context, runID string) error {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		j.bind(`UPDATE runs SET status = 'cancelled', finished_at = $1 WHERE id = $2 AND status IN ('running','suspended')`),
		j.now(), runID); err != nil {
		return fmt.Errorf("journal: finalize cancel: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		j.bind(`UPDATE schedules SET fired = $1 WHERE run_id = $2 AND fired = $3`),
		j.boolValue(true), runID, j.boolValue(false)); err != nil {
		return fmt.Errorf("journal: finalize cancel: fire schedules: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// Cancellation is terminal: meter it like any other run end (best-effort).
	j.recordUsageBestEffort(ctx, runID, "cancelled")
	return nil
}

// FinalizeCancelIfUnleased is the cross-process watcher fallback. It may
// finalize a suspended/local/orphaned run, but never a run currently owned by
// a distributed worker. The owner must observe the cancel request, stop its
// child, and commit cancellation through FinalizeOwnedRun; a different worker
// is not allowed to race that lease generation.
func (j *Journal) FinalizeCancelIfUnleased(ctx context.Context, runID string) (bool, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		j.bind(`UPDATE runs SET status = 'cancelled', finished_at = $1
			WHERE id = $2 AND status IN ('running','suspended')
			AND NOT EXISTS (SELECT 1 FROM leases WHERE run_id = $3)`),
		j.now(), runID, runID)
	if err != nil {
		return false, fmt.Errorf("journal: finalize unleased cancel: %w", err)
	}
	moved, _ := res.RowsAffected()
	if moved == 0 {
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return false, nil
	}
	if _, err := tx.ExecContext(ctx,
		j.bind(`UPDATE schedules SET fired = $1 WHERE run_id = $2 AND fired = $3`),
		j.boolValue(true), runID, j.boolValue(false)); err != nil {
		return false, fmt.Errorf("journal: finalize unleased cancel schedules: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	j.recordUsageBestEffort(ctx, runID, "cancelled")
	return true, nil
}

// SaveRunLogs persists a run's buffered log lines. Called once when a run
// terminates (the in-memory ring is about to be dropped). Idempotent on
// the (run_id, seq) key so a double-flush is harmless.
func (j *Journal) SaveRunLogs(ctx context.Context, runID string, lines []string) error {
	if runID == "" || len(lines) == 0 {
		return nil
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx,
		j.bind(`INSERT INTO run_logs (run_id, seq, line) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`))
	if err != nil {
		return fmt.Errorf("journal: save run logs: prepare: %w", err)
	}
	defer stmt.Close()
	for i, line := range lines {
		if _, err := stmt.ExecContext(ctx, runID, i, line); err != nil {
			return fmt.Errorf("journal: save run logs: insert: %w", err)
		}
	}
	return tx.Commit()
}

// GetRunLogs returns a run's persisted log lines in order. Empty slice
// when none were saved (e.g. a still-running run whose logs only live in
// the in-memory ring).
func (j *Journal) GetRunLogs(ctx context.Context, runID string) ([]string, error) {
	const q = `SELECT line FROM run_logs WHERE run_id = $1 ORDER BY seq ASC`
	rows, err := j.db.QueryContext(ctx, j.bind(q), runID)
	if err != nil {
		return nil, fmt.Errorf("journal: get run logs: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, err
		}
		out = append(out, line)
	}
	return out, rows.Err()
}
