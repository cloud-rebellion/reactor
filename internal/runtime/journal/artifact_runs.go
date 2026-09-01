package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// WorkflowArtifactFenceRunLog is intentionally free of paths, payloads, and
// digests. Detailed integrity errors stay in the structured server log; this
// durable operator-facing line explains the recovery action without leaking
// deployment layout or customer data.
const WorkflowArtifactFenceRunLog = "execution blocked: pinned workflow artifact is unavailable, untrusted, or incompatible; rebuild/register the workflow and review or redrive this run"

// ActivateWorkflowArtifactIfCurrent serializes the filesystem compatibility
// activation with workflow-version allocation. The callback runs while the
// workflows row is locked and only when version+digest are still current.
// This closes the out-of-order race where registration A committed v2, B
// committed and activated v3, then delayed A overwrote the mutable binary with
// v2. Runtime execution never uses that mutable path, but authoring/status
// tooling must still not advertise stale bytes.
func (j *Journal) ActivateWorkflowArtifactIfCurrent(ctx context.Context, workflowID string, version int, artifactSHA256 string, activate func() error) (bool, error) {
	if workflowID == "" || version <= 0 || !validArtifactSHA256(artifactSHA256) || activate == nil {
		return false, errors.New("journal: activate workflow artifact: invalid arguments")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("journal: begin workflow artifact activation: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EnginePostgres {
		var lockedID string
		if err := tx.QueryRowContext(ctx, `SELECT id FROM workflows WHERE id = $1 FOR UPDATE`, workflowID).Scan(&lockedID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false, ErrNotFound
			}
			return false, fmt.Errorf("journal: lock workflow artifact activation: %w", err)
		}
	} else {
		res, err := tx.ExecContext(ctx, j.bind(`UPDATE workflows SET updated_at = updated_at WHERE id = $1`), workflowID)
		if err != nil {
			return false, fmt.Errorf("journal: lock workflow artifact activation: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return false, ErrNotFound
		}
	}
	var (
		currentVersion int
		currentDigest  sql.NullString
	)
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT version, artifact_sha256
		FROM workflow_versions WHERE workflow_id = $1 ORDER BY version DESC LIMIT 1`), workflowID).
		Scan(&currentVersion, &currentDigest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, fmt.Errorf("journal: read current workflow artifact: %w", err)
	}
	if currentVersion != version || !currentDigest.Valid || currentDigest.String != artifactSHA256 {
		return false, nil
	}
	if err := activate(); err != nil {
		return false, fmt.Errorf("journal: activate current workflow artifact: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("journal: commit workflow artifact activation: %w", err)
	}
	return true, nil
}

// FailRunArtifactFence atomically makes an unexecutable queued/running/resumed
// run terminal, consumes pending schedules, releases its worker lease, and
// appends an operator-visible log line. A worker crash cannot leave the row in
// a requeue loop that repeatedly attempts mutable code.
func (j *Journal) FailRunArtifactFence(ctx context.Context, runID string) error {
	_, err := j.FailRunArtifactFenceStatus(ctx, runID)
	return err
}

// FailRunArtifactFenceStatus is FailRunArtifactFence with the committed run
// status returned to lifecycle publishers. A pre-StepStart DLQ redrive is
// restored to failed_dlq; an ordinary run is failed.
func (j *Journal) FailRunArtifactFenceStatus(ctx context.Context, runID string) (string, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("journal: begin artifact fence failure: %w", err)
	}
	defer tx.Rollback()
	if err := lockRunForStepRepair(ctx, tx, j, runID); err != nil {
		return "", err
	}
	var currentStatus string
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT status FROM runs WHERE id = $1`), runID).Scan(&currentStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("journal: read artifact-fenced run status: %w", err)
	}
	if currentStatus != "queued" && currentStatus != "running" && currentStatus != "suspended" {
		return "", fmt.Errorf("journal: mark artifact fence failed: run is no longer executable")
	}
	recovered, err := restorePendingRedriveTx(ctx, tx, j, runID)
	if err != nil {
		return "", err
	}
	targetStatus := "failed"
	if recovered {
		targetStatus = "failed_dlq"
	}
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE runs SET status = $1, finished_at = $2
		WHERE id = $3 AND status = $4`), targetStatus, j.now(), runID, currentStatus)
	if err != nil {
		return "", fmt.Errorf("journal: mark artifact fence failed: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return "", fmt.Errorf("journal: mark artifact fence failed: run is no longer executable")
	}
	if _, err := tx.ExecContext(ctx, j.bind(`UPDATE schedules SET fired = $1 WHERE run_id = $2 AND fired = $3`),
		j.boolValue(true), runID, j.boolValue(false)); err != nil {
		return "", fmt.Errorf("journal: consume schedules after artifact fence: %w", err)
	}
	if _, err := tx.ExecContext(ctx, j.bind(`DELETE FROM leases WHERE run_id = $1`), runID); err != nil {
		return "", fmt.Errorf("journal: release artifact-fenced lease: %w", err)
	}
	if err := appendArtifactFenceLog(ctx, tx, j, runID); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("journal: commit artifact fence failure: %w", err)
	}
	j.recordUsageBestEffort(ctx, runID, targetStatus)
	return targetStatus, nil
}

// FailLeasedRunArtifactFence is the distributed-worker variant. It locks and
// verifies the exact per-claim owner before touching the run, then commits the
// terminal failure, schedule cleanup, operator log, and owned lease release
// atomically. A claimant delayed in artifact verification cannot fail a run or
// delete the lease after a reaper has handed it to another worker.
func (j *Journal) FailLeasedRunArtifactFence(ctx context.Context, runID, owner string) error {
	_, err := j.FailLeasedRunArtifactFenceStatus(ctx, runID, owner)
	return err
}

// FailLeasedRunArtifactFenceStatus is the exact-owner variant that also
// reports the status committed in the fenced transaction.
func (j *Journal) FailLeasedRunArtifactFenceStatus(ctx context.Context, runID, owner string) (string, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("journal: begin leased artifact fence failure: %w", err)
	}
	defer tx.Rollback()
	if err := j.lockOwnedLease(ctx, tx, runID, owner); err != nil {
		return "", err
	}
	statusQ := `SELECT status FROM runs WHERE id = $1`
	if j.engine == EnginePostgres {
		statusQ += ` FOR UPDATE`
	}
	var currentStatus string
	if err := tx.QueryRowContext(ctx, j.bind(statusQ), runID).Scan(&currentStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("journal: read leased artifact-fenced run status: %w", err)
	}
	if currentStatus != "running" {
		return "", fmt.Errorf("journal: mark leased artifact fence failed: run is no longer owned-running")
	}
	recovered, err := restorePendingRedriveTx(ctx, tx, j, runID)
	if err != nil {
		return "", err
	}
	targetStatus := "failed"
	if recovered {
		targetStatus = "failed_dlq"
	}
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE runs SET status = $1, finished_at = $2
		WHERE id = $3 AND status = 'running'`), targetStatus, j.now(), runID)
	if err != nil {
		return "", fmt.Errorf("journal: mark leased artifact fence failed: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return "", fmt.Errorf("journal: mark leased artifact fence failed: run is no longer owned-running")
	}
	if _, err := tx.ExecContext(ctx, j.bind(`UPDATE schedules SET fired = $1 WHERE run_id = $2 AND fired = $3`),
		j.boolValue(true), runID, j.boolValue(false)); err != nil {
		return "", fmt.Errorf("journal: consume schedules after leased artifact fence: %w", err)
	}
	if err := appendArtifactFenceLog(ctx, tx, j, runID); err != nil {
		return "", err
	}
	res, err = tx.ExecContext(ctx, j.bind(`DELETE FROM leases WHERE run_id = $1 AND worker_id = $2`), runID, owner)
	if err != nil {
		return "", fmt.Errorf("journal: release leased artifact-fenced run: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return "", fmt.Errorf("%w: artifact fence run=%s", ErrLeaseOwnershipLost, runID)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("journal: commit leased artifact fence failure: %w", err)
	}
	j.recordUsageBestEffort(ctx, runID, targetStatus)
	return targetStatus, nil
}

// LogRunArtifactFence preserves an already-terminal/DLQ status while making a
// refused redrive visible on the durable run page.
func (j *Journal) LogRunArtifactFence(ctx context.Context, runID string) error {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin artifact fence log: %w", err)
	}
	defer tx.Rollback()
	if err := appendArtifactFenceLog(ctx, tx, j, runID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit artifact fence log: %w", err)
	}
	return nil
}

func appendArtifactFenceLog(ctx context.Context, tx *sql.Tx, j *Journal, runID string) error {
	var seq int
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COALESCE(MAX(seq), -1) + 1 FROM run_logs WHERE run_id = $1`), runID).Scan(&seq); err != nil {
		return fmt.Errorf("journal: next artifact fence log sequence: %w", err)
	}
	if _, err := tx.ExecContext(ctx, j.bind(`INSERT INTO run_logs (run_id, seq, line) VALUES ($1, $2, $3)`),
		runID, seq, WorkflowArtifactFenceRunLog); err != nil {
		return fmt.Errorf("journal: append artifact fence log: %w", err)
	}
	return nil
}
