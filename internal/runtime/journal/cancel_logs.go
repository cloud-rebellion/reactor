package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
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
	return j.requestRunCancel(ctx, runID, "")
}

// requestRunCancel performs the cancellation read and mutation in one
// transaction. When tenantID is set, the tenant predicate is included in the
// row lock/read and the state update; callers cannot turn a scoped read into an
// unscoped mutation between those operations.
func (j *Journal) requestRunCancel(ctx context.Context, runID, tenantID string) (string, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	// Serialize cancellation with queue claims/finalization. Without this lock a
	// queued row could be selected here, claimed by a worker, then overwritten
	// to cancelled while its child was already starting.
	if j.engine == EngineSQLite {
		lockQ := `UPDATE runs SET id = id WHERE id = $1`
		lockArgs := []any{runID}
		if tenantID != "" {
			lockQ += ` AND tenant_id = $2`
			lockArgs = append(lockArgs, tenantID)
		}
		if _, err := tx.ExecContext(ctx, j.bind(lockQ), lockArgs...); err != nil {
			return "", fmt.Errorf("journal: request cancel: lock run: %w", err)
		}
	}
	selectStatus := `SELECT status FROM runs WHERE id = $1`
	statusArgs := []any{runID}
	if tenantID != "" {
		selectStatus += ` AND tenant_id = $2`
		statusArgs = append(statusArgs, tenantID)
	}
	if j.engine == EnginePostgres {
		selectStatus += ` FOR UPDATE`
	}
	var status string
	err = tx.QueryRowContext(ctx, j.bind(selectStatus), statusArgs...).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return CancelNotPossible, ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("journal: request cancel: %w", err)
	}

	switch status {
	case "queued", "suspended":
		updateQ := `UPDATE runs SET status = 'cancelled', finished_at = $1, cancel_requested = $2 WHERE id = $3 AND status = $4`
		updateArgs := []any{j.now(), j.boolValue(true), runID, status}
		if tenantID != "" {
			updateQ += ` AND tenant_id = $5`
			updateArgs = append(updateArgs, tenantID)
		}
		if _, err := tx.ExecContext(ctx, j.bind(updateQ), updateArgs...); err != nil {
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
		// A queued or suspended cancellation is terminalized here rather than
		// through the supervisor's normal finish path. Record the same durable
		// usage receipt so tenant quotas and billing cannot omit operator
		// cancellations. The ledger is idempotent if a watcher observes the
		// already-terminal run and tries to finalize it again.
		j.recordUsageBestEffort(ctx, runID, "cancelled")
		return CancelDone, nil
	case "running":
		updateQ := `UPDATE runs SET cancel_requested = $1 WHERE id = $2`
		updateArgs := []any{j.boolValue(true), runID}
		if tenantID != "" {
			updateQ += ` AND tenant_id = $3`
			updateArgs = append(updateArgs, tenantID)
		}
		if _, err := tx.ExecContext(ctx, j.bind(updateQ), updateArgs...); err != nil {
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

// RequestRunCancelForTenant is the MCP/member-safe cancellation entrypoint.
// Run ids are globally unique, but the tenant check is still required before
// a mutating operation so a caller cannot cancel another tenant's run by id.
func (j *Journal) RequestRunCancelForTenant(ctx context.Context, runID, tenantID string) (string, error) {
	if strings.TrimSpace(tenantID) == "" {
		return CancelNotPossible, ErrNotFound
	}
	return j.requestRunCancel(ctx, runID, tenantID)
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
	tenantQ := `SELECT tenant_id FROM runs WHERE id = $1`
	if j.engine == EnginePostgres {
		// Serialize retry-tail sequence assignment across workers and keep the
		// authenticated tenant stable until every row has been inserted.
		tenantQ += ` FOR UPDATE`
	}
	var tenantID string
	if err := tx.QueryRowContext(ctx, j.bind(tenantQ), runID).Scan(&tenantID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: save run logs: resolve tenant: %w", err)
	}
	if err := j.requireRunLogPayloadKey(ctx, tx); err != nil {
		return err
	}
	var maxSeq sql.NullInt64
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT MAX(seq) FROM run_logs WHERE run_id = $1`), runID).Scan(&maxSeq); err != nil {
		return fmt.Errorf("journal: save run logs: read tail: %w", err)
	}
	startSeq := int64(0)
	if maxSeq.Valid {
		startSeq = maxSeq.Int64 + 1
		// A terminal hook can be retried after a lost acknowledgement. When the
		// same attempt is flushed again, recognize its exact existing suffix so
		// idempotency is preserved while a later DLQ retry can append new lines
		// under the same durable run id.
		tailQ := fmt.Sprintf(`SELECT seq,
			CASE WHEN (payload_crypto_version = 0 AND %s <= %d)
				OR (payload_crypto_version = 1 AND %s <= %d)
			THEN line ELSE NULL END,
			payload_crypto_version, plaintext_bytes, kind
			FROM run_logs WHERE run_id = $1 ORDER BY seq DESC LIMIT $2`,
			j.runLogStoredSizeExpr(), maxRunLogLineBytes,
			j.runLogStoredSizeExpr(), payloadcrypto.CiphertextLimit(maxRunLogLineBytes))
		rows, err := tx.QueryContext(ctx, j.bind(tailQ), runID, len(lines))
		if err != nil {
			return fmt.Errorf("journal: save run logs: read existing tail: %w", err)
		}
		var existing []string
		dedupPossible := true
		for rows.Next() {
			var (
				seq       int64
				stored    sql.NullString
				version   int
				plainSize sql.NullInt64
				kind      string
			)
			if err := rows.Scan(&seq, &stored, &version, &plainSize, &kind); err != nil {
				rows.Close()
				return fmt.Errorf("journal: save run logs: scan existing tail: %w", err)
			}
			if version == 0 && !stored.Valid {
				// An oversized historical line is not loaded into the daemon.
				// It cannot prove an exact duplicate suffix; append this flush.
				dedupPossible = false
				continue
			}
			line, err := j.openRunLogLine(tenantID, runID, seq, kind, version, plainSize, stored)
			if err != nil {
				rows.Close()
				return fmt.Errorf("journal: save run logs: authenticate existing tail: %w", err)
			}
			existing = append(existing, line)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("journal: save run logs: read existing tail: %w", err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("journal: save run logs: close existing tail: %w", err)
		}
		if dedupPossible && len(existing) == len(lines) {
			match := true
			for i := range lines {
				// existing is newest-first; lines is oldest-first.
				if existing[i] != lines[len(lines)-1-i] {
					match = false
					break
				}
			}
			if match {
				return tx.Commit()
			}
		}
	}
	stmt, err := tx.PrepareContext(ctx,
		j.bind(`INSERT INTO run_logs
			(run_id, seq, line, payload_crypto_version, plaintext_bytes, kind)
			VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`))
	if err != nil {
		return fmt.Errorf("journal: save run logs: prepare: %w", err)
	}
	defer stmt.Close()
	for i, line := range lines {
		seq := startSeq + int64(i)
		value, err := j.prepareRunLogLine(tenantID, runID, seq, runLogKindRuntime, line)
		if err != nil {
			return err
		}
		if _, err := stmt.ExecContext(ctx, runID, seq, value.line, value.version, value.plainBytes, runLogKindRuntime); err != nil {
			return fmt.Errorf("journal: save run logs: insert: %w", err)
		}
	}
	return tx.Commit()
}

// GetRunLogs returns a run's persisted log lines in order. Empty slice
// when none were saved (e.g. a still-running run whose logs only live in
// the in-memory ring).
func (j *Journal) GetRunLogs(ctx context.Context, runID string) ([]string, error) {
	return j.GetRunLogsPage(ctx, runID, 0, 0)
}

// GetRunLogsPage returns a bounded chronological page when limit is positive.
// A zero limit preserves the historical unbounded behavior for the dashboard;
// HTTP MCP supplies a positive limit and applies a byte cap before serializing
// the response.
func (j *Journal) GetRunLogsPage(ctx context.Context, runID string, limit, offset int) ([]string, error) {
	return j.getRunLogsPage(ctx, runID, "", limit, offset)
}

// GetRunLogsPageForTenant keeps the parent run tenant predicate in the same
// query as the persisted log read used by MCP. This avoids a check-then-read
// window when a run is erased or an identifier is later reused.
func (j *Journal) GetRunLogsPageForTenant(ctx context.Context, runID, tenantID string, limit, offset int) ([]string, error) {
	return j.getRunLogsPage(ctx, runID, tenantID, limit, offset)
}

// BoundedRunLogLine is the read-model form used by MCP. Bytes reports the
// durable UTF-8 size, while Text is populated only when the row fits the
// caller's bound. This keeps an oversized legacy log line out of process
// memory while still allowing the caller to emit an honest truncation marker.
type BoundedRunLogLine struct {
	Text      string
	Bytes     int
	Truncated bool
}

// GetRunLogsPageForTenantBounded keeps the tenant predicate and value bound in
// the same SQL query. A non-positive maxBytes is rejected because a log page
// without a materialization bound would defeat the control-plane contract.
func (j *Journal) GetRunLogsPageForTenantBounded(ctx context.Context, runID, tenantID string, limit, offset, maxBytes int) ([]BoundedRunLogLine, error) {
	if limit <= 0 || limit > 1000 || offset < 0 || maxBytes <= 0 || maxBytes > 16<<20 {
		return nil, errors.New("journal: invalid bounded log page")
	}
	sizeExpr := j.runLogStoredSizeExpr()
	// The bound has been validated as an integer above. Embed it rather than
	// repeating a placeholder before the run-id predicate: bind() rewrites
	// numbered placeholders to positional '?' for SQLite.
	valueExpr := fmt.Sprintf(`CASE WHEN run_logs.payload_crypto_version = 0 AND %s <= %d THEN run_logs.line
		WHEN run_logs.payload_crypto_version = 1 AND run_logs.plaintext_bytes <= %d AND %s <= %d THEN run_logs.line
		ELSE NULL END`, sizeExpr, maxBytes, maxBytes, sizeExpr, payloadcrypto.CiphertextLimit(maxBytes))
	q := fmt.Sprintf(`SELECT run_logs.seq, %s, run_logs.payload_crypto_version, run_logs.plaintext_bytes,
		run_logs.kind, runs.tenant_id, %s
		FROM run_logs JOIN runs ON runs.id = run_logs.run_id WHERE run_logs.run_id = $1`, valueExpr, sizeExpr)
	args := []any{runID}
	position := 2
	if tenantID != "" {
		q += fmt.Sprintf(" AND runs.tenant_id = $%d", position)
		args = append(args, tenantID)
		position++
	}
	q += fmt.Sprintf(" ORDER BY run_logs.seq ASC LIMIT $%d OFFSET $%d", position, position+1)
	args = append(args, limit, offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, fmt.Errorf("journal: get bounded run logs: %w", err)
	}
	defer rows.Close()
	out := make([]BoundedRunLogLine, 0, limit)
	for rows.Next() {
		var (
			seq       int64
			line      sql.NullString
			version   int
			plainSize sql.NullInt64
			kind      string
			owner     string
			storedLen int64
		)
		if err := rows.Scan(&seq, &line, &version, &plainSize, &kind, &owner, &storedLen); err != nil {
			return nil, fmt.Errorf("journal: scan bounded run log: %w", err)
		}
		item := BoundedRunLogLine{}
		if version == 1 {
			if j.payloadKey == nil {
				return nil, payloadcrypto.ErrKeyRequired
			}
			if !plainSize.Valid || plainSize.Int64 < 0 || plainSize.Int64 > maxRunLogLineBytes {
				return nil, payloadcrypto.ErrInvalidEnvelope
			}
			item.Bytes = int(plainSize.Int64)
			if storedLen > int64(payloadcrypto.CiphertextLimit(item.Bytes)) {
				return nil, payloadcrypto.ErrInvalidEnvelope
			}
		} else if version == 0 && !plainSize.Valid {
			item.Bytes = int(storedLen)
		} else {
			return nil, payloadcrypto.ErrInvalidEnvelope
		}
		if line.Valid {
			opened, err := j.openRunLogLine(owner, runID, seq, kind, version, plainSize, line)
			if err != nil {
				return nil, fmt.Errorf("journal: authenticate bounded run log: %w", err)
			}
			item.Text = opened
		} else {
			item.Truncated = true
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("journal: get bounded run logs rows: %w", err)
	}
	return out, nil
}

func (j *Journal) getRunLogsPage(ctx context.Context, runID, tenantID string, limit, offset int) ([]string, error) {
	q := fmt.Sprintf(`SELECT run_logs.seq,
		CASE WHEN (run_logs.payload_crypto_version = 0 AND %s <= %d)
			OR (run_logs.payload_crypto_version = 1 AND %s <= %d)
			THEN run_logs.line ELSE NULL END,
		run_logs.payload_crypto_version, run_logs.plaintext_bytes, run_logs.kind, runs.tenant_id
		FROM run_logs JOIN runs ON runs.id = run_logs.run_id WHERE run_logs.run_id = $1`,
		j.runLogStoredSizeExpr(), maxRunLogLineBytes,
		j.runLogStoredSizeExpr(), payloadcrypto.CiphertextLimit(maxRunLogLineBytes))
	args := []any{runID}
	if tenantID != "" {
		q += ` AND runs.tenant_id = $2`
		args = append(args, tenantID)
	}
	q += ` ORDER BY run_logs.seq ASC`
	if limit > 0 {
		limitPos := len(args) + 1
		offsetPos := limitPos + 1
		q += fmt.Sprintf(` LIMIT $%d OFFSET $%d`, limitPos, offsetPos)
		args = append(args, limit, offset)
	}
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, fmt.Errorf("journal: get run logs: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var (
			seq       int64
			stored    sql.NullString
			version   int
			plainSize sql.NullInt64
			kind      string
			owner     string
		)
		if err := rows.Scan(&seq, &stored, &version, &plainSize, &kind, &owner); err != nil {
			return nil, err
		}
		line, err := j.openRunLogLine(owner, runID, seq, kind, version, plainSize, stored)
		if err != nil {
			return nil, fmt.Errorf("journal: authenticate run log: %w", err)
		}
		out = append(out, line)
	}
	return out, rows.Err()
}

func (j *Journal) runLogStoredSizeExpr() string {
	if j.engine == EnginePostgres {
		return "octet_length(run_logs.line)"
	}
	return "length(CAST(run_logs.line AS BLOB))"
}
