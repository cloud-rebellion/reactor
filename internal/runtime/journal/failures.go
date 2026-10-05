package journal

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

// FailedRun is one failed execution for the error log: the run plus the error
// text of its most recent failed step. PostmortemID is filled by the caller
// (the server links to a generated post-mortem when one exists).
type FailedRun struct {
	RunID      string
	WorkflowID string
	TenantID   string
	Status     string
	StartedAt  time.Time
	FinishedAt time.Time
	StepName   string
	Error      string
}

// ListFailedRuns returns the most recent failed executions (status LIKE
// 'failed%', covering 'failed' + 'failed_dlq') with the error text of each
// run's latest failed step. When tenantID is non-empty it is scoped to that
// tenant (dashboard isolation). This is the error log's data source.
func (j *Journal) ListFailedRuns(ctx context.Context, tenantID string, limit int) ([]FailedRun, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	// The exact failed step is selected in one join, so its encrypted error
	// cannot be accidentally attributed to a different attempt. The UI only
	// displays a short preview; SQL omits larger fields before materialization.
	const maxFailurePreviewBytes = 4096
	q := fmt.Sprintf(`SELECT r.id, r.workflow_id, r.tenant_id, r.status, r.started_at, r.finished_at,
		COALESCE(steps.step_name, ''), COALESCE(steps.seq, 0), COALESCE(steps.attempt, 0),
		COALESCE(steps.payload_crypto_version, 0), steps.error_plaintext_bytes, %s,
		COALESCE(steps.error_text IS NOT NULL, false)
		FROM runs r LEFT JOIN steps ON steps.run_id = r.id AND
			(steps.step_name, steps.seq, steps.attempt) =
			(SELECT s.step_name, s.seq, s.attempt FROM steps s
			 WHERE s.run_id = r.id AND s.status = 'failed'
			 ORDER BY s.started_at DESC, s.seq DESC, s.attempt DESC LIMIT 1)
		WHERE r.status LIKE 'failed%%'`, stepErrorValue(j.engine, maxFailurePreviewBytes))
	args := []any{}
	pos := 1
	if tenantID != "" {
		q += fmt.Sprintf(" AND r.tenant_id = $%d", pos)
		args = append(args, tenantID)
		pos++
	}
	q += fmt.Sprintf(" ORDER BY r.finished_at DESC LIMIT $%d", pos)
	args = append(args, limit)

	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, fmt.Errorf("journal: list failed runs: %w", err)
	}
	defer rows.Close()
	var out []FailedRun
	for rows.Next() {
		var (
			fr                FailedRun
			started, finished sql.NullString
			seq               int64
			attempt           int
			version           int
			plainBytes        sql.NullInt64
			storedError       sql.NullString
			errorPresent      bool
		)
		if err := rows.Scan(&fr.RunID, &fr.WorkflowID, &fr.TenantID, &fr.Status,
			&started, &finished, &fr.StepName, &seq, &attempt, &version, &plainBytes,
			&storedError, &errorPresent); err != nil {
			return nil, fmt.Errorf("journal: scan failed run: %w", err)
		}
		if version == 1 && j.payloadKey == nil {
			return nil, payloadcrypto.ErrKeyRequired
		}
		if version != 0 && version != 1 || version == 1 &&
			(errorPresent != plainBytes.Valid || plainBytes.Int64 < 0 || plainBytes.Int64 > maxStepPayloadPlaintextBytes) {
			return nil, payloadcrypto.ErrInvalidEnvelope
		}
		if storedError.Valid {
			fr.Error, err = j.openStepError(fr.TenantID, fr.RunID, fr.StepName, seq, attempt,
				version, plainBytes, storedError.String)
			if err != nil {
				return nil, err
			}
		} else if errorPresent {
			if version == 1 && plainBytes.Int64 <= maxFailurePreviewBytes {
				return nil, payloadcrypto.ErrInvalidEnvelope
			}
			fr.Error = "[step error omitted: exceeds preview limit]"
		}
		if started.Valid {
			if t, err := j.parseTime(started.String); err == nil {
				fr.StartedAt = t
			}
		}
		if finished.Valid {
			if t, err := j.parseTime(finished.String); err == nil {
				fr.FinishedAt = t
			}
		}
		out = append(out, fr)
	}
	return out, rows.Err()
}

// WorkflowFailureCount is one row of the recurring-failure summary.
type WorkflowFailureCount struct {
	WorkflowID string
	Count      int
}

// TopFailingWorkflows groups failed runs by workflow to surface recurring
// failure patterns (the workflows worth fixing first). Optionally tenant-scoped.
func (j *Journal) TopFailingWorkflows(ctx context.Context, tenantID string, limit int) ([]WorkflowFailureCount, error) {
	if limit <= 0 {
		limit = 10
	}
	q := `SELECT workflow_id, COUNT(*) AS n FROM runs WHERE status LIKE 'failed%'`
	args := []any{}
	pos := 1
	if tenantID != "" {
		q += fmt.Sprintf(" AND tenant_id = $%d", pos)
		args = append(args, tenantID)
		pos++
	}
	q += fmt.Sprintf(" GROUP BY workflow_id ORDER BY n DESC, workflow_id LIMIT $%d", pos)
	args = append(args, limit)
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, fmt.Errorf("journal: top failing workflows: %w", err)
	}
	defer rows.Close()
	var out []WorkflowFailureCount
	for rows.Next() {
		var c WorkflowFailureCount
		if err := rows.Scan(&c.WorkflowID, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CountFailedRuns counts failed executions, optionally scoped to a tenant.
func (j *Journal) CountFailedRuns(ctx context.Context, tenantID string) (int, error) {
	q := `SELECT COUNT(*) FROM runs WHERE status LIKE 'failed%'`
	args := []any{}
	if tenantID != "" {
		q += " AND tenant_id = $1"
		args = append(args, tenantID)
	}
	var n int
	if err := j.db.QueryRowContext(ctx, j.bind(q), args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("journal: count failed runs: %w", err)
	}
	return n, nil
}
