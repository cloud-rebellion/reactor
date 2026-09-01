package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// DeadLetterItem is one row of the dead_letter table. The supervisor
// writes a row when a step's final attempt returned a non-retryable error;
// operators read the table via `reactor dlq list/show` to inspect or
// (week 8) re-queue the failed step.
//
// JSON tags use snake_case so the CLI --json output matches what we
// expect from future dashboard / MCP surfaces.
type DeadLetterItem struct {
	ID           string          `json:"id"`
	RunID        string          `json:"run_id"`
	StepName     string          `json:"step_name"`
	StepSeq      *int64          `json:"step_seq,omitempty"`
	StepAttempt  *int            `json:"step_attempt,omitempty"`
	FailureOrder int64           `json:"failure_order,omitempty"`
	ErrorText    string          `json:"error_text"`
	Payload      json.RawMessage `json:"payload"`
	MovedAt      time.Time       `json:"moved_at"`
}

// MoveStepToDeadLetter inserts a dead_letter row. payload is the step's
// last-attempted output (or input snapshot) JSON-encoded so a manual
// retry can inspect the data the failed attempt was working with.
func (j *Journal) MoveStepToDeadLetter(ctx context.Context, runID, stepName, errorText string, payload json.RawMessage) error {
	return j.moveStepToDeadLetter(ctx, runID, stepName, nil, nil, errorText, payload)
}

// MoveStepAttemptToDeadLetter inserts a DLQ row bound to one exact durable
// attempt. This identity is what lets an operator redrive a repeated step name
// without accidentally authorizing another loop ordinal/generation.
func (j *Journal) MoveStepAttemptToDeadLetter(ctx context.Context, runID, stepName string, seq int64, attempt int, errorText string, payload json.RawMessage) error {
	return j.moveStepToDeadLetter(ctx, runID, stepName, &seq, &attempt, errorText, payload)
}

func (j *Journal) moveStepToDeadLetter(ctx context.Context, runID, stepName string, seq *int64, attempt *int, errorText string, payload json.RawMessage) error {
	id, err := newID("dlq_")
	if err != nil {
		return err
	}
	pl := outputArg(payload, j.engine)
	if pl == nil {
		// dead_letter.payload is NOT NULL on both engines; default to {}.
		if j.engine == EngineSQLite {
			pl = "{}"
		} else {
			pl = []byte("{}")
		}
	}
	const q = `INSERT INTO dead_letter
		(id, run_id, step_name, step_seq, step_attempt, failure_order, error_text, payload)
		SELECT $1, $2, $3, $4, $5, COALESCE(MAX(failure_order), 0) + 1, $6, $7
		FROM dead_letter WHERE run_id = $8`
	_, err = j.db.ExecContext(ctx, j.bind(q),
		id, runID, stepName, nullableInt64(seq), nullableInt(attempt), errorText, pl, runID,
	)
	if err != nil {
		return fmt.Errorf("journal: move dead_letter: %w", err)
	}
	return nil
}

// ListDeadLetterItems pages through dead_letter newest-first. limit caps
// the result; offset supports follow-up pagination from CLI / dashboard.
func (j *Journal) ListDeadLetterItems(ctx context.Context, limit, offset int) ([]DeadLetterItem, error) {
	if limit <= 0 {
		limit = 50
	}
	const q = `SELECT id, run_id, step_name, step_seq, step_attempt, failure_order, error_text, payload, moved_at
		FROM dead_letter ORDER BY moved_at DESC, id DESC LIMIT $1 OFFSET $2`
	rows, err := j.db.QueryContext(ctx, j.bind(q), limit, offset)
	if err != nil {
		return nil, fmt.Errorf("journal: list dead_letter: %w", err)
	}
	defer rows.Close()

	var out []DeadLetterItem
	for rows.Next() {
		item, err := scanDeadLetter(rows.Scan, j)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// GetDeadLetterItem returns the single row by id. Returns ErrNotFound when
// no row matches; callers (dlq show CLI) map this to a non-zero exit.
func (j *Journal) GetDeadLetterItem(ctx context.Context, id string) (DeadLetterItem, error) {
	const q = `SELECT id, run_id, step_name, step_seq, step_attempt, failure_order, error_text, payload, moved_at
		FROM dead_letter WHERE id = $1`
	row := j.db.QueryRowContext(ctx, j.bind(q), id)
	item, err := scanDeadLetter(row.Scan, j)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DeadLetterItem{}, ErrNotFound
		}
		return DeadLetterItem{}, err
	}
	return item, nil
}

// FindDeadLetterByRun returns the dead_letter row for the given run id,
// or ErrNotFound when no DLQ row exists for the run. The dashboard's
// run detail page uses this to decide whether to render a "Retry from
// DLQ" button.
func (j *Journal) FindDeadLetterByRun(ctx context.Context, runID string) (DeadLetterItem, error) {
	const q = `SELECT id, run_id, step_name, step_seq, step_attempt, failure_order, error_text, payload, moved_at
		FROM dead_letter WHERE run_id = $1
		ORDER BY CASE WHEN failure_order IS NULL THEN 1 ELSE 0 END, failure_order DESC, moved_at DESC, id DESC LIMIT 1`
	row := j.db.QueryRowContext(ctx, j.bind(q), runID)
	item, err := scanDeadLetter(row.Scan, j)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DeadLetterItem{}, ErrNotFound
		}
		return DeadLetterItem{}, err
	}
	return item, nil
}

// DeleteDeadLetter removes a dead_letter row by id. Used by `reactor
// dlq retry` after a successful retry so the operator's todo list
// shrinks. Errors when the row is gone (caller should treat as success).
func (j *Journal) DeleteDeadLetter(ctx context.Context, id string) error {
	const q = `DELETE FROM dead_letter WHERE id = $1`
	res, err := j.db.ExecContext(ctx, j.bind(q), id)
	if err != nil {
		return fmt.Errorf("journal: delete dead_letter: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanDeadLetter(scan func(...any) error, j *Journal) (DeadLetterItem, error) {
	var (
		item    DeadLetterItem
		seq     sql.NullInt64
		attempt sql.NullInt64
		order   sql.NullInt64
		payload []byte
		moved   sql.NullString
	)
	if err := scan(&item.ID, &item.RunID, &item.StepName, &seq, &attempt, &order, &item.ErrorText, &payload, &moved); err != nil {
		return DeadLetterItem{}, err
	}
	if seq.Valid {
		value := seq.Int64
		item.StepSeq = &value
	}
	if attempt.Valid {
		value := int(attempt.Int64)
		item.StepAttempt = &value
	}
	if order.Valid {
		item.FailureOrder = order.Int64
	}
	if len(payload) > 0 {
		item.Payload = append(json.RawMessage(nil), payload...)
	}
	if moved.Valid {
		if t, err := j.parseTime(moved.String); err == nil {
			item.MovedAt = t
		}
	}
	return item, nil
}

func nullableInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullableInt(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}
