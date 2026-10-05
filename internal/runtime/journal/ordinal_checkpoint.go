package journal

import (
	"context"
	"errors"
	"fmt"
)

// RecordedCall is the durable operation identity at one workflow call ordinal.
// Steps and suspended waits use separate tables, but their seq values come
// from the same SDK counter and must not be interpreted independently.
type RecordedCall struct {
	Kind     string
	StepName string
}

const RecordedCallStep = "step"

// ErrRecordedCallConflict means multiple operation identities were already
// persisted at the same ordinal. A resumed workflow cannot safely choose one.
var ErrRecordedCallConflict = errors.New("journal: conflicting recorded calls at ordinal")

// FindRecordedCallBySeq reads a prior step attempt or suspended wait at seq.
// It includes unsuccessful steps and fired waits: both still prove which
// operation the original workflow reached. A conflict fails closed instead of
// treating the most recently written row as authoritative. Pre-ordinal seq=0
// retains the legacy name-keyed replay behavior.
func (j *Journal) FindRecordedCallBySeq(ctx context.Context, runID string, seq int64) (RecordedCall, error) {
	if seq <= 0 {
		return RecordedCall{}, ErrNotFound
	}
	const q = `SELECT kind, step_name FROM (
		SELECT 'step' AS kind, step_name FROM steps WHERE run_id = $1 AND seq = $2
		UNION
		SELECT kind, step_name FROM schedules
		WHERE run_id = $3 AND seq = $4 AND kind IN ('sleep', 'signal')
	) AS recorded LIMIT 2`
	rows, err := j.db.QueryContext(ctx, j.bind(q), runID, seq, runID, seq)
	if err != nil {
		return RecordedCall{}, fmt.Errorf("journal: find recorded call by seq: %w", err)
	}
	defer rows.Close()
	var call RecordedCall
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return RecordedCall{}, fmt.Errorf("journal: read recorded call by seq: %w", err)
		}
		return RecordedCall{}, ErrNotFound
	}
	if err := rows.Scan(&call.Kind, &call.StepName); err != nil {
		return RecordedCall{}, fmt.Errorf("journal: scan recorded call by seq: %w", err)
	}
	if rows.Next() {
		return RecordedCall{}, fmt.Errorf("%w: run=%s seq=%d", ErrRecordedCallConflict, runID, seq)
	}
	if err := rows.Err(); err != nil {
		return RecordedCall{}, fmt.Errorf("journal: read recorded call by seq: %w", err)
	}
	return call, nil
}
