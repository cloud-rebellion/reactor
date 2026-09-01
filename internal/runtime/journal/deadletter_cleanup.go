package journal

import (
	"context"
	"fmt"
)

// DeleteDeadLettersByRun removes every DLQ item resolved by a fully successful
// redrive. A run can accumulate more than one item across repeated failures or
// different steps; deleting only the operator-selected row leaves stale retry
// buttons that no longer describe the successful run.
func (j *Journal) DeleteDeadLettersByRun(ctx context.Context, runID string) (int64, error) {
	const q = `DELETE FROM dead_letter WHERE run_id = $1`
	res, err := j.db.ExecContext(ctx, j.bind(q), runID)
	if err != nil {
		return 0, fmt.Errorf("journal: delete run dead_letters: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
