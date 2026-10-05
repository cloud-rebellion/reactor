package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// BlockReceipt is a value-free report from the workflow SDK. It is not an
// attestation: authored Go can speak the child wire protocol directly.
type BlockReceipt struct {
	RunID       string `json:"run_id"`
	StepName    string `json:"step_name"`
	Seq         int64  `json:"seq"`
	Attempt     int    `json:"attempt"`
	CallOrdinal int    `json:"call_ordinal"`
	BlockID     string `json:"block_id"`
	Kind        string `json:"kind"`
	Mode        string `json:"mode"`
	LeftRows    int    `json:"left_rows"`
	RightRows   int    `json:"right_rows"`
	OutputRows  int    `json:"output_rows"`
	MaxRows     int    `json:"max_rows"`
	InputRows   *int   `json:"input_rows,omitempty"`
	YesRows     *int   `json:"yes_rows,omitempty"`
	NoRows      *int   `json:"no_rows,omitempty"`
	Outcome     string `json:"outcome"`
}

type ObservedBlockIdentity struct {
	StepName string `json:"step_name"`
	BlockID  string `json:"block_id"`
}

// AppendBlockReceipt binds a report to a running tenant-owned step attempt.
// Distributed execution locks its exact lease generation before the run and
// step; reaping/finalization cannot replace ownership during this commit. It
// ACKs only after the durable row exists. Counts remain bounded even if child
// code bypasses the SDK helper and sends a wire frame directly.
func (j *Journal) AppendBlockReceipt(ctx context.Context, tenantID, leaseOwner string, receipt BlockReceipt) error {
	if tenantID == "" || receipt.RunID == "" || receipt.StepName == "" || len(receipt.StepName) > 128 ||
		receipt.Seq < 1 || receipt.Attempt < 1 || receipt.CallOrdinal < 1 || receipt.CallOrdinal > 128 ||
		!validBlockReceiptID(receipt.BlockID) || !ValidBlockReceiptShape(receipt) {
		return errors.New("journal: invalid block receipt metadata")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin block receipt: %w", err)
	}
	defer tx.Rollback()
	var leaseDeadline time.Time
	if leaseOwner != "" {
		// Same lock order as FinalizeOwnedRun and ReapExpiredLeases.
		leaseDeadline, err = j.lockOwnedLease(ctx, tx, receipt.RunID, leaseOwner)
		if err != nil {
			return err
		}
	}
	runQ := `SELECT status FROM runs WHERE id = $1 AND tenant_id = $2`
	if j.engine == EnginePostgres {
		runQ += ` FOR UPDATE`
	} else {
		// SQLite's deferred transaction needs its writer lock before reads.
		res, lockErr := tx.ExecContext(ctx, j.bind(`UPDATE runs SET id = id WHERE id = $1 AND tenant_id = $2`), receipt.RunID, tenantID)
		if lockErr != nil {
			return fmt.Errorf("journal: lock observed receipt run: %w", lockErr)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
	}
	var runStatus string
	if err := tx.QueryRowContext(ctx, j.bind(runQ), receipt.RunID, tenantID).Scan(&runStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: read observed receipt run: %w", err)
	}
	if runStatus != "running" {
		return ErrNotFound
	}
	stepQ := `SELECT status FROM steps WHERE run_id = $1 AND seq = $2 AND step_name = $3 AND attempt = $4`
	if j.engine == EnginePostgres {
		stepQ += ` FOR UPDATE`
	}
	var stepStatus string
	if err := tx.QueryRowContext(ctx, j.bind(stepQ), receipt.RunID, receipt.Seq, receipt.StepName, receipt.Attempt).Scan(&stepStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: read observed receipt step: %w", err)
	}
	if stepStatus != StatusRunning {
		return ErrNotFound
	}
	const insert = `INSERT INTO run_block_receipts
		(run_id, step_name, seq, attempt, call_ordinal, block_id, kind, mode,
		 left_rows, right_rows, output_rows, max_rows, input_rows, yes_rows, no_rows,
		 outcome, observed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`
	res, err := tx.ExecContext(ctx, j.bind(insert), receipt.RunID, receipt.StepName,
		receipt.Seq, receipt.Attempt, receipt.CallOrdinal, receipt.BlockID,
		receipt.Kind, receipt.Mode, receipt.LeftRows, receipt.RightRows,
		receipt.OutputRows, receipt.MaxRows, receipt.InputRows, receipt.YesRows,
		receipt.NoRows, receipt.Outcome, j.now())
	if err != nil {
		return fmt.Errorf("journal: append block receipt: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("journal: append block receipt rows affected: %w", err)
	}
	if n != 1 {
		return ErrNotFound
	}
	if leaseOwner != "" {
		if err := checkOwnedLeaseDeadline(receipt.RunID, leaseDeadline); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit block receipt: %w", err)
	}
	return nil
}

// ListBlockReceiptsForTenant is a bounded metadata-only projection. A foreign
// run is indistinguishable from a missing one to this reader.
func (j *Journal) ListBlockReceiptsForTenant(ctx context.Context, runID, tenantID string, limit, offset int) ([]BlockReceipt, bool, error) {
	if runID == "" || tenantID == "" || limit < 1 || limit > 500 || offset < 0 || offset > 10000 {
		return nil, false, errors.New("journal: invalid block receipt page")
	}
	const q = `SELECT b.run_id, b.step_name, b.seq, b.attempt, b.call_ordinal,
		b.block_id, b.kind, b.mode, b.left_rows, b.right_rows, b.output_rows,
		b.max_rows, b.input_rows, b.yes_rows, b.no_rows, b.outcome
		FROM run_block_receipts b JOIN runs r ON r.id = b.run_id
		WHERE b.run_id = $1 AND r.tenant_id = $2
		ORDER BY b.seq DESC, b.attempt DESC, b.call_ordinal DESC
		LIMIT $3 OFFSET $4`
	rows, err := j.db.QueryContext(ctx, j.bind(q), runID, tenantID, limit+1, offset)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list block receipts: %w", err)
	}
	defer rows.Close()
	out := make([]BlockReceipt, 0, limit)
	for rows.Next() {
		var item BlockReceipt
		var input, yes, no sql.NullInt64
		if err := rows.Scan(&item.RunID, &item.StepName, &item.Seq, &item.Attempt,
			&item.CallOrdinal, &item.BlockID, &item.Kind, &item.Mode,
			&item.LeftRows, &item.RightRows, &item.OutputRows, &item.MaxRows,
			&input, &yes, &no, &item.Outcome); err != nil {
			return nil, false, fmt.Errorf("journal: scan block receipt: %w", err)
		}
		if input.Valid {
			value := int(input.Int64)
			item.InputRows = &value
		}
		if yes.Valid {
			value := int(yes.Int64)
			item.YesRows = &value
		}
		if no.Valid {
			value := int(no.Int64)
			item.NoRows = &value
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("journal: iterate block receipts: %w", err)
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

// ObservedBlockIdentitiesForTenant returns the complete set of observed
// declared block identities under the visual-flow total bound. A caller may
// label a missing identity "no SDK observation" only after this succeeds.
func (j *Journal) ObservedBlockIdentitiesForTenant(ctx context.Context, runID, tenantID string) ([]ObservedBlockIdentity, error) {
	if runID == "" || tenantID == "" {
		return nil, errors.New("journal: run and tenant are required for block presence")
	}
	const q = `SELECT DISTINCT b.step_name, b.block_id
		FROM run_block_receipts b JOIN runs r ON r.id = b.run_id
		WHERE b.run_id = $1 AND r.tenant_id = $2
		ORDER BY b.step_name, b.block_id LIMIT 257`
	rows, err := j.db.QueryContext(ctx, j.bind(q), runID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("journal: list observed block identities: %w", err)
	}
	defer rows.Close()
	out := make([]ObservedBlockIdentity, 0, 32)
	for rows.Next() {
		var item ObservedBlockIdentity
		if err := rows.Scan(&item.StepName, &item.BlockID); err != nil {
			return nil, fmt.Errorf("journal: scan observed block identity: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("journal: iterate observed block identities: %w", err)
	}
	if len(out) > 256 {
		return nil, errors.New("journal: observed block identities exceed visual-flow bound")
	}
	return out, nil
}

func validBlockReceiptID(id string) bool {
	if len(id) == 0 || len(id) > 128 || !((id[0] >= 'A' && id[0] <= 'Z') || (id[0] >= 'a' && id[0] <= 'z')) {
		return false
	}
	for i := 1; i < len(id); i++ {
		c := id[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func validBlockReceiptMode(mode string) bool {
	switch mode {
	case "inner_join", "left_join", "right_join", "full_join":
		return true
	}
	return false
}

// ValidBlockReceiptShape rejects impossible or mixed operation metadata.
// Both supervisor and journal enforce this before accepting a child report.
func ValidBlockReceiptShape(r BlockReceipt) bool {
	if r.Kind == "split" {
		return r.Mode == "" && r.MaxRows == 0 && r.LeftRows == 0 &&
			r.RightRows == 0 && r.OutputRows == 0 && r.Outcome == "succeeded" &&
			r.InputRows != nil && r.YesRows != nil && r.NoRows != nil &&
			*r.InputRows >= 0 && *r.InputRows <= 100000 &&
			*r.YesRows >= 0 && *r.YesRows <= 100000 &&
			*r.NoRows >= 0 && *r.NoRows <= 100000 &&
			*r.YesRows+*r.NoRows == *r.InputRows
	}
	if r.Kind == "iterate" || r.Kind == "aggregate" {
		if r.InputRows == nil || *r.InputRows < 0 || *r.InputRows > 100000 ||
			r.Mode != "" || r.MaxRows != 0 || r.LeftRows != 0 || r.RightRows != 0 ||
			r.YesRows != nil || r.NoRows != nil || r.Outcome != "succeeded" {
			return false
		}
		if r.Kind == "iterate" {
			return r.OutputRows == *r.InputRows
		}
		return r.OutputRows == 1
	}
	return r.Kind == "merge" && validBlockReceiptMode(r.Mode) &&
		r.MaxRows >= 1 && r.MaxRows <= 100000 &&
		r.LeftRows >= 0 && r.LeftRows <= 100000 &&
		r.RightRows >= 0 && r.RightRows <= 100000 &&
		r.OutputRows >= 0 && r.OutputRows <= r.MaxRows &&
		(r.Outcome == "succeeded" || r.Outcome == "bounded_failure") &&
		(r.Outcome != "bounded_failure" || r.OutputRows == 0) &&
		r.InputRows == nil && r.YesRows == nil && r.NoRows == nil
}
