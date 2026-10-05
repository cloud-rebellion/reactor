package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// RuntimeSecretAccess is a value-free receipt for a secret made available to
// a workflow child. It covers both vault credentials and OAuth connections.
// The receipt is written after successful resolution and before the wire reply;
// it means authorization was recorded, not that a child consumed the reply.
type RuntimeSecretAccess struct {
	ID         string `json:"id"`
	TenantID   string `json:"tenant_id"`
	WorkflowID string `json:"workflow_id"`
	RunID      string `json:"run_id"`
	SecretRef  string `json:"secret_ref"`
	SecretKind string `json:"secret_kind"`
	// PolicyRevision binds a generic broker use to its reviewed API policy.
	PolicyRevision int64     `json:"policy_revision,omitempty"`
	At             time.Time `json:"at"`
}

// AppendRuntimeSecretAccess binds a value-release receipt to the current run
// and, in distributed mode, the exact live lease generation. The lease is
// locked before the run, matching reaping and finalization; the run lock also
// serializes this decision with cancellation. An empty owner is allowed only
// for a local run with no lease. This gate precedes value release, but cannot
// prevent cancellation or expiry immediately after it commits.
func (j *Journal) AppendRuntimeSecretAccess(ctx context.Context, leaseOwner string, entry RuntimeSecretAccess) error {
	if entry.TenantID == "" || entry.WorkflowID == "" || entry.RunID == "" || entry.SecretRef == "" {
		return errors.New("journal: runtime secret audit requires tenant, workflow, run, and secret reference")
	}
	if len(entry.SecretRef) > 512 {
		return errors.New("journal: runtime secret audit reference exceeds 512 bytes")
	}
	if entry.SecretKind != "vault" && entry.SecretKind != "oauth" {
		return errors.New("journal: runtime secret audit kind must be vault or oauth")
	}
	if entry.PolicyRevision < 0 || (entry.PolicyRevision > 0 && entry.SecretKind != "oauth") {
		return errors.New("journal: invalid broker policy revision on runtime secret audit")
	}
	id, err := newID("secretaccess_")
	if err != nil {
		return err
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin runtime secret audit: %w", err)
	}
	defer tx.Rollback()
	var leaseDeadline time.Time
	if leaseOwner != "" {
		leaseDeadline, err = j.lockOwnedLease(ctx, tx, entry.RunID, leaseOwner)
		if err != nil {
			return err
		}
	}
	if j.engine == EngineSQLite {
		// A deferred SQLite transaction must acquire its writer lock before
		// reading state; otherwise a concurrent cancel/reap can win afterward.
		res, err := tx.ExecContext(ctx, j.bind(`UPDATE runs SET id = id WHERE id = $1 AND workflow_id = $2 AND tenant_id = $3`),
			entry.RunID, entry.WorkflowID, entry.TenantID)
		if err != nil {
			return fmt.Errorf("journal: lock runtime secret run: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
	}
	runQ := `SELECT 1 FROM runs WHERE id = $1 AND workflow_id = $2 AND tenant_id = $3
		AND status = 'running' AND cancel_requested = $4`
	if j.engine == EnginePostgres {
		runQ += ` FOR UPDATE`
	}
	var active int
	err = tx.QueryRowContext(ctx, j.bind(runQ), entry.RunID, entry.WorkflowID,
		entry.TenantID, j.boolValue(false)).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("journal: verify runtime secret run: %w", err)
	}
	if leaseOwner == "" {
		// A local supervisor must not become an accidental bypass for a run
		// already owned by a distributed worker. Claiming locks/updates the
		// run, so the run lock above also serializes a concurrent claim.
		var leased int
		err := tx.QueryRowContext(ctx, j.bind(`SELECT 1 FROM leases WHERE run_id = $1`), entry.RunID).Scan(&leased)
		if err == nil {
			return fmt.Errorf("%w: runtime secret access requires lease owner run=%s", ErrLeaseOwnershipLost, entry.RunID)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("journal: verify unleased runtime secret run: %w", err)
		}
	}
	const q = `INSERT INTO runtime_secret_access_audit
		(id, tenant_id, workflow_id, run_id, secret_ref, secret_kind, at, policy_revision)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	var revision any
	if entry.PolicyRevision > 0 {
		revision = entry.PolicyRevision
	}
	res, err := tx.ExecContext(ctx, j.bind(q), id, entry.TenantID, entry.WorkflowID,
		entry.RunID, entry.SecretRef, entry.SecretKind, j.now(), revision)
	if err != nil {
		return fmt.Errorf("journal: append runtime secret audit: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("journal: append runtime secret audit: rows affected: %w", err)
	} else if n != 1 {
		return ErrNotFound
	}
	if leaseOwner != "" {
		if err := checkOwnedLeaseDeadline(entry.RunID, leaseDeadline); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit runtime secret audit: %w", err)
	}
	return nil
}

// VerifyRuntimeSecretRun is a final, read-only check close to a value reply or
// brokered HTTP request. The receipt transaction above is the durable gate;
// this check catches a cancel/reap committed after that transaction. It cannot
// make an external write or a child pipe reply atomic with later lease changes.
func (j *Journal) VerifyRuntimeSecretRun(ctx context.Context, runID, workflowID, tenantID, leaseOwner string) error {
	if runID == "" || workflowID == "" || tenantID == "" {
		return errors.New("journal: runtime secret verification requires run, workflow, and tenant")
	}
	q := `SELECT 1 FROM runs r WHERE r.id = $1 AND r.workflow_id = $2 AND r.tenant_id = $3
		AND r.status = 'running' AND r.cancel_requested = $4`
	args := []any{runID, workflowID, tenantID, j.boolValue(false)}
	if leaseOwner != "" {
		q += ` AND EXISTS (SELECT 1 FROM leases l WHERE l.run_id = r.id
			AND l.worker_id = $5 AND l.expires_at > $6)`
		args = append(args, leaseOwner, j.formatTime(time.Now().UTC()))
	} else {
		q += ` AND NOT EXISTS (SELECT 1 FROM leases l WHERE l.run_id = r.id)`
	}
	var one int
	err := j.db.QueryRowContext(ctx, j.bind(q), args...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrLeaseOwnershipLost
	}
	if err != nil {
		return fmt.Errorf("journal: verify runtime secret run: %w", err)
	}
	return nil
}

// ListRuntimeSecretAccessForTenant returns bounded newest-first receipts for
// operators and tests. Secret values, token bytes, and fingerprints never
// enter this table or this read model.
func (j *Journal) ListRuntimeSecretAccessForTenant(ctx context.Context, tenantID string, limit, offset int) ([]RuntimeSecretAccess, error) {
	if tenantID == "" || limit < 1 || limit > 1000 || offset < 0 {
		return nil, errors.New("journal: invalid runtime secret audit page")
	}
	const q = `SELECT id, tenant_id, workflow_id, run_id, secret_ref, secret_kind, at, policy_revision
		FROM runtime_secret_access_audit WHERE tenant_id = $1
		ORDER BY at DESC, id DESC LIMIT $2 OFFSET $3`
	rows, err := j.db.QueryContext(ctx, j.bind(q), tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("journal: list runtime secret audit: %w", err)
	}
	defer rows.Close()
	out := make([]RuntimeSecretAccess, 0, limit)
	for rows.Next() {
		var entry RuntimeSecretAccess
		var at any
		var revision sql.NullInt64
		if err := rows.Scan(&entry.ID, &entry.TenantID, &entry.WorkflowID, &entry.RunID,
			&entry.SecretRef, &entry.SecretKind, &at, &revision); err != nil {
			return nil, fmt.Errorf("journal: scan runtime secret audit: %w", err)
		}
		if revision.Valid {
			entry.PolicyRevision = revision.Int64
		}
		switch v := at.(type) {
		case time.Time:
			entry.At = v.UTC()
		case string:
			parsed, err := j.parseTime(v)
			if err != nil {
				return nil, fmt.Errorf("journal: parse runtime secret audit time: %w", err)
			}
			entry.At = parsed
		case []byte:
			parsed, err := j.parseTime(string(v))
			if err != nil {
				return nil, fmt.Errorf("journal: parse runtime secret audit time: %w", err)
			}
			entry.At = parsed
		default:
			return nil, fmt.Errorf("journal: unexpected runtime secret audit time type %T", at)
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("journal: iterate runtime secret audit: %w", err)
	}
	return out, nil
}
