package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrWorkflowDisabled means a new live run lost the enabled-state admission
// race. Callers should surface the same operator-facing disabled result as the
// fast IsWorkflowEnabled check, while automatic trigger sources may treat it
// as a no-op.
var ErrWorkflowDisabled = errors.New("journal: workflow is disabled")

// beginWorkflowAdmissionTx opens the transaction used by live run insertion.
// The workflow row is locked before its enabled flag is read, so a disable
// cannot commit between the admission check and the run INSERT. SQLite has no
// row-level FOR UPDATE; its harmless self-update acquires the single-writer
// lock and gives the same ordering against SetWorkflowEnabled.
func (j *Journal) beginWorkflowAdmissionTx(ctx context.Context, workflowID string) (*sql.Tx, error) {
	// Tenant quota counters are read after a tenant row lock. PostgreSQL needs
	// a fresh statement snapshot after waiting on that lock, even when an
	// operator has raised the server's default transaction isolation level.
	var txOpts *sql.TxOptions
	if j.engine == EnginePostgres {
		txOpts = &sql.TxOptions{Isolation: sql.LevelReadCommitted}
	}
	tx, err := j.db.BeginTx(ctx, txOpts)
	if err != nil {
		return nil, fmt.Errorf("journal: begin enabled workflow admission: %w", err)
	}
	rollback := func(e error) (*sql.Tx, error) {
		_ = tx.Rollback()
		return nil, e
	}

	if err := j.lockWorkflowTx(ctx, tx, workflowID); err != nil {
		return rollback(err)
	}
	return tx, nil
}

func (j *Journal) lockWorkflowTx(ctx context.Context, tx *sql.Tx, workflowID string) error {
	if j.engine == EnginePostgres {
		var lockedID string
		if err := tx.QueryRowContext(ctx, `SELECT id FROM workflows WHERE id = $1 FOR UPDATE`, workflowID).Scan(&lockedID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("journal: lock enabled workflow admission: %w", err)
		}
		return nil
	}
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE workflows SET updated_at = updated_at WHERE id = $1`), workflowID)
	if err != nil {
		return fmt.Errorf("journal: lock enabled workflow admission: %w", err)
	}
	if n, rowsErr := res.RowsAffected(); rowsErr != nil {
		return fmt.Errorf("journal: lock enabled workflow admission rows affected: %w", rowsErr)
	} else if n != 1 {
		return ErrNotFound
	}
	return nil
}

func (j *Journal) requireEnabledWorkflowTx(ctx context.Context, tx *sql.Tx, workflowID string) error {
	var enabled any
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT enabled FROM workflows WHERE id = $1`), workflowID).Scan(&enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: read enabled workflow admission: %w", err)
	}
	if !parseBool(enabled) {
		return ErrWorkflowDisabled
	}
	return nil
}

// beginEnabledWorkflowTx is the common path for non-idempotent live inserts.
func (j *Journal) beginEnabledWorkflowTx(ctx context.Context, workflowID string) (*sql.Tx, error) {
	tx, err := j.beginWorkflowAdmissionTx(ctx, workflowID)
	if err != nil {
		return nil, err
	}
	if err := j.requireEnabledWorkflowTx(ctx, tx, workflowID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

// WorkflowRateLimitError is the authoritative admission result for a
// per-workflow rate cap. The dispatcher translates it to its public
// ErrRateLimited sentinel; journal callers (including the MCP compatibility
// path) retain the exact workflow and configured limit for diagnostics.
type WorkflowRateLimitError struct {
	WorkflowID string
	Limit      int
	Count      int
}

func (e *WorkflowRateLimitError) Error() string {
	return fmt.Sprintf("workflow %q rate limit reached (%d/%d run(s)/minute)", e.WorkflowID, e.Count, e.Limit)
}

// checkWorkflowAdmissionTx is the authoritative quota/rate-limit gate for a
// live run INSERT. The dispatcher performs a fast read before resolving the
// artifact, but that read is advisory: concurrent dispatchers could otherwise
// all observe capacity and then commit past the same cap. This helper runs
// after the workflow row has been locked by beginWorkflowAdmissionTx and locks
// the tenant row as well, so queue/monthly admission is serialized across
// workflows in one tenant. The INSERT must follow this check in the same tx.
//
// queued controls whether max_queued_runs applies. Local runs are inserted in
// the running state and therefore do not consume the waiting queue; local
// admission also enforces max_concurrent_runs. Distributed workers enforce
// that cap again at claim time because queued work has not started yet. Both
// modes still enforce tenant disabled/monthly policy and the workflow rate
// window.
func (j *Journal) checkWorkflowAdmissionTx(ctx context.Context, tx *sql.Tx, workflowID string, queued bool) error {
	var tenantID string
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT tenant_id FROM workflows WHERE id = $1`), workflowID).Scan(&tenantID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: read workflow tenant admission: %w", err)
	}

	// Lock the workflow's current rate limit through the workflow row already
	// held by beginWorkflowAdmissionTx. The query is deliberately inside this
	// transaction so a rate-limit edit cannot commit between the read and run
	// INSERT.
	var rateLimit int
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT rate_limit_per_min FROM workflows WHERE id = $1`), workflowID).Scan(&rateLimit); err != nil {
		return fmt.Errorf("journal: read workflow rate admission: %w", err)
	}
	if rateLimit > 0 {
		var count int
		if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM runs WHERE workflow_id = $1 AND created_at >= $2`), workflowID, j.formatTime(time.Now().UTC().Add(-time.Minute))).Scan(&count); err != nil {
			return fmt.Errorf("journal: workflow rate admission count: %w", err)
		}
		if count >= rateLimit {
			return &WorkflowRateLimitError{WorkflowID: workflowID, Limit: rateLimit, Count: count}
		}
	}

	// Unknown tenant rows intentionally retain the single-tenant compatibility
	// behavior: the workflow is unlimited + enabled until its tenant is
	// provisioned. Existing tenant rows are locked before their counters are
	// read so concurrent inserts for different workflows cannot pass together.
	tenant, exists, err := j.lockTenantTx(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if tenant.Disabled {
		return &QuotaError{TenantID: tenantID, Reason: "tenant disabled"}
	}
	if queued && tenant.MaxQueuedRuns > 0 {
		count, err := j.countRunsTx(ctx, tx,
			`SELECT COUNT(*) FROM runs WHERE tenant_id = $1 AND status = 'queued' AND cancel_requested = `+j.falseLiteral(), tenantID)
		if err != nil {
			return err
		}
		if count >= tenant.MaxQueuedRuns {
			return &QuotaError{TenantID: tenantID, Reason: fmt.Sprintf("queue full (%d/%d)", count, tenant.MaxQueuedRuns)}
		}
	}
	if !queued && tenant.MaxConcurrentRuns > 0 {
		count, err := j.countRunsTx(ctx, tx,
			`SELECT COUNT(*) FROM runs WHERE tenant_id = $1 AND status = 'running'`, tenantID)
		if err != nil {
			return err
		}
		if count >= tenant.MaxConcurrentRuns {
			return &QuotaError{TenantID: tenantID, Reason: fmt.Sprintf("concurrency full (%d/%d)", count, tenant.MaxConcurrentRuns)}
		}
	}
	if tenant.HardCap && tenant.MonthlyRunQuota > 0 {
		count, err := j.countRunsTx(ctx, tx,
			`SELECT COUNT(*) FROM runs WHERE tenant_id = $1 AND created_at >= $2`, tenantID, j.formatTime(startOfMonthUTC()))
		if err != nil {
			return err
		}
		if count >= tenant.MonthlyRunQuota {
			return &QuotaError{TenantID: tenantID, Reason: fmt.Sprintf("monthly run quota reached (%d/%d)", count, tenant.MonthlyRunQuota)}
		}
	}
	return nil
}

// lockTenantTx serializes the tenant policy and counters used by
// checkWorkflowAdmissionTx. SQLite already owns its single-writer lock after
// the workflow self-update in lockWorkflowTx; the explicit touch keeps the
// intent clear and protects this helper if it is reused by another admission
// path later.
func (j *Journal) lockTenantTx(ctx context.Context, tx *sql.Tx, tenantID string) (Tenant, bool, error) {
	q := `SELECT ` + tenantCols + ` FROM tenants WHERE tenant_id = $1`
	if j.engine == EnginePostgres {
		q += ` FOR UPDATE`
	}
	tenant, err := j.scanTenant(tx.QueryRowContext(ctx, j.bind(q), tenantID))
	if errors.Is(err, sql.ErrNoRows) {
		return Tenant{}, false, nil
	}
	if err != nil {
		return Tenant{}, false, fmt.Errorf("journal: lock tenant admission: %w", err)
	}
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE tenants SET updated_at = updated_at WHERE tenant_id = $1`), tenantID); err != nil {
			return Tenant{}, false, fmt.Errorf("journal: lock tenant admission: %w", err)
		}
	}
	return tenant, true, nil
}

func (j *Journal) countRunsTx(ctx context.Context, tx *sql.Tx, query string, args ...any) (int, error) {
	var count int
	if err := tx.QueryRowContext(ctx, j.bind(query), args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("journal: count admission runs: %w", err)
	}
	return count, nil
}

func (j *Journal) falseLiteral() string {
	if j.engine == EngineSQLite {
		return "0"
	}
	return "false"
}
