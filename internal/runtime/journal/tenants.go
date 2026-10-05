package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Tenant is a billing + isolation boundary with its own quotas. A quota of 0
// means unlimited. The 'default' tenant (seeded unlimited) owns everything in
// a single-tenant install, so quotas + fair scheduling stay inert until an
// operator creates real tenants. A workflow's tenant_id that has no row here
// is treated as unlimited + enabled.
type Tenant struct {
	TenantID          string
	Name              string
	Plan              string // display label (the plan's name); PlanID is the catalog link
	PlanID            string // assigned plan (empty = custom quotas, no plan)
	MaxConcurrentRuns int    // cap on simultaneously running runs (0 = unlimited)
	MaxQueuedRuns     int    // cap on waiting runs (0 = unlimited)
	MonthlyRunQuota   int    // cap on runs created per calendar month (0 = unlimited)
	HardCap           bool   // true: refuse past the monthly quota; false: allow + bill overage
	Disabled          bool
	CreatedAt         time.Time
}

// ErrTenantNotFound is returned by GetTenant for an unknown tenant.
var ErrTenantNotFound = errors.New("journal: tenant not found")

// ErrTenantHasReferences means a tenant still owns durable configuration,
// identity, audit, or run history. Removing the registry row in that state
// would make the remaining rows look like an unlimited, enabled tenant.
var ErrTenantHasReferences = errors.New("journal: tenant still has durable references")

const tenantCols = `tenant_id, name, plan, max_concurrent_runs, max_queued_runs, monthly_run_quota, disabled, created_at, plan_id, hard_cap`

type scanner interface{ Scan(...any) error }

func (j *Journal) scanTenant(s scanner) (Tenant, error) {
	var t Tenant
	var disabled, created, planID, hardCap any
	if err := s.Scan(&t.TenantID, &t.Name, &t.Plan, &t.MaxConcurrentRuns,
		&t.MaxQueuedRuns, &t.MonthlyRunQuota, &disabled, &created, &planID, &hardCap); err != nil {
		return Tenant{}, err
	}
	t.Disabled = parseBool(disabled)
	t.CreatedAt = j.anyTime(created)
	t.PlanID = anyToString(planID)
	t.HardCap = parseBool(hardCap)
	return t, nil
}

// anyToString normalizes a scanned nullable text column to a string ("" for
// NULL).
func anyToString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	}
	return ""
}

// anyTime normalizes a scanned timestamp (time.Time on Postgres, ISO string on
// SQLite) to time.Time.
func (j *Journal) anyTime(v any) time.Time {
	switch x := v.(type) {
	case time.Time:
		return x.UTC()
	case string:
		t, _ := j.parseTime(x)
		return t
	case []byte:
		t, _ := j.parseTime(string(x))
		return t
	}
	return time.Time{}
}

// GetTenant returns one tenant by id, or ErrTenantNotFound.
func (j *Journal) GetTenant(ctx context.Context, tenantID string) (Tenant, error) {
	row := j.db.QueryRowContext(ctx, j.bind(`SELECT `+tenantCols+` FROM tenants WHERE tenant_id = $1`), tenantID)
	t, err := j.scanTenant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Tenant{}, ErrTenantNotFound
	}
	if err != nil {
		return Tenant{}, fmt.Errorf("journal: get tenant: %w", err)
	}
	return t, nil
}

// ListTenants returns all tenants ordered by id.
func (j *Journal) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := j.db.QueryContext(ctx, j.bind(`SELECT `+tenantCols+` FROM tenants ORDER BY tenant_id`))
	if err != nil {
		return nil, fmt.Errorf("journal: list tenants: %w", err)
	}
	defer rows.Close()
	var out []Tenant
	for rows.Next() {
		t, err := j.scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// UpsertTenant creates or updates a tenant's profile + quotas.
func (j *Journal) UpsertTenant(ctx context.Context, t Tenant) error {
	// plan_id is intentionally not set here: manual quota edits preserve the
	// existing plan association (AssignPlan owns plan_id).
	const q = `INSERT INTO tenants (tenant_id, name, plan, max_concurrent_runs, max_queued_runs, monthly_run_quota, disabled, hard_cap, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id) DO UPDATE SET
			name = excluded.name, plan = excluded.plan,
			max_concurrent_runs = excluded.max_concurrent_runs,
			max_queued_runs = excluded.max_queued_runs,
			monthly_run_quota = excluded.monthly_run_quota,
			disabled = excluded.disabled, hard_cap = excluded.hard_cap,
			updated_at = excluded.updated_at`
	if _, err := j.db.ExecContext(ctx, j.bind(q),
		t.TenantID, t.Name, t.Plan, t.MaxConcurrentRuns, t.MaxQueuedRuns,
		t.MonthlyRunQuota, j.boolValue(t.Disabled), j.boolValue(t.HardCap), j.now()); err != nil {
		return fmt.Errorf("journal: upsert tenant: %w", err)
	}
	return nil
}

// DeleteTenant removes an empty tenant row. A tenant with durable references
// cannot be deleted: leaving those rows behind would make the quota gate treat
// the tenant as unlimited and enabled. Operators should erase run history and
// remove tenant-owned configuration first, then retry the deletion.
func (j *Journal) DeleteTenant(ctx context.Context, tenantID string) error {
	if tenantID == "default" {
		return fmt.Errorf("journal: cannot delete the default tenant")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: delete tenant: begin: %w", err)
	}
	defer tx.Rollback()
	// Serialize the reference check with other tenant administration writes.
	// Resource tables intentionally do not have foreign keys to tenants because
	// older installations predate the registry, so this explicit guard is the
	// fail-closed boundary.
	lockQ := `SELECT tenant_id FROM tenants WHERE tenant_id = $1`
	if j.engine == EnginePostgres {
		lockQ += ` FOR UPDATE`
	}
	var lockedID string
	if err := tx.QueryRowContext(ctx, j.bind(lockQ), tenantID).Scan(&lockedID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTenantNotFound
		}
		return fmt.Errorf("journal: delete tenant: lock: %w", err)
	}
	if j.engine == EngineSQLite {
		// A read-only deferred transaction does not acquire SQLite's writer
		// lock. Touch the locked row before checking references so another
		// writer cannot interleave a delete with this inspection.
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE tenants SET updated_at = updated_at WHERE tenant_id = $1`), tenantID); err != nil {
			return fmt.Errorf("journal: delete tenant: lock: %w", err)
		}
	}
	checks := []struct {
		name  string
		query string
	}{
		{name: "users", query: `SELECT COUNT(*) FROM users WHERE tenant_id = $1`},
		{name: "workflows", query: `SELECT COUNT(*) FROM workflows WHERE tenant_id = $1`},
		{name: "credentials", query: `SELECT COUNT(*) FROM credentials WHERE tenant_id = $1`},
		{name: "runs", query: `SELECT COUNT(*) FROM runs WHERE tenant_id = $1`},
		{name: "run_usage", query: `SELECT COUNT(*) FROM run_usage WHERE tenant_id = $1`},
		{name: "triggers", query: `SELECT COUNT(*) FROM triggers WHERE tenant_id = $1`},
		{name: "notification_channels", query: `SELECT COUNT(*) FROM notification_channels WHERE tenant_id = $1`},
		{name: "oauth_connections", query: `SELECT COUNT(*) FROM oauth_connections WHERE tenant_id = $1`},
		{name: "oauth_states", query: `SELECT COUNT(*) FROM oauth_states WHERE tenant_id = $1`},
		{name: "mcp_audit", query: `SELECT COUNT(*) FROM mcp_audit WHERE tenant_id = $1`},
		{name: "runtime_secret_access_audit", query: `SELECT COUNT(*) FROM runtime_secret_access_audit WHERE tenant_id = $1`},
		{name: "command_automations", query: `SELECT COUNT(*) FROM command_automations WHERE tenant_id = $1`},
	}
	for _, check := range checks {
		var count int
		if err := tx.QueryRowContext(ctx, j.bind(check.query), tenantID).Scan(&count); err != nil {
			return fmt.Errorf("journal: delete tenant: inspect %s: %w", check.name, err)
		}
		if count > 0 {
			return fmt.Errorf("%w: %s=%d", ErrTenantHasReferences, check.name, count)
		}
	}
	res, err := tx.ExecContext(ctx, j.bind(`DELETE FROM tenants WHERE tenant_id = $1`), tenantID)
	if err != nil {
		return fmt.Errorf("journal: delete tenant: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrTenantNotFound
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: delete tenant: commit: %w", err)
	}
	return nil
}

// CountRunningForTenant counts a tenant's in-flight runs (for the concurrency
// quota).
func (j *Journal) CountRunningForTenant(ctx context.Context, tenantID string) (int, error) {
	return j.countRuns(ctx, `SELECT COUNT(*) FROM runs WHERE tenant_id = $1 AND status = 'running'`, tenantID)
}

// CountQueuedForTenant counts a tenant's waiting runs (for the queue quota).
func (j *Journal) CountQueuedForTenant(ctx context.Context, tenantID string) (int, error) {
	falseLit := "false"
	if j.engine == EngineSQLite {
		falseLit = "0"
	}
	return j.countRuns(ctx, `SELECT COUNT(*) FROM runs WHERE tenant_id = $1 AND status = 'queued' AND cancel_requested = `+falseLit, tenantID)
}

// CountRunsSince counts a tenant's runs created at or after t (for the monthly
// run quota; pass the start of the current calendar month).
func (j *Journal) CountRunsSince(ctx context.Context, tenantID string, t time.Time) (int, error) {
	var n int
	err := j.db.QueryRowContext(ctx,
		j.bind(`SELECT COUNT(*) FROM runs WHERE tenant_id = $1 AND created_at >= $2`),
		tenantID, j.formatTime(t)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("journal: count runs since: %w", err)
	}
	return n, nil
}

// QuotaError says why an enqueue was refused. Callers can type-assert to
// distinguish a quota refusal (a 429-class condition) from an infra error.
type QuotaError struct {
	TenantID string
	Reason   string
}

func (e *QuotaError) Error() string {
	return fmt.Sprintf("tenant %q quota: %s", e.TenantID, e.Reason)
}

// WorkflowTenant resolves the tenant that owns a workflow. An unknown workflow
// resolves to 'default' (defensive; the FK normally guarantees existence).
func (j *Journal) WorkflowTenant(ctx context.Context, workflowID string) (string, error) {
	var tid string
	err := j.db.QueryRowContext(ctx, j.bind(`SELECT tenant_id FROM workflows WHERE id = $1`), workflowID).Scan(&tid)
	if errors.Is(err, sql.ErrNoRows) {
		return "default", nil
	}
	if err != nil {
		return "", fmt.Errorf("journal: workflow tenant: %w", err)
	}
	return tid, nil
}

// CheckWorkflowEnqueueAllowed is the fast, read-only admission projection used
// before artifact resolution. It returns a *QuotaError if the tenant is
// disabled, at its max_queued_runs, or at its monthly_run_quota. The enabled
// run INSERT methods repeat the policy inside a workflow+tenant transaction;
// callers must not treat this read as the concurrency authority. Unknown
// tenants and 0 quotas always pass, so single-tenant installs are never gated.
func (j *Journal) CheckWorkflowEnqueueAllowed(ctx context.Context, workflowID string) error {
	tenantID, err := j.WorkflowTenant(ctx, workflowID)
	if err != nil {
		return err
	}
	t, err := j.GetTenant(ctx, tenantID)
	if errors.Is(err, ErrTenantNotFound) {
		return nil // no tenant row == unlimited + enabled
	}
	if err != nil {
		return err
	}
	if t.Disabled {
		return &QuotaError{TenantID: tenantID, Reason: "tenant disabled"}
	}
	if t.MaxQueuedRuns > 0 {
		n, err := j.CountQueuedForTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		if n >= t.MaxQueuedRuns {
			return &QuotaError{TenantID: tenantID, Reason: fmt.Sprintf("queue full (%d/%d)", n, t.MaxQueuedRuns)}
		}
	}
	// The monthly quota only HARD-refuses on a hard-cap plan (free /
	// unverified). On a soft-cap plan the run is allowed and the excess is
	// billed as overage from the run_usage ledger.
	if t.HardCap && t.MonthlyRunQuota > 0 {
		n, err := j.CountRunsSince(ctx, tenantID, startOfMonthUTC())
		if err != nil {
			return err
		}
		if n >= t.MonthlyRunQuota {
			return &QuotaError{TenantID: tenantID, Reason: fmt.Sprintf("monthly run quota reached (%d/%d)", n, t.MonthlyRunQuota)}
		}
	}
	return nil
}

// startOfMonthUTC is the first instant of the current calendar month (UTC),
// the window for the monthly run quota.
func startOfMonthUTC() time.Time {
	y, m, _ := time.Now().UTC().Date()
	return time.Date(y, m, 1, 0, 0, 0, 0, time.UTC)
}

func (j *Journal) countRuns(ctx context.Context, q, tenantID string) (int, error) {
	var n int
	if err := j.db.QueryRowContext(ctx, j.bind(q), tenantID).Scan(&n); err != nil {
		return 0, fmt.Errorf("journal: count runs: %w", err)
	}
	return n, nil
}
