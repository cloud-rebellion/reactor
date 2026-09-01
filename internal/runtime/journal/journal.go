// Package journal owns the step-level durable execution log.
//
// At every Step boundary the supervisor records:
//
//  1. step_start: insert (run_id, step_name, attempt, status=running, idem_key, input_hash, started_at)
//  2. step_end:   update to status=succeeded|failed, output_jsonb, error_text, finished_at
//
// On host restart the workflow subprocess re-spawns and replays Run() from
// the top. Every Step call routes through the supervisor which queries the
// journal: if a prior attempt for (run_id, step_name) succeeded the cached
// output is returned without invoking the closure. This is the durable
// execution primitive that survives mid-step host crashes.
//
// Engine portability: SQLite uses TEXT for jsonb columns + ISO8601 strings
// for timestamps; Postgres uses native JSONB + TIMESTAMPTZ. The Journal
// type abstracts over both via *sql.DB and engine-aware SQL.
package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Status values for the steps.status column.
const (
	StatusRunning   = "running"
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	StatusRetrying  = "retrying"
)

// Engine reports the SQL dialect; the journal uses this to pick the right
// timestamp + jsonb representation.
type Engine string

const (
	EngineSQLite   Engine = "sqlite"
	EnginePostgres Engine = "postgres"
)

// ErrNotFound is returned by FindCachedOutput when no prior successful
// attempt exists.
var ErrNotFound = errors.New("journal: no cached output")

// DefaultTenant is the tenant a resource lands in when none is specified. It
// matches the schema default so existing rows and new unscoped writes agree.
const DefaultTenant = "default"

// Journal is the durable step log. Safe for concurrent use; the underlying
// *sql.DB owns its connection pool.
type Journal struct {
	db     *sql.DB
	engine Engine
	log    *slog.Logger
}

// New wraps an open *sql.DB.
func New(db *sql.DB, engine Engine) *Journal {
	return &Journal{db: db, engine: engine, log: slog.Default()}
}

// WithLogger sets the logger used for best-effort background work (e.g.
// metering writes that must not fail a run). Returns j for chaining.
func (j *Journal) WithLogger(log *slog.Logger) *Journal {
	if log != nil {
		j.log = log
	}
	return j
}

// RecordStepStart inserts a running attempt row. If a row already exists
// for (run_id, step_name, attempt) it is left untouched and (false, nil)
// is returned, which the supervisor reads as "this attempt is already
// recorded; check FindCachedOutput".
func (j *Journal) RecordStepStart(ctx context.Context, runID, stepName string, attempt int, idemKey, inputHash string) (inserted bool, err error) {
	return j.RecordStepStartSeq(ctx, runID, stepName, 0, attempt, idemKey, inputHash)
}

// RecordStepStartSeq is RecordStepStart keyed additionally by the per-run call
// ordinal, which is what lets two iterations of one Step in a loop occupy two
// journal rows instead of colliding on the primary key and being swallowed by
// ON CONFLICT DO NOTHING. seq is 1-based; seq = 0 keeps legacy
// (run_id, step_name) semantics for workflow binaries built before the ordinal.
func (j *Journal) RecordStepStartSeq(ctx context.Context, runID, stepName string, seq int64, attempt int, idemKey, inputHash string) (inserted bool, err error) {
	now := j.now()
	const q = `INSERT INTO steps
		(run_id, step_name, seq, attempt, idempotency_key, input_hash, status, started_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT DO NOTHING`
	res, err := j.db.ExecContext(ctx, j.bind(q),
		runID, stepName, seq, attempt, nullable(idemKey), inputHash, StatusRunning, now,
	)
	if err != nil {
		return false, fmt.Errorf("journal: insert step_start: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, nil // not all drivers report this; treat as inserted
	}
	return n > 0, nil
}

// RecordStepEnd updates the running attempt with the final outcome. If the
// attempt row is missing, an error is returned because step_end without
// step_start is a contract violation.
func (j *Journal) RecordStepEnd(ctx context.Context, runID, stepName string, attempt int, output json.RawMessage, errText string) error {
	return j.RecordStepEndSeq(ctx, runID, stepName, 0, attempt, output, errText)
}

// RecordStepEndSeq is RecordStepEnd narrowed to one call ordinal. seq must match
// the RecordStepStartSeq that opened the step: keyed on name alone, the UPDATE
// landed on the FIRST iteration's row when a Step repeats in a loop, so three
// executions collapsed into one row carrying the last iteration's output.
func (j *Journal) RecordStepEndSeq(ctx context.Context, runID, stepName string, seq int64, attempt int, output json.RawMessage, errText string) error {
	now := j.now()
	status := StatusSucceeded
	if errText != "" {
		status = StatusFailed
	}
	out := outputArg(output, j.engine)
	const q = `UPDATE steps SET status = $1, output_jsonb = $2, error_text = $3, finished_at = $4
		WHERE run_id = $5 AND step_name = $6 AND seq = $7 AND attempt = $8`
	res, err := j.db.ExecContext(ctx, j.bind(q),
		status, out, nullable(errText), now, runID, stepName, seq, attempt,
	)
	if err != nil {
		return fmt.Errorf("journal: update step_end: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("journal: no step row for (%s, %s, seq=%d, attempt=%d)", runID, stepName, seq, attempt)
	}
	return nil
}

// FindCachedOutput returns the most recent successful output for the
// (run_id, step_name) pair, optionally narrowed by idempotency key. Returns
// ErrNotFound if no row matches.
//
// Deprecated for the supervisor's step_start path; use FindCachedOutputForInput
// so input drift triggers re-execution instead of silently returning a stale
// output. Retained for tests and for callers that intentionally ignore the
// input_hash dimension.
func (j *Journal) FindCachedOutput(ctx context.Context, runID, stepName, idemKey string) (json.RawMessage, error) {
	return j.findCached(ctx, runID, stepName, idemKey, "")
}

// FindCachedOutputBySeq resolves a step by its per-run CALL ORDINAL rather than
// by name, which is what makes a loop durable: two iterations of the same
// flow.Step(name) are distinct ordinals and therefore distinct journal rows.
//
// It returns the step name recorded against that ordinal so the caller can
// detect divergence. A recorded name that differs from the one now being
// requested means the workflow's program order changed between the original run
// and this replay (a step was inserted, removed or reordered), and serving the
// cached output would silently attribute one step's result to another.
func (j *Journal) FindCachedOutputBySeq(ctx context.Context, runID string, seq int64) (out json.RawMessage, recordedStep string, err error) {
	if seq <= 0 {
		return nil, "", ErrNotFound
	}
	const q = `SELECT output_jsonb, step_name FROM steps
		WHERE run_id = $1 AND seq = $2 AND status = $3
		ORDER BY attempt DESC LIMIT 1`
	var raw []byte
	row := j.db.QueryRowContext(ctx, j.bind(q), runID, seq, StatusSucceeded)
	if err := row.Scan(&raw, &recordedStep); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", ErrNotFound
		}
		return nil, "", fmt.Errorf("journal: find cached by seq: %w", err)
	}
	return raw, recordedStep, nil
}

// FindCachedOutputForInput is FindCachedOutput plus an input_hash filter.
// Used by the supervisor on step_start so a workflow author who changes
// a Step's input while keeping the name re-executes the step instead of
// inheriting the previous run's output. Empty inputHash falls back to
// FindCachedOutput's behaviour (matches any input).
func (j *Journal) FindCachedOutputForInput(ctx context.Context, runID, stepName, idemKey, inputHash string) (json.RawMessage, error) {
	return j.findCached(ctx, runID, stepName, idemKey, inputHash)
}

func (j *Journal) findCached(ctx context.Context, runID, stepName, idemKey, inputHash string) (json.RawMessage, error) {
	var (
		row *sql.Row
		out []byte
	)
	switch {
	case idemKey != "" && inputHash != "":
		const q = `SELECT output_jsonb FROM steps
			WHERE run_id = $1 AND step_name = $2 AND idempotency_key = $3 AND input_hash = $4 AND status = $5
			ORDER BY attempt DESC LIMIT 1`
		row = j.db.QueryRowContext(ctx, j.bind(q), runID, stepName, idemKey, inputHash, StatusSucceeded)
	case idemKey != "":
		const q = `SELECT output_jsonb FROM steps
			WHERE run_id = $1 AND step_name = $2 AND idempotency_key = $3 AND status = $4
			ORDER BY attempt DESC LIMIT 1`
		row = j.db.QueryRowContext(ctx, j.bind(q), runID, stepName, idemKey, StatusSucceeded)
	case inputHash != "":
		const q = `SELECT output_jsonb FROM steps
			WHERE run_id = $1 AND step_name = $2 AND input_hash = $3 AND status = $4
			ORDER BY attempt DESC LIMIT 1`
		row = j.db.QueryRowContext(ctx, j.bind(q), runID, stepName, inputHash, StatusSucceeded)
	default:
		const q = `SELECT output_jsonb FROM steps
			WHERE run_id = $1 AND step_name = $2 AND status = $3
			ORDER BY attempt DESC LIMIT 1`
		row = j.db.QueryRowContext(ctx, j.bind(q), runID, stepName, StatusSucceeded)
	}
	if err := row.Scan(&out); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("journal: find cached: %w", err)
	}
	return out, nil
}

// HasCachedOutputAnyInput returns true if there is any successful cached
// output for (run_id, step_name) regardless of input_hash. The supervisor
// uses this in replay mode to distinguish "drift: input changed since
// recorded run" (return ErrReplayDivergence) from "step never recorded"
// (a fresh frame that should not exist in replay).
func (j *Journal) HasCachedOutputAnyInput(ctx context.Context, runID, stepName string) (bool, error) {
	const q = `SELECT 1 FROM steps
		WHERE run_id = $1 AND step_name = $2 AND status = $3 LIMIT 1`
	row := j.db.QueryRowContext(ctx, j.bind(q), runID, stepName, StatusSucceeded)
	var n int
	if err := row.Scan(&n); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("journal: probe cached: %w", err)
	}
	return true, nil
}

// AttemptCount returns the number of recorded attempts for (run_id, step_name).
// Used by the supervisor to assign attempt numbers on retry.
func (j *Journal) AttemptCount(ctx context.Context, runID, stepName string) (int, error) {
	const q = `SELECT COUNT(*) FROM steps WHERE run_id = $1 AND step_name = $2`
	var n int
	if err := j.db.QueryRowContext(ctx, j.bind(q), runID, stepName).Scan(&n); err != nil {
		return 0, fmt.Errorf("journal: attempt count: %w", err)
	}
	return n, nil
}

// CreateRun inserts a runs row. Used by tests + the supervisor on dispatch.
func (j *Journal) CreateRun(ctx context.Context, runID, workflowID, triggerKind string, triggerMeta json.RawMessage) error {
	now := j.now()
	tm := outputArg(triggerMeta, j.engine)
	const q = `INSERT INTO runs (id, workflow_id, trigger_kind, trigger_meta, status, started_at, created_at, tenant_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE((SELECT tenant_id FROM workflows WHERE id = $8), 'default'))`
	_, err := j.db.ExecContext(ctx, j.bind(q),
		runID, workflowID, triggerKind, tm, "running", now, now, workflowID,
	)
	if err != nil {
		return fmt.Errorf("journal: create run: %w", err)
	}
	return nil
}

// CreateRunPinned atomically records the executable identity with the run. The
// dispatcher uses this for every new local execution; the legacy wrapper above
// remains for fixtures/imports and deliberately creates an unpinned row that
// resume/redrive paths will refuse to execute.
func (j *Journal) CreateRunPinned(ctx context.Context, runID, workflowID, triggerKind string, triggerMeta json.RawMessage, workflowVersion int, artifactSHA256 string) error {
	if workflowVersion <= 0 || !validArtifactSHA256(artifactSHA256) {
		return fmt.Errorf("journal: create pinned run: %w", ErrWorkflowArtifactFence)
	}
	now := j.now()
	tm := outputArg(triggerMeta, j.engine)
	// tenant_id is denormalized from the workflow (the $N rewriter does not
	// dedupe, so workflowID is passed again rather than reusing $2).
	const q = `INSERT INTO runs (id, workflow_id, trigger_kind, trigger_meta, status, started_at, created_at, tenant_id, workflow_version, workflow_artifact_sha256)
		VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE((SELECT tenant_id FROM workflows WHERE id = $8), 'default'), $9, $10)`
	_, err := j.db.ExecContext(ctx, j.bind(q),
		runID, workflowID, triggerKind, tm, "running", now, now, workflowID, workflowVersion, artifactSHA256,
	)
	if err != nil {
		return fmt.Errorf("journal: create run: %w", err)
	}
	return nil
}

// MarkRunFinished sets runs.status + finished_at. Used by the supervisor on
// terminal exit. Guarded: a cancelled run is terminal, so a workflow subprocess
// that completes just after an operator cancel cannot overwrite 'cancelled'
// with 'succeeded'/'failed' and un-cancel the run.
func (j *Journal) MarkRunFinished(ctx context.Context, runID, status string) error {
	const q = `UPDATE runs SET status = $1, finished_at = $2 WHERE id = $3 AND status <> 'cancelled'`
	res, err := j.db.ExecContext(ctx, j.bind(q), status, j.now(), runID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Already terminal (cancelled): don't record usage for a finish that
		// the guard just prevented.
		return nil
	}
	j.recordUsageBestEffort(ctx, runID, status)
	return nil
}

// ReapOrphanedRuns classifies every unleased local run still in "running" at
// daemon startup. Durable in-flight attempts become suspended behind one due
// recovery schedule, unused exact redrives return to failed_dlq, accepted
// cancellation becomes terminal, and unknown crashes fail closed. Suspended
// runs are left untouched because they already own scheduler work. Distributed
// deployments must use lease reaping instead. Returns the number classified.
func (j *Journal) ReapOrphanedRuns(ctx context.Context) (int64, error) {
	rows, err := j.db.QueryContext(ctx, `SELECT id FROM runs WHERE status = 'running'`)
	if err != nil {
		return 0, fmt.Errorf("journal: list orphaned runs: %w", err)
	}
	var runIDs []string
	for rows.Next() {
		var runID string
		if err := rows.Scan(&runID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("journal: scan orphaned run: %w", err)
		}
		runIDs = append(runIDs, runID)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("journal: close orphaned runs: %w", err)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("journal: iterate orphaned runs: %w", err)
	}

	var (
		classified int64
		reapErr    error
	)
	for _, runID := range runIDs {
		// A fresh local daemon proves that no prior in-process supervisor is
		// alive. Resume from the journal even when the last durable row already
		// succeeded: the daemon may have died after committing StepEnd but before
		// terminal run persistence. This force is intentionally startup-only;
		// live deterministic workflow errors after a cached step stay terminal.
		if _, err := j.RecoverLocalInterruptedRun(ctx, runID, true); err != nil {
			reapErr = errors.Join(reapErr, fmt.Errorf("run %s: %w", runID, err))
			continue
		}
		classified++
	}
	return classified, reapErr
}

// RunInfo is the read-only summary the replay CLI + dashboard need.
// JSON tags use snake_case so the eventual dashboard surface and CLI
// --json output share one shape.
type RunInfo struct {
	ID                     string          `json:"id"`
	WorkflowID             string          `json:"workflow_id"`
	TenantID               string          `json:"tenant_id"`
	TriggerKind            string          `json:"trigger_kind"`
	Status                 string          `json:"status"`
	TriggerMeta            json.RawMessage `json:"trigger_meta,omitempty"`
	WorkflowVersion        int             `json:"workflow_version,omitempty"`
	WorkflowArtifactSHA256 string          `json:"workflow_artifact_sha256,omitempty"`
	StartedAt              time.Time       `json:"started_at"`
	FinishedAt             time.Time       `json:"finished_at"`
}

// GetRun returns the runs row by id. Returns ErrNotFound if no row exists.
func (j *Journal) GetRun(ctx context.Context, runID string) (RunInfo, error) {
	const q = `SELECT id, workflow_id, tenant_id, trigger_kind, status, trigger_meta, workflow_version, workflow_artifact_sha256, started_at, finished_at
		FROM runs WHERE id = $1`
	row := j.db.QueryRowContext(ctx, j.bind(q), runID)
	var (
		info     RunInfo
		meta     []byte
		version  sql.NullInt64
		artifact sql.NullString
		started  sql.NullString
		finished sql.NullString
	)
	if err := row.Scan(&info.ID, &info.WorkflowID, &info.TenantID, &info.TriggerKind, &info.Status, &meta, &version, &artifact, &started, &finished); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RunInfo{}, ErrNotFound
		}
		return RunInfo{}, fmt.Errorf("journal: get run: %w", err)
	}
	if len(meta) > 0 {
		info.TriggerMeta = json.RawMessage(meta)
	}
	if version.Valid {
		info.WorkflowVersion = int(version.Int64)
	}
	info.WorkflowArtifactSHA256 = artifact.String
	if started.Valid {
		if t, err := j.parseTime(started.String); err == nil {
			info.StartedAt = t
		}
	}
	if finished.Valid {
		if t, err := j.parseTime(finished.String); err == nil {
			info.FinishedAt = t
		}
	}
	return info, nil
}

// StepRow is one row of the steps table flattened for the replay timeline.
// JSON tags mirror snake_case for consistency with RunInfo + DeadLetterItem.
type StepRow struct {
	StepName       string          `json:"step_name"`
	Attempt        int             `json:"attempt"`
	IdempotencyKey string          `json:"idempotency_key"`
	Status         string          `json:"status"`
	OutputJSONB    json.RawMessage `json:"output_jsonb,omitempty"`
	ErrorText      string          `json:"error_text"`
	StartedAt      time.Time       `json:"started_at"`
	FinishedAt     time.Time       `json:"finished_at"`
}

// ListSteps returns every recorded step attempt for a run, ordered
// chronologically. Used by `reactor replay <run-id>` to reconstruct
// the timeline a finished run executed, and by the dashboard's
// /runs/{id} page to render output_jsonb per successful step.
func (j *Journal) ListSteps(ctx context.Context, runID string) ([]StepRow, error) {
	const q = `SELECT step_name, attempt, idempotency_key, status, output_jsonb, error_text, started_at, finished_at
		FROM steps WHERE run_id = $1 ORDER BY started_at ASC, attempt ASC`
	rows, err := j.db.QueryContext(ctx, j.bind(q), runID)
	if err != nil {
		return nil, fmt.Errorf("journal: list steps: %w", err)
	}
	defer rows.Close()
	var out []StepRow
	for rows.Next() {
		var (
			s        StepRow
			idem     sql.NullString
			outBlob  []byte
			errText  sql.NullString
			started  sql.NullString
			finished sql.NullString
		)
		if err := rows.Scan(&s.StepName, &s.Attempt, &idem, &s.Status, &outBlob, &errText, &started, &finished); err != nil {
			return nil, fmt.Errorf("journal: scan step: %w", err)
		}
		if idem.Valid {
			s.IdempotencyKey = idem.String
		}
		if len(outBlob) > 0 {
			s.OutputJSONB = json.RawMessage(outBlob)
		}
		if errText.Valid {
			s.ErrorText = errText.String
		}
		if started.Valid {
			if t, err := j.parseTime(started.String); err == nil {
				s.StartedAt = t
			}
		}
		if finished.Valid {
			if t, err := j.parseTime(finished.String); err == nil {
				s.FinishedAt = t
			}
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// WorkflowIDBySlug returns the id of an active workflow by its slug.
// Used by the daemon's `reactor workflow register/build` flows so
// re-registrations don't require remembering opaque ids.
func (j *Journal) WorkflowIDBySlug(ctx context.Context, slug string) (string, error) {
	const q = `SELECT id FROM workflows WHERE slug = $1 ORDER BY created_at DESC LIMIT 1`
	var id string
	if err := j.db.QueryRowContext(ctx, j.bind(q), slug).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("journal: workflow id by slug: %w", err)
	}
	return id, nil
}

// WorkflowIDBySlugInTenant resolves a slug WITHIN one tenant.
//
// Slugs are unique per tenant (UNIQUE (tenant_id, slug)), not globally, so the
// unscoped WorkflowIDBySlug returns whichever tenant's row was created most
// recently. That was harmless only while every workflow shared one tenant; once
// tenants are real it silently resolves across the boundary, and its result
// feeds HasGrant (the secret ACL) and the oauth tenant lookup. Use this wherever
// the caller knows the tenant.
//
// An empty tenantID falls back to the unscoped lookup so callers that genuinely
// have no tenant context (the CLI, the scheduler) keep working.
func (j *Journal) WorkflowIDBySlugInTenant(ctx context.Context, slug, tenantID string) (string, error) {
	if tenantID == "" {
		return j.WorkflowIDBySlug(ctx, slug)
	}
	const q = `SELECT id FROM workflows WHERE slug = $1 AND tenant_id = $2 ORDER BY created_at DESC LIMIT 1`
	var id string
	if err := j.db.QueryRowContext(ctx, j.bind(q), slug, tenantID).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("journal: workflow id by slug in tenant: %w", err)
	}
	return id, nil
}

// WorkflowSlugByID is the inverse of WorkflowIDBySlug. Used by the
// dispatcher to resolve a trigger's workflow_id back to a slug for
// supervisor + binary registry lookups.
func (j *Journal) WorkflowSlugByID(ctx context.Context, id string) (string, error) {
	const q = `SELECT slug FROM workflows WHERE id = $1`
	var slug string
	if err := j.db.QueryRowContext(ctx, j.bind(q), id).Scan(&slug); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("journal: workflow slug by id: %w", err)
	}
	return slug, nil
}

// ListWorkflows returns every workflow ordered by slug. Used by the
// status server's home page + the `reactor workflow list` CLI.
func (j *Journal) ListWorkflows(ctx context.Context) ([]Workflow, error) {
	return j.listWorkflows(ctx, "")
}

// SetWorkflowRateLimit sets a workflow's max runs per minute (0 = unlimited).
func (j *Journal) SetWorkflowRateLimit(ctx context.Context, workflowID string, perMin int) error {
	if perMin < 0 {
		perMin = 0
	}
	_, err := j.db.ExecContext(ctx,
		j.bind(`UPDATE workflows SET rate_limit_per_min = $1, updated_at = $2 WHERE id = $3`),
		perMin, j.now(), workflowID)
	if err != nil {
		return fmt.Errorf("journal: set rate limit: %w", err)
	}
	return nil
}

// WorkflowRateLimit returns a workflow's per-minute run cap (0 = unlimited).
func (j *Journal) WorkflowRateLimit(ctx context.Context, workflowID string) (int, error) {
	var n int
	err := j.db.QueryRowContext(ctx,
		j.bind(`SELECT rate_limit_per_min FROM workflows WHERE id = $1`), workflowID).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("journal: get rate limit: %w", err)
	}
	return n, nil
}

// CheckWorkflowRateLimit reports whether a new run is allowed under the
// workflow's per-minute rate limit. It counts runs created in the last 60s
// from the shared runs table, so the limit holds across serve/worker
// instances. Returns (allowed, limit, err); limit 0 means unlimited.
func (j *Journal) CheckWorkflowRateLimit(ctx context.Context, workflowID string) (bool, int, error) {
	limit, err := j.WorkflowRateLimit(ctx, workflowID)
	if err != nil || limit <= 0 {
		return true, limit, err
	}
	var n int
	err = j.db.QueryRowContext(ctx,
		j.bind(`SELECT COUNT(*) FROM runs WHERE workflow_id = $1 AND created_at >= $2`),
		workflowID, j.formatTime(time.Now().UTC().Add(-time.Minute))).Scan(&n)
	if err != nil {
		return true, limit, fmt.Errorf("journal: rate-limit count: %w", err) // fail open
	}
	return n < limit, limit, nil
}

// WorkflowDAG returns a workflow's current dag_json (the step graph). Used by
// the run-flow visualization to lay out steps + edges. Returns ErrNotFound for
// an unknown workflow.
func (j *Journal) WorkflowDAG(ctx context.Context, workflowID string) (json.RawMessage, error) {
	var dag []byte
	err := j.db.QueryRowContext(ctx, j.bind(`SELECT dag_json FROM workflows WHERE id = $1`), workflowID).Scan(&dag)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("journal: workflow dag: %w", err)
	}
	return json.RawMessage(dag), nil
}

// ListWorkflowsByTenant returns only the given tenant's workflows (dashboard
// scoping for non-admin viewers).
func (j *Journal) ListWorkflowsByTenant(ctx context.Context, tenantID string) ([]Workflow, error) {
	return j.listWorkflows(ctx, tenantID)
}

func (j *Journal) listWorkflows(ctx context.Context, tenantID string) ([]Workflow, error) {
	q := `SELECT id, slug, tenant_id, code_hash, sdk_version, created_at, updated_at, estimated_minutes_saved_per_run
		FROM workflows`
	var args []any
	if tenantID != "" {
		q += ` WHERE tenant_id = $1`
		args = append(args, tenantID)
	}
	q += ` ORDER BY slug ASC`
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, fmt.Errorf("journal: list workflows: %w", err)
	}
	defer rows.Close()
	var out []Workflow
	for rows.Next() {
		var (
			w       Workflow
			created sql.NullString
			updated sql.NullString
		)
		if err := rows.Scan(&w.ID, &w.Slug, &w.TenantID, &w.CodeHash, &w.SDKVersion, &created, &updated, &w.EstimatedMinutesSavedPerRun); err != nil {
			return nil, fmt.Errorf("journal: scan workflow: %w", err)
		}
		if created.Valid {
			if t, err := j.parseTime(created.String); err == nil {
				w.CreatedAt = t
			}
		}
		if updated.Valid {
			if t, err := j.parseTime(updated.String); err == nil {
				w.UpdatedAt = t
			}
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// Workflow is the read-only summary returned by ListWorkflows.
type Workflow struct {
	ID                          string    `json:"id"`
	Slug                        string    `json:"slug"`
	TenantID                    string    `json:"tenant_id"`
	CodeHash                    string    `json:"code_hash"`
	SDKVersion                  string    `json:"sdk_version"`
	CreatedAt                   time.Time `json:"created_at"`
	UpdatedAt                   time.Time `json:"updated_at"`
	EstimatedMinutesSavedPerRun int       `json:"estimated_minutes_saved_per_run"`
}

// GetWorkflow returns a single workflow's metadata. Used by the
// dashboard's workflow detail page so the editable minutes-saved
// baseline pre-populates with the stored value instead of forcing the
// operator to re-type on every save.
func (j *Journal) GetWorkflow(ctx context.Context, id string) (Workflow, error) {
	const q = `SELECT id, slug, tenant_id, code_hash, sdk_version, created_at, updated_at, estimated_minutes_saved_per_run
		FROM workflows WHERE id = $1`
	row := j.db.QueryRowContext(ctx, j.bind(q), id)
	var (
		w       Workflow
		created sql.NullString
		updated sql.NullString
	)
	if err := row.Scan(&w.ID, &w.Slug, &w.TenantID, &w.CodeHash, &w.SDKVersion, &created, &updated, &w.EstimatedMinutesSavedPerRun); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Workflow{}, ErrNotFound
		}
		return Workflow{}, fmt.Errorf("journal: get workflow: %w", err)
	}
	if created.Valid {
		if t, err := j.parseTime(created.String); err == nil {
			w.CreatedAt = t
		}
	}
	if updated.Valid {
		if t, err := j.parseTime(updated.String); err == nil {
			w.UpdatedAt = t
		}
	}
	return w, nil
}

// SetEstimatedMinutesSavedPerRun updates the operator-declared "manual
// baseline" used by the home dashboard's time-saved rollup. Refuses
// negative values (a baseline less than zero would invert the rollup).
func (j *Journal) SetEstimatedMinutesSavedPerRun(ctx context.Context, workflowID string, minutes int) error {
	if minutes < 0 {
		return fmt.Errorf("journal: minutes_saved must be non-negative, got %d", minutes)
	}
	const q = `UPDATE workflows SET estimated_minutes_saved_per_run = $1, updated_at = $2 WHERE id = $3`
	res, err := j.db.ExecContext(ctx, j.bind(q), minutes, j.now(), workflowID)
	if err != nil {
		return fmt.Errorf("journal: set minutes_saved: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("journal: workflow %s not found: %w", workflowID, ErrNotFound)
	}
	return nil
}

// ListRecentRuns returns up to limit runs ordered newest-first.
func (j *Journal) ListRecentRuns(ctx context.Context, limit int) ([]RunInfo, error) {
	return j.ListRuns(ctx, RunFilter{Limit: limit})
}

// RunFilter narrows ListRuns. Zero values disable that filter dimension.
type RunFilter struct {
	WorkflowID string
	TenantID   string // when set, only this tenant's runs (dashboard scoping)
	Status     string
	Limit      int
	Offset     int
}

// CountRuns returns the total number of runs matching f (ignoring
// Limit/Offset). Paired with ListRuns to drive pagination controls.
func (j *Journal) CountRuns(ctx context.Context, f RunFilter) (int, error) {
	q := `SELECT COUNT(*) FROM runs WHERE 1=1`
	args := []any{}
	pos := 1
	if f.WorkflowID != "" {
		q += fmt.Sprintf(" AND workflow_id = $%d", pos)
		args = append(args, f.WorkflowID)
		pos++
	}
	if f.TenantID != "" {
		q += fmt.Sprintf(" AND tenant_id = $%d", pos)
		args = append(args, f.TenantID)
		pos++
	}
	if f.Status != "" {
		q += fmt.Sprintf(" AND status = $%d", pos)
		args = append(args, f.Status)
		pos++
	}
	var n int
	if err := j.db.QueryRowContext(ctx, j.bind(q), args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("journal: count runs: %w", err)
	}
	return n, nil
}

// ListRuns returns runs matching f ordered newest-first. Limit defaults
// to 50 when zero/negative; Offset is taken as-is.
func (j *Journal) ListRuns(ctx context.Context, f RunFilter) ([]RunInfo, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	q := `SELECT id, workflow_id, tenant_id, trigger_kind, status, started_at, finished_at FROM runs WHERE 1=1`
	args := []any{}
	pos := 1
	if f.WorkflowID != "" {
		q += fmt.Sprintf(" AND workflow_id = $%d", pos)
		args = append(args, f.WorkflowID)
		pos++
	}
	if f.TenantID != "" {
		q += fmt.Sprintf(" AND tenant_id = $%d", pos)
		args = append(args, f.TenantID)
		pos++
	}
	if f.Status != "" {
		q += fmt.Sprintf(" AND status = $%d", pos)
		args = append(args, f.Status)
		pos++
	}
	q += fmt.Sprintf(" ORDER BY started_at DESC LIMIT $%d OFFSET $%d", pos, pos+1)
	args = append(args, f.Limit, f.Offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, fmt.Errorf("journal: list runs: %w", err)
	}
	defer rows.Close()
	var out []RunInfo
	for rows.Next() {
		var (
			info     RunInfo
			started  sql.NullString
			finished sql.NullString
		)
		if err := rows.Scan(&info.ID, &info.WorkflowID, &info.TenantID, &info.TriggerKind, &info.Status, &started, &finished); err != nil {
			return nil, fmt.Errorf("journal: scan run: %w", err)
		}
		if started.Valid {
			if t, err := j.parseTime(started.String); err == nil {
				info.StartedAt = t
			}
		}
		if finished.Valid {
			if t, err := j.parseTime(finished.String); err == nil {
				info.FinishedAt = t
			}
		}
		out = append(out, info)
	}
	return out, rows.Err()
}

// CreateWorkflow inserts a workflows row + the corresponding version-1
// row in workflow_versions. Used by tests + the production register
// paths (CLI, dashboard, MCP, codegen). Subsequent re-registrations
// against the same slug should call RecordWorkflowVersion directly to
// append a new version row without touching the workflows pointer.
func (j *Journal) CreateWorkflow(ctx context.Context, id, slug, codeHash, sdkVer string, dag json.RawMessage) error {
	return j.CreateWorkflowInTenant(ctx, id, slug, codeHash, sdkVer, dag, DefaultTenant)
}

// CreateWorkflowWithArtifact creates a default-tenant workflow whose first
// version is immediately executable through the immutable artifact registry.
func (j *Journal) CreateWorkflowWithArtifact(ctx context.Context, id, slug, codeHash, sdkVer, artifactSHA256 string, dag json.RawMessage) error {
	return j.CreateWorkflowInTenantWithArtifact(ctx, id, slug, codeHash, sdkVer, artifactSHA256, dag, DefaultTenant)
}

// CreateWorkflowInTenant is CreateWorkflow with an explicit owner.
//
// CreateWorkflow's INSERT omitted tenant_id entirely, so every workflow took the
// schema default and the tenant boundary was inert: a member on the default
// tenant saw everything, a member moved to a real tenant saw nothing (no code
// path could create a workflow there), and the cross-tenant grant guard could
// never fire because both sides were always equal. Empty tenantID means
// DefaultTenant so unscoped callers keep their existing behaviour.
func (j *Journal) CreateWorkflowInTenant(ctx context.Context, id, slug, codeHash, sdkVer string, dag json.RawMessage, tenantID string) error {
	return j.CreateWorkflowInTenantWithArtifact(ctx, id, slug, codeHash, sdkVer, "", dag, tenantID)
}

// CreateWorkflowInTenantWithArtifact is the production registration path for
// compiled workflows. Metadata-only callers may use CreateWorkflowInTenant,
// but the resulting empty artifact pin intentionally cannot execute.
func (j *Journal) CreateWorkflowInTenantWithArtifact(ctx context.Context, id, slug, codeHash, sdkVer, artifactSHA256 string, dag json.RawMessage, tenantID string) error {
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	if artifactSHA256 != "" && !validArtifactSHA256(artifactSHA256) {
		return errors.New("journal: create workflow: invalid artifact sha256")
	}
	now := j.now()
	dg := outputArg(dag, j.engine)
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: create workflow: begin: %w", err)
	}
	defer tx.Rollback()
	const q = `INSERT INTO workflows (id, tenant_id, slug, code_hash, sdk_version, dag_json, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err = tx.ExecContext(ctx, j.bind(q),
		id, tenantID, slug, codeHash, sdkVer, dg, now, now,
	)
	if err != nil {
		return fmt.Errorf("journal: create workflow: %w", err)
	}
	const versionQ = `INSERT INTO workflow_versions
		(workflow_id, version, sdk_version, code_hash, artifact_sha256, dag_json, created_at)
		VALUES ($1, 1, $2, $3, $4, $5, $6)`
	if _, err := tx.ExecContext(ctx, j.bind(versionQ), id, sdkVer, codeHash, nullIfEmpty(artifactSHA256), dg, now); err != nil {
		return fmt.Errorf("journal: create workflow: version row: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: create workflow: commit: %w", err)
	}
	return nil
}

// SetWorkflowEnabled toggles workflows.enabled. Disabled workflows
// stay in the table (so audit history + run timeline still resolve)
// but the dispatcher refuses new dispatches and the cron driver
// drops their triggers on the next reconcile.
func (j *Journal) SetWorkflowEnabled(ctx context.Context, id string, enabled bool) error {
	const q = `UPDATE workflows SET enabled = $1, updated_at = $2 WHERE id = $3`
	_, err := j.db.ExecContext(ctx, j.bind(q), j.boolValue(enabled), j.now(), id)
	if err != nil {
		return fmt.Errorf("journal: set workflow enabled: %w", err)
	}
	return nil
}

// ErrWorkflowBusy is returned by DeleteWorkflow when the workflow has
// runs in a non-terminal status (running, suspended). The dashboard
// maps this to an inline 409 error pill so the operator disables the
// workflow first.
var ErrWorkflowBusy = errors.New("journal: workflow has active runs")

// IsWorkflowEnabled reports whether the workflow accepts new dispatches.
// Returns ErrNotFound when no row matches. A missing/legacy row is
// treated as enabled (the column defaults to 1), so this never silently
// disables an existing workflow.
func (j *Journal) IsWorkflowEnabled(ctx context.Context, id string) (bool, error) {
	const q = `SELECT enabled FROM workflows WHERE id = $1`
	var enabled any
	err := j.db.QueryRowContext(ctx, j.bind(q), id).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("journal: is workflow enabled: %w", err)
	}
	return parseBool(enabled), nil
}

// DeleteWorkflow removes a workflow + cascades through every dependent
// row (triggers, runs, steps, schedules, dead_letter, secret grants,
// workflow_versions). Hard delete because workflows are identified by
// slug; an operator who wants to keep the audit trail should
// SetWorkflowEnabled(false) instead.
//
// Refuses to proceed when any run for the workflow is in a non-terminal
// status (running, suspended) so a concurrent supervisor cannot keep
// inserting step rows for a run_id the cascade already dropped. The
// operator is expected to disable + drain (or wait for runs to finish)
// before deleting.
func (j *Journal) DeleteWorkflow(ctx context.Context, id string) error {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Check active-run count first. SELECT-then-DELETE in the same
	// transaction so a fresh run starting between the probe and the
	// cascade gets blocked by the FK / cascade once committed; in
	// practice operators see the busy error and retry after the run
	// finishes.
	const busyQ = `SELECT COUNT(*) FROM runs
		WHERE workflow_id = $1 AND status IN ('queued', 'running', 'suspended')`
	var active int
	if err := tx.QueryRowContext(ctx, j.bind(busyQ), id).Scan(&active); err != nil {
		return fmt.Errorf("journal: delete workflow: probe active runs: %w", err)
	}
	if active > 0 {
		return fmt.Errorf("%w: %d run(s) still queued, running or suspended (disable + wait, or use SetWorkflowEnabled(false) to keep history)", ErrWorkflowBusy, active)
	}

	stmts := []string{
		`DELETE FROM workflow_secret_grants WHERE workflow_id = $1`,
		`DELETE FROM workflow_notification_routes WHERE workflow_id = $1`,
		`DELETE FROM workflow_versions WHERE workflow_id = $1`,
		`DELETE FROM triggers WHERE workflow_id = $1`,
		`DELETE FROM schedules WHERE run_id IN (SELECT id FROM runs WHERE workflow_id = $1)`,
		`DELETE FROM steps WHERE run_id IN (SELECT id FROM runs WHERE workflow_id = $1)`,
		`DELETE FROM run_logs WHERE run_id IN (SELECT id FROM runs WHERE workflow_id = $1)`,
		`DELETE FROM dead_letter WHERE run_id IN (SELECT id FROM runs WHERE workflow_id = $1)`,
		`DELETE FROM runs WHERE workflow_id = $1`,
		`DELETE FROM workflows WHERE id = $1`,
	}
	for _, q := range stmts {
		if _, err := tx.ExecContext(ctx, j.bind(q), id); err != nil {
			return fmt.Errorf("journal: delete workflow: %w", err)
		}
	}
	// Chain triggers where THIS workflow is the source live on OTHER
	// workflows' rows with the source id inside config_json (not a FK
	// column), so the cascade above misses them. Delete them too, or they
	// linger pointing at a workflow that can never fire again. CAST keeps
	// the LIKE portable across SQLite TEXT and Postgres JSONB config_json.
	orphanQ := `DELETE FROM triggers WHERE kind = '` + string(TriggerWorkflowComplete) +
		`' AND CAST(config_json AS TEXT) LIKE '%"source_workflow_id":"' || $1 || '"%'`
	if _, err := tx.ExecContext(ctx, j.bind(orphanQ), id); err != nil {
		return fmt.Errorf("journal: delete workflow: orphan chain triggers: %w", err)
	}
	return tx.Commit()
}

// UpdateTriggerConfig replaces a trigger's config_json. Used by the
// dashboard's "edit cron spec" flow so an operator can tweak a
// schedule without delete + recreate (which would lose the trigger id
// + change webhook URLs).
func (j *Journal) UpdateTriggerConfig(ctx context.Context, id string, config []byte) error {
	cfg := outputArg(config, j.engine)
	if cfg == nil {
		cfg = "{}"
		if j.engine != EngineSQLite {
			cfg = []byte("{}")
		}
	}
	const q = `UPDATE triggers SET config_json = $1, updated_at = $2 WHERE id = $3`
	_, err := j.db.ExecContext(ctx, j.bind(q), cfg, j.now(), id)
	if err != nil {
		return fmt.Errorf("journal: update trigger config: %w", err)
	}
	return nil
}

// now returns the engine-appropriate timestamp representation.
func (j *Journal) now() any {
	if j.engine == EngineSQLite {
		return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return time.Now().UTC()
}

// bind rewrites $N positional placeholders to ? for SQLite. Postgres uses
// $N natively. Keeps the SQL above engine-portable.
func (j *Journal) bind(q string) string {
	if j.engine != EngineSQLite {
		return q
	}
	out := make([]byte, 0, len(q))
	for i := 0; i < len(q); i++ {
		if q[i] == '$' && i+1 < len(q) && q[i+1] >= '0' && q[i+1] <= '9' {
			out = append(out, '?')
			// skip the digits
			i++
			for i+1 < len(q) && q[i+1] >= '0' && q[i+1] <= '9' {
				i++
			}
			continue
		}
		out = append(out, q[i])
	}
	return string(out)
}

// outputArg packages a JSON-raw output for the right engine. SQLite stores
// it as TEXT (the json string); Postgres takes a json.RawMessage which
// encodes/decodes correctly because pgx's stdlib bridge marshals
// json.RawMessage as the JSON text it already is.
func outputArg(out json.RawMessage, engine Engine) any {
	if len(out) == 0 {
		return nil
	}
	if engine == EngineSQLite {
		return string(out)
	}
	return []byte(out)
}

// nullable converts an empty string to a SQL NULL.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
