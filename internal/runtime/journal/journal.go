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

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
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
	// Set once at process startup, before the Journal is shared. A stable
	// wrapped data key keeps payloads decryptable across master-key rotation.
	payloadKey *payloadcrypto.Keyring
}

// New wraps an open *sql.DB.
func New(db *sql.DB, engine Engine) *Journal {
	return &Journal{db: db, engine: engine, log: slog.Default()}
}

// Ping verifies that the journal's database connection is usable. The HTTP
// readiness probe calls this with a short deadline so a live listener cannot
// report ready while its durable execution store is unavailable.
func (j *Journal) Ping(ctx context.Context) error {
	if j == nil || j.db == nil {
		return errors.New("journal: database is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return j.db.PingContext(ctx)
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
	payload, err := j.prepareStepPayload(ctx, j.db, runID, stepName, seq, attempt, output, errText)
	if err != nil {
		return err
	}
	const q = `UPDATE steps SET status = $1, output_jsonb = $2, error_text = $3, finished_at = $4,
		payload_crypto_version = $5, output_plaintext_bytes = $6, error_plaintext_bytes = $7
		WHERE run_id = $8 AND step_name = $9 AND seq = $10 AND attempt = $11`
	res, err := j.db.ExecContext(ctx, j.bind(q),
		status, payload.output, payload.errorText, now, payload.version, payload.outputBytes, payload.errorBytes,
		runID, stepName, seq, attempt,
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
	out, recordedStep, _, _, err = j.findCachedOutputBySeq(ctx, runID, seq)
	return out, recordedStep, err
}

// FindCachedOutputBySeqForInput resolves a successful ordinal cache entry and
// returns the identity fields recorded with that output. A call ordinal is
// only safe to replay when it still refers to the same step name,
// idempotency key, and input hash. The supervisor uses these fields to reject
// a changed workflow frame instead of silently serving an output produced for
// a different operation.
func (j *Journal) FindCachedOutputBySeqForInput(ctx context.Context, runID string, seq int64) (out json.RawMessage, recordedStep, recordedIdempotencyKey, recordedInputHash string, err error) {
	return j.findCachedOutputBySeq(ctx, runID, seq)
}

// FindRecordedStepNameBySeq returns the latest step name recorded at a
// per-run call ordinal, regardless of whether that attempt succeeded. A
// replay/resume must compare the ordinal against every prior checkpoint: a
// failed, retrying, or interrupted attempt is still evidence of the program
// position that was reached. Looking only at successful rows would let a
// renamed step create a second row at the same ordinal and execute a
// different side effect after a crash.
func (j *Journal) FindRecordedStepNameBySeq(ctx context.Context, runID string, seq int64) (string, error) {
	if seq <= 0 {
		return "", ErrNotFound
	}
	const q = `SELECT step_name FROM steps
		WHERE run_id = $1 AND seq = $2
		ORDER BY attempt DESC, started_at DESC LIMIT 1`
	var stepName string
	err := j.db.QueryRowContext(ctx, j.bind(q), runID, seq).Scan(&stepName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("journal: find recorded step by seq: %w", err)
	}
	return stepName, nil
}

func (j *Journal) findCachedOutputBySeq(ctx context.Context, runID string, seq int64) (out json.RawMessage, recordedStep, recordedIdempotencyKey, recordedInputHash string, err error) {
	if seq <= 0 {
		return nil, "", "", "", ErrNotFound
	}
	q := fmt.Sprintf(`SELECT %s, steps.output_jsonb IS NOT NULL, steps.step_name, steps.attempt,
		steps.idempotency_key, steps.input_hash, runs.tenant_id,
		steps.payload_crypto_version, steps.output_plaintext_bytes
		FROM steps JOIN runs ON runs.id = steps.run_id
		WHERE steps.run_id = $1 AND steps.seq = $2 AND steps.status = $3
		ORDER BY steps.attempt DESC LIMIT 1`, stepOutputReplayValue(j.engine))
	var (
		raw        []byte
		present    bool
		attempt    int
		idem       sql.NullString
		tenantID   string
		version    int
		plainBytes sql.NullInt64
	)
	row := j.db.QueryRowContext(ctx, j.bind(q), runID, seq, StatusSucceeded)
	if err := row.Scan(&raw, &present, &recordedStep, &attempt, &idem, &recordedInputHash,
		&tenantID, &version, &plainBytes); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", "", "", ErrNotFound
		}
		return nil, "", "", "", fmt.Errorf("journal: find cached by seq: %w", err)
	}
	if idem.Valid {
		recordedIdempotencyKey = idem.String
	}
	if version == 1 && j.payloadKey == nil {
		return nil, "", "", "", payloadcrypto.ErrKeyRequired
	}
	if version == 1 && present != plainBytes.Valid || present && raw == nil {
		return nil, "", "", "", payloadcrypto.ErrInvalidEnvelope
	}
	if present {
		out, err = j.openStepOutput(tenantID, runID, recordedStep, seq, attempt, version, plainBytes, raw)
		if err != nil {
			return nil, "", "", "", err
		}
	}
	return out, recordedStep, recordedIdempotencyKey, recordedInputHash, nil
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
	q := fmt.Sprintf(`SELECT %s, steps.output_jsonb IS NOT NULL, steps.seq, steps.attempt,
		runs.tenant_id, steps.payload_crypto_version, steps.output_plaintext_bytes
		FROM steps JOIN runs ON runs.id = steps.run_id
		WHERE steps.run_id = $1 AND steps.step_name = $2 AND steps.status = $3`, stepOutputReplayValue(j.engine))
	args := []any{runID, stepName, StatusSucceeded}
	switch {
	case idemKey != "" && inputHash != "":
		q += ` AND steps.idempotency_key = $4 AND steps.input_hash = $5`
		args = append(args, idemKey, inputHash)
	case idemKey != "":
		q += ` AND steps.idempotency_key = $4`
		args = append(args, idemKey)
	case inputHash != "":
		q += ` AND steps.input_hash = $4`
		args = append(args, inputHash)
	}
	q += ` ORDER BY steps.attempt DESC LIMIT 1`
	var (
		raw        []byte
		present    bool
		seq        int64
		attempt    int
		tenantID   string
		version    int
		plainBytes sql.NullInt64
	)
	if err := j.db.QueryRowContext(ctx, j.bind(q), args...).Scan(&raw, &present, &seq, &attempt,
		&tenantID, &version, &plainBytes); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("journal: find cached: %w", err)
	}
	if version == 1 && present != plainBytes.Valid || present && raw == nil {
		return nil, payloadcrypto.ErrInvalidEnvelope
	}
	if version == 1 && j.payloadKey == nil {
		return nil, payloadcrypto.ErrKeyRequired
	}
	if !present {
		return nil, nil
	}
	return j.openStepOutput(tenantID, runID, stepName, seq, attempt, version, plainBytes, raw)
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
	p, err := j.prepareRunPayload(ctx, j.db, workflowID, runID, triggerMeta)
	if err != nil {
		return err
	}
	const q = `INSERT INTO runs (id, workflow_id, trigger_kind, trigger_meta, trigger_input, status, started_at, created_at, tenant_id, dispatch_payload_sha256, payload_crypto_version, payload_plaintext_bytes)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`
	_, err = j.db.ExecContext(ctx, j.bind(q),
		runID, workflowID, triggerKind, p.meta, p.input, "running", now, now, p.tenantID, inputSHA256(triggerMeta), p.cryptoVersion, p.plaintextBytes,
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
	p, err := j.prepareRunPayload(ctx, j.db, workflowID, runID, triggerMeta)
	if err != nil {
		return err
	}
	const q = `INSERT INTO runs (id, workflow_id, trigger_kind, trigger_meta, trigger_input, status, started_at, created_at, tenant_id, workflow_version, workflow_artifact_sha256, dispatch_payload_sha256, payload_crypto_version, payload_plaintext_bytes)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`
	_, err = j.db.ExecContext(ctx, j.bind(q),
		runID, workflowID, triggerKind, p.meta, p.input, "running", now, now, p.tenantID, workflowVersion, artifactSHA256, inputSHA256(triggerMeta), p.cryptoVersion, p.plaintextBytes,
	)
	if err != nil {
		return fmt.Errorf("journal: create run: %w", err)
	}
	return nil
}

// CreateRunPinnedIfEnabled atomically admits a live run only while the
// workflow is enabled. The workflow row lock and INSERT share one transaction
// so a concurrent disable cannot land between the dispatch gate and run
// creation.
func (j *Journal) CreateRunPinnedIfEnabled(ctx context.Context, runID, workflowID, triggerKind string, triggerMeta json.RawMessage, workflowVersion int, artifactSHA256 string) error {
	if workflowVersion <= 0 || !validArtifactSHA256(artifactSHA256) {
		return fmt.Errorf("journal: create enabled pinned run: %w", ErrWorkflowArtifactFence)
	}
	tx, err := j.beginEnabledWorkflowTx(ctx, workflowID)
	if err != nil {
		return fmt.Errorf("journal: create enabled pinned run: %w", err)
	}
	defer tx.Rollback()
	if err := j.checkWorkflowAdmissionTx(ctx, tx, workflowID, false); err != nil {
		return fmt.Errorf("journal: create enabled pinned run: %w", err)
	}
	now := j.now()
	p, err := j.prepareRunPayload(ctx, tx, workflowID, runID, triggerMeta)
	if err != nil {
		return err
	}
	const q = `INSERT INTO runs (id, workflow_id, trigger_kind, trigger_meta, trigger_input, status, started_at, created_at, tenant_id, workflow_version, workflow_artifact_sha256, dispatch_payload_sha256, payload_crypto_version, payload_plaintext_bytes)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`
	if _, err := tx.ExecContext(ctx, j.bind(q), runID, workflowID, triggerKind, p.meta, p.input, "running", now, now, p.tenantID, workflowVersion, artifactSHA256, inputSHA256(triggerMeta), p.cryptoVersion, p.plaintextBytes); err != nil {
		return fmt.Errorf("journal: create enabled pinned run: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit enabled pinned run: %w", err)
	}
	return nil
}

// MarkRunFinished sets runs.status + finished_at. Used by the supervisor on
// terminal exit. Guarded: a cancelled run is terminal, so a workflow subprocess
// that completes just after an operator cancel cannot overwrite 'cancelled'
// with 'succeeded'/'failed' and un-cancel the run.
func (j *Journal) MarkRunFinished(ctx context.Context, runID, status string) error {
	return j.MarkRunFinishedForMode(ctx, runID, status, false)
}

// MarkRunFinishedForMode commits a terminal status and its side-effect
// receipt atomically. Dry runs suppress notifications and chains, so they do
// not enqueue a terminal effect.
func (j *Journal) MarkRunFinishedForMode(ctx context.Context, runID, status string, suppressTerminalEffects bool) error {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE runs SET status = $1, finished_at = $2 WHERE id = $3 AND status <> 'cancelled'`), status, j.now(), runID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Already terminal (cancelled): don't record usage for a finish that
		// the guard just prevented.
		return nil
	}
	if !suppressTerminalEffects {
		if err := j.enqueueTerminalEffectTx(ctx, tx, runID, status); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit run finish: %w", err)
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
	ID          string `json:"id"`
	WorkflowID  string `json:"workflow_id"`
	TenantID    string `json:"tenant_id"`
	TriggerKind string `json:"trigger_kind"`
	// InputSHA256 fingerprints the exact trigger bytes supplied at dispatch.
	// It is opaque and safe to expose in receipts; the trigger payload itself
	// remains untrusted data and is bounded by the caller's read surface.
	InputSHA256     string          `json:"input_sha256,omitempty"`
	Status          string          `json:"status"`
	CancelRequested bool            `json:"cancel_requested,omitempty"`
	TriggerMeta     json.RawMessage `json:"trigger_meta,omitempty"`
	// TriggerMetaBytes records the durable byte length even when a bounded
	// read intentionally omits the metadata bytes. It is not serialized in
	// RunInfo JSON; MCP uses it to emit an explicit truncation receipt.
	TriggerMetaBytes int `json:"-"`
	// TriggerInputBytes records the durable byte length even when a bounded
	// control-plane read intentionally omits the exact trigger bytes. The
	// worker-facing GetRun path still materializes TriggerInput; dashboards and
	// MCP receipts use this count plus TriggerInputPresent instead.
	TriggerInputBytes   int  `json:"-"`
	TriggerInputPresent bool `json:"-"`
	// TriggerInput retains the exact bytes used to start the workflow. It is
	// intentionally omitted from JSON views; callers receive InputSHA256 while
	// workers use this field to avoid Postgres JSONB canonicalisation changing
	// the execution input. Nil means a legacy row predates migration 0040.
	TriggerInput           []byte    `json:"-"`
	WorkflowVersion        int       `json:"workflow_version,omitempty"`
	WorkflowArtifactSHA256 string    `json:"workflow_artifact_sha256,omitempty"`
	StartedAt              time.Time `json:"started_at"`
	FinishedAt             time.Time `json:"finished_at"`
}

// ExecutionInput returns the exact bytes captured at dispatch. Rows created
// before migration 0040 fall back to trigger_meta, which is the only input
// available for those historical runs and may already be canonicalized by
// Postgres JSONB.
func (info RunInfo) ExecutionInput() []byte {
	if info.TriggerInput != nil {
		out := make([]byte, len(info.TriggerInput))
		copy(out, info.TriggerInput)
		return out
	}
	if info.TriggerMeta == nil {
		return nil
	}
	out := make([]byte, len(info.TriggerMeta))
	copy(out, info.TriggerMeta)
	return out
}

// GetRun returns the runs row by id. Returns ErrNotFound if no row exists.
func (j *Journal) GetRun(ctx context.Context, runID string) (RunInfo, error) {
	return j.getRun(ctx, runID, "")
}

func (j *Journal) getRun(ctx context.Context, runID, tenantID string) (RunInfo, error) {
	q := `SELECT id, workflow_id, tenant_id, trigger_kind, dispatch_payload_sha256, status, cancel_requested, trigger_meta, trigger_input, workflow_version, workflow_artifact_sha256, started_at, finished_at, payload_crypto_version, payload_plaintext_bytes
		FROM runs WHERE id = $1`
	args := []any{runID}
	if tenantID != "" {
		q += ` AND tenant_id = $2`
		args = append(args, tenantID)
	}
	row := j.db.QueryRowContext(ctx, j.bind(q), args...)
	var (
		info      RunInfo
		inputHash sql.NullString
		cancel    any
		meta      []byte
		input     []byte
		version   sql.NullInt64
		artifact  sql.NullString
		started   sql.NullString
		finished  sql.NullString
		cryptoVer int
		plainLen  sql.NullInt64
	)
	if err := row.Scan(&info.ID, &info.WorkflowID, &info.TenantID, &info.TriggerKind, &inputHash, &info.Status, &cancel, &meta, &input, &version, &artifact, &started, &finished, &cryptoVer, &plainLen); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RunInfo{}, ErrNotFound
		}
		return RunInfo{}, fmt.Errorf("journal: get run: %w", err)
	}
	info.CancelRequested = parseBool(cancel)
	meta, input, err := j.openRunPayload(info.TenantID, runID, cryptoVer, plainLen, meta, input)
	if err != nil {
		return RunInfo{}, fmt.Errorf("journal: open run payload: %w", err)
	}
	if inputHash.Valid {
		info.InputSHA256 = inputHash.String
		if cryptoVer == 1 && input != nil && info.InputSHA256 != inputSHA256(input) {
			return RunInfo{}, fmt.Errorf("journal: run input fingerprint mismatch: %w", payloadcrypto.ErrInvalidEnvelope)
		}
	}
	if len(meta) > 0 {
		info.TriggerMeta = json.RawMessage(meta)
		info.TriggerMetaBytes = len(meta)
	}
	if input != nil {
		info.TriggerInput = make([]byte, len(input))
		copy(info.TriggerInput, input)
		info.TriggerInputBytes = len(input)
		info.TriggerInputPresent = true
	} else if meta != nil {
		// Legacy rows use trigger_meta as their execution input. Preserve its
		// durable size for receipt views without treating it as a trigger_input
		// column value.
		info.TriggerInputBytes = len(meta)
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

// GetRunForTenant returns a run only when it belongs to tenantID. A foreign
// run is reported as ErrNotFound so callers cannot use the scoped lookup to
// confirm that another tenant's run exists.
func (j *Journal) GetRunForTenant(ctx context.Context, runID, tenantID string) (RunInfo, error) {
	return j.getRun(ctx, runID, tenantID)
}

// StepRow is one row of the steps table flattened for the replay timeline.
// JSON tags mirror snake_case for consistency with RunInfo + DeadLetterItem.
type StepRow struct {
	StepName       string          `json:"step_name"`
	Seq            int64           `json:"seq"`
	Attempt        int             `json:"attempt"`
	IdempotencyKey string          `json:"idempotency_key"`
	Status         string          `json:"status"`
	OutputJSONB    json.RawMessage `json:"output_jsonb,omitempty"`
	ErrorText      string          `json:"error_text"`
	StartedAt      time.Time       `json:"started_at"`
	FinishedAt     time.Time       `json:"finished_at"`
	// OutputBytes and ErrorBytes are durable sizes populated by bounded
	// control-plane reads. The worker-facing row readers leave them zero so
	// this internal metadata never changes their historical behavior.
	OutputBytes     int  `json:"-"`
	ErrorBytes      int  `json:"-"`
	OutputTruncated bool `json:"-"`
	ErrorTruncated  bool `json:"-"`
}

// ListSteps returns every recorded step attempt for a run, ordered
// chronologically. Used by `reactor replay <run-id>` to reconstruct
// the timeline a finished run executed, and by the dashboard's
// /runs/{id} page to render output_jsonb per successful step.
func (j *Journal) ListSteps(ctx context.Context, runID string) ([]StepRow, error) {
	return j.ListStepsPage(ctx, runID, 0, 0)
}

// LatestSuccessfulStepOutputBounded returns the most recently finished
// successful step output without materializing the rest of a run's timeline.
// A non-empty stepName narrows the lookup to that step; an empty name selects
// the latest successful step of any kind. The SQL projection omits output
// bytes above maxBytes while still returning OutputBytes/OutputTruncated, so
// synchronous webhook responses and public reconciliation endpoints cannot
// turn a large run into an unbounded read.
func (j *Journal) LatestSuccessfulStepOutputBounded(ctx context.Context, runID, stepName string, maxBytes int) (StepRow, error) {
	if maxBytes <= 0 || maxBytes > 16<<20 {
		return StepRow{}, errors.New("journal: invalid latest step output bound")
	}
	if len(stepName) > 256 {
		return StepRow{}, errors.New("journal: latest step name exceeds 256 bytes")
	}
	q := fmt.Sprintf(`SELECT steps.step_name, steps.seq, steps.attempt, steps.status,
		%s, %s, runs.tenant_id, steps.payload_crypto_version, steps.output_plaintext_bytes
		FROM steps JOIN runs ON runs.id = steps.run_id
		WHERE steps.run_id = $1 AND steps.status = $2 AND steps.output_jsonb IS NOT NULL`,
		stepOutputValue(j.engine, maxBytes), stepOutputPlainSize(j.engine))
	args := []any{runID, StatusSucceeded}
	position := 3
	if stepName != "" {
		q += fmt.Sprintf(" AND steps.step_name = $%d", position)
		args = append(args, stepName)
		position++
	}
	// The explicit NULL-first flag keeps legacy rows with a missing
	// finished_at from winning over a genuinely completed output on either
	// PostgreSQL or SQLite (their DESC NULL ordering differs).
	q += fmt.Sprintf(" ORDER BY (steps.finished_at IS NULL) ASC, steps.finished_at DESC, steps.started_at DESC, steps.seq DESC, steps.attempt DESC, steps.step_name DESC LIMIT $%d", position)
	args = append(args, 1)
	var (
		step        StepRow
		output      []byte
		outputBytes sql.NullInt64
		tenantID    string
		version     int
		plainBytes  sql.NullInt64
	)
	err := j.db.QueryRowContext(ctx, j.bind(q), args...).Scan(
		&step.StepName, &step.Seq, &step.Attempt, &step.Status, &output, &outputBytes,
		&tenantID, &version, &plainBytes,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return StepRow{}, ErrNotFound
	}
	if err != nil {
		return StepRow{}, fmt.Errorf("journal: latest bounded step output: %w", err)
	}
	if version == 1 && (!plainBytes.Valid || plainBytes.Int64 < 0 || plainBytes.Int64 > maxStepPayloadPlaintextBytes) {
		return StepRow{}, payloadcrypto.ErrInvalidEnvelope
	}
	if version == 1 && j.payloadKey == nil {
		return StepRow{}, payloadcrypto.ErrKeyRequired
	}
	if outputBytes.Valid && outputBytes.Int64 >= 0 {
		step.OutputBytes = int(outputBytes.Int64)
		step.OutputTruncated = output == nil
	}
	if output != nil {
		step.OutputJSONB, err = j.openStepOutput(tenantID, runID, step.StepName, step.Seq,
			step.Attempt, version, plainBytes, output)
		if err != nil {
			return StepRow{}, err
		}
	} else if version == 1 && plainBytes.Int64 <= int64(maxBytes) {
		return StepRow{}, payloadcrypto.ErrInvalidEnvelope
	}
	return step, nil
}

// ListStepsPage returns a bounded chronological page when limit is positive.
// A zero limit preserves ListSteps' historical unbounded behavior for trusted
// dashboard/CLI callers; HTTP MCP uses a positive limit so a large run cannot
// turn one tool call into an unbounded response.
func (j *Journal) ListStepsPage(ctx context.Context, runID string, limit, offset int) ([]StepRow, error) {
	return j.listStepsPage(ctx, runID, "", limit, offset)
}

// ListStepsPageForTenant is the tenant-scoped MCP/read-model variant. The
// parent run predicate is part of the same SQL query as the step rows, so a
// caller cannot pass a prior tenant check and then read rows after the run is
// deleted or an identifier is reused.
func (j *Journal) ListStepsPageForTenant(ctx context.Context, runID, tenantID string, limit, offset int) ([]StepRow, error) {
	return j.listStepsPage(ctx, runID, tenantID, limit, offset)
}

// ListStepsPageForTenantBounded returns a tenant-scoped step page while
// projecting output and error text only when each value fits its explicit
// read bound. Size probes remain available for an honest truncation receipt,
// but hostile historical blobs never cross the SQL boundary into the MCP
// process. A non-positive bound omits the corresponding value entirely.
func (j *Journal) ListStepsPageForTenantBounded(ctx context.Context, runID, tenantID string, limit, offset, maxOutputBytes, maxErrorBytes int) ([]StepRow, error) {
	return j.listStepsPageForTenantBounded(ctx, runID, tenantID, limit, offset, maxOutputBytes, maxErrorBytes, false)
}

// ListLatestStepsPageForTenantBounded returns the newest bounded step rows in
// chronological order. Dashboard flow overlays need the final attempt for
// each node; selecting the newest rows before reversing avoids silently
// showing stale early attempts when a run has more rows than the projection
// cap, while preserving deterministic source order for the renderer.
func (j *Journal) ListLatestStepsPageForTenantBounded(ctx context.Context, runID, tenantID string, limit, offset, maxOutputBytes, maxErrorBytes int) ([]StepRow, error) {
	return j.listStepsPageForTenantBounded(ctx, runID, tenantID, limit, offset, maxOutputBytes, maxErrorBytes, true)
}

func (j *Journal) listStepsPageForTenantBounded(ctx context.Context, runID, tenantID string, limit, offset, maxOutputBytes, maxErrorBytes int, latest bool) ([]StepRow, error) {
	if limit <= 0 || limit > 1000 || offset < 0 {
		return nil, errors.New("journal: invalid bounded step page")
	}
	if maxOutputBytes < 0 || maxErrorBytes < 0 || maxOutputBytes > 16<<20 || maxErrorBytes > 16<<20 {
		return nil, errors.New("journal: invalid bounded step value limit")
	}
	q := fmt.Sprintf(`SELECT steps.step_name, steps.seq, steps.attempt, steps.idempotency_key, steps.status,
		%s, %s, %s, %s, steps.started_at, steps.finished_at,
		runs.tenant_id, steps.payload_crypto_version, steps.output_plaintext_bytes, steps.error_plaintext_bytes,
		steps.output_jsonb IS NOT NULL, steps.error_text IS NOT NULL
		FROM steps JOIN runs ON runs.id = steps.run_id WHERE steps.run_id = $1`,
		stepOutputValue(j.engine, maxOutputBytes), stepOutputPlainSize(j.engine),
		stepErrorValue(j.engine, maxErrorBytes), stepErrorPlainSize(j.engine))
	args := []any{runID}
	position := 2
	if tenantID != "" {
		q += fmt.Sprintf(" AND runs.tenant_id = $%d", position)
		args = append(args, tenantID)
		position++
	}
	if latest {
		// Keep NULL timestamps deterministic across SQLite and PostgreSQL. The
		// newest page is reversed below so callers still receive chronological
		// rows, with legacy NULL-start rows first.
		q += fmt.Sprintf(" ORDER BY (steps.started_at IS NULL) ASC, steps.started_at DESC, steps.seq DESC, steps.attempt DESC, steps.step_name DESC LIMIT $%d OFFSET $%d", position, position+1)
	} else {
		q += fmt.Sprintf(" ORDER BY steps.started_at ASC, steps.seq ASC, steps.attempt ASC, steps.step_name ASC LIMIT $%d OFFSET $%d", position, position+1)
	}
	args = append(args, limit, offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, fmt.Errorf("journal: list bounded steps: %w", err)
	}
	defer rows.Close()
	out := make([]StepRow, 0, limit)
	for rows.Next() {
		var (
			step        StepRow
			idem        sql.NullString
			output      []byte
			outputBytes sql.NullInt64
			errText     sql.NullString
			errorBytes  sql.NullInt64
			started     sql.NullString
			finished    sql.NullString
			tenant      string
			version     int
			outputPlain sql.NullInt64
			errorPlain  sql.NullInt64
			outPresent  bool
			errPresent  bool
		)
		if err := rows.Scan(&step.StepName, &step.Seq, &step.Attempt, &idem, &step.Status,
			&output, &outputBytes, &errText, &errorBytes, &started, &finished,
			&tenant, &version, &outputPlain, &errorPlain, &outPresent, &errPresent); err != nil {
			return nil, fmt.Errorf("journal: scan bounded step: %w", err)
		}
		if idem.Valid {
			step.IdempotencyKey = idem.String
		}
		if version == 1 && j.payloadKey == nil {
			return nil, payloadcrypto.ErrKeyRequired
		}
		if version != 0 && version != 1 || version == 1 && (outPresent != outputPlain.Valid ||
			errPresent != errorPlain.Valid ||
			outPresent && (outputPlain.Int64 < 0 || outputPlain.Int64 > maxStepPayloadPlaintextBytes) ||
			errPresent && (errorPlain.Int64 < 0 || errorPlain.Int64 > maxStepPayloadPlaintextBytes)) {
			return nil, payloadcrypto.ErrInvalidEnvelope
		}
		if outputBytes.Valid && outputBytes.Int64 >= 0 {
			step.OutputBytes = int(outputBytes.Int64)
			step.OutputTruncated = output == nil
		}
		if output != nil {
			step.OutputJSONB, err = j.openStepOutput(tenant, runID, step.StepName, step.Seq,
				step.Attempt, version, outputPlain, output)
			if err != nil {
				return nil, err
			}
		} else if version == 1 && outPresent && outputPlain.Int64 <= int64(maxOutputBytes) && maxOutputBytes > 0 {
			return nil, payloadcrypto.ErrInvalidEnvelope
		}
		if errorBytes.Valid && errorBytes.Int64 >= 0 {
			step.ErrorBytes = int(errorBytes.Int64)
			step.ErrorTruncated = !errText.Valid
		}
		if errText.Valid {
			step.ErrorText, err = j.openStepError(tenant, runID, step.StepName, step.Seq,
				step.Attempt, version, errorPlain, errText.String)
			if err != nil {
				return nil, err
			}
		} else if version == 1 && errPresent && errorPlain.Int64 <= int64(maxErrorBytes) && maxErrorBytes > 0 {
			return nil, payloadcrypto.ErrInvalidEnvelope
		}
		if started.Valid {
			if t, parseErr := j.parseTime(started.String); parseErr == nil {
				step.StartedAt = t
			}
		}
		if finished.Valid {
			if t, parseErr := j.parseTime(finished.String); parseErr == nil {
				step.FinishedAt = t
			}
		}
		out = append(out, step)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("journal: list bounded steps rows: %w", err)
	}
	if latest {
		for left, right := 0, len(out)-1; left < right; left, right = left+1, right-1 {
			out[left], out[right] = out[right], out[left]
		}
	}
	return out, nil
}

func (j *Journal) listStepsPage(ctx context.Context, runID, tenantID string, limit, offset int) ([]StepRow, error) {
	q := fmt.Sprintf(`SELECT steps.step_name, steps.seq, steps.attempt, steps.idempotency_key, steps.status,
		%s, %s, steps.started_at, steps.finished_at, runs.tenant_id,
		steps.payload_crypto_version, steps.output_plaintext_bytes, steps.error_plaintext_bytes,
		steps.output_jsonb IS NOT NULL, steps.error_text IS NOT NULL
		FROM steps JOIN runs ON runs.id = steps.run_id WHERE steps.run_id = $1`,
		stepOutputReplayValue(j.engine), stepErrorReplayValue(j.engine))
	args := []any{runID}
	if tenantID != "" {
		q += ` AND runs.tenant_id = $2`
		args = append(args, tenantID)
	}
	q += ` ORDER BY steps.started_at ASC, steps.seq ASC, steps.attempt ASC, steps.step_name ASC`
	if limit > 0 {
		limitPos := len(args) + 1
		offsetPos := limitPos + 1
		q += fmt.Sprintf(` LIMIT $%d OFFSET $%d`, limitPos, offsetPos)
		args = append(args, limit, offset)
	}
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
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
			tenant   string
			version  int
			outLen   sql.NullInt64
			errLen   sql.NullInt64
			outSet   bool
			errSet   bool
		)
		if err := rows.Scan(&s.StepName, &s.Seq, &s.Attempt, &idem, &s.Status, &outBlob,
			&errText, &started, &finished, &tenant, &version, &outLen, &errLen, &outSet, &errSet); err != nil {
			return nil, fmt.Errorf("journal: scan step: %w", err)
		}
		if idem.Valid {
			s.IdempotencyKey = idem.String
		}
		if version == 1 && (outSet != outLen.Valid || errSet != errLen.Valid ||
			outSet && outBlob == nil || errSet && !errText.Valid) {
			return nil, payloadcrypto.ErrInvalidEnvelope
		}
		s.OutputJSONB, s.ErrorText, err = j.openStepValues(tenant, runID, s.StepName, s.Seq,
			s.Attempt, version, outLen, errLen, outBlob, errText)
		if err != nil {
			return nil, err
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

// ReadStepOutputPage returns one exact step attempt and a bounded slice of its
// persisted output. The database performs the substring operation so a large
// cached result is never loaded into the MCP process merely to be truncated.
// offset is zero-based and limit must be positive.
func (j *Journal) ReadStepOutputPage(ctx context.Context, runID, stepName string, seq int64, attempt, offset, limit int) (StepRow, int, error) {
	return j.readStepOutputPage(ctx, runID, "", stepName, seq, attempt, offset, limit)
}

// ReadStepOutputPageForTenant keeps the parent-run tenant predicate in the
// same bounded output query used by MCP. It never materializes another
// tenant's persisted output merely because the run check happened earlier.
func (j *Journal) ReadStepOutputPageForTenant(ctx context.Context, runID, tenantID, stepName string, seq int64, attempt, offset, limit int) (StepRow, int, error) {
	return j.readStepOutputPage(ctx, runID, tenantID, stepName, seq, attempt, offset, limit)
}

func (j *Journal) readStepOutputPage(ctx context.Context, runID, tenantID, stepName string, seq int64, attempt, offset, limit int) (StepRow, int, error) {
	if limit <= 0 || offset < 0 || offset > 16<<20 || limit > 1<<20 {
		return StepRow{}, 0, errors.New("journal: invalid step output page")
	}
	// The MCP caller only needs a bounded diagnostic error alongside the output
	// page. Project its size and omit the full legacy text when it exceeds the
	// same 32 KiB control-plane cap used by run receipts.
	const maxStepErrorReadBytes = 32 << 10
	// A v1 page must authenticate the complete envelope before exposing any
	// plaintext slice. The wire limit makes that read bounded to about 1 MiB.
	outputValue := fmt.Sprintf(`CASE WHEN steps.payload_crypto_version = 1 THEN
		CASE WHEN %s <= %d THEN %s ELSE NULL END
		ELSE SUBSTR(CAST(steps.output_jsonb AS TEXT), $5, $6) END`,
		stepOutputStoredSize(j.engine), payloadcrypto.JSONCiphertextLimit(maxStepPayloadPlaintextBytes),
		stepOutputText(j.engine))
	q := fmt.Sprintf(`SELECT steps.step_name, steps.seq, steps.attempt, steps.idempotency_key, steps.status,
		COALESCE(CASE WHEN steps.payload_crypto_version = 1 THEN steps.output_plaintext_bytes
			ELSE LENGTH(CAST(steps.output_jsonb AS TEXT)) END, 0),
		%s, %s, %s, steps.started_at, steps.finished_at, runs.tenant_id,
		steps.payload_crypto_version, steps.output_plaintext_bytes, steps.error_plaintext_bytes,
		steps.output_jsonb IS NOT NULL, steps.error_text IS NOT NULL
		FROM steps JOIN runs ON runs.id = steps.run_id
		WHERE steps.run_id = $1 AND steps.step_name = $2 AND steps.seq = $3 AND steps.attempt = $4
			AND ($7 = '' OR runs.tenant_id = $7)`, outputValue,
		stepErrorValue(j.engine, maxStepErrorReadBytes), stepErrorPlainSize(j.engine))
	var (
		step       StepRow
		idem       sql.NullString
		outputSize int
		outBlob    []byte
		errText    sql.NullString
		errorBytes sql.NullInt64
		started    sql.NullString
		finished   sql.NullString
		tenant     string
		version    int
		outLen     sql.NullInt64
		errLen     sql.NullInt64
		outSet     bool
		errSet     bool
	)
	args := []any{runID, stepName, seq, attempt, offset + 1, limit, tenantID}
	// bind rewrites PostgreSQL's numbered placeholders to anonymous SQLite
	// placeholders. SQLite binds those in textual order, and the SUBSTR
	// arguments appear before the WHERE arguments in this SELECT.
	if j.engine == EngineSQLite {
		args = []any{offset + 1, limit, runID, stepName, seq, attempt, tenantID, tenantID}
	}
	err := j.db.QueryRowContext(ctx, j.bind(q), args...).Scan(
		&step.StepName, &step.Seq, &step.Attempt, &idem, &step.Status, &outputSize,
		&outBlob, &errText, &errorBytes, &started, &finished, &tenant, &version,
		&outLen, &errLen, &outSet, &errSet,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return StepRow{}, 0, ErrNotFound
	}
	if err != nil {
		return StepRow{}, 0, fmt.Errorf("journal: read step output: %w", err)
	}
	if idem.Valid {
		step.IdempotencyKey = idem.String
	}
	if version == 1 && j.payloadKey == nil {
		return StepRow{}, 0, payloadcrypto.ErrKeyRequired
	}
	if version != 0 && version != 1 || version == 1 && (outSet != outLen.Valid ||
		errSet != errLen.Valid || outSet && outLen.Int64 > maxStepPayloadPlaintextBytes ||
		errSet && errLen.Int64 > maxStepPayloadPlaintextBytes) {
		return StepRow{}, 0, payloadcrypto.ErrInvalidEnvelope
	}
	if version == 1 {
		if outSet {
			if outBlob == nil {
				return StepRow{}, 0, payloadcrypto.ErrInvalidEnvelope
			}
			plain, openErr := j.openStepOutput(tenant, runID, step.StepName, step.Seq, step.Attempt,
				version, outLen, outBlob)
			if openErr != nil {
				return StepRow{}, 0, openErr
			}
			runes := []rune(string(plain))
			outputSize = len(runes)
			if offset < len(runes) {
				end := offset + limit
				if end > len(runes) {
					end = len(runes)
				}
				step.OutputJSONB = json.RawMessage(string(runes[offset:end]))
			}
		}
	} else if len(outBlob) > 0 {
		step.OutputJSONB = json.RawMessage(outBlob)
	}
	if errText.Valid {
		step.ErrorText, err = j.openStepError(tenant, runID, step.StepName, step.Seq,
			step.Attempt, version, errLen, errText.String)
		if err != nil {
			return StepRow{}, 0, err
		}
	} else if version == 1 && errSet && errLen.Int64 <= maxStepErrorReadBytes {
		return StepRow{}, 0, payloadcrypto.ErrInvalidEnvelope
	}
	if errorBytes.Valid && errorBytes.Int64 >= 0 {
		step.ErrorBytes = int(errorBytes.Int64)
		step.ErrorTruncated = !errText.Valid
	}
	if started.Valid {
		if t, parseErr := j.parseTime(started.String); parseErr == nil {
			step.StartedAt = t
		}
	}
	if finished.Valid {
		if t, parseErr := j.parseTime(finished.String); parseErr == nil {
			step.FinishedAt = t
		}
	}
	return step, outputSize, nil
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

// WorkflowTenantsBySlug returns every tenant that owns a workflow with slug.
// The database intentionally permits duplicate slugs across tenants, while
// the node-local executable registry still has one mutable filesystem
// namespace per slug. Artifact registration uses this inventory to refuse a
// cross-tenant collision before it can overwrite candidate/source/current
// compatibility files.
func (j *Journal) WorkflowTenantsBySlug(ctx context.Context, slug string) ([]string, error) {
	const q = `SELECT DISTINCT tenant_id FROM workflows WHERE slug = $1 ORDER BY tenant_id`
	rows, err := j.db.QueryContext(ctx, j.bind(q), slug)
	if err != nil {
		return nil, fmt.Errorf("journal: workflow tenants by slug: %w", err)
	}
	defer rows.Close()
	var tenants []string
	for rows.Next() {
		var tenant string
		if err := rows.Scan(&tenant); err != nil {
			return nil, fmt.Errorf("journal: scan workflow tenant by slug: %w", err)
		}
		tenants = append(tenants, tenant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("journal: iterate workflow tenants by slug: %w", err)
	}
	return tenants, nil
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

// ListWorkflowsPage returns one bounded page from the estate-wide workflow
// inventory. The graph builder uses this variant so a large tenant estate is
// not materialised into a second temporary slice before it becomes graph
// nodes. The returned bool is true when more rows remain after the page.
//
// This is intentionally separate from ListWorkflows: dashboard and CLI
// callers historically receive the complete slice, while background graph
// rebuilds can keep their database read working set bounded.
func (j *Journal) ListWorkflowsPage(ctx context.Context, limit, offset int) ([]Workflow, bool, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		return nil, false, fmt.Errorf("journal: list workflows: page limit exceeds 500")
	}
	if offset < 0 {
		return nil, false, fmt.Errorf("journal: list workflows: negative offset")
	}
	return j.listWorkflowsPage(ctx, "", limit, offset)
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
// instances. Returns (allowed, limit, err); limit 0 means unlimited. Any
// lookup/count error returns allowed=false alongside the error so an
// admission caller cannot accidentally treat an unavailable counter as an
// empty window.
func (j *Journal) CheckWorkflowRateLimit(ctx context.Context, workflowID string) (bool, int, error) {
	limit, err := j.WorkflowRateLimit(ctx, workflowID)
	if err != nil {
		return false, limit, err
	}
	if limit <= 0 {
		return true, limit, err
	}
	var n int
	err = j.db.QueryRowContext(ctx,
		j.bind(`SELECT COUNT(*) FROM runs WHERE workflow_id = $1 AND created_at >= $2`),
		workflowID, j.formatTime(time.Now().UTC().Add(-time.Minute))).Scan(&n)
	if err != nil {
		// An unavailable usage count is not an empty window. Return false with
		// the error so every caller that forgets to branch on err still fails
		// closed rather than bypassing a configured limit.
		return false, limit, fmt.Errorf("journal: rate-limit count: %w", err)
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

// WorkflowDAGBounded returns the current legacy workflow DAG with a SQL-side
// byte cap. The durable size remains available to control-plane callers even
// when the blob itself is omitted, so an oversized graph can be reported and
// treated as incomplete proof rather than silently rendered as empty.
func (j *Journal) WorkflowDAGBounded(ctx context.Context, workflowID string, maxDAGBytes int) (dag json.RawMessage, dagBytes int, truncated bool, err error) {
	if maxDAGBytes < 0 || maxDAGBytes > 64<<20 {
		return nil, 0, false, fmt.Errorf("journal: workflow DAG bound must be between 0 and 64 MiB")
	}
	var sizeExpr, valueExpr string
	if j.engine == EnginePostgres {
		sizeExpr = "COALESCE(octet_length(dag_json::text), 0)"
		valueExpr = fmt.Sprintf("CASE WHEN %s <= %d THEN dag_json ELSE NULL END", sizeExpr, maxDAGBytes)
	} else {
		sizeExpr = "COALESCE(length(CAST(dag_json AS BLOB)), 0)"
		valueExpr = fmt.Sprintf("CASE WHEN %s <= %d THEN dag_json ELSE NULL END", sizeExpr, maxDAGBytes)
	}
	q := fmt.Sprintf("SELECT %s, %s FROM workflows WHERE id = $1", valueExpr, sizeExpr)
	var raw []byte
	var size int64
	if err := j.db.QueryRowContext(ctx, j.bind(q), workflowID).Scan(&raw, &size); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, false, ErrNotFound
		}
		return nil, 0, false, fmt.Errorf("journal: bounded workflow dag: %w", err)
	}
	if size < 0 || size > int64(^uint(0)>>1) {
		return nil, 0, false, fmt.Errorf("journal: workflow DAG byte count out of range")
	}
	return json.RawMessage(raw), int(size), int(size) > maxDAGBytes, nil
}

// ListWorkflowsByTenant returns only the given tenant's workflows (dashboard
// scoping for non-admin viewers).
func (j *Journal) ListWorkflowsByTenant(ctx context.Context, tenantID string) ([]Workflow, error) {
	return j.listWorkflows(ctx, tenantID)
}

// ListWorkflowsByTenantPage returns one bounded tenant-scoped workflow page.
// It fetches one extra row so callers can expose continuation without a
// separate count query.
func (j *Journal) ListWorkflowsByTenantPage(ctx context.Context, tenantID string, limit, offset int) ([]Workflow, bool, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		return nil, false, fmt.Errorf("journal: list workflows: page limit exceeds 500")
	}
	if offset < 0 {
		return nil, false, fmt.Errorf("journal: list workflows: negative offset")
	}
	return j.listWorkflowsPage(ctx, tenantID, limit, offset)
}

func (j *Journal) listWorkflows(ctx context.Context, tenantID string) ([]Workflow, error) {
	out, _, err := j.listWorkflowsPage(ctx, tenantID, 0, 0)
	return out, err
}

func (j *Journal) listWorkflowsPage(ctx context.Context, tenantID string, limit, offset int) ([]Workflow, bool, error) {
	q := `SELECT w.id, w.slug, w.tenant_id, w.code_hash, w.sdk_version, w.created_at, w.updated_at,
			w.estimated_minutes_saved_per_run, w.enabled,
			COALESCE((SELECT MAX(v.version) FROM workflow_versions v WHERE v.workflow_id = w.id), 0)
		FROM workflows w`
	var args []any
	if tenantID != "" {
		q += ` WHERE w.tenant_id = $1`
		args = append(args, tenantID)
	}
	// Include immutable tie-breakers so offset pagination cannot duplicate or
	// skip rows when multiple tenants reuse a slug.
	q += ` ORDER BY slug ASC, tenant_id ASC, id ASC`
	fetchLimit := limit
	if fetchLimit > 0 {
		fetchLimit++
		q += fmt.Sprintf(" LIMIT %d OFFSET %d", fetchLimit, offset)
	}
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list workflows: %w", err)
	}
	defer rows.Close()
	var out []Workflow
	for rows.Next() {
		var (
			w       Workflow
			created sql.NullString
			updated sql.NullString
			enabled any
		)
		if err := rows.Scan(&w.ID, &w.Slug, &w.TenantID, &w.CodeHash, &w.SDKVersion, &created, &updated, &w.EstimatedMinutesSavedPerRun, &enabled, &w.CurrentVersion); err != nil {
			return nil, false, fmt.Errorf("journal: scan workflow: %w", err)
		}
		w.Enabled = parseBool(enabled)
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
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := false
	if limit > 0 && len(out) > limit {
		hasMore = true
		out = out[:limit]
	}
	return out, hasMore, nil
}

// Workflow is the read-only summary returned by ListWorkflows.
type Workflow struct {
	ID                          string    `json:"id"`
	Slug                        string    `json:"slug"`
	TenantID                    string    `json:"tenant_id"`
	CodeHash                    string    `json:"code_hash"`
	SDKVersion                  string    `json:"sdk_version"`
	Enabled                     bool      `json:"enabled"`
	CurrentVersion              int       `json:"current_version"`
	CreatedAt                   time.Time `json:"created_at"`
	UpdatedAt                   time.Time `json:"updated_at"`
	EstimatedMinutesSavedPerRun int       `json:"estimated_minutes_saved_per_run"`
}

// GetWorkflow returns a single workflow's metadata. Used by the
// dashboard's workflow detail page so the editable minutes-saved
// baseline pre-populates with the stored value instead of forcing the
// operator to re-type on every save.
func (j *Journal) GetWorkflow(ctx context.Context, id string) (Workflow, error) {
	const q = `SELECT w.id, w.slug, w.tenant_id, w.code_hash, w.sdk_version, w.created_at, w.updated_at,
		w.estimated_minutes_saved_per_run, w.enabled,
		COALESCE((SELECT MAX(v.version) FROM workflow_versions v WHERE v.workflow_id = w.id), 0)
		FROM workflows w WHERE w.id = $1`
	row := j.db.QueryRowContext(ctx, j.bind(q), id)
	var (
		w       Workflow
		created sql.NullString
		updated sql.NullString
		enabled any
	)
	if err := row.Scan(&w.ID, &w.Slug, &w.TenantID, &w.CodeHash, &w.SDKVersion, &created, &updated, &w.EstimatedMinutesSavedPerRun, &enabled, &w.CurrentVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Workflow{}, ErrNotFound
		}
		return Workflow{}, fmt.Errorf("journal: get workflow: %w", err)
	}
	w.Enabled = parseBool(enabled)
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
	q := `SELECT id, workflow_id, tenant_id, trigger_kind, dispatch_payload_sha256, status, cancel_requested, started_at, finished_at FROM runs WHERE 1=1`
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
	// Keep offset pagination stable when runs share a timestamp. SQLite and
	// PostgreSQL are both free to reorder equal started_at rows between page
	// reads; the unique run id is the deterministic tie-breaker that prevents
	// an MCP caller from seeing duplicates or skipped runs while walking a
	// tenant-scoped page sequence.
	q += fmt.Sprintf(" ORDER BY started_at DESC, id DESC LIMIT $%d OFFSET $%d", pos, pos+1)
	args = append(args, f.Limit, f.Offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, fmt.Errorf("journal: list runs: %w", err)
	}
	defer rows.Close()
	var out []RunInfo
	for rows.Next() {
		var (
			info      RunInfo
			inputHash sql.NullString
			cancel    any
			started   sql.NullString
			finished  sql.NullString
		)
		if err := rows.Scan(&info.ID, &info.WorkflowID, &info.TenantID, &info.TriggerKind, &inputHash, &info.Status, &cancel, &started, &finished); err != nil {
			return nil, fmt.Errorf("journal: scan run: %w", err)
		}
		info.CancelRequested = parseBool(cancel)
		if inputHash.Valid {
			info.InputSHA256 = inputHash.String
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
func (j *Journal) CreateWorkflowWithArtifact(ctx context.Context, id, slug, codeHash, sdkVer, artifactSHA256 string, dag json.RawMessage, sourceManifestSHA256 ...string) error {
	return j.CreateWorkflowInTenantWithArtifact(ctx, id, slug, codeHash, sdkVer, artifactSHA256, dag, DefaultTenant, sourceManifestSHA256...)
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

// CreateWorkflowInTenantDisabled is the MCP authoring path. New workflows
// remain reviewable but inert until an operator explicitly enables them after
// inspecting the retained source and flow.
func (j *Journal) CreateWorkflowInTenantDisabled(ctx context.Context, id, slug, codeHash, sdkVer string, dag json.RawMessage, tenantID string) error {
	return j.createWorkflowInTenantWithArtifact(ctx, id, slug, codeHash, sdkVer, "", dag, tenantID, false)
}

// CreateWorkflowInTenantWithArtifact is the production registration path for
// compiled workflows. Metadata-only callers may use CreateWorkflowInTenant,
// but the resulting empty artifact pin intentionally cannot execute.
func (j *Journal) CreateWorkflowInTenantWithArtifact(ctx context.Context, id, slug, codeHash, sdkVer, artifactSHA256 string, dag json.RawMessage, tenantID string, sourceManifestSHA256 ...string) error {
	return j.createWorkflowInTenantWithArtifact(ctx, id, slug, codeHash, sdkVer, artifactSHA256, dag, tenantID, true, sourceManifestSHA256...)
}

// CreateWorkflowInTenantWithArtifactDisabled is the MCP compiled-authoring
// path. The artifact is durable and reviewable, but dispatch remains refused
// until reactor_set_workflow_state explicitly enables the workflow.
func (j *Journal) CreateWorkflowInTenantWithArtifactDisabled(ctx context.Context, id, slug, codeHash, sdkVer, artifactSHA256 string, dag json.RawMessage, tenantID string, sourceManifestSHA256 ...string) error {
	return j.createWorkflowInTenantWithArtifact(ctx, id, slug, codeHash, sdkVer, artifactSHA256, dag, tenantID, false, sourceManifestSHA256...)
}

func (j *Journal) createWorkflowInTenantWithArtifact(ctx context.Context, id, slug, codeHash, sdkVer, artifactSHA256 string, dag json.RawMessage, tenantID string, enabled bool, sourceManifestSHA256 ...string) error {
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	if artifactSHA256 != "" && !validArtifactSHA256(artifactSHA256) {
		return errors.New("journal: create workflow: invalid artifact sha256")
	}
	if len(sourceManifestSHA256) > 1 || (len(sourceManifestSHA256) == 1 && !validArtifactSHA256(sourceManifestSHA256[0])) {
		return errors.New("journal: create workflow: invalid source manifest sha256")
	}
	manifestDigest := ""
	if len(sourceManifestSHA256) == 1 {
		manifestDigest = sourceManifestSHA256[0]
		if artifactSHA256 == "" {
			return errors.New("journal: source manifest pin requires an artifact")
		}
	}
	now := j.now()
	dg := outputArg(dag, j.engine)
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: create workflow: begin: %w", err)
	}
	defer tx.Rollback()
	const q = `INSERT INTO workflows (id, tenant_id, slug, code_hash, sdk_version, dag_json, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err = tx.ExecContext(ctx, j.bind(q),
		id, tenantID, slug, codeHash, sdkVer, dg, j.boolValue(enabled), now, now,
	)
	if err != nil {
		return fmt.Errorf("journal: create workflow: %w", err)
	}
	const versionQ = `INSERT INTO workflow_versions
		(workflow_id, version, sdk_version, code_hash, artifact_sha256, source_manifest_sha256, dag_json, created_at)
		VALUES ($1, 1, $2, $3, $4, $5, $6, $7)`
	if _, err := tx.ExecContext(ctx, j.bind(versionQ), id, sdkVer, codeHash, nullIfEmpty(artifactSHA256), nullIfEmpty(manifestDigest), dg, now); err != nil {
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

// ErrWorkflowStateConflict means an authoring caller supplied a state that is
// no longer current. It is deliberately separate from ErrNotFound so an MCP
// client can re-read the tenant-scoped workflow and review the intervening
// state before retrying.
var ErrWorkflowStateConflict = errors.New("journal: workflow state conflict")

// SetWorkflowEnabledIfState toggles a workflow only when its current enabled
// state still matches the caller's read. The predicate and update are one SQL
// mutation, so two agents cannot both successfully apply decisions based on
// the same stale state.
func (j *Journal) SetWorkflowEnabledIfState(ctx context.Context, id string, enabled, expectedEnabled bool) error {
	const q = `UPDATE workflows SET enabled = $1, updated_at = $2
		WHERE id = $3 AND enabled = $4`
	res, err := j.db.ExecContext(ctx, j.bind(q), j.boolValue(enabled), j.now(), id, j.boolValue(expectedEnabled))
	if err != nil {
		return fmt.Errorf("journal: set workflow enabled if state: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("journal: set workflow enabled if state rows affected: %w", err)
	}
	if n == 1 {
		return nil
	}
	var current bool
	if err := j.db.QueryRowContext(ctx, j.bind(`SELECT enabled FROM workflows WHERE id = $1`), id).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: read workflow state after conflict: %w", err)
	}
	return fmt.Errorf("%w: expected enabled=%t, current enabled=%t", ErrWorkflowStateConflict, expectedEnabled, current)
}

// SetWorkflowEnabledIfVersion toggles a workflow only when the immutable
// version reviewed by the caller is still current. The workflow row is locked
// before reading the version and changing enabled, so an authoring write and
// activation cannot cross and turn a stale review into a live deployment.
func (j *Journal) SetWorkflowEnabledIfVersion(ctx context.Context, id string, enabled bool, expectedVersion int) error {
	return j.setWorkflowEnabledFence(ctx, id, enabled, expectedVersion, nil)
}

// SetWorkflowEnabledIfStateAndVersion combines both optimistic-concurrency
// fences for callers that reviewed the workflow's state and immutable version
// together. Both predicates are checked in one transaction.
func (j *Journal) SetWorkflowEnabledIfStateAndVersion(ctx context.Context, id string, enabled, expectedEnabled bool, expectedVersion int) error {
	return j.setWorkflowEnabledFence(ctx, id, enabled, expectedVersion, &expectedEnabled)
}

func (j *Journal) setWorkflowEnabledFence(ctx context.Context, id string, enabled bool, expectedVersion int, expectedState *bool) error {
	if expectedVersion < 1 {
		return fmt.Errorf("%w: expected version must be positive", ErrWorkflowVersionConflict)
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin workflow activation fence: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EnginePostgres {
		var lockedID string
		if err := tx.QueryRowContext(ctx, `SELECT id FROM workflows WHERE id = $1 FOR UPDATE`, id).Scan(&lockedID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("journal: lock workflow activation: %w", err)
		}
	} else {
		res, err := tx.ExecContext(ctx, j.bind(`UPDATE workflows SET updated_at = updated_at WHERE id = $1`), id)
		if err != nil {
			return fmt.Errorf("journal: lock workflow activation: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
	}
	var currentVersion int
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COALESCE(MAX(version), 0) FROM workflow_versions WHERE workflow_id = $1`), id).Scan(&currentVersion); err != nil {
		return fmt.Errorf("journal: read workflow activation version: %w", err)
	}
	if currentVersion != expectedVersion {
		return fmt.Errorf("%w: expected version %d, current version %d", ErrWorkflowVersionConflict, expectedVersion, currentVersion)
	}
	if expectedState != nil {
		var current any
		if err := tx.QueryRowContext(ctx, j.bind(`SELECT enabled FROM workflows WHERE id = $1`), id).Scan(&current); err != nil {
			return fmt.Errorf("journal: read workflow activation state: %w", err)
		}
		currentEnabled := parseBool(current)
		if currentEnabled != *expectedState {
			return fmt.Errorf("%w: expected enabled=%t, current enabled=%t", ErrWorkflowStateConflict, *expectedState, currentEnabled)
		}
	}
	if _, err := tx.ExecContext(ctx, j.bind(`UPDATE workflows SET enabled = $1, updated_at = $2 WHERE id = $3`), j.boolValue(enabled), j.now(), id); err != nil {
		return fmt.Errorf("journal: set workflow enabled with version fence: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit workflow activation fence: %w", err)
	}
	return nil
}

// ErrWorkflowBusy is returned by DeleteWorkflow when the workflow has
// runs in a non-terminal status (running, suspended). The dashboard
// maps this to an inline 409 error pill so the operator disables the
// workflow first.
var ErrWorkflowBusy = errors.New("journal: workflow has active runs")

// ErrWorkflowEnabled is returned by DeleteWorkflowIfDisabled when a caller
// has not paused the workflow first. Keeping this check in the same
// transaction as the cascade prevents a concurrent re-enable from turning a
// destructive operation into a live dispatch race.
var ErrWorkflowEnabled = errors.New("journal: workflow is enabled")

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
	return j.deleteWorkflow(ctx, id, false)
}

// DeleteWorkflowIfDisabled removes a workflow only when its enabled flag is
// false in the same transaction as the cascade. It is the safe lifecycle
// operation for control-plane callers that require an explicit pause before a
// destructive delete.
func (j *Journal) DeleteWorkflowIfDisabled(ctx context.Context, id string) error {
	return j.deleteWorkflow(ctx, id, true)
}

// DeleteWorkflowIfDisabledAndVersion permanently removes a disabled workflow
// only when the caller's reviewed immutable version is still current. The
// workflow row is locked before the version and enabled-state checks so a
// stale AI retirement decision cannot delete a newer authored revision.
func (j *Journal) DeleteWorkflowIfDisabledAndVersion(ctx context.Context, id string, expectedVersion int) error {
	if expectedVersion < 1 {
		return ErrWorkflowVersionConflict
	}
	return j.deleteWorkflowVersion(ctx, id, true, expectedVersion)
}

func (j *Journal) deleteWorkflow(ctx context.Context, id string, requireDisabled bool) error {
	return j.deleteWorkflowVersion(ctx, id, requireDisabled, 0)
}

func (j *Journal) deleteWorkflowVersion(ctx context.Context, id string, requireDisabled bool, expectedVersion int) error {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if expectedVersion > 0 {
		if j.engine == EnginePostgres {
			var lockedID string
			if err := tx.QueryRowContext(ctx, `SELECT id FROM workflows WHERE id = $1 FOR UPDATE`, id).Scan(&lockedID); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ErrNotFound
				}
				return fmt.Errorf("journal: delete workflow: lock version: %w", err)
			}
		} else {
			res, err := tx.ExecContext(ctx, j.bind(`UPDATE workflows SET updated_at = updated_at WHERE id = $1`), id)
			if err != nil {
				return fmt.Errorf("journal: delete workflow: lock version: %w", err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return ErrNotFound
			}
		}
		var currentVersion int
		if err := tx.QueryRowContext(ctx, j.bind(`SELECT COALESCE(MAX(version), 0) FROM workflow_versions WHERE workflow_id = $1`), id).Scan(&currentVersion); err != nil {
			return fmt.Errorf("journal: delete workflow: read version: %w", err)
		}
		if currentVersion != expectedVersion {
			return fmt.Errorf("%w: expected version %d, current version %d", ErrWorkflowVersionConflict, expectedVersion, currentVersion)
		}
	}

	if requireDisabled {
		const enabledQ = `SELECT enabled FROM workflows WHERE id = $1`
		var enabled any
		if err := tx.QueryRowContext(ctx, j.bind(enabledQ), id).Scan(&enabled); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("journal: delete workflow: check enabled: %w", err)
		}
		if parseBool(enabled) {
			return fmt.Errorf("%w: disable it before deleting", ErrWorkflowEnabled)
		}
	}

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
		`DELETE FROM runtime_secret_access_audit WHERE run_id IN (SELECT id FROM runs WHERE workflow_id = $1)`,
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
	const q = `UPDATE triggers SET config_json = $1, updated_at = $2, revision = revision + 1 WHERE id = $3`
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

// rawInputArg keeps the exact trigger bytes in the binary input column. A
// separate copy prevents a caller that reuses its request buffer after the
// insert from changing the value captured for distributed execution. Preserve
// a non-nil zero-length slice as an empty BLOB rather than turning it into
// SQL NULL; nil is reserved for rows written before migration 0040.
func rawInputArg(input []byte) any {
	if input == nil {
		return nil
	}
	out := make([]byte, len(input))
	copy(out, input)
	return out
}

// nullable converts an empty string to a SQL NULL.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
