package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ErrMCPDispatchIdempotencyConflict means a caller reused an idempotency key
// for a different payload. Returning the original run in that case would make
// an automation appear to have accepted data it never received, while creating
// a second run would defeat the retry contract.
var ErrMCPDispatchIdempotencyConflict = errors.New("journal: MCP dispatch idempotency key reused with a different payload")

// ErrMCPDispatchInputHashMismatch means an internal caller supplied a digest
// that does not describe the exact trigger bytes it is persisting. The public
// dispatcher computes this value itself; keeping the journal check here closes
// the lower-level path as well, so a fabricated receipt cannot bind a key to a
// different input than the run actually receives.
var ErrMCPDispatchInputHashMismatch = errors.New("journal: MCP dispatch payload hash does not match trigger input")

func validateMCPDispatchInputHash(triggerMeta []byte, payloadSHA256 string) error {
	if inputSHA256(triggerMeta) != payloadSHA256 {
		return ErrMCPDispatchInputHashMismatch
	}
	return nil
}

// FindMCPDispatchRun returns the run already recorded for a workflow/key pair.
// The payload digest is checked before the run id is returned, so the key is a
// binding to both the workflow and the exact input data.
func (j *Journal) FindMCPDispatchRun(ctx context.Context, workflowID, key, payloadSHA256 string) (string, error) {
	workflowID = strings.TrimSpace(workflowID)
	key = strings.TrimSpace(key)
	if workflowID == "" || key == "" {
		return "", ErrNotFound
	}
	const q = `SELECT id, dispatch_payload_sha256
		FROM runs WHERE workflow_id = $1 AND dispatch_idempotency_key = $2 LIMIT 1`
	var runID, recordedHash string
	err := j.db.QueryRowContext(ctx, j.bind(q), workflowID, key).Scan(&runID, &recordedHash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("journal: find MCP dispatch idempotency: %w", err)
	}
	if recordedHash != payloadSHA256 {
		return "", ErrMCPDispatchIdempotencyConflict
	}
	return runID, nil
}

// CreateRunPinnedIdempotent is the local execution variant. It atomically
// inserts a pinned run when the key is new, or returns the existing run id
// when an identical request is retried. created reports whether this caller
// owns the new run and therefore may start its supervisor.
func (j *Journal) CreateRunPinnedIdempotent(ctx context.Context, runID, workflowID, triggerKind string, triggerMeta []byte, workflowVersion int, artifactSHA256, key, payloadSHA256 string) (id string, created bool, err error) {
	if workflowVersion <= 0 || !validArtifactSHA256(artifactSHA256) {
		return "", false, fmt.Errorf("journal: create idempotent pinned run: %w", ErrWorkflowArtifactFence)
	}
	if strings.TrimSpace(key) == "" || strings.TrimSpace(payloadSHA256) == "" {
		return "", false, errors.New("journal: create idempotent pinned run: key and payload hash are required")
	}
	if err := validateMCPDispatchInputHash(triggerMeta, payloadSHA256); err != nil {
		return "", false, err
	}
	now := j.now()
	p, err := j.prepareRunPayload(ctx, j.db, workflowID, runID, triggerMeta)
	if err != nil {
		return "", false, err
	}
	const q = `INSERT INTO runs (id, workflow_id, trigger_kind, trigger_meta, trigger_input, status, started_at, created_at, tenant_id, workflow_version, workflow_artifact_sha256, dispatch_idempotency_key, dispatch_payload_sha256, payload_crypto_version, payload_plaintext_bytes)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT DO NOTHING`
	res, err := j.db.ExecContext(ctx, j.bind(q), runID, workflowID, triggerKind, p.meta, p.input, "running", now, now, p.tenantID, workflowVersion, artifactSHA256, key, payloadSHA256, p.cryptoVersion, p.plaintextBytes)
	if err != nil {
		return "", false, fmt.Errorf("journal: create idempotent pinned run: %w", err)
	}
	if n, rowsErr := res.RowsAffected(); rowsErr == nil && n == 1 {
		return runID, true, nil
	}
	existing, findErr := j.FindMCPDispatchRun(ctx, workflowID, key, payloadSHA256)
	if findErr != nil {
		return "", false, fmt.Errorf("journal: resolve idempotent pinned run: %w", findErr)
	}
	return existing, false, nil
}

// CreateQueuedRunPinnedIdempotent is the distributed-worker counterpart to
// CreateRunPinnedIdempotent. The unique journal index makes concurrent MCP
// retries converge before a second queued row can be created.
func (j *Journal) CreateQueuedRunPinnedIdempotent(ctx context.Context, runID, workflowID, triggerKind string, triggerMeta []byte, workflowVersion int, artifactSHA256, key, payloadSHA256 string) (id string, created bool, err error) {
	if workflowVersion <= 0 || !validArtifactSHA256(artifactSHA256) {
		return "", false, fmt.Errorf("journal: create idempotent queued run: %w", ErrWorkflowArtifactFence)
	}
	if strings.TrimSpace(key) == "" || strings.TrimSpace(payloadSHA256) == "" {
		return "", false, errors.New("journal: create idempotent queued run: key and payload hash are required")
	}
	if err := validateMCPDispatchInputHash(triggerMeta, payloadSHA256); err != nil {
		return "", false, err
	}
	p, err := j.prepareRunPayload(ctx, j.db, workflowID, runID, triggerMeta)
	if err != nil {
		return "", false, err
	}
	const q = `INSERT INTO runs (id, workflow_id, trigger_kind, trigger_meta, trigger_input, status, created_at, tenant_id, workflow_version, workflow_artifact_sha256, dispatch_idempotency_key, dispatch_payload_sha256, payload_crypto_version, payload_plaintext_bytes)
		VALUES ($1, $2, $3, $4, $5, 'queued', $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT DO NOTHING`
	res, err := j.db.ExecContext(ctx, j.bind(q), runID, workflowID, triggerKind, p.meta, p.input, j.now(), p.tenantID, workflowVersion, artifactSHA256, key, payloadSHA256, p.cryptoVersion, p.plaintextBytes)
	if err != nil {
		return "", false, fmt.Errorf("journal: create idempotent queued run: %w", err)
	}
	if n, rowsErr := res.RowsAffected(); rowsErr == nil && n == 1 {
		return runID, true, nil
	}
	existing, findErr := j.FindMCPDispatchRun(ctx, workflowID, key, payloadSHA256)
	if findErr != nil {
		return "", false, fmt.Errorf("journal: resolve idempotent queued run: %w", findErr)
	}
	return existing, false, nil
}

// CreateRunPinnedIdempotentIfEnabled is the live local-dispatch variant. It
// locks the workflow before checking enabled and inserting, while resolving an
// existing idempotency receipt first so a retry remains replayable even after
// an operator pauses the workflow.
func (j *Journal) CreateRunPinnedIdempotentIfEnabled(ctx context.Context, runID, workflowID, triggerKind string, triggerMeta []byte, workflowVersion int, artifactSHA256, key, payloadSHA256 string) (id string, created bool, err error) {
	if workflowVersion <= 0 || !validArtifactSHA256(artifactSHA256) {
		return "", false, fmt.Errorf("journal: create enabled idempotent pinned run: %w", ErrWorkflowArtifactFence)
	}
	if strings.TrimSpace(key) == "" || strings.TrimSpace(payloadSHA256) == "" {
		return "", false, errors.New("journal: create enabled idempotent pinned run: key and payload hash are required")
	}
	if err := validateMCPDispatchInputHash(triggerMeta, payloadSHA256); err != nil {
		return "", false, err
	}
	tx, err := j.beginWorkflowAdmissionTx(ctx, workflowID)
	if err != nil {
		return "", false, fmt.Errorf("journal: begin enabled idempotent pinned run: %w", err)
	}
	defer tx.Rollback()
	var existingID, recordedHash string
	lookupErr := tx.QueryRowContext(ctx, j.bind(`SELECT id, dispatch_payload_sha256 FROM runs WHERE workflow_id = $1 AND dispatch_idempotency_key = $2 LIMIT 1`), workflowID, key).Scan(&existingID, &recordedHash)
	switch {
	case lookupErr == nil:
		if recordedHash != payloadSHA256 {
			return "", false, ErrMCPDispatchIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return "", false, fmt.Errorf("journal: commit existing enabled idempotent pinned run: %w", err)
		}
		return existingID, false, nil
	case !errors.Is(lookupErr, sql.ErrNoRows):
		return "", false, fmt.Errorf("journal: find enabled idempotent pinned run: %w", lookupErr)
	}
	if err := j.requireEnabledWorkflowTx(ctx, tx, workflowID); err != nil {
		return "", false, fmt.Errorf("journal: create enabled idempotent pinned run: %w", err)
	}
	if err := j.checkWorkflowAdmissionTx(ctx, tx, workflowID, false); err != nil {
		return "", false, fmt.Errorf("journal: create enabled idempotent pinned run: %w", err)
	}
	now := j.now()
	p, err := j.prepareRunPayload(ctx, tx, workflowID, runID, triggerMeta)
	if err != nil {
		return "", false, err
	}
	const q = `INSERT INTO runs (id, workflow_id, trigger_kind, trigger_meta, trigger_input, status, started_at, created_at, tenant_id, workflow_version, workflow_artifact_sha256, dispatch_idempotency_key, dispatch_payload_sha256, payload_crypto_version, payload_plaintext_bytes)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT DO NOTHING`
	res, err := tx.ExecContext(ctx, j.bind(q), runID, workflowID, triggerKind, p.meta, p.input, "running", now, now, p.tenantID, workflowVersion, artifactSHA256, key, payloadSHA256, p.cryptoVersion, p.plaintextBytes)
	if err != nil {
		return "", false, fmt.Errorf("journal: create enabled idempotent pinned run: %w", err)
	}
	if n, rowsErr := res.RowsAffected(); rowsErr == nil && n == 1 {
		if err := tx.Commit(); err != nil {
			return "", false, fmt.Errorf("journal: commit enabled idempotent pinned run: %w", err)
		}
		return runID, true, nil
	}
	if err := tx.Commit(); err != nil {
		return "", false, fmt.Errorf("journal: commit enabled idempotent pinned run: %w", err)
	}
	existing, findErr := j.FindMCPDispatchRun(ctx, workflowID, key, payloadSHA256)
	if findErr != nil {
		return "", false, fmt.Errorf("journal: resolve enabled idempotent pinned run: %w", findErr)
	}
	return existing, false, nil
}

// CreateQueuedRunPinnedIdempotentIfEnabled is the distributed-worker
// counterpart to CreateRunPinnedIdempotentIfEnabled.
func (j *Journal) CreateQueuedRunPinnedIdempotentIfEnabled(ctx context.Context, runID, workflowID, triggerKind string, triggerMeta []byte, workflowVersion int, artifactSHA256, key, payloadSHA256 string) (id string, created bool, err error) {
	if workflowVersion <= 0 || !validArtifactSHA256(artifactSHA256) {
		return "", false, fmt.Errorf("journal: create enabled idempotent queued run: %w", ErrWorkflowArtifactFence)
	}
	if strings.TrimSpace(key) == "" || strings.TrimSpace(payloadSHA256) == "" {
		return "", false, errors.New("journal: create enabled idempotent queued run: key and payload hash are required")
	}
	if err := validateMCPDispatchInputHash(triggerMeta, payloadSHA256); err != nil {
		return "", false, err
	}
	tx, err := j.beginWorkflowAdmissionTx(ctx, workflowID)
	if err != nil {
		return "", false, fmt.Errorf("journal: begin enabled idempotent queued run: %w", err)
	}
	defer tx.Rollback()
	var existingID, recordedHash string
	lookupErr := tx.QueryRowContext(ctx, j.bind(`SELECT id, dispatch_payload_sha256 FROM runs WHERE workflow_id = $1 AND dispatch_idempotency_key = $2 LIMIT 1`), workflowID, key).Scan(&existingID, &recordedHash)
	switch {
	case lookupErr == nil:
		if recordedHash != payloadSHA256 {
			return "", false, ErrMCPDispatchIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return "", false, fmt.Errorf("journal: commit existing enabled idempotent queued run: %w", err)
		}
		return existingID, false, nil
	case !errors.Is(lookupErr, sql.ErrNoRows):
		return "", false, fmt.Errorf("journal: find enabled idempotent queued run: %w", lookupErr)
	}
	if err := j.requireEnabledWorkflowTx(ctx, tx, workflowID); err != nil {
		return "", false, fmt.Errorf("journal: create enabled idempotent queued run: %w", err)
	}
	if err := j.checkWorkflowAdmissionTx(ctx, tx, workflowID, true); err != nil {
		return "", false, fmt.Errorf("journal: create enabled idempotent queued run: %w", err)
	}
	p, err := j.prepareRunPayload(ctx, tx, workflowID, runID, triggerMeta)
	if err != nil {
		return "", false, err
	}
	const q = `INSERT INTO runs (id, workflow_id, trigger_kind, trigger_meta, trigger_input, status, created_at, tenant_id, workflow_version, workflow_artifact_sha256, dispatch_idempotency_key, dispatch_payload_sha256, payload_crypto_version, payload_plaintext_bytes)
		VALUES ($1, $2, $3, $4, $5, 'queued', $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT DO NOTHING`
	res, err := tx.ExecContext(ctx, j.bind(q), runID, workflowID, triggerKind, p.meta, p.input, j.now(), p.tenantID, workflowVersion, artifactSHA256, key, payloadSHA256, p.cryptoVersion, p.plaintextBytes)
	if err != nil {
		return "", false, fmt.Errorf("journal: create enabled idempotent queued run: %w", err)
	}
	if n, rowsErr := res.RowsAffected(); rowsErr == nil && n == 1 {
		if err := tx.Commit(); err != nil {
			return "", false, fmt.Errorf("journal: commit enabled idempotent queued run: %w", err)
		}
		return runID, true, nil
	}
	if err := tx.Commit(); err != nil {
		return "", false, fmt.Errorf("journal: commit enabled idempotent queued run: %w", err)
	}
	existing, findErr := j.FindMCPDispatchRun(ctx, workflowID, key, payloadSHA256)
	if findErr != nil {
		return "", false, fmt.Errorf("journal: resolve enabled idempotent queued run: %w", findErr)
	}
	return existing, false, nil
}
