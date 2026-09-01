package journal

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// WorkflowVersion is one row of workflow_versions. The current pointer
// (highest version) mirrors the workflows row's code_hash + sdk_version +
// dag_json so the legacy `reactor_get_workflow` path keeps working.
// Historical versions live here for audit + future "freeze runs to v3"
// enforcement.
type WorkflowVersion struct {
	WorkflowID string `json:"workflow_id"`
	Version    int    `json:"version"`
	SDKVersion string `json:"sdk_version"`
	CodeHash   string `json:"code_hash"`
	// ArtifactSHA256 identifies the immutable executable stored by the file
	// registry. It is deliberately separate from CodeHash, which is the short
	// source hash shown in authoring/audit views.
	ArtifactSHA256 string    `json:"artifact_sha256,omitempty"`
	DAG            []byte    `json:"dag_json"`
	CreatedAt      time.Time `json:"created_at"`
}

// ErrWorkflowArtifactFence means Reactor could not prove that a run resolves
// to the exact immutable executable selected at dispatch. Callers must fail
// closed before invoking a binary path.
var ErrWorkflowArtifactFence = errors.New("journal: workflow artifact fence")

// WorkflowArtifactFenceError carries only non-secret execution identifiers so
// it is safe to persist in the run log and surface to an operator.
type WorkflowArtifactFenceError struct {
	WorkflowID    string
	Version       int
	PinnedDigest  string
	VersionDigest string
	Reason        string
}

func (e *WorkflowArtifactFenceError) Error() string {
	return fmt.Sprintf("%v: workflow=%s version=%d reason=%s", ErrWorkflowArtifactFence, e.WorkflowID, e.Version, e.Reason)
}

func (e *WorkflowArtifactFenceError) Unwrap() error { return ErrWorkflowArtifactFence }

// RecordWorkflowVersion appends a new version row for the given workflow
// id. Returns the new version number (starts at 1, increments by 1 per
// call). Used by CreateWorkflow on first insert and by the future
// re-register path on every subsequent register.
func (j *Journal) RecordWorkflowVersion(ctx context.Context, workflowID, sdkVersion, codeHash string, dag json.RawMessage) (int, error) {
	return j.RecordWorkflowVersionWithArtifact(ctx, workflowID, sdkVersion, codeHash, "", dag)
}

// RecordWorkflowVersionWithArtifact appends a version and binds it to the
// immutable executable digest published by the registry. An empty digest is
// accepted only for legacy metadata-only registration; such a version cannot
// execute through the production dispatcher until rebuilt with an artifact.
func (j *Journal) RecordWorkflowVersionWithArtifact(ctx context.Context, workflowID, sdkVersion, codeHash, artifactSHA256 string, dag json.RawMessage) (int, error) {
	if workflowID == "" {
		return 0, errors.New("journal: record workflow version: workflow_id required")
	}
	if artifactSHA256 != "" && !validArtifactSHA256(artifactSHA256) {
		return 0, errors.New("journal: record workflow version: invalid artifact sha256")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("journal: begin workflow version: %w", err)
	}
	defer tx.Rollback()
	// Serialize version allocation per workflow. PostgreSQL uses a row lock;
	// SQLite's harmless UPDATE acquires its single-writer lock before MAX+1.
	if j.engine == EnginePostgres {
		var lockedID string
		if err := tx.QueryRowContext(ctx, `SELECT id FROM workflows WHERE id = $1 FOR UPDATE`, workflowID).Scan(&lockedID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return 0, ErrNotFound
			}
			return 0, fmt.Errorf("journal: lock workflow version: %w", err)
		}
	} else {
		res, err := tx.ExecContext(ctx, j.bind(`UPDATE workflows SET updated_at = updated_at WHERE id = $1`), workflowID)
		if err != nil {
			return 0, fmt.Errorf("journal: lock workflow version: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return 0, ErrNotFound
		}
	}
	var current int
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COALESCE(MAX(version), 0) FROM workflow_versions WHERE workflow_id = $1`), workflowID).Scan(&current); err != nil {
		return 0, fmt.Errorf("journal: allocate workflow version: %w", err)
	}
	next := current + 1
	dg := outputArg(dag, j.engine)
	const q = `INSERT INTO workflow_versions
		(workflow_id, version, sdk_version, code_hash, artifact_sha256, dag_json, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	if _, err := tx.ExecContext(ctx, j.bind(q),
		workflowID, next, sdkVersion, codeHash, nullIfEmpty(artifactSHA256), dg, j.now()); err != nil {
		return 0, fmt.Errorf("journal: insert workflow version: %w", err)
	}
	const updateCurrent = `UPDATE workflows
		SET sdk_version = $1, code_hash = $2, dag_json = $3, updated_at = $4
		WHERE id = $5`
	if _, err := tx.ExecContext(ctx, j.bind(updateCurrent), sdkVersion, codeHash, dg, j.now(), workflowID); err != nil {
		return 0, fmt.Errorf("journal: update current workflow version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("journal: commit workflow version: %w", err)
	}
	return next, nil
}

// CurrentWorkflowVersionRecord returns the current version metadata including
// its immutable artifact identity. ErrNotFound means no version row exists.
func (j *Journal) CurrentWorkflowVersionRecord(ctx context.Context, workflowID string) (WorkflowVersion, error) {
	const q = `SELECT workflow_id, version, sdk_version, code_hash, artifact_sha256, dag_json, created_at
		FROM workflow_versions WHERE workflow_id = $1 ORDER BY version DESC LIMIT 1`
	return j.scanWorkflowVersion(j.db.QueryRowContext(ctx, j.bind(q), workflowID))
}

// WorkflowVersionAt returns one historical version for an execution fence.
func (j *Journal) WorkflowVersionAt(ctx context.Context, workflowID string, version int) (WorkflowVersion, error) {
	const q = `SELECT workflow_id, version, sdk_version, code_hash, artifact_sha256, dag_json, created_at
		FROM workflow_versions WHERE workflow_id = $1 AND version = $2`
	return j.scanWorkflowVersion(j.db.QueryRowContext(ctx, j.bind(q), workflowID, version))
}

func (j *Journal) scanWorkflowVersion(row *sql.Row) (WorkflowVersion, error) {
	var (
		v        WorkflowVersion
		artifact sql.NullString
		dag      []byte
		created  sql.NullString
	)
	if err := row.Scan(&v.WorkflowID, &v.Version, &v.SDKVersion, &v.CodeHash, &artifact, &dag, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return WorkflowVersion{}, ErrNotFound
		}
		return WorkflowVersion{}, fmt.Errorf("journal: scan workflow version: %w", err)
	}
	v.ArtifactSHA256 = artifact.String
	v.DAG = dag
	if created.Valid {
		if t, err := j.parseTime(created.String); err == nil {
			v.CreatedAt = t
		}
	}
	return v, nil
}

// CurrentWorkflowVersion returns the highest version number recorded
// for the workflow id, or (0, nil) if no version rows exist (which
// happens on fresh installs that registered workflows before 0008
// migrated; CreateWorkflow auto-fills the first row going forward).
func (j *Journal) CurrentWorkflowVersion(ctx context.Context, workflowID string) (int, error) {
	const q = `SELECT COALESCE(MAX(version), 0) FROM workflow_versions WHERE workflow_id = $1`
	var v int
	if err := j.db.QueryRowContext(ctx, j.bind(q), workflowID).Scan(&v); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("journal: current workflow version: %w", err)
	}
	return v, nil
}

// ListWorkflowVersions returns every recorded version for a workflow,
// newest first. Used by the dashboard to render a version timeline on
// the workflow detail page.
func (j *Journal) ListWorkflowVersions(ctx context.Context, workflowID string) ([]WorkflowVersion, error) {
	const q = `SELECT workflow_id, version, sdk_version, code_hash, artifact_sha256, dag_json, created_at
		FROM workflow_versions WHERE workflow_id = $1 ORDER BY version DESC`
	rows, err := j.db.QueryContext(ctx, j.bind(q), workflowID)
	if err != nil {
		return nil, fmt.Errorf("journal: list workflow versions: %w", err)
	}
	defer rows.Close()
	var out []WorkflowVersion
	for rows.Next() {
		var (
			v        WorkflowVersion
			artifact sql.NullString
			dag      []byte
			created  sql.NullString
		)
		if err := rows.Scan(&v.WorkflowID, &v.Version, &v.SDKVersion, &v.CodeHash, &artifact, &dag, &created); err != nil {
			return nil, fmt.Errorf("journal: scan workflow version: %w", err)
		}
		v.ArtifactSHA256 = artifact.String
		v.DAG = dag
		if created.Valid {
			if t, err := j.parseTime(created.String); err == nil {
				v.CreatedAt = t
			}
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ValidateRunWorkflowArtifact verifies the three-way binding between a run,
// its historical workflow version, and the immutable executable digest. It
// never inspects the mutable current version; a queued v1 remains allowed after
// v2 is registered, provided v1's content-addressed artifact still exists.
func (j *Journal) ValidateRunWorkflowArtifact(ctx context.Context, run RunInfo) (WorkflowVersion, error) {
	if run.WorkflowVersion <= 0 {
		return WorkflowVersion{}, &WorkflowArtifactFenceError{
			WorkflowID: run.WorkflowID, Version: run.WorkflowVersion, Reason: "run has no pinned workflow version",
		}
	}
	if !validArtifactSHA256(run.WorkflowArtifactSHA256) {
		return WorkflowVersion{}, &WorkflowArtifactFenceError{
			WorkflowID: run.WorkflowID, Version: run.WorkflowVersion, Reason: "run has no valid immutable artifact pin",
		}
	}
	v, err := j.WorkflowVersionAt(ctx, run.WorkflowID, run.WorkflowVersion)
	if errors.Is(err, ErrNotFound) {
		return WorkflowVersion{}, &WorkflowArtifactFenceError{
			WorkflowID: run.WorkflowID, Version: run.WorkflowVersion, PinnedDigest: run.WorkflowArtifactSHA256,
			Reason: "pinned workflow version no longer exists",
		}
	}
	if err != nil {
		return WorkflowVersion{}, err
	}
	if !validArtifactSHA256(v.ArtifactSHA256) {
		return WorkflowVersion{}, &WorkflowArtifactFenceError{
			WorkflowID: run.WorkflowID, Version: run.WorkflowVersion, PinnedDigest: run.WorkflowArtifactSHA256,
			Reason: "workflow version has no valid immutable artifact",
		}
	}
	if v.ArtifactSHA256 != run.WorkflowArtifactSHA256 {
		return WorkflowVersion{}, &WorkflowArtifactFenceError{
			WorkflowID: run.WorkflowID, Version: run.WorkflowVersion, PinnedDigest: run.WorkflowArtifactSHA256,
			VersionDigest: v.ArtifactSHA256, Reason: "run artifact does not match workflow version",
		}
	}
	return v, nil
}

func validArtifactSHA256(v string) bool {
	if len(v) != 64 {
		return false
	}
	b, err := hex.DecodeString(v)
	return err == nil && hex.EncodeToString(b) == v
}

func nullIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// SetRunWorkflowVersion records the workflow version this run was
// dispatched against. Called by the dispatcher right after CreateRun
// so the run timeline can show "ran against v3" even after v4 lands.
func (j *Journal) SetRunWorkflowVersion(ctx context.Context, runID string, version int) error {
	const q = `UPDATE runs SET workflow_version = $1 WHERE id = $2`
	_, err := j.db.ExecContext(ctx, j.bind(q), version, runID)
	if err != nil {
		return fmt.Errorf("journal: set run workflow version: %w", err)
	}
	return nil
}

// nextWorkflowVersion peeks at the highest existing version for the
// workflow id and returns highest+1. Not atomic against concurrent
// RecordWorkflowVersion callers; the dispatcher + CLI both serialize
// register calls so this is fine for v0.1. v0.2 can move to a
// per-workflow advisory lock if concurrent registers become real.
func (j *Journal) nextWorkflowVersion(ctx context.Context, workflowID string) (int, error) {
	cur, err := j.CurrentWorkflowVersion(ctx, workflowID)
	if err != nil {
		return 0, err
	}
	return cur + 1, nil
}
