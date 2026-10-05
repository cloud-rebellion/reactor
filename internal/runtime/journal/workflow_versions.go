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
	ArtifactSHA256 string `json:"artifact_sha256,omitempty"`
	// SourceManifestSHA256 pins the exact retained full-tree source manifest.
	// Empty means this version predates source-manifest pinning and must not
	// inherit a newer version's visual proof policy.
	SourceManifestSHA256 string `json:"source_manifest_sha256,omitempty"`
	// SourceProofVersion is 1 for versions present before migration 0056 and
	// 2 for newly authored versions that must have a pinned manifest.
	SourceProofVersion int       `json:"source_proof_version"`
	DAG                []byte    `json:"dag_json"`
	CreatedAt          time.Time `json:"created_at"`
	// DAGBytes and DAGTruncated are populated by bounded control-plane reads.
	// Keep them out of the default JSON shape so internal/dashboard callers that
	// use the historical unbounded methods retain their wire contract.
	DAGBytes     int  `json:"-"`
	DAGTruncated bool `json:"-"`
}

// ErrWorkflowArtifactFence means Reactor could not prove that a run resolves
// to the exact immutable executable selected at dispatch. Callers must fail
// closed before invoking a binary path.
var ErrWorkflowArtifactFence = errors.New("journal: workflow artifact fence")

// ErrWorkflowVersionConflict means an author attempted to append against a
// stale immutable workflow version.
var ErrWorkflowVersionConflict = errors.New("journal: workflow version conflict")

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
func (j *Journal) RecordWorkflowVersionWithArtifact(ctx context.Context, workflowID, sdkVersion, codeHash, artifactSHA256 string, dag json.RawMessage, sourceManifestSHA256 ...string) (int, error) {
	return j.recordWorkflowVersionWithArtifact(ctx, workflowID, sdkVersion, codeHash, artifactSHA256, dag, false, 0, sourceManifestSHA256)
}

// RecordWorkflowVersionWithArtifactExpected appends a version only while the
// workflow's current immutable version still equals expectedVersion. The
// workflow row lock, version comparison, and append share one transaction so
// editor saves cannot silently publish over a newer MCP or CLI revision.
func (j *Journal) RecordWorkflowVersionWithArtifactExpected(ctx context.Context, workflowID, sdkVersion, codeHash, artifactSHA256 string, dag json.RawMessage, expectedVersion int, sourceManifestSHA256 ...string) (int, error) {
	if expectedVersion < 1 {
		return 0, errors.New("journal: expected workflow version must be positive")
	}
	return j.recordWorkflowVersionWithArtifact(ctx, workflowID, sdkVersion, codeHash, artifactSHA256, dag, false, expectedVersion, sourceManifestSHA256)
}

// RecordWorkflowVersionWithArtifactIfDisabled appends an authored version only
// while the workflow is disabled. The enabled check is inside the same
// transaction as version allocation, so an active workflow cannot be changed
// between an MCP preflight and the durable version write.
func (j *Journal) RecordWorkflowVersionWithArtifactIfDisabled(ctx context.Context, workflowID, sdkVersion, codeHash, artifactSHA256 string, dag json.RawMessage, sourceManifestSHA256 ...string) (int, error) {
	return j.recordWorkflowVersionWithArtifact(ctx, workflowID, sdkVersion, codeHash, artifactSHA256, dag, true, 0, sourceManifestSHA256)
}

// RecordWorkflowVersionWithArtifactIfDisabledExpected appends an authored
// version only while the workflow is disabled and while its current version
// still equals expectedVersion. The check is inside the same transaction as
// version allocation, so an AI author cannot overwrite a revision it did not
// review after compiling against stale state.
func (j *Journal) RecordWorkflowVersionWithArtifactIfDisabledExpected(ctx context.Context, workflowID, sdkVersion, codeHash, artifactSHA256 string, dag json.RawMessage, expectedVersion int, sourceManifestSHA256 ...string) (int, error) {
	if expectedVersion < 1 {
		return 0, errors.New("journal: expected workflow version must be positive")
	}
	return j.recordWorkflowVersionWithArtifact(ctx, workflowID, sdkVersion, codeHash, artifactSHA256, dag, true, expectedVersion, sourceManifestSHA256)
}

func (j *Journal) recordWorkflowVersionWithArtifact(ctx context.Context, workflowID, sdkVersion, codeHash, artifactSHA256 string, dag json.RawMessage, requireDisabled bool, expectedVersion int, sourceManifestSHA256 []string) (int, error) {
	if workflowID == "" {
		return 0, errors.New("journal: record workflow version: workflow_id required")
	}
	if artifactSHA256 != "" && !validArtifactSHA256(artifactSHA256) {
		return 0, errors.New("journal: record workflow version: invalid artifact sha256")
	}
	if len(sourceManifestSHA256) > 1 || (len(sourceManifestSHA256) == 1 && !validArtifactSHA256(sourceManifestSHA256[0])) {
		return 0, errors.New("journal: record workflow version: invalid source manifest sha256")
	}
	manifestDigest := ""
	if len(sourceManifestSHA256) == 1 {
		manifestDigest = sourceManifestSHA256[0]
		if artifactSHA256 == "" {
			return 0, errors.New("journal: source manifest pin requires an artifact")
		}
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
	if requireDisabled {
		var enabled any
		if err := tx.QueryRowContext(ctx, j.bind(`SELECT enabled FROM workflows WHERE id = $1`), workflowID).Scan(&enabled); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return 0, ErrNotFound
			}
			return 0, fmt.Errorf("journal: check workflow enabled for version: %w", err)
		}
		if parseBool(enabled) {
			return 0, ErrWorkflowEnabled
		}
	}
	var current int
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COALESCE(MAX(version), 0) FROM workflow_versions WHERE workflow_id = $1`), workflowID).Scan(&current); err != nil {
		return 0, fmt.Errorf("journal: allocate workflow version: %w", err)
	}
	if expectedVersion > 0 && current != expectedVersion {
		return 0, fmt.Errorf("%w: expected version %d, current version %d", ErrWorkflowVersionConflict, expectedVersion, current)
	}
	next := current + 1
	dg := outputArg(dag, j.engine)
	const q = `INSERT INTO workflow_versions
		(workflow_id, version, sdk_version, code_hash, artifact_sha256, source_manifest_sha256, dag_json, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	if _, err := tx.ExecContext(ctx, j.bind(q),
		workflowID, next, sdkVersion, codeHash, nullIfEmpty(artifactSHA256), nullIfEmpty(manifestDigest), dg, j.now()); err != nil {
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

// RollbackWorkflowVersion appends a new current version whose immutable
// artifact and DAG are copied from a historical version. The workflow must be
// disabled so no new dispatch can cross the rollback boundary while it is
// being prepared. Existing runs remain pinned to their original versions.
func (j *Journal) RollbackWorkflowVersion(ctx context.Context, workflowID string, targetVersion int) (WorkflowVersion, error) {
	return j.rollbackWorkflowVersion(ctx, workflowID, targetVersion, 0)
}

// RollbackWorkflowVersionIfCurrent appends a rollback version only when the
// caller's reviewed current version is still current. The workflow row lock,
// version comparison, and append share one transaction.
func (j *Journal) RollbackWorkflowVersionIfCurrent(ctx context.Context, workflowID string, targetVersion, expectedCurrentVersion int) (WorkflowVersion, error) {
	if expectedCurrentVersion < 1 {
		return WorkflowVersion{}, ErrWorkflowVersionConflict
	}
	return j.rollbackWorkflowVersion(ctx, workflowID, targetVersion, expectedCurrentVersion)
}

func (j *Journal) rollbackWorkflowVersion(ctx context.Context, workflowID string, targetVersion, expectedCurrentVersion int) (WorkflowVersion, error) {
	if workflowID == "" || targetVersion <= 0 {
		return WorkflowVersion{}, errors.New("journal: rollback workflow version: invalid arguments")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return WorkflowVersion{}, fmt.Errorf("journal: begin workflow rollback: %w", err)
	}
	defer tx.Rollback()
	var enabled any
	if j.engine == EnginePostgres {
		if err := tx.QueryRowContext(ctx, `SELECT enabled FROM workflows WHERE id = $1 FOR UPDATE`, workflowID).Scan(&enabled); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return WorkflowVersion{}, ErrNotFound
			}
			return WorkflowVersion{}, fmt.Errorf("journal: lock workflow rollback: %w", err)
		}
	} else if expectedCurrentVersion > 0 {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE workflows SET updated_at = updated_at WHERE id = $1`), workflowID); err != nil {
			return WorkflowVersion{}, fmt.Errorf("journal: lock workflow rollback: %w", err)
		}
		if err := tx.QueryRowContext(ctx, j.bind(`SELECT enabled FROM workflows WHERE id = $1`), workflowID).Scan(&enabled); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return WorkflowVersion{}, ErrNotFound
			}
			return WorkflowVersion{}, fmt.Errorf("journal: read workflow rollback state: %w", err)
		}
	} else {
		if err := tx.QueryRowContext(ctx, j.bind(`SELECT enabled FROM workflows WHERE id = $1`), workflowID).Scan(&enabled); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return WorkflowVersion{}, ErrNotFound
			}
			return WorkflowVersion{}, fmt.Errorf("journal: read workflow rollback state: %w", err)
		}
	}
	if parseBool(enabled) {
		return WorkflowVersion{}, fmt.Errorf("%w: disable it before rolling back", ErrWorkflowEnabled)
	}
	var target WorkflowVersion
	var artifact sql.NullString
	var sourceManifest sql.NullString
	var dag []byte
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT sdk_version, code_hash, artifact_sha256, source_manifest_sha256, source_proof_version, dag_json
		FROM workflow_versions WHERE workflow_id = $1 AND version = $2`), workflowID, targetVersion).
		Scan(&target.SDKVersion, &target.CodeHash, &artifact, &sourceManifest, &target.SourceProofVersion, &dag); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return WorkflowVersion{}, ErrNotFound
		}
		return WorkflowVersion{}, fmt.Errorf("journal: read rollback target: %w", err)
	}
	if !artifact.Valid || !validArtifactSHA256(artifact.String) {
		return WorkflowVersion{}, fmt.Errorf("journal: rollback target has no executable artifact")
	}
	target.ArtifactSHA256 = artifact.String
	target.SourceManifestSHA256 = sourceManifest.String
	target.DAG = append([]byte(nil), dag...)
	var current int
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COALESCE(MAX(version), 0) FROM workflow_versions WHERE workflow_id = $1`), workflowID).Scan(&current); err != nil {
		return WorkflowVersion{}, fmt.Errorf("journal: allocate rollback version: %w", err)
	}
	if expectedCurrentVersion > 0 && current != expectedCurrentVersion {
		return WorkflowVersion{}, fmt.Errorf("%w: expected version %d, current version %d", ErrWorkflowVersionConflict, expectedCurrentVersion, current)
	}
	target.WorkflowID = workflowID
	target.Version = current + 1
	target.CreatedAt = time.Now().UTC()
	if _, err := tx.ExecContext(ctx, j.bind(`INSERT INTO workflow_versions
		(workflow_id, version, sdk_version, code_hash, artifact_sha256, source_manifest_sha256, source_proof_version, dag_json, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`), workflowID, target.Version, target.SDKVersion, target.CodeHash, target.ArtifactSHA256, nullIfEmpty(target.SourceManifestSHA256), target.SourceProofVersion, outputArg(target.DAG, j.engine), j.now()); err != nil {
		return WorkflowVersion{}, fmt.Errorf("journal: insert rollback version: %w", err)
	}
	if _, err := tx.ExecContext(ctx, j.bind(`UPDATE workflows SET sdk_version = $1, code_hash = $2, dag_json = $3, updated_at = $4 WHERE id = $5`), target.SDKVersion, target.CodeHash, outputArg(target.DAG, j.engine), j.now(), workflowID); err != nil {
		return WorkflowVersion{}, fmt.Errorf("journal: update rollback workflow: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return WorkflowVersion{}, fmt.Errorf("journal: commit workflow rollback: %w", err)
	}
	return target, nil
}

// CurrentWorkflowVersionRecord returns the current version metadata including
// its immutable artifact identity. ErrNotFound means no version row exists.
func (j *Journal) CurrentWorkflowVersionRecord(ctx context.Context, workflowID string) (WorkflowVersion, error) {
	const q = `SELECT workflow_id, version, sdk_version, code_hash, artifact_sha256, source_manifest_sha256, source_proof_version, dag_json, created_at
		FROM workflow_versions WHERE workflow_id = $1 ORDER BY version DESC LIMIT 1`
	return j.scanWorkflowVersion(j.db.QueryRowContext(ctx, j.bind(q), workflowID))
}

// CurrentWorkflowVersionRecordBounded returns current version metadata while
// allowing the caller to cap the DAG bytes materialized from SQL. A zero cap
// retains only the durable byte count, which is useful for metadata receipts;
// callers that need to validate/render the graph should pass their projection
// budget and fail closed when DAGTruncated is true.
func (j *Journal) CurrentWorkflowVersionRecordBounded(ctx context.Context, workflowID string, maxDAGBytes int) (WorkflowVersion, error) {
	if err := validateWorkflowDAGBound(maxDAGBytes); err != nil {
		return WorkflowVersion{}, err
	}
	q := boundedWorkflowVersionQuery(j.engine, "WHERE workflow_id = $1 ORDER BY version DESC LIMIT 1", maxDAGBytes)
	return j.scanWorkflowVersionBounded(j.db.QueryRowContext(ctx, j.bind(q), workflowID), maxDAGBytes)
}

// WorkflowVersionAt returns one historical version for an execution fence.
func (j *Journal) WorkflowVersionAt(ctx context.Context, workflowID string, version int) (WorkflowVersion, error) {
	const q = `SELECT workflow_id, version, sdk_version, code_hash, artifact_sha256, source_manifest_sha256, source_proof_version, dag_json, created_at
		FROM workflow_versions WHERE workflow_id = $1 AND version = $2`
	return j.scanWorkflowVersion(j.db.QueryRowContext(ctx, j.bind(q), workflowID, version))
}

// WorkflowVersionAtBounded is the bounded control-plane counterpart to
// WorkflowVersionAt. It preserves the exact version/artifact identity while
// avoiding a full legacy DAG allocation when the caller only needs proof
// metadata or a capped review graph.
func (j *Journal) WorkflowVersionAtBounded(ctx context.Context, workflowID string, version, maxDAGBytes int) (WorkflowVersion, error) {
	if err := validateWorkflowDAGBound(maxDAGBytes); err != nil {
		return WorkflowVersion{}, err
	}
	q := boundedWorkflowVersionQuery(j.engine, "WHERE workflow_id = $1 AND version = $2", maxDAGBytes)
	return j.scanWorkflowVersionBounded(j.db.QueryRowContext(ctx, j.bind(q), workflowID, version), maxDAGBytes)
}

func (j *Journal) scanWorkflowVersion(row *sql.Row) (WorkflowVersion, error) {
	var (
		v              WorkflowVersion
		artifact       sql.NullString
		sourceManifest sql.NullString
		dag            []byte
		created        sql.NullString
	)
	if err := row.Scan(&v.WorkflowID, &v.Version, &v.SDKVersion, &v.CodeHash, &artifact, &sourceManifest, &v.SourceProofVersion, &dag, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return WorkflowVersion{}, ErrNotFound
		}
		return WorkflowVersion{}, fmt.Errorf("journal: scan workflow version: %w", err)
	}
	v.ArtifactSHA256 = artifact.String
	v.SourceManifestSHA256 = sourceManifest.String
	v.DAG = dag
	v.DAGBytes = len(dag)
	if created.Valid {
		if t, err := j.parseTime(created.String); err == nil {
			v.CreatedAt = t
		}
	}
	return v, nil
}

func validateWorkflowDAGBound(maxDAGBytes int) error {
	if maxDAGBytes < 0 || maxDAGBytes > 64<<20 {
		return fmt.Errorf("journal: workflow DAG bound must be between 0 and 64 MiB")
	}
	return nil
}

// boundedWorkflowVersionQuery selects a version row with a durable DAG byte
// count and only returns dag_json when it fits maxDAGBytes. The expression is
// deliberately dialect-specific because SQLite and PostgreSQL count JSON/text
// bytes differently; callers must not rely on a post-Scan slice bound.
func boundedWorkflowVersionQuery(engine Engine, predicate string, maxDAGBytes int) string {
	var sizeExpr, valueExpr string
	if engine == EnginePostgres {
		sizeExpr = "COALESCE(octet_length(dag_json::text), 0)"
		valueExpr = fmt.Sprintf("CASE WHEN %s <= %d THEN dag_json ELSE NULL END", sizeExpr, maxDAGBytes)
	} else {
		sizeExpr = "COALESCE(length(CAST(dag_json AS BLOB)), 0)"
		valueExpr = fmt.Sprintf("CASE WHEN %s <= %d THEN dag_json ELSE NULL END", sizeExpr, maxDAGBytes)
	}
	return fmt.Sprintf(`SELECT workflow_id, version, sdk_version, code_hash, artifact_sha256, source_manifest_sha256, source_proof_version,
		%s, created_at, %s AS dag_bytes FROM workflow_versions %s`, valueExpr, sizeExpr, predicate)
}

func (j *Journal) scanWorkflowVersionBounded(row *sql.Row, maxDAGBytes int) (WorkflowVersion, error) {
	var (
		v              WorkflowVersion
		artifact       sql.NullString
		sourceManifest sql.NullString
		dag            []byte
		dagBytes       int64
		created        sql.NullString
	)
	if err := row.Scan(&v.WorkflowID, &v.Version, &v.SDKVersion, &v.CodeHash, &artifact, &sourceManifest, &v.SourceProofVersion, &dag, &created, &dagBytes); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return WorkflowVersion{}, ErrNotFound
		}
		return WorkflowVersion{}, fmt.Errorf("journal: scan bounded workflow version: %w", err)
	}
	v.ArtifactSHA256 = artifact.String
	v.SourceManifestSHA256 = sourceManifest.String
	v.DAG = dag
	if dagBytes < 0 || dagBytes > int64(^uint(0)>>1) {
		return WorkflowVersion{}, fmt.Errorf("journal: workflow DAG byte count out of range")
	}
	v.DAGBytes = int(dagBytes)
	v.DAGTruncated = v.DAGBytes > maxDAGBytes
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
	const q = `SELECT workflow_id, version, sdk_version, code_hash, artifact_sha256, source_manifest_sha256, source_proof_version, dag_json, created_at
		FROM workflow_versions WHERE workflow_id = $1 ORDER BY version DESC`
	rows, err := j.db.QueryContext(ctx, j.bind(q), workflowID)
	if err != nil {
		return nil, fmt.Errorf("journal: list workflow versions: %w", err)
	}
	defer rows.Close()
	var out []WorkflowVersion
	for rows.Next() {
		var (
			v              WorkflowVersion
			artifact       sql.NullString
			sourceManifest sql.NullString
			dag            []byte
			created        sql.NullString
		)
		if err := rows.Scan(&v.WorkflowID, &v.Version, &v.SDKVersion, &v.CodeHash, &artifact, &sourceManifest, &v.SourceProofVersion, &dag, &created); err != nil {
			return nil, fmt.Errorf("journal: scan workflow version: %w", err)
		}
		v.ArtifactSHA256 = artifact.String
		v.SourceManifestSHA256 = sourceManifest.String
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

// ListWorkflowVersionsPage returns one bounded newest-first version page and
// a lookahead flag. The unpaged ListWorkflowVersions API remains for the
// dashboard timeline, while external control-plane callers should use this
// method to keep responses bounded.
func (j *Journal) ListWorkflowVersionsPage(ctx context.Context, workflowID string, limit, offset int) ([]WorkflowVersion, bool, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		return nil, false, fmt.Errorf("journal: list workflow versions: negative offset")
	}
	fetch := limit + 1
	q := fmt.Sprintf(`SELECT workflow_id, version, sdk_version, code_hash, artifact_sha256, source_manifest_sha256, source_proof_version, dag_json, created_at
		FROM workflow_versions WHERE workflow_id = $1 ORDER BY version DESC LIMIT %d OFFSET %d`, fetch, offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q), workflowID)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list workflow versions page: %w", err)
	}
	defer rows.Close()
	var out []WorkflowVersion
	for rows.Next() {
		var (
			v              WorkflowVersion
			artifact       sql.NullString
			sourceManifest sql.NullString
			dag            []byte
			created        sql.NullString
		)
		if err := rows.Scan(&v.WorkflowID, &v.Version, &v.SDKVersion, &v.CodeHash, &artifact, &sourceManifest, &v.SourceProofVersion, &dag, &created); err != nil {
			return nil, false, fmt.Errorf("journal: scan workflow version page: %w", err)
		}
		v.ArtifactSHA256 = artifact.String
		v.SourceManifestSHA256 = sourceManifest.String
		v.DAG = dag
		if created.Valid {
			if t, err := j.parseTime(created.String); err == nil {
				v.CreatedAt = t
			}
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

// ListWorkflowVersionsPageBounded is the MCP/control-plane projection of the
// immutable version index. It fetches one lookahead row while selecting only
// DAG bytes that fit maxDAGBytes; each returned row retains DAGBytes and
// DAGTruncated so a caller can distinguish an empty graph from omitted legacy
// data.
func (j *Journal) ListWorkflowVersionsPageBounded(ctx context.Context, workflowID string, limit, offset, maxDAGBytes int) ([]WorkflowVersion, bool, error) {
	if err := validateWorkflowDAGBound(maxDAGBytes); err != nil {
		return nil, false, err
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		return nil, false, fmt.Errorf("journal: list workflow versions: page limit exceeds 500")
	}
	if offset < 0 {
		return nil, false, fmt.Errorf("journal: list workflow versions: negative offset")
	}
	fetch := limit + 1
	predicate := fmt.Sprintf("WHERE workflow_id = $1 ORDER BY version DESC LIMIT %d OFFSET %d", fetch, offset)
	q := boundedWorkflowVersionQuery(j.engine, predicate, maxDAGBytes)
	rows, err := j.db.QueryContext(ctx, j.bind(q), workflowID)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list bounded workflow versions page: %w", err)
	}
	defer rows.Close()
	out := make([]WorkflowVersion, 0, fetch)
	for rows.Next() {
		var (
			v              WorkflowVersion
			artifact       sql.NullString
			sourceManifest sql.NullString
			dag            []byte
			dagBytes       int64
			created        sql.NullString
		)
		if err := rows.Scan(&v.WorkflowID, &v.Version, &v.SDKVersion, &v.CodeHash, &artifact, &sourceManifest, &v.SourceProofVersion, &dag, &created, &dagBytes); err != nil {
			return nil, false, fmt.Errorf("journal: scan bounded workflow version page: %w", err)
		}
		v.ArtifactSHA256 = artifact.String
		v.SourceManifestSHA256 = sourceManifest.String
		v.DAG = dag
		if dagBytes < 0 || dagBytes > int64(^uint(0)>>1) {
			return nil, false, fmt.Errorf("journal: workflow DAG byte count out of range")
		}
		v.DAGBytes = int(dagBytes)
		v.DAGTruncated = v.DAGBytes > maxDAGBytes
		if created.Valid {
			if t, err := j.parseTime(created.String); err == nil {
				v.CreatedAt = t
			}
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
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
