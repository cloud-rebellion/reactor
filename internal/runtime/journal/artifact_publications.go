package journal

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ArtifactPublicationPending   = "pending"
	ArtifactPublicationClaimed   = "claimed"
	ArtifactPublicationPublished = "published"
	ArtifactPublicationFailed    = "failed"

	MaxArtifactPublicationAttempts = 10
	maxArtifactPublicationClaim    = 32
	maxArtifactPublicationLease    = 30 * time.Minute
)

// ArtifactPublication is a durable request to publish one exact, immutable
// workflow version. Slug is read from the tenant-owned workflow row, never
// accepted or stored as a caller-selected filesystem destination. ClaimToken
// is returned to an in-process publisher only and is never serialized.
type ArtifactPublication struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	WorkflowID      string     `json:"workflow_id"`
	Slug            string     `json:"slug"`
	Version         int        `json:"version"`
	ArtifactSHA256  string     `json:"artifact_sha256"`
	Status          string     `json:"status"`
	Attempts        int        `json:"attempts"`
	ClaimToken      string     `json:"-"`
	ClaimUntil      *time.Time `json:"claim_until,omitempty"`
	NextAttemptAt   time.Time  `json:"next_attempt_at"`
	RequestedAt     time.Time  `json:"requested_at"`
	PublishedAt     *time.Time `json:"published_at,omitempty"`
	LastFailureCode string     `json:"last_failure_code,omitempty"`
}

var ErrArtifactPublicationClaimLost = errors.New("journal: artifact publication claim lost")
var ErrArtifactPublicationNotFailed = errors.New("journal: artifact publication is not terminal failed")

// EnqueueArtifactPublication checks the tenant, exact version, immutable
// digest, and pinned-source policy in the journal before inserting. An exact
// retry returns the existing receipt, including terminal status; it never
// resets the bounded automatic attempt counter.
func (j *Journal) EnqueueArtifactPublication(ctx context.Context, tenantID, workflowID string, version int, expectedDigest string) (ArtifactPublication, error) {
	if strings.TrimSpace(tenantID) != tenantID || tenantID == "" || len(tenantID) > 256 ||
		strings.TrimSpace(workflowID) != workflowID || workflowID == "" || len(workflowID) > 512 ||
		version < 1 || !validArtifactSHA256(expectedDigest) {
		return ArtifactPublication{}, errors.New("journal: invalid artifact publication identity")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return ArtifactPublication{}, fmt.Errorf("journal: begin artifact publication: %w", err)
	}
	defer tx.Rollback()
	// Registration serializes version allocation on the workflow row. Take
	// that same lock so a review of version N cannot enqueue N after N+1
	// became current. A previously queued N may still finish publishing.
	if j.engine == EnginePostgres {
		var lockedID string
		err = tx.QueryRowContext(ctx, `SELECT id FROM workflows WHERE id = $1 AND tenant_id = $2 FOR UPDATE`, workflowID, tenantID).Scan(&lockedID)
		if errors.Is(err, sql.ErrNoRows) {
			return ArtifactPublication{}, ErrNotFound
		}
		if err != nil {
			return ArtifactPublication{}, fmt.Errorf("journal: lock artifact publication workflow: %w", err)
		}
	} else {
		res, lockErr := tx.ExecContext(ctx, j.bind(`UPDATE workflows SET updated_at = updated_at
			WHERE id = $1 AND tenant_id = $2`), workflowID, tenantID)
		if lockErr != nil {
			return ArtifactPublication{}, fmt.Errorf("journal: lock artifact publication workflow: %w", lockErr)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ArtifactPublication{}, ErrNotFound
		}
	}
	var current int
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COALESCE(MAX(version), 0) FROM workflow_versions
		WHERE workflow_id = $1`), workflowID).Scan(&current); err != nil {
		return ArtifactPublication{}, fmt.Errorf("journal: inspect current artifact publication version: %w", err)
	}
	if current != version {
		return ArtifactPublication{}, ErrWorkflowVersionConflict
	}
	var artifact, manifest sql.NullString
	var proofVersion int
	err = tx.QueryRowContext(ctx, j.bind(`SELECT v.artifact_sha256, v.source_manifest_sha256, v.source_proof_version
		FROM workflow_versions v JOIN workflows w ON w.id = v.workflow_id
		WHERE v.workflow_id = $1 AND v.version = $2 AND w.tenant_id = $3`), workflowID, version, tenantID).
		Scan(&artifact, &manifest, &proofVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return ArtifactPublication{}, ErrNotFound
	}
	if err != nil {
		return ArtifactPublication{}, fmt.Errorf("journal: inspect artifact publication version: %w", err)
	}
	if !artifact.Valid || artifact.String != expectedDigest || proofVersion != 2 ||
		!manifest.Valid || !validArtifactSHA256(manifest.String) {
		return ArtifactPublication{}, ErrWorkflowArtifactFence
	}
	id, err := newArtifactPublicationID()
	if err != nil {
		return ArtifactPublication{}, err
	}
	now := j.formatTime(time.Now().UTC())
	_, err = tx.ExecContext(ctx, j.bind(`INSERT INTO artifact_publications
		(id, tenant_id, workflow_id, version, artifact_sha256, status, attempts, next_attempt_at, requested_at)
		VALUES ($1, $2, $3, $4, $5, 'pending', 0, $6, $7)
		ON CONFLICT (workflow_id, version) DO NOTHING`), id, tenantID, workflowID, version, expectedDigest, now, now)
	if err != nil {
		return ArtifactPublication{}, fmt.Errorf("journal: enqueue artifact publication: %w", err)
	}
	var receiptID string
	err = tx.QueryRowContext(ctx, j.bind(`SELECT id FROM artifact_publications
		WHERE tenant_id = $1 AND workflow_id = $2 AND version = $3 AND artifact_sha256 = $4`),
		tenantID, workflowID, version, expectedDigest).Scan(&receiptID)
	if errors.Is(err, sql.ErrNoRows) {
		return ArtifactPublication{}, ErrWorkflowArtifactFence
	}
	if err != nil {
		return ArtifactPublication{}, fmt.Errorf("journal: inspect artifact publication receipt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ArtifactPublication{}, fmt.Errorf("journal: commit artifact publication: %w", err)
	}
	return j.GetArtifactPublicationForTenant(ctx, receiptID, tenantID)
}

// RequeueFailedArtifactPublication is an explicit recovery action after an
// operator fixes the cause of a terminal publication failure. The same
// receipt ID is reused, but only while its tenant-owned immutable version is
// still current and still has the exact requested digest and v2 source pin.
// Ordinary enqueue retries never reset the automatic attempt budget.
func (j *Journal) RequeueFailedArtifactPublication(ctx context.Context, tenantID, publicationID, expectedDigest string) (ArtifactPublication, error) {
	if strings.TrimSpace(tenantID) != tenantID || tenantID == "" || len(tenantID) > 256 ||
		strings.TrimSpace(publicationID) != publicationID || publicationID == "" || len(publicationID) > 512 ||
		!validArtifactSHA256(expectedDigest) {
		return ArtifactPublication{}, errors.New("journal: invalid artifact publication recovery identity")
	}
	// Read only a tenant-owned receipt to discover the workflow lock key. The
	// row is checked again after locking, so a stale observation cannot reopen
	// a claim or a different workflow version. Do this before BeginTx so SQLite
	// does not retain a read snapshot before acquiring the writer lock.
	var workflowID string
	err := j.db.QueryRowContext(ctx, j.bind(`SELECT p.workflow_id FROM artifact_publications p
		JOIN workflows w ON w.id = p.workflow_id
		WHERE p.id = $1 AND p.tenant_id = $2 AND w.tenant_id = $3`),
		publicationID, tenantID, tenantID).Scan(&workflowID)
	if errors.Is(err, sql.ErrNoRows) {
		return ArtifactPublication{}, ErrNotFound
	}
	if err != nil {
		return ArtifactPublication{}, fmt.Errorf("journal: inspect artifact publication recovery: %w", err)
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return ArtifactPublication{}, fmt.Errorf("journal: begin artifact publication recovery: %w", err)
	}
	defer tx.Rollback()
	// Match the workflow row lock used by version registration and enqueue.
	// SQLite's no-op UPDATE acquires its single-writer lock before checking the
	// current version; PostgreSQL's row lock serializes with an append.
	if j.engine == EnginePostgres {
		var lockedID string
		err = tx.QueryRowContext(ctx, `SELECT id FROM workflows WHERE id = $1 AND tenant_id = $2 FOR UPDATE`, workflowID, tenantID).Scan(&lockedID)
		if errors.Is(err, sql.ErrNoRows) {
			return ArtifactPublication{}, ErrNotFound
		}
		if err != nil {
			return ArtifactPublication{}, fmt.Errorf("journal: lock artifact publication recovery workflow: %w", err)
		}
	} else {
		res, lockErr := tx.ExecContext(ctx, j.bind(`UPDATE workflows SET updated_at = updated_at
			WHERE id = $1 AND tenant_id = $2`), workflowID, tenantID)
		if lockErr != nil {
			return ArtifactPublication{}, fmt.Errorf("journal: lock artifact publication recovery workflow: %w", lockErr)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ArtifactPublication{}, ErrNotFound
		}
	}
	query := `SELECT p.version, p.artifact_sha256, p.status,
		v.artifact_sha256, v.source_manifest_sha256, v.source_proof_version
		FROM artifact_publications p
		JOIN workflow_versions v ON v.workflow_id = p.workflow_id AND v.version = p.version
		JOIN workflows w ON w.id = p.workflow_id
		WHERE p.id = $1 AND p.tenant_id = $2 AND w.tenant_id = $3
			AND p.workflow_id = $4`
	if j.engine == EnginePostgres {
		query += ` FOR UPDATE OF p`
	}
	var version, proofVersion int
	var receiptDigest, status string
	var versionDigest, manifest sql.NullString
	err = tx.QueryRowContext(ctx, j.bind(query), publicationID, tenantID, tenantID, workflowID).
		Scan(&version, &receiptDigest, &status, &versionDigest, &manifest, &proofVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return ArtifactPublication{}, ErrNotFound
	}
	if err != nil {
		return ArtifactPublication{}, fmt.Errorf("journal: inspect locked artifact publication recovery: %w", err)
	}
	if status != ArtifactPublicationFailed {
		return ArtifactPublication{}, ErrArtifactPublicationNotFailed
	}
	var current int
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COALESCE(MAX(version), 0)
		FROM workflow_versions WHERE workflow_id = $1`), workflowID).Scan(&current); err != nil {
		return ArtifactPublication{}, fmt.Errorf("journal: inspect current artifact publication recovery version: %w", err)
	}
	if current != version {
		return ArtifactPublication{}, ErrWorkflowVersionConflict
	}
	if receiptDigest != expectedDigest || !versionDigest.Valid || versionDigest.String != expectedDigest ||
		proofVersion != 2 || !manifest.Valid || !validArtifactSHA256(manifest.String) {
		return ArtifactPublication{}, ErrWorkflowArtifactFence
	}
	now := j.formatTime(time.Now().UTC())
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE artifact_publications
		SET status = 'pending', attempts = 0, claim_token = NULL,
			claim_until = NULL, next_attempt_at = $1, published_at = NULL,
			last_failure_code = NULL
		WHERE id = $2 AND tenant_id = $3 AND workflow_id = $4 AND version = $5
			AND artifact_sha256 = $6 AND status = 'failed'`),
		now, publicationID, tenantID, workflowID, version, expectedDigest)
	if err != nil {
		return ArtifactPublication{}, fmt.Errorf("journal: requeue failed artifact publication: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ArtifactPublication{}, ErrArtifactPublicationNotFailed
	}
	if err := tx.Commit(); err != nil {
		return ArtifactPublication{}, fmt.Errorf("journal: commit artifact publication recovery: %w", err)
	}
	return j.GetArtifactPublicationForTenant(ctx, publicationID, tenantID)
}

func newArtifactPublicationID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("journal: create artifact publication id: %w", err)
	}
	return "apub_" + hex.EncodeToString(raw[:]), nil
}

// ClaimArtifactPublications takes a bounded batch. PostgreSQL uses row locks
// with SKIP LOCKED; an expired lease can be reclaimed. The tenth expired
// attempt becomes terminal instead of staying claimed forever.
func (j *Journal) ClaimArtifactPublications(ctx context.Context, limit int, lease time.Duration) ([]ArtifactPublication, error) {
	if limit < 1 || limit > maxArtifactPublicationClaim {
		return nil, fmt.Errorf("journal: artifact publication claim limit must be 1..%d", maxArtifactPublicationClaim)
	}
	if lease <= 0 || lease > maxArtifactPublicationLease {
		return nil, fmt.Errorf("journal: artifact publication lease must be positive and at most %s", maxArtifactPublicationLease)
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("journal: begin artifact publication claim: %w", err)
	}
	defer tx.Rollback()
	nowTime := time.Now().UTC()
	now := j.formatTime(nowTime)
	if _, err := tx.ExecContext(ctx, j.bind(`UPDATE artifact_publications
		SET status = 'failed', claim_token = NULL, claim_until = NULL,
			last_failure_code = 'lease_expired'
		WHERE status = 'claimed' AND attempts >= $1 AND claim_until <= $2`),
		MaxArtifactPublicationAttempts, now); err != nil {
		return nil, fmt.Errorf("journal: retire exhausted artifact publication claims: %w", err)
	}
	query := `SELECT id FROM artifact_publications
		WHERE attempts < $1 AND
			((status = 'pending' AND next_attempt_at <= $2) OR
			 (status = 'claimed' AND claim_until <= $3))
		ORDER BY requested_at, id LIMIT $4`
	if j.engine == EnginePostgres {
		query += ` FOR UPDATE SKIP LOCKED`
	}
	rows, err := tx.QueryContext(ctx, j.bind(query), MaxArtifactPublicationAttempts, now, now, limit)
	if err != nil {
		return nil, fmt.Errorf("journal: select artifact publications: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, fmt.Errorf("journal: scan artifact publication claim: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("journal: iterate artifact publication claims: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("journal: close artifact publication claims: %w", err)
	}
	until := j.formatTime(nowTime.Add(lease))
	claimed := make([]ArtifactPublication, 0, len(ids))
	for _, id := range ids {
		token, err := newTerminalEffectClaimToken()
		if err != nil {
			return nil, fmt.Errorf("journal: generate artifact publication claim token: %w", err)
		}
		res, err := tx.ExecContext(ctx, j.bind(`UPDATE artifact_publications
			SET status = 'claimed', attempts = attempts + 1, claim_token = $1, claim_until = $2
			WHERE id = $3 AND attempts < $4 AND
				((status = 'pending' AND next_attempt_at <= $5) OR
				 (status = 'claimed' AND claim_until <= $6))`),
			token, until, id, MaxArtifactPublicationAttempts, now, now)
		if err != nil {
			return nil, fmt.Errorf("journal: claim artifact publication: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			continue
		}
		publication, err := j.getArtifactPublication(ctx, tx, id, "")
		if err != nil {
			return nil, err
		}
		publication.ClaimToken = token
		claimed = append(claimed, publication)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("journal: commit artifact publication claims: %w", err)
	}
	return claimed, nil
}

// RenewArtifactPublicationClaim extends only a live claim generation. A late
// publisher cannot resurrect a lease that another process may have reclaimed.
func (j *Journal) RenewArtifactPublicationClaim(ctx context.Context, id, claimToken string, lease time.Duration) error {
	if id == "" || claimToken == "" || lease <= 0 || lease > maxArtifactPublicationLease {
		return ErrArtifactPublicationClaimLost
	}
	nowTime := time.Now().UTC()
	res, err := j.db.ExecContext(ctx, j.bind(`UPDATE artifact_publications SET claim_until = $1
		WHERE id = $2 AND claim_token = $3 AND status = 'claimed' AND claim_until > $4`),
		j.formatTime(nowTime.Add(lease)), id, claimToken, j.formatTime(nowTime))
	if err != nil {
		return fmt.Errorf("journal: renew artifact publication claim: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrArtifactPublicationClaimLost
	}
	return nil
}

// CompleteArtifactPublication acknowledges only the still-live claim that
// checked the destination proof. It does not enable or dispatch the workflow.
func (j *Journal) CompleteArtifactPublication(ctx context.Context, id, claimToken string) error {
	if id == "" || claimToken == "" {
		return ErrArtifactPublicationClaimLost
	}
	now := j.formatTime(time.Now().UTC())
	res, err := j.db.ExecContext(ctx, j.bind(`UPDATE artifact_publications
		SET status = 'published', published_at = $1, claim_token = NULL,
			claim_until = NULL, last_failure_code = NULL
		WHERE id = $2 AND claim_token = $3 AND status = 'claimed' AND claim_until > $4`),
		now, id, claimToken, now)
	if err != nil {
		return fmt.Errorf("journal: complete artifact publication: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrArtifactPublicationClaimLost
	}
	return nil
}

// FailArtifactPublication records only an allowlisted non-secret failure code.
// It schedules a bounded retry, or terminates after the tenth claim. A stale
// publisher cannot release a newer claim.
func (j *Journal) FailArtifactPublication(ctx context.Context, id, claimToken, failureCode string) error {
	if id == "" || claimToken == "" {
		return ErrArtifactPublicationClaimLost
	}
	if !validArtifactPublicationFailureCode(failureCode) {
		return errors.New("journal: invalid artifact publication failure code")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin artifact publication failure: %w", err)
	}
	defer tx.Rollback()
	nowTime := time.Now().UTC()
	now := j.formatTime(nowTime)
	query := `SELECT attempts FROM artifact_publications
		WHERE id = $1 AND claim_token = $2 AND status = 'claimed' AND claim_until > $3`
	if j.engine == EnginePostgres {
		query += ` FOR UPDATE`
	}
	var attempts int
	err = tx.QueryRowContext(ctx, j.bind(query), id, claimToken, now).Scan(&attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrArtifactPublicationClaimLost
	}
	if err != nil {
		return fmt.Errorf("journal: inspect artifact publication claim: %w", err)
	}
	status := ArtifactPublicationPending
	next := nowTime.Add(artifactPublicationBackoff(attempts))
	if attempts >= MaxArtifactPublicationAttempts {
		status = ArtifactPublicationFailed
		next = nowTime
	}
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE artifact_publications
		SET status = $1, claim_token = NULL, claim_until = NULL,
			next_attempt_at = $2, last_failure_code = $3
		WHERE id = $4 AND claim_token = $5 AND status = 'claimed' AND claim_until > $6`),
		status, j.formatTime(next), failureCode, id, claimToken, now)
	if err != nil {
		return fmt.Errorf("journal: fail artifact publication claim: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrArtifactPublicationClaimLost
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit artifact publication failure: %w", err)
	}
	return nil
}

func artifactPublicationBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	if attempts > 8 {
		attempts = 8
	}
	return time.Duration(1<<attempts) * time.Second
}

func validArtifactPublicationFailureCode(code string) bool {
	switch code {
	case "source_unavailable", "source_unverified", "destination_unavailable",
		"destination_mismatch", "copy_failed", "proof_failed",
		"configuration_error", "lease_expired", "unexpected":
		return true
	default:
		return false
	}
}

// GetArtifactPublicationForTenant returns one bounded metadata receipt; it
// never includes the publisher's claim token or a host filesystem path.
func (j *Journal) GetArtifactPublicationForTenant(ctx context.Context, id, tenantID string) (ArtifactPublication, error) {
	if id == "" || tenantID == "" {
		return ArtifactPublication{}, ErrNotFound
	}
	return j.getArtifactPublication(ctx, j.db, id, tenantID)
}

type artifactPublicationQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (j *Journal) getArtifactPublication(ctx context.Context, q artifactPublicationQueryer, id, tenantID string) (ArtifactPublication, error) {
	query := `SELECT p.id, p.tenant_id, p.workflow_id, w.slug, p.version, p.artifact_sha256,
		p.status, p.attempts, p.claim_until, p.next_attempt_at, p.requested_at,
		p.published_at, p.last_failure_code
		FROM artifact_publications p JOIN workflows w ON w.id = p.workflow_id
		WHERE p.id = $1`
	args := []any{id}
	if tenantID != "" {
		query += ` AND p.tenant_id = $2 AND w.tenant_id = $3`
		args = append(args, tenantID, tenantID)
	}
	var publication ArtifactPublication
	var claimUntil, next, requested, published, failure sql.NullString
	err := q.QueryRowContext(ctx, j.bind(query), args...).Scan(
		&publication.ID, &publication.TenantID, &publication.WorkflowID, &publication.Slug,
		&publication.Version, &publication.ArtifactSHA256, &publication.Status,
		&publication.Attempts, &claimUntil, &next, &requested, &published, &failure,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ArtifactPublication{}, ErrNotFound
	}
	if err != nil {
		return ArtifactPublication{}, fmt.Errorf("journal: get artifact publication: %w", err)
	}
	if publication.NextAttemptAt, err = j.parseTime(next.String); err != nil {
		return ArtifactPublication{}, err
	}
	if publication.RequestedAt, err = j.parseTime(requested.String); err != nil {
		return ArtifactPublication{}, err
	}
	if claimUntil.Valid {
		value, parseErr := j.parseTime(claimUntil.String)
		if parseErr != nil {
			return ArtifactPublication{}, parseErr
		}
		publication.ClaimUntil = &value
	}
	if published.Valid {
		value, parseErr := j.parseTime(published.String)
		if parseErr != nil {
			return ArtifactPublication{}, parseErr
		}
		publication.PublishedAt = &value
	}
	publication.LastFailureCode = failure.String
	return publication, nil
}
