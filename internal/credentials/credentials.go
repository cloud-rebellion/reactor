// Package credentials owns the SQL helpers for the credentials + audit
// tables. Separate from the workflow journal because credentials are
// orthogonal to workflow runs and have their own lifecycle (rotation,
// audit, ACL).
//
// The vault.Store handles the encrypted blob; this package holds the
// metadata (provider, rotation interval, last-rotated, targets) plus
// the append-only audit log.
package credentials

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Engine reports the SQL dialect; the repo uses this to pick the right
// timestamp + jsonb representation. Mirrors journal.Engine.
type Engine string

const (
	EngineSQLite   Engine = "sqlite"
	EnginePostgres Engine = "postgres"
)

// ErrNotFound is returned when a credential id has no matching row.
var ErrNotFound = errors.New("credentials: not found")

// Repo is the queries handle.
type Repo struct {
	db     *sql.DB
	engine Engine
}

// New wraps an open *sql.DB.
func New(db *sql.DB, engine Engine) *Repo {
	return &Repo{db: db, engine: engine}
}

// Credential is the metadata-only view of a row. The encrypted blob is
// owned by vault.Store; metadata is what the rotation engine, dashboard,
// and MCP need.
type Credential struct {
	ID                   string            `json:"id"`
	TenantID             string            `json:"tenant_id"`
	Name                 string            `json:"name"`
	Service              string            `json:"service"`
	Provider             string            `json:"provider"`
	ProviderMeta         map[string]string `json:"provider_meta"`
	RotationPolicy       string            `json:"rotation_policy"`
	AutoRotate           bool              `json:"auto_rotate"`
	RotationIntervalDays int               `json:"rotation_interval_days"`
	LastRotatedAt        time.Time         `json:"last_rotated_at,omitempty"`
	LastRotationError    string            `json:"last_rotation_error,omitempty"`
	RotationTargets      []Target          `json:"rotation_targets"`
	CreatedAt            time.Time         `json:"created_at"`
	UpdatedAt            time.Time         `json:"updated_at"`
}

// Target is one delivery destination for a rotated credential. The
// rotator runs each target sequentially after the new value is encrypted
// + persisted.
type Target struct {
	Kind         string `json:"kind"`      // "webhook"
	URL          string `json:"url"`       // POST URL
	SecretID     string `json:"secret_id"` // vault credential id holding HMAC secret
	KeyName      string `json:"key_name"`  // body key (e.g. SCANNER_SVAR_SECRET)
	GraceSeconds int    `json:"grace_seconds,omitempty"`
}

// TargetKinds are the delivery kinds the rotation runner implements, with the
// operator-facing meaning of the shared URL/KeyName fields (the Target struct is
// uniform; only the semantics differ per kind).
var TargetKinds = []struct {
	Kind, Label, URLHint, KeyNameHint string
	NeedsKeyName, NeedsSecretID       bool
}{
	{"webhook", "Webhook (one POST, receiver swaps atomically)", "POST URL the receiver listens on", "body key the new value arrives under, e.g. SCANNER_SVAR_SECRET", true, true},
	{"reload_endpoint", "Reload endpoint (two-phase: accept, then cut over)", "POST URL the receiver listens on", "body key the new value arrives under", true, true},
	{"file_write", "File write (drop the value on disk)", "absolute file path (must sit under REACTOR_FILE_WRITE_ROOT)", "", false, false},
	{"forgejo_secret", "Forgejo repo/org secret", "Forgejo API base for the repo or org", "secret name to set", true, true},
	{"github_secret", "GitHub Actions secret", "GitHub repo API base", "secret name to set", true, true},
	{"dockyard_vault", "Dockyard vault entry", "vault entry endpoint", "", false, true},
}

// Validate reports whether a target carries the fields its kind requires. It is
// the single source of truth for that rule: the dashboard uses it to reject a
// half-filled form, and the rotation runner uses it before attempting delivery,
// so the two cannot drift into accepting different things.
func (t Target) Validate() error {
	for _, k := range TargetKinds {
		if k.Kind != t.Kind {
			continue
		}
		if t.URL == "" {
			return fmt.Errorf("target %q missing url (%s)", t.Kind, k.URLHint)
		}
		if k.NeedsKeyName && t.KeyName == "" {
			return fmt.Errorf("target %q missing key_name (%s)", t.Kind, k.KeyNameHint)
		}
		if k.NeedsSecretID && t.SecretID == "" {
			return fmt.Errorf("target %q missing secret_id (the vault credential holding the auth secret for this target)", t.Kind)
		}
		if t.GraceSeconds < 0 {
			return fmt.Errorf("target %q grace_seconds must not be negative", t.Kind)
		}
		return nil
	}
	return fmt.Errorf("unsupported target kind %q", t.Kind)
}

// AuditEntry is a single row from credential_audit.
type AuditEntry struct {
	ID              int64           `json:"id"`
	CredentialID    string          `json:"credential_id"`
	Action          string          `json:"action"`
	ActorKind       string          `json:"actor_kind"`
	ActorID         string          `json:"actor_id,omitempty"`
	WorkflowID      string          `json:"workflow_id,omitempty"`
	RunID           string          `json:"run_id,omitempty"`
	StepID          string          `json:"step_id,omitempty"`
	Detail          json.RawMessage `json:"detail"`
	At              time.Time       `json:"at"`
	DetailBytes     int             `json:"-"`
	DetailTruncated bool            `json:"-"`
}

// CreateParams captures the rotation-aware fields the test seed + admin
// CLI pass when registering a credential.
type CreateParams struct {
	ID   string
	Name string
	// TenantID owns the credential. Empty means DefaultTenant.
	//
	// This used to be a hardcoded 'default' STRING LITERAL in the INSERT, not a
	// parameter, so every credential in the system belonged to one tenant no
	// matter what the caller intended. Combined with CreateWorkflow omitting the
	// column, both sides of the cross-tenant grant guard were permanently equal,
	// which made that guard vacuous: it could never fire.
	TenantID     string
	Service      string
	Provider     string
	ProviderMeta map[string]string
	// AllowLocalMint records an explicit operator acknowledgement that a
	// provider which mints values inside Reactor may replace the stored value.
	// It is persisted in provider_meta so scheduled rotations cannot silently
	// perform a destructive local mint after the create request is gone.
	AllowLocalMint       bool
	AutoRotate           bool
	RotationIntervalDays int
	RotationTargets      []Target
}

// DefaultTenant is the tenant a resource lands in when no tenant is specified.
// It matches the schema default, so existing rows and new unscoped writes agree.
const DefaultTenant = "default"

// LocalMintAcknowledgementKey is an internal provider_meta marker. It is
// deliberately namespaced so provider-specific metadata cannot accidentally
// satisfy the rotation safety gate.
const LocalMintAcknowledgementKey = "_reactor_allow_local_mint"

// LocalMintAcknowledged reports whether an operator explicitly approved a
// provider that generates replacement values locally. Callers must still
// verify that the selected provider actually has this capability; this helper
// only answers the acknowledgement half of that policy.
func LocalMintAcknowledged(meta map[string]string) bool {
	return strings.EqualFold(strings.TrimSpace(meta[LocalMintAcknowledgementKey]), "true")
}

// Create inserts a credentials row with rotation metadata. The
// encrypted blob lives in vault.Store; we persist a sentinel here so
// the row's NOT NULL constraint is satisfied. Real deployments populate
// `blob` via vault.Store.Put which encrypts with the master key; tests
// can either go through vault or stash a sentinel.
func (r *Repo) Create(ctx context.Context, p CreateParams) error {
	if p.ID == "" || p.Name == "" {
		return errors.New("credentials: id and name required")
	}
	if p.Provider == "" {
		p.Provider = "manual"
	}
	if p.TenantID == "" {
		p.TenantID = DefaultTenant
	}
	providerMeta := make(map[string]string, len(p.ProviderMeta)+1)
	for k, v := range p.ProviderMeta {
		providerMeta[k] = v
	}
	if p.AllowLocalMint {
		providerMeta[LocalMintAcknowledgementKey] = "true"
	}
	meta := encodeJSON(providerMeta)
	targets := encodeJSON(p.RotationTargets)
	const q = `INSERT INTO credentials
		(id, tenant_id, name, service, blob, metadata,
		 provider, provider_meta, auto_rotate, rotation_interval_days, rotation_targets)
		VALUES ($1, $2, $3, $4, $5, '{}', $6, $7, $8, $9, $10)`
	_, err := r.db.ExecContext(ctx, r.bind(q),
		p.ID, p.TenantID, p.Name, p.Service,
		[]byte("sentinel"),
		p.Provider, meta, r.boolValue(p.AutoRotate), p.RotationIntervalDays, targets,
	)
	if err != nil {
		return fmt.Errorf("credentials: create: %w", err)
	}
	return nil
}

// Get returns a credential row by id.
func (r *Repo) Get(ctx context.Context, id string) (Credential, error) {
	const q = `SELECT id, tenant_id, name, service, provider, provider_meta,
		rotation_policy, auto_rotate, rotation_interval_days,
		last_rotated_at, last_rotation_error, rotation_targets, created_at, updated_at
		FROM credentials WHERE id = $1 AND deleted_at IS NULL`
	row := r.db.QueryRowContext(ctx, r.bind(q), id)
	c, err := r.scanCredential(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Credential{}, ErrNotFound
		}
		return Credential{}, err
	}
	return c, nil
}

// GetMetadataByTenant returns only the small identity/provider projection
// needed by control-plane ownership and compatibility checks. It deliberately
// does not select provider_meta, rotation_targets, or rotation errors: those
// fields can contain provider URLs, vault references, operator notes, and
// arbitrarily large legacy values. The tenant predicate is part of the SQL
// lookup so a cross-tenant id is indistinguishable from a missing credential
// to MCP callers and the oversized columns never cross this read boundary.
func (r *Repo) GetMetadataByTenant(ctx context.Context, id, tenantID string) (Credential, error) {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(tenantID) == "" {
		return Credential{}, ErrNotFound
	}
	const q = `SELECT id, tenant_id, name, service, provider
		FROM credentials WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`
	var c Credential
	if err := r.db.QueryRowContext(ctx, r.bind(q), id, tenantID).
		Scan(&c.ID, &c.TenantID, &c.Name, &c.Service, &c.Provider); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Credential{}, ErrNotFound
		}
		return Credential{}, fmt.Errorf("credentials: get metadata by tenant: %w", err)
	}
	return c, nil
}

// List returns every non-deleted credential, name-sorted for stable CLI output.
func (r *Repo) List(ctx context.Context) ([]Credential, error) {
	const q = `SELECT id, tenant_id, name, service, provider, provider_meta,
		rotation_policy, auto_rotate, rotation_interval_days,
		last_rotated_at, last_rotation_error, rotation_targets, created_at, updated_at
		FROM credentials WHERE deleted_at IS NULL ORDER BY name ASC`
	rows, err := r.db.QueryContext(ctx, r.bind(q))
	if err != nil {
		return nil, fmt.Errorf("credentials: list: %w", err)
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		c, err := r.scanCredential(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListByTenant returns live credential metadata for one tenant. An explicit
// tenant predicate keeps callers such as MCP from turning a metadata list into
// a cross-tenant inventory.
func (r *Repo) ListByTenant(ctx context.Context, tenantID string) ([]Credential, error) {
	if tenantID == "" {
		return nil, errors.New("credentials: tenant required")
	}
	const q = `SELECT id, tenant_id, name, service, provider, provider_meta,
		rotation_policy, auto_rotate, rotation_interval_days,
		last_rotated_at, last_rotation_error, rotation_targets, created_at, updated_at
		FROM credentials WHERE deleted_at IS NULL AND tenant_id = $1 ORDER BY name ASC`
	rows, err := r.db.QueryContext(ctx, r.bind(q), tenantID)
	if err != nil {
		return nil, fmt.Errorf("credentials: list tenant: %w", err)
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		c, err := r.scanCredential(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListByTenantPage returns one bounded tenant-scoped metadata page and a
// lookahead flag. Rotation targets remain available to internal callers but
// are redacted by MCP before crossing the control-plane boundary.
func (r *Repo) ListByTenantPage(ctx context.Context, tenantID string, limit, offset int) ([]Credential, bool, error) {
	if tenantID == "" {
		return nil, false, errors.New("credentials: tenant required")
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		return nil, false, errors.New("credentials: negative offset")
	}
	q := fmt.Sprintf(`SELECT id, tenant_id, name, service, provider, provider_meta,
		rotation_policy, auto_rotate, rotation_interval_days,
		last_rotated_at, last_rotation_error, rotation_targets, created_at, updated_at
		FROM credentials WHERE deleted_at IS NULL AND tenant_id = $1 ORDER BY name ASC LIMIT %d OFFSET %d`, limit+1, offset)
	rows, err := r.db.QueryContext(ctx, r.bind(q), tenantID)
	if err != nil {
		return nil, false, fmt.Errorf("credentials: list tenant page: %w", err)
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		c, err := r.scanCredential(rows.Scan)
		if err != nil {
			return nil, false, err
		}
		out = append(out, c)
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

// ListMetadataByTenantPage returns the projection needed by control-plane
// inventories without selecting provider_meta or rotation_targets. Those JSON
// columns can contain provider URLs, vault references, and operator notes; MCP
// redacts them from its response, so loading them first would still create a
// needless secret-bearing allocation. The rotation error is clipped to a
// short prefix because MCP only needs its stable error code.
func (r *Repo) ListMetadataByTenantPage(ctx context.Context, tenantID string, limit, offset int) ([]Credential, bool, error) {
	if tenantID == "" {
		return nil, false, errors.New("credentials: tenant required")
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		return nil, false, errors.New("credentials: negative offset")
	}
	errorExpr := "substr(last_rotation_error, 1, 512)"
	if r.engine != EngineSQLite {
		errorExpr = "left(last_rotation_error, 512)"
	}
	q := fmt.Sprintf(`SELECT id, tenant_id, name, service, provider,
		rotation_policy, auto_rotate, rotation_interval_days,
		last_rotated_at, %s, created_at, updated_at
		FROM credentials WHERE deleted_at IS NULL AND tenant_id = $1 ORDER BY name ASC LIMIT %d OFFSET %d`, errorExpr, limit+1, offset)
	rows, err := r.db.QueryContext(ctx, r.bind(q), tenantID)
	if err != nil {
		return nil, false, fmt.Errorf("credentials: list metadata tenant page: %w", err)
	}
	defer rows.Close()
	out := make([]Credential, 0, limit)
	for rows.Next() {
		c, err := r.scanCredentialMetadata(rows.Scan)
		if err != nil {
			return nil, false, err
		}
		out = append(out, c)
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

// ListMetadataPage returns one bounded estate-wide metadata page. It is for
// control-plane projections such as the graph builder, where a tenant is not
// known up front. Provider metadata and rotation targets are deliberately
// omitted: those columns may contain vault references, URLs, operator notes,
// or other secret-adjacent values that a topology rebuild does not need.
// Rotation errors are clipped to the same bounded diagnostic projection used
// by ListMetadataByTenantPage.
func (r *Repo) ListMetadataPage(ctx context.Context, limit, offset int) ([]Credential, bool, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		return nil, false, errors.New("credentials: negative offset")
	}
	errorExpr := "substr(last_rotation_error, 1, 512)"
	if r.engine != EngineSQLite {
		errorExpr = "left(last_rotation_error, 512)"
	}
	q := fmt.Sprintf(`SELECT id, tenant_id, name, service, provider,
		rotation_policy, auto_rotate, rotation_interval_days,
		last_rotated_at, %s, created_at, updated_at
		FROM credentials WHERE deleted_at IS NULL
		ORDER BY tenant_id ASC, name ASC, id ASC LIMIT %d OFFSET %d`, errorExpr, limit+1, offset)
	rows, err := r.db.QueryContext(ctx, r.bind(q))
	if err != nil {
		return nil, false, fmt.Errorf("credentials: list metadata page: %w", err)
	}
	defer rows.Close()
	out := make([]Credential, 0, limit)
	for rows.Next() {
		c, err := r.scanCredentialMetadata(rows.Scan)
		if err != nil {
			return nil, false, err
		}
		out = append(out, c)
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

// ListNeedingRotation returns credentials whose auto_rotate is true and
// whose last_rotated_at is past the configured interval (or never). Used
// by the rotation runner's tick loop.
func (r *Repo) ListNeedingRotation(ctx context.Context, now time.Time) ([]Credential, error) {
	const q = `SELECT id, tenant_id, name, service, provider, provider_meta,
		rotation_policy, auto_rotate, rotation_interval_days,
		last_rotated_at, last_rotation_error, rotation_targets, created_at, updated_at
		FROM credentials WHERE deleted_at IS NULL AND auto_rotate = $1`
	rows, err := r.db.QueryContext(ctx, r.bind(q), r.boolValue(true))
	if err != nil {
		return nil, fmt.Errorf("credentials: list rotation: %w", err)
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		c, err := r.scanCredential(rows.Scan)
		if err != nil {
			return nil, err
		}
		// Filter in Go: cross-engine arithmetic on dates is awkward in
		// portable SQL. The list is small enough (< thousands of creds
		// per FF deployment) that this is fine.
		if c.LastRotatedAt.IsZero() {
			out = append(out, c)
			continue
		}
		due := c.LastRotatedAt.Add(time.Duration(c.RotationIntervalDays) * 24 * time.Hour)
		if !due.After(now) {
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

// MarkRotated updates last_rotated_at + clears last_rotation_error.
// ErrAuditRetained is returned by Delete when the credential could only be
// tombstoned, because credential_audit rows reference it and dropping the
// "who touched which secret, when" trail to reclaim an identifier is the wrong
// trade for a security product. The caller should tell the operator that the
// name stays reserved.
var ErrAuditRetained = errors.New("credentials: deleted, but the row is retained because it has audit history")

// Delete removes a credential, preferring a hard delete so its id and name
// become reusable.
//
// The id defaults to the NAME (so a workflow can call vault.MustGet("stripe-key")
// without looking up a random cred_<hex>), which means a surviving row holds
// BOTH identifiers. Freeing only the name would therefore not let an operator
// recreate the credential: the primary key still collides.
//
// A hard delete is refused by credential_audit's ON DELETE-less foreign key once
// any audit row exists, so this deletes what it can and falls back to a
// tombstone, returning ErrAuditRetained to say which happened. The common case
// this exists for, a create that failed between the row write and the vault put,
// has NO audit rows yet and so deletes cleanly, which is what makes that
// previously stuck state recoverable.
func (r *Repo) Delete(ctx context.Context, id string) error {
	var exists string
	err := r.db.QueryRowContext(ctx, r.bind(`SELECT id FROM credentials WHERE id = $1`), id).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("credentials: delete lookup: %w", err)
	}

	var auditRows int
	if err := r.db.QueryRowContext(ctx,
		r.bind(`SELECT COUNT(*) FROM credential_audit WHERE credential_id = $1`), id).Scan(&auditRows); err != nil {
		return fmt.Errorf("credentials: delete audit probe: %w", err)
	}

	if auditRows == 0 {
		if _, err := r.db.ExecContext(ctx, r.bind(`DELETE FROM credentials WHERE id = $1`), id); err != nil {
			return fmt.Errorf("credentials: delete: %w", err)
		}
		return nil
	}

	now := r.formatTime(time.Now().UTC())
	const q = `UPDATE credentials SET deleted_at = $1, updated_at = $2 WHERE id = $3 AND deleted_at IS NULL`
	if _, err := r.db.ExecContext(ctx, r.bind(q), now, now, id); err != nil {
		return fmt.Errorf("credentials: tombstone: %w", err)
	}
	return ErrAuditRetained
}

// SetRotationTargets replaces a credential's delivery targets.
//
// Before this existed, rotation_targets could only be populated by hand-written
// SQL: no repo setter, no caller, no UI, no CLI flag. So every credential an
// operator could create had ZERO targets, and rotation stored the new value and
// delivered it nowhere while the audit trail recorded success. Delivery is the
// product's headline differentiator, so it was the differentiator that was
// unreachable.
//
// Every target is validated before the write, so a malformed one cannot sit in
// the column waiting to fail at rotation time (hours later, in a scheduler tick
// no one is watching).
func (r *Repo) SetRotationTargets(ctx context.Context, id string, targets []Target) error {
	for i, t := range targets {
		if err := t.Validate(); err != nil {
			return fmt.Errorf("credentials: target %d: %w", i+1, err)
		}
	}
	if targets == nil {
		targets = []Target{}
	}
	const q = `UPDATE credentials SET rotation_targets = $1, updated_at = $2 WHERE id = $3`
	res, err := r.db.ExecContext(ctx, r.bind(q), encodeJSON(targets), r.formatTime(time.Now().UTC()), id)
	if err != nil {
		return fmt.Errorf("credentials: set rotation targets: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repo) MarkRotated(ctx context.Context, id string, at time.Time) error {
	const q = `UPDATE credentials
		SET last_rotated_at = $1, last_rotation_error = NULL, updated_at = $2
		WHERE id = $3`
	res, err := r.db.ExecContext(ctx, r.bind(q), r.formatTime(at), r.formatTime(at), id)
	if err != nil {
		return fmt.Errorf("credentials: mark rotated: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordError stamps last_rotation_error so the dashboard / CLI can
// surface "this credential failed last rotation". Successful later
// rotations clear it via MarkRotated.
func (r *Repo) RecordError(ctx context.Context, id, msg string) error {
	const q = `UPDATE credentials SET last_rotation_error = $1, updated_at = $2 WHERE id = $3`
	now := r.formatTime(time.Now().UTC())
	_, err := r.db.ExecContext(ctx, r.bind(q), msg, now, id)
	return err
}

// AppendAudit writes a row to credential_audit. detail is a free-form
// JSON map describing the event (target URL, error text, etc.).
func (r *Repo) AppendAudit(ctx context.Context, e AuditEntry) error {
	if e.CredentialID == "" || e.Action == "" || e.ActorKind == "" {
		return errors.New("credentials: audit credential_id, action, actor_kind required")
	}
	detail := e.Detail
	if len(detail) == 0 {
		detail = json.RawMessage("{}")
	}
	d := outputArg(detail, r.engine)
	const q = `INSERT INTO credential_audit
		(credential_id, action, actor_kind, actor_id, workflow_id, run_id, step_id, detail)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := r.db.ExecContext(ctx, r.bind(q),
		e.CredentialID, e.Action, e.ActorKind,
		nullable(e.ActorID), nullable(e.WorkflowID),
		nullable(e.RunID), nullable(e.StepID), d,
	)
	if err != nil {
		return fmt.Errorf("credentials: audit append: %w", err)
	}
	return nil
}

// ListAudit returns the most recent audit entries for a credential,
// newest first. limit caps the result; 0 means default 50.
func (r *Repo) ListAudit(ctx context.Context, credentialID string, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	return r.ListAuditPage(ctx, credentialID, limit, 0)
}

// ListAuditPage returns a bounded newest-first page for a credential. The MCP
// surface requests one lookahead row so it can expose continuation without a
// count query.
func (r *Repo) ListAuditPage(ctx context.Context, credentialID string, limit, offset int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		return nil, errors.New("credentials: audit offset must be non-negative")
	}
	const q = `SELECT id, credential_id, action, actor_kind, actor_id, workflow_id, run_id, step_id, detail, at
		FROM credential_audit WHERE credential_id = $1 ORDER BY at DESC, id DESC LIMIT $2 OFFSET $3`
	rows, err := r.db.QueryContext(ctx, r.bind(q), credentialID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("credentials: audit list: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var (
			e          AuditEntry
			actorID    sql.NullString
			workflowID sql.NullString
			runID      sql.NullString
			stepID     sql.NullString
			detail     []byte
			at         sql.NullString
		)
		if err := rows.Scan(&e.ID, &e.CredentialID, &e.Action, &e.ActorKind,
			&actorID, &workflowID, &runID, &stepID, &detail, &at); err != nil {
			return nil, fmt.Errorf("credentials: audit scan: %w", err)
		}
		e.ActorID = nullableString(actorID)
		e.WorkflowID = nullableString(workflowID)
		e.RunID = nullableString(runID)
		e.StepID = nullableString(stepID)
		if len(detail) > 0 {
			e.Detail = append(json.RawMessage(nil), detail...)
		} else {
			e.Detail = json.RawMessage("{}")
		}
		if at.Valid {
			if t, err := r.parseTime(at.String); err == nil {
				e.At = t
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListAuditPageBounded is the control-plane projection of the audit log. The
// detail JSON can contain provider URLs, response bodies, or imported legacy
// blobs, so the database returns only a bounded prefix while reporting the
// durable byte count. This keeps an oversized row out of the MCP process even
// when the caller only needs a redacted status view.
func (r *Repo) ListAuditPageBounded(ctx context.Context, credentialID string, limit, offset, maxDetailBytes int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		return nil, errors.New("credentials: audit page limit exceeds 1000")
	}
	if offset < 0 {
		return nil, errors.New("credentials: audit offset must be non-negative")
	}
	if maxDetailBytes <= 0 || maxDetailBytes > 16<<20 {
		return nil, errors.New("credentials: audit detail bound must be between 1 byte and 16 MiB")
	}
	var sizeExpr, valueExpr string
	if r.engine == EnginePostgres {
		sizeExpr = "octet_length(detail::text)"
		valueExpr = fmt.Sprintf("CASE WHEN %s <= %d THEN detail::text ELSE left(detail::text, %d) END", sizeExpr, maxDetailBytes, maxDetailBytes)
	} else {
		sizeExpr = "length(CAST(detail AS BLOB))"
		valueExpr = fmt.Sprintf("CASE WHEN %s <= %d THEN detail ELSE substr(detail, 1, %d) END", sizeExpr, maxDetailBytes, maxDetailBytes)
	}
	q := fmt.Sprintf(`SELECT id, credential_id, action, actor_kind, actor_id, workflow_id, run_id, step_id,
		%s, %s, at FROM credential_audit
		WHERE credential_id = $1 ORDER BY at DESC, id DESC LIMIT %d OFFSET %d`, valueExpr, sizeExpr, limit, offset)
	rows, err := r.db.QueryContext(ctx, r.bind(q), credentialID)
	if err != nil {
		return nil, fmt.Errorf("credentials: bounded audit list: %w", err)
	}
	defer rows.Close()
	out := make([]AuditEntry, 0, limit)
	for rows.Next() {
		var (
			e           AuditEntry
			actorID     sql.NullString
			workflowID  sql.NullString
			runID       sql.NullString
			stepID      sql.NullString
			detail      []byte
			detailBytes sql.NullInt64
			at          sql.NullString
		)
		if err := rows.Scan(&e.ID, &e.CredentialID, &e.Action, &e.ActorKind,
			&actorID, &workflowID, &runID, &stepID, &detail, &detailBytes, &at); err != nil {
			return nil, fmt.Errorf("credentials: bounded audit scan: %w", err)
		}
		e.ActorID = nullableString(actorID)
		e.WorkflowID = nullableString(workflowID)
		e.RunID = nullableString(runID)
		e.StepID = nullableString(stepID)
		if len(detail) > 0 {
			e.Detail = append(json.RawMessage(nil), detail...)
		} else {
			e.Detail = json.RawMessage("{}")
		}
		if detailBytes.Valid && detailBytes.Int64 >= 0 {
			e.DetailBytes = int(detailBytes.Int64)
			e.DetailTruncated = e.DetailBytes > len(detail)
		}
		if at.Valid {
			if t, err := r.parseTime(at.String); err == nil {
				e.At = t
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// scanCredential is shared by Get / List / ListNeedingRotation.
func (r *Repo) scanCredential(scan func(...any) error) (Credential, error) {
	var (
		c            Credential
		tenantID     sql.NullString
		providerMeta []byte
		policy       sql.NullString
		autoRotate   any
		intervalDays sql.NullInt64
		lastRotated  sql.NullString
		lastErr      sql.NullString
		targets      []byte
		createdAt    sql.NullString
		updatedAt    sql.NullString
	)
	if err := scan(&c.ID, &tenantID, &c.Name, &c.Service, &c.Provider, &providerMeta,
		&policy, &autoRotate, &intervalDays, &lastRotated, &lastErr, &targets, &createdAt, &updatedAt); err != nil {
		return Credential{}, err
	}
	c.TenantID = nullableString(tenantID)
	c.RotationPolicy = nullableString(policy)
	c.AutoRotate = parseBool(autoRotate)
	c.RotationIntervalDays = int(intervalDays.Int64)
	c.LastRotationError = nullableString(lastErr)
	c.ProviderMeta = decodeStringMap(providerMeta)
	c.RotationTargets = decodeTargets(targets)
	if lastRotated.Valid {
		if t, err := r.parseTime(lastRotated.String); err == nil {
			c.LastRotatedAt = t
		}
	}
	if createdAt.Valid {
		if t, err := r.parseTime(createdAt.String); err == nil {
			c.CreatedAt = t
		}
	}
	if updatedAt.Valid {
		if t, err := r.parseTime(updatedAt.String); err == nil {
			c.UpdatedAt = t
		}
	}
	return c, nil
}

func (r *Repo) scanCredentialMetadata(scan func(...any) error) (Credential, error) {
	var (
		c            Credential
		tenantID     sql.NullString
		policy       sql.NullString
		autoRotate   any
		intervalDays sql.NullInt64
		lastRotated  sql.NullString
		lastErr      sql.NullString
		createdAt    sql.NullString
		updatedAt    sql.NullString
	)
	if err := scan(&c.ID, &tenantID, &c.Name, &c.Service, &c.Provider,
		&policy, &autoRotate, &intervalDays, &lastRotated, &lastErr, &createdAt, &updatedAt); err != nil {
		return Credential{}, err
	}
	c.TenantID = nullableString(tenantID)
	c.RotationPolicy = nullableString(policy)
	c.AutoRotate = parseBool(autoRotate)
	c.RotationIntervalDays = int(intervalDays.Int64)
	c.LastRotationError = nullableString(lastErr)
	if lastRotated.Valid {
		if t, err := r.parseTime(lastRotated.String); err == nil {
			c.LastRotatedAt = t
		}
	}
	if createdAt.Valid {
		if t, err := r.parseTime(createdAt.String); err == nil {
			c.CreatedAt = t
		}
	}
	if updatedAt.Valid {
		if t, err := r.parseTime(updatedAt.String); err == nil {
			c.UpdatedAt = t
		}
	}
	return c, nil
}

// NewID generates an opaque credential id with a "cred_" prefix.
func NewID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("credentials: id: %w", err)
	}
	return "cred_" + hex.EncodeToString(b), nil
}

// --- internal helpers ---

func (r *Repo) bind(q string) string {
	if r.engine != EngineSQLite {
		return q
	}
	out := make([]byte, 0, len(q))
	for i := 0; i < len(q); i++ {
		if q[i] == '$' && i+1 < len(q) && q[i+1] >= '0' && q[i+1] <= '9' {
			out = append(out, '?')
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

func (r *Repo) formatTime(t time.Time) any {
	if r.engine == EngineSQLite {
		return t.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return t.UTC()
}

func (r *Repo) parseTime(s string) (time.Time, error) {
	for _, layout := range []string{
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("credentials: unparseable time %q", s)
}

func (r *Repo) boolValue(b bool) any {
	if r.engine == EngineSQLite {
		if b {
			return 1
		}
		return 0
	}
	return b
}

func parseBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int64:
		return x != 0
	case int:
		return x != 0
	case []byte:
		return len(x) == 1 && x[0] == 't'
	case string:
		return x == "t" || x == "true" || x == "1"
	}
	return false
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableString(s sql.NullString) string {
	if s.Valid {
		return s.String
	}
	return ""
}

func encodeJSON(v any) any {
	if v == nil {
		return "{}"
	}
	b, err := json.Marshal(v)
	if err != nil || len(b) == 0 {
		return "{}"
	}
	return string(b)
}

func decodeStringMap(raw []byte) map[string]string {
	if len(raw) == 0 {
		return map[string]string{}
	}
	m := map[string]string{}
	_ = json.Unmarshal(raw, &m)
	return m
}

func decodeTargets(raw []byte) []Target {
	if len(raw) == 0 {
		return nil
	}
	var out []Target
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

func outputArg(out json.RawMessage, engine Engine) any {
	if len(out) == 0 {
		return nil
	}
	if engine == EngineSQLite {
		return string(out)
	}
	return []byte(out)
}
