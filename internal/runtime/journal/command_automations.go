package journal

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bright-interaction/reactor/internal/commandautomations"
)

// CommandAutomation is the safe, declarative command-automation record. It is
// not executable by inspection alone: execution requires the separate
// sandboxed runner, immutable receipt, and explicit manual or schedule gate.
type CommandAutomation struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Target         string    `json:"target"`
	Enabled        bool      `json:"enabled"`
	CurrentVersion int       `json:"current_version"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// CommandAutomationVersion stores the exact normalized declarative definition
// an operator reviewed. DefinitionJSON is untrusted data at MCP boundaries.
type CommandAutomationVersion struct {
	AutomationID   string          `json:"automation_id"`
	Version        int             `json:"version"`
	DefinitionJSON json.RawMessage `json:"definition_json"`
	CreatedBy      string          `json:"created_by"`
	CreatedAt      time.Time       `json:"created_at"`
}

// CommandAutomationVersionSummary identifies an immutable version without
// returning its command-bearing definition. The digest lets callers detect
// whether a review target changed while keeping the full definition behind
// the explicit get-by-version surface.
type CommandAutomationVersionSummary struct {
	AutomationID     string    `json:"automation_id"`
	Version          int       `json:"version"`
	DefinitionSHA256 string    `json:"definition_sha256"`
	DefinitionBytes  int       `json:"definition_bytes"`
	CreatedBy        string    `json:"created_by"`
	CreatedAt        time.Time `json:"created_at"`
}

var (
	ErrCommandAutomationNameTaken           = errors.New("journal: a command automation with that name already exists")
	ErrCommandAutomationIdempotencyConflict = errors.New("journal: command automation idempotency key reused with a different request")
	ErrCommandAutomationTenant              = ErrNotFound
	ErrCommandAutomationConflict            = errors.New("journal: command automation version changed; read the current plan before revising")
	ErrCommandAutomationStateConflict       = errors.New("journal: command automation enabled state changed; read the current plan before retrying")
	ErrCommandAutomationEnabled             = errors.New("journal: command automation is enabled; disable it before changing or deleting the plan")
	ErrCommandAutomationHasRuns             = errors.New("journal: command automation has durable runs; erase or retain the run history before deleting it")
	ErrCommandAutomationHasTriggers         = errors.New("journal: command automation has trigger bindings; delete its schedules, webhooks, and chains before deleting it")
)

// CreateCommandAutomation creates version 1 atomically. The definition is
// stored as JSON so future fields can be added without a schema migration for
// every declarative step property.
func (j *Journal) CreateCommandAutomation(ctx context.Context, tenantID, id, name, description, target, actor string, definition json.RawMessage) (CommandAutomation, error) {
	created, _, err := j.CreateCommandAutomationWithIdempotency(ctx, tenantID, id, name, description, target, actor, definition, "")
	return created, err
}

// CreateCommandAutomationWithIdempotency creates version 1 atomically and,
// when key is supplied, binds that caller key to the exact request. A retry
// with the same tenant-scoped key and normalized request returns the original
// plan with replay=true; reusing the key for another request is rejected. The
// key is optional so existing journal callers retain the historical name-only
// uniqueness contract.
func (j *Journal) CreateCommandAutomationWithIdempotency(ctx context.Context, tenantID, id, name, description, target, actor string, definition json.RawMessage, key string) (created CommandAutomation, replay bool, err error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	if strings.TrimSpace(id) == "" || strings.TrimSpace(name) == "" {
		return CommandAutomation{}, false, errors.New("journal: command automation id and name are required")
	}
	if !commandautomations.ValidName(name) || len(description) > 4096 || len(target) > 256 {
		return CommandAutomation{}, false, errors.New("journal: invalid command automation metadata")
	}
	if err := commandautomations.SafeText(description + "\n" + target); err != nil {
		return CommandAutomation{}, false, err
	}
	key = strings.TrimSpace(key)
	if key != "" && (len(key) > 200 || strings.IndexFunc(key, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0) {
		return CommandAutomation{}, false, errors.New("journal: command automation idempotency key must be 1..200 bytes without control characters")
	}
	_, normalized, validationErr := commandautomations.Normalize(definition)
	if validationErr != nil {
		return CommandAutomation{}, false, validationErr
	}
	definition = normalized
	idempotencyHash := commandAutomationCreateIdempotencyHash(name, description, target, actor, definition)
	storedDefinition, err := j.prepareCommandDefinition(ctx, j.db, tenantID, id, 1, definition)
	if err != nil {
		return CommandAutomation{}, false, err
	}
	now := j.now()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return CommandAutomation{}, false, fmt.Errorf("journal: begin command automation create: %w", err)
	}
	defer tx.Rollback()
	q := `INSERT INTO command_automations
		(id, tenant_id, name, description, target, enabled, current_version, created_by, created_at, updated_at, idempotency_key, idempotency_hash)
		VALUES ($1,$2,$3,$4,$5,$6,1,$7,$8,$9,$10,$11)
		ON CONFLICT DO NOTHING`
	result, err := tx.ExecContext(ctx, j.bind(q), id, tenantID, name, description, target, j.boolValue(false), actor, now, now, nullable(key), nullable(idempotencyHash))
	if err != nil {
		return CommandAutomation{}, false, fmt.Errorf("journal: create command automation: %w", err)
	}
	rows, rowsErr := result.RowsAffected()
	if rowsErr != nil {
		return CommandAutomation{}, false, fmt.Errorf("journal: create command automation rows affected: %w", rowsErr)
	}
	if rows == 0 {
		if key == "" {
			return CommandAutomation{}, false, ErrCommandAutomationNameTaken
		}
		var existingID, existingHash string
		lookup := `SELECT id, idempotency_hash FROM command_automations WHERE tenant_id = $1 AND idempotency_key = $2`
		if j.engine == EnginePostgres {
			lookup += ` FOR UPDATE`
		}
		if err := tx.QueryRowContext(ctx, j.bind(lookup), tenantID, key).Scan(&existingID, &existingHash); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				// A different plan already owns the requested name. Keep the
				// historical error rather than exposing whether another key exists.
				return CommandAutomation{}, false, ErrCommandAutomationNameTaken
			}
			return CommandAutomation{}, false, fmt.Errorf("journal: read command automation idempotency: %w", err)
		}
		if existingHash == "" || existingHash != idempotencyHash {
			return CommandAutomation{}, false, ErrCommandAutomationIdempotencyConflict
		}
		replayed, err := j.scanCommandAutomation(tx.QueryRowContext(ctx, j.bind(`SELECT id, tenant_id, name, description, target, enabled, current_version, created_by, created_at, updated_at FROM command_automations WHERE tenant_id = $1 AND id = $2`), tenantID, existingID).Scan)
		if err != nil {
			return CommandAutomation{}, false, fmt.Errorf("journal: read command automation idempotent receipt: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return CommandAutomation{}, false, fmt.Errorf("journal: commit command automation idempotent receipt: %w", err)
		}
		return replayed, true, nil
	}
	versionQ := `INSERT INTO command_automation_versions
		(automation_id, version, definition_json, definition_crypto_version, definition_plaintext_bytes, definition_sha256, created_by, created_at)
		VALUES ($1,1,$2,$3,$4,$5,$6,$7)`
	if _, err := tx.ExecContext(ctx, j.bind(versionQ), id, storedDefinition.JSON, storedDefinition.CryptoVersion, storedDefinition.PlaintextBytes, storedDefinition.DefinitionSHA256, actor, now); err != nil {
		return CommandAutomation{}, false, fmt.Errorf("journal: create command automation version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return CommandAutomation{}, false, fmt.Errorf("journal: commit command automation: %w", err)
	}
	createdAt := j.anyTime(now)
	return CommandAutomation{ID: id, TenantID: tenantID, Name: name, Description: description, Target: target, Enabled: false, CurrentVersion: 1, CreatedBy: actor, CreatedAt: createdAt, UpdatedAt: createdAt}, false, nil
}

func commandAutomationCreateIdempotencyHash(name, description, target, actor string, definition json.RawMessage) string {
	payload, _ := json.Marshal(struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Target      string          `json:"target"`
		Actor       string          `json:"actor"`
		Definition  json.RawMessage `json:"definition"`
	}{name, description, target, actor, definition})
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("%x", sum[:])
}

// AppendCommandAutomationVersion appends a version only for the owning,
// disabled plan. Version allocation, the enabled-state check, and the current
// pointer update are one transaction so an active plan cannot change under a
// previously reviewed receipt.
func (j *Journal) AppendCommandAutomationVersion(ctx context.Context, tenantID, id, actor string, expectedVersion int, definition json.RawMessage) (int, error) {
	_, normalized, validationErr := commandautomations.Normalize(definition)
	if validationErr != nil {
		return 0, validationErr
	}
	definition = normalized
	if expectedVersion < 1 {
		return 0, ErrCommandAutomationConflict
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("journal: begin command automation version: %w", err)
	}
	defer tx.Rollback()
	// Take SQLite's write lock before reading the version to avoid a
	// read-to-write transaction upgrade race between competing revisions.
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automations SET current_version = current_version WHERE id = $1 AND tenant_id = $2`), id, tenantID); err != nil {
			return 0, err
		}
	}
	var owner string
	var current int
	var enabled any
	lockQ := `SELECT tenant_id, current_version, enabled FROM command_automations WHERE id = $1`
	if j.engine == EnginePostgres {
		lockQ += ` FOR UPDATE`
	}
	if err := tx.QueryRowContext(ctx, j.bind(lockQ), id).Scan(&owner, &current, &enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("journal: lock command automation: %w", err)
	}
	if owner != tenantID {
		return 0, ErrCommandAutomationTenant
	}
	if parseBool(enabled) {
		return 0, ErrCommandAutomationEnabled
	}
	if current != expectedVersion {
		return 0, ErrCommandAutomationConflict
	}
	next := current + 1
	now := j.now()
	storedDefinition, err := j.prepareCommandDefinition(ctx, tx, tenantID, id, next, definition)
	if err != nil {
		return 0, err
	}
	q := `INSERT INTO command_automation_versions
		(automation_id, version, definition_json, definition_crypto_version, definition_plaintext_bytes, definition_sha256, created_by, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`
	if _, err := tx.ExecContext(ctx, j.bind(q), id, next, storedDefinition.JSON, storedDefinition.CryptoVersion, storedDefinition.PlaintextBytes, storedDefinition.DefinitionSHA256, actor, now); err != nil {
		return 0, fmt.Errorf("journal: append command automation version: %w", err)
	}
	if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automations SET current_version = $1, updated_at = $2 WHERE id = $3`), next, now, id); err != nil {
		return 0, fmt.Errorf("journal: update command automation current version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("journal: commit command automation version: %w", err)
	}
	return next, nil
}

// SetCommandAutomationEnabled toggles one tenant-owned command plan. The
// durable default is disabled; callers that activate a reviewed version
// should prefer SetCommandAutomationEnabledIfStateAndVersion.
func (j *Journal) SetCommandAutomationEnabled(ctx context.Context, tenantID, id string, enabled bool) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	res, err := j.db.ExecContext(ctx, j.bind(`UPDATE command_automations SET enabled = $1, updated_at = $2 WHERE tenant_id = $3 AND id = $4`), j.boolValue(enabled), j.now(), tenantID, id)
	if err != nil {
		return fmt.Errorf("journal: set command automation enabled: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("journal: set command automation enabled rows affected: %w", err)
	} else if n != 1 {
		return ErrNotFound
	}
	return nil
}

// IsCommandAutomationEnabled reports the tenant-scoped activation state of a
// command plan. Missing or foreign plans are indistinguishable.
func (j *Journal) IsCommandAutomationEnabled(ctx context.Context, tenantID, id string) (bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	var raw any
	err := j.db.QueryRowContext(ctx, j.bind(`SELECT enabled FROM command_automations WHERE tenant_id = $1 AND id = $2`), tenantID, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("journal: is command automation enabled: %w", err)
	}
	return parseBool(raw), nil
}

// SetCommandAutomationEnabledIfStateAndVersion toggles a command plan only
// when the caller's tenant-scoped read still matches both the enabled state
// and immutable current version. The row lock and update share one
// transaction, so a concurrent revision or activation cannot turn a stale
// review into a live command plan.
func (j *Journal) SetCommandAutomationEnabledIfStateAndVersion(ctx context.Context, tenantID, id string, enabled, expectedEnabled bool, expectedVersion int) error {
	return j.setCommandAutomationEnabledFence(ctx, tenantID, id, enabled, expectedVersion, &expectedEnabled)
}

// SetCommandAutomationEnabledIfVersion changes a plan only when the exact
// immutable current version still matches. It is useful for callers that do
// not need a separate state compare but still must prevent enabling an
// unreviewed revision.
func (j *Journal) SetCommandAutomationEnabledIfVersion(ctx context.Context, tenantID, id string, enabled bool, expectedVersion int) error {
	return j.setCommandAutomationEnabledFence(ctx, tenantID, id, enabled, expectedVersion, nil)
}

func (j *Journal) setCommandAutomationEnabledFence(ctx context.Context, tenantID, id string, enabled bool, expectedVersion int, expectedState *bool) error {
	if expectedVersion < 1 {
		return fmt.Errorf("%w: expected version must be positive", ErrCommandAutomationConflict)
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin command automation activation fence: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		// SQLite has no row-level FOR UPDATE. Take its writer lock before the
		// read so a concurrent revision cannot cross this state transition.
		res, lockErr := tx.ExecContext(ctx, j.bind(`UPDATE command_automations SET updated_at = updated_at WHERE id = $1 AND tenant_id = $2`), id, tenantID)
		if lockErr != nil {
			return fmt.Errorf("journal: lock command automation activation: %w", lockErr)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
	}
	lockQ := `SELECT enabled, current_version FROM command_automations WHERE id = $1 AND tenant_id = $2`
	if j.engine == EnginePostgres {
		lockQ += ` FOR UPDATE`
	}
	var currentEnabled any
	var currentVersion int
	if err := tx.QueryRowContext(ctx, j.bind(lockQ), id, tenantID).Scan(&currentEnabled, &currentVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: read command automation activation: %w", err)
	}
	if currentVersion != expectedVersion {
		return fmt.Errorf("%w: expected version %d, current version %d", ErrCommandAutomationConflict, expectedVersion, currentVersion)
	}
	current := parseBool(currentEnabled)
	if expectedState != nil && current != *expectedState {
		return fmt.Errorf("%w: expected enabled=%t, current enabled=%t", ErrCommandAutomationStateConflict, *expectedState, current)
	}
	if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automations SET enabled = $1, updated_at = $2 WHERE id = $3 AND tenant_id = $4`), j.boolValue(enabled), j.now(), id, tenantID); err != nil {
		return fmt.Errorf("journal: set command automation enabled with fence: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit command automation activation fence: %w", err)
	}
	return nil
}

func (j *Journal) GetCommandAutomationByName(ctx context.Context, tenantID, name string) (CommandAutomation, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	return j.scanCommandAutomation(j.db.QueryRowContext(ctx, j.bind(`SELECT id, tenant_id, name, description, target, enabled, current_version, created_by, created_at, updated_at FROM command_automations WHERE tenant_id = $1 AND name = $2`), tenantID, name).Scan)
}

func (j *Journal) GetCommandAutomation(ctx context.Context, tenantID, id string) (CommandAutomation, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	a, err := j.scanCommandAutomation(j.db.QueryRowContext(ctx, j.bind(`SELECT id, tenant_id, name, description, target, enabled, current_version, created_by, created_at, updated_at FROM command_automations WHERE tenant_id = $1 AND id = $2`), tenantID, id).Scan)
	if errors.Is(err, ErrNotFound) {
		return CommandAutomation{}, err
	}
	return a, err
}

func (j *Journal) GetCommandAutomationVersion(ctx context.Context, tenantID, id string, version int) (CommandAutomationVersion, error) {
	if version <= 0 {
		return CommandAutomationVersion{}, errors.New("journal: command automation version must be positive")
	}
	tenantID = normalizedCommandAutomationTenant(tenantID)
	q := fmt.Sprintf(`SELECT v.automation_id, v.version, %s, v.definition_crypto_version,
		v.definition_plaintext_bytes, v.definition_sha256, v.created_by, v.created_at
		FROM command_automation_versions v JOIN command_automations a ON a.id = v.automation_id
		WHERE a.tenant_id = $1 AND v.automation_id = $2 AND v.version = $3`, j.commandDefinitionProjection("v"))
	v, err := j.scanCommandAutomationVersion(j.db.QueryRowContext(ctx, j.bind(q), tenantID, id, version).Scan, tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return CommandAutomationVersion{}, ErrNotFound
	}
	if err != nil {
		return CommandAutomationVersion{}, fmt.Errorf("journal: get command automation version: %w", err)
	}
	return v, nil
}

func normalizedCommandAutomationTenant(tenantID string) string {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return DefaultTenant
	}
	return tenantID
}

func (j *Journal) scanCommandAutomationVersion(scan func(...any) error, tenantID string) (CommandAutomationVersion, error) {
	var v CommandAutomationVersion
	var stored []byte
	var cryptoVersion int
	var plainBytes sql.NullInt64
	var digest sql.NullString
	var created any
	if err := scan(&v.AutomationID, &v.Version, &stored, &cryptoVersion, &plainBytes, &digest, &v.CreatedBy, &created); err != nil {
		return CommandAutomationVersion{}, err
	}
	definition, err := j.openCommandDefinition(tenantID, v.AutomationID, v.Version, cryptoVersion, plainBytes, digest, stored)
	if err != nil {
		return CommandAutomationVersion{}, err
	}
	v.DefinitionJSON = definition
	v.CreatedAt = j.anyTime(created)
	return v, nil
}

// ListCommandAutomationVersions returns every immutable definition for one
// tenant-owned plan in ascending version order. It is used by tenant export;
// command text remains untrusted data and credential values are never read.
func (j *Journal) ListCommandAutomationVersions(ctx context.Context, tenantID, id string) ([]CommandAutomationVersion, error) {
	plan, err := j.GetCommandAutomation(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	q := fmt.Sprintf(`SELECT v.automation_id, v.version, %s, v.definition_crypto_version,
		v.definition_plaintext_bytes, v.definition_sha256, v.created_by, v.created_at
		FROM command_automation_versions v WHERE v.automation_id = $1 ORDER BY v.version ASC`, j.commandDefinitionProjection("v"))
	rows, err := j.db.QueryContext(ctx, j.bind(q), id)
	if err != nil {
		return nil, fmt.Errorf("journal: list command automation versions: %w", err)
	}
	defer rows.Close()
	versions := make([]CommandAutomationVersion, 0)
	for rows.Next() {
		v, err := j.scanCommandAutomationVersion(rows.Scan, plan.TenantID)
		if err != nil {
			return nil, fmt.Errorf("journal: scan command automation version: %w", err)
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("journal: list command automation versions: %w", err)
	}
	return versions, nil
}

// ListCommandAutomationVersionsPage returns one bounded page of immutable
// definitions for a tenant-owned plan. Export callers must use this method
// rather than ListCommandAutomationVersions when the number of revisions is
// user-controlled; loading every definition defeats the export boundary.
func (j *Journal) ListCommandAutomationVersionsPage(ctx context.Context, tenantID, id string, limit, offset int) ([]CommandAutomationVersion, bool, error) {
	if limit <= 0 || limit > 500 || offset < 0 {
		return nil, false, errors.New("journal: invalid command automation version page")
	}
	plan, err := j.GetCommandAutomation(ctx, tenantID, id)
	if err != nil {
		return nil, false, err
	}
	fetch := limit + 1
	q := fmt.Sprintf(`SELECT v.automation_id, v.version, %s, v.definition_crypto_version,
		v.definition_plaintext_bytes, v.definition_sha256, v.created_by, v.created_at
		FROM command_automation_versions v WHERE v.automation_id = $1 ORDER BY v.version ASC LIMIT %d OFFSET %d`,
		j.commandDefinitionProjection("v"), fetch, offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q), id)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list command automation versions page: %w", err)
	}
	defer rows.Close()
	out := make([]CommandAutomationVersion, 0, limit)
	for rows.Next() {
		v, err := j.scanCommandAutomationVersion(rows.Scan, plan.TenantID)
		if err != nil {
			return nil, false, fmt.Errorf("journal: scan command automation version page: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("journal: list command automation versions page: %w", err)
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

// ListCommandAutomationVersionSummariesPage returns bounded newest-first
// revision metadata for one tenant-owned plan. It deliberately excludes the
// stored definition so MCP callers can discover versions before opting into
// untrusted command-bearing review data.
func (j *Journal) ListCommandAutomationVersionSummariesPage(ctx context.Context, tenantID, id string, limit, offset int) ([]CommandAutomationVersionSummary, bool, error) {
	if limit <= 0 || limit > 500 || offset < 0 {
		return nil, false, errors.New("journal: invalid command automation version page")
	}
	if _, err := j.GetCommandAutomation(ctx, tenantID, id); err != nil {
		return nil, false, err
	}
	fetch := limit + 1
	q := fmt.Sprintf(`SELECT v.automation_id, v.version, %s, v.definition_crypto_version,
		v.definition_plaintext_bytes, v.definition_sha256, v.definition_canonical_sha256, v.created_by, v.created_at
		FROM command_automation_versions v WHERE v.automation_id = $1 ORDER BY v.version DESC LIMIT %d OFFSET %d`,
		j.commandDefinitionLegacyProjection("v"), fetch, offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q), id)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list command automation version summaries: %w", err)
	}
	defer rows.Close()
	out := make([]CommandAutomationVersionSummary, 0, limit)
	for rows.Next() {
		var (
			v               CommandAutomationVersionSummary
			raw             []byte
			cryptoVersion   int
			plainBytes      sql.NullInt64
			storedDigest    sql.NullString
			canonicalDigest sql.NullString
			created         any
		)
		if err := rows.Scan(&v.AutomationID, &v.Version, &raw, &cryptoVersion, &plainBytes, &storedDigest, &canonicalDigest, &v.CreatedBy, &created); err != nil {
			return nil, false, fmt.Errorf("journal: scan command automation version summary: %w", err)
		}
		switch cryptoVersion {
		case 0:
			// Pre-cutover imports may use non-canonical but valid JSON. Retain
			// the historical canonical digest, with a raw-byte fallback for a
			// malformed definition that later review/admission rejects.
			if plainBytes.Valid || storedDigest.Valid || canonicalDigest.Valid || raw == nil || !json.Valid(raw) {
				return nil, false, fmt.Errorf("journal: invalid legacy command automation version summary")
			}
			v.DefinitionSHA256 = commandDefinitionReceiptDigest(raw)
			v.DefinitionBytes = len(raw)
		case 1:
			// This metadata-only inventory does not authenticate the envelope;
			// exact-version get, review, and dispatch do before using its data.
			if !plainBytes.Valid || plainBytes.Int64 < 1 || plainBytes.Int64 > commandautomations.MaxDefinitionBytes ||
				!storedDigest.Valid || !validCommandDefinitionDigest(storedDigest.String) {
				return nil, false, fmt.Errorf("journal: invalid encrypted command automation version summary")
			}
			v.DefinitionSHA256 = storedDigest.String
			if canonicalDigest.Valid {
				if !validCommandDefinitionDigest(canonicalDigest.String) {
					return nil, false, fmt.Errorf("journal: invalid encrypted command automation canonical digest")
				}
				v.DefinitionSHA256 = canonicalDigest.String
			}
			v.DefinitionBytes = int(plainBytes.Int64)
		default:
			return nil, false, fmt.Errorf("journal: unsupported command automation definition version")
		}
		v.CreatedAt = j.anyTime(created)
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("journal: list command automation version summaries: %w", err)
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

func (j *Journal) ListCommandAutomationsPage(ctx context.Context, tenantID string, limit, offset int) ([]CommandAutomation, bool, error) {
	if limit <= 0 || limit > 500 || offset < 0 {
		return nil, false, errors.New("journal: invalid command automation page")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	q := fmt.Sprintf(`SELECT id, tenant_id, name, description, target, enabled, current_version, created_by, created_at, updated_at FROM command_automations WHERE tenant_id = $1 ORDER BY name ASC, id ASC LIMIT %d OFFSET %d`, limit+1, offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q), tenantID)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list command automations: %w", err)
	}
	defer rows.Close()
	out := make([]CommandAutomation, 0, limit)
	for rows.Next() {
		var a CommandAutomation
		var enabled, created, updated any
		if err := rows.Scan(&a.ID, &a.TenantID, &a.Name, &a.Description, &a.Target, &enabled, &a.CurrentVersion, &a.CreatedBy, &created, &updated); err != nil {
			return nil, false, fmt.Errorf("journal: scan command automation: %w", err)
		}
		a.Enabled = parseBool(enabled)
		a.CreatedAt, a.UpdatedAt = j.anyTime(created), j.anyTime(updated)
		out = append(out, a)
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

// ListAllCommandAutomationsPage is the internal graph-builder inventory. It
// deliberately has no tenant predicate because the graph is built globally;
// MCP query and neighbor methods apply the tenant filter before returning it.
func (j *Journal) ListAllCommandAutomationsPage(ctx context.Context, limit, offset int) ([]CommandAutomation, bool, error) {
	if limit <= 0 || limit > 500 || offset < 0 {
		return nil, false, errors.New("journal: invalid command automation page")
	}
	q := fmt.Sprintf(`SELECT id, tenant_id, name, description, target, enabled, current_version, created_by, created_at, updated_at FROM command_automations ORDER BY tenant_id ASC, name ASC, id ASC LIMIT %d OFFSET %d`, limit+1, offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q))
	if err != nil {
		return nil, false, fmt.Errorf("journal: list all command automations: %w", err)
	}
	defer rows.Close()
	out := make([]CommandAutomation, 0, limit)
	for rows.Next() {
		var a CommandAutomation
		var enabled, created, updated any
		if err := rows.Scan(&a.ID, &a.TenantID, &a.Name, &a.Description, &a.Target, &enabled, &a.CurrentVersion, &a.CreatedBy, &created, &updated); err != nil {
			return nil, false, fmt.Errorf("journal: scan command automation: %w", err)
		}
		a.Enabled = parseBool(enabled)
		a.CreatedAt, a.UpdatedAt = j.anyTime(created), j.anyTime(updated)
		out = append(out, a)
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

// DeleteCommandAutomation removes the plan and every historical definition in
// one transaction, including when a caller opens SQLite without FK enforcement.
func (j *Journal) DeleteCommandAutomation(ctx context.Context, tenantID, id string) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	plan, err := j.GetCommandAutomation(ctx, tenantID, id)
	if err != nil {
		return err
	}
	return j.DeleteCommandAutomationIfVersion(ctx, tenantID, id, plan.CurrentVersion)
}

// DeleteCommandAutomationIfVersion removes a plan only when the caller's
// reviewed current version is still current. The row lock and deletion share
// one transaction so a concurrent revision cannot be deleted by a stale
// authoring decision.
func (j *Journal) DeleteCommandAutomationIfVersion(ctx context.Context, tenantID, id string, expectedVersion int) error {
	if expectedVersion < 1 {
		return ErrCommandAutomationConflict
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin command automation delete: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automations SET current_version = current_version WHERE id = $1 AND tenant_id = $2`), id, tenantID); err != nil {
			return fmt.Errorf("journal: lock command automation delete: %w", err)
		}
	}
	var owner string
	var current int
	var enabled any
	lockQ := `SELECT tenant_id, current_version, enabled FROM command_automations WHERE id = $1`
	if j.engine == EnginePostgres {
		lockQ += ` FOR UPDATE`
	}
	if err := tx.QueryRowContext(ctx, j.bind(lockQ), id).Scan(&owner, &current, &enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: lock command automation delete: %w", err)
	}
	if owner != tenantID {
		return ErrCommandAutomationTenant
	}
	if parseBool(enabled) {
		return ErrCommandAutomationEnabled
	}
	if current != expectedVersion {
		return ErrCommandAutomationConflict
	}
	// Trigger rows and durable command runs deliberately use RESTRICT foreign
	// keys. Check them while the plan row is locked so deletion fails with a
	// stable, actionable error instead of a driver-specific constraint message
	// (and so installations with foreign-key enforcement disabled cannot leave
	// orphaned trigger bindings or run receipts behind).
	var hasRuns bool
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT EXISTS (SELECT 1 FROM command_runs WHERE automation_id = $1)`), id).Scan(&hasRuns); err != nil {
		return fmt.Errorf("journal: inspect command automation runs before delete: %w", err)
	}
	if hasRuns {
		return ErrCommandAutomationHasRuns
	}
	var hasTriggers bool
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT EXISTS (
		SELECT 1 FROM command_automation_schedules WHERE automation_id = $1
		UNION ALL SELECT 1 FROM command_automation_webhook_triggers WHERE automation_id = $2
		UNION ALL SELECT 1 FROM command_automation_chain_triggers WHERE automation_id = $3
	)`), id, id, id).Scan(&hasTriggers); err != nil {
		return fmt.Errorf("journal: inspect command automation triggers before delete: %w", err)
	}
	if hasTriggers {
		return ErrCommandAutomationHasTriggers
	}
	if _, err := tx.ExecContext(ctx, j.bind(`DELETE FROM command_automation_versions WHERE automation_id = $1`), id); err != nil {
		return fmt.Errorf("journal: delete command automation versions: %w", err)
	}
	res, err := tx.ExecContext(ctx, j.bind(`DELETE FROM command_automations WHERE id = $1 AND tenant_id = $2`), id, tenantID)
	if err != nil {
		return fmt.Errorf("journal: delete command automation: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("journal: delete command automation rows affected: %w", err)
	} else if n != 1 {
		return ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit command automation delete: %w", err)
	}
	return nil
}

func (j *Journal) scanCommandAutomation(scan func(...any) error) (CommandAutomation, error) {
	var a CommandAutomation
	var enabled, created, updated any
	if err := scan(&a.ID, &a.TenantID, &a.Name, &a.Description, &a.Target, &enabled, &a.CurrentVersion, &a.CreatedBy, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CommandAutomation{}, ErrNotFound
		}
		return CommandAutomation{}, fmt.Errorf("journal: scan command automation: %w", err)
	}
	a.Enabled = parseBool(enabled)
	a.CreatedAt, a.UpdatedAt = j.anyTime(created), j.anyTime(updated)
	return a, nil
}
