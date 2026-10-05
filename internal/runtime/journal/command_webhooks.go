package journal

// This file is the durable control-plane half of command-automation webhook
// triggers. It intentionally does not dispatch a command or retain an inbound
// body. The token/secret binding and the exact immutable plan receipt are kept
// separate from workflow triggers so a workflow token can never accidentally
// acquire command execution authority.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/reactor/internal/commandautomations"
)

const (
	CommandAutomationWebhookActive   = "active"
	CommandAutomationWebhookDisabled = "disabled"
	maxCommandWebhookID              = 128
	maxCommandWebhookToken           = 256
	maxCommandWebhookSecret          = 512
	maxCommandWebhookProvider        = 64
	maxCommandWebhookActor           = 512
	maxCommandWebhookKey             = 200
	maxCommandWebhookPage            = 500
)

var (
	ErrCommandAutomationWebhookRevisionConflict = errors.New("journal: command automation webhook revision conflict")
	ErrCommandAutomationWebhookConflict         = errors.New("journal: command automation webhook conflict")
	ErrCommandAutomationWebhookBindingMismatch  = errors.New("journal: command automation webhook admission binding mismatch")
	ErrCommandAutomationWebhookState            = errors.New("journal: invalid command automation webhook state")
	ErrCommandAutomationWebhookActive           = errors.New("journal: disable command automation webhook before editing it")
)

// CommandAutomationWebhookTrigger is a tenant-scoped inbound command
// binding. SecretID is only a vault reference; no secret or request payload is
// part of this projection.
type CommandAutomationWebhookTrigger struct {
	ID                string     `json:"id"`
	TenantID          string     `json:"tenant_id"`
	AutomationID      string     `json:"automation_id"`
	AutomationVersion int        `json:"automation_version"`
	DefinitionSHA256  string     `json:"definition_sha256"`
	ReceiptID         string     `json:"receipt_id"`
	GateDigest        string     `json:"gate_digest"`
	ActorID           string     `json:"actor_id"`
	TokenID           string     `json:"token_id"`
	SecretID          string     `json:"secret_id"`
	Provider          string     `json:"provider"`
	State             string     `json:"state"`
	Revision          int64      `json:"revision"`
	LastFiredAt       *time.Time `json:"last_fired_at,omitempty"`
	LastError         string     `json:"last_error,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// CommandAutomationWebhookTriggerInput is the exact reviewed binding used
// to create a trigger. New rows always start disabled.
type CommandAutomationWebhookTriggerInput struct {
	ID                string
	AutomationID      string
	AutomationVersion int
	DefinitionSHA256  string
	ReceiptID         string
	GateDigest        string
	ActorID           string
	TokenID           string
	SecretID          string
	Provider          string
}

type CommandAutomationWebhookTriggerUpdate struct {
	AutomationVersion int
	DefinitionSHA256  string
	ReceiptID         string
	GateDigest        string
	ActorID           string
	TokenID           string
	SecretID          string
	Provider          string
}

// UpdateCommandAutomationWebhookTriggerIfRevision replaces the disabled
// trigger's reviewed binding under an optimistic revision fence. Secret and
// token rotation are deliberately disabled while active; callers must first
// stop ingress, then supply a fresh exact-version receipt.
func (j *Journal) UpdateCommandAutomationWebhookTriggerIfRevision(ctx context.Context, tenantID, id string, update CommandAutomationWebhookTriggerUpdate, expectedRevision int64) error {
	tenantID = normalizeCommandWebhookTenant(tenantID)
	if expectedRevision < 1 {
		return errors.New("journal: command automation webhook revision must be positive")
	}
	if err := validateCommandAutomationWebhookInput(CommandAutomationWebhookTriggerInput{
		ID: id, AutomationID: "webhook-update", AutomationVersion: update.AutomationVersion,
		DefinitionSHA256: update.DefinitionSHA256, ReceiptID: update.ReceiptID, GateDigest: update.GateDigest,
		ActorID: update.ActorID, TokenID: update.TokenID, SecretID: update.SecretID, Provider: update.Provider,
	}); err != nil {
		return err
	}
	secretTenant, err := j.SecretTenant(ctx, update.SecretID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	if secretTenant != tenantID {
		return ErrNotFound
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin command automation webhook update: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automation_webhook_triggers SET id = id WHERE id = $1 AND tenant_id = $2`), id, tenantID); err != nil {
			return fmt.Errorf("journal: lock command automation webhook update: %w", err)
		}
	}
	// Command-run admission locks the plan row before the trigger row. Keep
	// this update in the same order on Postgres; locking the trigger first can
	// deadlock with a concurrent admission that is waiting on this revision.
	lockQ := `SELECT automation_id, state, revision FROM command_automation_webhook_triggers WHERE id = $1 AND tenant_id = $2`
	var automationID, state string
	var revision int64
	if err := tx.QueryRowContext(ctx, j.bind(lockQ), id, tenantID).Scan(&automationID, &state, &revision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: resolve command automation webhook update: %w", err)
	}
	if revision != expectedRevision {
		return fmt.Errorf("%w: expected %d, current %d", ErrCommandAutomationWebhookRevisionConflict, expectedRevision, revision)
	}
	if state != CommandAutomationWebhookDisabled {
		return ErrCommandAutomationWebhookActive
	}
	planQ := `SELECT current_version FROM command_automations WHERE id = $1 AND tenant_id = $2`
	if j.engine == EnginePostgres {
		planQ += ` FOR UPDATE`
	}
	var currentVersion int
	if err := tx.QueryRowContext(ctx, j.bind(planQ), automationID, tenantID).Scan(&currentVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: resolve command automation webhook plan: %w", err)
	}
	if currentVersion != update.AutomationVersion {
		return ErrCommandAutomationWebhookConflict
	}
	if j.engine == EnginePostgres {
		var lockedAutomationID, lockedState string
		var lockedRevision int64
		if err := tx.QueryRowContext(ctx, j.bind(lockQ+` FOR UPDATE`), id, tenantID).Scan(&lockedAutomationID, &lockedState, &lockedRevision); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("journal: lock command automation webhook update: %w", err)
		}
		if lockedAutomationID != automationID || lockedRevision != expectedRevision {
			return fmt.Errorf("%w: expected %d, current %d", ErrCommandAutomationWebhookRevisionConflict, expectedRevision, lockedRevision)
		}
		if lockedState != CommandAutomationWebhookDisabled {
			return ErrCommandAutomationWebhookActive
		}
	}
	binding := CommandAutomationWebhookTriggerInput{
		ID: id, AutomationID: automationID, AutomationVersion: update.AutomationVersion,
		DefinitionSHA256: update.DefinitionSHA256, ReceiptID: update.ReceiptID, GateDigest: update.GateDigest,
		ActorID: update.ActorID, TokenID: update.TokenID, SecretID: update.SecretID, Provider: update.Provider,
	}
	if err := verifyCommandAutomationWebhookBindingTx(ctx, tx, j, tenantID, binding); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automation_webhook_triggers SET automation_version = $1, definition_sha256 = $2, receipt_id = $3, gate_digest = $4, actor_id = $5, token_id = $6, secret_id = $7, provider = $8, revision = revision + 1, updated_at = $9 WHERE id = $10 AND tenant_id = $11 AND revision = $12`), update.AutomationVersion, update.DefinitionSHA256, update.ReceiptID, update.GateDigest, update.ActorID, update.TokenID, update.SecretID, update.Provider, j.now(), id, tenantID, expectedRevision)
	if err != nil {
		return fmt.Errorf("journal: update command automation webhook: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: expected %d", ErrCommandAutomationWebhookRevisionConflict, expectedRevision)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit command automation webhook update: %w", err)
	}
	return nil
}

type CommandAutomationWebhookTriggerFilter struct {
	TenantID     string
	AutomationID string
	State        string
	Limit        int
	Offset       int
}

// NewCommandAutomationWebhookToken returns a URL-safe opaque token whose
// prefix keeps command ingress distinct from workflow /webhook tokens.
func NewCommandAutomationWebhookToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("journal: command webhook token: %w", err)
	}
	return "cmdwhk_" + hex.EncodeToString(b), nil
}

func (j *Journal) CreateCommandAutomationWebhookTrigger(ctx context.Context, tenantID string, input CommandAutomationWebhookTriggerInput) (CommandAutomationWebhookTrigger, error) {
	row, _, err := j.CreateCommandAutomationWebhookTriggerWithIdempotency(ctx, tenantID, input, "")
	return row, err
}

// CreateCommandAutomationWebhookTriggerWithIdempotency creates a disabled
// trigger after checking tenant ownership, current immutable version, exact
// definition digest, and receipt binding. The key intentionally excludes the
// generated token so a retry after a lost response returns the original token.
func (j *Journal) CreateCommandAutomationWebhookTriggerWithIdempotency(ctx context.Context, tenantID string, input CommandAutomationWebhookTriggerInput, key string) (row CommandAutomationWebhookTrigger, replay bool, err error) {
	tenantID = normalizeCommandWebhookTenant(tenantID)
	key = strings.TrimSpace(key)
	if key != "" {
		if err := validateCommandWebhookText("idempotency_key", key, maxCommandWebhookKey); err != nil {
			return row, false, err
		}
	}
	if input.ID == "" {
		input.ID, err = newID("cmdwhk_")
		if err != nil {
			return row, false, err
		}
	}
	if err := validateCommandAutomationWebhookInput(input); err != nil {
		return row, false, err
	}
	if secretTenant, secretErr := j.SecretTenant(ctx, input.SecretID); secretErr != nil {
		if errors.Is(secretErr, ErrNotFound) {
			return row, false, ErrNotFound
		}
		return row, false, secretErr
	} else if secretTenant != tenantID {
		// Keep ownership failures indistinguishable from a missing secret.
		return row, false, ErrNotFound
	}
	hash := commandAutomationWebhookIdempotencyHash(input)
	if key != "" {
		if existing, existingHash, lookupErr := j.getCommandAutomationWebhookByIdempotency(ctx, tenantID, key); lookupErr == nil {
			if existingHash != hash {
				return row, false, ErrCommandAutomationWebhookConflict
			}
			return existing, true, nil
		} else if !errors.Is(lookupErr, ErrNotFound) {
			return row, false, lookupErr
		}
	}

	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return row, false, fmt.Errorf("journal: begin command automation webhook create: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automations SET current_version = current_version WHERE id = $1 AND tenant_id = $2`), input.AutomationID, tenantID); err != nil {
			return row, false, fmt.Errorf("journal: lock command automation for webhook: %w", err)
		}
	}
	planQ := `SELECT current_version FROM command_automations WHERE id = $1 AND tenant_id = $2`
	if j.engine == EnginePostgres {
		planQ += ` FOR UPDATE`
	}
	var currentVersion int
	if err := tx.QueryRowContext(ctx, j.bind(planQ), input.AutomationID, tenantID).Scan(&currentVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return row, false, ErrNotFound
		}
		return row, false, fmt.Errorf("journal: resolve command automation for webhook: %w", err)
	}
	if currentVersion != input.AutomationVersion {
		return row, false, ErrCommandAutomationWebhookConflict
	}
	if err := verifyCommandAutomationWebhookBindingTx(ctx, tx, j, tenantID, input); err != nil {
		return row, false, err
	}
	now := j.now()
	storedHash := any(nil)
	if key != "" {
		storedHash = hash
	}
	insertQ := `INSERT INTO command_automation_webhook_triggers
		(id, tenant_id, automation_id, automation_version, definition_sha256, receipt_id, gate_digest, actor_id, token_id, secret_id, provider, state, revision, idempotency_key, idempotency_hash, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,$13,$14,$15,$16)
		ON CONFLICT DO NOTHING`
	res, err := tx.ExecContext(ctx, j.bind(insertQ), input.ID, tenantID, input.AutomationID, input.AutomationVersion, input.DefinitionSHA256, input.ReceiptID, input.GateDigest, input.ActorID, input.TokenID, input.SecretID, input.Provider, CommandAutomationWebhookDisabled, nullable(key), storedHash, now, now)
	if err != nil {
		return row, false, fmt.Errorf("journal: create command automation webhook: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return row, false, fmt.Errorf("journal: create command automation webhook rows affected: %w", err)
	}
	if n == 0 {
		var existing CommandAutomationWebhookTrigger
		var ignoredKey, existingHash any
		var scanErr error
		if key != "" {
			scanErr = tx.QueryRowContext(ctx, j.bind(commandAutomationWebhookSelect()+` WHERE w.tenant_id = $1 AND w.idempotency_key = $2`), tenantID, key).Scan(commandAutomationWebhookScanArgs(&existing, &ignoredKey, &existingHash)...)
		} else {
			scanErr = tx.QueryRowContext(ctx, j.bind(commandAutomationWebhookSelect()+` WHERE w.tenant_id = $1 AND w.id = $2`), tenantID, input.ID).Scan(commandAutomationWebhookScanArgs(&existing, &ignoredKey, &existingHash)...)
		}
		if scanErr == nil && key != "" && anyToString(existingHash) == hash {
			if err := tx.Commit(); err != nil {
				return row, false, fmt.Errorf("journal: commit command automation webhook replay: %w", err)
			}
			return existing, true, nil
		}
		if errors.Is(scanErr, sql.ErrNoRows) {
			return row, false, ErrCommandAutomationWebhookConflict
		}
		if scanErr != nil {
			return row, false, fmt.Errorf("journal: resolve command automation webhook conflict: %w", scanErr)
		}
		return row, false, ErrCommandAutomationWebhookConflict
	}
	if err := tx.Commit(); err != nil {
		return row, false, fmt.Errorf("journal: commit command automation webhook: %w", err)
	}
	created, getErr := j.GetCommandAutomationWebhookTriggerForTenant(ctx, tenantID, input.ID)
	return created, false, getErr
}

func (j *Journal) GetCommandAutomationWebhookTriggerForTenant(ctx context.Context, tenantID, id string) (CommandAutomationWebhookTrigger, error) {
	tenantID = normalizeCommandWebhookTenant(tenantID)
	if err := validateCommandWebhookText("id", id, maxCommandWebhookID); err != nil {
		return CommandAutomationWebhookTrigger{}, err
	}
	return j.scanCommandAutomationWebhook(j.db.QueryRowContext(ctx, j.bind(commandAutomationWebhookSelect()+` WHERE w.tenant_id = $1 AND w.id = $2`), tenantID, id).Scan)
}

// FindActiveCommandAutomationWebhookByToken is the public ingress lookup. It
// joins the plan tenant marker so imported/legacy rows with a mismatched owner
// cannot become an execution capability.
func (j *Journal) FindActiveCommandAutomationWebhookByToken(ctx context.Context, token string) (CommandAutomationWebhookTrigger, error) {
	if err := validateCommandWebhookText("token_id", token, maxCommandWebhookToken); err != nil {
		return CommandAutomationWebhookTrigger{}, ErrNotFound
	}
	return j.scanCommandAutomationWebhook(j.db.QueryRowContext(ctx, j.bind(commandAutomationWebhookSelect()+` WHERE w.token_id = $1 AND w.state = $2 LIMIT 1`), token, CommandAutomationWebhookActive).Scan)
}

func (j *Journal) ListCommandAutomationWebhookTriggersForTenantPage(ctx context.Context, filter CommandAutomationWebhookTriggerFilter) ([]CommandAutomationWebhookTrigger, bool, error) {
	filter.TenantID = normalizeCommandWebhookTenant(filter.TenantID)
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > maxCommandWebhookPage {
		return nil, false, fmt.Errorf("journal: list command automation webhooks: page limit exceeds %d", maxCommandWebhookPage)
	}
	if filter.Offset < 0 {
		return nil, false, errors.New("journal: list command automation webhooks: negative offset")
	}
	where := []string{"w.tenant_id = $1", "w.tenant_id = a.tenant_id"}
	args := []any{filter.TenantID}
	if filter.AutomationID != "" {
		if err := validateCommandWebhookText("automation_id", filter.AutomationID, maxCommandWebhookID); err != nil {
			return nil, false, err
		}
		where = append(where, fmt.Sprintf("w.automation_id = $%d", len(args)+1))
		args = append(args, filter.AutomationID)
	}
	if filter.State != "" {
		if err := validateCommandAutomationWebhookState(filter.State); err != nil {
			return nil, false, err
		}
		where = append(where, fmt.Sprintf("w.state = $%d", len(args)+1))
		args = append(args, filter.State)
	}
	q := commandAutomationWebhookSelect() + " WHERE " + strings.Join(where, " AND ") + fmt.Sprintf(" ORDER BY w.created_at DESC, w.id ASC LIMIT %d OFFSET %d", filter.Limit+1, filter.Offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list command automation webhooks: %w", err)
	}
	defer rows.Close()
	out := make([]CommandAutomationWebhookTrigger, 0, filter.Limit)
	for rows.Next() {
		row, scanErr := j.scanCommandAutomationWebhook(rows.Scan)
		if scanErr != nil {
			return nil, false, scanErr
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("journal: list command automation webhooks rows: %w", err)
	}
	more := len(out) > filter.Limit
	if more {
		out = out[:filter.Limit]
	}
	return out, more, nil
}

func (j *Journal) SetCommandAutomationWebhookTriggerStateIfRevision(ctx context.Context, tenantID, id, state string, expectedRevision int64) error {
	tenantID = normalizeCommandWebhookTenant(tenantID)
	if expectedRevision < 1 {
		return errors.New("journal: command automation webhook revision must be positive")
	}
	if err := validateCommandAutomationWebhookState(state); err != nil {
		return err
	}
	if err := validateCommandWebhookText("id", id, maxCommandWebhookID); err != nil {
		return err
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin command automation webhook state: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automation_webhook_triggers SET id = id WHERE id = $1 AND tenant_id = $2`), id, tenantID); err != nil {
			return fmt.Errorf("journal: lock command automation webhook state: %w", err)
		}
	}
	// Activation follows the plan-then-trigger lock order used by admission;
	// disabling remains a trigger-only emergency stop.
	q := `SELECT automation_id, automation_version, revision FROM command_automation_webhook_triggers WHERE id = $1 AND tenant_id = $2`
	if j.engine == EnginePostgres && state != CommandAutomationWebhookActive {
		q += ` FOR UPDATE`
	}
	var automationID string
	var version int
	var revision int64
	if err := tx.QueryRowContext(ctx, j.bind(q), id, tenantID).Scan(&automationID, &version, &revision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: resolve command automation webhook state: %w", err)
	}
	if revision != expectedRevision {
		return fmt.Errorf("%w: expected %d, current %d", ErrCommandAutomationWebhookRevisionConflict, expectedRevision, revision)
	}
	if state == CommandAutomationWebhookActive {
		planQ := `SELECT enabled, current_version FROM command_automations WHERE id = $1 AND tenant_id = $2`
		if j.engine == EnginePostgres {
			planQ += ` FOR UPDATE`
		}
		var enabled any
		var current int
		if err := tx.QueryRowContext(ctx, j.bind(planQ), automationID, tenantID).Scan(&enabled, &current); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("journal: resolve command automation webhook plan: %w", err)
		}
		if !parseBool(enabled) || current != version {
			return ErrCommandAutomationWebhookBindingMismatch
		}
		var lockedAutomationID, lockedDefinitionSHA256, lockedReceiptID, lockedGateDigest string
		var lockedVersion int
		var lockedRevision int64
		triggerLockQ := `SELECT automation_id, automation_version, definition_sha256, receipt_id, gate_digest, revision FROM command_automation_webhook_triggers WHERE id = $1 AND tenant_id = $2`
		if j.engine == EnginePostgres {
			triggerLockQ += ` FOR UPDATE`
		}
		if err := tx.QueryRowContext(ctx, j.bind(triggerLockQ), id, tenantID).Scan(&lockedAutomationID, &lockedVersion, &lockedDefinitionSHA256, &lockedReceiptID, &lockedGateDigest, &lockedRevision); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("journal: lock command automation webhook state: %w", err)
		}
		if lockedAutomationID != automationID || lockedVersion != version || lockedRevision != expectedRevision {
			return fmt.Errorf("%w: expected %d, current %d", ErrCommandAutomationWebhookRevisionConflict, expectedRevision, lockedRevision)
		}
		// MCP activation re-evaluates capabilities and runtime readiness. Keep
		// this durable state transition fail-closed as well: a direct journal
		// caller must not be able to activate an imported row whose immutable
		// definition digest or receipt identity no longer matches its plan.
		if err := verifyCommandAutomationWebhookBindingTx(ctx, tx, j, tenantID, CommandAutomationWebhookTriggerInput{
			AutomationID: automationID, AutomationVersion: version,
			DefinitionSHA256: lockedDefinitionSHA256, ReceiptID: lockedReceiptID, GateDigest: lockedGateDigest,
		}); err != nil {
			return err
		}
	}
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automation_webhook_triggers SET state = $1, revision = revision + 1, updated_at = $2 WHERE id = $3 AND tenant_id = $4 AND revision = $5`), state, j.now(), id, tenantID, expectedRevision)
	if err != nil {
		return fmt.Errorf("journal: set command automation webhook state: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: expected %d", ErrCommandAutomationWebhookRevisionConflict, expectedRevision)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit command automation webhook state: %w", err)
	}
	return nil
}

func (j *Journal) DeleteCommandAutomationWebhookTriggerIfRevision(ctx context.Context, tenantID, id string, expectedRevision int64) error {
	tenantID = normalizeCommandWebhookTenant(tenantID)
	if expectedRevision < 1 {
		return errors.New("journal: command automation webhook revision must be positive")
	}
	res, err := j.db.ExecContext(ctx, j.bind(`DELETE FROM command_automation_webhook_triggers WHERE id = $1 AND tenant_id = $2 AND state = $3 AND revision = $4`), id, tenantID, CommandAutomationWebhookDisabled, expectedRevision)
	if err != nil {
		return fmt.Errorf("journal: delete command automation webhook: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return j.commandAutomationWebhookRevisionConflictOrNotFound(ctx, tenantID, id, expectedRevision)
	}
	return nil
}

func (j *Journal) MarkCommandAutomationWebhookFired(ctx context.Context, tenantID, id string) error {
	tenantID = normalizeCommandWebhookTenant(tenantID)
	now := j.now()
	_, err := j.db.ExecContext(ctx, j.bind(`UPDATE command_automation_webhook_triggers SET last_fired_at = $1, last_error = NULL, revision = revision + 1, updated_at = $2 WHERE id = $3 AND tenant_id = $4 AND EXISTS (SELECT 1 FROM command_automations a WHERE a.id = command_automation_webhook_triggers.automation_id AND a.tenant_id = command_automation_webhook_triggers.tenant_id)`), now, now, id, tenantID)
	return err
}

func (j *Journal) MarkCommandAutomationWebhookError(ctx context.Context, tenantID, id, message string) error {
	tenantID = normalizeCommandWebhookTenant(tenantID)
	message = strings.TrimSpace(message)
	if len(message) > MaxCommandErrorBytes {
		message = message[:MaxCommandErrorBytes]
	}
	_, err := j.db.ExecContext(ctx, j.bind(`UPDATE command_automation_webhook_triggers SET last_error = $1, revision = revision + 1, updated_at = $2 WHERE id = $3 AND tenant_id = $4 AND EXISTS (SELECT 1 FROM command_automations a WHERE a.id = command_automation_webhook_triggers.automation_id AND a.tenant_id = command_automation_webhook_triggers.tenant_id)`), nullable(message), j.now(), id, tenantID)
	return err
}

func (j *Journal) commandAutomationWebhookRevisionConflictOrNotFound(ctx context.Context, tenantID, id string, expected int64) error {
	var current int64
	err := j.db.QueryRowContext(ctx, j.bind(`SELECT revision FROM command_automation_webhook_triggers WHERE tenant_id = $1 AND id = $2`), tenantID, id).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: expected %d, current %d", ErrCommandAutomationWebhookRevisionConflict, expected, current)
}

func commandAutomationWebhookSelect() string {
	return `SELECT w.id, w.tenant_id, w.automation_id, w.automation_version, w.definition_sha256,
		w.receipt_id, w.gate_digest, w.actor_id, w.token_id, w.secret_id, w.provider, w.state, w.revision,
		w.last_fired_at, w.last_error, w.created_at, w.updated_at, w.idempotency_key, w.idempotency_hash
		FROM command_automation_webhook_triggers w JOIN command_automations a ON a.id = w.automation_id AND a.tenant_id = w.tenant_id`
}

func (j *Journal) scanCommandAutomationWebhook(scan func(...any) error) (CommandAutomationWebhookTrigger, error) {
	var row CommandAutomationWebhookTrigger
	var lastFired, lastError, created, updated, ignoredKey, ignoredHash any
	if err := scan(&row.ID, &row.TenantID, &row.AutomationID, &row.AutomationVersion, &row.DefinitionSHA256, &row.ReceiptID, &row.GateDigest, &row.ActorID, &row.TokenID, &row.SecretID, &row.Provider, &row.State, &row.Revision, &lastFired, &lastError, &created, &updated, &ignoredKey, &ignoredHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CommandAutomationWebhookTrigger{}, ErrNotFound
		}
		return CommandAutomationWebhookTrigger{}, fmt.Errorf("journal: scan command automation webhook: %w", err)
	}
	if t := j.anyTime(lastFired); !t.IsZero() {
		row.LastFiredAt = &t
	}
	row.LastError = anyToString(lastError)
	row.CreatedAt = j.anyTime(created)
	row.UpdatedAt = j.anyTime(updated)
	return row, nil
}

func commandAutomationWebhookScanArgs(row *CommandAutomationWebhookTrigger, key, hash *any) []any {
	var lastFired, lastError, created, updated any
	return []any{&row.ID, &row.TenantID, &row.AutomationID, &row.AutomationVersion, &row.DefinitionSHA256, &row.ReceiptID, &row.GateDigest, &row.ActorID, &row.TokenID, &row.SecretID, &row.Provider, &row.State, &row.Revision, &lastFired, &lastError, &created, &updated, key, hash}
}

func (j *Journal) getCommandAutomationWebhookByIdempotency(ctx context.Context, tenantID, key string) (CommandAutomationWebhookTrigger, string, error) {
	var row CommandAutomationWebhookTrigger
	var idKey, idHash any
	err := j.db.QueryRowContext(ctx, j.bind(commandAutomationWebhookSelect()+` WHERE w.tenant_id = $1 AND w.idempotency_key = $2`), tenantID, key).Scan(commandAutomationWebhookScanArgs(&row, &idKey, &idHash)...)
	if errors.Is(err, sql.ErrNoRows) {
		return row, "", ErrNotFound
	}
	if err != nil {
		return row, "", err
	}
	return row, anyToString(idHash), nil
}

func verifyCommandAutomationWebhookBindingTx(ctx context.Context, tx *sql.Tx, j *Journal, tenantID string, input CommandAutomationWebhookTriggerInput) error {
	raw, err := j.commandDefinitionTx(ctx, tx, tenantID, input.AutomationID, input.AutomationVersion)
	if err != nil {
		return fmt.Errorf("journal: resolve command automation webhook version: %w", err)
	}
	_, normalized, err := commandautomations.Normalize(raw)
	if err != nil {
		return fmt.Errorf("journal: normalize command automation webhook version: %w", err)
	}
	digest := sha256.Sum256(normalized)
	digestHex := hex.EncodeToString(digest[:])
	if input.DefinitionSHA256 != digestHex {
		return fmt.Errorf("%w: definition digest does not match immutable version", ErrCommandAutomationWebhookBindingMismatch)
	}
	if input.ReceiptID != commandautomations.ReceiptIDForGateDigest(tenantID, input.AutomationID, input.AutomationVersion, digestHex, input.GateDigest) {
		return ErrCommandAutomationWebhookBindingMismatch
	}
	return nil
}

func commandAutomationWebhookIdempotencyHash(input CommandAutomationWebhookTriggerInput) string {
	payload, _ := json.Marshal(struct {
		AutomationID string `json:"automation_id"`
		Version      int    `json:"version"`
		Definition   string `json:"definition_sha256"`
		Receipt      string `json:"receipt_id"`
		Gate         string `json:"gate_digest"`
		Actor        string `json:"actor_id"`
		Secret       string `json:"secret_id"`
		Provider     string `json:"provider"`
	}{input.AutomationID, input.AutomationVersion, input.DefinitionSHA256, input.ReceiptID, input.GateDigest, input.ActorID, input.SecretID, input.Provider})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func validateCommandAutomationWebhookInput(input CommandAutomationWebhookTriggerInput) error {
	if err := validateCommandWebhookText("id", input.ID, maxCommandWebhookID); err != nil {
		return err
	}
	if err := validateCommandWebhookText("automation_id", input.AutomationID, maxCommandWebhookID); err != nil {
		return err
	}
	if input.AutomationVersion < 1 {
		return errors.New("journal: command automation webhook version must be positive")
	}
	if err := validateCommandWebhookDigest("definition_sha256", input.DefinitionSHA256); err != nil {
		return err
	}
	if err := validateCommandWebhookDigest("gate_digest", input.GateDigest); err != nil {
		return err
	}
	if err := validateCommandWebhookText("receipt_id", input.ReceiptID, 512); err != nil {
		return err
	}
	if err := validateCommandWebhookText("actor_id", input.ActorID, maxCommandWebhookActor); err != nil {
		return err
	}
	if err := validateCommandWebhookText("token_id", input.TokenID, maxCommandWebhookToken); err != nil {
		return err
	}
	if !strings.HasPrefix(input.TokenID, "cmdwhk_") {
		return errors.New("journal: command automation webhook token must use cmdwhk_ prefix")
	}
	if err := validateCommandWebhookText("secret_id", input.SecretID, maxCommandWebhookSecret); err != nil {
		return err
	}
	if err := validateCommandWebhookText("provider", input.Provider, maxCommandWebhookProvider); err != nil {
		return err
	}
	return nil
}

func validateCommandWebhookDigest(name, value string) error {
	if err := validateCommandWebhookText(name, value, 64); err != nil {
		return err
	}
	if len(value) != 64 {
		return fmt.Errorf("journal: command automation webhook %s must be sha256", name)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("journal: command automation webhook %s must be hexadecimal", name)
	}
	return nil
}

func validateCommandWebhookText(name, value string, max int) error {
	if strings.TrimSpace(value) == "" || len(value) > max || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("journal: invalid command automation webhook %s", name)
	}
	return nil
}

func validateCommandAutomationWebhookState(state string) error {
	if state != CommandAutomationWebhookActive && state != CommandAutomationWebhookDisabled {
		return fmt.Errorf("%w: %q", ErrCommandAutomationWebhookState, state)
	}
	return nil
}

func normalizeCommandWebhookTenant(tenantID string) string {
	if tenantID = strings.TrimSpace(tenantID); tenantID != "" {
		return tenantID
	}
	return DefaultTenant
}
