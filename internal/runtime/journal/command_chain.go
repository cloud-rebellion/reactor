package journal

// Durable command-plan terminal chains. These bindings intentionally live in
// their own table instead of `triggers`: workflow triggers carry a mandatory
// workflow_id and dispatch workflow artifacts, while a command chain must
// resolve an immutable command-plan version through the command-runner gates.
// The source workflow is an event identity only; its input and output are
// never copied into the command admission row.

import (
	"context"
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
	CommandAutomationChainActive   = "active"
	CommandAutomationChainDisabled = "disabled"

	maxCommandAutomationChainID     = 128
	maxCommandAutomationChainStatus = 128
	maxCommandAutomationChainActor  = 512
	maxCommandAutomationChainKey    = 200
	maxCommandAutomationChainPage   = 500
)

var (
	ErrCommandAutomationChainRevisionConflict = errors.New("journal: command automation chain revision conflict")
	ErrCommandAutomationChainConflict         = errors.New("journal: command automation chain conflict")
	ErrCommandAutomationChainBindingMismatch  = errors.New("journal: command automation chain admission binding mismatch")
	ErrCommandAutomationChainState            = errors.New("journal: invalid command automation chain state")
	ErrCommandAutomationChainActive           = errors.New("journal: disable command automation chain before editing or deleting it")
)

// CommandAutomationChainTrigger is the bounded, tenant-fenced projection used
// by the terminal hook. It contains only an exact immutable plan/admission
// binding and source workflow identity; command text, event payloads,
// credentials, and output are deliberately absent.
type CommandAutomationChainTrigger struct {
	ID                string     `json:"id"`
	TenantID          string     `json:"tenant_id"`
	AutomationID      string     `json:"automation_id"`
	AutomationVersion int        `json:"automation_version"`
	DefinitionSHA256  string     `json:"definition_sha256"`
	ReceiptID         string     `json:"receipt_id"`
	GateDigest        string     `json:"gate_digest"`
	ActorID           string     `json:"actor_id"`
	SourceWorkflowID  string     `json:"source_workflow_id"`
	OnStatuses        string     `json:"on_statuses"`
	State             string     `json:"state"`
	Revision          int64      `json:"revision"`
	LastFiredAt       *time.Time `json:"last_fired_at,omitempty"`
	LastError         string     `json:"last_error,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// CommandAutomationChainTriggerInput is the reviewed binding used at create
// time. New rows always start disabled; activation is a separate CAS mutation
// after the caller has observed the durable receipt.
type CommandAutomationChainTriggerInput struct {
	ID                string
	AutomationID      string
	AutomationVersion int
	DefinitionSHA256  string
	ReceiptID         string
	GateDigest        string
	ActorID           string
	SourceWorkflowID  string
	OnStatuses        string
}

type CommandAutomationChainTriggerUpdate struct {
	AutomationVersion int
	DefinitionSHA256  string
	ReceiptID         string
	GateDigest        string
	ActorID           string
	OnStatuses        string
}

type CommandAutomationChainTriggerFilter struct {
	TenantID       string
	AutomationID   string
	SourceWorkflow string
	State          string
	Limit          int
	Offset         int
}

// CreateCommandAutomationChainTrigger creates one disabled terminal-chain
// binding without a caller idempotency key.
func (j *Journal) CreateCommandAutomationChainTrigger(ctx context.Context, tenantID string, input CommandAutomationChainTriggerInput) (CommandAutomationChainTrigger, error) {
	row, _, err := j.CreateCommandAutomationChainTriggerWithIdempotency(ctx, tenantID, input, "")
	return row, err
}

// CreateCommandAutomationChainTriggerWithIdempotency creates or replays one
// disabled command-chain binding. Plan/version, definition digest, receipt,
// source workflow, and tenant are checked in one transaction. A key replay
// returns the original row only when every request field is identical.
func (j *Journal) CreateCommandAutomationChainTriggerWithIdempotency(ctx context.Context, tenantID string, input CommandAutomationChainTriggerInput, key string) (row CommandAutomationChainTrigger, replay bool, err error) {
	tenantID = normalizeCommandChainTenant(tenantID)
	key = strings.TrimSpace(key)
	if key != "" {
		if err := validateCommandChainText("idempotency_key", key, maxCommandAutomationChainKey); err != nil {
			return CommandAutomationChainTrigger{}, false, err
		}
	}
	if strings.TrimSpace(input.ID) == "" {
		input.ID, err = newID("cmdchain_")
		if err != nil {
			return CommandAutomationChainTrigger{}, false, err
		}
	}
	requestedStatuses := strings.TrimSpace(input.OnStatuses)
	input.OnStatuses = normalizeCommandChainStatuses(input.OnStatuses)
	if input.OnStatuses == "" {
		if requestedStatuses != "" {
			return CommandAutomationChainTrigger{}, false, errors.New("journal: invalid command automation chain on_statuses")
		}
		input.OnStatuses = "succeeded"
	}
	if err := validateCommandAutomationChainInput(input); err != nil {
		return CommandAutomationChainTrigger{}, false, err
	}
	hash := commandAutomationChainIdempotencyHash(input)
	if key != "" {
		if existing, existingHash, lookupErr := j.getCommandAutomationChainByIdempotency(ctx, tenantID, key); lookupErr == nil {
			if existingHash != hash {
				return CommandAutomationChainTrigger{}, false, ErrCommandAutomationChainConflict
			}
			return existing, true, nil
		} else if !errors.Is(lookupErr, ErrNotFound) {
			return CommandAutomationChainTrigger{}, false, lookupErr
		}
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return CommandAutomationChainTrigger{}, false, fmt.Errorf("journal: begin command automation chain create: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automations SET current_version = current_version WHERE id = $1 AND tenant_id = $2`), input.AutomationID, tenantID); err != nil {
			return CommandAutomationChainTrigger{}, false, fmt.Errorf("journal: lock command automation for chain: %w", err)
		}
	}
	lockQ := `SELECT current_version FROM command_automations WHERE id = $1 AND tenant_id = $2`
	if j.engine == EnginePostgres {
		lockQ += ` FOR UPDATE`
	}
	var currentVersion int
	if err := tx.QueryRowContext(ctx, j.bind(lockQ), input.AutomationID, tenantID).Scan(&currentVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CommandAutomationChainTrigger{}, false, ErrNotFound
		}
		return CommandAutomationChainTrigger{}, false, fmt.Errorf("journal: resolve command automation for chain: %w", err)
	}
	if currentVersion != input.AutomationVersion {
		return CommandAutomationChainTrigger{}, false, ErrCommandAutomationConflict
	}
	var sourceTenant string
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT tenant_id FROM workflows WHERE id = $1`), input.SourceWorkflowID).Scan(&sourceTenant); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CommandAutomationChainTrigger{}, false, ErrNotFound
		}
		return CommandAutomationChainTrigger{}, false, fmt.Errorf("journal: resolve command chain source workflow: %w", err)
	}
	if sourceTenant != tenantID {
		return CommandAutomationChainTrigger{}, false, ErrNotFound
	}
	if err := verifyCommandAutomationChainBindingTx(ctx, tx, j, tenantID, input); err != nil {
		return CommandAutomationChainTrigger{}, false, err
	}
	now := j.now()
	storedHash := any(nil)
	if key != "" {
		storedHash = hash
	}
	insertQ := `INSERT INTO command_automation_chain_triggers
		(id, tenant_id, automation_id, automation_version, definition_sha256, receipt_id, gate_digest, actor_id, source_workflow_id, on_statuses, state, revision, idempotency_key, idempotency_hash, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1,$12,$13,$14,$15)
		ON CONFLICT DO NOTHING`
	res, err := tx.ExecContext(ctx, j.bind(insertQ), input.ID, tenantID, input.AutomationID, input.AutomationVersion, input.DefinitionSHA256, input.ReceiptID, input.GateDigest, input.ActorID, input.SourceWorkflowID, input.OnStatuses, CommandAutomationChainDisabled, nullable(key), storedHash, now, now)
	if err != nil {
		return CommandAutomationChainTrigger{}, false, fmt.Errorf("journal: create command automation chain: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return CommandAutomationChainTrigger{}, false, fmt.Errorf("journal: create command automation chain rows affected: %w", err)
	}
	if n == 0 {
		var existing CommandAutomationChainTrigger
		var existingKey, existingHash any
		var lastFired, lastError, created, updated any
		lookupQ := commandAutomationChainSelect()
		if key != "" {
			lookupQ += ` WHERE c.tenant_id = $1 AND c.idempotency_key = $2`
		} else {
			lookupQ += ` WHERE c.tenant_id = $1 AND c.id = $2`
		}
		args := []any{tenantID}
		if key != "" {
			args = append(args, key)
		} else {
			args = append(args, input.ID)
		}
		scanArgs := []any{&existing.ID, &existing.TenantID, &existing.AutomationID, &existing.AutomationVersion, &existing.DefinitionSHA256, &existing.ReceiptID, &existing.GateDigest, &existing.ActorID, &existing.SourceWorkflowID, &existing.OnStatuses, &existing.State, &existing.Revision, &lastFired, &lastError, &created, &updated, &existingKey, &existingHash}
		if scanErr := tx.QueryRowContext(ctx, j.bind(lookupQ), args...).Scan(scanArgs...); scanErr == nil {
			if key != "" && anyToString(existingHash) == hash && anyToString(existingKey) == key {
				if err := tx.Commit(); err != nil {
					return CommandAutomationChainTrigger{}, false, fmt.Errorf("journal: commit command automation chain replay: %w", err)
				}
				existing.LastFiredAt = commandChainTimePtr(j.anyTime(lastFired))
				existing.LastError = anyToString(lastError)
				existing.CreatedAt = j.anyTime(created)
				existing.UpdatedAt = j.anyTime(updated)
				return existing, true, nil
			}
			return CommandAutomationChainTrigger{}, false, ErrCommandAutomationChainConflict
		} else if errors.Is(scanErr, sql.ErrNoRows) {
			return CommandAutomationChainTrigger{}, false, ErrCommandAutomationChainConflict
		} else {
			return CommandAutomationChainTrigger{}, false, fmt.Errorf("journal: resolve command automation chain conflict: %w", scanErr)
		}
	}
	if err := tx.Commit(); err != nil {
		return CommandAutomationChainTrigger{}, false, fmt.Errorf("journal: commit command automation chain: %w", err)
	}
	return input.toCommandAutomationChainTrigger(tenantID, now), false, nil
}

func (j *Journal) GetCommandAutomationChainTriggerForTenant(ctx context.Context, tenantID, id string) (CommandAutomationChainTrigger, error) {
	tenantID = normalizeCommandChainTenant(tenantID)
	if err := validateCommandAutomationChainID(id); err != nil {
		return CommandAutomationChainTrigger{}, err
	}
	row := j.db.QueryRowContext(ctx, j.bind(commandAutomationChainSelect()+` WHERE c.tenant_id = $1 AND c.id = $2 AND a.tenant_id = c.tenant_id AND src.tenant_id = c.tenant_id`), tenantID, id)
	return j.scanCommandAutomationChainTrigger(row.Scan)
}

// ListCommandAutomationChainTriggersForSource returns active rows only when
// the source workflow and referenced plan still carry the requested tenant.
// Status routing is done in SQL after normalising the bounded CSV in Go.
func (j *Journal) ListCommandAutomationChainTriggersForSource(ctx context.Context, tenantID, sourceWorkflowID, status string) ([]CommandAutomationChainTrigger, error) {
	tenantID = normalizeCommandChainTenant(tenantID)
	if err := validateCommandChainText("source_workflow_id", sourceWorkflowID, maxCommandAutomationChainID); err != nil {
		return nil, err
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if !commandAutomationChainStatusAllowed(status) {
		return nil, fmt.Errorf("journal: invalid command automation chain status")
	}
	q := commandAutomationChainSelect() + ` WHERE c.tenant_id = $1 AND c.state = $2 AND c.source_workflow_id = $3
		AND a.tenant_id = c.tenant_id AND src.tenant_id = c.tenant_id ORDER BY c.created_at ASC, c.id ASC`
	rows, err := j.db.QueryContext(ctx, j.bind(q), tenantID, CommandAutomationChainActive, sourceWorkflowID)
	if err != nil {
		return nil, fmt.Errorf("journal: list command automation chains for source: %w", err)
	}
	defer rows.Close()
	var out []CommandAutomationChainTrigger
	for rows.Next() {
		row, scanErr := j.scanCommandAutomationChainTrigger(rows.Scan)
		if scanErr != nil {
			return nil, scanErr
		}
		if commandAutomationChainStatusMatches(row.OnStatuses, status) {
			out = append(out, row)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("journal: list command automation chains for source rows: %w", err)
	}
	return out, nil
}

func (j *Journal) ListCommandAutomationChainTriggersForTenantPage(ctx context.Context, filter CommandAutomationChainTriggerFilter) ([]CommandAutomationChainTrigger, bool, error) {
	filter.TenantID = normalizeCommandChainTenant(filter.TenantID)
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > maxCommandAutomationChainPage {
		return nil, false, fmt.Errorf("journal: list command automation chains: page limit exceeds %d", maxCommandAutomationChainPage)
	}
	if filter.Offset < 0 {
		return nil, false, errors.New("journal: list command automation chains: negative offset")
	}
	where := []string{"c.tenant_id = $1", "a.tenant_id = c.tenant_id", "src.tenant_id = c.tenant_id"}
	args := []any{filter.TenantID}
	if filter.AutomationID != "" {
		if err := validateCommandChainText("automation_id", filter.AutomationID, maxCommandAutomationChainID); err != nil {
			return nil, false, err
		}
		where = append(where, fmt.Sprintf("c.automation_id = $%d", len(args)+1))
		args = append(args, filter.AutomationID)
	}
	if filter.SourceWorkflow != "" {
		if err := validateCommandChainText("source_workflow_id", filter.SourceWorkflow, maxCommandAutomationChainID); err != nil {
			return nil, false, err
		}
		where = append(where, fmt.Sprintf("c.source_workflow_id = $%d", len(args)+1))
		args = append(args, filter.SourceWorkflow)
	}
	if filter.State != "" {
		if err := validateCommandAutomationChainState(filter.State); err != nil {
			return nil, false, err
		}
		where = append(where, fmt.Sprintf("c.state = $%d", len(args)+1))
		args = append(args, filter.State)
	}
	q := commandAutomationChainSelect() + " WHERE " + strings.Join(where, " AND ") + fmt.Sprintf(" ORDER BY c.created_at DESC, c.id ASC LIMIT %d OFFSET %d", filter.Limit+1, filter.Offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list command automation chains: %w", err)
	}
	defer rows.Close()
	out := make([]CommandAutomationChainTrigger, 0, filter.Limit)
	for rows.Next() {
		row, scanErr := j.scanCommandAutomationChainTrigger(rows.Scan)
		if scanErr != nil {
			return nil, false, scanErr
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("journal: list command automation chains rows: %w", err)
	}
	hasMore := len(out) > filter.Limit
	if hasMore {
		out = out[:filter.Limit]
	}
	return out, hasMore, nil
}

func (j *Journal) UpdateCommandAutomationChainTriggerIfRevision(ctx context.Context, tenantID, id string, update CommandAutomationChainTriggerUpdate, expectedRevision int64) error {
	tenantID = normalizeCommandChainTenant(tenantID)
	if expectedRevision < 1 {
		return errors.New("journal: command automation chain revision must be positive")
	}
	requestedStatuses := strings.TrimSpace(update.OnStatuses)
	update.OnStatuses = normalizeCommandChainStatuses(update.OnStatuses)
	if update.OnStatuses == "" {
		if requestedStatuses != "" {
			return errors.New("journal: invalid command automation chain on_statuses")
		}
		update.OnStatuses = "succeeded"
	}
	if err := validateCommandAutomationChainUpdate(update); err != nil {
		return err
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin command automation chain update: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automation_chain_triggers SET id = id WHERE id = $1 AND tenant_id = $2`), id, tenantID); err != nil {
			return fmt.Errorf("journal: lock command automation chain update: %w", err)
		}
	}
	// Command-run admission locks the plan row before the trigger row. Keep
	// this update in that order on Postgres to avoid a plan/trigger deadlock
	// with a concurrent terminal admission.
	lockQ := `SELECT automation_id, state, revision, source_workflow_id FROM command_automation_chain_triggers WHERE id = $1 AND tenant_id = $2`
	var automationID, state, sourceID string
	var revision int64
	if err := tx.QueryRowContext(ctx, j.bind(lockQ), id, tenantID).Scan(&automationID, &state, &revision, &sourceID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: resolve command automation chain update: %w", err)
	}
	if revision != expectedRevision {
		return fmt.Errorf("%w: expected %d, current %d", ErrCommandAutomationChainRevisionConflict, expectedRevision, revision)
	}
	if state != CommandAutomationChainDisabled {
		return ErrCommandAutomationChainActive
	}
	var currentVersion int
	var enabled any
	planQ := `SELECT current_version, enabled FROM command_automations WHERE id = $1 AND tenant_id = $2`
	if j.engine == EnginePostgres {
		planQ += ` FOR UPDATE`
	}
	if err := tx.QueryRowContext(ctx, j.bind(planQ), automationID, tenantID).Scan(&currentVersion, &enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: resolve command automation chain plan: %w", err)
	}
	if !parseBool(enabled) {
		return ErrCommandAutomationEnabled
	}
	if currentVersion != update.AutomationVersion {
		return ErrCommandAutomationConflict
	}
	if j.engine == EnginePostgres {
		var lockedAutomationID, lockedState, lockedSourceID string
		var lockedRevision int64
		if err := tx.QueryRowContext(ctx, j.bind(lockQ+` FOR UPDATE`), id, tenantID).Scan(&lockedAutomationID, &lockedState, &lockedRevision, &lockedSourceID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("journal: lock command automation chain update: %w", err)
		}
		if lockedAutomationID != automationID || lockedSourceID != sourceID || lockedRevision != expectedRevision {
			return fmt.Errorf("%w: expected %d, current %d", ErrCommandAutomationChainRevisionConflict, expectedRevision, lockedRevision)
		}
		if lockedState != CommandAutomationChainDisabled {
			return ErrCommandAutomationChainActive
		}
	}
	input := CommandAutomationChainTriggerInput{AutomationID: automationID, AutomationVersion: update.AutomationVersion, DefinitionSHA256: update.DefinitionSHA256, ReceiptID: update.ReceiptID, GateDigest: update.GateDigest, ActorID: update.ActorID, SourceWorkflowID: sourceID, OnStatuses: update.OnStatuses}
	if err := verifyCommandAutomationChainBindingTx(ctx, tx, j, tenantID, input); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automation_chain_triggers SET automation_version = $1, definition_sha256 = $2, receipt_id = $3, gate_digest = $4, actor_id = $5, on_statuses = $6, revision = revision + 1, updated_at = $7 WHERE id = $8 AND tenant_id = $9 AND revision = $10`), update.AutomationVersion, update.DefinitionSHA256, update.ReceiptID, update.GateDigest, update.ActorID, update.OnStatuses, j.now(), id, tenantID, expectedRevision)
	if err != nil {
		return fmt.Errorf("journal: update command automation chain: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: expected %d", ErrCommandAutomationChainRevisionConflict, expectedRevision)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit command automation chain update: %w", err)
	}
	return nil
}

func (j *Journal) SetCommandAutomationChainTriggerStateIfRevision(ctx context.Context, tenantID, id, state string, expectedRevision int64) error {
	tenantID = normalizeCommandChainTenant(tenantID)
	if expectedRevision < 1 {
		return errors.New("journal: command automation chain revision must be positive")
	}
	if err := validateCommandAutomationChainState(state); err != nil {
		return err
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin command automation chain state: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automation_chain_triggers SET id = id WHERE id = $1 AND tenant_id = $2`), id, tenantID); err != nil {
			return fmt.Errorf("journal: lock command automation chain state: %w", err)
		}
	}
	// Activation follows the plan-then-trigger lock order used by admission;
	// disabling remains a trigger-only emergency stop.
	lockQ := `SELECT automation_id, automation_version, source_workflow_id, revision FROM command_automation_chain_triggers WHERE id = $1 AND tenant_id = $2`
	if j.engine == EnginePostgres && state != CommandAutomationChainActive {
		lockQ += ` FOR UPDATE`
	}
	var automationID, sourceID string
	var version int
	var revision int64
	if err := tx.QueryRowContext(ctx, j.bind(lockQ), id, tenantID).Scan(&automationID, &version, &sourceID, &revision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: resolve command automation chain state: %w", err)
	}
	if revision != expectedRevision {
		return fmt.Errorf("%w: expected %d, current %d", ErrCommandAutomationChainRevisionConflict, expectedRevision, revision)
	}
	if state == CommandAutomationChainActive {
		var currentVersion int
		var enabled any
		planQ := `SELECT current_version, enabled FROM command_automations WHERE id = $1 AND tenant_id = $2`
		if j.engine == EnginePostgres {
			planQ += ` FOR UPDATE`
		}
		if err := tx.QueryRowContext(ctx, j.bind(planQ), automationID, tenantID).Scan(&currentVersion, &enabled); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("journal: resolve command automation chain plan: %w", err)
		}
		if !parseBool(enabled) {
			return ErrCommandAutomationEnabled
		}
		if currentVersion != version {
			return ErrCommandAutomationConflict
		}
		triggerLockQ := `SELECT automation_id, automation_version, source_workflow_id, definition_sha256, receipt_id, gate_digest, revision FROM command_automation_chain_triggers WHERE id = $1 AND tenant_id = $2`
		if j.engine == EnginePostgres {
			triggerLockQ += ` FOR UPDATE`
		}
		var lockedAutomationID, lockedSourceID, lockedDefinitionSHA256, lockedReceiptID, lockedGateDigest string
		var lockedVersion int
		var lockedRevision int64
		if err := tx.QueryRowContext(ctx, j.bind(triggerLockQ), id, tenantID).Scan(&lockedAutomationID, &lockedVersion, &lockedSourceID, &lockedDefinitionSHA256, &lockedReceiptID, &lockedGateDigest, &lockedRevision); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("journal: lock command automation chain state: %w", err)
		}
		if lockedAutomationID != automationID || lockedVersion != version || lockedSourceID != sourceID || lockedRevision != expectedRevision {
			return fmt.Errorf("%w: expected %d, current %d", ErrCommandAutomationChainRevisionConflict, expectedRevision, lockedRevision)
		}
		// MCP activation checks the current capability and runtime gates. The
		// journal must still protect its own ACTIVE transition from stale or
		// imported bindings when called directly, so re-derive the immutable
		// definition digest and receipt identity before updating the row.
		if err := verifyCommandAutomationChainBindingTx(ctx, tx, j, tenantID, CommandAutomationChainTriggerInput{
			AutomationID: automationID, AutomationVersion: version,
			DefinitionSHA256: lockedDefinitionSHA256, ReceiptID: lockedReceiptID, GateDigest: lockedGateDigest,
			SourceWorkflowID: sourceID, OnStatuses: "succeeded",
		}); err != nil {
			return err
		}
		var sourceTenant string
		if err := tx.QueryRowContext(ctx, j.bind(`SELECT tenant_id FROM workflows WHERE id = $1`), sourceID).Scan(&sourceTenant); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if sourceTenant != tenantID {
			return ErrNotFound
		}
	}
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automation_chain_triggers SET state = $1, revision = revision + 1, updated_at = $2 WHERE id = $3 AND tenant_id = $4 AND revision = $5`), state, j.now(), id, tenantID, expectedRevision)
	if err != nil {
		return fmt.Errorf("journal: set command automation chain state: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: expected %d", ErrCommandAutomationChainRevisionConflict, expectedRevision)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit command automation chain state: %w", err)
	}
	return nil
}

func (j *Journal) DeleteCommandAutomationChainTriggerIfRevision(ctx context.Context, tenantID, id string, expectedRevision int64) error {
	tenantID = normalizeCommandChainTenant(tenantID)
	if expectedRevision < 1 {
		return errors.New("journal: command automation chain revision must be positive")
	}
	if err := validateCommandAutomationChainID(id); err != nil {
		return err
	}
	var state string
	if err := j.db.QueryRowContext(ctx, j.bind(`SELECT state FROM command_automation_chain_triggers WHERE id = $1 AND tenant_id = $2`), id, tenantID).Scan(&state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if state != CommandAutomationChainDisabled {
		return ErrCommandAutomationChainActive
	}
	res, err := j.db.ExecContext(ctx, j.bind(`DELETE FROM command_automation_chain_triggers WHERE id = $1 AND tenant_id = $2 AND revision = $3`), id, tenantID, expectedRevision)
	if err != nil {
		return fmt.Errorf("journal: delete command automation chain: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	var current int64
	err = j.db.QueryRowContext(ctx, j.bind(`SELECT revision FROM command_automation_chain_triggers WHERE id = $1 AND tenant_id = $2`), id, tenantID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: expected %d, current %d", ErrCommandAutomationChainRevisionConflict, expectedRevision, current)
}

func (j *Journal) MarkCommandAutomationChainTriggerFired(ctx context.Context, tenantID, id string) error {
	return j.markCommandAutomationChainTrigger(ctx, tenantID, id, "")
}

func (j *Journal) MarkCommandAutomationChainTriggerError(ctx context.Context, tenantID, id, message string) error {
	message = strings.TrimSpace(message)
	if len(message) > 4096 {
		message = message[:4096]
	}
	return j.markCommandAutomationChainTrigger(ctx, tenantID, id, message)
}

func (j *Journal) markCommandAutomationChainTrigger(ctx context.Context, tenantID, id, message string) error {
	tenantID = normalizeCommandChainTenant(tenantID)
	now := j.now()
	var q string
	var args []any
	if message == "" {
		q = `UPDATE command_automation_chain_triggers SET last_fired_at = $1, last_error = NULL, revision = revision + 1, updated_at = $2 WHERE id = $3 AND tenant_id = $4 AND state = 'active' AND EXISTS (SELECT 1 FROM command_automations a JOIN workflows src ON src.tenant_id = a.tenant_id WHERE a.id = command_automation_chain_triggers.automation_id AND a.tenant_id = command_automation_chain_triggers.tenant_id AND src.id = command_automation_chain_triggers.source_workflow_id AND src.tenant_id = command_automation_chain_triggers.tenant_id)`
		args = []any{now, now, id, tenantID}
	} else {
		q = `UPDATE command_automation_chain_triggers SET last_error = $1, revision = revision + 1, updated_at = $2 WHERE id = $3 AND tenant_id = $4 AND EXISTS (SELECT 1 FROM command_automations a JOIN workflows src ON src.tenant_id = a.tenant_id WHERE a.id = command_automation_chain_triggers.automation_id AND a.tenant_id = command_automation_chain_triggers.tenant_id AND src.id = command_automation_chain_triggers.source_workflow_id AND src.tenant_id = command_automation_chain_triggers.tenant_id)`
		args = []any{nullable(message), now, id, tenantID}
	}
	res, err := j.db.ExecContext(ctx, j.bind(q), args...)
	if err != nil {
		return fmt.Errorf("journal: mark command automation chain: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

// CommandAutomationChainEventID is deterministic for one source run and
// terminal status. It is safe to retry the terminal hook after a crash: every
// retry presents the same trigger/event pair to command-run admission.
func CommandAutomationChainEventID(triggerID, sourceRunID, status string) string {
	material := strings.Join([]string{"cmdchain-v1", triggerID, sourceRunID, strings.ToLower(strings.TrimSpace(status))}, "\x00")
	sum := sha256.Sum256([]byte(material))
	return "cmdchain_event_" + hex.EncodeToString(sum[:16])
}

func commandAutomationChainSelect() string {
	return `SELECT c.id, c.tenant_id, c.automation_id, c.automation_version, c.definition_sha256,
		c.receipt_id, c.gate_digest, c.actor_id, c.source_workflow_id, c.on_statuses, c.state, c.revision,
		c.last_fired_at, c.last_error, c.created_at, c.updated_at, c.idempotency_key, c.idempotency_hash
		FROM command_automation_chain_triggers c
		JOIN command_automations a ON a.id = c.automation_id AND a.tenant_id = c.tenant_id
		JOIN workflows src ON src.id = c.source_workflow_id AND src.tenant_id = c.tenant_id`
}

func (j *Journal) scanCommandAutomationChainTrigger(scan func(...any) error) (CommandAutomationChainTrigger, error) {
	var row CommandAutomationChainTrigger
	var lastFired, lastError, created, updated, key, hash any
	if err := scan(&row.ID, &row.TenantID, &row.AutomationID, &row.AutomationVersion, &row.DefinitionSHA256, &row.ReceiptID, &row.GateDigest, &row.ActorID, &row.SourceWorkflowID, &row.OnStatuses, &row.State, &row.Revision, &lastFired, &lastError, &created, &updated, &key, &hash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CommandAutomationChainTrigger{}, ErrNotFound
		}
		return CommandAutomationChainTrigger{}, fmt.Errorf("journal: scan command automation chain: %w", err)
	}
	row.LastFiredAt = commandChainTimePtr(j.anyTime(lastFired))
	row.LastError = anyToString(lastError)
	row.CreatedAt = j.anyTime(created)
	row.UpdatedAt = j.anyTime(updated)
	return row, nil
}

func (j *Journal) getCommandAutomationChainByIdempotency(ctx context.Context, tenantID, key string) (CommandAutomationChainTrigger, string, error) {
	row := j.db.QueryRowContext(ctx, j.bind(commandAutomationChainSelect()+` WHERE c.tenant_id = $1 AND c.idempotency_key = $2 AND a.tenant_id = c.tenant_id AND src.tenant_id = c.tenant_id`), tenantID, key)
	var out CommandAutomationChainTrigger
	var lastFired, lastError, created, updated, storedKey, hash any
	if err := row.Scan(&out.ID, &out.TenantID, &out.AutomationID, &out.AutomationVersion, &out.DefinitionSHA256, &out.ReceiptID, &out.GateDigest, &out.ActorID, &out.SourceWorkflowID, &out.OnStatuses, &out.State, &out.Revision, &lastFired, &lastError, &created, &updated, &storedKey, &hash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CommandAutomationChainTrigger{}, "", ErrNotFound
		}
		return CommandAutomationChainTrigger{}, "", fmt.Errorf("journal: get command automation chain idempotency: %w", err)
	}
	out.LastFiredAt = commandChainTimePtr(j.anyTime(lastFired))
	out.LastError = anyToString(lastError)
	out.CreatedAt = j.anyTime(created)
	out.UpdatedAt = j.anyTime(updated)
	return out, anyToString(hash), nil
}

func verifyCommandAutomationChainBindingTx(ctx context.Context, tx *sql.Tx, j *Journal, tenantID string, input CommandAutomationChainTriggerInput) error {
	raw, err := j.commandDefinitionTx(ctx, tx, tenantID, input.AutomationID, input.AutomationVersion)
	if err != nil {
		return fmt.Errorf("journal: resolve command automation chain version: %w", err)
	}
	// Definitions are normalised before digesting everywhere else in the
	// command-run path. Keep this binding byte-for-byte consistent.
	_, canonical, err := commandautomations.Normalize(raw)
	if err != nil {
		return fmt.Errorf("journal: normalize command automation chain version: %w", err)
	}
	digest := sha256.Sum256(canonical)
	digestHex := hex.EncodeToString(digest[:])
	if input.DefinitionSHA256 != digestHex {
		return fmt.Errorf("%w: definition digest does not match immutable version", ErrCommandAutomationChainBindingMismatch)
	}
	if input.ReceiptID != commandautomations.ReceiptIDForGateDigest(tenantID, input.AutomationID, input.AutomationVersion, digestHex, input.GateDigest) {
		return ErrCommandAutomationChainBindingMismatch
	}
	return nil
}

func commandAutomationChainIdempotencyHash(input CommandAutomationChainTriggerInput) string {
	payload, _ := json.Marshal(struct {
		AutomationID string `json:"automation_id"`
		Version      int    `json:"automation_version"`
		Definition   string `json:"definition_sha256"`
		Receipt      string `json:"receipt_id"`
		Gate         string `json:"gate_digest"`
		Actor        string `json:"actor_id"`
		Source       string `json:"source_workflow_id"`
		Statuses     string `json:"on_statuses"`
	}{input.AutomationID, input.AutomationVersion, input.DefinitionSHA256, input.ReceiptID, input.GateDigest, input.ActorID, input.SourceWorkflowID, input.OnStatuses})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func (input CommandAutomationChainTriggerInput) toCommandAutomationChainTrigger(tenantID string, now any) CommandAutomationChainTrigger {
	t := timeFromJournalValue(now)
	return CommandAutomationChainTrigger{ID: input.ID, TenantID: tenantID, AutomationID: input.AutomationID, AutomationVersion: input.AutomationVersion, DefinitionSHA256: input.DefinitionSHA256, ReceiptID: input.ReceiptID, GateDigest: input.GateDigest, ActorID: input.ActorID, SourceWorkflowID: input.SourceWorkflowID, OnStatuses: input.OnStatuses, State: CommandAutomationChainDisabled, Revision: 1, CreatedAt: t, UpdatedAt: t}
}

func validateCommandAutomationChainInput(input CommandAutomationChainTriggerInput) error {
	if err := validateCommandAutomationChainID(input.ID); err != nil {
		return err
	}
	for name, value := range map[string]string{"automation_id": input.AutomationID, "source_workflow_id": input.SourceWorkflowID, "actor_id": input.ActorID} {
		limit := maxCommandAutomationChainID
		if name == "actor_id" {
			limit = maxCommandAutomationChainActor
		}
		if err := validateCommandChainText(name, value, limit); err != nil {
			return err
		}
	}
	if input.AutomationVersion < 1 {
		return errors.New("journal: command automation chain version must be positive")
	}
	for name, value := range map[string]string{"definition_sha256": input.DefinitionSHA256, "gate_digest": input.GateDigest} {
		if len(value) != 64 {
			return fmt.Errorf("journal: command automation chain %s must be sha256", name)
		}
		if _, err := hex.DecodeString(value); err != nil {
			return fmt.Errorf("journal: command automation chain %s must be hexadecimal", name)
		}
	}
	if err := validateCommandChainText("receipt_id", input.ReceiptID, 512); err != nil {
		return err
	}
	if len(input.OnStatuses) > maxCommandAutomationChainStatus || !commandAutomationChainStatusesValid(input.OnStatuses) {
		return errors.New("journal: invalid command automation chain on_statuses")
	}
	return nil
}

func validateCommandAutomationChainUpdate(update CommandAutomationChainTriggerUpdate) error {
	return validateCommandAutomationChainInput(CommandAutomationChainTriggerInput{ID: "chain-update", AutomationID: "chain-update", AutomationVersion: update.AutomationVersion, DefinitionSHA256: update.DefinitionSHA256, ReceiptID: update.ReceiptID, GateDigest: update.GateDigest, ActorID: update.ActorID, SourceWorkflowID: "source", OnStatuses: update.OnStatuses})
}

func validateCommandAutomationChainState(state string) error {
	if state != CommandAutomationChainActive && state != CommandAutomationChainDisabled {
		return fmt.Errorf("%w: %q", ErrCommandAutomationChainState, state)
	}
	return nil
}

func validateCommandAutomationChainID(id string) error {
	return validateCommandChainText("id", id, maxCommandAutomationChainID)
}

func validateCommandChainText(name, value string, max int) error {
	if strings.TrimSpace(value) == "" || len(value) > max || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("journal: invalid command automation chain %s", name)
	}
	return nil
}

func normalizeCommandChainTenant(tenantID string) string {
	if tenantID = strings.TrimSpace(tenantID); tenantID != "" {
		return tenantID
	}
	return DefaultTenant
}

func normalizeCommandChainStatuses(statuses string) string {
	parts := strings.Split(statuses, ",")
	seen := map[string]bool{}
	var out []string
	for _, part := range parts {
		status := strings.ToLower(strings.TrimSpace(part))
		if status == "" || seen[status] {
			continue
		}
		if !commandAutomationChainStatusAllowed(status) {
			return ""
		}
		seen[status] = true
		out = append(out, status)
	}
	return strings.Join(sortStrings(out), ",")
}

func commandAutomationChainStatusAllowed(status string) bool {
	return status == "succeeded" || status == "failed" || status == "failed_dlq"
}

func commandAutomationChainStatusesValid(statuses string) bool {
	if strings.TrimSpace(statuses) == "" {
		return false
	}
	for _, status := range strings.Split(statuses, ",") {
		if !commandAutomationChainStatusAllowed(strings.TrimSpace(status)) {
			return false
		}
	}
	return true
}

func commandAutomationChainStatusMatches(statuses, status string) bool {
	for _, item := range strings.Split(statuses, ",") {
		if strings.TrimSpace(item) == status {
			return true
		}
	}
	return false
}

func commandChainTimePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	t = t.UTC()
	return &t
}
