package journal

// This file is the durable control-plane half of command-plan schedules. A
// schedule stores only a tenant-bound immutable plan/admission binding and
// cron metadata. It does not copy command text, credentials, or execution
// output. Runtime code must still re-check the current plan state before every
// fire; this journal layer only makes the authoring binding durable.

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
	CommandAutomationScheduleActive   = "active"
	CommandAutomationScheduleDisabled = "disabled"

	maxCommandAutomationScheduleID       = 128
	maxCommandAutomationScheduleSpec     = 256
	maxCommandAutomationScheduleTimezone = 128
	maxCommandAutomationScheduleActor    = 512
	maxCommandAutomationScheduleKey      = 200
)

var (
	// ErrCommandAutomationScheduleRevisionConflict means an authoring mutation
	// used a revision that is no longer current. Callers should re-read the
	// tenant-scoped schedule before retrying.
	ErrCommandAutomationScheduleRevisionConflict = errors.New("journal: command automation schedule revision conflict")
	// ErrCommandAutomationScheduleConflict means a schedule id or binding is
	// already occupied by another durable schedule.
	ErrCommandAutomationScheduleConflict = errors.New("journal: command automation schedule conflict")
	// ErrCommandAutomationScheduleBindingMismatch means a receipt/digest pair
	// does not bind the exact tenant, immutable plan version, and definition.
	ErrCommandAutomationScheduleBindingMismatch = errors.New("journal: command automation schedule admission binding mismatch")
	// ErrCommandAutomationScheduleState is returned for an unsupported state.
	ErrCommandAutomationScheduleState = errors.New("journal: invalid command automation schedule state")
	// ErrCommandAutomationScheduleActive prevents changing a live schedule's
	// immutable binding or cadence without an explicit disable mutation.
	ErrCommandAutomationScheduleActive = errors.New("journal: disable command automation schedule before editing it")
)

// CommandAutomationSchedule is a tenant-scoped cron binding for one exact
// immutable command-plan version. It deliberately contains no command text,
// credential values, or worker claim data.
type CommandAutomationSchedule struct {
	ID                string     `json:"id"`
	TenantID          string     `json:"tenant_id"`
	AutomationID      string     `json:"automation_id"`
	AutomationVersion int        `json:"automation_version"`
	DefinitionSHA256  string     `json:"definition_sha256"`
	ReceiptID         string     `json:"receipt_id"`
	GateDigest        string     `json:"gate_digest"`
	ActorID           string     `json:"actor_id"`
	Spec              string     `json:"spec"`
	Timezone          string     `json:"timezone"`
	State             string     `json:"state"`
	Revision          int64      `json:"revision"`
	LastFiredAt       *time.Time `json:"last_fired_at,omitempty"`
	LastError         string     `json:"last_error,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// CommandAutomationScheduleInput is the reviewed binding used to create a
// schedule. New schedules always start disabled; activation is a separate CAS
// mutation so a lost create response can never leave an unattended command
// firing before the caller has observed and approved the receipt.
type CommandAutomationScheduleInput struct {
	ID                string
	AutomationID      string
	AutomationVersion int
	DefinitionSHA256  string
	ReceiptID         string
	GateDigest        string
	ActorID           string
	Spec              string
	Timezone          string
}

// CommandAutomationScheduleUpdate replaces the immutable plan/admission
// binding and cron metadata under a schedule revision fence. The schedule id,
// tenant, and automation id remain fixed; changing to another plan requires a
// new schedule.
type CommandAutomationScheduleUpdate struct {
	AutomationVersion int
	DefinitionSHA256  string
	ReceiptID         string
	GateDigest        string
	ActorID           string
	Spec              string
	Timezone          string
}

// CommandAutomationScheduleFilter bounds a tenant-scoped schedule inventory.
// State and AutomationID are optional filters; page size is capped so a
// restored or hostile journal row cannot allocate an unbounded MCP response.
type CommandAutomationScheduleFilter struct {
	TenantID     string
	AutomationID string
	State        string
	Limit        int
	Offset       int
}

const maxCommandAutomationSchedulePage = 500

// CreateCommandAutomationSchedule creates one disabled schedule without a
// caller idempotency key.
func (j *Journal) CreateCommandAutomationSchedule(ctx context.Context, tenantID string, input CommandAutomationScheduleInput) (CommandAutomationSchedule, error) {
	schedule, _, err := j.CreateCommandAutomationScheduleWithIdempotency(ctx, tenantID, input, "")
	return schedule, err
}

// CreateCommandAutomationScheduleWithIdempotency creates one disabled schedule
// after verifying that the tenant owns the plan, the exact version is current,
// the immutable definition digest matches, and the admission receipt binds
// that digest. New rows are disabled until a separate state CAS is authorized.
// A retry with the same tenant-scoped key and exact
// payload returns the original schedule; a changed payload is rejected.
func (j *Journal) CreateCommandAutomationScheduleWithIdempotency(ctx context.Context, tenantID string, input CommandAutomationScheduleInput, key string) (schedule CommandAutomationSchedule, replay bool, err error) {
	tenantID = normalizeCommandScheduleTenant(tenantID)
	key = strings.TrimSpace(key)
	if key != "" {
		if err := validateCommandScheduleText("idempotency_key", key, maxCommandAutomationScheduleKey); err != nil {
			return CommandAutomationSchedule{}, false, err
		}
	}
	if strings.TrimSpace(input.ID) == "" {
		input.ID, err = newID("cmdsched_")
		if err != nil {
			return CommandAutomationSchedule{}, false, err
		}
	}
	if err := validateCommandAutomationScheduleInput(input); err != nil {
		return CommandAutomationSchedule{}, false, err
	}
	input.Timezone = normalizeCommandScheduleTimezone(input.Timezone)
	hash := commandAutomationScheduleIdempotencyHash(input)

	// Resolve a replay before taking the plan lock. A schedule remains an audit
	// receipt even if the plan is subsequently disabled, so a lost HTTP response
	// must still be recoverable by its original key.
	if key != "" {
		if existing, existingHash, lookupErr := j.getCommandAutomationScheduleByIdempotency(ctx, tenantID, key); lookupErr == nil {
			if existingHash != hash {
				return CommandAutomationSchedule{}, false, ErrCommandAutomationScheduleConflict
			}
			return existing, true, nil
		} else if !errors.Is(lookupErr, ErrNotFound) {
			return CommandAutomationSchedule{}, false, lookupErr
		}
	}

	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return CommandAutomationSchedule{}, false, fmt.Errorf("journal: begin command automation schedule create: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		// Acquire SQLite's writer lock before resolving the plan so a concurrent
		// disable/revision cannot cross this admission transaction.
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automations SET current_version = current_version WHERE id = $1 AND tenant_id = $2`), input.AutomationID, tenantID); err != nil {
			return CommandAutomationSchedule{}, false, fmt.Errorf("journal: lock command automation for schedule: %w", err)
		}
	}
	lockQ := `SELECT current_version, enabled FROM command_automations WHERE id = $1 AND tenant_id = $2`
	if j.engine == EnginePostgres {
		lockQ += ` FOR UPDATE`
	}
	var currentVersion int
	var enabled any
	if err := tx.QueryRowContext(ctx, j.bind(lockQ), input.AutomationID, tenantID).Scan(&currentVersion, &enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CommandAutomationSchedule{}, false, ErrNotFound
		}
		return CommandAutomationSchedule{}, false, fmt.Errorf("journal: resolve command automation for schedule: %w", err)
	}
	if currentVersion != input.AutomationVersion {
		return CommandAutomationSchedule{}, false, ErrCommandAutomationConflict
	}
	if err := verifyCommandAutomationScheduleBindingTx(ctx, tx, j, tenantID, input); err != nil {
		return CommandAutomationSchedule{}, false, err
	}

	now := j.now()
	insertQ := `INSERT INTO command_automation_schedules
		(id, tenant_id, automation_id, automation_version, definition_sha256, receipt_id, gate_digest, actor_id, spec, timezone, state, revision, idempotency_key, idempotency_hash, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1,$12,$13,$14,$15)
		ON CONFLICT DO NOTHING`
	storedHash := any(nil)
	if key != "" {
		storedHash = hash
	}
	res, err := tx.ExecContext(ctx, j.bind(insertQ), input.ID, tenantID, input.AutomationID, input.AutomationVersion, input.DefinitionSHA256, input.ReceiptID, input.GateDigest, input.ActorID, input.Spec, input.Timezone, CommandAutomationScheduleDisabled, nullable(key), storedHash, now, now)
	if err != nil {
		return CommandAutomationSchedule{}, false, fmt.Errorf("journal: create command automation schedule: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return CommandAutomationSchedule{}, false, fmt.Errorf("journal: create command automation schedule rows affected: %w", err)
	}
	if rows == 0 {
		// A concurrent caller may have won either the id or idempotency key.
		// Resolve only rows owned by this tenant and compare the full hash.
		var existing CommandAutomationSchedule
		var existingKey, existingHash any
		var scanErr error
		if key != "" {
			scanErr = tx.QueryRowContext(ctx, j.bind(commandAutomationScheduleSelect()+` WHERE s.tenant_id = $1 AND s.idempotency_key = $2`), tenantID, key).Scan(commandAutomationScheduleScanArgs(&existing, &existingKey, &existingHash)...)
		} else {
			scanErr = tx.QueryRowContext(ctx, j.bind(commandAutomationScheduleSelect()+` WHERE s.tenant_id = $1 AND s.id = $2`), tenantID, input.ID).Scan(commandAutomationScheduleScanArgs(&existing, &existingKey, &existingHash)...)
		}
		if scanErr == nil {
			if key != "" && anyToString(existingHash) == hash && anyToString(existingKey) == key {
				if err := tx.Commit(); err != nil {
					return CommandAutomationSchedule{}, false, fmt.Errorf("journal: commit command automation schedule replay: %w", err)
				}
				existing.TenantID = tenantID
				return existing, true, nil
			}
			return CommandAutomationSchedule{}, false, ErrCommandAutomationScheduleConflict
		}
		if errors.Is(scanErr, sql.ErrNoRows) {
			return CommandAutomationSchedule{}, false, ErrCommandAutomationScheduleConflict
		}
		return CommandAutomationSchedule{}, false, fmt.Errorf("journal: resolve command automation schedule conflict: %w", scanErr)
	}
	if err := tx.Commit(); err != nil {
		return CommandAutomationSchedule{}, false, fmt.Errorf("journal: commit command automation schedule: %w", err)
	}
	schedule = input.toSchedule(tenantID, now)
	schedule.State = CommandAutomationScheduleDisabled
	schedule.Revision = 1
	return schedule, false, nil
}

// GetCommandAutomationScheduleForTenant returns one schedule only when both
// the schedule and its referenced plan carry the requested tenant marker.
func (j *Journal) GetCommandAutomationScheduleForTenant(ctx context.Context, tenantID, id string) (CommandAutomationSchedule, error) {
	tenantID = normalizeCommandScheduleTenant(tenantID)
	if err := validateCommandScheduleID(id); err != nil {
		return CommandAutomationSchedule{}, err
	}
	row := j.db.QueryRowContext(ctx, j.bind(commandAutomationScheduleSelect()+` WHERE s.tenant_id = $1 AND s.id = $2`), tenantID, id)
	return j.scanCommandAutomationSchedule(row.Scan)
}

// ListCommandAutomationSchedulesForTenantPage returns one bounded schedule
// page with a lookahead flag. Filtering and joins remain tenant-fenced even if
// an old/restored database contains a schedule whose plan marker is stale.
func (j *Journal) ListCommandAutomationSchedulesForTenantPage(ctx context.Context, filter CommandAutomationScheduleFilter) ([]CommandAutomationSchedule, bool, error) {
	filter.TenantID = normalizeCommandScheduleTenant(filter.TenantID)
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > maxCommandAutomationSchedulePage {
		return nil, false, fmt.Errorf("journal: list command automation schedules: page limit exceeds %d", maxCommandAutomationSchedulePage)
	}
	if filter.Offset < 0 {
		return nil, false, errors.New("journal: list command automation schedules: negative offset")
	}
	if filter.AutomationID != "" {
		if err := validateCommandScheduleText("automation_id", filter.AutomationID, maxCommandAutomationScheduleID); err != nil {
			return nil, false, err
		}
	}
	if filter.State != "" {
		if err := validateCommandAutomationScheduleState(filter.State); err != nil {
			return nil, false, err
		}
	}
	where := []string{"s.tenant_id = $1", "s.tenant_id = a.tenant_id"}
	args := []any{filter.TenantID}
	if filter.AutomationID != "" {
		where = append(where, fmt.Sprintf("s.automation_id = $%d", len(args)+1))
		args = append(args, filter.AutomationID)
	}
	if filter.State != "" {
		where = append(where, fmt.Sprintf("s.state = $%d", len(args)+1))
		args = append(args, filter.State)
	}
	q := commandAutomationScheduleSelect() + " WHERE " + strings.Join(where, " AND ") + fmt.Sprintf(" ORDER BY s.created_at DESC, s.id ASC LIMIT %d OFFSET %d", filter.Limit+1, filter.Offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list command automation schedules: %w", err)
	}
	defer rows.Close()
	out := make([]CommandAutomationSchedule, 0, filter.Limit)
	for rows.Next() {
		schedule, scanErr := j.scanCommandAutomationSchedule(rows.Scan)
		if scanErr != nil {
			return nil, false, scanErr
		}
		out = append(out, schedule)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("journal: list command automation schedules rows: %w", err)
	}
	hasMore := len(out) > filter.Limit
	if hasMore {
		out = out[:filter.Limit]
	}
	return out, hasMore, nil
}

// UpdateCommandAutomationScheduleIfRevision replaces schedule metadata only
// when the tenant, schedule id, and revision all match. The referenced plan
// must still be enabled at the exact current version, and the new receipt must
// bind that immutable definition.
func (j *Journal) UpdateCommandAutomationScheduleIfRevision(ctx context.Context, tenantID, id string, update CommandAutomationScheduleUpdate, expectedRevision int64) error {
	tenantID = normalizeCommandScheduleTenant(tenantID)
	if expectedRevision < 1 {
		return errors.New("journal: command automation schedule revision must be positive")
	}
	if err := validateCommandScheduleID(id); err != nil {
		return err
	}
	if err := validateCommandAutomationScheduleUpdate(update); err != nil {
		return err
	}
	update.Timezone = normalizeCommandScheduleTimezone(update.Timezone)
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin command automation schedule update: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automation_schedules SET id = id WHERE id = $1 AND tenant_id = $2`), id, tenantID); err != nil {
			return fmt.Errorf("journal: lock command automation schedule update: %w", err)
		}
	}
	// Command-run admission locks the plan row before the trigger row. Keep
	// the same order here: an update that locked the trigger first could
	// deadlock with a concurrent admission transaction on Postgres.
	lockQ := `SELECT automation_id, state, revision FROM command_automation_schedules WHERE id = $1 AND tenant_id = $2`
	var automationID, scheduleState string
	var currentRevision int64
	if err := tx.QueryRowContext(ctx, j.bind(lockQ), id, tenantID).Scan(&automationID, &scheduleState, &currentRevision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: resolve command automation schedule update: %w", err)
	}
	if currentRevision != expectedRevision {
		return fmt.Errorf("%w: expected %d, current %d", ErrCommandAutomationScheduleRevisionConflict, expectedRevision, currentRevision)
	}
	if scheduleState != CommandAutomationScheduleDisabled {
		return ErrCommandAutomationScheduleActive
	}
	planLockQ := `SELECT current_version, enabled FROM command_automations WHERE id = $1 AND tenant_id = $2`
	if j.engine == EnginePostgres {
		planLockQ += ` FOR UPDATE`
	}
	var currentVersion int
	var enabled any
	if err := tx.QueryRowContext(ctx, j.bind(planLockQ), automationID, tenantID).Scan(&currentVersion, &enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: resolve command automation for schedule update: %w", err)
	}
	if !parseBool(enabled) {
		return ErrCommandAutomationEnabled
	}
	if currentVersion != update.AutomationVersion {
		return ErrCommandAutomationConflict
	}
	if j.engine == EnginePostgres {
		// Re-read and lock the trigger only after the plan lock. The first read
		// supplied the plan id; this second read is the CAS authority after any
		// concurrent revision/update waiting on the same plan row.
		var lockedAutomationID, lockedState string
		var lockedRevision int64
		if err := tx.QueryRowContext(ctx, j.bind(lockQ+` FOR UPDATE`), id, tenantID).Scan(&lockedAutomationID, &lockedState, &lockedRevision); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("journal: lock command automation schedule update: %w", err)
		}
		if lockedAutomationID != automationID || lockedRevision != expectedRevision {
			return fmt.Errorf("%w: expected %d, current %d", ErrCommandAutomationScheduleRevisionConflict, expectedRevision, lockedRevision)
		}
		if lockedState != CommandAutomationScheduleDisabled {
			return ErrCommandAutomationScheduleActive
		}
	}
	input := CommandAutomationScheduleInput{AutomationID: automationID, AutomationVersion: update.AutomationVersion, DefinitionSHA256: update.DefinitionSHA256, ReceiptID: update.ReceiptID, GateDigest: update.GateDigest, ActorID: update.ActorID, Spec: update.Spec, Timezone: update.Timezone}
	if err := verifyCommandAutomationScheduleBindingTx(ctx, tx, j, tenantID, input); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automation_schedules SET automation_version = $1, definition_sha256 = $2, receipt_id = $3, gate_digest = $4, actor_id = $5, spec = $6, timezone = $7, revision = revision + 1, updated_at = $8 WHERE id = $9 AND tenant_id = $10 AND revision = $11`), update.AutomationVersion, update.DefinitionSHA256, update.ReceiptID, update.GateDigest, update.ActorID, update.Spec, update.Timezone, j.now(), id, tenantID, expectedRevision)
	if err != nil {
		return fmt.Errorf("journal: update command automation schedule: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: expected %d", ErrCommandAutomationScheduleRevisionConflict, expectedRevision)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit command automation schedule update: %w", err)
	}
	return nil
}

// SetCommandAutomationScheduleStateIfRevision changes a schedule state under
// an optimistic revision fence. Re-enabling additionally requires that the
// referenced plan is still enabled and current and that the stored immutable
// definition/receipt binding still verifies; disabling remains an emergency
// stop and does not require plan readiness.
func (j *Journal) SetCommandAutomationScheduleStateIfRevision(ctx context.Context, tenantID, id, state string, expectedRevision int64) error {
	tenantID = normalizeCommandScheduleTenant(tenantID)
	if expectedRevision < 1 {
		return errors.New("journal: command automation schedule revision must be positive")
	}
	if err := validateCommandAutomationScheduleState(state); err != nil {
		return err
	}
	if err := validateCommandScheduleID(id); err != nil {
		return err
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin command automation schedule state: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automation_schedules SET id = id WHERE id = $1 AND tenant_id = $2`), id, tenantID); err != nil {
			return fmt.Errorf("journal: lock command automation schedule state: %w", err)
		}
	}
	// Activation must acquire the plan lock before the trigger lock, matching
	// CreateCommandRun. Disabling remains an emergency trigger-only lock and
	// therefore does not participate in a reverse plan/trigger wait cycle.
	lockQ := `SELECT automation_id, automation_version, revision FROM command_automation_schedules WHERE id = $1 AND tenant_id = $2`
	if j.engine == EnginePostgres && state != CommandAutomationScheduleActive {
		lockQ += ` FOR UPDATE`
	}
	var automationID string
	var version int
	var currentRevision int64
	if err := tx.QueryRowContext(ctx, j.bind(lockQ), id, tenantID).Scan(&automationID, &version, &currentRevision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: resolve command automation schedule state: %w", err)
	}
	if currentRevision != expectedRevision {
		return fmt.Errorf("%w: expected %d, current %d", ErrCommandAutomationScheduleRevisionConflict, expectedRevision, currentRevision)
	}
	if state == CommandAutomationScheduleActive {
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
			return fmt.Errorf("journal: resolve command automation schedule plan state: %w", err)
		}
		if !parseBool(enabled) {
			return ErrCommandAutomationEnabled
		}
		if currentVersion != version {
			return ErrCommandAutomationConflict
		}
		var lockedAutomationID, lockedDefinitionSHA256, lockedReceiptID, lockedGateDigest string
		var lockedVersion int
		var lockedRevision int64
		triggerLockQ := `SELECT automation_id, automation_version, definition_sha256, receipt_id, gate_digest, revision FROM command_automation_schedules WHERE id = $1 AND tenant_id = $2`
		if j.engine == EnginePostgres {
			triggerLockQ += ` FOR UPDATE`
		}
		if err := tx.QueryRowContext(ctx, j.bind(triggerLockQ), id, tenantID).Scan(&lockedAutomationID, &lockedVersion, &lockedDefinitionSHA256, &lockedReceiptID, &lockedGateDigest, &lockedRevision); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("journal: lock command automation schedule state: %w", err)
		}
		if lockedAutomationID != automationID || lockedVersion != version || lockedRevision != expectedRevision {
			return fmt.Errorf("%w: expected %d, current %d", ErrCommandAutomationScheduleRevisionConflict, expectedRevision, lockedRevision)
		}
		// The MCP activation path also evaluates current capabilities, but the
		// journal is the final authority for every state transition. Recompute
		// the immutable definition binding here so a repaired/imported row with
		// a stale digest or receipt cannot be activated through a direct journal
		// caller.
		if err := verifyCommandAutomationScheduleBindingTx(ctx, tx, j, tenantID, CommandAutomationScheduleInput{
			AutomationID: automationID, AutomationVersion: version,
			DefinitionSHA256: lockedDefinitionSHA256, ReceiptID: lockedReceiptID, GateDigest: lockedGateDigest,
		}); err != nil {
			return err
		}
	}
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automation_schedules SET state = $1, revision = revision + 1, updated_at = $2 WHERE id = $3 AND tenant_id = $4 AND revision = $5`), state, j.now(), id, tenantID, expectedRevision)
	if err != nil {
		return fmt.Errorf("journal: set command automation schedule state: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: expected %d", ErrCommandAutomationScheduleRevisionConflict, expectedRevision)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit command automation schedule state: %w", err)
	}
	return nil
}

// DeleteCommandAutomationScheduleIfRevision removes one schedule only when
// the tenant and opaque control-plane revision still match.
func (j *Journal) DeleteCommandAutomationScheduleIfRevision(ctx context.Context, tenantID, id string, expectedRevision int64) error {
	tenantID = normalizeCommandScheduleTenant(tenantID)
	if expectedRevision < 1 {
		return errors.New("journal: command automation schedule revision must be positive")
	}
	if err := validateCommandScheduleID(id); err != nil {
		return err
	}
	res, err := j.db.ExecContext(ctx, j.bind(`DELETE FROM command_automation_schedules WHERE id = $1 AND tenant_id = $2 AND revision = $3`), id, tenantID, expectedRevision)
	if err != nil {
		return fmt.Errorf("journal: delete command automation schedule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	return j.commandAutomationScheduleRevisionConflictOrNotFound(ctx, tenantID, id, expectedRevision)
}

// MarkCommandAutomationScheduleFired records the last successful dispatch
// without changing the schedule binding. The tenant and referenced-plan
// predicates keep a legacy/imported row from being updated across tenants.
func (j *Journal) MarkCommandAutomationScheduleFired(ctx context.Context, tenantID, id string) error {
	tenantID = normalizeCommandScheduleTenant(tenantID)
	now := j.now()
	res, err := j.db.ExecContext(ctx, j.bind(`UPDATE command_automation_schedules SET last_fired_at = $1, last_error = NULL, revision = revision + 1, updated_at = $2 WHERE id = $3 AND tenant_id = $4 AND EXISTS (SELECT 1 FROM command_automations a WHERE a.id = command_automation_schedules.automation_id AND a.tenant_id = command_automation_schedules.tenant_id)`), now, now, id, tenantID)
	if err != nil {
		return fmt.Errorf("journal: mark command automation schedule fired: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

// CommandAutomationScheduleEventID is deterministic for one schedule and
// minute slot. The runtime captures the slot when the cron callback starts,
// before any potentially slow journal or queue work, so retries of that
// callback cannot mint a second run after crossing a wall-clock minute.
func CommandAutomationScheduleEventID(scheduleID string, slot time.Time) string {
	material := strings.Join([]string{"cmdsched-v1", strings.TrimSpace(scheduleID), slot.UTC().Truncate(time.Minute).Format(time.RFC3339)}, "\x00")
	sum := sha256.Sum256([]byte(material))
	return "cmdsched_event_" + hex.EncodeToString(sum[:16])
}

// MarkCommandAutomationScheduleError records a bounded operational error and
// leaves the schedule state unchanged. Runtime admission remains fail-closed;
// the next slot re-evaluates the current plan and receipt binding.
func (j *Journal) MarkCommandAutomationScheduleError(ctx context.Context, tenantID, id, message string) error {
	tenantID = normalizeCommandScheduleTenant(tenantID)
	message = strings.TrimSpace(message)
	if len(message) > 4096 {
		message = message[:4096]
	}
	now := j.now()
	res, err := j.db.ExecContext(ctx, j.bind(`UPDATE command_automation_schedules SET last_error = $1, revision = revision + 1, updated_at = $2 WHERE id = $3 AND tenant_id = $4 AND EXISTS (SELECT 1 FROM command_automations a WHERE a.id = command_automation_schedules.automation_id AND a.tenant_id = command_automation_schedules.tenant_id)`), nullable(message), now, id, tenantID)
	if err != nil {
		return fmt.Errorf("journal: mark command automation schedule error: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

func (j *Journal) commandAutomationScheduleRevisionConflictOrNotFound(ctx context.Context, tenantID, id string, expectedRevision int64) error {
	var current int64
	err := j.db.QueryRowContext(ctx, j.bind(`SELECT s.revision FROM command_automation_schedules s JOIN command_automations a ON a.id = s.automation_id AND a.tenant_id = s.tenant_id WHERE s.tenant_id = $1 AND s.id = $2`), tenantID, id).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("journal: read command automation schedule revision: %w", err)
	}
	return fmt.Errorf("%w: expected %d, current %d", ErrCommandAutomationScheduleRevisionConflict, expectedRevision, current)
}

func commandAutomationScheduleSelect() string {
	return `SELECT s.id, s.tenant_id, s.automation_id, s.automation_version, s.definition_sha256,
		s.receipt_id, s.gate_digest, s.actor_id, s.spec, s.timezone, s.state, s.revision,
		s.last_fired_at, s.last_error, s.created_at, s.updated_at, s.idempotency_key, s.idempotency_hash
		FROM command_automation_schedules s JOIN command_automations a ON a.id = s.automation_id AND a.tenant_id = s.tenant_id`
}

func (j *Journal) scanCommandAutomationSchedule(scan func(...any) error) (CommandAutomationSchedule, error) {
	var (
		schedule                        CommandAutomationSchedule
		lastFired, lastError            any
		created, updated                any
		idempotencyKey, idempotencyHash any
	)
	if err := scan(&schedule.ID, &schedule.TenantID, &schedule.AutomationID, &schedule.AutomationVersion, &schedule.DefinitionSHA256,
		&schedule.ReceiptID, &schedule.GateDigest, &schedule.ActorID, &schedule.Spec, &schedule.Timezone, &schedule.State, &schedule.Revision,
		&lastFired, &lastError, &created, &updated, &idempotencyKey, &idempotencyHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CommandAutomationSchedule{}, ErrNotFound
		}
		return CommandAutomationSchedule{}, fmt.Errorf("journal: scan command automation schedule: %w", err)
	}
	if t := j.anyTime(lastFired); !t.IsZero() {
		schedule.LastFiredAt = &t
	}
	schedule.LastError = anyToString(lastError)
	schedule.CreatedAt = j.anyTime(created)
	schedule.UpdatedAt = j.anyTime(updated)
	return schedule, nil
}

func commandAutomationScheduleScanArgs(schedule *CommandAutomationSchedule, idempotencyKey, idempotencyHash *any) []any {
	var lastFired, lastError, created, updated any
	return []any{&schedule.ID, &schedule.TenantID, &schedule.AutomationID, &schedule.AutomationVersion, &schedule.DefinitionSHA256,
		&schedule.ReceiptID, &schedule.GateDigest, &schedule.ActorID, &schedule.Spec, &schedule.Timezone, &schedule.State, &schedule.Revision,
		&lastFired, &lastError, &created, &updated, idempotencyKey, idempotencyHash}
}

func (j *Journal) getCommandAutomationScheduleByIdempotency(ctx context.Context, tenantID, key string) (CommandAutomationSchedule, string, error) {
	var idempotencyKey, idempotencyHash any
	var schedule CommandAutomationSchedule
	var lastFired, lastError, created, updated any
	row := j.db.QueryRowContext(ctx, j.bind(commandAutomationScheduleSelect()+` WHERE s.tenant_id = $1 AND s.idempotency_key = $2`), tenantID, key)
	if err := row.Scan(&schedule.ID, &schedule.TenantID, &schedule.AutomationID, &schedule.AutomationVersion, &schedule.DefinitionSHA256,
		&schedule.ReceiptID, &schedule.GateDigest, &schedule.ActorID, &schedule.Spec, &schedule.Timezone, &schedule.State, &schedule.Revision,
		&lastFired, &lastError, &created, &updated, &idempotencyKey, &idempotencyHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CommandAutomationSchedule{}, "", ErrNotFound
		}
		return CommandAutomationSchedule{}, "", fmt.Errorf("journal: get command automation schedule idempotency: %w", err)
	}
	if t := j.anyTime(lastFired); !t.IsZero() {
		schedule.LastFiredAt = &t
	}
	schedule.LastError = anyToString(lastError)
	schedule.CreatedAt = j.anyTime(created)
	schedule.UpdatedAt = j.anyTime(updated)
	return schedule, anyToString(idempotencyHash), nil
}

func verifyCommandAutomationScheduleBindingTx(ctx context.Context, tx *sql.Tx, j *Journal, tenantID string, input CommandAutomationScheduleInput) error {
	raw, err := j.commandDefinitionTx(ctx, tx, tenantID, input.AutomationID, input.AutomationVersion)
	if err != nil {
		return fmt.Errorf("journal: resolve command automation schedule version: %w", err)
	}
	_, normalized, err := commandautomations.Normalize(raw)
	if err != nil {
		return fmt.Errorf("journal: normalize command automation schedule version: %w", err)
	}
	digest := sha256.Sum256(normalized)
	digestHex := hex.EncodeToString(digest[:])
	if input.DefinitionSHA256 != digestHex {
		return fmt.Errorf("%w: definition digest does not match immutable version", ErrCommandAutomationScheduleBindingMismatch)
	}
	if input.ReceiptID != commandautomations.ReceiptIDForGateDigest(tenantID, input.AutomationID, input.AutomationVersion, digestHex, input.GateDigest) {
		return ErrCommandAutomationScheduleBindingMismatch
	}
	return nil
}

func commandAutomationScheduleIdempotencyHash(input CommandAutomationScheduleInput) string {
	payload, _ := json.Marshal(struct {
		AutomationID      string `json:"automation_id"`
		AutomationVersion int    `json:"automation_version"`
		DefinitionSHA256  string `json:"definition_sha256"`
		ReceiptID         string `json:"receipt_id"`
		GateDigest        string `json:"gate_digest"`
		ActorID           string `json:"actor_id"`
		Spec              string `json:"spec"`
		Timezone          string `json:"timezone"`
	}{input.AutomationID, input.AutomationVersion, input.DefinitionSHA256, input.ReceiptID, input.GateDigest, input.ActorID, input.Spec, input.Timezone})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func (input CommandAutomationScheduleInput) toSchedule(tenantID string, now any) CommandAutomationSchedule {
	return CommandAutomationSchedule{
		ID: input.ID, TenantID: tenantID, AutomationID: input.AutomationID, AutomationVersion: input.AutomationVersion,
		DefinitionSHA256: input.DefinitionSHA256, ReceiptID: input.ReceiptID, GateDigest: input.GateDigest,
		ActorID: input.ActorID, Spec: input.Spec, Timezone: input.Timezone, State: CommandAutomationScheduleDisabled,
		Revision: 1, CreatedAt: timeFromJournalValue(now), UpdatedAt: timeFromJournalValue(now),
	}
}

func timeFromJournalValue(v any) time.Time {
	switch x := v.(type) {
	case time.Time:
		return x.UTC()
	case string:
		t, _ := time.Parse("2006-01-02T15:04:05.000Z", x)
		return t
	default:
		return time.Time{}
	}
}

func validateCommandAutomationScheduleInput(input CommandAutomationScheduleInput) error {
	if err := validateCommandScheduleID(input.ID); err != nil {
		return err
	}
	if err := validateCommandScheduleText("automation_id", input.AutomationID, maxCommandAutomationScheduleID); err != nil {
		return err
	}
	if input.AutomationVersion < 1 {
		return errors.New("journal: command automation schedule version must be positive")
	}
	if err := validateCommandScheduleDigest("definition_sha256", input.DefinitionSHA256); err != nil {
		return err
	}
	if err := validateCommandScheduleDigest("gate_digest", input.GateDigest); err != nil {
		return err
	}
	if err := validateCommandScheduleText("receipt_id", input.ReceiptID, 512); err != nil {
		return err
	}
	if err := validateCommandScheduleText("actor_id", input.ActorID, maxCommandAutomationScheduleActor); err != nil {
		return err
	}
	if err := validateCommandScheduleText("spec", input.Spec, maxCommandAutomationScheduleSpec); err != nil {
		return err
	}
	if input.Timezone != "" {
		if err := validateCommandScheduleText("timezone", input.Timezone, maxCommandAutomationScheduleTimezone); err != nil {
			return err
		}
	}
	return nil
}

func validateCommandAutomationScheduleUpdate(update CommandAutomationScheduleUpdate) error {
	return validateCommandAutomationScheduleInput(CommandAutomationScheduleInput{
		ID: "schedule-update", AutomationID: "schedule-update", AutomationVersion: update.AutomationVersion, DefinitionSHA256: update.DefinitionSHA256,
		ReceiptID: update.ReceiptID, GateDigest: update.GateDigest, ActorID: update.ActorID, Spec: update.Spec, Timezone: update.Timezone,
	})
}

func validateCommandScheduleID(id string) error {
	return validateCommandScheduleText("id", id, maxCommandAutomationScheduleID)
}

func validateCommandScheduleDigest(name, value string) error {
	if err := validateCommandScheduleText(name, value, 64); err != nil {
		return err
	}
	if len(value) != 64 {
		return fmt.Errorf("journal: command automation schedule %s must be sha256", name)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("journal: command automation schedule %s must be hexadecimal", name)
	}
	return nil
}

func validateCommandScheduleText(name, value string, max int) error {
	if strings.TrimSpace(value) == "" || len(value) > max || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("journal: invalid command automation schedule %s", name)
	}
	return nil
}

func validateCommandAutomationScheduleState(state string) error {
	if state != CommandAutomationScheduleActive && state != CommandAutomationScheduleDisabled {
		return fmt.Errorf("%w: %q", ErrCommandAutomationScheduleState, state)
	}
	return nil
}

func normalizeCommandScheduleTenant(tenantID string) string {
	if tenantID = strings.TrimSpace(tenantID); tenantID != "" {
		return tenantID
	}
	return DefaultTenant
}

func normalizeCommandScheduleTimezone(timezone string) string {
	if strings.TrimSpace(timezone) == "" {
		return "UTC"
	}
	return strings.TrimSpace(timezone)
}
