package journal

// This file is the durable, non-executing half of the command runner
// contract. It records an immutable command-automation version, the gate
// receipt that admitted a run, worker leases, and bounded per-attempt output.
// There is deliberately no process launch here. The commandrunner package
// satisfies the gates and uses these fenced methods around its sandbox or
// external-agent transport.

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
	"github.com/bright-interaction/reactor/internal/knowledge"
	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

const (
	CommandRunQueued    = "queued"
	CommandRunRunning   = "running"
	CommandRunSucceeded = "succeeded"
	CommandRunFailed    = "failed"
	CommandRunCancelled = "cancelled"

	CommandRunStepPending   = "pending"
	CommandRunStepRunning   = "running"
	CommandRunStepSucceeded = "succeeded"
	CommandRunStepFailed    = "failed"
	CommandRunStepCancelled = "cancelled"

	// Command-run trigger kinds identify which durable trigger table owns the
	// admission provenance. Empty is reserved for interactive/manual runs;
	// legacy rows with TriggerID but no kind are treated as schedules.
	CommandRunTriggerSchedule = "schedule"
	CommandRunTriggerWebhook  = "webhook"
	CommandRunTriggerChain    = "chain"

	// Output is retained for inspection, but a command cannot use an
	// unbounded stream to exhaust the journal or MCP process memory.
	MaxCommandOutputBytes    = 1 << 20
	MaxCommandErrorBytes     = 16 << 10
	MaxCommandAdmissionBytes = 8 << 10
)

var (
	ErrCommandRunNotClaimable  = errors.New("journal: command run is not claimable")
	ErrCommandRunOwnershipLost = errors.New("journal: command run lease ownership lost")
	ErrCommandRunStepOrder     = errors.New("journal: command run step is out of order")
	ErrCommandRunInvalidState  = errors.New("journal: command run has an invalid state")
	// ErrCommandRunDefinitionMismatch means the admission receipt was minted
	// for a different immutable definition than the version requested for the
	// run. A runner must never be able to execute a stale receipt against
	// a newly revised plan.
	ErrCommandRunDefinitionMismatch = errors.New("journal: command run admission definition mismatch")
	ErrCommandRunBindingMismatch    = errors.New("journal: command run admission receipt binding mismatch")
	ErrCommandRunConflict           = errors.New("journal: command run id is already bound to a different admission")
	ErrCommandRunRetryNotTerminal   = errors.New("journal: command run retry source is not terminal")
	// ErrCommandRunRetryBindingMismatch prevents a retry lineage edge from
	// pointing at a terminal run belonging to a different immutable plan
	// version. Without this check a caller using the journal directly could
	// label an unrelated run as the source of a retry, corrupting audit
	// provenance even though MCP's higher-level path normally binds the two.
	ErrCommandRunRetryBindingMismatch = errors.New("journal: command run retry source does not match the requested automation version")
)

// CommandRunAdmission is a reference to an already-authenticated, step-up
// gate receipt. It contains no assertion, credential, or command text. The
// receipt must be resolved by the runner immediately before execution;
// storing this summary is only the audit link.
type CommandRunAdmission struct {
	ReceiptID        string `json:"receipt_id"`
	GateDigest       string `json:"gate_digest"`
	DefinitionSHA256 string `json:"definition_sha256"`
	ActorID          string `json:"actor_id"`
	TriggerKind      string `json:"trigger_kind,omitempty"`
	// TriggerID and TriggerEventID are bounded provenance for internally
	// scheduled admissions. They are metadata only; the scheduler still has to
	// bind the exact immutable version and receipt before a run is created.
	TriggerID      string `json:"trigger_id,omitempty"`
	TriggerEventID string `json:"trigger_event_id,omitempty"`
}

type CommandRun struct {
	ID                string              `json:"id"`
	TenantID          string              `json:"tenant_id"`
	AutomationID      string              `json:"automation_id"`
	AutomationVersion int                 `json:"automation_version"`
	DefinitionSHA256  string              `json:"definition_sha256"`
	Target            string              `json:"target"`
	ActorID           string              `json:"actor_id"`
	Admission         CommandRunAdmission `json:"admission"`
	RetryOf           string              `json:"retry_of,omitempty"`
	Status            string              `json:"status"`
	Attempt           int                 `json:"attempt"`
	ClaimOwner        string              `json:"claim_owner,omitempty"`
	ClaimToken        string              `json:"-"`
	LeaseExpiresAt    *time.Time          `json:"lease_expires_at,omitempty"`
	ErrorText         string              `json:"error_text,omitempty"`
	// ErrorBytes and ErrorTruncated are bounded read metadata. Legacy or
	// imported rows may contain an oversized parent error even though current
	// writes cap it; read projections omit that payload while retaining the
	// original byte count for an operator-safe receipt.
	ErrorBytes     int        `json:"-"`
	ErrorTruncated bool       `json:"-"`
	CreatedAt      time.Time  `json:"created_at"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
	UpdatedAt      time.Time  `json:"updated_at"`
	// Created is an internal idempotency receipt and is never serialized.
	Created bool `json:"-"`
}

// CommandRunStep is the current projection of one immutable plan step. The
// command itself is intentionally represented only by its digest; callers can
// request the exact reviewed definition through the separately authorized
// command-automation read surface.
type CommandRunStep struct {
	RunID            string `json:"run_id"`
	StepSeq          int    `json:"step_seq"`
	StepName         string `json:"step_name"`
	CommandSHA256    string `json:"command_sha256"`
	ExpectedExitCode int    `json:"expected_exit_code"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
	Status           string `json:"status"`
	Attempt          int    `json:"attempt"`
	ExitCode         *int   `json:"exit_code,omitempty"`
	StdoutText       string `json:"stdout_text,omitempty"`
	StderrText       string `json:"stderr_text,omitempty"`
	StdoutBytes      int    `json:"stdout_bytes"`
	StderrBytes      int    `json:"stderr_bytes"`
	StdoutTruncated  bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated  bool   `json:"stderr_truncated,omitempty"`
	ErrorText        string `json:"error_text,omitempty"`
	// ErrorBytes and ErrorTruncated are bounded read metadata. Keep them out
	// of direct JSON serialization so callers cannot mistake an internal
	// projection for an unbounded error payload; the MCP read model exposes
	// them only when a bounded query omitted the text.
	ErrorBytes     int        `json:"-"`
	ErrorTruncated bool       `json:"-"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// CommandRunStepAttempt is the immutable-ish audit projection for one
// worker generation. Output is scrubbed before persistence and bounded by the
// constants above. ClaimToken is deliberately omitted from JSON responses.
type CommandRunStepAttempt struct {
	RunID           string     `json:"run_id"`
	StepSeq         int        `json:"step_seq"`
	Attempt         int        `json:"attempt"`
	ClaimOwner      string     `json:"claim_owner"`
	ClaimToken      string     `json:"-"`
	Status          string     `json:"status"`
	ExitCode        *int       `json:"exit_code,omitempty"`
	StdoutText      string     `json:"stdout_text,omitempty"`
	StderrText      string     `json:"stderr_text,omitempty"`
	StdoutBytes     int        `json:"stdout_bytes"`
	StderrBytes     int        `json:"stderr_bytes"`
	StdoutTruncated bool       `json:"stdout_truncated,omitempty"`
	StderrTruncated bool       `json:"stderr_truncated,omitempty"`
	ErrorText       string     `json:"error_text,omitempty"`
	StartedAt       time.Time  `json:"started_at"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// CommandRunFilter bounds a tenant-scoped command-run inventory query. The
// command run list is a read model for MCP/operator inspection; it never
// returns claim tokens or command text.
type CommandRunFilter struct {
	TenantID     string
	AutomationID string
	Status       string
	Limit        int
	Offset       int
}

// CommandOutputMetadata preserves the total byte count observed by a bounded
// sandbox capture. The journal stores only the first MaxCommandOutputBytes but
// still reports whether more data was produced.
type CommandOutputMetadata struct {
	StdoutBytes     int
	StderrBytes     int
	StdoutTruncated bool
	StderrTruncated bool
}

// AppendCommandRunStepOutput durably appends one live output chunk under the
// exact run lease and step attempt. The current step and attempt projections
// are updated together; no unbounded chunk history is created. Callers may
// append either stdout or stderr while the step is running, and the method
// keeps retained text bounded while preserving total byte counts.
func (j *Journal) AppendCommandRunStepOutput(ctx context.Context, runID, workerID, claimToken string, stepSeq, attempt int, stream string, chunk []byte) error {
	if strings.TrimSpace(runID) == "" || strings.TrimSpace(workerID) == "" || strings.TrimSpace(claimToken) == "" || stepSeq < 1 || attempt < 1 {
		return errors.New("journal: invalid command run output append")
	}
	if stream != "stdout" && stream != "stderr" {
		return errors.New("journal: invalid command run output stream")
	}
	if len(chunk) == 0 {
		return nil
	}
	// A writer should normally provide small pipe-sized chunks. Refuse an
	// absurd direct call before arithmetic can overflow a durable byte count.
	if len(chunk) > int(^uint(0)>>1)/2 {
		return errors.New("journal: command run output chunk is too large")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_runs SET updated_at = updated_at WHERE id = $1`), runID); err != nil {
			return err
		}
	}
	q := `SELECT status, claim_owner, claim_token, lease_expires_at, tenant_id FROM command_runs WHERE id = $1`
	if j.engine == EnginePostgres {
		q += ` FOR UPDATE`
	}
	var status string
	var owner, token sql.NullString
	var leaseRaw any
	var tenantID string
	if err := tx.QueryRowContext(ctx, j.bind(q), runID).Scan(&status, &owner, &token, &leaseRaw, &tenantID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if status != CommandRunRunning || !owner.Valid || !token.Valid || owner.String != workerID || token.String != claimToken || !j.anyTime(leaseRaw).After(time.Now().UTC()) {
		return ErrCommandRunOwnershipLost
	}
	if err := j.requireCommandPayloadKey(ctx, tx); err != nil {
		return err
	}
	var currentStatus string
	var currentAttempt int
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT status, attempt FROM command_run_steps WHERE run_id = $1 AND step_seq = $2`), runID, stepSeq).Scan(&currentStatus, &currentAttempt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if currentStatus != CommandRunStepRunning || currentAttempt != attempt {
		return ErrCommandRunOwnershipLost
	}
	var attemptStatus string
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT status FROM command_run_step_attempts WHERE run_id = $1 AND step_seq = $2 AND attempt = $3 AND claim_owner = $4 AND claim_token = $5`), runID, stepSeq, attempt, workerID, claimToken).Scan(&attemptStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrCommandRunOwnershipLost
		}
		return err
	}
	if attemptStatus != CommandRunStepRunning {
		return ErrCommandRunOwnershipLost
	}
	var stored sql.NullString
	var cryptoVersion int
	var total int
	var truncated any
	projection := j.commandTextProjection("command_run_steps", stream, MaxCommandOutputBytes, MaxCommandOutputBytes)
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT `+projection+`, `+stream+`_crypto_version, `+stream+`_bytes, `+stream+`_truncated FROM command_run_steps WHERE run_id = $1 AND step_seq = $2`), runID, stepSeq).Scan(&stored, &cryptoVersion, &total, &truncated); err != nil {
		return err
	}
	text, err := j.openCommandField(tenantID, runID, stepSeq, attempt, "step_"+stream, cryptoVersion, stored)
	if err != nil {
		return err
	}
	// Apply the generic redactor across the existing suffix and new chunk so a
	// keyed token split at a write boundary cannot be reconstructed from two
	// individually safe-looking durable updates. Runner's exact credential
	// redaction runs earlier and handles tenant-specific values.
	combinedRaw := append(append([]byte(nil), []byte(text)...), chunk...)
	bounded, _, visibleTruncated := scrubBoundCommandOutput(combinedRaw, MaxCommandOutputBytes)
	chunkTruncated := len(chunk) > MaxCommandOutputBytes
	if len(chunk) > int(^uint(0)>>1)-total {
		return errors.New("journal: command run output byte count overflow")
	}
	total += len(chunk)
	wasTruncated := parseBool(truncated)
	wasTruncated = wasTruncated || chunkTruncated || visibleTruncated || total > MaxCommandOutputBytes
	now := j.now()
	stepField, err := j.sealCommandField(tenantID, runID, stepSeq, attempt, "step_"+stream, bounded)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_run_steps SET `+stream+`_text = $1, `+stream+`_crypto_version = $2, `+stream+`_bytes = $3, `+stream+`_truncated = $4, updated_at = $5 WHERE run_id = $6 AND step_seq = $7 AND status = $8 AND attempt = $9`), stepField.Text, stepField.Version, total, j.boolValue(wasTruncated), now, runID, stepSeq, CommandRunStepRunning, attempt); err != nil {
		return err
	}
	// Mirror the live projection into the immutable-ish attempt row so an
	// interrupted worker retains partial output for recovery inspection.
	var attemptStored sql.NullString
	var attemptVersion int
	var attemptTotal int
	var attemptTruncated any
	attemptProjection := j.commandTextProjection("command_run_step_attempts", stream, MaxCommandOutputBytes, MaxCommandOutputBytes)
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT `+attemptProjection+`, `+stream+`_crypto_version, `+stream+`_bytes, `+stream+`_truncated FROM command_run_step_attempts WHERE run_id = $1 AND step_seq = $2 AND attempt = $3 AND claim_owner = $4 AND claim_token = $5`), runID, stepSeq, attempt, workerID, claimToken).Scan(&attemptStored, &attemptVersion, &attemptTotal, &attemptTruncated); err != nil {
		return err
	}
	attemptText, err := j.openCommandField(tenantID, runID, stepSeq, attempt, "attempt_"+stream, attemptVersion, attemptStored)
	if err != nil {
		return err
	}
	attemptCombinedRaw := append(append([]byte(nil), []byte(attemptText)...), chunk...)
	attemptBounded, _, attemptVisibleTruncated := scrubBoundCommandOutput(attemptCombinedRaw, MaxCommandOutputBytes)
	if len(chunk) > int(^uint(0)>>1)-attemptTotal {
		return errors.New("journal: command run attempt output byte count overflow")
	}
	attemptTotal += len(chunk)
	attemptWasTruncated := parseBool(attemptTruncated) || chunkTruncated || attemptVisibleTruncated || attemptTotal > MaxCommandOutputBytes
	attemptField, err := j.sealCommandField(tenantID, runID, stepSeq, attempt, "attempt_"+stream, attemptBounded)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_run_step_attempts SET `+stream+`_text = $1, `+stream+`_crypto_version = $2, `+stream+`_bytes = $3, `+stream+`_truncated = $4, updated_at = $5 WHERE run_id = $6 AND step_seq = $7 AND attempt = $8 AND claim_owner = $9 AND claim_token = $10 AND status = $11`), attemptField.Text, attemptField.Version, attemptTotal, j.boolValue(attemptWasTruncated), now, runID, stepSeq, attempt, workerID, claimToken, CommandRunStepRunning); err != nil {
		return err
	}
	return tx.Commit()
}

// CreateCommandRun admits one exact immutable command-automation version to
// the durable queue. It performs no execution and accepts only a bounded,
// secret-free admission summary rather than an assertion or credential.
func (j *Journal) CreateCommandRun(ctx context.Context, tenantID, runID, automationID string, version int, admission CommandRunAdmission) (CommandRun, error) {
	return j.createCommandRun(ctx, tenantID, runID, automationID, version, admission, "")
}

// CreateCommandRunWithRetryOf admits a fresh run while retaining a bounded,
// tenant-scoped reference to the failed or cancelled source run. The source
// row is locked and validated in the same transaction as admission, so a
// retry cannot point at a foreign, active, or missing run.
func (j *Journal) CreateCommandRunWithRetryOf(ctx context.Context, tenantID, runID, automationID string, version int, admission CommandRunAdmission, retryOf string) (CommandRun, error) {
	return j.createCommandRun(ctx, tenantID, runID, automationID, version, admission, retryOf)
}

func (j *Journal) createCommandRun(ctx context.Context, tenantID, runID, automationID string, version int, admission CommandRunAdmission, retryOf string) (CommandRun, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	if err := validCommandRunID(runID); err != nil {
		return CommandRun{}, err
	}
	retryOf = strings.TrimSpace(retryOf)
	if retryOf != "" {
		if err := validCommandRunID(retryOf); err != nil || retryOf == runID {
			return CommandRun{}, ErrCommandRunRetryNotTerminal
		}
	}
	if strings.TrimSpace(automationID) == "" || version < 1 {
		return CommandRun{}, errors.New("journal: command run requires automation and positive version")
	}
	if err := validateCommandRunAdmission(admission); err != nil {
		return CommandRun{}, err
	}
	// A caller may retry a timed-out MCP request with the same run id. Resolve
	// that id before opening the admission transaction so a retry returns the
	// existing durable receipt instead of launching the command twice.
	if existing, lookupErr := j.GetCommandRunForTenant(ctx, tenantID, runID); lookupErr == nil {
		if existing.AutomationID != automationID || existing.AutomationVersion != version || existing.Admission != admission || existing.RetryOf != retryOf {
			return CommandRun{}, ErrCommandRunConflict
		}
		return existing, nil
	} else if !errors.Is(lookupErr, ErrNotFound) {
		return CommandRun{}, fmt.Errorf("journal: resolve idempotent command run: %w", lookupErr)
	}

	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return CommandRun{}, fmt.Errorf("journal: begin command run: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		// Acquire SQLite's single-writer lock before resolving the immutable
		// definition, so deletion/revision cannot race this admission.
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automations SET current_version = current_version WHERE id = $1 AND tenant_id = $2`), automationID, tenantID); err != nil {
			return CommandRun{}, fmt.Errorf("journal: lock command automation for run: %w", err)
		}
	}
	lockQ := `SELECT tenant_id, target, enabled, current_version FROM command_automations WHERE id = $1`
	if j.engine == EnginePostgres {
		lockQ += ` FOR UPDATE`
	}
	var owner, target string
	var enabled any
	var currentVersion int
	if err := tx.QueryRowContext(ctx, j.bind(lockQ), automationID).Scan(&owner, &target, &enabled, &currentVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CommandRun{}, ErrNotFound
		}
		return CommandRun{}, fmt.Errorf("journal: resolve command automation for run: %w", err)
	}
	if owner != tenantID {
		return CommandRun{}, ErrCommandAutomationTenant
	}
	if !parseBool(enabled) {
		return CommandRun{}, ErrCommandAutomationEnabled
	}
	if currentVersion != version {
		return CommandRun{}, ErrCommandAutomationConflict
	}
	if retryOf != "" {
		lockRetryQ := `SELECT status, automation_id, automation_version FROM command_runs WHERE tenant_id = $1 AND id = $2`
		if j.engine == EnginePostgres {
			lockRetryQ += ` FOR UPDATE`
		}
		var retryStatus, retryAutomationID string
		var retryVersion int
		if err := tx.QueryRowContext(ctx, j.bind(lockRetryQ), tenantID, retryOf).Scan(&retryStatus, &retryAutomationID, &retryVersion); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return CommandRun{}, ErrNotFound
			}
			return CommandRun{}, fmt.Errorf("journal: resolve command retry source: %w", err)
		}
		if retryStatus != CommandRunFailed && retryStatus != CommandRunCancelled {
			return CommandRun{}, ErrCommandRunRetryNotTerminal
		}
		if retryAutomationID != automationID || retryVersion != version {
			return CommandRun{}, ErrCommandRunRetryBindingMismatch
		}
	}
	raw, err := j.commandDefinitionTx(ctx, tx, tenantID, automationID, version)
	if err != nil {
		return CommandRun{}, fmt.Errorf("journal: resolve command automation version for run: %w", err)
	}
	definition, normalized, err := commandautomations.Normalize(raw)
	if err != nil {
		return CommandRun{}, fmt.Errorf("journal: normalize command automation for run: %w", err)
	}
	digest := sha256.Sum256(normalized)
	digestHex := hex.EncodeToString(digest[:])
	if admission.DefinitionSHA256 != digestHex {
		return CommandRun{}, fmt.Errorf("%w: got %q for version %d, want immutable digest", ErrCommandRunDefinitionMismatch, admission.DefinitionSHA256, version)
	}
	if admission.ReceiptID != commandautomations.ReceiptIDForGateDigest(tenantID, automationID, version, digestHex, admission.GateDigest) {
		return CommandRun{}, ErrCommandRunBindingMismatch
	}
	// Triggered admissions carry a durable trigger identity. Fence the final
	// insert against the owning trigger row in this same transaction so a
	// disable/delete racing a callback cannot leave a new run admitted after
	// the kill switch became visible. The row lock also serializes a concurrent
	// trigger revision on Postgres; SQLite already holds its writer lock from
	// the transaction start.
	if triggerID := strings.TrimSpace(admission.TriggerID); triggerID != "" {
		if strings.TrimSpace(admission.TriggerEventID) == "" {
			return CommandRun{}, ErrCommandRunBindingMismatch
		}
		triggerKind := strings.TrimSpace(admission.TriggerKind)
		if triggerKind == "" {
			// Rows written before trigger_kind was introduced were schedules.
			triggerKind = CommandRunTriggerSchedule
		}
		if triggerKind != CommandRunTriggerSchedule && triggerKind != CommandRunTriggerWebhook && triggerKind != CommandRunTriggerChain {
			return CommandRun{}, ErrCommandRunBindingMismatch
		}
		var (
			triggerState, triggerAutomationID, triggerDefinition, triggerReceipt, triggerGate, triggerActor string
			triggerVersion                                                                                  int
		)
		var triggerQ string
		switch triggerKind {
		case CommandRunTriggerSchedule:
			triggerQ = `SELECT state, automation_id, automation_version, definition_sha256, receipt_id, gate_digest, actor_id FROM command_automation_schedules WHERE tenant_id = $1 AND id = $2`
		case CommandRunTriggerWebhook:
			triggerQ = `SELECT state, automation_id, automation_version, definition_sha256, receipt_id, gate_digest, actor_id FROM command_automation_webhook_triggers WHERE tenant_id = $1 AND id = $2`
		case CommandRunTriggerChain:
			triggerQ = `SELECT c.state, c.automation_id, c.automation_version, c.definition_sha256, c.receipt_id, c.gate_digest, c.actor_id
				FROM command_automation_chain_triggers c
				JOIN command_automations a ON a.id = c.automation_id AND a.tenant_id = c.tenant_id
				JOIN workflows src ON src.id = c.source_workflow_id AND src.tenant_id = c.tenant_id
				WHERE c.tenant_id = $1 AND c.id = $2`
		}
		if j.engine == EnginePostgres {
			triggerQ += ` FOR UPDATE`
		}
		if err := tx.QueryRowContext(ctx, j.bind(triggerQ), tenantID, triggerID).Scan(&triggerState, &triggerAutomationID, &triggerVersion, &triggerDefinition, &triggerReceipt, &triggerGate, &triggerActor); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return CommandRun{}, ErrCommandRunBindingMismatch
			}
			return CommandRun{}, fmt.Errorf("journal: resolve command %s for run: %w", triggerKind, err)
		}
		if triggerState != "active" || triggerAutomationID != automationID || triggerVersion != version || triggerDefinition != digestHex || triggerReceipt != admission.ReceiptID || triggerGate != admission.GateDigest || triggerActor != admission.ActorID {
			return CommandRun{}, ErrCommandRunBindingMismatch
		}
	}
	admissionJSON, _ := json.Marshal(admission)
	now := j.now()
	if _, err := tx.ExecContext(ctx, j.bind(`INSERT INTO command_runs
		(id, tenant_id, automation_id, automation_version, definition_sha256, target, actor_id, admission_json, status, retry_of, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`),
		runID, tenantID, automationID, version, digestHex, target, admission.ActorID, outputArg(admissionJSON, j.engine), CommandRunQueued, sql.NullString{String: retryOf, Valid: retryOf != ""}, now, now); err != nil {
		if isUniqueViolation(err) {
			_ = tx.Rollback()
			existing, lookupErr := j.GetCommandRunForTenant(ctx, tenantID, runID)
			if lookupErr == nil && existing.AutomationID == automationID && existing.AutomationVersion == version && existing.Admission == admission && existing.RetryOf == retryOf {
				return existing, nil
			}
			if lookupErr == nil {
				return CommandRun{}, ErrCommandRunConflict
			}
		}
		return CommandRun{}, fmt.Errorf("journal: create command run: %w", err)
	}
	for i, step := range definition.Steps {
		stepDigest := sha256.Sum256([]byte(step.Command))
		if _, err := tx.ExecContext(ctx, j.bind(`INSERT INTO command_run_steps
			(run_id, step_seq, step_name, command_sha256, expected_exit_code, timeout_seconds, status, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`), runID, i+1, step.Name, hex.EncodeToString(stepDigest[:]), step.ExpectedExitCode, step.TimeoutSeconds, CommandRunStepPending, now); err != nil {
			return CommandRun{}, fmt.Errorf("journal: create command run step: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return CommandRun{}, fmt.Errorf("journal: commit command run: %w", err)
	}
	created, err := j.GetCommandRunForTenant(ctx, tenantID, runID)
	if err != nil {
		return CommandRun{}, err
	}
	created.Created = true
	return created, nil
}

// commandRunSelect returns the shared bounded read projection. Current writes
// cap error_text, but imported or repaired rows can predate that invariant;
// never materialize an untrusted oversized parent error in a worker or MCP
// process. The byte count remains available for an omission receipt.
func (j *Journal) commandRunSelect() string {
	size := j.commandTextSize("error_text")
	errorText := fmt.Sprintf(`CASE WHEN error_crypto_version = 0 AND %s <= %d THEN error_text
		WHEN error_crypto_version = 1 AND %s <= %d THEN error_text ELSE NULL END`,
		size, MaxCommandErrorBytes, size, payloadcrypto.CiphertextLimit(MaxCommandErrorBytes))
	errorBytes := fmt.Sprintf("CASE WHEN error_crypto_version = 1 THEN error_plaintext_bytes ELSE %s END", size)
	return `SELECT id, tenant_id, automation_id, automation_version, definition_sha256, target,
		actor_id, admission_json, status, retry_of, attempt, claim_owner, claim_token, lease_expires_at,
		` + errorText + `, ` + errorBytes + `, error_crypto_version, error_plaintext_bytes,
		created_at, started_at, finished_at, updated_at
		FROM command_runs`
}

// GetCommandRunForTenant reads one durable run without exposing the claim
// token. A foreign tenant is intentionally indistinguishable from missing.
func (j *Journal) GetCommandRunForTenant(ctx context.Context, tenantID, runID string) (CommandRun, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(runID) == "" {
		return CommandRun{}, ErrNotFound
	}
	q := j.commandRunSelect() + ` WHERE tenant_id = $1 AND id = $2`
	row := j.db.QueryRowContext(ctx, j.bind(q), tenantID, runID)
	run, err := j.scanCommandRun(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return CommandRun{}, ErrNotFound
	}
	if err != nil {
		return CommandRun{}, fmt.Errorf("journal: get command run: %w", err)
	}
	return run, nil
}

// ListCommandRunStepsForTenant returns the current step projection in plan
// order. It never returns command text or claim tokens.
func (j *Journal) ListCommandRunStepsForTenant(ctx context.Context, tenantID, runID string) ([]CommandRunStep, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(runID) == "" {
		return nil, ErrNotFound
	}
	q := fmt.Sprintf(`SELECT s.run_id, s.step_seq, s.step_name, s.command_sha256, s.expected_exit_code,
		s.timeout_seconds, s.status, s.attempt, s.exit_code, %s, %s,
		s.stdout_bytes, s.stderr_bytes, s.stdout_truncated, s.stderr_truncated, %s,
		%s, s.stdout_crypto_version, s.stderr_crypto_version, s.error_crypto_version,
		s.error_plaintext_bytes, s.started_at, s.finished_at, s.updated_at
		FROM command_run_steps s JOIN command_runs r ON r.id = s.run_id
		WHERE r.tenant_id = $1 AND s.run_id = $2 ORDER BY s.step_seq ASC`,
		j.commandTextProjection("s", "stdout", MaxCommandOutputBytes, MaxCommandOutputBytes),
		j.commandTextProjection("s", "stderr", MaxCommandOutputBytes, MaxCommandOutputBytes),
		j.commandTextProjection("s", "error", MaxCommandErrorBytes, MaxCommandErrorBytes),
		j.commandErrorSizeExpr("s"))
	rows, err := j.db.QueryContext(ctx, j.bind(q), tenantID, runID)
	if err != nil {
		return nil, fmt.Errorf("journal: list command run steps: %w", err)
	}
	defer rows.Close()
	var out []CommandRunStep
	for rows.Next() {
		step, err := j.scanCommandRunStep(rows.Scan, tenantID)
		if err != nil {
			return nil, err
		}
		out = append(out, step)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("journal: list command run steps: %w", err)
	}
	if len(out) == 0 {
		if _, err := j.GetCommandRunForTenant(ctx, tenantID, runID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ListCommandRunsForTenantPage returns a bounded, newest-first page of
// durable command-run projections. The lookahead row is retained so MCP can
// report has_more without a count query. Admission JSON is bounded at write
// time and scanCommandRun intentionally keeps the claim token internal.
func (j *Journal) ListCommandRunsForTenantPage(ctx context.Context, filter CommandRunFilter) ([]CommandRun, error) {
	tenantID := strings.TrimSpace(filter.TenantID)
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	if filter.Limit <= 0 || filter.Limit > 1000 || filter.Offset < 0 {
		return nil, errors.New("journal: invalid command run page")
	}
	if filter.Status != "" && filter.Status != CommandRunQueued && filter.Status != CommandRunRunning && filter.Status != CommandRunSucceeded && filter.Status != CommandRunFailed && filter.Status != CommandRunCancelled {
		return nil, errors.New("journal: invalid command run status")
	}
	q := j.commandRunSelect() + ` WHERE tenant_id = $1`
	args := []any{tenantID}
	position := 2
	if strings.TrimSpace(filter.AutomationID) != "" {
		q += fmt.Sprintf(" AND automation_id = $%d", position)
		args = append(args, strings.TrimSpace(filter.AutomationID))
		position++
	}
	if filter.Status != "" {
		q += fmt.Sprintf(" AND status = $%d", position)
		args = append(args, filter.Status)
		position++
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d OFFSET $%d", position, position+1)
	args = append(args, filter.Limit, filter.Offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, fmt.Errorf("journal: list command runs: %w", err)
	}
	defer rows.Close()
	out := make([]CommandRun, 0, filter.Limit)
	for rows.Next() {
		run, err := j.scanCommandRun(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("journal: scan command run page: %w", err)
		}
		out = append(out, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("journal: iterate command run page: %w", err)
	}
	return out, nil
}

// ListQueuedCommandRunsForTenantPage returns the oldest queued command runs
// for one tenant first. The recovery worker uses this ordering so a continual
// stream of newer admissions cannot starve an older durable row behind the
// newest-first inspection page exposed to MCP.
func (j *Journal) ListQueuedCommandRunsForTenantPage(ctx context.Context, tenantID string, limit int) ([]CommandRun, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	if limit <= 0 || limit > 1000 {
		return nil, errors.New("journal: invalid queued command run page")
	}
	q := j.commandRunSelect() + ` WHERE tenant_id = $1 AND status = $2
		ORDER BY created_at ASC, id ASC LIMIT $3`
	rows, err := j.db.QueryContext(ctx, j.bind(q), tenantID, CommandRunQueued, limit)
	if err != nil {
		return nil, fmt.Errorf("journal: list queued command runs: %w", err)
	}
	defer rows.Close()
	out := make([]CommandRun, 0, limit)
	for rows.Next() {
		run, err := j.scanCommandRun(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("journal: scan queued command run page: %w", err)
		}
		out = append(out, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("journal: iterate queued command run page: %w", err)
	}
	return out, nil
}

// ListCommandRunStepsPageForTenantBounded returns one ordered page of a
// tenant-owned command run while keeping oversized persisted output outside
// the MCP process. The durable byte counters remain visible so callers can
// request a larger, separately bounded view later. Command text is never
// selected by this projection.
func (j *Journal) ListCommandRunStepsPageForTenantBounded(ctx context.Context, tenantID, runID string, limit, offset, maxOutputBytes, maxErrorBytes int) ([]CommandRunStep, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	if limit <= 0 || limit > 1000 || offset < 0 {
		return nil, errors.New("journal: invalid command run step page")
	}
	if maxOutputBytes < 0 || maxErrorBytes < 0 || maxOutputBytes > 16<<20 || maxErrorBytes > 16<<20 {
		return nil, errors.New("journal: invalid command run step value limit")
	}
	stdoutExpr := "NULL"
	stderrExpr := "NULL"
	errorExpr := "NULL"
	errorBytesExpr := j.commandErrorSizeExpr("s")
	stdoutSize := j.commandTextSize("s.stdout_text")
	stderrSize := j.commandTextSize("s.stderr_text")
	legacyMax := "MAX"
	if j.engine == EnginePostgres {
		legacyMax = "GREATEST"
	}
	stdoutBytesExpr := fmt.Sprintf("CASE WHEN s.stdout_crypto_version = 1 THEN s.stdout_bytes ELSE %s(s.stdout_bytes, %s) END", legacyMax, stdoutSize)
	stderrBytesExpr := fmt.Sprintf("CASE WHEN s.stderr_crypto_version = 1 THEN s.stderr_bytes ELSE %s(s.stderr_bytes, %s) END", legacyMax, stderrSize)
	stdoutTruncatedExpr := "s.stdout_truncated"
	stderrTruncatedExpr := "s.stderr_truncated"
	if maxOutputBytes > 0 {
		stdoutExpr = j.commandTextProjection("s", "stdout", maxOutputBytes, maxOutputBytes)
		stderrExpr = j.commandTextProjection("s", "stderr", maxOutputBytes, maxOutputBytes)
	}
	if maxErrorBytes > 0 {
		errorExpr = j.commandTextProjection("s", "error", maxErrorBytes, maxErrorBytes)
	}
	q := fmt.Sprintf(`SELECT s.run_id, s.step_seq, s.step_name, s.command_sha256, s.expected_exit_code,
		s.timeout_seconds, s.status, s.attempt, s.exit_code, %s, %s,
		%s, %s, %s, %s, %s, %s,
		s.stdout_crypto_version, s.stderr_crypto_version, s.error_crypto_version, s.error_plaintext_bytes,
		s.started_at, s.finished_at, s.updated_at
		FROM command_run_steps s JOIN command_runs r ON r.id = s.run_id
		WHERE r.tenant_id = $1 AND s.run_id = $2
		ORDER BY s.step_seq ASC LIMIT $3 OFFSET $4`, stdoutExpr, stderrExpr, stdoutBytesExpr, stderrBytesExpr, stdoutTruncatedExpr, stderrTruncatedExpr, errorExpr, errorBytesExpr)
	rows, err := j.db.QueryContext(ctx, j.bind(q), tenantID, runID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("journal: list command run steps page: %w", err)
	}
	defer rows.Close()
	out := make([]CommandRunStep, 0, limit)
	for rows.Next() {
		step, err := j.scanCommandRunStepBounded(rows.Scan, tenantID, maxOutputBytes)
		if err != nil {
			return nil, fmt.Errorf("journal: scan command run step page: %w", err)
		}
		if maxOutputBytes > 0 && step.StdoutBytes > maxOutputBytes {
			step.StdoutTruncated = true
			step.StdoutText = ""
		}
		if maxOutputBytes > 0 && step.StderrBytes > maxOutputBytes {
			step.StderrTruncated = true
			step.StderrText = ""
		}
		if maxErrorBytes == 0 {
			step.ErrorText = ""
		}
		out = append(out, step)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("journal: iterate command run steps page: %w", err)
	}
	if len(out) == 0 {
		if _, err := j.GetCommandRunForTenant(ctx, tenantID, runID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ClaimCommandRun leases one queued or expired run to a worker. The exact
// claim token fences every later mutation; a stale worker cannot overwrite a
// replacement after its lease expires. This method only changes journal
// state and never starts a process.
func (j *Journal) ClaimCommandRun(ctx context.Context, runID, workerID string, leaseTTL time.Duration) (CommandRun, error) {
	if strings.TrimSpace(runID) == "" || strings.TrimSpace(workerID) == "" {
		return CommandRun{}, errors.New("journal: claim command run requires run and worker")
	}
	if leaseTTL <= 0 || leaseTTL > 24*time.Hour {
		return CommandRun{}, errors.New("journal: command run lease must be 1..86400 seconds")
	}
	token, err := newID("cmdclaim_")
	if err != nil {
		return CommandRun{}, err
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return CommandRun{}, fmt.Errorf("journal: begin command run claim: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_runs SET updated_at = updated_at WHERE id = $1`), runID); err != nil {
			return CommandRun{}, fmt.Errorf("journal: lock command run claim: %w", err)
		}
	}
	// Resolve the owning automation in the same transaction and lock it with
	// the run. A worker can otherwise read an enabled plan, race an operator's
	// disable, and claim the queued row after the kill switch commits. The
	// enabled/current-version fence belongs at the durable claim boundary, not
	// only in the caller's earlier read.
	q := `SELECT c.status, c.attempt, c.lease_expires_at, c.automation_version, a.enabled, a.current_version
		FROM command_runs c JOIN command_automations a ON a.id = c.automation_id AND a.tenant_id = c.tenant_id
		WHERE c.id = $1`
	if j.engine == EnginePostgres {
		q += ` FOR UPDATE`
	}
	var status string
	var attempt int
	var leaseRaw any
	var runVersion int
	var enabled any
	var currentVersion int
	if err := tx.QueryRowContext(ctx, j.bind(q), runID).Scan(&status, &attempt, &leaseRaw, &runVersion, &enabled, &currentVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CommandRun{}, ErrNotFound
		}
		return CommandRun{}, fmt.Errorf("journal: read command run claim: %w", err)
	}
	if !parseBool(enabled) || currentVersion < 1 || runVersion != currentVersion {
		return CommandRun{}, ErrCommandRunNotClaimable
	}
	now := time.Now().UTC()
	leaseExpired := j.anyTime(leaseRaw).IsZero() || !j.anyTime(leaseRaw).After(now)
	if status != CommandRunQueued && !(status == CommandRunRunning && leaseExpired) {
		return CommandRun{}, ErrCommandRunNotClaimable
	}
	expires := now.Add(leaseTTL)
	newAttempt := attempt + 1
	if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_runs SET status = $1, attempt = $2, claim_owner = $3,
		claim_token = $4, lease_expires_at = $5, started_at = COALESCE(started_at, $6), updated_at = $7
		WHERE id = $8`), CommandRunRunning, newAttempt, workerID, token, j.formatTime(expires), j.formatTime(now), j.formatTime(now), runID); err != nil {
		return CommandRun{}, fmt.Errorf("journal: claim command run: %w", err)
	}
	run, err := j.scanCommandRun(tx.QueryRowContext(ctx, j.bind(j.commandRunSelect()+` WHERE id = $1`), runID).Scan)
	if err != nil {
		return CommandRun{}, fmt.Errorf("journal: read claimed command run: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return CommandRun{}, fmt.Errorf("journal: commit command run claim: %w", err)
	}
	return run, nil
}

// VerifyCommandRunLease is the pre-execution fence for a command worker. It
// requires the exact worker generation (owner + claim token) and a live lease;
// a stale worker must not start a process after the reaper has handed the run
// to another worker.
func (j *Journal) VerifyCommandRunLease(ctx context.Context, runID, workerID, claimToken string) error {
	if strings.TrimSpace(runID) == "" || strings.TrimSpace(workerID) == "" || strings.TrimSpace(claimToken) == "" {
		return fmt.Errorf("%w: invalid command run lease identity", ErrCommandRunOwnershipLost)
	}
	const q = `SELECT 1 FROM command_runs
		WHERE id = $1 AND status = $2 AND claim_owner = $3 AND claim_token = $4
		AND lease_expires_at > $5`
	var one int
	err := j.db.QueryRowContext(ctx, j.bind(q), runID, CommandRunRunning, workerID, claimToken, j.formatTime(time.Now().UTC())).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: verify run=%s", ErrCommandRunOwnershipLost, runID)
	}
	if err != nil {
		return fmt.Errorf("journal: verify command run lease: %w", err)
	}
	return nil
}

// ExtendCommandRunLease renews a live command-run claim. Renewal carries the
// exact claim token as well as the worker id, so a reaped and reclaimed run
// cannot be renewed by its old worker. Once the lease expires the worker must
// stop; it cannot resurrect its generation by renewing after the deadline.
func (j *Journal) ExtendCommandRunLease(ctx context.Context, runID, workerID, claimToken string, leaseTTL time.Duration) error {
	if strings.TrimSpace(runID) == "" || strings.TrimSpace(workerID) == "" || strings.TrimSpace(claimToken) == "" {
		return fmt.Errorf("%w: invalid command run lease identity", ErrCommandRunOwnershipLost)
	}
	if leaseTTL <= 0 || leaseTTL > 24*time.Hour {
		return errors.New("journal: command run lease must be 1..86400 seconds")
	}
	now := time.Now().UTC()
	const q = `UPDATE command_runs SET lease_expires_at = $1, updated_at = $2
		WHERE id = $3 AND status = $4 AND claim_owner = $5 AND claim_token = $6
		AND lease_expires_at > $7`
	res, err := j.db.ExecContext(ctx, j.bind(q), j.formatTime(now.Add(leaseTTL)), j.formatTime(now), runID, CommandRunRunning, workerID, claimToken, j.formatTime(now))
	if err != nil {
		return fmt.Errorf("journal: extend command run lease: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: extend run=%s", ErrCommandRunOwnershipLost, runID)
	}
	return nil
}

// ReapExpiredCommandRunLeases requeues command runs whose worker lease died.
// It clears the old owner and token in the same transaction, allowing a new
// claim generation to resume from the durable step projection while ensuring
// every stale result is rejected by the token fence. No command process is
// launched here; the command worker owns that policy.
func (j *Journal) ReapExpiredCommandRunLeases(ctx context.Context) (int64, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("journal: begin command run lease reaper: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	nowArg := j.formatTime(now)
	// SQLite has no row-level SELECT lock. Acquire its writer lock before
	// selecting candidates so renewal and reaping cannot both win.
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_runs SET updated_at = updated_at WHERE status = $1 AND lease_expires_at <= $2`), CommandRunRunning, nowArg); err != nil {
			return 0, fmt.Errorf("journal: lock expired command run leases: %w", err)
		}
	}
	q := `SELECT id, tenant_id, claim_owner, claim_token FROM command_runs
		WHERE status = $1 AND lease_expires_at <= $2`
	if j.engine == EnginePostgres {
		q += ` FOR UPDATE SKIP LOCKED`
	}
	rows, err := tx.QueryContext(ctx, j.bind(q), CommandRunRunning, nowArg)
	if err != nil {
		return 0, fmt.Errorf("journal: select expired command run leases: %w", err)
	}
	type expiredClaim struct{ id, tenant, owner, token string }
	claims := make([]expiredClaim, 0)
	for rows.Next() {
		var claim expiredClaim
		if err := rows.Scan(&claim.id, &claim.tenant, &claim.owner, &claim.token); err != nil {
			rows.Close()
			return 0, fmt.Errorf("journal: scan expired command run lease: %w", err)
		}
		claims = append(claims, claim)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("journal: close expired command run leases: %w", err)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("journal: iterate expired command run leases: %w", err)
	}
	var reaped int64
	for _, claim := range claims {
		if err := j.requireCommandPayloadKey(ctx, tx); err != nil {
			return 0, err
		}
		// Close the in-flight step attempt that belonged to the expired
		// generation before clearing the parent lease. The process may still be
		// alive, but its token is fenced; retaining a running attempt would make
		// inspection claim that work is active forever and would leave no durable
		// indication why the replacement attempt was created.
		const recoveryReason = "command worker lease expired"
		if err := j.closeCommandAttemptErrors(ctx, tx, claim.tenant, claim.id, CommandRunStepRunning, CommandRunStepCancelled, recoveryReason, now, claim.owner, claim.token); err != nil {
			return 0, fmt.Errorf("journal: close expired command run step attempts: %w", err)
		}
		// Every non-succeeded projection is retryable after the parent claim
		// expires. A process can finish and persist a failed/cancelled step just
		// before the worker dies, before the parent terminal transition commits;
		// leaving that projection terminal would make the replacement worker
		// reject it forever. Reset pending/running/failed/cancelled projections,
		// while preserving immutable succeeded steps and the per-attempt audit
		// rows above.
		if err := j.closeCommandStepErrors(ctx, tx, claim.tenant, claim.id,
			[]string{CommandRunStepPending, CommandRunStepRunning, CommandRunStepFailed, CommandRunStepCancelled},
			CommandRunStepPending, recoveryReason, now, true); err != nil {
			return 0, fmt.Errorf("journal: reset expired command run steps: %w", err)
		}
		res, err := tx.ExecContext(ctx, j.bind(`UPDATE command_runs SET status = $1,
			claim_owner = NULL, claim_token = NULL, lease_expires_at = NULL, updated_at = $2
			WHERE id = $3 AND status = $4 AND claim_owner = $5 AND claim_token = $6
			AND lease_expires_at <= $7`), CommandRunQueued, nowArg, claim.id, CommandRunRunning, claim.owner, claim.token, nowArg)
		if err != nil {
			return 0, fmt.Errorf("journal: requeue expired command run lease: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 1 {
			reaped++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("journal: commit command run lease reaper: %w", err)
	}
	return reaped, nil
}

// ClaimCommandRunStep begins the next ordered step under the parent run's
// exact claim. Every retry gets its own immutable attempt row.
func (j *Journal) ClaimCommandRunStep(ctx context.Context, runID, workerID, claimToken string, stepSeq int) (CommandRunStep, error) {
	if strings.TrimSpace(runID) == "" || strings.TrimSpace(workerID) == "" || strings.TrimSpace(claimToken) == "" || stepSeq < 1 {
		return CommandRunStep{}, errors.New("journal: invalid command run step claim")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return CommandRunStep{}, fmt.Errorf("journal: begin command run step claim: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_runs SET updated_at = updated_at WHERE id = $1`), runID); err != nil {
			return CommandRunStep{}, err
		}
	}
	q := `SELECT status, claim_owner, claim_token, lease_expires_at, tenant_id FROM command_runs WHERE id = $1`
	if j.engine == EnginePostgres {
		q += ` FOR UPDATE`
	}
	var runStatus string
	var owner, token sql.NullString
	var leaseRaw any
	var tenantID string
	if err := tx.QueryRowContext(ctx, j.bind(q), runID).Scan(&runStatus, &owner, &token, &leaseRaw, &tenantID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CommandRunStep{}, ErrNotFound
		}
		return CommandRunStep{}, fmt.Errorf("journal: read command run step owner: %w", err)
	}
	if runStatus != CommandRunRunning || !owner.Valid || !token.Valid || owner.String != workerID || token.String != claimToken || !j.anyTime(leaseRaw).After(time.Now().UTC()) {
		return CommandRunStep{}, ErrCommandRunOwnershipLost
	}
	var status string
	var attempt int
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT status, attempt FROM command_run_steps WHERE run_id = $1 AND step_seq = $2`), runID, stepSeq).Scan(&status, &attempt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CommandRunStep{}, ErrNotFound
		}
		return CommandRunStep{}, err
	}
	if status == CommandRunStepSucceeded || status == CommandRunStepFailed || status == CommandRunStepCancelled {
		return CommandRunStep{}, ErrCommandRunNotClaimable
	}
	var blocked int
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM command_run_steps WHERE run_id = $1 AND step_seq < $2 AND status <> $3`), runID, stepSeq, CommandRunStepSucceeded).Scan(&blocked); err != nil {
		return CommandRunStep{}, fmt.Errorf("journal: check command run step order: %w", err)
	}
	if blocked != 0 {
		return CommandRunStep{}, ErrCommandRunStepOrder
	}
	now := j.now()
	nextAttempt := attempt + 1
	if err := j.requireCommandPayloadKey(ctx, tx); err != nil {
		return CommandRunStep{}, err
	}
	resetStdout, err := j.sealCommandField(tenantID, runID, stepSeq, nextAttempt, "step_stdout", "")
	if err != nil {
		return CommandRunStep{}, err
	}
	resetStderr, err := j.sealCommandField(tenantID, runID, stepSeq, nextAttempt, "step_stderr", "")
	if err != nil {
		return CommandRunStep{}, err
	}
	resetError, err := j.sealCommandField(tenantID, runID, stepSeq, nextAttempt, "step_error", "")
	if err != nil {
		return CommandRunStep{}, err
	}
	if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_run_steps SET status = $1, attempt = $2, exit_code = NULL,
		stdout_text = $3, stderr_text = $4, stdout_crypto_version = $5, stderr_crypto_version = $6,
		stdout_bytes = 0, stderr_bytes = 0, stdout_truncated = $7, stderr_truncated = $8,
		error_text = $9, error_crypto_version = $10, error_plaintext_bytes = $11, started_at = $12,
		finished_at = NULL, updated_at = $13 WHERE run_id = $14 AND step_seq = $15`),
		CommandRunStepRunning, nextAttempt, resetStdout.Text, resetStderr.Text, resetStdout.Version, resetStderr.Version,
		j.boolValue(false), j.boolValue(false), resetError.Text, resetError.Version, resetError.PlainBytes,
		now, now, runID, stepSeq); err != nil {
		return CommandRunStep{}, fmt.Errorf("journal: mark command run step: %w", err)
	}
	if _, err := tx.ExecContext(ctx, j.bind(`INSERT INTO command_run_step_attempts
		(run_id, step_seq, attempt, claim_owner, claim_token, status, started_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`), runID, stepSeq, nextAttempt, workerID, claimToken, CommandRunStepRunning, now, now); err != nil {
		return CommandRunStep{}, fmt.Errorf("journal: create command run step attempt: %w", err)
	}
	stepQ := fmt.Sprintf(`SELECT run_id, step_seq, step_name, command_sha256, expected_exit_code,
		timeout_seconds, status, attempt, exit_code, %s, %s,
		stdout_bytes, stderr_bytes, stdout_truncated, stderr_truncated, %s,
		%s, stdout_crypto_version, stderr_crypto_version, error_crypto_version, error_plaintext_bytes,
		started_at, finished_at, updated_at FROM command_run_steps WHERE run_id = $1 AND step_seq = $2`,
		j.commandTextProjection("command_run_steps", "stdout", MaxCommandOutputBytes, MaxCommandOutputBytes),
		j.commandTextProjection("command_run_steps", "stderr", MaxCommandOutputBytes, MaxCommandOutputBytes),
		j.commandTextProjection("command_run_steps", "error", MaxCommandErrorBytes, MaxCommandErrorBytes),
		j.commandErrorSizeExpr("command_run_steps"))
	step, err := j.scanCommandRunStep(tx.QueryRowContext(ctx, j.bind(stepQ), runID, stepSeq).Scan, tenantID)
	if err != nil {
		return CommandRunStep{}, err
	}
	if err := tx.Commit(); err != nil {
		return CommandRunStep{}, fmt.Errorf("journal: commit command run step claim: %w", err)
	}
	return step, nil
}

// RecordCommandRunStepResult commits one bounded, redacted command result
// under the exact run/step claim. A non-matching worker/token is rejected.
func (j *Journal) RecordCommandRunStepResult(ctx context.Context, runID, workerID, claimToken string, stepSeq, attempt, exitCode int, stdout, stderr []byte, errText string) error {
	return j.recordCommandRunStepResult(ctx, runID, workerID, claimToken, stepSeq, attempt, exitCode, stdout, stderr, errText, nil)
}

// RecordCommandRunStepResultWithMetadata is the bounded-output variant used
// by sandboxes that count bytes while streaming. It keeps the persisted text
// bounded while retaining accurate total byte counts and truncation flags.
func (j *Journal) RecordCommandRunStepResultWithMetadata(ctx context.Context, runID, workerID, claimToken string, stepSeq, attempt, exitCode int, stdout, stderr []byte, errText string, metadata CommandOutputMetadata) error {
	return j.recordCommandRunStepResult(ctx, runID, workerID, claimToken, stepSeq, attempt, exitCode, stdout, stderr, errText, &metadata)
}

func (j *Journal) recordCommandRunStepResult(ctx context.Context, runID, workerID, claimToken string, stepSeq, attempt, exitCode int, stdout, stderr []byte, errText string, metadata *CommandOutputMetadata) error {
	if strings.TrimSpace(runID) == "" || strings.TrimSpace(workerID) == "" || strings.TrimSpace(claimToken) == "" || stepSeq < 1 || attempt < 1 || exitCode < -1 || exitCode > 255 {
		return errors.New("journal: invalid command run step result")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_runs SET updated_at = updated_at WHERE id = $1`), runID); err != nil {
			return err
		}
	}
	q := `SELECT status, claim_owner, claim_token, lease_expires_at, tenant_id FROM command_runs WHERE id = $1`
	if j.engine == EnginePostgres {
		q += ` FOR UPDATE`
	}
	var status string
	var owner, token sql.NullString
	var leaseRaw any
	var tenantID string
	if err := tx.QueryRowContext(ctx, j.bind(q), runID).Scan(&status, &owner, &token, &leaseRaw, &tenantID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if status != CommandRunRunning || !owner.Valid || !token.Valid || owner.String != workerID || token.String != claimToken || !j.anyTime(leaseRaw).After(time.Now().UTC()) {
		return ErrCommandRunOwnershipLost
	}
	if err := j.requireCommandPayloadKey(ctx, tx); err != nil {
		return err
	}
	var expected int
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT expected_exit_code FROM command_run_steps WHERE run_id = $1 AND step_seq = $2`), runID, stepSeq).Scan(&expected); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	// A streaming adapter may intentionally return no final capture because
	// output was already appended while the process ran. Preserve that durable
	// live projection instead of replacing it with an empty terminal result.
	var liveStdoutStored, liveStderrStored sql.NullString
	var liveStdoutVersion, liveStderrVersion int
	var liveStdoutBytes, liveStderrBytes int
	var liveStdoutTruncated, liveStderrTruncated any
	liveQuery := fmt.Sprintf(`SELECT %s, %s, stdout_crypto_version, stderr_crypto_version,
		stdout_bytes, stderr_bytes, stdout_truncated, stderr_truncated FROM command_run_steps WHERE run_id = $1 AND step_seq = $2`,
		j.commandTextProjection("command_run_steps", "stdout", MaxCommandOutputBytes, MaxCommandOutputBytes),
		j.commandTextProjection("command_run_steps", "stderr", MaxCommandOutputBytes, MaxCommandOutputBytes))
	if err := tx.QueryRowContext(ctx, j.bind(liveQuery), runID, stepSeq).Scan(&liveStdoutStored, &liveStderrStored,
		&liveStdoutVersion, &liveStderrVersion, &liveStdoutBytes, &liveStderrBytes, &liveStdoutTruncated, &liveStderrTruncated); err != nil {
		return err
	}
	if len(stdout) == 0 && liveStdoutBytes > 0 {
		liveStdout, err := j.openCommandField(tenantID, runID, stepSeq, attempt, "step_stdout", liveStdoutVersion, liveStdoutStored)
		if err != nil {
			return err
		}
		stdout = []byte(liveStdout)
		if metadata == nil {
			metadata = &CommandOutputMetadata{}
		}
		if metadata.StdoutBytes == 0 {
			metadata.StdoutBytes = liveStdoutBytes
		}
		metadata.StdoutTruncated = metadata.StdoutTruncated || parseBool(liveStdoutTruncated)
	}
	if len(stderr) == 0 && liveStderrBytes > 0 {
		liveStderr, err := j.openCommandField(tenantID, runID, stepSeq, attempt, "step_stderr", liveStderrVersion, liveStderrStored)
		if err != nil {
			return err
		}
		stderr = []byte(liveStderr)
		if metadata == nil {
			metadata = &CommandOutputMetadata{}
		}
		if metadata.StderrBytes == 0 {
			metadata.StderrBytes = liveStderrBytes
		}
		metadata.StderrTruncated = metadata.StderrTruncated || parseBool(liveStderrTruncated)
	}
	outText, outBytes, outTrunc := scrubBoundCommandOutput(stdout, MaxCommandOutputBytes)
	errOutputText, errOutputBytes, errOutputTrunc := scrubBoundCommandOutput(stderr, MaxCommandOutputBytes)
	if metadata != nil {
		if metadata.StdoutBytes < len(stdout) || metadata.StderrBytes < len(stderr) || metadata.StdoutBytes < 0 || metadata.StderrBytes < 0 {
			return errors.New("journal: invalid command output metadata")
		}
		outBytes, outTrunc = metadata.StdoutBytes, metadata.StdoutTruncated || metadata.StdoutBytes > MaxCommandOutputBytes
		errOutputBytes, errOutputTrunc = metadata.StderrBytes, metadata.StderrTruncated || metadata.StderrBytes > MaxCommandOutputBytes
	}
	// The helper scrubs a bounded prefix plus lookahead, then reapplies the
	// storage cap. Keep byte totals from the original sandbox capture above;
	// visible text is the only value subject to the post-redaction fence.
	errTextBound := scrubBoundCommandError(errText)
	// Scrubbing may shorten the visible text while preserving the original
	// byte count for operators diagnosing truncation or a redacted result.
	errStatus := CommandRunStepSucceeded
	if exitCode != expected || errText != "" {
		errStatus = CommandRunStepFailed
	}
	stepOut, err := j.sealCommandField(tenantID, runID, stepSeq, attempt, "step_stdout", outText)
	if err != nil {
		return err
	}
	stepErrOutput, err := j.sealCommandField(tenantID, runID, stepSeq, attempt, "step_stderr", errOutputText)
	if err != nil {
		return err
	}
	stepError, err := j.sealCommandField(tenantID, runID, stepSeq, attempt, "step_error", errTextBound)
	if err != nil {
		return err
	}
	attemptOut, err := j.sealCommandField(tenantID, runID, stepSeq, attempt, "attempt_stdout", outText)
	if err != nil {
		return err
	}
	attemptErrOutput, err := j.sealCommandField(tenantID, runID, stepSeq, attempt, "attempt_stderr", errOutputText)
	if err != nil {
		return err
	}
	attemptError, err := j.sealCommandField(tenantID, runID, stepSeq, attempt, "attempt_error", errTextBound)
	if err != nil {
		return err
	}
	now := j.now()
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE command_run_step_attempts SET status = $1, exit_code = $2,
		stdout_text = $3, stderr_text = $4, stdout_bytes = $5, stderr_bytes = $6,
		stdout_truncated = $7, stderr_truncated = $8, error_text = $9,
		stdout_crypto_version = $10, stderr_crypto_version = $11, error_crypto_version = $12,
		error_plaintext_bytes = $13, finished_at = $14, updated_at = $15
		WHERE run_id = $16 AND step_seq = $17 AND attempt = $18 AND claim_owner = $19 AND claim_token = $20 AND status = $21`),
		errStatus, exitCode, attemptOut.Text, attemptErrOutput.Text, outBytes, errOutputBytes,
		j.boolValue(outTrunc), j.boolValue(errOutputTrunc), attemptError.Text,
		attemptOut.Version, attemptErrOutput.Version, attemptError.Version, attemptError.PlainBytes,
		now, now, runID, stepSeq, attempt, workerID, claimToken, CommandRunStepRunning)
	if err != nil {
		return fmt.Errorf("journal: record command run step attempt: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrCommandRunOwnershipLost
	}
	if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_run_steps SET status = $1, exit_code = $2,
		stdout_text = $3, stderr_text = $4, stdout_bytes = $5, stderr_bytes = $6,
		stdout_truncated = $7, stderr_truncated = $8, error_text = $9,
		stdout_crypto_version = $10, stderr_crypto_version = $11, error_crypto_version = $12,
		error_plaintext_bytes = $13, finished_at = $14, updated_at = $15
		WHERE run_id = $16 AND step_seq = $17 AND attempt = $18`),
		errStatus, exitCode, stepOut.Text, stepErrOutput.Text, outBytes, errOutputBytes,
		j.boolValue(outTrunc), j.boolValue(errOutputTrunc), stepError.Text,
		stepOut.Version, stepErrOutput.Version, stepError.Version, stepError.PlainBytes,
		now, now, runID, stepSeq, attempt); err != nil {
		return fmt.Errorf("journal: update command run step: %w", err)
	}
	return tx.Commit()
}

// FinishCommandRun writes a terminal run state only under the live claim.
// Succeeded requires every planned step to have succeeded; cancellation and
// failure may terminate pending steps but never erase their audit rows.
func (j *Journal) FinishCommandRun(ctx context.Context, runID, workerID, claimToken, status, errText string) error {
	if status != CommandRunSucceeded && status != CommandRunFailed && status != CommandRunCancelled {
		return fmt.Errorf("journal: invalid command run terminal status %q", status)
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_runs SET updated_at = updated_at WHERE id = $1`), runID); err != nil {
			return err
		}
	}
	q := `SELECT status, claim_owner, claim_token, lease_expires_at, tenant_id FROM command_runs WHERE id = $1`
	if j.engine == EnginePostgres {
		q += ` FOR UPDATE`
	}
	var current string
	var owner, token sql.NullString
	var leaseRaw any
	var tenantID string
	if err := tx.QueryRowContext(ctx, j.bind(q), runID).Scan(&current, &owner, &token, &leaseRaw, &tenantID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if current != CommandRunRunning || !owner.Valid || !token.Valid || owner.String != workerID || token.String != claimToken || !j.anyTime(leaseRaw).After(time.Now().UTC()) {
		return ErrCommandRunOwnershipLost
	}
	if err := j.requireCommandPayloadKey(ctx, tx); err != nil {
		return err
	}
	if status == CommandRunSucceeded {
		var incomplete int
		if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM command_run_steps WHERE run_id = $1 AND status <> $2`), runID, CommandRunStepSucceeded).Scan(&incomplete); err != nil {
			return err
		}
		if incomplete != 0 {
			return ErrCommandRunInvalidState
		}
	}
	boundErr := scrubBoundCommandError(errText)
	runError, err := j.sealCommandField(tenantID, runID, 0, 0, "run_error", boundErr)
	if err != nil {
		return err
	}
	finishedAt := j.now()
	// A terminal run closes every non-terminal step projection in the same
	// transaction. Without this fence a failed/cancelled run can retain a
	// pending or running step forever, and a stale worker may later appear to
	// have progressed it even though the parent run is terminal. Clearing the
	// attempt rows too preserves a truthful, crash-recoverable audit trail.
	if status == CommandRunFailed || status == CommandRunCancelled {
		closureReason := boundErr
		if closureReason == "" {
			closureReason = "command run " + status + " before step completion"
		}
		if err := j.closeCommandAttemptErrors(ctx, tx, tenantID, runID, CommandRunStepRunning, CommandRunStepCancelled, closureReason, finishedAt, "", ""); err != nil {
			return fmt.Errorf("journal: close command run step attempts: %w", err)
		}
		if err := j.closeCommandStepErrors(ctx, tx, tenantID, runID, []string{CommandRunStepPending, CommandRunStepRunning}, CommandRunStepCancelled, closureReason, finishedAt, false); err != nil {
			return fmt.Errorf("journal: close command run steps: %w", err)
		}
	}
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE command_runs SET status = $1, error_text = $2, error_crypto_version = $3,
		error_plaintext_bytes = $4, finished_at = $5,
		claim_owner = NULL, claim_token = NULL, lease_expires_at = NULL, updated_at = $6
		WHERE id = $7 AND status = $8 AND claim_owner = $9 AND claim_token = $10`),
		status, runError.Text, runError.Version, runError.PlainBytes, finishedAt, finishedAt, runID, CommandRunRunning, workerID, claimToken)
	if err != nil {
		return fmt.Errorf("journal: finish command run: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrCommandRunOwnershipLost
	}
	return tx.Commit()
}

func validateCommandRunAdmission(a CommandRunAdmission) error {
	for name, value := range map[string]string{"receipt_id": a.ReceiptID, "gate_digest": a.GateDigest, "definition_sha256": a.DefinitionSHA256, "actor_id": a.ActorID} {
		if strings.TrimSpace(value) == "" || len(value) > 512 || strings.IndexFunc(value, unicode.IsControl) >= 0 || !utf8.ValidString(value) {
			return fmt.Errorf("journal: invalid command run admission %s", name)
		}
	}
	for name, value := range map[string]string{"trigger_id": a.TriggerID, "trigger_event_id": a.TriggerEventID} {
		if len(value) > 512 || strings.IndexFunc(value, unicode.IsControl) >= 0 || !utf8.ValidString(value) {
			return fmt.Errorf("journal: invalid command run admission %s", name)
		}
	}
	if a.TriggerKind != "" && a.TriggerKind != CommandRunTriggerSchedule && a.TriggerKind != CommandRunTriggerWebhook && a.TriggerKind != CommandRunTriggerChain {
		return errors.New("journal: invalid command run admission trigger kind")
	}
	if (a.TriggerID == "") != (a.TriggerEventID == "") || (a.TriggerKind != "" && a.TriggerID == "") {
		return errors.New("journal: command run trigger provenance is incomplete")
	}
	if len(a.GateDigest) != 64 {
		return errors.New("journal: command run gate digest must be sha256")
	}
	if _, err := hex.DecodeString(a.GateDigest); err != nil {
		return errors.New("journal: command run gate digest must be hexadecimal")
	}
	if len(a.DefinitionSHA256) != 64 {
		return errors.New("journal: command run definition digest must be sha256")
	}
	if _, err := hex.DecodeString(a.DefinitionSHA256); err != nil {
		return errors.New("journal: command run definition digest must be hexadecimal")
	}
	b, err := json.Marshal(a)
	if err != nil || len(b) > MaxCommandAdmissionBytes {
		return errors.New("journal: command run admission is too large")
	}
	return nil
}

func validCommandRunID(id string) error {
	// A caller can supply this identity and ordinary MCP run receipts return
	// it for correlation. Keep newly persisted IDs to opaque ASCII tokens so
	// arbitrary customer text cannot be smuggled into the default AI read.
	if len(id) == 0 || len(id) > 128 {
		return errors.New("journal: invalid command run id")
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if i > 0 && (c == '_' || c == '-' || c == '.') {
			continue
		}
		return errors.New("journal: invalid command run id")
	}
	return nil
}

func boundCommandOutput(raw []byte, max int) (string, int, bool) {
	bytes := len(raw)
	text := strings.ToValidUTF8(string(raw), "�")
	if len(text) > max {
		text = text[:max]
		for len(text) > 0 && !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
	}
	return text, bytes, bytes > max
}

func boundCommandError(raw string) (string, int, bool) {
	bytes := len(raw)
	raw = strings.ToValidUTF8(raw, "�")
	if len(raw) > MaxCommandErrorBytes {
		raw = raw[:MaxCommandErrorBytes]
		for len(raw) > 0 && !utf8.ValidString(raw) {
			raw = raw[:len(raw)-1]
		}
	}
	return raw, bytes, bytes > MaxCommandErrorBytes
}

// scrubBoundCommandOutput gives the redactor a bounded lookahead beyond the
// durable cap. Without that lookahead, a bearer token or email that starts at
// the last bytes of the retained prefix can be cut before its pattern is
// complete and a partial value could survive persistence. The sandbox capture
// is limited to the same two-cap window; direct callers are clipped here too.
func scrubBoundCommandOutput(raw []byte, max int) (string, int, bool) {
	total := len(raw)
	scanLimit := max * 2
	if scanLimit < max {
		scanLimit = max
	}
	scan := raw
	if len(scan) > scanLimit {
		scan = scan[:scanLimit]
	}
	scrubbed := knowledge.NewRedactor().Scrub(string(scan))
	text, _, visibleTruncated := boundCommandOutput([]byte(scrubbed), max)
	return text, total, total > max || visibleTruncated || len(scan) < len(raw)
}

// scrubBoundCommandError applies the generic redactor and then reapplies the
// error cap. Redaction markers can expand a matched value, so a pre-scrub
// bound alone is insufficient to keep the durable error column bounded.
func scrubBoundCommandError(raw string) string {
	scanLimit := MaxCommandErrorBytes * 2
	if len(raw) > scanLimit {
		raw = raw[:scanLimit]
	}
	bounded := knowledge.NewRedactor().Scrub(raw)
	bounded, _, _ = boundCommandError(bounded)
	return bounded
}

func (j *Journal) scanCommandRun(scan func(...any) error) (CommandRun, error) {
	var (
		run                                                                         CommandRun
		rawAdmission                                                                []byte
		claimOwner, claimToken, lease, retryOf, created, started, finished, updated any
		errText                                                                     sql.NullString
		errorBytes, plainBytes                                                      sql.NullInt64
		errorVersion                                                                int
	)
	if err := scan(&run.ID, &run.TenantID, &run.AutomationID, &run.AutomationVersion, &run.DefinitionSHA256,
		&run.Target, &run.ActorID, &rawAdmission, &run.Status, &retryOf, &run.Attempt, &claimOwner, &claimToken,
		&lease, &errText, &errorBytes, &errorVersion, &plainBytes, &created, &started, &finished, &updated); err != nil {
		return CommandRun{}, err
	}
	if err := json.Unmarshal(rawAdmission, &run.Admission); err != nil {
		return CommandRun{}, fmt.Errorf("journal: decode command run admission: %w", err)
	}
	run.RetryOf = anyToString(retryOf)
	run.ClaimOwner, run.ClaimToken = anyToString(claimOwner), anyToString(claimToken)
	if errorVersion == 1 {
		if !plainBytes.Valid || !errText.Valid {
			return CommandRun{}, payloadcrypto.ErrInvalidEnvelope
		}
		opened, err := j.openCommandField(run.TenantID, run.ID, 0, 0, "run_error", errorVersion, errText)
		if err != nil || len(opened) != int(plainBytes.Int64) {
			return CommandRun{}, payloadReadError(err)
		}
		run.ErrorText = opened
	} else if errorVersion == 0 && !plainBytes.Valid {
		run.ErrorText = errText.String
	} else {
		return CommandRun{}, payloadcrypto.ErrInvalidEnvelope
	}
	if errorBytes.Valid && errorBytes.Int64 >= 0 {
		run.ErrorBytes = int(errorBytes.Int64)
		run.ErrorTruncated = run.ErrorBytes > len([]byte(run.ErrorText))
	}
	run.CreatedAt, run.UpdatedAt = j.anyTime(created), j.anyTime(updated)
	if t := j.anyTime(lease); !t.IsZero() {
		run.LeaseExpiresAt = &t
	}
	if t := j.anyTime(started); !t.IsZero() {
		run.StartedAt = &t
	}
	if t := j.anyTime(finished); !t.IsZero() {
		run.FinishedAt = &t
	}
	return run, nil
}

func (j *Journal) scanCommandRunStep(scan func(...any) error, tenantID string) (CommandRunStep, error) {
	return j.scanCommandRunStepPayload(scan, tenantID, false, MaxCommandOutputBytes)
}

// The bounded projection can omit a field in SQL before it enters the MCP
// process. The worker projection requires every selected field to authenticate.
func (j *Journal) scanCommandRunStepBounded(scan func(...any) error, tenantID string, maxOutputBytes int) (CommandRunStep, error) {
	return j.scanCommandRunStepPayload(scan, tenantID, true, maxOutputBytes)
}

func (j *Journal) scanCommandRunStepPayload(scan func(...any) error, tenantID string, allowOmitted bool, maxOutputBytes int) (CommandRunStep, error) {
	var (
		step                                                 CommandRunStep
		exit                                                 sql.NullInt64
		stdout, stderr, errText                              sql.NullString
		started, finished, updated, stdoutTrunc, stderrTrunc any
		errorBytes, errorPlaintextBytes                      sql.NullInt64
		stdoutVersion, stderrVersion, errorVersion           int
	)
	if err := scan(&step.RunID, &step.StepSeq, &step.StepName, &step.CommandSHA256, &step.ExpectedExitCode,
		&step.TimeoutSeconds, &step.Status, &step.Attempt, &exit, &stdout, &stderr, &step.StdoutBytes,
		&step.StderrBytes, &stdoutTrunc, &stderrTrunc, &errText, &errorBytes,
		&stdoutVersion, &stderrVersion, &errorVersion, &errorPlaintextBytes,
		&started, &finished, &updated); err != nil {
		return CommandRunStep{}, err
	}
	if exit.Valid {
		value := int(exit.Int64)
		step.ExitCode = &value
	}
	step.StdoutTruncated, step.StderrTruncated = parseBool(stdoutTrunc), parseBool(stderrTrunc)
	for _, field := range []struct {
		name    string
		stored  sql.NullString
		version int
		text    *string
		trunc   *bool
		bytes   int
	}{
		{"step_stdout", stdout, stdoutVersion, &step.StdoutText, &step.StdoutTruncated, step.StdoutBytes},
		{"step_stderr", stderr, stderrVersion, &step.StderrText, &step.StderrTruncated, step.StderrBytes},
	} {
		if !field.stored.Valid {
			if !allowOmitted {
				return CommandRunStep{}, payloadcrypto.ErrInvalidEnvelope
			}
			if maxOutputBytes > 0 && field.bytes > 0 {
				*field.trunc = true
			}
			continue
		}
		opened, err := j.openCommandField(tenantID, step.RunID, step.StepSeq, step.Attempt, field.name, field.version, field.stored)
		if err != nil {
			return CommandRunStep{}, err
		}
		*field.text = opened
	}
	if errorBytes.Valid && errorBytes.Int64 >= 0 {
		step.ErrorBytes = int(errorBytes.Int64)
	}
	if errorVersion == 1 {
		if !errorPlaintextBytes.Valid || errorPlaintextBytes.Int64 < 0 || errorPlaintextBytes.Int64 > MaxCommandErrorBytes ||
			step.ErrorBytes != int(errorPlaintextBytes.Int64) {
			return CommandRunStep{}, payloadcrypto.ErrInvalidEnvelope
		}
	} else if errorVersion != 0 || errorPlaintextBytes.Valid {
		return CommandRunStep{}, payloadcrypto.ErrInvalidEnvelope
	}
	if errText.Valid {
		opened, err := j.openCommandField(tenantID, step.RunID, step.StepSeq, step.Attempt, "step_error", errorVersion, errText)
		if err != nil {
			return CommandRunStep{}, err
		}
		if errorVersion == 1 && len(opened) != step.ErrorBytes {
			return CommandRunStep{}, payloadcrypto.ErrInvalidEnvelope
		}
		step.ErrorText = opened
	} else if !allowOmitted {
		return CommandRunStep{}, payloadcrypto.ErrInvalidEnvelope
	}
	step.ErrorTruncated = step.ErrorBytes > len(step.ErrorText)
	step.UpdatedAt = j.anyTime(updated)
	if t := j.anyTime(started); !t.IsZero() {
		step.StartedAt = &t
	}
	if t := j.anyTime(finished); !t.IsZero() {
		step.FinishedAt = &t
	}
	return step, nil
}
