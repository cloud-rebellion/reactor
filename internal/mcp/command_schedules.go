package mcp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	robfig "github.com/robfig/cron/v3"
)

const (
	maxMCPCommandAutomationSchedulePage = 100
	maxMCPCommandAutomationScheduleSpec = 256
	maxMCPCommandAutomationScheduleZone = 128
)

// CommandAutomationScheduleStore is the narrow durable boundary used by the
// MCP tools. Implementations must enforce tenant ownership, optimistic
// revision checks, immutable receipt binding, and idempotent creation in one
// database transaction. The MCP layer validates syntax and the exact plan
// digest before calling these methods; the store remains the final authority.
type CommandAutomationScheduleStore interface {
	CreateCommandAutomationScheduleWithIdempotency(context.Context, string, journal.CommandAutomationScheduleInput, string) (journal.CommandAutomationSchedule, bool, error)
	ListCommandAutomationSchedulesForTenantPage(context.Context, journal.CommandAutomationScheduleFilter) ([]journal.CommandAutomationSchedule, bool, error)
	GetCommandAutomationScheduleForTenant(context.Context, string, string) (journal.CommandAutomationSchedule, error)
	UpdateCommandAutomationScheduleIfRevision(context.Context, string, string, journal.CommandAutomationScheduleUpdate, int64) error
	SetCommandAutomationScheduleStateIfRevision(context.Context, string, string, string, int64) error
	DeleteCommandAutomationScheduleIfRevision(context.Context, string, string, int64) error
}

var _ CommandAutomationScheduleStore = (*journal.Journal)(nil)

func (s *Server) registerCommandAutomationScheduleTools() {
	store := s.CommandAutomationSchedules
	if store == nil && s.Journal != nil {
		// The production journal implements this narrow interface directly. An
		// embedding may still provide an adapter explicitly, while the ordinary
		// daemon does not need a second wiring path just to expose durable
		// schedules.
		if candidate, ok := any(s.Journal).(CommandAutomationScheduleStore); ok {
			store = candidate
		}
	}
	if s.Journal == nil || store == nil {
		return
	}

	s.tools["reactor_list_command_automation_schedules"] = toolDef{tool: Tool{
		Name:        "reactor_list_command_automation_schedules",
		Description: "List bounded tenant-owned schedules for command automations. Schedules expose only immutable-version and receipt metadata; command text, credentials, and operation idempotency keys are never returned.",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{
			"automation_id": map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes, "description": "optional exact command automation id"},
			"state":         map[string]any{"type": "string", "enum": []string{"active", "disabled"}},
			"limit":         map[string]any{"type": "integer", "minimum": 1, "maximum": maxMCPCommandAutomationSchedulePage, "default": 50},
			"offset":        map[string]any{"type": "integer", "minimum": 0, "maximum": 10000, "default": 0},
		}},
	}, handler: func(ctx context.Context, args json.RawMessage) (any, error) {
		var a struct {
			AutomationID string `json:"automation_id"`
			State        string `json:"state"`
			Limit        int    `json:"limit"`
			Offset       int    `json:"offset"`
		}
		if err := decodeCommandArgs(args, &a); err != nil {
			return nil, err
		}
		a.AutomationID = strings.TrimSpace(a.AutomationID)
		a.State = strings.TrimSpace(a.State)
		if len(a.AutomationID) > maxMCPRunIdentityBytes {
			return nil, fmt.Errorf("%w: automation_id exceeds %d bytes", errInvalidParamsErr, maxMCPRunIdentityBytes)
		}
		if a.State != "" && a.State != journal.CommandAutomationScheduleActive && a.State != journal.CommandAutomationScheduleDisabled {
			return nil, fmt.Errorf("%w: state must be active or disabled", errInvalidParamsErr)
		}
		if a.Limit == 0 {
			a.Limit = 50
		}
		if a.Limit < 1 || a.Limit > maxMCPCommandAutomationSchedulePage || a.Offset < 0 || a.Offset > 10000 {
			return nil, fmt.Errorf("%w: limit must be 1..%d and offset 0..10000", errInvalidParamsErr, maxMCPCommandAutomationSchedulePage)
		}
		rows, more, err := store.ListCommandAutomationSchedulesForTenantPage(ctx, journal.CommandAutomationScheduleFilter{
			TenantID: s.tenantID(ctx), AutomationID: a.AutomationID, State: a.State, Limit: a.Limit, Offset: a.Offset,
		})
		if err != nil {
			return nil, err
		}
		views := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			views = append(views, mcpCommandAutomationScheduleView(row))
		}
		result := map[string]any{"schedules": views, "automation_id": a.AutomationID, "state": a.State, "limit": a.Limit, "offset": a.Offset, "has_more": more, "content_trust": "metadata"}
		if more {
			result["next_offset"] = a.Offset + len(views)
		}
		return result, nil
	}}

	// A schedule is both a trigger and a command-dispatch authority. Require
	// both explicit scopes when the daemon uses scoped MCP, so granting command
	// execution alone cannot create an unattended trigger.
	if !s.writeEnabled(s.Scopes == nil || (s.Scopes.CommandExecution && s.Scopes.Triggers)) {
		return
	}

	s.tools["reactor_create_command_automation_schedule"] = toolDef{tool: Tool{
		Name:        "reactor_create_command_automation_schedule",
		Description: "Create a disabled cron schedule for one exact reviewed command-automation version. The supplied preflight receipt and gate digest are checked against the immutable definition; creation never enables or dispatches the plan. Requires both trigger and command-execution MCP scopes.",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []string{"name", "version", "spec", "receipt_id", "gate_digest"}, "properties": map[string]any{
			"name":            map[string]any{"type": "string"},
			"version":         map[string]any{"type": "integer", "minimum": 1},
			"spec":            map[string]any{"type": "string", "maxLength": maxMCPCommandAutomationScheduleSpec, "description": "five-field cron expression"},
			"timezone":        map[string]any{"type": "string", "maxLength": maxMCPCommandAutomationScheduleZone, "description": "IANA timezone; defaults to UTC"},
			"receipt_id":      map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes, "description": "receipt_id returned by reactor_preflight_command_automation"},
			"gate_digest":     map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes, "description": "gate_digest returned by reactor_preflight_command_automation"},
			"idempotency_key": map[string]any{"type": "string", "minLength": 1, "maxLength": 200},
		}},
	}, handler: func(ctx context.Context, args json.RawMessage) (any, error) {
		var a struct {
			Name           string `json:"name"`
			Version        int    `json:"version"`
			Spec           string `json:"spec"`
			Timezone       string `json:"timezone"`
			ReceiptID      string `json:"receipt_id"`
			GateDigest     string `json:"gate_digest"`
			IdempotencyKey string `json:"idempotency_key"`
		}
		if err := decodeCommandArgs(args, &a); err != nil {
			return nil, err
		}
		key, err := normalizeTriggerIdempotencyKey(args, a.IdempotencyKey)
		if err != nil {
			return nil, err
		}
		a.Name, a.Spec, a.Timezone, a.ReceiptID, a.GateDigest = strings.TrimSpace(a.Name), strings.TrimSpace(a.Spec), strings.TrimSpace(a.Timezone), strings.TrimSpace(a.ReceiptID), strings.TrimSpace(a.GateDigest)
		if !commandautomations.ValidName(a.Name) || a.Version < 1 {
			return nil, fmt.Errorf("%w: valid name and positive version are required", errInvalidParamsErr)
		}
		spec, timezone, err := validateCommandAutomationSchedule(a.Spec, a.Timezone)
		if err != nil {
			return nil, err
		}
		if len(a.ReceiptID) == 0 || len(a.ReceiptID) > maxMCPRunIdentityBytes || len(a.GateDigest) == 0 || len(a.GateDigest) > maxMCPRunIdentityBytes {
			return nil, fmt.Errorf("%w: receipt_id and gate_digest are required and bounded", errInvalidParamsErr)
		}
		if len(a.GateDigest) != 64 || hex.DecodedLen(len(a.GateDigest)) != 32 {
			return nil, fmt.Errorf("%w: gate_digest must be a 64-character SHA-256 digest", errInvalidParamsErr)
		}
		if _, err := hex.DecodeString(a.GateDigest); err != nil {
			return nil, fmt.Errorf("%w: gate_digest must be hexadecimal", errInvalidParamsErr)
		}
		plan, err := s.Journal.GetCommandAutomationByName(ctx, s.tenantID(ctx), a.Name)
		if err != nil {
			return nil, err
		}
		if plan.CurrentVersion != a.Version {
			return nil, fmt.Errorf("%w: version %d is not the current reviewed version %d", errInvalidParamsErr, a.Version, plan.CurrentVersion)
		}
		stored, err := s.Journal.GetCommandAutomationVersion(ctx, s.tenantID(ctx), plan.ID, a.Version)
		if err != nil {
			return nil, err
		}
		definitionSHA256 := commandDefinitionSHA256(stored.DefinitionJSON)
		expectedReceipt := commandautomations.ReceiptIDForGateDigest(s.tenantID(ctx), plan.ID, a.Version, definitionSHA256, a.GateDigest)
		if a.ReceiptID != expectedReceipt {
			return nil, fmt.Errorf("%w: receipt_id does not bind this tenant, automation, version, definition, and gate_digest", errInvalidParamsErr)
		}
		row, replayed, err := store.CreateCommandAutomationScheduleWithIdempotency(ctx, s.tenantID(ctx), journal.CommandAutomationScheduleInput{
			AutomationID: plan.ID, AutomationVersion: a.Version, DefinitionSHA256: definitionSHA256,
			ReceiptID: a.ReceiptID, GateDigest: a.GateDigest, ActorID: s.actorID(ctx), Spec: spec, Timezone: timezone,
		}, key)
		if err != nil {
			return nil, err
		}
		if row.State != journal.CommandAutomationScheduleDisabled {
			return nil, fmt.Errorf("%w: schedule store returned a non-disabled create receipt", errInvalidParamsErr)
		}
		result := map[string]any{"schedule": mcpCommandAutomationScheduleView(row), "idempotent": replayed, "state": row.State, "execution_note": "Created disabled. Enabling requires a current exact-version receipt, administrator authorization, fresh step-up, and runtime admission checks."}
		for key, value := range s.commandScheduleRuntimeReceipt(ctx) {
			result[key] = value
		}
		return result, nil
	}}

	s.tools["reactor_update_command_automation_schedule"] = toolDef{tool: Tool{
		Name:        "reactor_update_command_automation_schedule",
		Description: "Update a disabled command-automation schedule with optimistic revision fencing. Cron syntax and timezone are validated before the durable mutation; active schedules must be disabled first. Requires both trigger and command-execution MCP scopes.",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []string{"schedule_id", "spec", "expected_revision"}, "properties": map[string]any{
			"schedule_id":       map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes},
			"spec":              map[string]any{"type": "string", "maxLength": maxMCPCommandAutomationScheduleSpec},
			"timezone":          map[string]any{"type": "string", "maxLength": maxMCPCommandAutomationScheduleZone},
			"expected_revision": map[string]any{"type": "integer", "minimum": 1},
		}},
	}, handler: func(ctx context.Context, args json.RawMessage) (any, error) {
		var a struct {
			ScheduleID       string `json:"schedule_id"`
			Spec             string `json:"spec"`
			Timezone         string `json:"timezone"`
			ExpectedRevision int64  `json:"expected_revision"`
		}
		if err := decodeCommandArgs(args, &a); err != nil {
			return nil, err
		}
		a.ScheduleID, a.Spec, a.Timezone = strings.TrimSpace(a.ScheduleID), strings.TrimSpace(a.Spec), strings.TrimSpace(a.Timezone)
		if a.ScheduleID == "" || len(a.ScheduleID) > maxMCPRunIdentityBytes || a.ExpectedRevision < 1 {
			return nil, fmt.Errorf("%w: schedule_id and positive expected_revision are required", errInvalidParamsErr)
		}
		if revision, present, err := optionalMCPPositiveInt(args, "expected_revision"); err != nil {
			return nil, err
		} else if !present {
			return nil, fmt.Errorf("%w: expected_revision is required", errInvalidParamsErr)
		} else if revision > int64(^uint64(0)>>1) {
			return nil, fmt.Errorf("%w: expected_revision is too large", errInvalidParamsErr)
		} else {
			a.ExpectedRevision = revision
		}
		spec, timezone, err := validateCommandAutomationSchedule(a.Spec, a.Timezone)
		if err != nil {
			return nil, err
		}
		current, err := store.GetCommandAutomationScheduleForTenant(ctx, s.tenantID(ctx), a.ScheduleID)
		if err != nil {
			return nil, err
		}
		if current.State != "disabled" {
			return nil, fmt.Errorf("%w: disable the schedule before editing it", errInvalidParamsErr)
		}
		err = store.UpdateCommandAutomationScheduleIfRevision(ctx, s.tenantID(ctx), a.ScheduleID, journal.CommandAutomationScheduleUpdate{
			AutomationVersion: current.AutomationVersion, DefinitionSHA256: current.DefinitionSHA256, ReceiptID: current.ReceiptID,
			GateDigest: current.GateDigest, ActorID: current.ActorID, Spec: spec, Timezone: timezone,
		}, a.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		updated, err := store.GetCommandAutomationScheduleForTenant(ctx, s.tenantID(ctx), a.ScheduleID)
		if err != nil {
			return nil, err
		}
		result := map[string]any{"schedule": mcpCommandAutomationScheduleView(updated), "updated": true, "execution_note": "Schedule remains disabled until explicitly enabled after a fresh exact-version review."}
		for key, value := range s.commandScheduleRuntimeReceipt(ctx) {
			result[key] = value
		}
		return result, nil
	}}

	s.tools["reactor_set_command_automation_schedule_state"] = toolDef{tool: Tool{
		Name:        "reactor_set_command_automation_schedule_state",
		Description: "Enable or disable one command-automation schedule with optimistic revision fencing. Enabling requires the bound plan to remain current and enabled, plus fresh administrator and step-up authorization; disabling is an emergency stop. Requires both trigger and command-execution MCP scopes.",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []string{"schedule_id", "state", "expected_revision"}, "properties": map[string]any{
			"schedule_id":       map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes},
			"state":             map[string]any{"type": "string", "enum": []string{"active", "disabled"}},
			"expected_revision": map[string]any{"type": "integer", "minimum": 1},
		}},
	}, handler: func(ctx context.Context, args json.RawMessage) (any, error) {
		var a struct {
			ScheduleID       string `json:"schedule_id"`
			State            string `json:"state"`
			ExpectedRevision int64  `json:"expected_revision"`
		}
		if err := decodeCommandArgs(args, &a); err != nil {
			return nil, err
		}
		a.ScheduleID, a.State = strings.TrimSpace(a.ScheduleID), strings.TrimSpace(a.State)
		if a.ScheduleID == "" || len(a.ScheduleID) > maxMCPRunIdentityBytes || (a.State != "active" && a.State != "disabled") || a.ExpectedRevision < 1 {
			return nil, fmt.Errorf("%w: schedule_id, state, and positive expected_revision are required", errInvalidParamsErr)
		}
		if revision, present, err := optionalMCPPositiveInt(args, "expected_revision"); err != nil {
			return nil, err
		} else if !present {
			return nil, fmt.Errorf("%w: expected_revision is required", errInvalidParamsErr)
		} else if revision > int64(^uint64(0)>>1) {
			return nil, fmt.Errorf("%w: expected_revision is too large", errInvalidParamsErr)
		} else {
			a.ExpectedRevision = revision
		}
		current, err := store.GetCommandAutomationScheduleForTenant(ctx, s.tenantID(ctx), a.ScheduleID)
		if err != nil {
			return nil, err
		}
		if a.State == "active" {
			plan, err := s.Journal.GetCommandAutomation(ctx, s.tenantID(ctx), current.AutomationID)
			if err != nil {
				return nil, err
			}
			if !plan.Enabled || plan.CurrentVersion != current.AutomationVersion {
				return nil, fmt.Errorf("%w: the bound command automation must be enabled at its current version before activating a schedule", errInvalidParamsErr)
			}
			stored, err := s.Journal.GetCommandAutomationVersion(ctx, s.tenantID(ctx), current.AutomationID, current.AutomationVersion)
			if err != nil {
				return nil, err
			}
			definition, err := decodeStoredCommandDefinition(stored.DefinitionJSON)
			if err != nil {
				return nil, err
			}
			if s.CommandExecutionCapabilities == nil {
				return nil, fmt.Errorf("%w: command execution authorization is unavailable", errInvalidParamsErr)
			}
			caps := s.CommandExecutionCapabilities(ctx, definition)
			if s.CommandTenantAllowed != nil && !s.CommandTenantAllowed(ctx) {
				caps.SingleTenant = false
			}
			// A schedule is a durable future dispatch. Re-evaluate the same
			// tenant/grant/resolver facts used by preflight before activating it;
			// storing a receipt from an earlier credential state must not open a
			// path that the eventual worker cannot safely serve.
			credentialIDs := commandDefinitionCredentialIDs(definition)
			_, missingCredentials := s.commandCredentialReadiness(ctx, definition, current.AutomationID)
			if len(missingCredentials) > 0 {
				caps.VaultBoundaryReady = false
				caps.CredentialsSupported = false
			}
			if len(credentialIDs) > 0 {
				if s.CommandCredentialResolverReady == nil {
					caps.CredentialsSupported = false
				} else {
					for _, credentialID := range credentialIDs {
						if !s.CommandCredentialResolverReady(ctx, credentialID) {
							caps.CredentialsSupported = false
							break
						}
					}
				}
			}
			if !caps.AdminAuthorized || !caps.StepUpAuthorized {
				return nil, fmt.Errorf("%w: administrator authorization and a fresh step-up are required to activate a schedule", errInvalidParamsErr)
			}
			caps.AutomationEnabled = true
			if s.CommandTargetAllowed != nil {
				caps.TargetReady = s.CommandTargetAllowed(ctx, plan.Target)
			}
			receipt := commandautomations.EvaluateExecutionGates(definition, caps)
			definitionSHA256 := commandDefinitionSHA256(stored.DefinitionJSON)
			binding := commandautomations.BindExecutionReceipt(s.tenantID(ctx), current.AutomationID, current.AutomationVersion, definitionSHA256, receipt)
			if current.DefinitionSHA256 != definitionSHA256 || current.ReceiptID != binding.ReceiptID || current.GateDigest != binding.GateDigest || !receipt.Executable {
				return nil, fmt.Errorf("%w: schedule receipt is stale or its current execution gates are closed; create a new schedule from a fresh preflight", errInvalidParamsErr)
			}
		}
		if a.State == "active" && current.State == "active" {
			return nil, fmt.Errorf("%w: schedule is already active", errInvalidParamsErr)
		}
		if err := store.SetCommandAutomationScheduleStateIfRevision(ctx, s.tenantID(ctx), a.ScheduleID, a.State, a.ExpectedRevision); err != nil {
			return nil, err
		}
		updated, err := store.GetCommandAutomationScheduleForTenant(ctx, s.tenantID(ctx), a.ScheduleID)
		if err != nil {
			return nil, err
		}
		result := map[string]any{"schedule": mcpCommandAutomationScheduleView(updated), "state": a.State, "updated": true}
		for key, value := range s.commandScheduleRuntimeReceipt(ctx) {
			result[key] = value
		}
		return result, nil
	}}

	s.tools["reactor_delete_command_automation_schedule"] = toolDef{tool: Tool{
		Name:        "reactor_delete_command_automation_schedule",
		Description: "Delete a disabled command-automation schedule after an exact revision check. Active schedules must be disabled first; the immutable plan and its execution receipts remain independent journal records. Requires both trigger and command-execution MCP scopes.",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []string{"schedule_id", "expected_revision"}, "properties": map[string]any{
			"schedule_id":       map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes},
			"expected_revision": map[string]any{"type": "integer", "minimum": 1},
		}},
	}, handler: func(ctx context.Context, args json.RawMessage) (any, error) {
		var a struct {
			ScheduleID       string `json:"schedule_id"`
			ExpectedRevision int64  `json:"expected_revision"`
		}
		if err := decodeCommandArgs(args, &a); err != nil {
			return nil, err
		}
		a.ScheduleID = strings.TrimSpace(a.ScheduleID)
		if a.ScheduleID == "" || len(a.ScheduleID) > maxMCPRunIdentityBytes || a.ExpectedRevision < 1 {
			return nil, fmt.Errorf("%w: schedule_id and positive expected_revision are required", errInvalidParamsErr)
		}
		if revision, present, err := optionalMCPPositiveInt(args, "expected_revision"); err != nil {
			return nil, err
		} else if !present {
			return nil, fmt.Errorf("%w: expected_revision is required", errInvalidParamsErr)
		} else if revision > int64(^uint64(0)>>1) {
			return nil, fmt.Errorf("%w: expected_revision is too large", errInvalidParamsErr)
		} else {
			a.ExpectedRevision = revision
		}
		row, err := store.GetCommandAutomationScheduleForTenant(ctx, s.tenantID(ctx), a.ScheduleID)
		if err != nil {
			return nil, err
		}
		if row.State != "disabled" {
			return nil, fmt.Errorf("%w: disable the schedule before deleting it", errInvalidParamsErr)
		}
		if err := store.DeleteCommandAutomationScheduleIfRevision(ctx, s.tenantID(ctx), a.ScheduleID, a.ExpectedRevision); err != nil {
			return nil, err
		}
		result := map[string]any{"schedule_id": a.ScheduleID, "deleted": true, "deleted_revision": a.ExpectedRevision}
		for key, value := range s.commandScheduleRuntimeReceipt(ctx) {
			result[key] = value
		}
		return result, nil
	}}
}

func (s *Server) reconcileCommandSchedules(ctx context.Context) error {
	if s == nil || s.ReconcileCommandSchedules == nil {
		return nil
	}
	return s.ReconcileCommandSchedules(ctx)
}

func (s *Server) commandScheduleRuntimeReceipt(ctx context.Context) map[string]any {
	if s == nil || s.ReconcileCommandSchedules == nil {
		return map[string]any{
			"runtime_reconciled": false,
			"runtime_note":       "durable schedule change saved; the configured command cron driver will apply it on its next reconcile or daemon restart",
		}
	}
	if err := s.reconcileCommandSchedules(ctx); err != nil {
		if s.Log != nil {
			s.Log.Warn("mcp: command schedule runtime reconcile deferred", "err", err)
		}
		return map[string]any{
			"runtime_reconciled": false,
			"runtime_note":       "durable schedule change saved; the configured command cron driver will apply it on its next reconcile or daemon restart",
		}
	}
	return map[string]any{"runtime_reconciled": true}
}

func validateCommandAutomationSchedule(spec, timezone string) (string, string, error) {
	spec = strings.TrimSpace(spec)
	timezone = strings.TrimSpace(timezone)
	if spec == "" {
		return "", "", fmt.Errorf("%w: spec is required", errInvalidParamsErr)
	}
	if len(spec) > maxMCPCommandAutomationScheduleSpec || len(timezone) > maxMCPCommandAutomationScheduleZone {
		return "", "", fmt.Errorf("%w: cron spec or timezone too long", errInvalidParamsErr)
	}
	if len(strings.Fields(spec)) != 5 {
		return "", "", fmt.Errorf("%w: cron spec must contain exactly five fields", errInvalidParamsErr)
	}
	if timezone == "" {
		timezone = "UTC"
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		return "", "", fmt.Errorf("%w: invalid timezone: %v", errInvalidParamsErr, err)
	}
	if _, err := robfig.ParseStandard("CRON_TZ=" + timezone + " " + spec); err != nil {
		return "", "", fmt.Errorf("%w: invalid cron spec or timezone: %v", errInvalidParamsErr, err)
	}
	return spec, timezone, nil
}

func mcpCommandAutomationScheduleView(row journal.CommandAutomationSchedule) map[string]any {
	view := map[string]any{
		"id": row.ID, "tenant_id": row.TenantID, "automation_id": row.AutomationID, "version": row.AutomationVersion,
		"definition_sha256": row.DefinitionSHA256, "receipt_id": row.ReceiptID, "gate_digest": row.GateDigest,
		"actor_id": row.ActorID, "spec": row.Spec, "timezone": row.Timezone, "state": row.State, "revision": row.Revision,
		"created_at": row.CreatedAt, "updated_at": row.UpdatedAt, "content_trust": "metadata",
	}
	if row.LastFiredAt != nil {
		view["last_fired_at"] = *row.LastFiredAt
	}
	if row.LastError != "" {
		// Runtime errors are untrusted worker output and may contain credentials
		// or target details. Keep only a presence/byte receipt in the schedule
		// inventory; the tenant-scoped run inspection surface owns diagnostics.
		view["last_error_present"] = true
		view["last_error_trust"] = "redacted"
		view["last_error_bytes"] = len([]byte(row.LastError))
	}
	for _, field := range []struct {
		name string
		max  int
	}{
		{"id", maxMCPRunIdentityBytes}, {"tenant_id", maxMCPRunIdentityBytes}, {"automation_id", maxMCPRunIdentityBytes},
		{"definition_sha256", maxMCPRunIdentityBytes}, {"receipt_id", maxMCPRunIdentityBytes}, {"gate_digest", maxMCPRunIdentityBytes},
		{"actor_id", maxMCPCommandRunActorBytes}, {"spec", maxMCPCommandAutomationScheduleSpec}, {"timezone", maxMCPCommandAutomationScheduleZone}, {"state", maxMCPCommandRunStatusBytes},
	} {
		value, _ := view[field.name].(string)
		bounded, truncated, bytes := boundMCPText(value, field.max)
		view[field.name] = bounded
		if truncated {
			view[field.name+"_truncated"], view[field.name+"_bytes"] = true, bytes
		}
	}
	return view
}
