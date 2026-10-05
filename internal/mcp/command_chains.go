package mcp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

const maxMCPCommandAutomationChainPage = 100

// CommandAutomationChainStore is intentionally separate from workflow
// triggers and from command cron/webhook stores. Implementations must keep the
// source workflow, plan tenant, immutable version, and receipt binding in the
// same durable fence.
type CommandAutomationChainStore interface {
	CreateCommandAutomationChainTriggerWithIdempotency(context.Context, string, journal.CommandAutomationChainTriggerInput, string) (journal.CommandAutomationChainTrigger, bool, error)
	GetCommandAutomationChainTriggerForTenant(context.Context, string, string) (journal.CommandAutomationChainTrigger, error)
	ListCommandAutomationChainTriggersForTenantPage(context.Context, journal.CommandAutomationChainTriggerFilter) ([]journal.CommandAutomationChainTrigger, bool, error)
	UpdateCommandAutomationChainTriggerIfRevision(context.Context, string, string, journal.CommandAutomationChainTriggerUpdate, int64) error
	SetCommandAutomationChainTriggerStateIfRevision(context.Context, string, string, string, int64) error
	DeleteCommandAutomationChainTriggerIfRevision(context.Context, string, string, int64) error
}

var _ CommandAutomationChainStore = (*journal.Journal)(nil)

func (s *Server) registerCommandAutomationChainTools() {
	store := s.CommandAutomationChains
	if store == nil && s.Journal != nil {
		if candidate, ok := any(s.Journal).(CommandAutomationChainStore); ok {
			store = candidate
		}
	}
	if s.Journal == nil || store == nil {
		return
	}

	s.tools["reactor_list_command_automation_chains"] = toolDef{tool: Tool{
		Name:        "reactor_list_command_automation_chains",
		Description: "List bounded tenant-owned terminal-chain bindings for command automations. Source workflow identity and immutable receipt metadata are returned; event payloads, command text, credentials, and operation keys are never returned.",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{
			"automation_id":      map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes},
			"source_workflow_id": map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes},
			"state":              map[string]any{"type": "string", "enum": []string{"active", "disabled"}},
			"limit":              map[string]any{"type": "integer", "minimum": 1, "maximum": maxMCPCommandAutomationChainPage, "default": 50},
			"offset":             map[string]any{"type": "integer", "minimum": 0, "maximum": 10000, "default": 0},
		}},
	}, handler: func(ctx context.Context, args json.RawMessage) (any, error) {
		var a struct {
			AutomationID     string `json:"automation_id"`
			SourceWorkflowID string `json:"source_workflow_id"`
			State            string `json:"state"`
			Limit            int    `json:"limit"`
			Offset           int    `json:"offset"`
		}
		if err := decodeCommandArgs(args, &a); err != nil {
			return nil, err
		}
		a.AutomationID, a.SourceWorkflowID, a.State = strings.TrimSpace(a.AutomationID), strings.TrimSpace(a.SourceWorkflowID), strings.TrimSpace(a.State)
		if a.Limit == 0 {
			a.Limit = 50
		}
		if a.Limit < 1 || a.Limit > maxMCPCommandAutomationChainPage || a.Offset < 0 || a.Offset > 10000 {
			return nil, fmt.Errorf("%w: limit must be 1..%d and offset 0..10000", errInvalidParamsErr, maxMCPCommandAutomationChainPage)
		}
		if a.State != "" && a.State != journal.CommandAutomationChainActive && a.State != journal.CommandAutomationChainDisabled {
			return nil, fmt.Errorf("%w: state must be active or disabled", errInvalidParamsErr)
		}
		rows, more, err := store.ListCommandAutomationChainTriggersForTenantPage(ctx, journal.CommandAutomationChainTriggerFilter{TenantID: s.tenantID(ctx), AutomationID: a.AutomationID, SourceWorkflow: a.SourceWorkflowID, State: a.State, Limit: a.Limit, Offset: a.Offset})
		if err != nil {
			return nil, err
		}
		views := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			views = append(views, mcpCommandAutomationChainView(row))
		}
		result := map[string]any{"chains": views, "automation_id": a.AutomationID, "source_workflow_id": a.SourceWorkflowID, "state": a.State, "limit": a.Limit, "offset": a.Offset, "has_more": more, "content_trust": "metadata"}
		if more {
			result["next_offset"] = a.Offset + len(views)
		}
		return result, nil
	}}

	if !s.writeEnabled(s.Scopes == nil || (s.Scopes.CommandExecution && s.Scopes.Triggers)) {
		return
	}

	s.tools["reactor_create_command_automation_chain"] = toolDef{tool: Tool{
		Name:        "reactor_create_command_automation_chain",
		Description: "Create a disabled terminal-chain binding for one exact reviewed command-automation version. The source workflow is tenant-scoped and only selected terminal statuses fire it; creation never enables or dispatches the plan. Requires both trigger and command-execution MCP scopes.",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []string{"name", "version", "source_workflow_id", "receipt_id", "gate_digest"}, "properties": map[string]any{
			"name":               map[string]any{"type": "string"},
			"version":            map[string]any{"type": "integer", "minimum": 1},
			"source_workflow_id": map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes, "description": "tenant-owned source workflow id"},
			"on_statuses":        map[string]any{"type": "string", "maxLength": 128, "default": "succeeded"},
			"receipt_id":         map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes},
			"gate_digest":        map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes},
			"idempotency_key":    map[string]any{"type": "string", "minLength": 1, "maxLength": 200},
		}},
	}, handler: func(ctx context.Context, args json.RawMessage) (any, error) {
		var a struct {
			Name             string `json:"name"`
			Version          int    `json:"version"`
			SourceWorkflowID string `json:"source_workflow_id"`
			OnStatuses       string `json:"on_statuses"`
			ReceiptID        string `json:"receipt_id"`
			GateDigest       string `json:"gate_digest"`
			IdempotencyKey   string `json:"idempotency_key"`
		}
		if err := decodeCommandArgs(args, &a); err != nil {
			return nil, err
		}
		key, err := normalizeTriggerIdempotencyKey(args, a.IdempotencyKey)
		if err != nil {
			return nil, err
		}
		a.Name, a.SourceWorkflowID, a.OnStatuses, a.ReceiptID, a.GateDigest = strings.TrimSpace(a.Name), strings.TrimSpace(a.SourceWorkflowID), strings.TrimSpace(a.OnStatuses), strings.TrimSpace(a.ReceiptID), strings.TrimSpace(a.GateDigest)
		if !commandautomations.ValidName(a.Name) || a.Version < 1 || a.SourceWorkflowID == "" {
			return nil, fmt.Errorf("%w: valid name, positive version, and source_workflow_id are required", errInvalidParamsErr)
		}
		if len(a.ReceiptID) == 0 || len(a.ReceiptID) > maxMCPRunIdentityBytes || len(a.GateDigest) != 64 {
			return nil, fmt.Errorf("%w: receipt_id and 64-character gate_digest are required", errInvalidParamsErr)
		}
		if _, err := hex.DecodeString(a.GateDigest); err != nil {
			return nil, fmt.Errorf("%w: gate_digest must be hexadecimal", errInvalidParamsErr)
		}
		if len(a.SourceWorkflowID) > maxMCPRunIdentityBytes || len(a.OnStatuses) > 128 {
			return nil, fmt.Errorf("%w: source workflow and statuses are bounded", errInvalidParamsErr)
		}
		if !commandChainStatusesValid(a.OnStatuses) {
			return nil, fmt.Errorf("%w: on_statuses must contain succeeded, failed, and/or failed_dlq", errInvalidParamsErr)
		}
		if sourceTenant, err := s.Journal.WorkflowTenant(ctx, a.SourceWorkflowID); err != nil || sourceTenant != s.tenantID(ctx) {
			// Keep a foreign source indistinguishable from a missing source.
			if err != nil {
				return nil, err
			}
			return nil, journal.ErrNotFound
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
		row, replayed, err := store.CreateCommandAutomationChainTriggerWithIdempotency(ctx, s.tenantID(ctx), journal.CommandAutomationChainTriggerInput{AutomationID: plan.ID, AutomationVersion: a.Version, DefinitionSHA256: definitionSHA256, ReceiptID: a.ReceiptID, GateDigest: a.GateDigest, ActorID: s.actorID(ctx), SourceWorkflowID: a.SourceWorkflowID, OnStatuses: a.OnStatuses}, key)
		if err != nil {
			return nil, err
		}
		return map[string]any{"chain": mcpCommandAutomationChainView(row), "idempotent": replayed, "state": row.State, "execution_note": "Created disabled. Enabling requires a current exact-version receipt, administrator authorization, fresh step-up, and runtime tenant/source checks."}, nil
	}}

	s.tools["reactor_update_command_automation_chain"] = toolDef{tool: Tool{
		Name:        "reactor_update_command_automation_chain",
		Description: "Update statuses for a disabled command-automation terminal chain under an optimistic revision fence. The source workflow and immutable plan binding remain fixed; active chains must be disabled first.",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []string{"chain_id", "on_statuses", "expected_revision"}, "properties": map[string]any{
			"chain_id":          map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes},
			"on_statuses":       map[string]any{"type": "string", "maxLength": 128},
			"expected_revision": map[string]any{"type": "integer", "minimum": 1},
		}},
	}, handler: func(ctx context.Context, args json.RawMessage) (any, error) {
		var a struct {
			ChainID          string `json:"chain_id"`
			OnStatuses       string `json:"on_statuses"`
			ExpectedRevision int64  `json:"expected_revision"`
		}
		if err := decodeCommandArgs(args, &a); err != nil {
			return nil, err
		}
		a.ChainID, a.OnStatuses = strings.TrimSpace(a.ChainID), strings.TrimSpace(a.OnStatuses)
		if a.ChainID == "" || a.ExpectedRevision < 1 || !commandChainStatusesValid(a.OnStatuses) {
			return nil, fmt.Errorf("%w: chain_id, supported on_statuses, and positive expected_revision are required", errInvalidParamsErr)
		}
		current, err := store.GetCommandAutomationChainTriggerForTenant(ctx, s.tenantID(ctx), a.ChainID)
		if err != nil {
			return nil, err
		}
		if err := store.UpdateCommandAutomationChainTriggerIfRevision(ctx, s.tenantID(ctx), a.ChainID, journal.CommandAutomationChainTriggerUpdate{AutomationVersion: current.AutomationVersion, DefinitionSHA256: current.DefinitionSHA256, ReceiptID: current.ReceiptID, GateDigest: current.GateDigest, ActorID: current.ActorID, OnStatuses: a.OnStatuses}, a.ExpectedRevision); err != nil {
			return nil, err
		}
		updated, err := store.GetCommandAutomationChainTriggerForTenant(ctx, s.tenantID(ctx), a.ChainID)
		if err != nil {
			return nil, err
		}
		return map[string]any{"chain": mcpCommandAutomationChainView(updated), "updated": true}, nil
	}}

	s.tools["reactor_set_command_automation_chain_state"] = toolDef{tool: Tool{
		Name:        "reactor_set_command_automation_chain_state",
		Description: "Enable or disable one command-automation terminal chain under an optimistic revision fence. Enabling requires the bound plan to remain current and executable with fresh administrator and step-up authorization; disabling is an emergency stop.",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []string{"chain_id", "state", "expected_revision"}, "properties": map[string]any{
			"chain_id":          map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes},
			"state":             map[string]any{"type": "string", "enum": []string{"active", "disabled"}},
			"expected_revision": map[string]any{"type": "integer", "minimum": 1},
		}},
	}, handler: func(ctx context.Context, args json.RawMessage) (any, error) {
		var a struct {
			ChainID          string `json:"chain_id"`
			State            string `json:"state"`
			ExpectedRevision int64  `json:"expected_revision"`
		}
		if err := decodeCommandArgs(args, &a); err != nil {
			return nil, err
		}
		a.ChainID, a.State = strings.TrimSpace(a.ChainID), strings.TrimSpace(a.State)
		if a.ChainID == "" || a.ExpectedRevision < 1 || (a.State != journal.CommandAutomationChainActive && a.State != journal.CommandAutomationChainDisabled) {
			return nil, fmt.Errorf("%w: chain_id, state, and positive expected_revision are required", errInvalidParamsErr)
		}
		current, err := store.GetCommandAutomationChainTriggerForTenant(ctx, s.tenantID(ctx), a.ChainID)
		if err != nil {
			return nil, err
		}
		if a.State == journal.CommandAutomationChainActive {
			if s.CommandAutomationChainRuntimeReady == nil || !s.CommandAutomationChainRuntimeReady(ctx) {
				return nil, fmt.Errorf("%w: command terminal-chain runtime is not configured", errInvalidParamsErr)
			}
			plan, err := s.Journal.GetCommandAutomation(ctx, s.tenantID(ctx), current.AutomationID)
			if err != nil {
				return nil, err
			}
			if !plan.Enabled || plan.CurrentVersion != current.AutomationVersion {
				return nil, fmt.Errorf("%w: bound plan must be enabled at its current version", errInvalidParamsErr)
			}
			stored, err := s.Journal.GetCommandAutomationVersion(ctx, s.tenantID(ctx), current.AutomationID, current.AutomationVersion)
			if err != nil {
				return nil, err
			}
			definition, err := decodeStoredCommandDefinition(stored.DefinitionJSON)
			if err != nil {
				return nil, err
			}
			// Imported or repaired chain rows can carry a stale digest while
			// their receipt and version still agree with each other. Fail closed
			// before activation so the chain cannot appear live only to fail at
			// the runner's later immutable-definition admission fence.
			definitionSHA256 := commandDefinitionSHA256(stored.DefinitionJSON)
			if current.DefinitionSHA256 != definitionSHA256 {
				return nil, fmt.Errorf("%w: chain definition digest is stale; create a new binding from the current immutable version", errInvalidParamsErr)
			}
			if s.CommandExecutionCapabilities == nil {
				return nil, fmt.Errorf("%w: command execution authorization is unavailable", errInvalidParamsErr)
			}
			caps := s.CommandExecutionCapabilities(ctx, definition)
			if s.CommandTenantAllowed != nil && !s.CommandTenantAllowed(ctx) {
				caps.SingleTenant = false
			}
			if !caps.AdminAuthorized || !caps.StepUpAuthorized {
				return nil, fmt.Errorf("%w: administrator authorization and a fresh step-up are required", errInvalidParamsErr)
			}
			caps.AutomationEnabled = true
			if s.CommandTargetAllowed != nil {
				caps.TargetReady = s.CommandTargetAllowed(ctx, plan.Target)
			}
			_, missing := s.commandCredentialReadiness(ctx, definition, current.AutomationID)
			if len(missing) > 0 {
				caps.VaultBoundaryReady, caps.CredentialsSupported = false, false
			}
			if len(commandDefinitionCredentialIDs(definition)) > 0 {
				if s.CommandCredentialResolverReady == nil {
					caps.CredentialsSupported = false
				} else {
					for _, id := range commandDefinitionCredentialIDs(definition) {
						if !s.CommandCredentialResolverReady(ctx, id) {
							caps.CredentialsSupported = false
							break
						}
					}
				}
			}
			receipt := commandautomations.EvaluateExecutionGates(definition, caps)
			binding := commandautomations.BindExecutionReceipt(s.tenantID(ctx), current.AutomationID, current.AutomationVersion, definitionSHA256, receipt)
			if current.ReceiptID != binding.ReceiptID || current.GateDigest != binding.GateDigest || !receipt.Executable {
				return nil, fmt.Errorf("%w: chain receipt is stale or execution gates are closed", errInvalidParamsErr)
			}
		}
		if err := store.SetCommandAutomationChainTriggerStateIfRevision(ctx, s.tenantID(ctx), a.ChainID, a.State, a.ExpectedRevision); err != nil {
			return nil, err
		}
		updated, err := store.GetCommandAutomationChainTriggerForTenant(ctx, s.tenantID(ctx), a.ChainID)
		if err != nil {
			return nil, err
		}
		return map[string]any{"chain": mcpCommandAutomationChainView(updated), "updated": true, "state": updated.State}, nil
	}}

	s.tools["reactor_delete_command_automation_chain"] = toolDef{tool: Tool{
		Name:        "reactor_delete_command_automation_chain",
		Description: "Delete a disabled command-automation terminal chain under an optimistic revision fence. Active chains must be disabled first.",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []string{"chain_id", "expected_revision"}, "properties": map[string]any{
			"chain_id":          map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes},
			"expected_revision": map[string]any{"type": "integer", "minimum": 1},
		}},
	}, handler: func(ctx context.Context, args json.RawMessage) (any, error) {
		var a struct {
			ChainID          string `json:"chain_id"`
			ExpectedRevision int64  `json:"expected_revision"`
		}
		if err := decodeCommandArgs(args, &a); err != nil {
			return nil, err
		}
		a.ChainID = strings.TrimSpace(a.ChainID)
		if a.ChainID == "" || a.ExpectedRevision < 1 {
			return nil, fmt.Errorf("%w: chain_id and positive expected_revision are required", errInvalidParamsErr)
		}
		if err := store.DeleteCommandAutomationChainTriggerIfRevision(ctx, s.tenantID(ctx), a.ChainID, a.ExpectedRevision); err != nil {
			return nil, err
		}
		return map[string]any{"deleted": true, "chain_id": a.ChainID}, nil
	}}
}

func mcpCommandAutomationChainView(row journal.CommandAutomationChainTrigger) map[string]any {
	actor, actorTruncated, actorBytes := boundMCPText(row.ActorID, maxMCPCommandRunActorBytes)
	view := map[string]any{
		"id": row.ID, "tenant_id": row.TenantID, "automation_id": row.AutomationID, "automation_version": row.AutomationVersion,
		"definition_sha256": row.DefinitionSHA256, "receipt_id": row.ReceiptID, "gate_digest": row.GateDigest,
		"actor_id": actor, "source_workflow_id": row.SourceWorkflowID,
		"on_statuses": row.OnStatuses, "state": row.State, "revision": row.Revision, "last_fired_at": row.LastFiredAt,
		"created_at": row.CreatedAt, "updated_at": row.UpdatedAt, "content_trust": "metadata",
	}
	if actorTruncated {
		view["actor_id_truncated"] = true
		view["actor_id_bytes"] = actorBytes
	}
	if strings.TrimSpace(row.LastError) != "" {
		// Runtime errors can contain target details or command output. Keep the
		// chain inventory to a presence/size receipt; run inspection owns the
		// tenant-scoped diagnostic projection.
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
		{"source_workflow_id", maxMCPRunIdentityBytes}, {"on_statuses", 128}, {"state", maxMCPCommandRunStatusBytes},
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

func commandChainStatusesValid(statuses string) bool {
	statuses = strings.TrimSpace(statuses)
	if statuses == "" {
		return true
	}
	seen := map[string]bool{}
	for _, item := range strings.Split(statuses, ",") {
		status := strings.ToLower(strings.TrimSpace(item))
		if status == "" || seen[status] {
			continue
		}
		if status != "succeeded" && status != "failed" && status != "failed_dlq" {
			return false
		}
		seen[status] = true
	}
	return len(seen) > 0
}
