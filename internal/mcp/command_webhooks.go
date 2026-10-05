package mcp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/webhook"
)

const (
	maxMCPCommandAutomationWebhookProvider = 64
	maxMCPCommandAutomationWebhookPage     = 100
)

// CommandAutomationWebhookStore is deliberately independent from the
// workflow trigger store. Implementations must enforce tenant ownership,
// immutable receipt binding, optimistic revisions, and idempotent creation in
// the durable journal.
type CommandAutomationWebhookStore interface {
	CreateCommandAutomationWebhookTriggerWithIdempotency(context.Context, string, journal.CommandAutomationWebhookTriggerInput, string) (journal.CommandAutomationWebhookTrigger, bool, error)
	GetCommandAutomationWebhookTriggerForTenant(context.Context, string, string) (journal.CommandAutomationWebhookTrigger, error)
	ListCommandAutomationWebhookTriggersForTenantPage(context.Context, journal.CommandAutomationWebhookTriggerFilter) ([]journal.CommandAutomationWebhookTrigger, bool, error)
	UpdateCommandAutomationWebhookTriggerIfRevision(context.Context, string, string, journal.CommandAutomationWebhookTriggerUpdate, int64) error
	SetCommandAutomationWebhookTriggerStateIfRevision(context.Context, string, string, string, int64) error
	DeleteCommandAutomationWebhookTriggerIfRevision(context.Context, string, string, int64) error
}

var _ CommandAutomationWebhookStore = (*journal.Journal)(nil)

func (s *Server) registerCommandAutomationWebhookTools() {
	store := s.CommandAutomationWebhooks
	if store == nil && s.Journal != nil {
		if candidate, ok := any(s.Journal).(CommandAutomationWebhookStore); ok {
			store = candidate
		}
	}
	if s.Journal == nil || store == nil {
		return
	}

	s.tools["reactor_list_command_automation_webhooks"] = toolDef{tool: Tool{
		Name:        "reactor_list_command_automation_webhooks",
		Description: "List bounded tenant-owned webhook bindings for command automations. Bearer tokens and HMAC credential ids are write-response-only and are never returned by this inventory.",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{
			"automation_id": map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes},
			"state":         map[string]any{"type": "string", "enum": []string{"active", "disabled"}},
			"limit":         map[string]any{"type": "integer", "minimum": 1, "maximum": maxMCPCommandAutomationWebhookPage, "default": 50},
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
		a.AutomationID, a.State = strings.TrimSpace(a.AutomationID), strings.TrimSpace(a.State)
		if a.Limit == 0 {
			a.Limit = 50
		}
		if a.Limit < 1 || a.Limit > maxMCPCommandAutomationWebhookPage || a.Offset < 0 || a.Offset > 10000 {
			return nil, fmt.Errorf("%w: limit must be 1..%d and offset 0..10000", errInvalidParamsErr, maxMCPCommandAutomationWebhookPage)
		}
		if a.State != "" && a.State != journal.CommandAutomationWebhookActive && a.State != journal.CommandAutomationWebhookDisabled {
			return nil, fmt.Errorf("%w: state must be active or disabled", errInvalidParamsErr)
		}
		rows, more, err := store.ListCommandAutomationWebhookTriggersForTenantPage(ctx, journal.CommandAutomationWebhookTriggerFilter{TenantID: s.tenantID(ctx), AutomationID: a.AutomationID, State: a.State, Limit: a.Limit, Offset: a.Offset})
		if err != nil {
			return nil, err
		}
		views := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			views = append(views, mcpCommandAutomationWebhookView(row, false))
		}
		result := map[string]any{"webhooks": views, "automation_id": a.AutomationID, "state": a.State, "limit": a.Limit, "offset": a.Offset, "has_more": more, "content_trust": "metadata"}
		if more {
			result["next_offset"] = a.Offset + len(views)
		}
		return result, nil
	}}

	if !s.writeEnabled(s.Scopes == nil || (s.Scopes.CommandExecution && s.Scopes.Triggers)) {
		return
	}

	s.tools["reactor_create_command_automation_webhook"] = toolDef{tool: Tool{
		Name:        "reactor_create_command_automation_webhook",
		Description: "Create a disabled HMAC webhook binding for one exact reviewed command-automation version. The endpoint is inert until separately enabled after a fresh receipt-bound authorization; workflow triggers use a different table and token path.",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []string{"name", "version", "credential_id", "receipt_id", "gate_digest"}, "properties": map[string]any{
			"name":            map[string]any{"type": "string"},
			"version":         map[string]any{"type": "integer", "minimum": 1},
			"credential_id":   map[string]any{"type": "string", "maxLength": maxMCPCredentialIDBytes, "description": "dedicated reactor-webhook shared-secret credential"},
			"provider":        map[string]any{"type": "string", "maxLength": maxMCPCommandAutomationWebhookProvider, "default": "generic"},
			"receipt_id":      map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes},
			"gate_digest":     map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes},
			"idempotency_key": map[string]any{"type": "string", "minLength": 1, "maxLength": 200},
		}},
	}, handler: func(ctx context.Context, args json.RawMessage) (any, error) {
		var a struct {
			Name           string `json:"name"`
			Version        int    `json:"version"`
			CredentialID   string `json:"credential_id"`
			Provider       string `json:"provider"`
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
		a.Name, a.CredentialID, a.Provider, a.ReceiptID, a.GateDigest = strings.TrimSpace(a.Name), strings.TrimSpace(a.CredentialID), strings.TrimSpace(a.Provider), strings.TrimSpace(a.ReceiptID), strings.TrimSpace(a.GateDigest)
		if a.Provider == "" {
			a.Provider = "generic"
		}
		if !commandautomations.ValidName(a.Name) || a.Version < 1 || a.CredentialID == "" {
			return nil, fmt.Errorf("%w: valid name, version, and credential_id are required", errInvalidParamsErr)
		}
		if len(a.Provider) > maxMCPCommandAutomationWebhookProvider || !webhook.IsSupportedProvider(a.Provider) {
			return nil, fmt.Errorf("%w: unsupported webhook provider", errInvalidParamsErr)
		}
		if len(a.ReceiptID) == 0 || len(a.ReceiptID) > maxMCPRunIdentityBytes || len(a.GateDigest) != 64 {
			return nil, fmt.Errorf("%w: receipt_id and 64-character gate_digest are required", errInvalidParamsErr)
		}
		if _, err := hex.DecodeString(a.GateDigest); err != nil {
			return nil, fmt.Errorf("%w: gate_digest must be hexadecimal", errInvalidParamsErr)
		}
		if s.Credentials == nil {
			return nil, fmt.Errorf("%w: webhook credential metadata is unavailable", errInvalidParamsErr)
		}
		credential, err := s.Credentials.GetMetadataByTenant(ctx, a.CredentialID, s.tenantID(ctx))
		if err != nil {
			return nil, err
		}
		if credential.Service != "reactor-webhook" || credential.Provider != "shared-secret" {
			return nil, fmt.Errorf("%w: credential must be a dedicated reactor-webhook shared-secret", errInvalidParamsErr)
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
		token, err := journal.NewCommandAutomationWebhookToken()
		if err != nil {
			return nil, err
		}
		row, replayed, err := store.CreateCommandAutomationWebhookTriggerWithIdempotency(ctx, s.tenantID(ctx), journal.CommandAutomationWebhookTriggerInput{
			AutomationID: plan.ID, AutomationVersion: a.Version, DefinitionSHA256: definitionSHA256, ReceiptID: a.ReceiptID, GateDigest: a.GateDigest,
			ActorID: s.actorID(ctx), TokenID: token, SecretID: a.CredentialID, Provider: a.Provider,
		}, key)
		if err != nil {
			return nil, err
		}
		// Build the endpoint from the same bounded/validated projection as the
		// write-response token. A token is a bearer capability and is returned
		// only by this create/replay projection. A replay can surface a legacy or repaired row;
		// never let that raw database value escape through a second result field.
		webhookView := mcpCommandAutomationWebhookView(row, true)
		result := map[string]any{"webhook": webhookView, "idempotent": replayed, "state": row.State, "execution_note": "Created disabled. Enabling requires current plan state, administrator authorization, fresh step-up, and runtime HMAC plus command admission checks."}
		if endpoint, ok := webhookView["endpoint_path"].(string); ok {
			result["endpoint_path"] = endpoint
		} else {
			result["endpoint_path_status"] = "write_response_invalid"
		}
		return result, nil
	}}

	s.tools["reactor_update_command_automation_webhook"] = toolDef{tool: Tool{
		Name:        "reactor_update_command_automation_webhook",
		Description: "Update a disabled command-automation webhook with optimistic revision fencing. Secret/provider rotation never changes an active binding; rotating the bearer token returns the new token once and list/inspect tools continue to omit it.",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []string{"webhook_id", "credential_id", "receipt_id", "gate_digest", "expected_revision"}, "properties": map[string]any{
			"webhook_id":        map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes},
			"credential_id":     map[string]any{"type": "string", "maxLength": maxMCPCredentialIDBytes},
			"provider":          map[string]any{"type": "string", "maxLength": maxMCPCommandAutomationWebhookProvider},
			"receipt_id":        map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes},
			"gate_digest":       map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes},
			"rotate_token":      map[string]any{"type": "boolean", "default": false},
			"expected_revision": map[string]any{"type": "integer", "minimum": 1},
		}},
	}, handler: func(ctx context.Context, args json.RawMessage) (any, error) {
		var a struct {
			WebhookID        string `json:"webhook_id"`
			CredentialID     string `json:"credential_id"`
			Provider         string `json:"provider"`
			ReceiptID        string `json:"receipt_id"`
			GateDigest       string `json:"gate_digest"`
			RotateToken      bool   `json:"rotate_token"`
			ExpectedRevision int64  `json:"expected_revision"`
		}
		if err := decodeCommandArgs(args, &a); err != nil {
			return nil, err
		}
		a.WebhookID, a.CredentialID, a.Provider, a.ReceiptID, a.GateDigest = strings.TrimSpace(a.WebhookID), strings.TrimSpace(a.CredentialID), strings.TrimSpace(a.Provider), strings.TrimSpace(a.ReceiptID), strings.TrimSpace(a.GateDigest)
		if a.WebhookID == "" || a.CredentialID == "" || a.ReceiptID == "" || len(a.GateDigest) != 64 || a.ExpectedRevision < 1 {
			return nil, fmt.Errorf("%w: webhook_id, credential_id, receipt_id, 64-character gate_digest, and positive expected_revision are required", errInvalidParamsErr)
		}
		if _, err := hex.DecodeString(a.GateDigest); err != nil {
			return nil, fmt.Errorf("%w: gate_digest must be hexadecimal", errInvalidParamsErr)
		}
		current, err := store.GetCommandAutomationWebhookTriggerForTenant(ctx, s.tenantID(ctx), a.WebhookID)
		if err != nil {
			return nil, err
		}
		if current.State != journal.CommandAutomationWebhookDisabled {
			return nil, fmt.Errorf("%w: disable the webhook before editing it", errInvalidParamsErr)
		}
		if a.Provider == "" {
			a.Provider = current.Provider
		}
		if len(a.Provider) > maxMCPCommandAutomationWebhookProvider || !webhook.IsSupportedProvider(a.Provider) {
			return nil, fmt.Errorf("%w: unsupported webhook provider", errInvalidParamsErr)
		}
		if s.Credentials == nil {
			return nil, fmt.Errorf("%w: webhook credential metadata is unavailable", errInvalidParamsErr)
		}
		credential, err := s.Credentials.GetMetadataByTenant(ctx, a.CredentialID, s.tenantID(ctx))
		if err != nil {
			return nil, err
		}
		if credential.Service != "reactor-webhook" || credential.Provider != "shared-secret" {
			return nil, fmt.Errorf("%w: credential must be a dedicated reactor-webhook shared-secret", errInvalidParamsErr)
		}
		plan, err := s.Journal.GetCommandAutomation(ctx, s.tenantID(ctx), current.AutomationID)
		if err != nil {
			return nil, err
		}
		if plan.CurrentVersion != current.AutomationVersion {
			return nil, fmt.Errorf("%w: bound version is no longer current; create a new webhook", errInvalidParamsErr)
		}
		stored, err := s.Journal.GetCommandAutomationVersion(ctx, s.tenantID(ctx), current.AutomationID, current.AutomationVersion)
		if err != nil {
			return nil, err
		}
		definitionSHA256 := commandDefinitionSHA256(stored.DefinitionJSON)
		if definitionSHA256 != current.DefinitionSHA256 {
			return nil, fmt.Errorf("%w: stored webhook definition digest is stale", errInvalidParamsErr)
		}
		expectedReceipt := commandautomations.ReceiptIDForGateDigest(s.tenantID(ctx), current.AutomationID, current.AutomationVersion, definitionSHA256, a.GateDigest)
		if a.ReceiptID != expectedReceipt {
			return nil, fmt.Errorf("%w: receipt_id does not bind this tenant, automation, version, definition, and gate_digest", errInvalidParamsErr)
		}
		token := current.TokenID
		if a.RotateToken {
			token, err = journal.NewCommandAutomationWebhookToken()
			if err != nil {
				return nil, err
			}
		}
		if err := store.UpdateCommandAutomationWebhookTriggerIfRevision(ctx, s.tenantID(ctx), a.WebhookID, journal.CommandAutomationWebhookTriggerUpdate{AutomationVersion: current.AutomationVersion, DefinitionSHA256: definitionSHA256, ReceiptID: a.ReceiptID, GateDigest: a.GateDigest, ActorID: s.actorID(ctx), TokenID: token, SecretID: a.CredentialID, Provider: a.Provider}, a.ExpectedRevision); err != nil {
			return nil, err
		}
		updated, err := store.GetCommandAutomationWebhookTriggerForTenant(ctx, s.tenantID(ctx), a.WebhookID)
		if err != nil {
			return nil, err
		}
		return map[string]any{"webhook": mcpCommandAutomationWebhookView(updated, a.RotateToken), "updated": true, "token_rotated": a.RotateToken, "execution_note": "Webhook remains disabled until a fresh activation gate succeeds."}, nil
	}}

	s.tools["reactor_set_command_automation_webhook_state"] = toolDef{tool: Tool{
		Name:        "reactor_set_command_automation_webhook_state",
		Description: "Enable or disable one command-automation webhook under an optimistic revision fence. Enabling rechecks the exact plan receipt and current execution gates; disabling is an emergency stop.",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []string{"webhook_id", "state", "expected_revision"}, "properties": map[string]any{
			"webhook_id":        map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes},
			"state":             map[string]any{"type": "string", "enum": []string{"active", "disabled"}},
			"expected_revision": map[string]any{"type": "integer", "minimum": 1},
		}},
	}, handler: func(ctx context.Context, args json.RawMessage) (any, error) {
		var a struct {
			WebhookID        string `json:"webhook_id"`
			State            string `json:"state"`
			ExpectedRevision int64  `json:"expected_revision"`
		}
		if err := decodeCommandArgs(args, &a); err != nil {
			return nil, err
		}
		a.WebhookID, a.State = strings.TrimSpace(a.WebhookID), strings.TrimSpace(a.State)
		if a.WebhookID == "" || a.ExpectedRevision < 1 || (a.State != journal.CommandAutomationWebhookActive && a.State != journal.CommandAutomationWebhookDisabled) {
			return nil, fmt.Errorf("%w: webhook_id, state, and positive expected_revision are required", errInvalidParamsErr)
		}
		current, err := store.GetCommandAutomationWebhookTriggerForTenant(ctx, s.tenantID(ctx), a.WebhookID)
		if err != nil {
			return nil, err
		}
		if a.State == journal.CommandAutomationWebhookActive {
			if s.CommandAutomationWebhookRuntimeReady == nil || !s.CommandAutomationWebhookRuntimeReady(ctx) {
				return nil, fmt.Errorf("%w: command webhook ingress runtime is not configured", errInvalidParamsErr)
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
			// Imported or repaired trigger rows can carry a stale digest even
			// when their version and receipt fields look internally consistent.
			// Recompute the digest from the authoritative immutable definition
			// before activation; otherwise the row could report an active
			// endpoint that can never pass runner admission.
			definitionSHA256 := commandDefinitionSHA256(stored.DefinitionJSON)
			if current.DefinitionSHA256 != definitionSHA256 {
				return nil, fmt.Errorf("%w: webhook definition digest is stale; create a new binding from the current immutable version", errInvalidParamsErr)
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
				caps.VaultBoundaryReady = false
				caps.CredentialsSupported = false
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
				return nil, fmt.Errorf("%w: webhook receipt is stale or execution gates are closed", errInvalidParamsErr)
			}
		}
		if err := store.SetCommandAutomationWebhookTriggerStateIfRevision(ctx, s.tenantID(ctx), a.WebhookID, a.State, a.ExpectedRevision); err != nil {
			return nil, err
		}
		updated, err := store.GetCommandAutomationWebhookTriggerForTenant(ctx, s.tenantID(ctx), a.WebhookID)
		if err != nil {
			return nil, err
		}
		return map[string]any{"webhook": mcpCommandAutomationWebhookView(updated, false), "updated": true, "state": updated.State}, nil
	}}

	s.tools["reactor_delete_command_automation_webhook"] = toolDef{tool: Tool{
		Name:        "reactor_delete_command_automation_webhook",
		Description: "Delete a disabled command-automation webhook under an optimistic revision fence. Active ingress must be disabled first.",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []string{"webhook_id", "expected_revision"}, "properties": map[string]any{
			"webhook_id":        map[string]any{"type": "string", "maxLength": maxMCPRunIdentityBytes},
			"expected_revision": map[string]any{"type": "integer", "minimum": 1},
		}},
	}, handler: func(ctx context.Context, args json.RawMessage) (any, error) {
		var a struct {
			WebhookID        string `json:"webhook_id"`
			ExpectedRevision int64  `json:"expected_revision"`
		}
		if err := decodeCommandArgs(args, &a); err != nil {
			return nil, err
		}
		a.WebhookID = strings.TrimSpace(a.WebhookID)
		if a.WebhookID == "" || a.ExpectedRevision < 1 {
			return nil, fmt.Errorf("%w: webhook_id and positive expected_revision are required", errInvalidParamsErr)
		}
		if err := store.DeleteCommandAutomationWebhookTriggerIfRevision(ctx, s.tenantID(ctx), a.WebhookID, a.ExpectedRevision); err != nil {
			return nil, err
		}
		return map[string]any{"deleted": true, "webhook_id": a.WebhookID}, nil
	}}
}

func mcpCommandAutomationWebhookView(row journal.CommandAutomationWebhookTrigger, includeToken bool) map[string]any {
	view := map[string]any{
		"id": row.ID, "tenant_id": row.TenantID, "automation_id": row.AutomationID, "automation_version": row.AutomationVersion,
		"definition_sha256": row.DefinitionSHA256, "receipt_id": row.ReceiptID, "gate_digest": row.GateDigest,
		"actor_id": row.ActorID, "provider": row.Provider, "state": row.State, "revision": row.Revision,
		"last_fired_at": row.LastFiredAt, "created_at": row.CreatedAt, "updated_at": row.UpdatedAt,
		"token_status": "write_response_only", "secret_status": "write_response_only", "content_trust": "metadata",
	}
	if strings.TrimSpace(row.LastError) != "" {
		view["last_error_present"] = true
		view["last_error_trust"] = "redacted"
		view["last_error_bytes"] = len([]byte(row.LastError))
	}
	if includeToken {
		// A create/replay response is the only place that may return the
		// bearer token. Imported or repaired rows still cross this response
		// boundary, so never reflect an unbounded or malformed token into the
		// MCP payload or endpoint path. A truncated token is not usable and is
		// intentionally omitted rather than returned as a misleading partial
		// capability.
		token, tokenTruncated, tokenBytes := boundMCPText(row.TokenID, maxMCPRunIdentityBytes)
		if !tokenTruncated && validMCPCommandWebhookToken(token) {
			view["token"] = token
			view["endpoint_path"] = "/command-webhook/" + token
		} else {
			view["token_status"] = "write_response_invalid"
			if tokenTruncated {
				view["token_truncated"], view["token_bytes"] = true, tokenBytes
			}
		}
	}
	for _, field := range []struct {
		name string
		max  int
	}{
		{"id", maxMCPRunIdentityBytes}, {"tenant_id", maxMCPRunIdentityBytes}, {"automation_id", maxMCPRunIdentityBytes},
		{"definition_sha256", maxMCPRunIdentityBytes}, {"receipt_id", maxMCPRunIdentityBytes}, {"gate_digest", maxMCPRunIdentityBytes},
		{"actor_id", maxMCPCommandRunActorBytes}, {"provider", maxMCPCommandAutomationWebhookProvider}, {"state", maxMCPCommandRunStatusBytes},
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

func validMCPCommandWebhookToken(token string) bool {
	const prefix = "cmdwhk_"
	if !strings.HasPrefix(token, prefix) || len(token) != len(prefix)+48 {
		return false
	}
	for _, r := range token[len(prefix):] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}
