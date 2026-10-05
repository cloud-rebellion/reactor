package mcp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/webhook"
	robfig "github.com/robfig/cron/v3"
)

func (s *Server) registerTriggerTools() {
	// Keep embedded/read-only servers honest: trigger inventory is journal
	// backed, so do not advertise handlers that would dereference a missing
	// journal. The production daemon always wires one, while small MCP mounts
	// used for documentation or capability discovery may intentionally omit it.
	if s.Journal == nil {
		return
	}
	s.tools["reactor_list_triggers"] = toolDef{
		tool: Tool{
			Name:        "reactor_list_triggers",
			Description: "List a bounded page of the active tenant's cron, webhook, and workflow-chain triggers for a workflow. Secret values, bearer webhook tokens, and credential contents are never returned.",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"slug"},
				"properties": map[string]any{
					"slug":   map[string]any{"type": "string"},
					"limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": maxMCPTriggerPage, "default": 100},
					"offset": map[string]any{"type": "integer", "minimum": 0, "maximum": 10000, "default": 0},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				Slug   string `json:"slug"`
				Limit  int    `json:"limit"`
				Offset int    `json:"offset"`
			}
			if err := decodeMCPArgs(args, &a); err != nil || strings.TrimSpace(a.Slug) == "" {
				return nil, fmt.Errorf("%w: slug required", errInvalidParamsErr)
			}
			if a.Limit == 0 {
				a.Limit = 100
			}
			if a.Limit < 1 || a.Limit > maxMCPTriggerPage {
				return nil, fmt.Errorf("%w: limit must be between 1 and %d", errInvalidParamsErr, maxMCPTriggerPage)
			}
			if a.Offset < 0 || a.Offset > 10000 {
				return nil, fmt.Errorf("%w: offset must be between 0 and 10000", errInvalidParamsErr)
			}
			workflowID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, a.Slug, s.tenantID(ctx))
			if err != nil {
				return nil, err
			}
			triggers, hasMore, err := s.Journal.ListTriggersForWorkflowPageBounded(ctx, workflowID, a.Limit, a.Offset, maxMCPTriggerConfigBytes)
			if err != nil {
				return nil, err
			}
			out := make([]map[string]any, 0, len(triggers))
			for _, trigger := range triggers {
				out = append(out, s.mcpTriggerViewForTenant(ctx, trigger))
			}
			result := map[string]any{"slug": a.Slug, "workflow_id": workflowID, "triggers": out, "limit": a.Limit, "offset": a.Offset, "has_more": hasMore}
			if hasMore {
				result["next_offset"] = a.Offset + len(out)
			}
			return result, nil
		},
	}

	if !s.writeEnabled(s.Scopes == nil || s.Scopes.Triggers) {
		return
	}

	s.tools["reactor_create_cron_trigger"] = toolDef{
		tool: Tool{
			Name:        "reactor_create_cron_trigger",
			Description: "Create an active cron trigger for a workflow after validating the same timezone-aware cron expression used by the runtime. Requires the triggers MCP scope (--mcp-allow-triggers on reactor serve; --allow-triggers on the explicit stdio compatibility command).",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"slug", "spec"},
				"properties": map[string]any{
					"slug":            map[string]any{"type": "string"},
					"spec":            map[string]any{"type": "string", "description": "five-field cron expression"},
					"timezone":        map[string]any{"type": "string", "description": "optional IANA timezone"},
					"idempotency_key": map[string]any{"type": "string", "minLength": 1, "maxLength": 200, "description": "Stable retry key; same key with different config is rejected"},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				Slug           string `json:"slug"`
				Spec           string `json:"spec"`
				Timezone       string `json:"timezone"`
				IdempotencyKey string `json:"idempotency_key"`
			}
			if err := decodeMCPArgs(args, &a); err != nil {
				return nil, fmt.Errorf("%w: %v", errInvalidParamsErr, err)
			}
			a.Slug, a.Spec, a.Timezone = strings.TrimSpace(a.Slug), strings.TrimSpace(a.Spec), strings.TrimSpace(a.Timezone)
			key, err := normalizeTriggerIdempotencyKey(args, a.IdempotencyKey)
			if err != nil {
				return nil, err
			}
			a.IdempotencyKey = key
			if len(a.Spec) > 256 || len(a.Timezone) > 128 {
				return nil, fmt.Errorf("%w: cron spec or timezone too long", errInvalidParamsErr)
			}
			if a.Slug == "" || a.Spec == "" {
				return nil, fmt.Errorf("%w: slug and spec are required", errInvalidParamsErr)
			}
			full := a.Spec
			if a.Timezone != "" {
				full = "CRON_TZ=" + a.Timezone + " " + a.Spec
			}
			if _, err := robfig.ParseStandard(full); err != nil {
				return nil, fmt.Errorf("%w: invalid cron spec or timezone: %v", errInvalidParamsErr, err)
			}
			workflowID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, a.Slug, s.tenantID(ctx))
			if err != nil {
				return nil, err
			}
			cfg := map[string]string{"spec": a.Spec}
			if a.Timezone != "" {
				cfg["timezone"] = a.Timezone
			}
			config, _ := json.Marshal(cfg)
			id, replay, err := s.Journal.CreateCronTriggerWithIdempotency(ctx, workflowID, config, a.IdempotencyKey)
			if err != nil {
				return nil, err
			}
			result := map[string]any{"trigger_id": id, "slug": a.Slug, "kind": string(journal.TriggerCron), "spec": a.Spec, "timezone": a.Timezone, "state": "active", "idempotent": replay}
			for key, value := range s.cronRuntimeReceipt(ctx) {
				result[key] = value
			}
			return result, nil
		},
	}

	s.tools["reactor_update_cron_trigger"] = toolDef{
		tool: Tool{
			Name:        "reactor_update_cron_trigger",
			Description: "Update the schedule and optional timezone of an existing cron trigger without changing its trigger id. The workflow slug and trigger id are bound atomically, webhook and chain triggers cannot be edited through this tool, and the configured cron reconciler applies the change (or a restart is required when live reload is disabled). Requires the triggers MCP scope (--mcp-allow-triggers on reactor serve; --allow-triggers on the explicit stdio compatibility command).",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"slug", "trigger_id", "spec"},
				"properties": map[string]any{
					"slug":              map[string]any{"type": "string"},
					"trigger_id":        map[string]any{"type": "string"},
					"spec":              map[string]any{"type": "string", "description": "five-field cron expression"},
					"timezone":          map[string]any{"type": "string", "description": "optional IANA timezone; empty uses UTC"},
					"expected_revision": map[string]any{"type": "integer", "minimum": 1, "description": "revision from reactor_list_triggers; stale revisions are rejected"},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				Slug             string `json:"slug"`
				TriggerID        string `json:"trigger_id"`
				Spec             string `json:"spec"`
				Timezone         string `json:"timezone"`
				ExpectedRevision int64  `json:"expected_revision"`
			}
			if err := decodeMCPArgs(args, &a); err != nil {
				return nil, fmt.Errorf("%w: %v", errInvalidParamsErr, err)
			}
			a.Slug, a.TriggerID, a.Spec, a.Timezone = strings.TrimSpace(a.Slug), strings.TrimSpace(a.TriggerID), strings.TrimSpace(a.Spec), strings.TrimSpace(a.Timezone)
			if a.Slug == "" || a.TriggerID == "" || a.Spec == "" {
				return nil, fmt.Errorf("%w: slug, trigger_id, and spec are required", errInvalidParamsErr)
			}
			if revision, present, revisionErr := optionalMCPPositiveInt(args, "expected_revision"); revisionErr != nil {
				return nil, revisionErr
			} else if present {
				a.ExpectedRevision = revision
			}
			if len(a.Spec) > 256 || len(a.Timezone) > 128 {
				return nil, fmt.Errorf("%w: cron spec or timezone too long", errInvalidParamsErr)
			}
			full := a.Spec
			if a.Timezone != "" {
				full = "CRON_TZ=" + a.Timezone + " " + a.Spec
			}
			if _, err := robfig.ParseStandard(full); err != nil {
				return nil, fmt.Errorf("%w: invalid cron spec or timezone: %v", errInvalidParamsErr, err)
			}
			workflowID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, a.Slug, s.tenantID(ctx))
			if err != nil {
				return nil, err
			}
			revision, err := s.triggerRevisionForMutation(ctx, a.TriggerID, workflowID, a.ExpectedRevision)
			if err != nil {
				return nil, err
			}
			cfg := map[string]string{"spec": a.Spec}
			if a.Timezone != "" {
				cfg["timezone"] = a.Timezone
			}
			config, _ := json.Marshal(cfg)
			if err := s.Journal.UpdateCronTriggerConfigForWorkflowIfRevision(ctx, a.TriggerID, workflowID, config, revision); err != nil {
				return nil, err
			}
			result := map[string]any{"trigger_id": a.TriggerID, "slug": a.Slug, "kind": string(journal.TriggerCron), "spec": a.Spec, "timezone": a.Timezone, "updated": true}
			if trigger, getErr := s.Journal.GetTriggerForWorkflowBounded(ctx, a.TriggerID, workflowID, 0); getErr == nil {
				result["revision"] = trigger.Revision
			}
			for key, value := range s.cronRuntimeReceipt(ctx) {
				result[key] = value
			}
			return result, nil
		},
	}

	s.tools["reactor_update_webhook_trigger"] = toolDef{
		tool: Tool{
			Name:        "reactor_update_webhook_trigger",
			Description: "Update an existing webhook's tenant-owned credential binding, provider, and verifier options without changing its public token. The trigger id, workflow binding, kind, and expected revision are checked atomically; use reactor_list_triggers first. Requires the triggers MCP scope (--mcp-allow-triggers on reactor serve; --allow-triggers on the explicit stdio compatibility command).",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"slug", "trigger_id", "credential_id", "expected_revision"},
				"properties": map[string]any{
					"slug":              map[string]any{"type": "string"},
					"trigger_id":        map[string]any{"type": "string"},
					"credential_id":     map[string]any{"type": "string"},
					"provider":          map[string]any{"type": "string", "description": "generic, github, stripe, automation-v1, or hash-v1; omitted preserves the current provider"},
					"sync":              map[string]any{"type": "boolean", "description": "optional; omitted preserves the current mode"},
					"timeout_seconds":   map[string]any{"type": "integer", "minimum": 1, "maximum": 120, "description": "optional synchronous timeout; omit to preserve the current value"},
					"expected_revision": map[string]any{"type": "integer", "minimum": 1, "description": "revision from reactor_list_triggers; stale revisions are rejected"},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				Slug             string `json:"slug"`
				TriggerID        string `json:"trigger_id"`
				CredentialID     string `json:"credential_id"`
				Provider         string `json:"provider"`
				Sync             *bool  `json:"sync"`
				TimeoutSeconds   *int   `json:"timeout_seconds"`
				ExpectedRevision int64  `json:"expected_revision"`
			}
			if err := decodeMCPArgs(args, &a); err != nil {
				return nil, fmt.Errorf("%w: %v", errInvalidParamsErr, err)
			}
			a.Slug, a.TriggerID, a.CredentialID, a.Provider = strings.TrimSpace(a.Slug), strings.TrimSpace(a.TriggerID), strings.TrimSpace(a.CredentialID), strings.TrimSpace(a.Provider)
			if a.Slug == "" || a.TriggerID == "" || a.CredentialID == "" {
				return nil, fmt.Errorf("%w: slug, trigger_id, and credential_id are required", errInvalidParamsErr)
			}
			if revision, present, revisionErr := optionalMCPPositiveInt(args, "expected_revision"); revisionErr != nil {
				return nil, revisionErr
			} else if !present {
				return nil, fmt.Errorf("%w: expected_revision is required", errInvalidParamsErr)
			} else {
				a.ExpectedRevision = revision
			}
			if a.TimeoutSeconds != nil && (*a.TimeoutSeconds < 1 || *a.TimeoutSeconds > 120) {
				return nil, fmt.Errorf("%w: timeout_seconds must be between 1 and 120", errInvalidParamsErr)
			}
			workflowID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, a.Slug, s.tenantID(ctx))
			if err != nil {
				return nil, err
			}
			trigger, err := s.Journal.GetTriggerForWorkflowBounded(ctx, a.TriggerID, workflowID, maxMCPTriggerConfigBytes)
			if err != nil {
				return nil, err
			}
			if trigger.ConfigTruncated {
				return nil, fmt.Errorf("%w: existing webhook configuration is %d bytes, above the %d-byte MCP mutation bound", errInvalidParamsErr, trigger.ConfigBytes, maxMCPTriggerConfigBytes)
			}
			if trigger.Kind != journal.TriggerWebhook {
				return nil, fmt.Errorf("%w: trigger is not a webhook", errInvalidParamsErr)
			}
			if trigger.Revision != a.ExpectedRevision {
				return nil, fmt.Errorf("%w: expected %d, current %d", journal.ErrTriggerRevisionConflict, a.ExpectedRevision, trigger.Revision)
			}
			provider := a.Provider
			if provider == "" {
				provider = trigger.Provider
			}
			if provider == "" {
				provider = "generic"
			}
			if !webhook.IsSupportedProvider(provider) {
				return nil, fmt.Errorf("%w: unsupported webhook provider", errInvalidParamsErr)
			}
			dag, dagBytes, dagTruncated, err := s.Journal.WorkflowDAGBounded(ctx, workflowID, maxMCPWorkflowDAGBytes)
			if err != nil {
				return nil, err
			}
			if dagTruncated {
				return nil, fmt.Errorf("%w: workflow DAG is %d bytes, above the %d-byte MCP mutation bound", errInvalidParamsErr, dagBytes, maxMCPWorkflowDAGBytes)
			}
			pinned, err := webhook.ProviderPinnedByDAG(dag)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid workflow webhook policy: %v", errInvalidParamsErr, err)
			}
			if pinned != "" && pinned != provider {
				return nil, fmt.Errorf("%w: workflow DAG requires webhook provider %q", errInvalidParamsErr, pinned)
			}
			if s.Credentials == nil {
				return nil, fmt.Errorf("webhook credentials unavailable")
			}
			credential, err := s.Credentials.GetMetadataByTenant(ctx, a.CredentialID, s.tenantID(ctx))
			if err != nil {
				return nil, err
			}
			if credential.Service != "reactor-webhook" || credential.Provider != "shared-secret" {
				return nil, fmt.Errorf("%w: credential must be a dedicated reactor-webhook shared-secret", errInvalidParamsErr)
			}
			var cfg map[string]json.RawMessage
			if len(trigger.Config) > 0 && json.Unmarshal(trigger.Config, &cfg) != nil {
				return nil, fmt.Errorf("%w: existing webhook configuration is invalid", errInvalidParamsErr)
			}
			if cfg == nil {
				cfg = map[string]json.RawMessage{}
			}
			if a.Sync != nil {
				if (provider == webhook.ProviderAutomationV1 || provider == webhook.ProviderHashV1) && *a.Sync {
					return nil, fmt.Errorf("%w: %s webhooks must be asynchronous", errInvalidParamsErr, provider)
				}
				if *a.Sync {
					cfg["sync"] = json.RawMessage(`true`)
				} else {
					delete(cfg, "sync")
					delete(cfg, "timeout_seconds")
				}
			} else if raw := cfg["sync"]; len(raw) > 0 {
				var syncMode bool
				if json.Unmarshal(raw, &syncMode) == nil && (provider == webhook.ProviderAutomationV1 || provider == webhook.ProviderHashV1) && syncMode {
					return nil, fmt.Errorf("%w: %s webhooks must be asynchronous", errInvalidParamsErr, provider)
				}
			}
			if a.TimeoutSeconds != nil {
				var syncMode bool
				if raw := cfg["sync"]; len(raw) == 0 || json.Unmarshal(raw, &syncMode) != nil || !syncMode {
					return nil, fmt.Errorf("%w: timeout_seconds requires sync=true", errInvalidParamsErr)
				}
				encoded, _ := json.Marshal(*a.TimeoutSeconds)
				cfg["timeout_seconds"] = encoded
			}
			config, _ := json.Marshal(cfg)
			if err := s.Journal.UpdateWebhookTriggerForWorkflowIfRevision(ctx, a.TriggerID, workflowID, a.CredentialID, provider, config, a.ExpectedRevision); err != nil {
				return nil, err
			}
			updated, _ := s.Journal.GetTriggerForWorkflowBounded(ctx, a.TriggerID, workflowID, 0)
			return map[string]any{"trigger_id": a.TriggerID, "slug": a.Slug, "kind": string(journal.TriggerWebhook), "credential_id": a.CredentialID, "provider": provider, "token_available": updated.TokenID != "", "state": updated.State, "revision": updated.Revision, "updated": true}, nil
		},
	}

	s.tools["reactor_update_chain_trigger"] = toolDef{
		tool: Tool{
			Name:        "reactor_update_chain_trigger",
			Description: "Rewire an existing workflow-chain trigger or change its terminal statuses without changing its trigger id. Both endpoints remain tenant-scoped, the candidate topology is cycle-checked, and expected_revision is required for the atomic update. Requires the triggers MCP scope (--mcp-allow-triggers on reactor serve; --allow-triggers on the explicit stdio compatibility command).",
			InputSchema: map[string]any{
				"type": "object", "required": []string{"downstream_slug", "trigger_id", "source_slug", "expected_revision"}, "properties": map[string]any{
					"downstream_slug":   map[string]any{"type": "string"},
					"trigger_id":        map[string]any{"type": "string"},
					"source_slug":       map[string]any{"type": "string"},
					"on_statuses":       map[string]any{"type": "string", "description": "comma-separated succeeded, failed, failed_dlq, or cancelled; defaults to succeeded"},
					"expected_revision": map[string]any{"type": "integer", "minimum": 1, "description": "revision from reactor_list_triggers; stale revisions are rejected"},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				DownstreamSlug   string `json:"downstream_slug"`
				TriggerID        string `json:"trigger_id"`
				SourceSlug       string `json:"source_slug"`
				OnStatuses       string `json:"on_statuses"`
				ExpectedRevision int64  `json:"expected_revision"`
			}
			if err := decodeMCPArgs(args, &a); err != nil {
				return nil, fmt.Errorf("%w: %v", errInvalidParamsErr, err)
			}
			a.DownstreamSlug, a.TriggerID, a.SourceSlug, a.OnStatuses = strings.TrimSpace(a.DownstreamSlug), strings.TrimSpace(a.TriggerID), strings.TrimSpace(a.SourceSlug), strings.TrimSpace(a.OnStatuses)
			if a.DownstreamSlug == "" || a.TriggerID == "" || a.SourceSlug == "" {
				return nil, fmt.Errorf("%w: downstream_slug, trigger_id, and source_slug are required", errInvalidParamsErr)
			}
			normalizedStatuses, statusErr := normalizeMCPChainStatuses(a.OnStatuses)
			if statusErr != nil {
				return nil, statusErr
			}
			a.OnStatuses = normalizedStatuses
			if revision, present, revisionErr := optionalMCPPositiveInt(args, "expected_revision"); revisionErr != nil {
				return nil, revisionErr
			} else if !present {
				return nil, fmt.Errorf("%w: expected_revision is required", errInvalidParamsErr)
			} else {
				a.ExpectedRevision = revision
			}
			downstreamID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, a.DownstreamSlug, s.tenantID(ctx))
			if err != nil {
				return nil, err
			}
			sourceID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, a.SourceSlug, s.tenantID(ctx))
			if err != nil {
				return nil, err
			}
			if err := s.Journal.UpdateChainTriggerForWorkflowIfRevision(ctx, a.TriggerID, downstreamID, sourceID, a.OnStatuses, a.ExpectedRevision); err != nil {
				return nil, err
			}
			updated, _ := s.Journal.GetTriggerForWorkflowBounded(ctx, a.TriggerID, downstreamID, 0)
			return map[string]any{"trigger_id": a.TriggerID, "kind": string(journal.TriggerWorkflowComplete), "downstream_slug": a.DownstreamSlug, "source_slug": a.SourceSlug, "on_statuses": a.OnStatuses, "state": updated.State, "revision": updated.Revision, "updated": true}, nil
		},
	}

	s.tools["reactor_create_webhook_trigger"] = toolDef{
		tool: Tool{
			Name:        "reactor_create_webhook_trigger",
			Description: "Bind a workflow to an existing tenant credential and return a public webhook token. The credential value stays in the vault; automation-v1 and hash-v1 are always asynchronous. Requires the triggers MCP scope (--mcp-allow-triggers on reactor serve; --allow-triggers on the explicit stdio compatibility command).",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"slug", "credential_id"},
				"properties": map[string]any{
					"slug":            map[string]any{"type": "string"},
					"credential_id":   map[string]any{"type": "string"},
					"provider":        map[string]any{"type": "string", "description": "generic, github, stripe, automation-v1, or hash-v1"},
					"sync":            map[string]any{"type": "boolean"},
					"timeout_seconds": map[string]any{"type": "integer", "minimum": 1, "maximum": 120},
					"idempotency_key": map[string]any{"type": "string", "minLength": 1, "maxLength": 200, "description": "Stable retry key; same key with different binding is rejected"},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				Slug           string `json:"slug"`
				CredentialID   string `json:"credential_id"`
				Provider       string `json:"provider"`
				Sync           bool   `json:"sync"`
				TimeoutSeconds *int   `json:"timeout_seconds"`
				IdempotencyKey string `json:"idempotency_key"`
			}
			if err := decodeMCPArgs(args, &a); err != nil {
				return nil, fmt.Errorf("%w: %v", errInvalidParamsErr, err)
			}
			// encoding/json maps an omitted timeout, explicit null, and zero to
			// the same Go value. Inspect the raw object so the advertised
			// minimum of one second is enforced for a supplied value while an
			// omitted value retains the runtime's default timeout.
			timeoutSeconds, timeoutPresent, timeoutErr := optionalMCPPositiveInt(args, "timeout_seconds")
			if timeoutErr != nil {
				return nil, timeoutErr
			}
			if timeoutPresent {
				if timeoutSeconds > 120 {
					return nil, fmt.Errorf("%w: timeout_seconds must be between 1 and 120", errInvalidParamsErr)
				}
				value := int(timeoutSeconds)
				a.TimeoutSeconds = &value
			}
			a.Slug, a.CredentialID, a.Provider = strings.TrimSpace(a.Slug), strings.TrimSpace(a.CredentialID), strings.TrimSpace(a.Provider)
			key, err := normalizeTriggerIdempotencyKey(args, a.IdempotencyKey)
			if err != nil {
				return nil, err
			}
			a.IdempotencyKey = key
			if a.Slug == "" || a.CredentialID == "" {
				return nil, fmt.Errorf("%w: slug and credential_id are required", errInvalidParamsErr)
			}
			workflowID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, a.Slug, s.tenantID(ctx))
			if err != nil {
				return nil, err
			}
			dag, dagBytes, dagTruncated, err := s.Journal.WorkflowDAGBounded(ctx, workflowID, maxMCPWorkflowDAGBytes)
			if err != nil {
				return nil, err
			}
			if dagTruncated {
				return nil, fmt.Errorf("%w: workflow DAG is %d bytes, above the %d-byte MCP mutation bound", errInvalidParamsErr, dagBytes, maxMCPWorkflowDAGBytes)
			}
			pinned, err := webhook.ProviderPinnedByDAG(dag)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid workflow webhook policy: %v", errInvalidParamsErr, err)
			}
			if a.Provider == "" {
				a.Provider = pinned
				if a.Provider == "" {
					a.Provider = "generic"
				}
			}
			if pinned != "" && pinned != a.Provider {
				return nil, fmt.Errorf("%w: workflow DAG requires webhook provider %q", errInvalidParamsErr, pinned)
			}
			if !webhook.IsSupportedProvider(a.Provider) {
				return nil, fmt.Errorf("%w: unsupported webhook provider", errInvalidParamsErr)
			}
			if (a.Provider == webhook.ProviderAutomationV1 || a.Provider == webhook.ProviderHashV1) && a.Sync {
				return nil, fmt.Errorf("%w: %s webhooks must be asynchronous", errInvalidParamsErr, a.Provider)
			}
			if timeoutPresent && !a.Sync {
				return nil, fmt.Errorf("%w: timeout_seconds requires sync and must be between 1 and 120", errInvalidParamsErr)
			}
			if s.Credentials == nil {
				return nil, fmt.Errorf("webhook credentials unavailable")
			}
			credential, err := s.Credentials.GetMetadataByTenant(ctx, a.CredentialID, s.tenantID(ctx))
			if err != nil {
				return nil, err
			}
			if credential.Service != "reactor-webhook" || credential.Provider != "shared-secret" {
				return nil, fmt.Errorf("%w: credential must be a dedicated reactor-webhook shared-secret", errInvalidParamsErr)
			}
			token, err := journal.NewTokenID()
			if err != nil {
				return nil, err
			}
			cfg := map[string]any{}
			if a.Sync {
				cfg["sync"] = true
			}
			if a.TimeoutSeconds != nil {
				cfg["timeout_seconds"] = *a.TimeoutSeconds
			}
			config, _ := json.Marshal(cfg)
			id, returnedToken, replay, err := s.Journal.CreateWebhookTriggerWithIdempotency(ctx, workflowID, token, a.CredentialID, a.Provider, config, a.IdempotencyKey)
			if err != nil {
				return nil, err
			}
			if replay {
				token = returnedToken
			}
			result := map[string]any{
				"trigger_id": id, "slug": a.Slug, "kind": string(journal.TriggerWebhook),
				"provider": a.Provider, "credential_id": a.CredentialID, "state": "active", "idempotent": replay,
			}
			// A replay can recover a legacy/imported row. Never reflect an
			// unbounded or malformed bearer token into the MCP response or URL;
			// generated tokens always satisfy this shape.
			if validMCPWorkflowWebhookToken(token) {
				result["token"] = token
				result["endpoint_path"] = "/webhook/" + token
			} else {
				result["token_status"] = "write_response_invalid"
			}
			return result, nil
		},
	}

	s.tools["reactor_create_chain_trigger"] = toolDef{
		tool: Tool{
			Name:        "reactor_create_chain_trigger",
			Description: "Create a cycle-checked trigger that dispatches a downstream workflow after a source workflow reaches one of the requested terminal statuses. Both workflows must belong to the active tenant. Requires the triggers MCP scope (--mcp-allow-triggers on reactor serve; --allow-triggers on the explicit stdio compatibility command).",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"downstream_slug", "source_slug"},
				"properties": map[string]any{
					"downstream_slug": map[string]any{"type": "string"},
					"source_slug":     map[string]any{"type": "string"},
					"on_statuses":     map[string]any{"type": "string", "description": "comma-separated statuses; defaults to succeeded"},
					"idempotency_key": map[string]any{"type": "string", "minLength": 1, "maxLength": 200, "description": "Stable retry key; same key with different topology is rejected"},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				DownstreamSlug string `json:"downstream_slug"`
				SourceSlug     string `json:"source_slug"`
				OnStatuses     string `json:"on_statuses"`
				IdempotencyKey string `json:"idempotency_key"`
			}
			if err := decodeMCPArgs(args, &a); err != nil {
				return nil, fmt.Errorf("%w: %v", errInvalidParamsErr, err)
			}
			a.DownstreamSlug, a.SourceSlug, a.OnStatuses = strings.TrimSpace(a.DownstreamSlug), strings.TrimSpace(a.SourceSlug), strings.TrimSpace(a.OnStatuses)
			key, err := normalizeTriggerIdempotencyKey(args, a.IdempotencyKey)
			if err != nil {
				return nil, err
			}
			a.IdempotencyKey = key
			if a.DownstreamSlug == "" || a.SourceSlug == "" {
				return nil, fmt.Errorf("%w: downstream_slug and source_slug are required", errInvalidParamsErr)
			}
			normalizedStatuses, statusErr := normalizeMCPChainStatuses(a.OnStatuses)
			if statusErr != nil {
				return nil, statusErr
			}
			a.OnStatuses = normalizedStatuses
			downstreamID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, a.DownstreamSlug, s.tenantID(ctx))
			if err != nil {
				return nil, err
			}
			sourceID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, a.SourceSlug, s.tenantID(ctx))
			if err != nil {
				return nil, err
			}
			id, replay, err := s.Journal.CreateChainTriggerWithIdempotency(ctx, downstreamID, sourceID, a.OnStatuses, a.IdempotencyKey)
			if err != nil {
				return nil, err
			}
			return map[string]any{"trigger_id": id, "kind": string(journal.TriggerWorkflowComplete), "downstream_slug": a.DownstreamSlug, "source_slug": a.SourceSlug, "on_statuses": a.OnStatuses, "state": "active", "idempotent": replay}, nil
		},
	}

	s.tools["reactor_set_trigger_state"] = toolDef{
		tool: Tool{
			Name:        "reactor_set_trigger_state",
			Description: "Pause or reactivate one trigger belonging to a workflow. State must be active or disabled. Requires the triggers MCP scope (--mcp-allow-triggers on reactor serve; --allow-triggers on the explicit stdio compatibility command).",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"slug", "trigger_id", "state"},
				"properties": map[string]any{
					"slug":              map[string]any{"type": "string"},
					"trigger_id":        map[string]any{"type": "string"},
					"state":             map[string]any{"type": "string", "enum": []string{"active", "disabled"}},
					"expected_revision": map[string]any{"type": "integer", "minimum": 1, "description": "revision from reactor_list_triggers; stale revisions are rejected"},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				Slug             string `json:"slug"`
				TriggerID        string `json:"trigger_id"`
				State            string `json:"state"`
				ExpectedRevision int64  `json:"expected_revision"`
			}
			if err := decodeMCPArgs(args, &a); err != nil || strings.TrimSpace(a.Slug) == "" || strings.TrimSpace(a.TriggerID) == "" {
				return nil, fmt.Errorf("%w: slug and trigger_id are required", errInvalidParamsErr)
			}
			a.Slug, a.TriggerID, a.State = strings.TrimSpace(a.Slug), strings.TrimSpace(a.TriggerID), strings.TrimSpace(a.State)
			if a.State != "active" && a.State != "disabled" {
				return nil, fmt.Errorf("%w: state must be active or disabled", errInvalidParamsErr)
			}
			if revision, present, revisionErr := optionalMCPPositiveInt(args, "expected_revision"); revisionErr != nil {
				return nil, revisionErr
			} else if present {
				a.ExpectedRevision = revision
			}
			workflowID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, a.Slug, s.tenantID(ctx))
			if err != nil {
				return nil, err
			}
			// Take one workflow-bound trigger snapshot for both the chain-state
			// safety check and the legacy implicit revision fence. Two independent
			// reads leave a race where a chain trigger can be disabled after the
			// first read, then reactivated using the newer revision from the second
			// read without running the recreate-and-cycle-check path.
			trigger, revision, err := s.triggerSnapshotForMutation(ctx, a.TriggerID, workflowID, a.ExpectedRevision)
			if err != nil {
				return nil, err
			}
			if a.State == "active" && trigger.Kind == journal.TriggerWorkflowComplete && trigger.State != "active" {
				return nil, fmt.Errorf("%w: recreate a disabled chain trigger so cycle checks run again", errInvalidParamsErr)
			}
			if err := s.Journal.SetTriggerStateForWorkflowIfRevision(ctx, a.TriggerID, workflowID, a.State, revision); err != nil {
				return nil, err
			}
			result := map[string]any{"trigger_id": a.TriggerID, "slug": a.Slug, "state": a.State}
			if trigger, getErr := s.Journal.GetTriggerForWorkflowBounded(ctx, a.TriggerID, workflowID, 0); getErr == nil {
				result["revision"] = trigger.Revision
			}
			for key, value := range s.cronRuntimeReceipt(ctx) {
				result[key] = value
			}
			return result, nil
		},
	}

	s.tools["reactor_delete_trigger"] = toolDef{
		tool: Tool{
			Name:        "reactor_delete_trigger",
			Description: "Delete one trigger belonging to a workflow. Deleting a webhook permanently invalidates its public token. Requires the triggers MCP scope (--mcp-allow-triggers on reactor serve; --allow-triggers on the explicit stdio compatibility command).",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"slug", "trigger_id"},
				"properties": map[string]any{
					"slug":              map[string]any{"type": "string"},
					"trigger_id":        map[string]any{"type": "string"},
					"expected_revision": map[string]any{"type": "integer", "minimum": 1, "description": "revision from reactor_list_triggers; stale revisions are rejected"},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				Slug             string `json:"slug"`
				TriggerID        string `json:"trigger_id"`
				ExpectedRevision int64  `json:"expected_revision"`
			}
			if err := decodeMCPArgs(args, &a); err != nil || strings.TrimSpace(a.Slug) == "" || strings.TrimSpace(a.TriggerID) == "" {
				return nil, fmt.Errorf("%w: slug and trigger_id are required", errInvalidParamsErr)
			}
			a.Slug, a.TriggerID = strings.TrimSpace(a.Slug), strings.TrimSpace(a.TriggerID)
			if revision, present, revisionErr := optionalMCPPositiveInt(args, "expected_revision"); revisionErr != nil {
				return nil, revisionErr
			} else if present {
				a.ExpectedRevision = revision
			}
			workflowID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, a.Slug, s.tenantID(ctx))
			if err != nil {
				return nil, err
			}
			revision, err := s.triggerRevisionForMutation(ctx, a.TriggerID, workflowID, a.ExpectedRevision)
			if err != nil {
				return nil, err
			}
			if err := s.Journal.DeleteTriggerForWorkflowIfRevision(ctx, a.TriggerID, workflowID, revision); err != nil {
				return nil, err
			}
			result := map[string]any{"trigger_id": a.TriggerID, "slug": a.Slug, "deleted": true}
			for key, value := range s.cronRuntimeReceipt(ctx) {
				result[key] = value
			}
			return result, nil
		},
	}
}

func validMCPWorkflowWebhookToken(token string) bool {
	const prefix = "whk_"
	if len(token) != len(prefix)+16*2 || !strings.HasPrefix(token, prefix) {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(token, prefix))
	return err == nil
}

// Only return known operational fields. Arbitrary trigger config can contain
// credentials for other trigger kinds, so it must not pass through wholesale.
// TokenID is a bearer capability for webhook delivery. It is returned only by
// create_webhook_trigger, where the caller can store it deliberately; read
// views expose presence without making inspection an invocation capability.
func mcpTriggerView(t journal.Trigger) map[string]any {
	out := map[string]any{"trigger_id": t.ID, "kind": t.Kind, "state": t.State, "provider": t.Provider, "token_available": t.TokenID != "", "revision": t.Revision, "last_fired_at": t.LastFiredAt, "created_at": t.CreatedAt, "updated_at": t.UpdatedAt}
	if t.ConfigTruncated {
		out["config_truncated"] = true
		out["config_bytes"] = t.ConfigBytes
		return out
	}
	var cfg map[string]json.RawMessage
	if json.Unmarshal(t.Config, &cfg) == nil {
		safe := map[string]json.RawMessage{}
		var keys []string
		switch t.Kind {
		case journal.TriggerCron:
			keys = []string{"spec", "timezone"}
		case journal.TriggerWebhook:
			keys = []string{"sync", "timeout_seconds"}
		case journal.TriggerWorkflowComplete:
			keys = []string{"source_workflow_id", "on_statuses"}
		}
		for _, key := range keys {
			if value, ok := cfg[key]; ok {
				safe[key] = value
			}
		}
		out["config"] = safe
	}
	return out
}

// mcpTriggerViewForTenant applies the final tenant fence to legacy/imported
// chain configuration. Current trigger writers only persist same-tenant
// source workflows, but an old or manually repaired row can still contain an
// opaque foreign workflow id. The trigger itself is already scoped by its
// downstream workflow; do not let that malformed source reference cross the
// MCP boundary.
func (s *Server) mcpTriggerViewForTenant(ctx context.Context, t journal.Trigger) map[string]any {
	out := mcpTriggerView(t)
	if t.Kind != journal.TriggerWorkflowComplete || s == nil || s.Journal == nil {
		return out
	}
	cfg, ok := out["config"].(map[string]json.RawMessage)
	if !ok {
		return out
	}
	var sourceID string
	if raw, exists := cfg["source_workflow_id"]; !exists || json.Unmarshal(raw, &sourceID) != nil || strings.TrimSpace(sourceID) == "" {
		return out
	}
	owner, err := s.Journal.WorkflowTenant(ctx, strings.TrimSpace(sourceID))
	if err == nil && owner == s.tenantID(ctx) {
		return out
	}
	delete(cfg, "source_workflow_id")
	cfg["source_workflow_id_status"] = json.RawMessage(`"redacted"`)
	out["config"] = cfg
	return out
}

// normalizeMCPChainStatuses validates and canonicalises the CSV representation
// before it reaches the journal. The journal applies the same canonical form
// (trim, dedupe, sort), so the mutation response and an idempotent retry report
// the exact persisted topology rather than echoing caller formatting.
func normalizeMCPChainStatuses(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "succeeded", nil
	}
	if len(raw) > 256 {
		return "", fmt.Errorf("%w: on_statuses exceeds 256 bytes", errInvalidParamsErr)
	}
	allowed := map[string]struct{}{
		"succeeded":  {},
		"failed":     {},
		"failed_dlq": {},
		"cancelled":  {},
	}
	seen := make(map[string]struct{}, len(allowed))
	statuses := make([]string, 0, len(allowed))
	for _, part := range strings.Split(raw, ",") {
		status := strings.TrimSpace(part)
		if status == "" {
			return "", fmt.Errorf("%w: on_statuses contains an empty status", errInvalidParamsErr)
		}
		if _, ok := allowed[status]; !ok {
			return "", fmt.Errorf("%w: unsupported terminal status %q", errInvalidParamsErr, status)
		}
		if _, duplicate := seen[status]; duplicate {
			continue
		}
		seen[status] = struct{}{}
		statuses = append(statuses, status)
	}
	sort.Strings(statuses)
	return strings.Join(statuses, ","), nil
}

func validateTriggerIdempotencyKey(raw string) error {
	key := strings.TrimSpace(raw)
	if key == "" {
		return nil
	}
	if len(key) > 200 || strings.IndexFunc(key, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return fmt.Errorf("%w: idempotency_key must be 1..200 characters without control characters", errInvalidParamsErr)
	}
	return nil
}

// normalizeTriggerIdempotencyKey preserves the distinction between an omitted
// optional key and an explicitly supplied empty/null key. The JSON schema says
// a supplied key has a minimum length of one, but MCP transports do not all
// enforce JSON Schema before invoking a handler. Accepting an explicit blank
// value would silently disable the caller's retry fence and could turn a lost
// response into a duplicate trigger.
func normalizeTriggerIdempotencyKey(args json.RawMessage, raw string) (string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil {
		return "", fmt.Errorf("%w: invalid arguments", errInvalidParamsErr)
	}
	if value, present := fields["idempotency_key"]; present {
		var supplied string
		if err := json.Unmarshal(value, &supplied); err != nil || strings.TrimSpace(supplied) == "" {
			return "", fmt.Errorf("%w: idempotency_key must be a non-empty string", errInvalidParamsErr)
		}
		raw = supplied
	}
	key := strings.TrimSpace(raw)
	if err := validateTriggerIdempotencyKey(key); err != nil {
		return "", err
	}
	return key, nil
}

// triggerRevisionForMutation keeps the legacy MCP shape (where
// expected_revision was optional) while making every update, state change,
// and delete optimistic-concurrency safe. When the caller omits the revision,
// use a workflow-bound read immediately before the atomic journal mutation;
// another writer between these operations then receives a revision conflict
// instead of having its change silently overwritten.
func (s *Server) triggerRevisionForMutation(ctx context.Context, triggerID, workflowID string, supplied int64) (int64, error) {
	_, revision, err := s.triggerSnapshotForMutation(ctx, triggerID, workflowID, supplied)
	return revision, err
}

// triggerSnapshotForMutation binds a trigger read to the already-authorized
// workflow and returns the revision that the caller should fence. Keeping the
// state and revision in one snapshot prevents a second read from observing a
// newer state and accidentally bypassing a state-specific safety check.
func (s *Server) triggerSnapshotForMutation(ctx context.Context, triggerID, workflowID string, supplied int64) (journal.Trigger, int64, error) {
	trigger, err := s.Journal.GetTriggerForWorkflowBounded(ctx, triggerID, workflowID, 0)
	if err != nil {
		return journal.Trigger{}, 0, err
	}
	if supplied > 0 {
		return trigger, supplied, nil
	}
	if trigger.Revision < 1 {
		return journal.Trigger{}, 0, fmt.Errorf("%w: trigger has no valid revision", errInvalidParamsErr)
	}
	return trigger, trigger.Revision, nil
}
