package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// registerMailSendReadTool makes an uncertain provider write inspectable
// without giving an AI client the email, recipient, token or request digest.
func (s *Server) registerMailSendReadTool() {
	if s.Journal == nil {
		return
	}
	s.tools["reactor_list_run_mail_sends"] = toolDef{
		tool: Tool{
			Name:        "reactor_list_run_mail_sends",
			Description: "List a bounded, tenant-scoped page of durable connected-mail send intents for one run, including the non-secret target provider and connection ID recorded before egress. An admitted intent has no recorded provider response; an optional separate resolution is only an operator finding. Reactor will not automatically send it again. Confirmed means provider API acceptance was recorded, not final delivery. Pre-target legacy rows report target_recorded=false. No message, recipient, OAuth token, request digest or provider message ID is returned.",
			InputSchema: map[string]any{
				"type": "object", "required": []string{"run_id"},
				"properties": map[string]any{
					"run_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 512},
					"limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 50},
					"offset": map[string]any{"type": "integer", "minimum": 0, "maximum": 10000, "default": 0},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				RunID  string `json:"run_id"`
				Limit  int    `json:"limit"`
				Offset int    `json:"offset"`
			}
			if err := decodeMCPArgs(args, &a); err != nil {
				return nil, fmt.Errorf("%w: %v", errInvalidParamsErr, err)
			}
			if a.RunID == "" || len(a.RunID) > 512 {
				return nil, fmt.Errorf("%w: run_id must be 1..512 bytes", errInvalidParamsErr)
			}
			if a.Limit == 0 {
				a.Limit = 50
			}
			if a.Limit < 1 || a.Limit > 100 || a.Offset < 0 || a.Offset > 10000 {
				return nil, fmt.Errorf("%w: invalid mail send page", errInvalidParamsErr)
			}
			tenant := s.tenantID(ctx)
			if _, err := s.Journal.GetRunForTenantMetadata(ctx, a.RunID, tenant, 0); err != nil {
				return nil, err
			}
			items, more, err := s.Journal.ListMailSendIntentsForRunTenant(ctx, a.RunID, tenant, a.Limit, a.Offset)
			if err != nil {
				return nil, err
			}
			receipts := make([]map[string]any, 0, len(items))
			for _, item := range items {
				receipts = append(receipts, mcpMailSendIntentView(item))
			}
			out := map[string]any{
				"run_id": a.RunID, "mail_sends": receipts,
				"limit": a.Limit, "offset": a.Offset, "has_more": more,
				"admitted_meaning":  "no_recorded_provider_response_check_separate_operator_resolution",
				"confirmed_meaning": "provider_api_accepted_delivery_unverified",
			}
			if more {
				out["next_offset"] = a.Offset + len(items)
			}
			return out, nil
		},
	}
	s.tools["reactor_list_uncertain_mail_sends"] = toolDef{
		tool: Tool{
			Name:        "reactor_list_uncertain_mail_sends",
			Description: "List a bounded, tenant-scoped, newest-first page of admitted connected-mail intents without a resolution across runs for operator reconciliation. Provider acceptance is unknown; never automatically redrive or claim delivery. Returns run and step IDs, timestamps, and non-secret provider/account routing IDs, but no message, recipient, OAuth token, request digest or provider message ID. Cursor pagination reflects the current queue, so confirmations and operator findings can remove rows between pages. Retention preserves unresolved runs until confirmation, resolution, or explicit tenant erasure.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 50},
					"cursor": map[string]any{"type": "string", "maxLength": 1024},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				Limit  int    `json:"limit"`
				Cursor string `json:"cursor"`
			}
			if err := decodeMCPArgs(args, &a); err != nil {
				return nil, fmt.Errorf("%w: %v", errInvalidParamsErr, err)
			}
			if a.Limit == 0 {
				a.Limit = 50
			}
			if a.Limit < 1 || a.Limit > 100 || len(a.Cursor) > 1024 {
				return nil, fmt.Errorf("%w: invalid admitted mail send page", errInvalidParamsErr)
			}
			items, more, next, err := s.Journal.ListAdmittedMailSendIntentsForTenant(ctx, s.tenantID(ctx), a.Limit, a.Cursor)
			if errors.Is(err, journal.ErrInvalidMailSendCursor) {
				return nil, fmt.Errorf("%w: invalid mail send cursor", errInvalidParamsErr)
			}
			if err != nil {
				return nil, err
			}
			receipts := make([]map[string]any, 0, len(items))
			for _, item := range items {
				view := mcpMailSendIntentView(item)
				runID, truncated, sourceBytes := boundMCPText(item.RunID, 512)
				view["run_id"] = runID
				if truncated {
					view["run_id_truncated"], view["run_id_bytes"] = true, sourceBytes
				}
				receipts = append(receipts, view)
			}
			out := map[string]any{
				"mail_sends": receipts, "limit": a.Limit, "has_more": more,
				"admitted_meaning":       "provider_acceptance_unknown_manual_reconciliation_required",
				"automatic_redrive_safe": false,
			}
			if more {
				out["next_cursor"] = next
			}
			return out, nil
		},
	}
}

func mcpMailSendIntentView(item journal.MailSendIntentReceipt) map[string]any {
	intentID, idTruncated, idBytes := boundMCPText(item.ID, 128)
	stepName, stepTruncated, stepBytes := boundMCPText(item.StepName, 256)
	view := map[string]any{
		"intent_id": intentID, "step_name": stepName,
		"seq": item.Seq, "attempt": item.Attempt, "status": item.Status,
		"target_recorded": item.TargetRecorded,
		"created_at":      item.CreatedAt.Format(time.RFC3339Nano),
	}
	if idTruncated {
		view["intent_id_truncated"], view["intent_id_bytes"] = true, idBytes
	}
	if stepTruncated {
		view["step_name_truncated"], view["step_name_bytes"] = true, stepBytes
	}
	// Today the broker permits only these fixed provider routes. An imported
	// legacy row must not pass arbitrary provider text to AI.
	provider := "unknown"
	if item.ProviderID == "google" || item.ProviderID == "microsoft" {
		provider = item.ProviderID
	}
	view["provider_id"] = provider
	if item.TargetRecorded {
		connectionID, truncated, sourceBytes := boundMCPText(item.ConnectionID, 256)
		view["connection_id"] = connectionID
		if truncated {
			view["connection_id_truncated"], view["connection_id_bytes"] = true, sourceBytes
		}
	}
	if item.Status == "confirmed" {
		view["provider_message_id_recorded"] = item.MessageIDKnown
		view["confirmed_at"] = item.ConfirmedAt.Format(time.RFC3339Nano)
	}
	if item.Resolution != nil {
		resolutionID, truncated, sourceBytes := boundMCPText(item.Resolution.ID, 128)
		view["resolution"] = map[string]any{
			"id": resolutionID, "decision": item.Resolution.Decision,
			"evidence_kind":            item.Resolution.EvidenceKind,
			"evidence_digest_recorded": true,
			"resolved_at":              item.Resolution.ResolvedAt.Format(time.RFC3339Nano),
			"operator_recorded":        true,
		}
		if truncated {
			view["resolution"].(map[string]any)["id_truncated"] = true
			view["resolution"].(map[string]any)["id_bytes"] = sourceBytes
		}
	}
	return view
}
