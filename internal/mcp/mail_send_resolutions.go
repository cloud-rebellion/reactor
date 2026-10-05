package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// registerMailSendResolutionTool exposes only an explicit operator finding.
// The HTTP route is admin-gated separately; the dedicated scope keeps an
// otherwise writable MCP connection from silently receiving this authority.
func (s *Server) registerMailSendResolutionTool() {
	if s.Journal == nil || s.Scopes == nil || !s.Scopes.MailReconciliation || s.MailReconciliationAuthorized == nil {
		return
	}
	s.tools["reactor_resolve_mail_send"] = toolDef{
		tool: Tool{
			Name:        "reactor_resolve_mail_send",
			Description: "Record one immutable, tenant-scoped operator finding for an admitted connected-mail send after checking the provider. The run must be terminal and its worker lease released. Requires admin HTTP MCP access and the separate mail-reconciliation scope. Repeat exact run, intent, sequence, and recorded target IDs; for legacy intents with no recorded target, pass empty target IDs. A provider finding needs the SHA-256 digest of an operator-held provider record; closed_unverified records a manual decision without asserting provider acceptance. This tool never sends or retries mail, never converts an admitted intent into a confirmed provider callback, and never accepts message content, recipients, tokens, provider message IDs, or raw evidence.",
			InputSchema: map[string]any{
				"type": "object", "additionalProperties": false,
				"required": []string{"run_id", "intent_id", "confirm_intent_id", "seq", "target_provider_id", "target_connection_id", "decision", "evidence_kind", "evidence_sha256"},
				"properties": map[string]any{
					"run_id":               map[string]any{"type": "string", "minLength": 1, "maxLength": 512},
					"intent_id":            map[string]any{"type": "string", "minLength": 1, "maxLength": 512},
					"confirm_intent_id":    map[string]any{"type": "string", "minLength": 1, "maxLength": 512},
					"seq":                  map[string]any{"type": "integer", "minimum": 1},
					"target_provider_id":   map[string]any{"type": "string", "enum": []string{"", "google", "microsoft"}},
					"target_connection_id": map[string]any{"type": "string", "maxLength": 256},
					"decision":             map[string]any{"type": "string", "enum": []string{"provider_accepted", "provider_rejected", "closed_unverified"}},
					"evidence_kind":        map[string]any{"type": "string", "enum": []string{"provider_record", "provider_audit", "manual_decision"}},
					"evidence_sha256":      map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			if s.MailReconciliationAuthorized == nil || !s.MailReconciliationAuthorized(ctx) {
				return nil, fmt.Errorf("%w: authenticated administrator required", errInvalidParamsErr)
			}
			var a struct {
				RunID              string `json:"run_id"`
				IntentID           string `json:"intent_id"`
				ConfirmIntentID    string `json:"confirm_intent_id"`
				Seq                int64  `json:"seq"`
				TargetProviderID   string `json:"target_provider_id"`
				TargetConnectionID string `json:"target_connection_id"`
				Decision           string `json:"decision"`
				EvidenceKind       string `json:"evidence_kind"`
				EvidenceSHA256     string `json:"evidence_sha256"`
			}
			if err := decodeMCPArgs(args, &a); err != nil {
				return nil, fmt.Errorf("%w: %v", errInvalidParamsErr, err)
			}
			if a.IntentID == "" || a.IntentID != a.ConfirmIntentID {
				return nil, fmt.Errorf("%w: confirm_intent_id must match intent_id exactly", errInvalidParamsErr)
			}
			receipt, err := s.Journal.ResolveAdmittedMailSend(ctx, journal.MailSendResolutionInput{
				TenantID: s.tenantID(ctx), RunID: a.RunID, IntentID: a.IntentID, Seq: a.Seq,
				TargetProviderID: a.TargetProviderID, TargetConnectionID: a.TargetConnectionID,
				Decision: a.Decision, EvidenceKind: a.EvidenceKind, EvidenceSHA256: a.EvidenceSHA256,
				ActorID: s.actorID(ctx),
			})
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"resolution_id": receipt.ID, "intent_id": receipt.IntentID, "run_id": a.RunID,
				"decision": receipt.Decision, "evidence_kind": receipt.EvidenceKind,
				"evidence_digest_recorded": true, "resolved_at": receipt.ResolvedAt.Format(time.RFC3339Nano),
				"idempotent": receipt.Replayed, "automatic_redrive_safe": false,
				"resolution_meaning": "operator_finding_not_provider_callback_or_delivery_proof",
			}, nil
		},
	}
}
