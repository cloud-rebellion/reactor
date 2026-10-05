package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestHTTPMCPMailResolutionRequiresSeparateScopeAndExactIdentity(t *testing.T) {
	readOnly, _, _ := newTestServer(t, false)
	readOnly.Scopes = &WriteScopes{Dispatch: true}
	readOnly.ensureRegistered()
	if _, ok := readOnly.tools["reactor_resolve_mail_send"]; ok {
		t.Fatal("mail resolution advertised under the dispatch scope")
	}
	callOperationalTool(t, readOnly, "reactor_resolve_mail_send", map[string]any{}, true)
	missingAdminProvider, _, _ := newTestServer(t, false)
	missingAdminProvider.Scopes = &WriteScopes{MailReconciliation: true}
	missingAdminProvider.ensureRegistered()
	if _, ok := missingAdminProvider.tools["reactor_resolve_mail_send"]; ok {
		t.Fatal("mail resolution advertised without an administrator provider")
	}
	callOperationalTool(t, missingAdminProvider, "reactor_resolve_mail_send", map[string]any{}, true)
	s, j, _ := newTestServer(t, false)
	s.TenantID = "acme"
	s.Scopes = &WriteScopes{MailReconciliation: true}
	s.MailReconciliationAuthorized = func(context.Context) bool { return false }
	ctx := context.Background()
	const private = "private-recipient-token-and-message"
	const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, tenant := range []string{"acme", "other"} {
		if err := j.CreateWorkflowInTenant(ctx, "wf_mail_resolution_"+tenant, "mail-resolution-"+tenant,
			"hash", "0.1.0", json.RawMessage(`{}`), tenant); err != nil {
			t.Fatal(err)
		}
		if err := j.CreateRun(ctx, "run_mail_resolution_"+tenant, "wf_mail_resolution_"+tenant,
			"manual", json.RawMessage(`{"recipient":"`+private+`"}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := j.ClaimStepAttemptSeq(ctx, "run_mail_resolution_"+tenant, "send", 1, 3, private, "input"); err != nil {
			t.Fatal(err)
		}
	}
	local, err := j.AdmitMailSend(ctx, "run_mail_resolution_acme", "", "send", 1, 1, private, digest,
		journal.MailSendTarget{ProviderID: "google", ConnectionID: "conn_resolution"})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := j.AdmitMailSend(ctx, "run_mail_resolution_other", "", "send", 1, 1, private, digest,
		journal.MailSendTarget{ProviderID: "google", ConnectionID: "conn_resolution"})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, "run_mail_resolution_acme", "failed"); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{
		"run_id": "run_mail_resolution_acme", "intent_id": local.IntentID,
		"confirm_intent_id": local.IntentID, "seq": 1,
		"target_provider_id": "google", "target_connection_id": "conn_resolution",
		"decision": "provider_accepted", "evidence_kind": "provider_record", "evidence_sha256": digest,
	}
	// The HTTP route may intentionally pass a local no-auth bootstrap request.
	// Even with the scope enabled, the tool itself must refuse it.
	callOperationalTool(t, s, "reactor_resolve_mail_send", args, true)
	s.MailReconciliationAuthorized = func(context.Context) bool { return true }
	wrong := cloneMailResolutionArgs(args)
	wrong["confirm_intent_id"] = "wrong"
	callOperationalTool(t, s, "reactor_resolve_mail_send", wrong, true)
	wrong = cloneMailResolutionArgs(args)
	wrong["seq"] = 2
	callOperationalTool(t, s, "reactor_resolve_mail_send", wrong, true)
	wrong = cloneMailResolutionArgs(args)
	wrong["target_connection_id"] = "wrong"
	callOperationalTool(t, s, "reactor_resolve_mail_send", wrong, true)
	wrong = cloneMailResolutionArgs(args)
	wrong["intent_id"], wrong["confirm_intent_id"] = foreign.IntentID, foreign.IntentID
	wrong["run_id"] = "run_mail_resolution_other"
	callOperationalTool(t, s, "reactor_resolve_mail_send", wrong, true)
	wrong = cloneMailResolutionArgs(args)
	wrong["message"] = private
	callOperationalTool(t, s, "reactor_resolve_mail_send", wrong, true)
	wrong = cloneMailResolutionArgs(args)
	wrong["run_id"], wrong["intent_id"], wrong["confirm_intent_id"] = private, private, private
	malformed := callOperationalTool(t, s, "reactor_resolve_mail_send", wrong, true)
	if strings.Contains(string(malformed), private) {
		t.Fatalf("rejected mail resolution echoed private input: %s", malformed)
	}

	first := callOperationalTool(t, s, "reactor_resolve_mail_send", args, false)
	if strings.Contains(string(first), private) || strings.Contains(string(first), digest) ||
		strings.Contains(string(first), "run_mail_resolution_other") || !strings.Contains(string(first), `"automatic_redrive_safe":false`) {
		t.Fatalf("unsafe resolution receipt: %s", first)
	}
	var receipt struct {
		ResolutionID string `json:"resolution_id"`
		Idempotent   bool   `json:"idempotent"`
	}
	if err := json.Unmarshal(first, &receipt); err != nil || receipt.ResolutionID == "" || receipt.Idempotent {
		t.Fatalf("new resolution = %+v, %v", receipt, err)
	}
	second := callOperationalTool(t, s, "reactor_resolve_mail_send", args, false)
	if err := json.Unmarshal(second, &receipt); err != nil || !receipt.Idempotent {
		t.Fatalf("idempotent resolution = %+v, %v", receipt, err)
	}
	wrong = cloneMailResolutionArgs(args)
	wrong["decision"] = "provider_rejected"
	callOperationalTool(t, s, "reactor_resolve_mail_send", wrong, true)

	queue := callOperationalTool(t, s, "reactor_list_uncertain_mail_sends", map[string]any{}, false)
	if strings.Contains(string(queue), local.IntentID) || strings.Contains(string(queue), foreign.IntentID) {
		t.Fatalf("resolved/foreign intent remains in tenant queue: %s", queue)
	}
	read := callOperationalTool(t, s, "reactor_list_run_mail_sends", map[string]any{"run_id": "run_mail_resolution_acme"}, false)
	if !strings.Contains(string(read), receipt.ResolutionID) || !strings.Contains(string(read), `"status":"admitted"`) ||
		strings.Contains(string(read), private) || strings.Contains(string(read), digest) {
		t.Fatalf("run receipt did not retain value-free manual finding: %s", read)
	}
	// The general mutation audit records identity and decision, never the
	// provider evidence digest or customer payload.
	audit, err := j.ListMCPAuditForTenant(ctx, "acme", 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range audit {
		if item.ToolName == "reactor_resolve_mail_send" {
			if item.Target != "connected-mail-send" || strings.Contains(string(item.Detail), digest) ||
				strings.Contains(string(item.Detail), private) || strings.Contains(item.Target, private) {
				t.Fatalf("mail resolution audit leaked private data: %+v", item)
			}
		}
	}
}

func cloneMailResolutionArgs(source map[string]any) map[string]any {
	clone := make(map[string]any, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}
