package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestMCPCommandAutomationWebhookCreateListHidesBearerAndSecret(t *testing.T) {
	t.Parallel()
	srv, j, creds := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true, Triggers: true, CommandExecution: true}
	if err := creds.Create(context.Background(), credentials.CreateParams{ID: "cred-command-webhook", Name: "command ingress", TenantID: "acme", Service: "reactor-webhook", Provider: "shared-secret"}); err != nil {
		t.Fatal(err)
	}
	definition := map[string]any{"steps": []map[string]any{{"name": "check", "command": "true", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0}}}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{"name": "webhook-check", "description": "inbound", "target": "local", "definition": definition}, false)
	plan, err := j.GetCommandAutomationByName(context.Background(), "acme", "webhook-check")
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(context.Background(), "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	stored, err := j.GetCommandAutomationVersion(context.Background(), "acme", plan.ID, plan.CurrentVersion)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeStoredCommandDefinition(stored.DefinitionJSON)
	if err != nil {
		t.Fatal(err)
	}
	caps := commandautomations.ExecutionCapabilities{FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true, StepUpAuthorized: true, AutomationEnabled: true, SandboxProfileReady: true, VaultBoundaryReady: true, CredentialsSupported: true, OutputLimitsReady: true, AuditReady: true, RunnerReady: true, TargetReady: true}
	receipt := commandautomations.EvaluateExecutionGates(decoded, caps)
	digest := commandDefinitionSHA256(stored.DefinitionJSON)
	binding := commandautomations.BindExecutionReceipt("acme", plan.ID, plan.CurrentVersion, digest, receipt)
	created := callOperationalTool(t, srv, "reactor_create_command_automation_webhook", map[string]any{
		"name": "webhook-check", "version": plan.CurrentVersion, "credential_id": "cred-command-webhook", "provider": "generic", "receipt_id": binding.ReceiptID, "gate_digest": binding.GateDigest, "idempotency_key": "cmd-webhook-key",
	}, false)
	text := string(created)
	if !strings.Contains(text, `"state":"disabled"`) || !strings.Contains(text, `"endpoint_path":"/command-webhook/`) || !strings.Contains(text, `"token":"cmdwhk_`) {
		t.Fatalf("create receipt missing disabled command endpoint/token: %s", created)
	}
	var decodedCreate struct {
		Webhook struct {
			ID    string `json:"id"`
			Token string `json:"token"`
		} `json:"webhook"`
	}
	if err := json.Unmarshal(created, &decodedCreate); err != nil {
		t.Fatal(err)
	}
	if decodedCreate.Webhook.ID == "" || decodedCreate.Webhook.Token == "" {
		t.Fatalf("create webhook receipt = %s", created)
	}
	listed := callOperationalTool(t, srv, "reactor_list_command_automation_webhooks", map[string]any{}, false)
	listText := string(listed)
	if strings.Contains(listText, decodedCreate.Webhook.Token) || strings.Contains(listText, "cred-command-webhook") || strings.Contains(listText, "cmd-webhook-key") {
		t.Fatalf("webhook inventory leaked bearer/secret/idempotency data: %s", listed)
	}
	if !strings.Contains(listText, decodedCreate.Webhook.ID) || !strings.Contains(listText, `"token_status":"write_response_only"`) {
		t.Fatalf("webhook inventory omitted safe metadata: %s", listed)
	}
	callOperationalTool(t, srv, "reactor_set_command_automation_webhook_state", map[string]any{"webhook_id": decodedCreate.Webhook.ID, "state": "active", "expected_revision": 1}, true)
}

func TestMCPCommandAutomationWebhookToolsRequireBothScopes(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{CommandExecution: true}
	srv.registerTools()
	if _, ok := srv.tools["reactor_create_command_automation_webhook"]; ok {
		t.Fatal("command webhook write tool registered without trigger scope")
	}
	srv.Scopes = &WriteScopes{Triggers: true}
	srv.registerTools()
	if _, ok := srv.tools["reactor_create_command_automation_webhook"]; ok {
		t.Fatal("command webhook write tool registered without command scope")
	}
}

func TestMCPCommandAutomationWebhookCreateViewBoundsInvalidImportedToken(t *testing.T) {
	longToken := "cmdwhk_" + strings.Repeat("x", maxMCPRunIdentityBytes+64)
	view := mcpCommandAutomationWebhookView(journal.CommandAutomationWebhookTrigger{TokenID: longToken}, true)
	if _, ok := view["token"]; ok {
		t.Fatal("invalid imported token was returned as a bearer capability")
	}
	if view["token_status"] != "write_response_invalid" || view["token_truncated"] != true {
		t.Fatalf("invalid token view = %#v", view)
	}
	if got, ok := view["token_bytes"].(int); !ok || got != len([]byte(longToken)) {
		t.Fatalf("invalid token byte receipt = %#v", view["token_bytes"])
	}
	if _, ok := view["endpoint_path"]; ok {
		t.Fatal("invalid imported token was reflected into endpoint path")
	}
}
