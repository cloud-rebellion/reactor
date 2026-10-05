package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// Exercise actual HTTP tools/call decoding and error envelopes, not just handlers.
func callOperationalTool(t *testing.T, s *Server, name string, args any, wantError bool) json.RawMessage {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	var resp struct {
		Error  *rpcError `json:"error"`
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || (resp.Error != nil || resp.Result.IsError) != wantError {
		t.Fatalf("%s: status=%d response=%s", name, w.Code, w.Body.String())
	}
	if len(resp.Result.Content) == 0 {
		return nil
	}
	return json.RawMessage(resp.Result.Content[0].Text)
}

func operationalID(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	id, _ := obj["trigger_id"].(string)
	if id == "" {
		t.Fatalf("missing trigger id: %s", raw)
	}
	return id
}

func TestMCPWorkflowWebhookTokenProjectionRejectsMalformedReplay(t *testing.T) {
	if !validMCPWorkflowWebhookToken("whk_" + strings.Repeat("a", 32)) {
		t.Fatal("canonical workflow webhook token rejected")
	}
	for _, token := range []string{
		"whk_" + strings.Repeat("a", 31),
		"whk_" + strings.Repeat("a", 32) + "x",
		"whk_" + strings.Repeat("g", 32),
		"whk_" + strings.Repeat("a", 1<<16),
	} {
		if validMCPWorkflowWebhookToken(token) {
			t.Fatalf("malformed workflow webhook token accepted: %q", token[:min(len(token), 40)])
		}
	}
}

func TestHTTPMCPTriggerLifecycleAndTenantIsolation(t *testing.T) {
	s, j, creds := newTestServer(t, false)
	s.TenantID = "acme"
	s.Scopes = &WriteScopes{Triggers: true}
	ctx := context.Background()
	for _, row := range []struct{ id, slug, tenant, dag string }{
		{"wf_local", "flow", "acme", `{"triggers":[{"kind":"webhook","provider":"hash-v1"}]}`},
		{"wf_foreign", "flow", "default", `{}`},
		{"wf_source", "source", "acme", `{}`},
	} {
		if err := j.CreateWorkflowInTenant(ctx, row.id, row.slug, "h", "0.1.0", json.RawMessage(row.dag), row.tenant); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct{ id, tenant, service string }{{"local-key", "acme", "reactor-webhook"}, {"foreign-key", "default", "reactor-webhook"}, {"api-key", "acme", "api"}} {
		if err := creds.Create(ctx, credentials.CreateParams{ID: row.id, Name: row.id, TenantID: row.tenant, Service: row.service, Provider: "shared-secret"}); err != nil {
			t.Fatal(err)
		}
	}
	cronID := operationalID(t, callOperationalTool(t, s, "reactor_create_cron_trigger", map[string]any{"slug": "flow", "spec": "0 9 * * *", "timezone": "Europe/Stockholm"}, false))
	updated := callOperationalTool(t, s, "reactor_update_cron_trigger", map[string]any{
		"slug": "flow", "trigger_id": cronID, "spec": "30 10 * * *",
	}, false)
	if !strings.Contains(string(updated), `"updated":true`) || !strings.Contains(string(updated), `"runtime_reconciled":false`) || !strings.Contains(string(updated), `"runtime_note"`) {
		t.Fatalf("cron update response = %s", updated)
	}
	rows, err := j.ListTriggersForWorkflow(ctx, "wf_local")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.ID == cronID && string(row.Config) != `{"spec":"30 10 * * *"}` {
			t.Fatalf("cron update config = %s", row.Config)
		}
	}
	for _, args := range []map[string]any{
		{"slug": "flow", "spec": "bad"}, {"slug": "flow", "spec": "0 9 * * *", "timezone": "no/such-zone"},
	} {
		callOperationalTool(t, s, "reactor_create_cron_trigger", args, true)
	}
	callOperationalTool(t, s, "reactor_create_cron_trigger", map[string]any{"slug": "flow", "spec": "0 9 * * *", "unexpected": true}, true)
	callOperationalTool(t, s, "reactor_update_cron_trigger", map[string]any{"slug": "flow", "trigger_id": cronID, "spec": "bad"}, true)
	for _, args := range []map[string]any{
		{"slug": "flow", "credential_id": "foreign-key"},
		{"slug": "flow", "credential_id": "api-key"},
		{"slug": "flow", "credential_id": "local-key", "provider": "generic"},
		{"slug": "flow", "credential_id": "local-key", "sync": true},
	} {
		callOperationalTool(t, s, "reactor_create_webhook_trigger", args, true)
	}
	webhookRaw := callOperationalTool(t, s, "reactor_create_webhook_trigger", map[string]any{"slug": "flow", "credential_id": "local-key"}, false)
	whID := operationalID(t, webhookRaw)
	var webhookView struct {
		Token        string `json:"token"`
		EndpointPath string `json:"endpoint_path"`
	}
	if err := json.Unmarshal(webhookRaw, &webhookView); err != nil {
		t.Fatal(err)
	}
	if webhookView.Token == "" || webhookView.EndpointPath != "/webhook/"+webhookView.Token {
		t.Fatalf("webhook endpoint view = %+v", webhookView)
	}
	rows, err = j.ListTriggersForWorkflow(ctx, "wf_local")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("invalid creates persisted rows: %+v", rows)
	}
	callOperationalTool(t, s, "reactor_update_cron_trigger", map[string]any{"slug": "flow", "trigger_id": whID, "spec": "0 11 * * *"}, true)
	for _, row := range rows {
		if row.ID == whID && (row.Provider != "hash-v1" || row.SecretID != "local-key" || row.TokenID == "") {
			t.Fatalf("webhook binding=%+v", row)
		}
	}
	foreignID, err := j.CreateCronTrigger(ctx, "wf_foreign", []byte(`{"spec":"* * * * *"}`))
	if err != nil {
		t.Fatal(err)
	}
	callOperationalTool(t, s, "reactor_set_trigger_state", map[string]any{"slug": "flow", "trigger_id": foreignID, "state": "disabled"}, true)
	callOperationalTool(t, s, "reactor_delete_trigger", map[string]any{"slug": "flow", "trigger_id": foreignID}, true)
	callOperationalTool(t, s, "reactor_set_trigger_state", map[string]any{"slug": "flow", "trigger_id": cronID, "state": "disabled"}, false)
	rows, _ = j.ListTriggersForWorkflow(ctx, "wf_local")
	for _, row := range rows {
		if row.ID == cronID && row.State != "disabled" {
			t.Fatal("pause not persisted")
		}
	}
	callOperationalTool(t, s, "reactor_set_trigger_state", map[string]any{"slug": "flow", "trigger_id": cronID, "state": "active"}, false)
	callOperationalTool(t, s, "reactor_delete_trigger", map[string]any{"slug": "flow", "trigger_id": cronID}, false)
	raw := callOperationalTool(t, s, "reactor_list_triggers", map[string]any{"slug": "flow"}, false)
	if strings.Contains(string(raw), "local-key") || strings.Contains(string(raw), foreignID) || strings.Contains(string(raw), cronID) || !strings.Contains(string(raw), whID) {
		t.Fatalf("trigger view=%s", raw)
	}
	callOperationalTool(t, s, "reactor_list_triggers", map[string]any{"slug": "flow", "limit": 501}, true)
	callOperationalTool(t, s, "reactor_list_triggers", map[string]any{"slug": "flow", "offset": 10001}, true)
	chainID := operationalID(t, callOperationalTool(t, s, "reactor_create_chain_trigger", map[string]any{"downstream_slug": "flow", "source_slug": "source"}, false))
	callOperationalTool(t, s, "reactor_create_chain_trigger", map[string]any{"downstream_slug": "source", "source_slug": "flow"}, true)
	callOperationalTool(t, s, "reactor_create_chain_trigger", map[string]any{"downstream_slug": "source", "source_slug": "flow", "on_statuses": "typo"}, true)
	callOperationalTool(t, s, "reactor_set_trigger_state", map[string]any{"slug": "flow", "trigger_id": chainID, "state": "disabled"}, false)
	callOperationalTool(t, s, "reactor_create_chain_trigger", map[string]any{"downstream_slug": "source", "source_slug": "flow"}, false)
	callOperationalTool(t, s, "reactor_set_trigger_state", map[string]any{"slug": "flow", "trigger_id": chainID, "state": "active"}, true)
}

func TestHTTPMCPTriggerInventoryBoundsLegacyConfig(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, false)
	s.TenantID = "acme"
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_trigger_config_bound", "trigger-config-bound", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	large := json.RawMessage(`{"spec":"` + strings.Repeat("x", maxMCPTriggerConfigBytes+1024) + `"}`)
	id, err := j.CreateCronTrigger(ctx, "wf_trigger_config_bound", large)
	if err != nil {
		t.Fatal(err)
	}
	page := callOperationalTool(t, s, "reactor_list_triggers", map[string]any{"slug": "trigger-config-bound"}, false)
	if !strings.Contains(string(page), `"trigger_id":"`+id+`"`) || !strings.Contains(string(page), `"config_truncated":true`) || !strings.Contains(string(page), `"config_bytes":`) {
		t.Fatalf("bounded trigger inventory = %s", page)
	}
	if strings.Contains(string(page), strings.Repeat("x", 256)) {
		t.Fatal("oversized trigger configuration crossed the MCP boundary")
	}
	bounded, err := j.GetTriggerForWorkflowBounded(ctx, id, "wf_trigger_config_bound", maxMCPTriggerConfigBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bounded.ConfigTruncated || bounded.ConfigBytes <= maxMCPTriggerConfigBytes || len(bounded.Config) != 0 {
		t.Fatalf("bounded journal trigger = truncated=%t bytes=%d materialized=%d", bounded.ConfigTruncated, bounded.ConfigBytes, len(bounded.Config))
	}
}

func TestHTTPMCPWebhookTriggerUpdatePreservesTokenAndFencesRevision(t *testing.T) {
	t.Parallel()
	s, j, creds := newTestServer(t, false)
	s.TenantID = "acme"
	s.Scopes = &WriteScopes{Triggers: true}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_webhook_update", "webhook-update", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"webhook-old", "webhook-new"} {
		if err := creds.Create(ctx, credentials.CreateParams{ID: id, Name: id, TenantID: "acme", Service: "reactor-webhook", Provider: "shared-secret"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := creds.Create(ctx, credentials.CreateParams{ID: "webhook-foreign", Name: "webhook-foreign", TenantID: "other", Service: "reactor-webhook", Provider: "shared-secret"}); err != nil {
		t.Fatal(err)
	}
	// The schema advertises timeout_seconds as 1..120. An explicit zero or
	// null must not collapse into the omitted/default timeout during Go JSON
	// decoding, otherwise a malformed authoring request is persisted.
	for _, timeout := range []any{0, nil} {
		callOperationalTool(t, s, "reactor_create_webhook_trigger", map[string]any{
			"slug": "webhook-update", "credential_id": "webhook-old", "provider": "generic",
			"sync": true, "timeout_seconds": timeout,
		}, true)
	}

	created := callOperationalTool(t, s, "reactor_create_webhook_trigger", map[string]any{
		"slug": "webhook-update", "credential_id": "webhook-old", "provider": "generic",
	}, false)
	triggerID := operationalID(t, created)
	var createdView struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(created, &createdView); err != nil {
		t.Fatal(err)
	}
	if createdView.Token == "" {
		t.Fatalf("create webhook response omitted token: %s", created)
	}

	updated := callOperationalTool(t, s, "reactor_update_webhook_trigger", map[string]any{
		"slug": "webhook-update", "trigger_id": triggerID, "credential_id": "webhook-new",
		"provider": "github", "sync": true, "timeout_seconds": 30, "expected_revision": 1,
	}, false)
	if !strings.Contains(string(updated), `"updated":true`) || !strings.Contains(string(updated), `"revision":2`) || !strings.Contains(string(updated), `"token_available":true`) {
		t.Fatalf("webhook update response = %s", updated)
	}
	row, err := j.GetTriggerForWorkflow(ctx, triggerID, "wf_webhook_update")
	if err != nil {
		t.Fatal(err)
	}
	if row.Revision != 2 || row.SecretID != "webhook-new" || row.Provider != "github" || row.TokenID != createdView.Token || string(row.Config) != `{"sync":true,"timeout_seconds":30}` {
		t.Fatalf("webhook update row = %+v config=%s token=%q want token=%q", row, row.Config, row.TokenID, createdView.Token)
	}

	// A stale read cannot rebind the credential or provider after the first
	// update. A foreign credential is also rejected before the journal write.
	callOperationalTool(t, s, "reactor_update_webhook_trigger", map[string]any{
		"slug": "webhook-update", "trigger_id": triggerID, "credential_id": "webhook-old",
		"provider": "stripe", "expected_revision": 1,
	}, true)
	callOperationalTool(t, s, "reactor_update_webhook_trigger", map[string]any{
		"slug": "webhook-update", "trigger_id": triggerID, "credential_id": "webhook-foreign",
		"provider": "stripe", "expected_revision": 2,
	}, true)
	callOperationalTool(t, s, "reactor_update_webhook_trigger", map[string]any{
		"slug": "webhook-update", "trigger_id": triggerID, "credential_id": "webhook-new",
		"provider": "not-a-provider", "expected_revision": 2,
	}, true)
	row, err = j.GetTriggerForWorkflow(ctx, triggerID, "wf_webhook_update")
	if err != nil {
		t.Fatal(err)
	}
	if row.Revision != 2 || row.SecretID != "webhook-new" || row.Provider != "github" || row.TokenID != createdView.Token {
		t.Fatalf("rejected webhook update changed row = %+v", row)
	}
}

func TestHTTPMCPChainTriggerUpdateFencesRevisionAndRejectsCycles(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, false)
	s.TenantID = "acme"
	s.Scopes = &WriteScopes{Triggers: true}
	ctx := context.Background()
	for _, row := range []struct {
		id, slug, tenant string
	}{
		{"wf_chain_a", "chain-a", "acme"},
		{"wf_chain_b", "chain-b", "acme"},
		{"wf_chain_c", "chain-c", "acme"},
		{"wf_chain_foreign", "chain-foreign", "other"},
	} {
		if err := j.CreateWorkflowInTenant(ctx, row.id, row.slug, "h", "0.1.0", json.RawMessage(`{}`), row.tenant); err != nil {
			t.Fatal(err)
		}
	}

	first := callOperationalTool(t, s, "reactor_create_chain_trigger", map[string]any{
		"downstream_slug": "chain-b", "source_slug": "chain-a",
	}, false)
	firstID := operationalID(t, first)
	second := callOperationalTool(t, s, "reactor_create_chain_trigger", map[string]any{
		"downstream_slug": "chain-c", "source_slug": "chain-b",
	}, false)
	secondID := operationalID(t, second)

	_ = callOperationalTool(t, s, "reactor_update_chain_trigger", map[string]any{
		"downstream_slug": "chain-b", "trigger_id": firstID, "source_slug": "chain-c",
		"on_statuses": "failed,failed_dlq", "expected_revision": 1,
	}, true)
	firstRow, err := j.GetTriggerForWorkflow(ctx, firstID, "wf_chain_b")
	if err != nil {
		t.Fatal(err)
	}
	if firstRow.Revision != 1 {
		t.Fatalf("cycle rejection changed revision: %+v", firstRow)
	}

	// Rewire the second edge to an acyclic source and verify the indexed
	// source/config fields and revision advance together.
	updated := callOperationalTool(t, s, "reactor_update_chain_trigger", map[string]any{
		"downstream_slug": "chain-c", "trigger_id": secondID, "source_slug": "chain-a",
		"on_statuses": "failed,failed_dlq", "expected_revision": 1,
	}, false)
	if !strings.Contains(string(updated), `"updated":true`) || !strings.Contains(string(updated), `"revision":2`) {
		t.Fatalf("chain update response = %s", updated)
	}
	secondRow, err := j.GetTriggerForWorkflow(ctx, secondID, "wf_chain_c")
	if err != nil {
		t.Fatal(err)
	}
	if secondRow.Revision != 2 || string(secondRow.Config) != `{"on_statuses":"failed,failed_dlq","source_workflow_id":"wf_chain_a"}` || secondRow.WorkflowID != "wf_chain_c" {
		t.Fatalf("chain update row = %+v config=%s", secondRow, secondRow.Config)
	}

	// The old revision and a source in another tenant both fail closed and do
	// not alter the already updated chain.
	callOperationalTool(t, s, "reactor_update_chain_trigger", map[string]any{
		"downstream_slug": "chain-c", "trigger_id": secondID, "source_slug": "chain-b",
		"expected_revision": 1,
	}, true)
	callOperationalTool(t, s, "reactor_update_chain_trigger", map[string]any{
		"downstream_slug": "chain-c", "trigger_id": secondID, "source_slug": "chain-foreign",
		"expected_revision": 2,
	}, true)
	secondRow, err = j.GetTriggerForWorkflow(ctx, secondID, "wf_chain_c")
	if err != nil {
		t.Fatal(err)
	}
	if secondRow.Revision != 2 || !bytes.Contains(secondRow.Config, []byte(`"source_workflow_id":"wf_chain_a"`)) {
		t.Fatalf("rejected chain update changed row = %+v config=%s", secondRow, secondRow.Config)
	}
}

func TestHTTPMCPTriggerRuntimeReceiptDistinguishesAppliedAndDeferred(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, false)
	s.Scopes = &WriteScopes{Triggers: true}
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_runtime_receipt", "runtime-receipt", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	reconciles := 0
	s.ReconcileCron = func(context.Context) error {
		reconciles++
		return nil
	}
	created := callOperationalTool(t, s, "reactor_create_cron_trigger", map[string]any{
		"slug": "runtime-receipt", "spec": "0 9 * * *",
	}, false)
	if !strings.Contains(string(created), `"runtime_reconciled":true`) {
		t.Fatalf("applied create receipt = %s", created)
	}
	triggerID := operationalID(t, created)
	updated := callOperationalTool(t, s, "reactor_update_cron_trigger", map[string]any{
		"slug": "runtime-receipt", "trigger_id": triggerID, "spec": "30 9 * * *",
	}, false)
	if !strings.Contains(string(updated), `"runtime_reconciled":true`) {
		t.Fatalf("applied update receipt = %s", updated)
	}
	if reconciles != 2 {
		t.Fatalf("reconcile calls = %d, want 2", reconciles)
	}
	s.ReconcileCron = func(context.Context) error { return errors.New("not leader") }
	deferred := callOperationalTool(t, s, "reactor_set_trigger_state", map[string]any{
		"slug": "runtime-receipt", "trigger_id": triggerID, "state": "disabled",
	}, false)
	if !strings.Contains(string(deferred), `"runtime_reconciled":false`) || !strings.Contains(string(deferred), `"runtime_note"`) {
		t.Fatalf("deferred state receipt = %s", deferred)
	}
}

func TestHTTPMCPTriggerMutationRejectsStaleRevision(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, false)
	s.TenantID = "acme"
	s.Scopes = &WriteScopes{Triggers: true}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_trigger_revision", "trigger-revision", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	id := operationalID(t, callOperationalTool(t, s, "reactor_create_cron_trigger", map[string]any{"slug": "trigger-revision", "spec": "0 9 * * *"}, false))
	page := callOperationalTool(t, s, "reactor_list_triggers", map[string]any{"slug": "trigger-revision"}, false)
	var listed struct {
		Triggers []struct {
			ID       string `json:"trigger_id"`
			Revision int64  `json:"revision"`
		} `json:"triggers"`
	}
	if err := json.Unmarshal(page, &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Triggers) != 1 || listed.Triggers[0].ID != id || listed.Triggers[0].Revision != 1 {
		t.Fatalf("trigger inventory = %+v", listed.Triggers)
	}
	callOperationalTool(t, s, "reactor_update_cron_trigger", map[string]any{"slug": "trigger-revision", "trigger_id": id, "spec": "30 9 * * *", "expected_revision": int64(1)}, false)
	callOperationalTool(t, s, "reactor_update_cron_trigger", map[string]any{"slug": "trigger-revision", "trigger_id": id, "spec": "45 9 * * *", "expected_revision": int64(1)}, true)
	row, err := j.GetTriggerForWorkflow(ctx, id, "wf_trigger_revision")
	if err != nil {
		t.Fatal(err)
	}
	if row.Revision != 2 || string(row.Config) != `{"spec":"30 9 * * *"}` {
		t.Fatalf("stale MCP update changed trigger = revision %d config %s", row.Revision, row.Config)
	}
}

func TestHTTPMCPTriggerMutationsRejectNullOrZeroRevision(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, false)
	s.TenantID = "acme"
	s.Scopes = &WriteScopes{Triggers: true}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_trigger_optional_revision", "trigger-optional-revision", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	id := operationalID(t, callOperationalTool(t, s, "reactor_create_cron_trigger", map[string]any{
		"slug": "trigger-optional-revision", "spec": "0 9 * * *",
	}, false))

	// expected_revision is optional for compatibility, but a present value
	// must be a positive integer. A zero or null must not be interpreted as an
	// omitted fence and then mutate or delete the trigger.
	for _, tc := range []struct {
		name string
		tool string
		args map[string]any
	}{
		{name: "update zero", tool: "reactor_update_cron_trigger", args: map[string]any{"slug": "trigger-optional-revision", "trigger_id": id, "spec": "30 9 * * *", "expected_revision": 0}},
		{name: "update null", tool: "reactor_update_cron_trigger", args: map[string]any{"slug": "trigger-optional-revision", "trigger_id": id, "spec": "30 9 * * *", "expected_revision": nil}},
		{name: "state zero", tool: "reactor_set_trigger_state", args: map[string]any{"slug": "trigger-optional-revision", "trigger_id": id, "state": "disabled", "expected_revision": 0}},
		{name: "state null", tool: "reactor_set_trigger_state", args: map[string]any{"slug": "trigger-optional-revision", "trigger_id": id, "state": "disabled", "expected_revision": nil}},
		{name: "delete zero", tool: "reactor_delete_trigger", args: map[string]any{"slug": "trigger-optional-revision", "trigger_id": id, "expected_revision": 0}},
		{name: "delete null", tool: "reactor_delete_trigger", args: map[string]any{"slug": "trigger-optional-revision", "trigger_id": id, "expected_revision": nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			callOperationalTool(t, s, tc.tool, tc.args, true)
		})
	}
	row, err := j.GetTriggerForWorkflow(ctx, id, "wf_trigger_optional_revision")
	if err != nil {
		t.Fatal(err)
	}
	if row.Revision != 1 || row.State != "active" || string(row.Config) != `{"spec":"0 9 * * *"}` {
		t.Fatalf("invalid optional revision changed trigger: %+v config=%s", row, row.Config)
	}
}

func TestHTTPMCPTriggerMutationsWithoutRevisionUseCurrentFence(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, false)
	s.TenantID = "acme"
	s.Scopes = &WriteScopes{Triggers: true}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_trigger_implicit_revision", "trigger-implicit-revision", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	id := operationalID(t, callOperationalTool(t, s, "reactor_create_cron_trigger", map[string]any{
		"slug": "trigger-implicit-revision", "spec": "0 9 * * *",
	}, false))

	// Legacy callers may omit expected_revision. The MCP path must resolve the
	// current workflow-bound revision and still use the atomic journal fence.
	state := callOperationalTool(t, s, "reactor_set_trigger_state", map[string]any{
		"slug": "trigger-implicit-revision", "trigger_id": id, "state": "disabled",
	}, false)
	if !strings.Contains(string(state), `"revision":2`) {
		t.Fatalf("implicit state fence receipt = %s", state)
	}
	// Revision 1 is stale after the implicit mutation and cannot overwrite it.
	callOperationalTool(t, s, "reactor_update_cron_trigger", map[string]any{
		"slug": "trigger-implicit-revision", "trigger_id": id, "spec": "30 9 * * *", "expected_revision": 1,
	}, true)
	row, err := j.GetTriggerForWorkflow(ctx, id, "wf_trigger_implicit_revision")
	if err != nil {
		t.Fatal(err)
	}
	if row.Revision != 2 || row.State != "disabled" || string(row.Config) != `{"spec":"0 9 * * *"}` {
		t.Fatalf("stale update changed trigger after implicit fence: %+v config=%s", row, row.Config)
	}

	updated := callOperationalTool(t, s, "reactor_update_cron_trigger", map[string]any{
		"slug": "trigger-implicit-revision", "trigger_id": id, "spec": "30 9 * * *",
	}, false)
	if !strings.Contains(string(updated), `"revision":3`) {
		t.Fatalf("implicit update fence receipt = %s", updated)
	}
	callOperationalTool(t, s, "reactor_delete_trigger", map[string]any{
		"slug": "trigger-implicit-revision", "trigger_id": id, "expected_revision": 2,
	}, true)
	if _, err := j.GetTriggerForWorkflow(ctx, id, "wf_trigger_implicit_revision"); err != nil {
		t.Fatal("stale delete removed trigger", err)
	}
	callOperationalTool(t, s, "reactor_delete_trigger", map[string]any{
		"slug": "trigger-implicit-revision", "trigger_id": id,
	}, false)
}

func TestTriggerSnapshotForMutationKeepsStateAndImplicitRevisionTogether(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, false)
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_trigger_snapshot", "trigger-snapshot", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	id, err := j.CreateCronTrigger(ctx, "wf_trigger_snapshot", []byte(`{"spec":"0 9 * * *"}`))
	if err != nil {
		t.Fatal(err)
	}
	trigger, revision, err := s.triggerSnapshotForMutation(ctx, id, "wf_trigger_snapshot", 0)
	if err != nil {
		t.Fatal(err)
	}
	if trigger.State != "active" || trigger.Revision != 1 || revision != trigger.Revision {
		t.Fatalf("initial trigger snapshot = state %q revision %d fence %d", trigger.State, trigger.Revision, revision)
	}
	if err := j.SetTriggerStateForWorkflowIfRevision(ctx, id, "wf_trigger_snapshot", "disabled", revision); err != nil {
		t.Fatal(err)
	}
	trigger, revision, err = s.triggerSnapshotForMutation(ctx, id, "wf_trigger_snapshot", 0)
	if err != nil {
		t.Fatal(err)
	}
	if trigger.State != "disabled" || trigger.Revision != 2 || revision != trigger.Revision {
		t.Fatalf("post-mutation trigger snapshot = state %q revision %d fence %d", trigger.State, trigger.Revision, revision)
	}
}

func TestHTTPMCPTriggerCreationIsIdempotent(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, false)
	s.TenantID = "acme"
	s.Scopes = &WriteScopes{Triggers: true}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_trigger_create_idem", "trigger-create-idem", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []any{"", "   ", nil} {
		callOperationalTool(t, s, "reactor_create_cron_trigger", map[string]any{
			"slug": "trigger-create-idem", "spec": "0 9 * * *", "idempotency_key": key,
		}, true)
	}
	first := callOperationalTool(t, s, "reactor_create_cron_trigger", map[string]any{
		"slug": "trigger-create-idem", "spec": "0 9 * * *", "idempotency_key": "cron-create-1",
	}, false)
	firstID := operationalID(t, first)
	retry := callOperationalTool(t, s, "reactor_create_cron_trigger", map[string]any{
		"slug": "trigger-create-idem", "spec": "0 9 * * *", "idempotency_key": "cron-create-1",
	}, false)
	if operationalID(t, retry) != firstID || !strings.Contains(string(retry), `"idempotent":true`) {
		t.Fatalf("cron retry = %s, first id %s", retry, firstID)
	}
	callOperationalTool(t, s, "reactor_create_cron_trigger", map[string]any{
		"slug": "trigger-create-idem", "spec": "30 9 * * *", "idempotency_key": "cron-create-1",
	}, true)
	rows, err := j.ListTriggersForWorkflow(ctx, "wf_trigger_create_idem")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != firstID {
		t.Fatalf("idempotent trigger rows = %+v", rows)
	}
}

func TestHTTPMCPWorkflowStateRuntimeReceiptDistinguishesAppliedAndDeferred(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, true)
	s.Scopes = &WriteScopes{Dispatch: true}
	ctx := context.Background()
	mainSource, dag := visualStepFixture("state-receipt", "execute")
	artifact := publishVerifiedTestArtifact(t, s, "state-receipt", []byte("state-receipt"), mainSource, dag)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_state_receipt", "state-receipt", sourceCodeHashForTest(mainSource), "0.1.0", artifact.Digest, dag, journal.DefaultTenant, sourceManifestPinForTest(t, artifact)); err != nil {
		t.Fatal(err)
	}
	reconciles := 0
	s.ReconcileCron = func(context.Context) error {
		reconciles++
		return nil
	}
	applied := callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{
		"slug": "state-receipt", "state": "disabled",
	}, false)
	if !strings.Contains(string(applied), `"runtime_reconciled":true`) {
		t.Fatalf("applied workflow state receipt = %s", applied)
	}
	s.ReconcileCron = func(context.Context) error { return errors.New("not leader") }
	deferred := callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{
		"slug": "state-receipt", "state": "enabled", "expected_version": 1,
	}, false)
	if !strings.Contains(string(deferred), `"runtime_reconciled":false`) || !strings.Contains(string(deferred), `"runtime_note"`) {
		t.Fatalf("deferred workflow state receipt = %s", deferred)
	}
	if reconciles != 1 {
		t.Fatalf("reconcile calls = %d, want 1", reconciles)
	}
}

func TestHTTPMCPWorkflowStateRejectsStaleExpectedState(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, true)
	s.Scopes = &WriteScopes{Dispatch: true}
	ctx := context.Background()
	mainSource, dag := visualStepFixture("state-fence", "execute")
	artifact := publishVerifiedTestArtifact(t, s, "state-fence", []byte("state-fence"), mainSource, dag)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_state_fence", "state-fence", sourceCodeHashForTest(mainSource), "0.1.0", artifact.Digest, dag, journal.DefaultTenant, sourceManifestPinForTest(t, artifact)); err != nil {
		t.Fatal(err)
	}
	callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{
		"slug": "state-fence", "state": "disabled", "expected_state": "enabled",
	}, false)
	callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{
		"slug": "state-fence", "state": "enabled", "expected_state": "enabled", "expected_version": 1,
	}, true)
	enabled, err := j.IsWorkflowEnabled(ctx, "wf_state_fence")
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("stale MCP state decision re-enabled workflow")
	}
}

func TestHTTPMCPWorkflowStateRejectsNullOrZeroOptionalFences(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, true)
	s.Scopes = &WriteScopes{Dispatch: true}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_state_optional_fence", "state-optional-fence", "h", "0.1.0", json.RawMessage(`{}`), journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}

	// Both fences are optional while disabling. A field that is present must
	// satisfy its schema: null and zero must not silently remove a fence.
	for _, args := range []map[string]any{
		{"slug": "state-optional-fence", "state": "disabled", "expected_version": 0},
		{"slug": "state-optional-fence", "state": "disabled", "expected_version": nil},
		{"slug": "state-optional-fence", "state": "disabled", "expected_state": ""},
		{"slug": "state-optional-fence", "state": "disabled", "expected_state": nil},
	} {
		callOperationalTool(t, s, "reactor_set_workflow_state", args, true)
	}
	enabled, err := j.IsWorkflowEnabled(ctx, "wf_state_optional_fence")
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Fatal("invalid optional fence changed workflow state")
	}
}

func TestHTTPMCPWorkflowStateRejectsStaleReviewedVersion(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, true)
	s.Scopes = &WriteScopes{Dispatch: true, Authoring: true}
	ctx := context.Background()
	mainSource, dag := visualStepFixture("version-state-fence", "execute")
	artifactA := publishVerifiedTestArtifact(t, s, "version-state-fence", []byte("version-a"), mainSource, dag)
	artifactB := publishVerifiedTestArtifact(t, s, "version-state-fence", []byte("version-b"), mainSource, dag)
	digestA, digestB := artifactA.Digest, artifactB.Digest
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_version_state_fence", "version-state-fence", sourceCodeHashForTest(mainSource), "0.1.0", digestA, dag, journal.DefaultTenant, sourceManifestPinForTest(t, artifactA)); err != nil {
		t.Fatal(err)
	}
	callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{
		"slug": "version-state-fence", "state": "disabled", "expected_state": "enabled", "expected_version": 1,
	}, false)
	if _, err := j.RecordWorkflowVersionWithArtifactIfDisabled(ctx, "wf_version_state_fence", "0.1.0", sourceCodeHashForTest(mainSource), digestB, dag, sourceManifestPinForTest(t, artifactB)); err != nil {
		t.Fatal(err)
	}
	callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{
		"slug": "version-state-fence", "state": "enabled", "expected_state": "disabled", "expected_version": 1,
	}, true)
	if enabled, err := j.IsWorkflowEnabled(ctx, "wf_version_state_fence"); err != nil || enabled {
		t.Fatalf("stale MCP version activation changed state: enabled=%v err=%v", enabled, err)
	}
	activation := callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{
		"slug": "version-state-fence", "state": "enabled", "expected_state": "disabled", "expected_version": 2,
	}, false)
	if !strings.Contains(string(activation), `"version":2`) || !strings.Contains(string(activation), `"artifact_sha256":"`+digestB+`"`) || !strings.Contains(string(activation), `"artifact_status":"verified"`) {
		t.Fatalf("activation receipt omitted immutable identity: %s", activation)
	}
	if enabled, err := j.IsWorkflowEnabled(ctx, "wf_version_state_fence"); err != nil || !enabled {
		t.Fatalf("current MCP version activation did not enable workflow: enabled=%v err=%v", enabled, err)
	}
}

func TestHTTPMCPWorkflowStateRequiresExplicitVersion(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, true)
	s.Scopes = &WriteScopes{Dispatch: true}
	ctx := context.Background()
	mainSource, dag := visualStepFixture("legacy-activation", "execute")
	artifactA := publishVerifiedTestArtifact(t, s, "legacy-activation", []byte("legacy-a"), mainSource, dag)
	artifactB := publishVerifiedTestArtifact(t, s, "legacy-activation", []byte("legacy-b"), mainSource, dag)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_legacy_activation", "legacy-activation", sourceCodeHashForTest(mainSource), "0.1.0", artifactA.Digest, dag, journal.DefaultTenant, sourceManifestPinForTest(t, artifactA)); err != nil {
		t.Fatal(err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_legacy_activation", false); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifactIfDisabled(ctx, "wf_legacy_activation", "0.1.0", sourceCodeHashForTest(mainSource), artifactB.Digest, dag, sourceManifestPinForTest(t, artifactB)); err != nil {
		t.Fatal(err)
	}
	callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{
		"slug": "legacy-activation", "state": "enabled", "expected_state": "disabled",
	}, true)
	if enabled, err := j.IsWorkflowEnabled(ctx, "wf_legacy_activation"); err != nil || enabled {
		t.Fatalf("unreviewed activation changed state: enabled=%t err=%v", enabled, err)
	}
	receipt := callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{
		"slug": "legacy-activation", "state": "enabled", "expected_state": "disabled", "expected_version": 2,
	}, false)
	if !strings.Contains(string(receipt), `"version":2`) || !strings.Contains(string(receipt), `"artifact_sha256":"`+artifactB.Digest+`"`) || !strings.Contains(string(receipt), `"artifact_status":"verified"`) {
		t.Fatalf("legacy activation receipt = %s", receipt)
	}
}

func TestHTTPMCPWorkflowStateRefusesMetadataOnlyActivation(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, true)
	s.Scopes = &WriteScopes{Dispatch: true}
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_metadata_only", "metadata-only", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_metadata_only", false); err != nil {
		t.Fatal(err)
	}
	callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{
		"slug": "metadata-only", "state": "enabled", "expected_version": 1,
	}, true)
	enabled, err := j.IsWorkflowEnabled(ctx, "wf_metadata_only")
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("metadata-only workflow was enabled without an immutable artifact")
	}
}

func TestHTTPMCPWorkflowMetadataOnlyRemainsInspectable(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, false)
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_metadata_inspect", "metadata-inspect", "source-hash", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_metadata_inspect", false); err != nil {
		t.Fatal(err)
	}
	view := callOperationalTool(t, s, "reactor_get_workflow", map[string]any{"slug": "metadata-inspect"}, false)
	if !strings.Contains(string(view), `"current_version":1`) ||
		!strings.Contains(string(view), `"artifact_status":"missing"`) ||
		!strings.Contains(string(view), `"enabled":false`) {
		t.Fatalf("metadata-only workflow view = %s", view)
	}
}

func TestHTTPMCPTriggerInventoryIsPaginated(t *testing.T) {
	s, j, _ := newTestServer(t, false)
	s.Scopes = &WriteScopes{Triggers: true}
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_trigger_page", "trigger-page", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := j.CreateCronTrigger(ctx, "wf_trigger_page", []byte(`{"spec":"* * * * *"}`)); err != nil {
			t.Fatal(err)
		}
	}
	page := callOperationalTool(t, s, "reactor_list_triggers", map[string]any{"slug": "trigger-page", "limit": 1}, false)
	if !strings.Contains(string(page), `"triggers":[`) || !strings.Contains(string(page), `"has_more":true`) || !strings.Contains(string(page), `"next_offset":1`) {
		t.Fatalf("trigger page=%s", page)
	}
	if !strings.Contains(string(page), `"limit":1`) || !strings.Contains(string(page), `"offset":0`) {
		t.Fatalf("trigger page omitted pagination envelope=%s", page)
	}
}

func TestHTTPMCPTriggerAndRetryScopes(t *testing.T) {
	for _, scopes := range []*WriteScopes{{}, {Authoring: true}, {Dispatch: true}} {
		s, _, _ := newTestServer(t, true)
		s.Scopes = scopes
		callOperationalTool(t, s, "reactor_create_cron_trigger", map[string]any{"slug": "flow", "spec": "* * * * *"}, true)
		s.ensureRegistered()
		if _, ok := s.tools["reactor_list_triggers"]; !ok {
			t.Fatal("read-only trigger inspection missing")
		}
		if _, ok := s.tools["reactor_create_cron_trigger"]; ok {
			t.Fatal("trigger scope leaked")
		}
	}
	s, _, _ := newTestServer(t, true)
	s.Scopes = &WriteScopes{Triggers: true}
	called := false
	s.RetryDeadLetter = func(context.Context, string) (string, error) { called = true; return "queued", nil }
	callOperationalTool(t, s, "reactor_retry_dead_letter", map[string]any{"dead_letter_id": "any"}, true)
	if called {
		t.Fatal("retry callback invoked without dispatch scope")
	}
}

func TestHTTPMCPWorkflowDeletionRequiresConfirmationPauseAndDrain(t *testing.T) {
	s, j, _ := newTestServer(t, false)
	s.TenantID = "acme"
	s.Scopes = &WriteScopes{Authoring: true}
	reconciles := 0
	s.ReconcileCron = func(context.Context) error {
		reconciles++
		return nil
	}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_delete", "retire-me", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	callOperationalTool(t, s, "reactor_delete_workflow", map[string]any{
		"slug": "retire-me", "confirm_slug": "retire-other", "expected_version": 1,
	}, true)
	callOperationalTool(t, s, "reactor_delete_workflow", map[string]any{
		"slug": "retire-me", "confirm_slug": "retire-me", "expected_version": 99,
	}, true)
	if err := j.SetWorkflowEnabled(ctx, "wf_delete", false); err != nil {
		t.Fatal(err)
	}
	deleted := callOperationalTool(t, s, "reactor_delete_workflow", map[string]any{
		"slug": "retire-me", "confirm_slug": "retire-me", "expected_version": 1,
	}, false)
	if !strings.Contains(string(deleted), `"deleted":true`) || !strings.Contains(string(deleted), `"runtime_reconciled":true`) {
		t.Fatalf("delete response = %s", deleted)
	}
	if reconciles != 1 {
		t.Fatalf("reconcile calls = %d, want 1", reconciles)
	}
	if _, err := j.WorkflowIDBySlugInTenant(ctx, "retire-me", "acme"); !errors.Is(err, journal.ErrNotFound) {
		t.Fatalf("deleted workflow lookup = %v, want not found", err)
	}

	if err := j.CreateWorkflowInTenant(ctx, "wf_busy", "busy-me", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_busy", "wf_busy", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_busy", false); err != nil {
		t.Fatal(err)
	}
	callOperationalTool(t, s, "reactor_delete_workflow", map[string]any{
		"slug": "busy-me", "confirm_slug": "busy-me", "expected_version": 1,
	}, true)
}

func TestHTTPMCPMutationAuditRecordsOutcomeAndRedactsPayload(t *testing.T) {
	s, j, _ := newTestServer(t, true)
	s.TenantID = "acme"
	s.Scopes = &WriteScopes{Dispatch: true}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_audit", "audited", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{"slug": "audited", "state": "disabled"}, false)
	raw := callOperationalTool(t, s, "reactor_list_mcp_audit", map[string]any{}, false)
	var auditPage struct {
		Entries []journal.MCPAuditEntry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &auditPage); err != nil {
		t.Fatal(err)
	}
	if len(auditPage.Entries) != 1 || auditPage.Entries[0].TenantID != "acme" || auditPage.Entries[0].ToolName != "reactor_set_workflow_state" || auditPage.Entries[0].Outcome != "succeeded" || auditPage.Entries[0].Target != "slug=audited" {
		t.Fatalf("audit rows = %+v", auditPage)
	}
	// Unknown fields are rejected at the handler boundary and still produce a
	// redacted failed mutation audit; the rejected value must never cross into
	// the durable audit detail.
	callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{"slug": "audited", "state": "disabled", "payload": "must-not-be-stored"}, true)
	callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{"slug": "missing", "state": "disabled"}, true)
	raw = callOperationalTool(t, s, "reactor_list_mcp_audit", map[string]any{}, false)
	if !strings.Contains(string(raw), `"outcome":"failed"`) || strings.Contains(string(raw), "must-not-be-stored") {
		t.Fatalf("failed mutation was not audited: %s", raw)
	}
}

func TestHTTPMCPMutationAuditBoundsOversizedTarget(t *testing.T) {
	s, j, _ := newTestServer(t, true)
	s.TenantID = "acme"
	s.Scopes = &WriteScopes{Dispatch: true}
	ctx := context.Background()
	longSlug := strings.Repeat("a", maxMCPAuditTargetBytes+128)
	if err := j.CreateWorkflowInTenant(ctx, "wf_long_audit", longSlug, "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{"slug": longSlug, "state": "disabled"}, false)

	raw := callOperationalTool(t, s, "reactor_list_mcp_audit", map[string]any{}, false)
	var page struct {
		Entries []journal.MCPAuditEntry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 1 {
		t.Fatalf("audit entries = %+v, want one successful mutation receipt", page.Entries)
	}
	target := page.Entries[0].Target
	if len(target) > maxMCPAuditTargetBytes || !strings.HasSuffix(target, "...[truncated]") {
		t.Fatalf("oversized audit target = %d bytes %q, want bounded truncation", len(target), target)
	}
	if strings.ContainsAny(target, "\r\n\t") {
		t.Fatalf("audit target contains control characters: %q", target)
	}

	args, err := json.Marshal(map[string]any{
		"slug":    longSlug,
		"payload": "customer-secret-must-not-be-stored",
	})
	if err != nil {
		t.Fatal(err)
	}
	boundedTarget, detail := summarizeMCPAuditArgs(args)
	if len(boundedTarget) > maxMCPAuditTargetBytes || strings.Contains(string(detail), "customer-secret") {
		t.Fatalf("audit summary leaked or exceeded bounds: target=%q detail=%s", boundedTarget, detail)
	}
}

func TestHTTPMCPDeadLetterRedriveIsScopedAndUsesCallback(t *testing.T) {
	s, j, _ := newTestServer(t, true)
	s.Scopes = &WriteScopes{Dispatch: true}
	ctx := context.Background()
	ids := map[string]string{}
	for _, tenant := range []string{"default", "acme"} {
		wf, run := "wf_"+tenant, "run_"+tenant
		if err := j.CreateWorkflowInTenant(ctx, wf, tenant, "h", "0.1.0", json.RawMessage(`{}`), tenant); err != nil {
			t.Fatal(err)
		}
		if err := j.CreateRun(ctx, run, wf, "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
		if err := j.MoveStepToDeadLetter(ctx, run, "step", "failed", nil); err != nil {
			t.Fatal(err)
		}
		item, err := j.FindDeadLetterByRun(ctx, run)
		if err != nil {
			t.Fatal(err)
		}
		ids[tenant] = item.ID
	}
	var called string
	var callbackErr error
	s.RetryDeadLetter = func(_ context.Context, id string) (string, error) { called = id; return "queued", callbackErr }
	callOperationalTool(t, s, "reactor_retry_dead_letter", map[string]any{"dead_letter_id": ids["acme"]}, true)
	if called != "" {
		t.Fatal("foreign retry reached dispatcher")
	}
	raw := callOperationalTool(t, s, "reactor_retry_dead_letter", map[string]any{"dead_letter_id": ids["default"]}, false)
	if called != ids["default"] || !strings.Contains(string(raw), `"status":"queued"`) || !strings.Contains(string(raw), `"run_id":"run_default"`) {
		t.Fatalf("redrive response=%s callback=%s", raw, called)
	}
	callbackErr = errors.New("workflow disabled")
	callOperationalTool(t, s, "reactor_retry_dead_letter", map[string]any{"dead_letter_id": ids["default"]}, true)
}

func TestMCPTriggerViewExcludesArbitraryConfiguration(t *testing.T) {
	raw, err := json.Marshal(mcpTriggerView(journal.Trigger{Kind: journal.TriggerWebhook, TokenID: "bearer-secret", SecretID: "private-id", Config: []byte(`{"sync":true,"password":"secret-value"}`)}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "bearer-secret") || strings.Contains(string(raw), "private-id") || strings.Contains(string(raw), "secret-value") || !strings.Contains(string(raw), `"token_available":true`) || !strings.Contains(string(raw), `"sync":true`) {
		t.Fatalf("unsafe view=%s", raw)
	}
}

func TestHTTPMCPTenantResolverOverridesStaticDefault(t *testing.T) {
	s, j, _ := newTestServer(t, false)
	if err := j.CreateWorkflowInTenant(context.Background(), "wf_acme", "acme-flow", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	type tenantKey struct{}
	s.TenantIDFromContext = func(ctx context.Context) string {
		value, _ := ctx.Value(tenantKey{}).(string)
		return value
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "reactor_list_workflows", "arguments": map[string]any{}}})
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), tenantKey{}, "acme"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "acme-flow") {
		t.Fatalf("tenant resolver did not scope HTTP MCP request: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestHTTPMCPWorkflowReviewAndLifecycle(t *testing.T) {
	s, j, _ := newTestServer(t, true)
	s.Scopes = &WriteScopes{Dispatch: true}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_review", "review-flow", "hash-v1", "0.1.0", json.RawMessage(`{"steps":[{"name":"one"}]}`), journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordWorkflowVersion(ctx, "wf_review", "0.2.0", "hash-v2", json.RawMessage(`{"steps":[{"name":"two"}]}`)); err != nil {
		t.Fatal(err)
	}
	metadata := callOperationalTool(t, s, "reactor_get_workflow", map[string]any{"slug": "review-flow"}, false)
	if !strings.Contains(string(metadata), `"current_version":2`) || !strings.Contains(string(metadata), `"enabled":true`) || !strings.Contains(string(metadata), `"artifact_status":"missing"`) {
		t.Fatalf("workflow metadata=%s", metadata)
	}
	versions := callOperationalTool(t, s, "reactor_list_workflow_versions", map[string]any{"slug": "review-flow"}, false)
	if !strings.Contains(string(versions), `"version":2`) || !strings.Contains(string(versions), `"artifact_sha256":""`) {
		t.Fatalf("workflow versions=%s", versions)
	}
	page := callOperationalTool(t, s, "reactor_list_workflow_versions", map[string]any{"slug": "review-flow", "limit": 1}, false)
	if !strings.Contains(string(page), `"limit":1`) || !strings.Contains(string(page), `"offset":0`) || !strings.Contains(string(page), `"has_more":true`) || !strings.Contains(string(page), `"next_offset":1`) || !strings.Contains(string(page), `"version":2`) {
		t.Fatalf("workflow version page=%s", page)
	}
	if strings.Contains(string(page), `"version":1`) {
		t.Fatalf("workflow version page exceeded limit=%s", page)
	}
	callOperationalTool(t, s, "reactor_list_workflow_versions", map[string]any{"slug": "review-flow", "limit": 501}, true)
	callOperationalTool(t, s, "reactor_list_workflow_versions", map[string]any{"slug": "review-flow", "offset": 10001}, true)
	callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{"slug": "review-flow", "state": "disabled"}, false)
	metadata = callOperationalTool(t, s, "reactor_get_workflow", map[string]any{"slug": "review-flow"}, false)
	if !strings.Contains(string(metadata), `"enabled":false`) {
		t.Fatalf("workflow disable did not persist: %s", metadata)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_other", "other-flow", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{"slug": "other-flow", "state": "enabled"}, true)
}

func TestHTTPMCPWorkflowReviewIsReadOnlyWithoutDispatchScope(t *testing.T) {
	s, j, _ := newTestServer(t, false)
	if err := j.CreateWorkflow(context.Background(), "wf_read", "read-flow", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	s.ensureRegistered()
	if _, ok := s.tools["reactor_get_workflow"]; !ok {
		t.Fatal("workflow metadata read tool missing")
	}
	if _, ok := s.tools["reactor_list_workflow_versions"]; !ok {
		t.Fatal("workflow version read tool missing")
	}
	if _, ok := s.tools["reactor_set_workflow_state"]; ok {
		t.Fatal("workflow lifecycle write leaked into read-only MCP")
	}
}

func TestHTTPMCPDryRunDelegatesToTestDispatcher(t *testing.T) {
	s, j, _ := newTestServer(t, false)
	s.Scopes = &WriteScopes{Dispatch: true}
	if err := j.CreateWorkflow(context.Background(), "wf_dry", "dry-flow", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.SetWorkflowEnabled(context.Background(), "wf_dry", false); err != nil {
		t.Fatal(err)
	}
	s.Dispatch = func(context.Context, string, json.RawMessage) (string, error) {
		return "live-path", nil
	}
	called := false
	s.TestDispatch = func(ctx context.Context, slug string, payload json.RawMessage) (string, error) {
		called = true
		if slug != "dry-flow" || string(payload) != `{"sample":true}` {
			t.Fatalf("dry dispatch args slug=%q payload=%s", slug, payload)
		}
		if err := j.CreateRun(ctx, "run_dry", "wf_dry", "manual", payload); err != nil {
			return "", err
		}
		return "run_dry", nil
	}
	result := callOperationalTool(t, s, "reactor_test_workflow", map[string]any{"slug": "dry-flow", "payload": map[string]any{"sample": true}}, false)
	if !called || !strings.Contains(string(result), `"mode":"dry_run"`) || !strings.Contains(string(result), `"run_id":"run_dry"`) || !strings.Contains(string(result), `"run":`) {
		t.Fatalf("dry-run result=%s called=%v", result, called)
	}
}

func TestHTTPMCPDeliverSignalIsTenantScopedAndTokenOpaque(t *testing.T) {
	s, j, _ := newTestServer(t, true)
	s.TenantID = "acme"
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_signal_acme", "signal-acme", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_signal_other", "signal-other", "h", "0.1.0", json.RawMessage(`{}`), "other"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_signal_acme", "wf_signal_acme", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_signal_other", "wf_signal_other", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.ScheduleSignal(ctx, "run_signal_acme", "approval", "approval", "sig_acme_bound", time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.ScheduleSignal(ctx, "run_signal_other", "approval", "approval", "sig_other_bound", time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	foreign := callOperationalTool(t, s, "reactor_deliver_signal", map[string]any{"signal_token": "sig_other_bound", "payload": map[string]any{"approved": true}}, true)
	if strings.Contains(string(foreign), `"accepted":true`) {
		t.Fatalf("foreign signal returned a success body: %s", foreign)
	}
	accepted := callOperationalTool(t, s, "reactor_deliver_signal", map[string]any{"signal_token": "sig_acme_bound", "payload": map[string]any{"approved": true}}, false)
	if !strings.Contains(string(accepted), `"accepted":true`) || !strings.Contains(string(accepted), `"run_id":"run_signal_acme"`) || strings.Contains(string(accepted), "sig_acme_bound") || !strings.Contains(string(accepted), `"token_returned":false`) {
		t.Fatalf("signal receipt leaked or was incomplete: %s", accepted)
	}
	row, err := j.FindLatestSignalSchedule(ctx, "run_signal_acme", "approval")
	if err != nil || string(row.SignalPayload) != `{"approved":true}` {
		t.Fatalf("signal payload = %s, err=%v", row.SignalPayload, err)
	}
	callOperationalTool(t, s, "reactor_deliver_signal", map[string]any{"signal_token": "sig_acme_bound", "payload": []any{map[string]any{"wrong": true}}}, true)
	callOperationalTool(t, s, "reactor_deliver_signal", map[string]any{"signal_token": "sig_acme_bound", "unexpected": true}, true)
}

func TestHTTPMCPWorkflowReviewReceiptIsTenantScopedAndBounded(t *testing.T) {
	s, j, _ := newTestServer(t, false)
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_review_receipt", "review-receipt", "h", "0.1.0", json.RawMessage(`{"slug":"review-receipt","steps":[{"name":"fetch","kind":"step"}]}`), "acme"); err != nil {
		t.Fatal(err)
	}
	s.TenantID = "acme"
	result := callOperationalTool(t, s, "reactor_review_workflow", map[string]any{"slug": "review-receipt"}, false)
	for _, want := range []string{`"review_status":"needs_build"`, `"flow_valid":false`, `"flow_verification":"unverified"`, `"flow_verification_reason":"retained source and visual DAG proof was not checked"`, `"flow_data_trust":"untrusted"`, `"version_source":"immutable_version"`, `"source_integrity":"not_checked"`, `"nodes"`, `"topology":{"complete":true`, `"provenance":"declared_dag"`} {
		if !strings.Contains(string(result), want) {
			t.Fatalf("workflow review missing %s: %s", want, result)
		}
	}
	for _, want := range []string{`"operational"`, `"triggers":[]`, `"secret_grants":[]`, `"notification_routes":[]`} {
		if !strings.Contains(string(result), want) {
			t.Fatalf("workflow review missing operational field %s: %s", want, result)
		}
	}
	callOperationalTool(t, s, "reactor_review_workflow", map[string]any{"slug": "review-receipt"}, false)
	s.TenantID = "other"
	callOperationalTool(t, s, "reactor_review_workflow", map[string]any{"slug": "review-receipt"}, true)
}

func TestHTTPMCPWorkflowReviewIncludesBoundedOperationalDependencies(t *testing.T) {
	s, j, creds := newTestServer(t, false)
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_review_ops", "review-ops", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := creds.Create(ctx, credentials.CreateParams{ID: "cred_review_ops", TenantID: "acme", Name: "ops", Service: "service", Provider: "shared-secret"}); err != nil {
		t.Fatal(err)
	}
	if err := j.GrantSecret(ctx, "wf_review_ops", "cred_review_ops", "operator", "must stay private"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.CreateCronTrigger(ctx, "wf_review_ops", json.RawMessage(`{"spec":"0 * * * *"}`)); err != nil {
		t.Fatal(err)
	}
	channelID, err := j.CreateNotificationChannelInTenant(ctx, "acme", "ops-alerts", journal.ChannelKindGenericWebhook, json.RawMessage(`{"url":"https://example.test/secret-hook"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.AddNotificationRoute(ctx, "wf_review_ops", channelID, "failed,failed_dlq"); err != nil {
		t.Fatal(err)
	}
	s.TenantID = "acme"
	result := callOperationalTool(t, s, "reactor_review_workflow", map[string]any{"slug": "review-ops"}, false)
	text := string(result)
	for _, want := range []string{`"operational"`, `"kind":"cron"`, `"credential_id":"cred_review_ops"`, `"channel_name":"ops-alerts"`, `"on_statuses":"failed,failed_dlq"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("workflow review missing operational dependency %s: %s", want, result)
		}
	}
	if strings.Contains(text, "must stay private") || strings.Contains(text, "secret-hook") {
		t.Fatalf("workflow review leaked secret or channel configuration: %s", result)
	}
}

func TestHTTPMCPNotificationRoutingIsTenantScoped(t *testing.T) {
	s, j, _ := newTestServer(t, false)
	s.Scopes = &WriteScopes{Notifications: true}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_alert", "alert-flow", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	localID, err := j.CreateNotificationChannelInTenant(ctx, "acme", "ops", journal.ChannelKindGenericWebhook, json.RawMessage(`{"url":"https://example.test/hook"}`))
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := j.CreateNotificationChannelInTenant(ctx, "acme", "ops-secondary", journal.ChannelKindGenericWebhook, json.RawMessage(`{"url":"https://example.test/secondary"}`))
	if err != nil {
		t.Fatal(err)
	}
	foreignID, err := j.CreateNotificationChannelInTenant(ctx, journal.DefaultTenant, "other-ops", journal.ChannelKindGenericWebhook, json.RawMessage(`{"url":"https://example.test/other"}`))
	if err != nil {
		t.Fatal(err)
	}
	s.TenantID = "acme"
	callOperationalTool(t, s, "reactor_attach_notification_channel", map[string]any{"slug": "alert-flow", "channel_id": foreignID}, true)
	attached := callOperationalTool(t, s, "reactor_attach_notification_channel", map[string]any{"slug": "alert-flow", "channel_id": localID, "on_statuses": "failed, failed_dlq, failed"}, false)
	if !strings.Contains(string(attached), `"on_statuses":"failed,failed_dlq"`) {
		t.Fatalf("attach response=%s", attached)
	}
	callOperationalTool(t, s, "reactor_attach_notification_channel", map[string]any{"slug": "alert-flow", "channel_id": secondID}, false)
	routes := callOperationalTool(t, s, "reactor_list_notification_routes", map[string]any{"slug": "alert-flow", "limit": 1}, false)
	if strings.Contains(string(routes), "https://") || !strings.Contains(string(routes), localID) || !strings.Contains(string(routes), "ops") {
		t.Fatalf("unsafe or incomplete route view=%s", routes)
	}
	if !strings.Contains(string(routes), `"has_more":true`) || !strings.Contains(string(routes), `"next_offset":1`) || strings.Contains(string(routes), secondID) {
		t.Fatalf("route page did not preserve continuation bounds=%s", routes)
	}
	callOperationalTool(t, s, "reactor_attach_notification_channel", map[string]any{"slug": "alert-flow", "channel_id": localID, "on_statuses": "unknown"}, true)
	callOperationalTool(t, s, "reactor_detach_notification_channel", map[string]any{"slug": "alert-flow", "channel_id": localID}, false)
	if routes = callOperationalTool(t, s, "reactor_list_notification_routes", map[string]any{"slug": "alert-flow"}, false); strings.Contains(string(routes), localID) {
		t.Fatalf("route still present after detach=%s", routes)
	}
	callOperationalTool(t, s, "reactor_list_notification_routes", map[string]any{"slug": "alert-flow", "limit": 501}, true)
	callOperationalTool(t, s, "reactor_list_notification_routes", map[string]any{"slug": "alert-flow", "offset": 10001}, true)
}

func TestHTTPMCPNotificationChannelLifecycleKeepsSecretsOutOfMCP(t *testing.T) {
	s, j, creds := newTestServer(t, false)
	s.TenantID = "acme"
	s.Scopes = &WriteScopes{Notifications: true}
	ctx := context.Background()
	if err := creds.Create(ctx, credentials.CreateParams{ID: "smtp-pass", Name: "smtp-pass", TenantID: "acme", Service: "smtp", Provider: "shared-secret"}); err != nil {
		t.Fatal(err)
	}
	if err := creds.Create(ctx, credentials.CreateParams{ID: "foreign-pass", Name: "foreign-pass", TenantID: "other", Service: "smtp", Provider: "shared-secret"}); err != nil {
		t.Fatal(err)
	}
	slack := callOperationalTool(t, s, "reactor_create_notification_channel", map[string]any{
		"name": "slack-ops", "kind": "slack_webhook",
		"config": map[string]any{"url_credential_id": "smtp-pass"},
	}, false)
	if !strings.Contains(string(slack), `"kind":"slack_webhook"`) {
		t.Fatalf("slack channel response=%s", slack)
	}
	created := callOperationalTool(t, s, "reactor_create_notification_channel", map[string]any{
		"name": "ops-webhook", "kind": "generic_webhook",
		"config": map[string]any{"url": "https://alerts.example.test/hook", "header_name": "X-Token", "header_credential_id": "smtp-pass"},
	}, false)
	if !strings.Contains(string(created), `"created":true`) || !strings.Contains(string(created), `"kind":"generic_webhook"`) {
		t.Fatalf("create channel response=%s", created)
	}
	var createdView struct {
		ChannelID string `json:"channel_id"`
	}
	if err := json.Unmarshal(created, &createdView); err != nil || createdView.ChannelID == "" {
		t.Fatalf("created channel id=%q err=%v", createdView.ChannelID, err)
	}
	channel, err := j.GetNotificationChannel(ctx, createdView.ChannelID)
	if err != nil || strings.Contains(string(channel.ConfigJSON), "secret") {
		t.Fatalf("stored channel=%s err=%v", channel.ConfigJSON, err)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_notify", "notify-flow", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.AddNotificationRoute(ctx, "wf_notify", createdView.ChannelID, "failed"); err != nil {
		t.Fatal(err)
	}
	callOperationalTool(t, s, "reactor_delete_notification_channel", map[string]any{"channel_id": createdView.ChannelID, "confirm_channel_id": createdView.ChannelID}, true)
	if err := j.DeleteNotificationRoute(ctx, "wf_notify", createdView.ChannelID); err != nil {
		t.Fatal(err)
	}
	callOperationalTool(t, s, "reactor_create_notification_channel", map[string]any{
		"name": "unsafe", "kind": "generic_webhook",
		"config": map[string]any{"url": "https://alerts.example.test/hook", "headers": map[string]any{"X-Token": "plaintext"}},
	}, true)
	callOperationalTool(t, s, "reactor_create_notification_channel", map[string]any{
		"name": "unsafe-smtp", "kind": "email_smtp",
		"config": map[string]any{"host": "smtp.example.test", "from": "a@example.test", "to": "ops@example.test", "password": "plaintext"},
	}, true)
	callOperationalTool(t, s, "reactor_create_notification_channel", map[string]any{
		"name": "foreign-ref", "kind": "email_smtp",
		"config": map[string]any{"host": "smtp.example.test", "from": "a@example.test", "to": "ops@example.test", "password_credential_id": "foreign-pass"},
	}, true)
	callOperationalTool(t, s, "reactor_delete_notification_channel", map[string]any{"channel_id": createdView.ChannelID, "confirm_channel_id": "wrong"}, true)
	deleted := callOperationalTool(t, s, "reactor_delete_notification_channel", map[string]any{"channel_id": createdView.ChannelID, "confirm_channel_id": createdView.ChannelID}, false)
	if !strings.Contains(string(deleted), `"deleted":true`) {
		t.Fatalf("delete channel response=%s", deleted)
	}
	if _, err := j.GetNotificationChannel(ctx, createdView.ChannelID); !errors.Is(err, journal.ErrNotFound) {
		t.Fatalf("deleted channel lookup=%v", err)
	}
}

func TestMCPNotificationConfigRejectsDuplicateNestedFields(t *testing.T) {
	t.Parallel()
	s, _, _ := newTestServer(t, false)

	_, err := s.normalizeNotificationConfig(context.Background(), journal.ChannelKindGenericWebhook, json.RawMessage(`{"url":"https://first.example.test/hook","url":"https://second.example.test/hook"}`))
	if !errors.Is(err, errInvalidParamsErr) {
		t.Fatalf("duplicate nested notification field error = %v, want invalid params", err)
	}
}

func TestHTTPMCPChainTriggerStatusCanonicalization(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, false)
	s.TenantID = "acme"
	s.Scopes = &WriteScopes{Triggers: true}
	ctx := context.Background()
	for _, row := range []struct {
		id, slug string
	}{
		{"wf_chain_status_downstream", "chain-status-downstream"},
		{"wf_chain_status_source", "chain-status-source"},
	} {
		if err := j.CreateWorkflowInTenant(ctx, row.id, row.slug, "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
			t.Fatal(err)
		}
	}

	first := callOperationalTool(t, s, "reactor_create_chain_trigger", map[string]any{
		"downstream_slug": "chain-status-downstream",
		"source_slug":     "chain-status-source",
		"on_statuses":     "succeeded,failed,succeeded",
		"idempotency_key": "chain-status-1",
	}, false)
	firstID := operationalID(t, first)
	if !strings.Contains(string(first), `"on_statuses":"failed,succeeded"`) || strings.Contains(string(first), `succeeded,failed,succeeded`) {
		t.Fatalf("create response did not expose canonical statuses: %s", first)
	}
	row, err := j.GetTriggerForWorkflow(ctx, firstID, "wf_chain_status_downstream")
	if err != nil {
		t.Fatal(err)
	}
	if string(row.Config) != `{"on_statuses":"failed,succeeded","source_workflow_id":"wf_chain_status_source"}` {
		t.Fatalf("persisted chain config = %s", row.Config)
	}

	// Formatting and ordering differences are the same logical request after
	// normalization, so an idempotent retry returns the original trigger.
	retry := callOperationalTool(t, s, "reactor_create_chain_trigger", map[string]any{
		"downstream_slug": "chain-status-downstream",
		"source_slug":     "chain-status-source",
		"on_statuses":     " failed , succeeded ",
		"idempotency_key": "chain-status-1",
	}, false)
	if operationalID(t, retry) != firstID || !strings.Contains(string(retry), `"on_statuses":"failed,succeeded"`) || !strings.Contains(string(retry), `"idempotent":true`) {
		t.Fatalf("canonical idempotent retry = %s, first id %s", retry, firstID)
	}

	updated := callOperationalTool(t, s, "reactor_update_chain_trigger", map[string]any{
		"downstream_slug":   "chain-status-downstream",
		"trigger_id":        firstID,
		"source_slug":       "chain-status-source",
		"on_statuses":       "cancelled,failed,cancelled",
		"expected_revision": int64(1),
	}, false)
	if !strings.Contains(string(updated), `"on_statuses":"cancelled,failed"`) || strings.Contains(string(updated), `cancelled,failed,cancelled`) {
		t.Fatalf("update response did not expose canonical statuses: %s", updated)
	}
	row, err = j.GetTriggerForWorkflow(ctx, firstID, "wf_chain_status_downstream")
	if err != nil {
		t.Fatal(err)
	}
	if row.Revision != 2 || string(row.Config) != `{"on_statuses":"cancelled,failed","source_workflow_id":"wf_chain_status_source"}` {
		t.Fatalf("updated chain config = revision %d config %s", row.Revision, row.Config)
	}

	// Empty CSV members were rejected by the pre-existing API contract and
	// remain rejected after canonicalization.
	callOperationalTool(t, s, "reactor_update_chain_trigger", map[string]any{
		"downstream_slug":   "chain-status-downstream",
		"trigger_id":        firstID,
		"source_slug":       "chain-status-source",
		"on_statuses":       "failed,,succeeded",
		"expected_revision": int64(2),
	}, true)
}
