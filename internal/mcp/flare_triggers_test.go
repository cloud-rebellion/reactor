package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/credentials"
)

func TestHTTPMCPFlareProjectBindingCreateUpdateAndRefusal(t *testing.T) {
	t.Parallel()
	s, j, creds := newTestServer(t, false)
	s.TenantID = "acme"
	s.Scopes = &WriteScopes{Triggers: true}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_flare", "flare-bridge", "h", "1", json.RawMessage(`{"triggers":[{"kind":"webhook","provider":"flare-v1"}]}`), "acme"); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ id, tenant string }{{"flare-key", "acme"}, {"foreign-key", "other"}} {
		if err := creds.Create(ctx, credentials.CreateParams{ID: row.id, Name: row.id, TenantID: row.tenant, Service: "reactor-webhook", Provider: "shared-secret"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, project := range []any{nil, "", "not a project", strings.Repeat("p", 129)} {
		callOperationalTool(t, s, "reactor_create_webhook_trigger", map[string]any{"slug": "flare-bridge", "credential_id": "flare-key", "provider": "flare-v1", "flare_project_id": project}, true)
	}
	callOperationalTool(t, s, "reactor_create_webhook_trigger", map[string]any{"slug": "flare-bridge", "credential_id": "flare-key", "provider": "flare-v1"}, true)
	callOperationalTool(t, s, "reactor_create_webhook_trigger", map[string]any{"slug": "flare-bridge", "credential_id": "flare-key", "provider": "flare-v1", "flare_project_id": "project-1", "sync": true}, true)
	callOperationalTool(t, s, "reactor_create_webhook_trigger", map[string]any{"slug": "flare-bridge", "credential_id": "foreign-key", "provider": "flare-v1", "flare_project_id": "project-1"}, true)
	if rows, err := j.ListTriggersForWorkflow(ctx, "wf_flare"); err != nil || len(rows) != 0 {
		t.Fatalf("invalid creation mutated triggers=%v %v", rows, err)
	}
	args := map[string]any{"slug": "flare-bridge", "credential_id": "flare-key", "provider": "flare-v1", "flare_project_id": "project-1", "idempotency_key": "flare-create"}
	created := callOperationalTool(t, s, "reactor_create_webhook_trigger", args, false)
	id := operationalID(t, created)
	var view struct {
		Token    string `json:"token"`
		Endpoint string `json:"endpoint_path"`
	}
	if err := json.Unmarshal(created, &view); err != nil || view.Endpoint != "/webhook/flare/"+view.Token {
		t.Fatalf("provider endpoint=%s %v", created, err)
	}
	replay := callOperationalTool(t, s, "reactor_create_webhook_trigger", args, false)
	if operationalID(t, replay) != id {
		t.Fatal("idempotent create changed trigger")
	}
	args["flare_project_id"] = "project-2"
	callOperationalTool(t, s, "reactor_create_webhook_trigger", args, true)
	// An ordinary credential rotation preserves the explicit project binding.
	update := map[string]any{"slug": "flare-bridge", "trigger_id": id, "credential_id": "flare-key", "expected_revision": 1}
	callOperationalTool(t, s, "reactor_update_webhook_trigger", update, false)
	row, err := j.GetTriggerForWorkflow(ctx, id, "wf_flare")
	if err != nil || row.Revision != 2 || !strings.Contains(string(row.Config), `"flare_project_id":"project-1"`) {
		t.Fatalf("preserved binding=%+v %v", row, err)
	}
	update["expected_revision"] = 2
	update["flare_project_id"] = "project-2"
	callOperationalTool(t, s, "reactor_update_webhook_trigger", update, false)
	// Reusing a stale revision cannot change the project or verifier options.
	update["flare_project_id"] = "project-3"
	callOperationalTool(t, s, "reactor_update_webhook_trigger", update, true)
	update["expected_revision"] = 3
	update["sync"] = true
	callOperationalTool(t, s, "reactor_update_webhook_trigger", update, true)
	delete(update, "sync")
	update["provider"] = "generic"
	callOperationalTool(t, s, "reactor_update_webhook_trigger", update, true) // DAG provider pin.
	delete(update, "provider")
	update["flare_project_id"] = nil
	callOperationalTool(t, s, "reactor_update_webhook_trigger", update, true)
	row, err = j.GetTriggerForWorkflow(ctx, id, "wf_flare")
	if err != nil || row.Revision != 3 || !strings.Contains(string(row.Config), `"flare_project_id":"project-2"`) {
		t.Fatalf("rejected update mutated binding=%+v %v", row, err)
	}
	listed := callOperationalTool(t, s, "reactor_list_triggers", map[string]any{"slug": "flare-bridge"}, false)
	if !strings.Contains(string(listed), `"flare_project_id":"project-2"`) || strings.Contains(string(listed), view.Token) || strings.Contains(string(listed), "flare-key") {
		t.Fatalf("unsafe/unusable projection=%s", listed)
	}
	// Tenant scoping is evaluated before a trigger or credential is selected.
	s.TenantID = "other"
	callOperationalTool(t, s, "reactor_update_webhook_trigger", map[string]any{"slug": "flare-bridge", "trigger_id": id, "credential_id": "foreign-key", "expected_revision": 3, "flare_project_id": "project-3"}, true)
}

func TestHTTPMCPFlareUpgradeRequiresExplicitProject(t *testing.T) {
	t.Parallel()
	s, j, creds := newTestServer(t, false)
	s.TenantID = "acme"
	s.Scopes = &WriteScopes{Triggers: true, CommandExecution: true}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_generic_flare", "generic-bridge", "h", "1", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := creds.Create(ctx, credentials.CreateParams{ID: "bridge-key", Name: "bridge-key", TenantID: "acme", Service: "reactor-webhook", Provider: "shared-secret"}); err != nil {
		t.Fatal(err)
	}
	created := callOperationalTool(t, s, "reactor_create_webhook_trigger", map[string]any{"slug": "generic-bridge", "credential_id": "bridge-key", "provider": "generic"}, false)
	id := operationalID(t, created)
	update := map[string]any{"slug": "generic-bridge", "trigger_id": id, "credential_id": "bridge-key", "provider": "flare-v1", "expected_revision": 1}
	callOperationalTool(t, s, "reactor_update_webhook_trigger", update, true)
	update["flare_project_id"] = "project-1"
	callOperationalTool(t, s, "reactor_update_webhook_trigger", update, false)
	update["expected_revision"] = 2
	update["provider"] = "generic"
	delete(update, "flare_project_id")
	callOperationalTool(t, s, "reactor_update_webhook_trigger", update, false)
	row, err := j.GetTriggerForWorkflow(ctx, id, "wf_generic_flare")
	if err != nil || strings.Contains(string(row.Config), "flare_project_id") {
		t.Fatalf("provider downgrade retained project policy=%+v %v", row, err)
	}
}
