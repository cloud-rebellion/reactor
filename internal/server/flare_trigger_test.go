package server

import (
	"context"
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/webhook"
)

func TestFlareV1DashboardRequiresProjectBeforeMintingSecret(t *testing.T) {
	t.Parallel()
	env := newTriggerTestEnv(t)
	ctx := context.Background()
	if err := env.j.CreateWorkflowInTenant(ctx, "wf_flare", "flare-bridge", "h", "1", json.RawMessage(`{"triggers":[{"kind":"webhook","provider":"flare-v1"}]}`), "acme"); err != nil {
		t.Fatal(err)
	}
	for _, form := range []url.Values{
		{"kind": {"webhook"}, "provider": {"flare-v1"}},
		{"kind": {"webhook"}, "provider": {"flare-v1"}, "flare_project_id": {"invalid project"}},
		{"kind": {"webhook"}, "provider": {"flare-v1"}, "flare_project_id": {"project-1"}, "sync": {"on"}},
		{"kind": {"webhook"}, "provider": {"generic"}, "flare_project_id": {"project-1"}},
	} {
		resp := postSameOrigin(t, env.server.URL+"/workflows/flare-bridge/triggers?tenant=acme", form)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("invalid Flare form=%d %s", resp.StatusCode, body)
		}
	}
	if rows, err := env.j.ListTriggersForWorkflow(ctx, "wf_flare"); err != nil || len(rows) != 0 {
		t.Fatalf("trigger side effects=%v %v", rows, err)
	}
	if rows, err := env.repo.List(ctx); err != nil || len(rows) != 0 {
		t.Fatalf("credential side effects=%v %v", rows, err)
	}
	if rows, err := env.backend.List(ctx); err != nil || len(rows) != 0 {
		t.Fatalf("vault side effects=%v %v", rows, err)
	}
	resp := postSameOrigin(t, env.server.URL+"/workflows/flare-bridge/triggers?tenant=acme", url.Values{"kind": {"webhook"}, "provider": {"flare-v1"}, "flare_project_id": {"project-1"}})
	defer resp.Body.Close()
	if resp.StatusCode != 303 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("valid Flare form=%d %s", resp.StatusCode, b)
	}
	rows, err := env.j.ListTriggersForWorkflow(ctx, "wf_flare")
	if err != nil || len(rows) != 1 {
		t.Fatalf("created Flare triggers=%v %v", rows, err)
	}
	trig := rows[0]
	if trig.Provider != webhook.ProviderFlareV1 || trig.TenantID != "acme" || !strings.Contains(string(trig.Config), `"flare_project_id":"project-1"`) {
		t.Fatalf("wrong bound trigger=%+v", trig)
	}
	cred, err := env.repo.Get(ctx, trig.SecretID)
	if err != nil || cred.TenantID != "acme" {
		t.Fatalf("credential tenant=%+v %v", cred, err)
	}
}

func TestFlareV1DashboardShowsBoundRouteAndProject(t *testing.T) {
	page := renderTriggersSection(workflowDetailData{NewWebhookToken: "whk_example", NewWebhookSecret: "synthetic-secret", NewWebhookProvider: webhook.ProviderFlareV1, TriggerWritesEnabled: true})
	if !strings.Contains(page, `https://YOUR_REACTOR_HOST/webhook/flare/whk_example`) || !strings.Contains(page, `name="flare_project_id"`) || !strings.Contains(page, `value="flare-v1"`) {
		t.Fatalf("Flare setup missing bound route/project: %s", page)
	}
	detail := triggerDetailCell(journal.Trigger{Kind: journal.TriggerWebhook, Provider: webhook.ProviderFlareV1, TokenID: "whk_example", Config: []byte(`{"flare_project_id":"project-1"}`)})
	if !strings.Contains(detail, `POST /webhook/flare/whk_example`) || !strings.Contains(detail, "project-1") {
		t.Fatalf("trigger detail=%s", detail)
	}
	if err := validateWebhookTriggerMode(webhook.ProviderFlareV1, true); err == nil {
		t.Fatal("Flare sync mode permitted")
	}
}
