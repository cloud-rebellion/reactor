package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestDocumentationOnlyServerDoesNotAdvertiseJournalResources(t *testing.T) {
	t.Parallel()
	s := &Server{}

	resources, ok := s.listResources()["resources"].([]map[string]any)
	if !ok || len(resources) != 1 || resources[0]["uri"] != "reactor://documentation/mcp" {
		t.Fatalf("resources = %#v, want documentation only", resources)
	}
	templates, ok := s.listResourceTemplates()["resourceTemplates"].([]map[string]any)
	if !ok || len(templates) != 1 || templates[0]["uriTemplate"] != "reactor://documentation/{page}" {
		t.Fatalf("resource templates = %#v, want documentation only", templates)
	}

	for _, uri := range []string{"reactor://workflows", "reactor://command-automations"} {
		if _, err := s.readResource(context.Background(), uri); err == nil {
			t.Fatalf("readResource(%q) succeeded without a journal", uri)
		}
	}
}

func TestMCPResourcesReadRejectsUnknownEnvelopeFields(t *testing.T) {
	t.Parallel()
	s := &Server{}
	for _, raw := range []string{
		`{"uri":"reactor://documentation/mcp","unexpected":true}`,
		`{"uri":"reactor://documentation/mcp","uri":"reactor://documentation/mcp"}`,
	} {
		if _, err := s.handle(context.Background(), "resources/read", json.RawMessage(raw)); !errors.Is(err, errInvalidParamsErr) {
			t.Fatalf("resources/read %s error = %v, want invalid params", raw, err)
		}
	}
	if _, err := s.handle(context.Background(), "resources/read", json.RawMessage(`{"uri":"reactor://documentation/mcp","_meta":{"trace":"test"}}`)); err != nil {
		t.Fatalf("standard _meta rejected: %v", err)
	}
}

func TestInventoryResourcesSupportBoundedContinuationURIs(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, false)
	s.TenantID = "acme"
	for i, slug := range []string{"inventory-first", "inventory-second"} {
		if err := j.CreateWorkflowInTenant(context.Background(), "wf_inventory_"+string(rune('a'+i)), slug, "hash", "0.1.0", []byte(`{}`), "acme"); err != nil {
			t.Fatal(err)
		}
	}
	resource, err := s.readResource(context.Background(), "reactor://workflows?limit=1&offset=0")
	if err != nil {
		t.Fatalf("first inventory page: %v", err)
	}
	contents, ok := resource["contents"].([]map[string]any)
	if !ok || len(contents) != 1 {
		t.Fatalf("resource contents = %#v", resource["contents"])
	}
	var payload struct {
		Workflows []any  `json:"workflows"`
		Limit     int    `json:"limit"`
		Offset    int    `json:"offset"`
		HasMore   bool   `json:"has_more"`
		NextURI   string `json:"next_uri"`
	}
	if err := json.Unmarshal([]byte(contents[0]["text"].(string)), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Workflows) != 1 || payload.Limit != 1 || payload.Offset != 0 || !payload.HasMore || payload.NextURI != "reactor://workflows?limit=1&offset=1" {
		t.Fatalf("inventory continuation payload = %+v", payload)
	}
	second, err := s.readResource(context.Background(), payload.NextURI)
	if err != nil {
		t.Fatalf("continuation inventory page: %v", err)
	}
	if len(second["contents"].([]map[string]any)) != 1 {
		t.Fatalf("continuation contents = %#v", second)
	}

	for _, uri := range []string{
		"reactor://workflows?limit=0",
		"reactor://workflows?limit=1&limit=2",
		"reactor://workflows?unknown=1",
		"reactor://workflows/inventory-first/flow?limit=1",
		"reactor://documentation/mcp?limit=1",
	} {
		if _, err := s.readResource(context.Background(), uri); err == nil || !strings.Contains(err.Error(), "invalid params") {
			t.Fatalf("readResource(%q) error = %v, want invalid params", uri, err)
		}
	}
}

func TestCommandAutomationInventoryIncludesTenantFencedTriggerMetadata(t *testing.T) {
	t.Parallel()
	srv, j, creds := newTestServer(t, false)
	srv.TenantID = "acme"
	ctx := context.Background()
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	gateDigest := strings.Repeat("a", 64)

	createPlanAndBindings := func(tenant, suffix string) (journal.CommandAutomation, string, string, string) {
		t.Helper()
		plan, err := j.CreateCommandAutomation(ctx, tenant, "cmd_resource_"+suffix, "resource-"+suffix, "", "local", "resource-test", definition)
		if err != nil {
			t.Fatal(err)
		}
		digest := commandDefinitionSHA256(definition)
		receipt := commandautomations.ReceiptIDForGateDigest(tenant, plan.ID, plan.CurrentVersion, digest, gateDigest)
		if _, err := j.CreateCommandAutomationSchedule(ctx, tenant, journal.CommandAutomationScheduleInput{
			ID: "cmdsched_resource_" + suffix, AutomationID: plan.ID, AutomationVersion: plan.CurrentVersion,
			DefinitionSHA256: digest, ReceiptID: receipt, GateDigest: gateDigest, ActorID: "resource-test", Spec: "0 9 * * *", Timezone: "UTC",
		}); err != nil {
			t.Fatal(err)
		}
		credentialID := "cred_resource_" + suffix
		if err := creds.Create(ctx, credentials.CreateParams{ID: credentialID, Name: credentialID, TenantID: tenant, Service: "reactor-webhook", Provider: "shared-secret"}); err != nil {
			t.Fatal(err)
		}
		if _, err := j.CreateCommandAutomationWebhookTrigger(ctx, tenant, journal.CommandAutomationWebhookTriggerInput{
			ID: "cmdwhk_resource_" + suffix, AutomationID: plan.ID, AutomationVersion: plan.CurrentVersion,
			DefinitionSHA256: digest, ReceiptID: receipt, GateDigest: gateDigest, ActorID: "resource-test",
			TokenID: "cmdwhk_token_resource_" + suffix, SecretID: credentialID, Provider: "generic",
		}); err != nil {
			t.Fatal(err)
		}
		workflowID := "wf_resource_" + suffix
		if err := j.CreateWorkflowInTenant(ctx, workflowID, "resource-source-"+suffix, "hash", "0.1.0", json.RawMessage(`{}`), tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := j.CreateCommandAutomationChainTrigger(ctx, tenant, journal.CommandAutomationChainTriggerInput{
			ID: "cmdchain_resource_" + suffix, AutomationID: plan.ID, AutomationVersion: plan.CurrentVersion,
			DefinitionSHA256: digest, ReceiptID: receipt, GateDigest: gateDigest, ActorID: "resource-test",
			SourceWorkflowID: workflowID, OnStatuses: "succeeded",
		}); err != nil {
			t.Fatal(err)
		}
		return plan, credentialID, "cmdwhk_token_resource_" + suffix, workflowID
	}

	acmePlan, acmeCredential, acmeToken, _ := createPlanAndBindings("acme", "acme")
	_, foreignCredential, foreignToken, _ := createPlanAndBindings("other", "foreign")
	resource, err := srv.readResource(ctx, "reactor://command-automations?limit=1&offset=0")
	if err != nil {
		t.Fatalf("command automation inventory: %v", err)
	}
	contents, ok := resource["contents"].([]map[string]any)
	if !ok || len(contents) != 1 {
		t.Fatalf("resource contents = %#v", resource["contents"])
	}
	raw := contents[0]["text"].(string)
	var payload struct {
		Plans     []map[string]any `json:"command_automations"`
		Schedules []map[string]any `json:"command_automation_schedules"`
		Webhooks  []map[string]any `json:"command_automation_webhooks"`
		Chains    []map[string]any `json:"command_automation_chains"`
		HasMore   bool             `json:"has_more"`
		NextURI   string           `json:"next_uri"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("decode command inventory: %v", err)
	}
	if len(payload.Plans) != 1 || payload.Plans[0]["id"] != acmePlan.ID || len(payload.Schedules) != 1 || len(payload.Webhooks) != 1 || len(payload.Chains) != 1 {
		t.Fatalf("command inventory omitted trigger classes or tenant fence: %s", raw)
	}
	if payload.HasMore || payload.NextURI != "" {
		t.Fatalf("command inventory continuation = has_more=%v next_uri=%q", payload.HasMore, payload.NextURI)
	}
	for _, secret := range []string{acmeCredential, foreignCredential, acmeToken, foreignToken} {
		if strings.Contains(raw, secret) {
			t.Fatalf("command inventory leaked write-only trigger secret %q: %s", secret, raw)
		}
	}
	if strings.Contains(raw, "cmd_resource_foreign") || strings.Contains(raw, "cmdsched_resource_foreign") || strings.Contains(raw, "cmdwhk_resource_foreign") || strings.Contains(raw, "cmdchain_resource_foreign") {
		t.Fatalf("command inventory leaked foreign tenant metadata: %s", raw)
	}
}
