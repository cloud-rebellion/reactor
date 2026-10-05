package graph

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	_ "modernc.org/sqlite"
)

func TestBuilderIncludesTenantScopedCommandAutomationsAndCredentialEdges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "graph.db")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(ctx, log, "sqlite://"+dbPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j := journal.New(db, journal.EngineSQLite)
	if _, err := db.ExecContext(ctx, `INSERT INTO credentials (id, tenant_id, name, service, blob) VALUES ('cred_acme', 'acme', 'acme-key', 'test', 'opaque')`); err != nil {
		t.Fatal(err)
	}
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0,"credential_ids":["cred_acme"]}]}`)
	if _, err := j.CreateCommandAutomation(ctx, "acme", "cmd_acme", "nightly-check", "Check host", "ops-host", "alice", definition); err != nil {
		t.Fatal(err)
	}
	if _, err := j.CreateCommandAutomation(ctx, "other", "cmd_other", "nightly-check", "Other host", "ops-host", "bob", definition); err != nil {
		t.Fatal(err)
	}

	g, err := (&Builder{Journal: j, Credentials: credentials.New(db, credentials.EngineSQLite)}).Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if node, ok := g.Get("command-automation:acme:nightly-check"); !ok || node.Attrs["executable"] != false {
		t.Fatalf("acme command node = %#v, found=%v", node, ok)
	}
	if _, ok := g.Get("command-automation:other:nightly-check"); !ok {
		t.Fatal("other tenant command node missing from global graph")
	}
	edges := g.Outbound("command-automation:acme:nightly-check", EdgeUses)
	if len(edges) != 1 || edges[0].To != "credential:cred_acme" || edges[0].Attrs["step"] != "check" {
		t.Fatalf("command credential edges = %#v", edges)
	}
	otherEdges := g.Outbound("command-automation:other:nightly-check", EdgeUses)
	if len(otherEdges) != 0 {
		t.Fatalf("cross-tenant command credential edges = %#v", otherEdges)
	}
	sub := g.QueryForTenant("nightly-check", "acme", 10)
	for _, node := range sub.Nodes {
		if tenant, ok := node.Attrs["tenant_id"].(string); ok && tenant == "other" {
			t.Fatalf("tenant-scoped graph leaked other command node: %#v", sub.Nodes)
		}
	}
}

func TestBuilderIncludesCommandWebhookAndChainFlowsWithoutSecrets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "graph-command-triggers.db")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(ctx, log, "sqlite://"+dbPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j := journal.New(db, journal.EngineSQLite)

	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0}]}`)
	workflowID := "wf_graph_command_source"
	if err := j.CreateWorkflowInTenant(ctx, workflowID, "graph-command-source", "hash", "0.1.0", json.RawMessage(`{"steps":[]}`), "acme"); err != nil {
		t.Fatal(err)
	}
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_graph_triggers", "graph-trigger-plan", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO credentials (id, tenant_id, name, service, blob) VALUES ('cred_graph_webhook', 'acme', 'webhook-secret', 'test', 'opaque')`); err != nil {
		t.Fatal(err)
	}
	_, normalized, err := commandautomations.Normalize(definition)
	if err != nil {
		t.Fatal(err)
	}
	digestBytes := sha256.Sum256(normalized)
	digest := hex.EncodeToString(digestBytes[:])
	gateBytes := sha256.Sum256([]byte("graph-trigger-gates"))
	gate := hex.EncodeToString(gateBytes[:])
	receipt := commandautomations.ReceiptIDForGateDigest("acme", plan.ID, plan.CurrentVersion, digest, gate)
	webhook, err := j.CreateCommandAutomationWebhookTrigger(ctx, "acme", journal.CommandAutomationWebhookTriggerInput{
		ID: "cmdwhk_graph", AutomationID: plan.ID, AutomationVersion: plan.CurrentVersion,
		DefinitionSHA256: digest, ReceiptID: receipt, GateDigest: gate, ActorID: "alice",
		TokenID: "cmdwhk_secret-token", SecretID: "cred_graph_webhook", Provider: "hash-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := j.CreateCommandAutomationChainTrigger(ctx, "acme", journal.CommandAutomationChainTriggerInput{
		ID: "cmdchain_graph", AutomationID: plan.ID, AutomationVersion: plan.CurrentVersion,
		DefinitionSHA256: digest, ReceiptID: receipt, GateDigest: gate, ActorID: "alice",
		SourceWorkflowID: workflowID, OnStatuses: "succeeded,failed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.MarkCommandAutomationWebhookError(ctx, "acme", webhook.ID, "Authorization: Bearer should-not-render"); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkCommandAutomationChainTriggerError(ctx, "acme", chain.ID, "request body should-not-render"); err != nil {
		t.Fatal(err)
	}

	graph, err := (&Builder{Journal: j}).Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	planNodeID := "command-automation:acme:graph-trigger-plan"
	webhookNodeID := "command-webhook:acme:" + webhook.ID
	chainNodeID := "command-chain:acme:" + chain.ID
	webhookNode, ok := graph.Get(webhookNodeID)
	if !ok || webhookNode.Kind != KindCommandWebhook {
		t.Fatalf("webhook graph node = %#v, found=%v", webhookNode, ok)
	}
	for _, secretField := range []string{"token_id", "secret_id", "last_error"} {
		if _, leaked := webhookNode.Attrs[secretField]; leaked {
			t.Fatalf("webhook graph exposed %s: %#v", secretField, webhookNode.Attrs)
		}
	}
	if webhookNode.Attrs["last_error_present"] != true || webhookNode.Attrs["last_error_trust"] != "redacted" {
		t.Fatalf("webhook error trust metadata = %#v", webhookNode.Attrs)
	}
	webhookEdges := graph.Outbound(webhookNodeID, EdgeFires)
	if len(webhookEdges) != 1 || webhookEdges[0].To != planNodeID {
		t.Fatalf("webhook plan edges = %#v", webhookEdges)
	}

	chainNode, ok := graph.Get(chainNodeID)
	if !ok || chainNode.Kind != KindCommandChain {
		t.Fatalf("chain graph node = %#v, found=%v", chainNode, ok)
	}
	for _, secretField := range []string{"last_error", "receipt_id", "gate_digest", "actor_id"} {
		if _, leaked := chainNode.Attrs[secretField]; leaked {
			t.Fatalf("chain graph exposed %s: %#v", secretField, chainNode.Attrs)
		}
	}
	if chainNode.Attrs["last_error_present"] != true || chainNode.Attrs["last_error_trust"] != "redacted" {
		t.Fatalf("chain error trust metadata = %#v", chainNode.Attrs)
	}
	chainPlanEdges := graph.Outbound(chainNodeID, EdgeFires)
	if len(chainPlanEdges) != 1 || chainPlanEdges[0].To != planNodeID {
		t.Fatalf("chain plan edges = %#v", chainPlanEdges)
	}
	chainSourceEdges := graph.Outbound(chainNodeID, EdgeOnTerminal)
	if len(chainSourceEdges) != 1 || chainSourceEdges[0].To != "workflow:acme:graph-command-source" {
		t.Fatalf("chain source edges = %#v", chainSourceEdges)
	}

	// The graph is global, but the MCP tenant lens must hide the same trigger
	// metadata when it belongs to a different tenant. This also exercises the
	// tenant marker on the new node kinds.
	otherWorkflowID := "wf_graph_command_other"
	if err := j.CreateWorkflowInTenant(ctx, otherWorkflowID, "graph-command-other", "hash", "0.1.0", json.RawMessage(`{"steps":[]}`), "other"); err != nil {
		t.Fatal(err)
	}
	otherPlan, err := j.CreateCommandAutomation(ctx, "other", "cmd_graph_triggers_other", "graph-trigger-plan", "", "local", "bob", definition)
	if err != nil {
		t.Fatal(err)
	}
	otherGateBytes := sha256.Sum256([]byte("graph-trigger-gates-other"))
	otherGate := hex.EncodeToString(otherGateBytes[:])
	otherReceipt := commandautomations.ReceiptIDForGateDigest("other", otherPlan.ID, otherPlan.CurrentVersion, digest, otherGate)
	otherChain, err := j.CreateCommandAutomationChainTrigger(ctx, "other", journal.CommandAutomationChainTriggerInput{
		ID: "cmdchain_graph_other", AutomationID: otherPlan.ID, AutomationVersion: otherPlan.CurrentVersion,
		DefinitionSHA256: digest, ReceiptID: otherReceipt, GateDigest: otherGate, ActorID: "bob",
		SourceWorkflowID: otherWorkflowID, OnStatuses: "succeeded",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.MarkCommandAutomationChainTriggerError(ctx, "other", otherChain.ID, "other tenant diagnostic"); err != nil {
		t.Fatal(err)
	}
	graph, err = (&Builder{Journal: j}).Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := graph.Get("command-chain:other:" + otherChain.ID); !ok {
		t.Fatal("other-tenant command chain missing from global graph")
	}
	sub := graph.QueryForTenant("graph-trigger-plan", "acme", 20)
	for _, node := range sub.Nodes {
		if tenant, ok := node.Attrs["tenant_id"].(string); ok && tenant == "other" {
			t.Fatalf("tenant-scoped graph leaked other command trigger: %#v", node)
		}
	}
}

func TestBuilderSkipsCredentialEdgesForMalformedCommandDefinition(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "graph.db")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(ctx, log, "sqlite://"+dbPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j := journal.New(db, journal.EngineSQLite)
	// Bypass the writer validator to model an imported/legacy row. The graph
	// builder must not infer credential relationships from a definition that
	// the authoring contract would reject.
	if _, err := db.ExecContext(ctx, `INSERT INTO command_automations (id, tenant_id, name, current_version) VALUES ('cmd_legacy', 'acme', 'legacy-plan', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO command_automation_versions (automation_id, version, definition_json) VALUES ('cmd_legacy', 1, $1)`,
		`{"steps":[{"name":"bad","command":"true","purpose":"Bad","timeout_seconds":0,"expected_exit_code":0,"credential_ids":["cred_should_not_be_linked"]}]}`); err != nil {
		t.Fatal(err)
	}

	g, err := (&Builder{Journal: j}).Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if edges := g.Outbound("command-automation:acme:legacy-plan", EdgeUses); len(edges) != 0 {
		t.Fatalf("malformed command definition produced credential edges: %#v", edges)
	}
}

func TestBuilderSkipsCrossTenantLegacyGrantEdges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "graph.db")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(ctx, log, "sqlite://"+dbPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j := journal.New(db, journal.EngineSQLite)
	if err := j.CreateWorkflowInTenant(ctx, "wf_acme", "acme-flow", "hash", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO credentials (id, tenant_id, name, service, blob) VALUES ('cred_other', 'other', 'other-key', 'test', 'opaque')`); err != nil {
		t.Fatal(err)
	}
	// Model a legacy/manual row that predates the cross-tenant GrantSecret
	// guard. The graph must fail closed even though the row is still durable.
	if _, err := db.ExecContext(ctx, `INSERT INTO workflow_secret_grants (workflow_id, credential_id, granted_by, note) VALUES ('wf_acme', 'cred_other', 'legacy', 'unsafe')`); err != nil {
		t.Fatal(err)
	}

	g, err := (&Builder{Journal: j, Credentials: credentials.New(db, credentials.EngineSQLite)}).Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if edges := g.Outbound("workflow:acme:acme-flow", EdgeUses); len(edges) != 0 {
		t.Fatalf("cross-tenant legacy grant edge = %#v", edges)
	}
}

func TestBuilderWorkflowEnabledStateIsVisible(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "graph.db")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(ctx, log, "sqlite://"+dbPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j := journal.New(db, journal.EngineSQLite)
	if err := j.CreateWorkflowInTenantDisabled(ctx, "wf_enabled", "enabled-flow", "h", "0.1.0", json.RawMessage(`{"steps":[]}`), "acme"); err != nil {
		t.Fatal(err)
	}

	g, err := (&Builder{Journal: j}).Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	node, ok := g.Get("workflow:acme:enabled-flow")
	if !ok {
		t.Fatal("workflow node missing from graph")
	}
	if enabled, ok := node.Attrs["enabled"].(bool); !ok || enabled {
		t.Fatalf("initial workflow enabled attr = %#v, want false", node.Attrs["enabled"])
	}

	if err := j.SetWorkflowEnabled(ctx, "wf_enabled", true); err != nil {
		t.Fatal(err)
	}
	g, err = (&Builder{Journal: j}).Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	node, ok = g.Get("workflow:acme:enabled-flow")
	if !ok {
		t.Fatal("workflow node missing after state update")
	}
	if enabled, ok := node.Attrs["enabled"].(bool); !ok || !enabled {
		t.Fatalf("updated workflow enabled attr = %#v, want true", node.Attrs["enabled"])
	}
}

func TestBuilderPaginatesEstateWideJournalInventories(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "graph.db")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(ctx, log, "sqlite://"+dbPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j := journal.New(db, journal.EngineSQLite)

	for i := 0; i < 3; i++ {
		workflowID := fmt.Sprintf("wf_page_%d", i)
		tenantID := fmt.Sprintf("tenant-page-%d", i)
		slug := fmt.Sprintf("paged-flow-%d", i)
		if err := j.CreateWorkflowInTenant(ctx, workflowID, slug, "h", "0.1.0", json.RawMessage(`{}`), tenantID); err != nil {
			t.Fatal(err)
		}
		if _, err := j.CreateCronTrigger(ctx, workflowID, []byte(`{"spec":"@hourly"}`)); err != nil {
			t.Fatal(err)
		}
		credentialID := fmt.Sprintf("cred_page_%d", i)
		if _, err := db.ExecContext(ctx, `INSERT INTO credentials (id, tenant_id, name, service, blob) VALUES ($1,$2,$3,$4,$5)`, credentialID, tenantID, credentialID, "test", []byte("opaque")); err != nil {
			t.Fatal(err)
		}
		if err := j.GrantSecret(ctx, workflowID, credentialID, "test", ""); err != nil {
			t.Fatal(err)
		}
	}

	g, err := (&Builder{Journal: j, JournalPageSize: 1}).Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		tenantID := fmt.Sprintf("tenant-page-%d", i)
		slug := fmt.Sprintf("paged-flow-%d", i)
		workflowNode := "workflow:" + tenantID + ":" + slug
		node, ok := g.Get(workflowNode)
		if !ok {
			t.Fatalf("workflow page %d missing from graph", i)
		}
		if node.Attrs["tenant_id"] != tenantID {
			t.Fatalf("workflow page %d tenant = %#v, want %q", i, node.Attrs["tenant_id"], tenantID)
		}
		if edges := g.Outbound(workflowNode, EdgeUses); len(edges) != 1 || edges[0].To != "credential:cred_page_"+fmt.Sprint(i) {
			t.Fatalf("workflow page %d grant edges = %#v", i, edges)
		}
		triggers := g.Inbound(workflowNode, EdgeFires)
		if len(triggers) != 1 {
			t.Fatalf("workflow page %d trigger edges = %#v", i, triggers)
		}
	}
}
