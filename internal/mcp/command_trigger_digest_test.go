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

// These fakes model an imported or repaired trigger row whose binding fields
// are internally self-consistent but no longer match the immutable definition
// in the command-plan version. The real journal rejects such a write; keeping
// the fake at the MCP boundary proves activation itself remains fail-closed if
// a legacy row is already present.
type staleCommandWebhookStore struct {
	*journal.Journal
	row       journal.CommandAutomationWebhookTrigger
	activated bool
}

func (s *staleCommandWebhookStore) GetCommandAutomationWebhookTriggerForTenant(context.Context, string, string) (journal.CommandAutomationWebhookTrigger, error) {
	return s.row, nil
}

func (s *staleCommandWebhookStore) SetCommandAutomationWebhookTriggerStateIfRevision(_ context.Context, _ string, _ string, state string, _ int64) error {
	s.activated = true
	s.row.State = state
	return nil
}

type staleCommandChainStore struct {
	*journal.Journal
	row       journal.CommandAutomationChainTrigger
	activated bool
}

func (s *staleCommandChainStore) GetCommandAutomationChainTriggerForTenant(context.Context, string, string) (journal.CommandAutomationChainTrigger, error) {
	return s.row, nil
}

func (s *staleCommandChainStore) SetCommandAutomationChainTriggerStateIfRevision(_ context.Context, _ string, _ string, state string, _ int64) error {
	s.activated = true
	s.row.State = state
	return nil
}

func readyCommandExecutionCaps(context.Context, commandautomations.Definition) commandautomations.ExecutionCapabilities {
	return commandautomations.ExecutionCapabilities{
		FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true, StepUpAuthorized: true,
		SandboxProfileReady: true, VaultBoundaryReady: true, CredentialsSupported: true,
		OutputLimitsReady: true, AuditReady: true, RunnerReady: true, TargetReady: true,
	}
}

func credentialsForCommandTrigger(id, tenant string) credentials.CreateParams {
	return credentials.CreateParams{ID: id, Name: id, TenantID: tenant, Service: "reactor-webhook", Provider: "shared-secret"}
}

func TestMCPCommandWebhookActivationRejectsStaleDefinitionDigest(t *testing.T) {
	t.Parallel()
	srv, j, creds := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Triggers: true, CommandExecution: true}
	srv.CommandAutomationWebhookRuntimeReady = func(context.Context) bool { return true }
	srv.CommandExecutionCapabilities = readyCommandExecutionCaps
	srv.CommandTargetAllowed = func(context.Context, string) bool { return true }
	ctx := context.Background()
	if err := creds.Create(ctx, credentialsForCommandTrigger("digest-webhook-secret", "acme")); err != nil {
		t.Fatal(err)
	}
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_digest_webhook", "digest-webhook", "", "local", "author", definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	stored, err := j.GetCommandAutomationVersion(ctx, "acme", plan.ID, plan.CurrentVersion)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := decodeStoredCommandDefinition(stored.DefinitionJSON)
	if err != nil {
		t.Fatal(err)
	}
	receipt := commandautomations.EvaluateExecutionGates(parsed, readyCommandExecutionCaps(ctx, parsed))
	digest := commandDefinitionSHA256(stored.DefinitionJSON)
	binding := commandautomations.BindExecutionReceipt("acme", plan.ID, plan.CurrentVersion, digest, receipt)
	token, err := journal.NewCommandAutomationWebhookToken()
	if err != nil {
		t.Fatal(err)
	}
	row, err := j.CreateCommandAutomationWebhookTrigger(ctx, "acme", journal.CommandAutomationWebhookTriggerInput{
		AutomationID: plan.ID, AutomationVersion: plan.CurrentVersion, DefinitionSHA256: digest,
		ReceiptID: binding.ReceiptID, GateDigest: binding.GateDigest, ActorID: "author", TokenID: token,
		SecretID: "digest-webhook-secret", Provider: "generic",
	})
	if err != nil {
		t.Fatal(err)
	}
	staleDigest := strings.Repeat("f", 64)
	if staleDigest == digest {
		t.Fatal("test digest unexpectedly matched immutable definition")
	}
	stale := &staleCommandWebhookStore{Journal: j, row: row}
	stale.row.DefinitionSHA256 = staleDigest
	stale.row.ReceiptID = commandautomations.ReceiptIDForGateDigest("acme", plan.ID, plan.CurrentVersion, staleDigest, binding.GateDigest)
	srv.CommandAutomationWebhooks = stale

	callOperationalTool(t, srv, "reactor_set_command_automation_webhook_state", map[string]any{
		"webhook_id": row.ID, "state": journal.CommandAutomationWebhookActive, "expected_revision": row.Revision,
	}, true)
	if stale.activated {
		t.Fatal("stale webhook binding was activated")
	}
}

func TestMCPCommandChainActivationRejectsStaleDefinitionDigest(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Triggers: true, CommandExecution: true}
	srv.CommandAutomationChainRuntimeReady = func(context.Context) bool { return true }
	srv.CommandExecutionCapabilities = readyCommandExecutionCaps
	srv.CommandTargetAllowed = func(context.Context, string) bool { return true }
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_digest_source", "digest-source", "hash", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_digest_chain", "digest-chain", "", "local", "author", definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	stored, err := j.GetCommandAutomationVersion(ctx, "acme", plan.ID, plan.CurrentVersion)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := decodeStoredCommandDefinition(stored.DefinitionJSON)
	if err != nil {
		t.Fatal(err)
	}
	receipt := commandautomations.EvaluateExecutionGates(parsed, readyCommandExecutionCaps(ctx, parsed))
	digest := commandDefinitionSHA256(stored.DefinitionJSON)
	binding := commandautomations.BindExecutionReceipt("acme", plan.ID, plan.CurrentVersion, digest, receipt)
	row, err := j.CreateCommandAutomationChainTrigger(ctx, "acme", journal.CommandAutomationChainTriggerInput{
		AutomationID: plan.ID, AutomationVersion: plan.CurrentVersion, DefinitionSHA256: digest,
		ReceiptID: binding.ReceiptID, GateDigest: binding.GateDigest, ActorID: "author",
		SourceWorkflowID: "wf_digest_source", OnStatuses: "succeeded",
	})
	if err != nil {
		t.Fatal(err)
	}
	staleDigest := strings.Repeat("e", 64)
	if staleDigest == digest {
		t.Fatal("test digest unexpectedly matched immutable definition")
	}
	stale := &staleCommandChainStore{Journal: j, row: row}
	stale.row.DefinitionSHA256 = staleDigest
	stale.row.ReceiptID = commandautomations.ReceiptIDForGateDigest("acme", plan.ID, plan.CurrentVersion, staleDigest, binding.GateDigest)
	srv.CommandAutomationChains = stale

	callOperationalTool(t, srv, "reactor_set_command_automation_chain_state", map[string]any{
		"chain_id": row.ID, "state": journal.CommandAutomationChainActive, "expected_revision": row.Revision,
	}, true)
	if stale.activated {
		t.Fatal("stale chain binding was activated")
	}
}
