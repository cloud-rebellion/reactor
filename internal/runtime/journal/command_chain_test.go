package journal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/bright-interaction/reactor/internal/commandautomations"
)

func commandChainInput(t *testing.T, tenant string, plan CommandAutomation, definition []byte, source string) CommandAutomationChainTriggerInput {
	t.Helper()
	digest := commandDefinitionDigest(t, definition)
	gate := sha256.Sum256([]byte("chain-gates-" + tenant))
	gateDigest := hex.EncodeToString(gate[:])
	return CommandAutomationChainTriggerInput{
		ID:                "cmdchain_" + tenant,
		AutomationID:      plan.ID,
		AutomationVersion: plan.CurrentVersion,
		DefinitionSHA256:  digest,
		ReceiptID:         commandautomations.ReceiptIDForGateDigest(tenant, plan.ID, plan.CurrentVersion, digest, gateDigest),
		GateDigest:        gateDigest,
		ActorID:           "alice",
		SourceWorkflowID:  source,
		OnStatuses:        "failed, succeeded,failed_dlq",
	}
}

func TestCommandAutomationChainCRUDTenantFenceAndRevision(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_chain_source_acme", "chain-source-acme", "h", "0.1.0", []byte(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_chain_crud", "chain-crud", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	input := commandChainInput(t, "acme", plan, definition, "wf_chain_source_acme")
	created, replay, err := j.CreateCommandAutomationChainTriggerWithIdempotency(ctx, "acme", input, "chain-key")
	if err != nil || replay || created.State != CommandAutomationChainDisabled || created.Revision != 1 || created.OnStatuses != "failed,failed_dlq,succeeded" {
		t.Fatalf("create chain = %+v replay=%v err=%v", created, replay, err)
	}
	replayed, replay, err := j.CreateCommandAutomationChainTriggerWithIdempotency(ctx, "acme", input, "chain-key")
	if err != nil || !replay || replayed.ID != created.ID {
		t.Fatalf("replay chain = %+v replay=%v err=%v", replayed, replay, err)
	}
	changed := input
	changed.OnStatuses = "succeeded"
	if _, replay, err := j.CreateCommandAutomationChainTriggerWithIdempotency(ctx, "acme", changed, "chain-key"); !errors.Is(err, ErrCommandAutomationChainConflict) || replay {
		t.Fatalf("idempotency mismatch = %v replay=%v", err, replay)
	}
	if _, err := j.GetCommandAutomationChainTriggerForTenant(ctx, "other", created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign get = %v, want ErrNotFound", err)
	}
	if err := j.SetCommandAutomationChainTriggerStateIfRevision(ctx, "acme", created.ID, CommandAutomationChainActive, created.Revision); !errors.Is(err, ErrCommandAutomationEnabled) {
		t.Fatalf("activate disabled plan = %v, want plan-state error", err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationChainTriggerStateIfRevision(ctx, "acme", created.ID, CommandAutomationChainActive, created.Revision); err != nil {
		t.Fatalf("activate chain: %v", err)
	}
	active, err := j.GetCommandAutomationChainTriggerForTenant(ctx, "acme", created.ID)
	if err != nil || active.State != CommandAutomationChainActive || active.Revision != 2 {
		t.Fatalf("active chain = %+v err=%v", active, err)
	}
	if err := j.UpdateCommandAutomationChainTriggerIfRevision(ctx, "acme", created.ID, CommandAutomationChainTriggerUpdate{AutomationVersion: plan.CurrentVersion, DefinitionSHA256: input.DefinitionSHA256, ReceiptID: input.ReceiptID, GateDigest: input.GateDigest, ActorID: "bob", OnStatuses: "succeeded"}, active.Revision); !errors.Is(err, ErrCommandAutomationChainActive) {
		t.Fatalf("update active chain = %v, want active fence", err)
	}
	if err := j.SetCommandAutomationChainTriggerStateIfRevision(ctx, "acme", created.ID, CommandAutomationChainDisabled, active.Revision); err != nil {
		t.Fatalf("disable chain: %v", err)
	}
	disabled, err := j.GetCommandAutomationChainTriggerForTenant(ctx, "acme", created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.DeleteCommandAutomationChainTriggerIfRevision(ctx, "other", created.ID, disabled.Revision); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign delete = %v, want ErrNotFound", err)
	}
	if err := j.DeleteCommandAutomationChainTriggerIfRevision(ctx, "acme", created.ID, disabled.Revision); err != nil {
		t.Fatalf("delete chain: %v", err)
	}
}

func TestCommandAutomationChainSourceTenantAndStatusFence(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_chain_source_foreign", "chain-source-foreign", "h", "0.1.0", []byte(`{}`), "other"); err != nil {
		t.Fatal(err)
	}
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_chain_fence", "chain-fence", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	input := commandChainInput(t, "acme", plan, definition, "wf_chain_source_foreign")
	if _, _, err := j.CreateCommandAutomationChainTriggerWithIdempotency(ctx, "acme", input, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign source accepted as %v", err)
	}
	input.SourceWorkflowID = "wf_1"
	input.OnStatuses = "cancelled"
	if _, _, err := j.CreateCommandAutomationChainTriggerWithIdempotency(ctx, "acme", input, ""); err == nil {
		t.Fatal("unsupported cancellation status accepted")
	}
}

func TestCommandAutomationChainInventoryOmitsForeignJoinedRows(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_chain_inventory_foreign", "chain-inventory-foreign", "h", "0.1.0", []byte(`{}`), "other"); err != nil {
		t.Fatal(err)
	}
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_chain_inventory", "chain-inventory", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	digest := commandDefinitionDigest(t, definition)
	gate := sha256.Sum256([]byte("inventory-gates"))
	gateDigest := hex.EncodeToString(gate[:])
	// Simulate an imported row whose foreign source survived because the
	// database schema's single-column foreign key does not encode tenant
	// ownership. Every inventory/read projection must repeat that relation
	// fence instead of trusting c.tenant_id alone.
	_, err = j.db.ExecContext(ctx, j.bind(`INSERT INTO command_automation_chain_triggers
		(id, tenant_id, automation_id, automation_version, definition_sha256, receipt_id, gate_digest, actor_id, source_workflow_id, on_statuses, state, revision)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`),
		"cmdchain_inventory_foreign", "acme", plan.ID, plan.CurrentVersion, digest,
		commandautomations.ReceiptIDForGateDigest("acme", plan.ID, plan.CurrentVersion, digest, gateDigest), gateDigest,
		"alice", "wf_chain_inventory_foreign", "succeeded", CommandAutomationChainDisabled, 1)
	if err != nil {
		t.Fatal(err)
	}
	rows, more, err := j.ListCommandAutomationChainTriggersForTenantPage(ctx, CommandAutomationChainTriggerFilter{TenantID: "acme", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if more || len(rows) != 0 {
		t.Fatalf("foreign chain row exposed in tenant inventory: rows=%+v more=%v", rows, more)
	}
	if _, err := j.GetCommandAutomationChainTriggerForTenant(ctx, "acme", "cmdchain_inventory_foreign"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign chain get = %v, want ErrNotFound", err)
	}
}

func TestCommandAutomationChainEventIDDeterministicAndDistinct(t *testing.T) {
	first := CommandAutomationChainEventID("chain-1", "run-1", "succeeded")
	if first == "" || first != CommandAutomationChainEventID("chain-1", "run-1", "succeeded") {
		t.Fatalf("event id is not deterministic: %q", first)
	}
	if first == CommandAutomationChainEventID("chain-1", "run-2", "succeeded") || first == CommandAutomationChainEventID("chain-1", "run-1", "failed") {
		t.Fatalf("event ids are not source/status bound: %q", first)
	}
}

func TestCommandAutomationChainAdmissionFenceRejectsDisabledTrigger(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_chain_run_fence", "chain-run-fence", "h", "0.1.0", []byte(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_chain_run_fence", "chain-run-fence", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	input := commandChainInput(t, "acme", plan, definition, "wf_chain_run_fence")
	trigger, err := j.CreateCommandAutomationChainTrigger(ctx, "acme", input)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationChainTriggerStateIfRevision(ctx, "acme", trigger.ID, CommandAutomationChainActive, trigger.Revision); err != nil {
		t.Fatal(err)
	}
	admission := CommandRunAdmission{
		ReceiptID: input.ReceiptID, GateDigest: input.GateDigest, DefinitionSHA256: input.DefinitionSHA256,
		ActorID: input.ActorID, TriggerKind: CommandRunTriggerChain, TriggerID: trigger.ID, TriggerEventID: CommandAutomationChainEventID(trigger.ID, "source-run-1", "succeeded"),
	}
	if _, err := j.CreateCommandRun(ctx, "acme", "cmdrun_chain_fence_1", plan.ID, plan.CurrentVersion, admission); err != nil {
		t.Fatalf("active chain admission: %v", err)
	}
	active, err := j.GetCommandAutomationChainTriggerForTenant(ctx, "acme", trigger.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationChainTriggerStateIfRevision(ctx, "acme", trigger.ID, CommandAutomationChainDisabled, active.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := j.CreateCommandRun(ctx, "acme", "cmdrun_chain_fence_2", plan.ID, plan.CurrentVersion, admission); !errors.Is(err, ErrCommandRunBindingMismatch) {
		t.Fatalf("disabled chain admission = %v, want binding mismatch", err)
	}
}
