package journal

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Activation is normally reached through MCP, which also evaluates the live
// capability and runtime gates. The journal remains the final state authority,
// so a direct caller must not be able to activate a trigger row whose
// immutable definition or receipt identity was tampered with after creation.
func TestCommandAutomationTriggerActivationRechecksImmutableBinding(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_activation_binding", "activation-binding", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}

	// A gate digest change without a matching receipt must not activate a
	// schedule, even though the plan and version remain current.
	scheduleInput := commandScheduleInput(t, "acme", plan, definition, "alice")
	schedule, err := j.CreateCommandAutomationSchedule(ctx, "acme", scheduleInput)
	if err != nil {
		t.Fatal(err)
	}
	wrongGate := strings.Repeat("0", 64)
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE command_automation_schedules SET gate_digest = $1 WHERE id = $2`), wrongGate, schedule.ID); err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationScheduleStateIfRevision(ctx, "acme", schedule.ID, CommandAutomationScheduleActive, schedule.Revision); !errors.Is(err, ErrCommandAutomationScheduleBindingMismatch) {
		t.Fatalf("tampered schedule activation = %v, want binding mismatch", err)
	}

	// A stale immutable-definition digest must likewise close webhook
	// activation before the endpoint can become discoverable by the receiver.
	commandWebhookCredential(t, j, "cred_activation_binding", "acme")
	webhookInput := commandWebhookInput(t, "acme", plan, definition, "cred_activation_binding", "cmdwhk_activation-binding")
	webhook, err := j.CreateCommandAutomationWebhookTrigger(ctx, "acme", webhookInput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE command_automation_webhook_triggers SET definition_sha256 = $1 WHERE id = $2`), wrongGate, webhook.ID); err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationWebhookTriggerStateIfRevision(ctx, "acme", webhook.ID, CommandAutomationWebhookActive, webhook.Revision); !errors.Is(err, ErrCommandAutomationWebhookBindingMismatch) {
		t.Fatalf("tampered webhook activation = %v, want binding mismatch", err)
	}

	if err := j.CreateWorkflowInTenant(ctx, "wf_activation_binding", "activation-binding-source", "hash", "0.1.0", []byte(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	chainInput := commandChainInput(t, "acme", plan, definition, "wf_activation_binding")
	chain, err := j.CreateCommandAutomationChainTrigger(ctx, "acme", chainInput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE command_automation_chain_triggers SET receipt_id = $1 WHERE id = $2`), "cmdpreflight_tampered", chain.ID); err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationChainTriggerStateIfRevision(ctx, "acme", chain.ID, CommandAutomationChainActive, chain.Revision); !errors.Is(err, ErrCommandAutomationChainBindingMismatch) {
		t.Fatalf("tampered chain activation = %v, want binding mismatch", err)
	}
}
