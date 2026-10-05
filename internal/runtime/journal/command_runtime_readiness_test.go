package journal

import (
	"context"
	"testing"
)

func TestHasActiveCommandAutomationTriggerForTenantIsBoundedAndPlanAware(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_readiness", "readiness", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	input := commandScheduleInput(t, "acme", plan, definition, "alice")
	schedule, err := j.CreateCommandAutomationSchedule(ctx, "acme", input)
	if err != nil {
		t.Fatal(err)
	}
	active, err := j.HasActiveCommandAutomationTriggerForTenant(ctx, "acme")
	if err != nil || active {
		t.Fatalf("disabled schedule reported active: active=%v err=%v", active, err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationScheduleStateIfRevision(ctx, "acme", schedule.ID, CommandAutomationScheduleActive, schedule.Revision); err != nil {
		t.Fatal(err)
	}
	active, err = j.HasActiveCommandAutomationTriggerForTenant(ctx, "acme")
	if err != nil || !active {
		t.Fatalf("enabled active schedule not reported: active=%v err=%v", active, err)
	}
	if err := j.SetCommandAutomationScheduleStateIfRevision(ctx, "acme", schedule.ID, CommandAutomationScheduleDisabled, schedule.Revision+1); err != nil {
		t.Fatalf("disable readiness schedule: %v", err)
	}
	commandWebhookCredential(t, j, "cred_cmd_readiness", "acme")
	webhook, err := j.CreateCommandAutomationWebhookTrigger(ctx, "acme", commandWebhookInput(t, "acme", plan, definition, "cred_cmd_readiness", "cmdwhk_readiness"))
	if err != nil {
		t.Fatalf("create readiness webhook: %v", err)
	}
	if err := j.SetCommandAutomationWebhookTriggerStateIfRevision(ctx, "acme", webhook.ID, CommandAutomationWebhookActive, webhook.Revision); err != nil {
		t.Fatalf("activate readiness webhook: %v", err)
	}
	active, err = j.HasActiveCommandAutomationTriggerForTenant(ctx, "acme")
	if err != nil || !active {
		t.Fatalf("enabled active webhook not reported: active=%v err=%v", active, err)
	}
	if err := j.SetCommandAutomationWebhookTriggerStateIfRevision(ctx, "acme", webhook.ID, CommandAutomationWebhookDisabled, webhook.Revision+1); err != nil {
		t.Fatalf("disable readiness webhook: %v", err)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_readiness_chain", "readiness-chain", "h", "0.1.0", []byte(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	chain, err := j.CreateCommandAutomationChainTrigger(ctx, "acme", commandChainInput(t, "acme", plan, definition, "wf_readiness_chain"))
	if err != nil {
		t.Fatalf("create readiness chain: %v", err)
	}
	if err := j.SetCommandAutomationChainTriggerStateIfRevision(ctx, "acme", chain.ID, CommandAutomationChainActive, chain.Revision); err != nil {
		t.Fatalf("activate readiness chain: %v", err)
	}
	active, err = j.HasActiveCommandAutomationTriggerForTenant(ctx, "acme")
	if err != nil || !active {
		t.Fatalf("enabled active chain not reported: active=%v err=%v", active, err)
	}
	foreign, err := j.HasActiveCommandAutomationTriggerForTenant(ctx, "other")
	if err != nil || foreign {
		t.Fatalf("foreign tenant saw active trigger: active=%v err=%v", foreign, err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, false, true, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	active, err = j.HasActiveCommandAutomationTriggerForTenant(ctx, "acme")
	if err != nil || active {
		t.Fatalf("disabled plan with retained active schedule reported runnable: active=%v err=%v", active, err)
	}
}
