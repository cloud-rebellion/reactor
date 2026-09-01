package journal

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestScopedTriggerMutationsBindWorkflowAndKind(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if err := j.CreateWorkflowInTenant(ctx, "wf_acme_shared", "shared", "h", "1", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_globex_shared", "shared", "h", "1", json.RawMessage(`{}`), "globex"); err != nil {
		t.Fatal(err)
	}
	acmeCron, err := j.CreateCronTrigger(ctx, "wf_acme_shared", []byte(`{"spec":"0 9 * * *"}`))
	if err != nil {
		t.Fatal(err)
	}
	globexCron, err := j.CreateCronTrigger(ctx, "wf_globex_shared", []byte(`{"spec":"0 10 * * *"}`))
	if err != nil {
		t.Fatal(err)
	}
	acmeWebhook, err := j.CreateWebhookTrigger(ctx, "wf_acme_shared", "whk_acme_scope", "cred_acme_scope", "generic", []byte(`{"created_by":"test"}`))
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func() error{
		"state": func() error {
			return j.SetTriggerStateForWorkflow(ctx, globexCron, "wf_acme_shared", "disabled")
		},
		"config": func() error {
			return j.UpdateCronTriggerConfigForWorkflow(ctx, globexCron, "wf_acme_shared", []byte(`{"spec":"* * * * *"}`))
		},
		"delete": func() error {
			return j.DeleteTriggerForWorkflow(ctx, globexCron, "wf_acme_shared")
		},
	} {
		if err := mutate(); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-workflow %s = %v, want ErrNotFound", name, err)
		}
	}
	if err := j.UpdateCronTriggerConfigForWorkflow(ctx, acmeWebhook, "wf_acme_shared", []byte(`{"spec":"* * * * *"}`)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("webhook cron edit = %v, want ErrNotFound", err)
	}

	globexTriggers, err := j.ListTriggersForWorkflow(ctx, "wf_globex_shared")
	if err != nil || len(globexTriggers) != 1 {
		t.Fatalf("globex triggers = %+v, %v", globexTriggers, err)
	}
	if globexTriggers[0].State != "active" || string(globexTriggers[0].Config) != `{"spec":"0 10 * * *"}` {
		t.Fatalf("cross-workflow mutation changed trigger: %+v", globexTriggers[0])
	}

	if err := j.SetTriggerStateForWorkflow(ctx, acmeCron, "wf_acme_shared", "disabled"); err != nil {
		t.Fatalf("same-workflow state: %v", err)
	}
	if err := j.UpdateCronTriggerConfigForWorkflow(ctx, acmeCron, "wf_acme_shared", []byte(`{"spec":"30 9 * * *"}`)); err != nil {
		t.Fatalf("same-workflow config: %v", err)
	}
	if err := j.DeleteTriggerForWorkflow(ctx, acmeCron, "wf_acme_shared"); err != nil {
		t.Fatalf("same-workflow delete: %v", err)
	}
	acmeTriggers, err := j.ListTriggersForWorkflow(ctx, "wf_acme_shared")
	if err != nil || len(acmeTriggers) != 1 || acmeTriggers[0].ID != acmeWebhook {
		t.Fatalf("acme triggers after scoped mutations = %+v, %v", acmeTriggers, err)
	}
}
