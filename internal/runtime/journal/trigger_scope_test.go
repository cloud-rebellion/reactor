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

// TestTriggerReadsFenceLegacyCrossTenantRows protects workflow-scoped MCP
// inventory/review reads when a trigger row restored from an older database
// carries a stale tenant marker. New trigger creation derives tenant_id from
// the workflow, but reads must still fail closed for corrupted legacy state.
func TestTriggerReadsFenceLegacyCrossTenantRows(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if err := j.CreateWorkflowInTenant(ctx, "wf_trigger_scope", "trigger-scope", "h", "1", json.RawMessage(`{}`), "tenant-a"); err != nil {
		t.Fatal(err)
	}
	triggerID, err := j.CreateCronTrigger(ctx, "wf_trigger_scope", []byte(`{"spec":"0 9 * * *"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE triggers SET tenant_id = $1 WHERE id = $2`), "tenant-b", triggerID); err != nil {
		t.Fatal(err)
	}
	if err := j.SetTriggerStateForWorkflow(ctx, triggerID, "wf_trigger_scope", "disabled"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mismatched trigger state mutation = %v, want ErrNotFound", err)
	}
	if err := j.UpdateCronTriggerConfigForWorkflow(ctx, triggerID, "wf_trigger_scope", []byte(`{"spec":"* * * * *"}`)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mismatched trigger config mutation = %v, want ErrNotFound", err)
	}
	if err := j.DeleteTriggerForWorkflow(ctx, triggerID, "wf_trigger_scope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mismatched trigger delete = %v, want ErrNotFound", err)
	}

	all, err := j.ListTriggersForWorkflow(ctx, "wf_trigger_scope")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 0 {
		t.Fatalf("unpaged trigger read = %+v, want no mismatched row", all)
	}
	page, more, err := j.ListTriggersForWorkflowPage(ctx, "wf_trigger_scope", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if more || len(page) != 0 {
		t.Fatalf("paged trigger read = %+v more=%v, want no mismatched row", page, more)
	}
	if _, err := j.GetTriggerForWorkflow(ctx, triggerID, "wf_trigger_scope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("single trigger read = %v, want ErrNotFound", err)
	}
}

func TestTriggerCreationIdempotencyReplaysAndRejectsMismatch(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	for _, row := range []struct{ id, slug string }{{"wf_idem_down", "idem-down"}, {"wf_idem_source", "idem-source"}} {
		if err := j.CreateWorkflowInTenant(ctx, row.id, row.slug, "h", "1", json.RawMessage(`{}`), "acme"); err != nil {
			t.Fatal(err)
		}
	}
	cronID, replay, err := j.CreateCronTriggerWithIdempotency(ctx, "wf_idem_down", []byte(`{"spec":"0 9 * * *"}`), "create-1")
	if err != nil || replay {
		t.Fatalf("first cron create = id %q replay %v err %v", cronID, replay, err)
	}
	replayedID, replay, err := j.CreateCronTriggerWithIdempotency(ctx, "wf_idem_down", []byte(`{"spec":"0 9 * * *"}`), "create-1")
	if err != nil || !replay || replayedID != cronID {
		t.Fatalf("cron replay = id %q replay %v err %v", replayedID, replay, err)
	}
	if _, _, err := j.CreateCronTriggerWithIdempotency(ctx, "wf_idem_down", []byte(`{"spec":"30 9 * * *"}`), "create-1"); !errors.Is(err, ErrTriggerIdempotencyConflict) {
		t.Fatalf("cron mismatch = %v, want ErrTriggerIdempotencyConflict", err)
	}
	webhookID, token, replay, err := j.CreateWebhookTriggerWithIdempotency(ctx, "wf_idem_down", "whk_idem", "cred_idem", "generic", []byte(`{}`), "webhook-1")
	if err != nil || replay || webhookID == "" || token != "whk_idem" {
		t.Fatalf("first webhook create = id %q token %q replay %v err %v", webhookID, token, replay, err)
	}
	replayedID, replayedToken, replay, err := j.CreateWebhookTriggerWithIdempotency(ctx, "wf_idem_down", "whk_other", "cred_idem", "generic", []byte(`{}`), "webhook-1")
	if err != nil || !replay || replayedID != webhookID || replayedToken != token {
		t.Fatalf("webhook replay = id %q token %q replay %v err %v", replayedID, replayedToken, replay, err)
	}
	chainID, replay, err := j.CreateChainTriggerWithIdempotency(ctx, "wf_idem_down", "wf_idem_source", "succeeded", "chain-1")
	if err != nil || replay {
		t.Fatalf("first chain create = id %q replay %v err %v", chainID, replay, err)
	}
	replayedID, replay, err = j.CreateChainTriggerWithIdempotency(ctx, "wf_idem_down", "wf_idem_source", "succeeded", "chain-1")
	if err != nil || !replay || replayedID != chainID {
		t.Fatalf("chain replay = id %q replay %v err %v", replayedID, replay, err)
	}
}

func TestScopedTriggerMutationsFenceRevision(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_revision", "revision", "h", "1", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	id, err := j.CreateCronTrigger(ctx, "wf_revision", []byte(`{"spec":"0 9 * * *"}`))
	if err != nil {
		t.Fatal(err)
	}
	trigger, err := j.GetTriggerForWorkflow(ctx, id, "wf_revision")
	if err != nil {
		t.Fatal(err)
	}
	if trigger.Revision != 1 {
		t.Fatalf("initial revision = %d, want 1", trigger.Revision)
	}
	if err := j.UpdateCronTriggerConfigForWorkflowIfRevision(ctx, id, "wf_revision", []byte(`{"spec":"30 9 * * *"}`), trigger.Revision); err != nil {
		t.Fatalf("first fenced update: %v", err)
	}
	if err := j.SetTriggerStateForWorkflowIfRevision(ctx, id, "wf_revision", "disabled", trigger.Revision); !errors.Is(err, ErrTriggerRevisionConflict) {
		t.Fatalf("stale state update = %v, want ErrTriggerRevisionConflict", err)
	}
	current, err := j.GetTriggerForWorkflow(ctx, id, "wf_revision")
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != 2 || current.State != "active" || string(current.Config) != `{"spec":"30 9 * * *"}` {
		t.Fatalf("stale update changed trigger = %+v config=%s", current, current.Config)
	}
	if err := j.DeleteTriggerForWorkflowIfRevision(ctx, id, "wf_revision", current.Revision); err != nil {
		t.Fatalf("current fenced delete: %v", err)
	}
}

func TestScopedWebhookTriggerUpdateFencesRevisionAndPreservesToken(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_webhook_revision", "webhook-revision", "h", "1", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	triggerID, err := j.CreateWebhookTrigger(ctx, "wf_webhook_revision", "whk_stable", "cred_old", "generic", []byte(`{"sync":true}`))
	if err != nil {
		t.Fatal(err)
	}
	before, err := j.GetTriggerForWorkflow(ctx, triggerID, "wf_webhook_revision")
	if err != nil {
		t.Fatal(err)
	}
	if before.Revision != 1 || before.TokenID != "whk_stable" {
		t.Fatalf("initial webhook = %+v", before)
	}
	if err := j.UpdateWebhookTriggerForWorkflowIfRevision(ctx, triggerID, "wf_webhook_revision", "cred_new", "github", []byte(`{"sync":true,"timeout_seconds":30}`), before.Revision); err != nil {
		t.Fatalf("fenced webhook update: %v", err)
	}
	after, err := j.GetTriggerForWorkflow(ctx, triggerID, "wf_webhook_revision")
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != 2 || after.SecretID != "cred_new" || after.Provider != "github" || after.TokenID != before.TokenID || string(after.Config) != `{"sync":true,"timeout_seconds":30}` {
		t.Fatalf("updated webhook = %+v config=%s, want stable token %q", after, after.Config, before.TokenID)
	}
	if err := j.UpdateWebhookTriggerForWorkflowIfRevision(ctx, triggerID, "wf_webhook_revision", "cred_other", "stripe", []byte(`{}`), before.Revision); !errors.Is(err, ErrTriggerRevisionConflict) {
		t.Fatalf("stale webhook update = %v, want ErrTriggerRevisionConflict", err)
	}
	unchanged, err := j.GetTriggerForWorkflow(ctx, triggerID, "wf_webhook_revision")
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Revision != 2 || unchanged.SecretID != "cred_new" || unchanged.TokenID != before.TokenID {
		t.Fatalf("stale webhook update changed row = %+v", unchanged)
	}
	if err := j.UpdateWebhookTriggerForWorkflowIfRevision(ctx, triggerID, "wf_missing", "cred_other", "stripe", []byte(`{}`), after.Revision); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-workflow webhook update = %v, want ErrNotFound", err)
	}
}
