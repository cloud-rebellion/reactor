package journal

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/bright-interaction/reactor/internal/commandautomations"
)

func commandWebhookInput(t *testing.T, tenant string, plan CommandAutomation, definition []byte, secret, token string) CommandAutomationWebhookTriggerInput {
	t.Helper()
	digest := commandDefinitionDigest(t, definition)
	gate := sha256.Sum256([]byte("webhook-gates-" + tenant))
	gateDigest := hex.EncodeToString(gate[:])
	return CommandAutomationWebhookTriggerInput{
		ID: "cmdwhk_" + tenant, AutomationID: plan.ID, AutomationVersion: plan.CurrentVersion,
		DefinitionSHA256: digest,
		ReceiptID:        commandautomations.ReceiptIDForGateDigest(tenant, plan.ID, plan.CurrentVersion, digest, gateDigest),
		GateDigest:       gateDigest, ActorID: "alice", TokenID: token, SecretID: secret, Provider: "generic",
	}
}

func commandWebhookCredential(t *testing.T, j *Journal, id, tenant string) {
	t.Helper()
	_, err := j.db.ExecContext(context.Background(), j.bind(`INSERT INTO credentials (id, tenant_id, name, service, provider, blob) VALUES ($1,$2,$3,$4,$5,$6)`), id, tenant, id, "reactor-webhook", "shared-secret", []byte("command-webhook-test-secret"))
	if err != nil {
		t.Fatalf("insert webhook credential: %v", err)
	}
}

func TestCommandAutomationWebhookCRUDAndTenantFence(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_webhook_crud", "webhook-crud", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	commandWebhookCredential(t, j, "cred_cmd_webhook", "acme")
	input := commandWebhookInput(t, "acme", plan, definition, "cred_cmd_webhook", "cmdwhk_token-1")
	created, replay, err := j.CreateCommandAutomationWebhookTriggerWithIdempotency(ctx, "acme", input, "webhook-key")
	if err != nil || replay || created.State != CommandAutomationWebhookDisabled || created.Revision != 1 {
		t.Fatalf("create webhook = %+v replay=%v err=%v", created, replay, err)
	}
	replayedInput := input
	replayedInput.TokenID = "cmdwhk_token-2"
	replayed, replay, err := j.CreateCommandAutomationWebhookTriggerWithIdempotency(ctx, "acme", replayedInput, "webhook-key")
	if err != nil || !replay || replayed.TokenID != input.TokenID {
		t.Fatalf("replay webhook = %+v replay=%v err=%v", replayed, replay, err)
	}
	changed := input
	changed.Provider = "stripe"
	if _, replay, err := j.CreateCommandAutomationWebhookTriggerWithIdempotency(ctx, "acme", changed, "webhook-key"); !errors.Is(err, ErrCommandAutomationWebhookConflict) || replay {
		t.Fatalf("idempotency mismatch = %v replay=%v", err, replay)
	}
	if _, err := j.GetCommandAutomationWebhookTriggerForTenant(ctx, "other", created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign get = %v, want ErrNotFound", err)
	}
	if _, err := j.FindActiveCommandAutomationWebhookByToken(ctx, input.TokenID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled token lookup = %v, want ErrNotFound", err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationWebhookTriggerStateIfRevision(ctx, "acme", created.ID, CommandAutomationWebhookActive, created.Revision); err != nil {
		t.Fatalf("activate webhook: %v", err)
	}
	active, err := j.FindActiveCommandAutomationWebhookByToken(ctx, input.TokenID)
	if err != nil || active.ID != created.ID || active.TenantID != "acme" {
		t.Fatalf("active webhook = %+v err=%v", active, err)
	}
	if err := j.SetCommandAutomationWebhookTriggerStateIfRevision(ctx, "acme", created.ID, CommandAutomationWebhookDisabled, created.Revision); !errors.Is(err, ErrCommandAutomationWebhookRevisionConflict) {
		t.Fatalf("stale disable = %v, want revision conflict", err)
	}
	if err := j.SetCommandAutomationWebhookTriggerStateIfRevision(ctx, "acme", created.ID, CommandAutomationWebhookDisabled, active.Revision); err != nil {
		t.Fatalf("disable webhook: %v", err)
	}
	if err := j.DeleteCommandAutomationWebhookTriggerIfRevision(ctx, "acme", created.ID, active.Revision); !errors.Is(err, ErrCommandAutomationWebhookRevisionConflict) {
		t.Fatalf("stale delete = %v, want revision conflict", err)
	}
	disabled, err := j.GetCommandAutomationWebhookTriggerForTenant(ctx, "acme", created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.DeleteCommandAutomationWebhookTriggerIfRevision(ctx, "acme", created.ID, disabled.Revision); err != nil {
		t.Fatalf("delete webhook: %v", err)
	}
	if _, err := j.GetCommandAutomationWebhookTriggerForTenant(ctx, "acme", created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted webhook = %v, want ErrNotFound", err)
	}
}

func TestCommandAutomationWebhookRejectsForeignSecretAndBinding(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_webhook_fence", "webhook-fence", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	commandWebhookCredential(t, j, "cred_cmd_webhook_foreign", "other")
	input := commandWebhookInput(t, "acme", plan, definition, "cred_cmd_webhook_foreign", "cmdwhk_token-fence")
	if _, _, err := j.CreateCommandAutomationWebhookTriggerWithIdempotency(ctx, "acme", input, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign secret accepted as %v", err)
	}
	commandWebhookCredential(t, j, "cred_cmd_webhook_owner", "acme")
	input.SecretID = "cred_cmd_webhook_owner"
	input.GateDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, _, err := j.CreateCommandAutomationWebhookTriggerWithIdempotency(ctx, "acme", input, ""); !errors.Is(err, ErrCommandAutomationWebhookBindingMismatch) {
		t.Fatalf("stale receipt accepted as %v", err)
	}
}

func TestCommandAutomationWebhookMigrationColumns(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	var table string
	if err := j.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='command_automation_webhook_triggers'`).Scan(&table); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			t.Fatal("command webhook migration did not create table")
		}
		t.Fatal(err)
	}
	if table != "command_automation_webhook_triggers" {
		t.Fatalf("table = %q", table)
	}
}

func TestCommandAutomationWebhookAdmissionFenceRejectsDisabledTrigger(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_webhook_run_fence", "webhook-run-fence", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	input := commandWebhookInput(t, "acme", plan, definition, "cred-not-used", "cmdwhk_run_fence")
	// The command webhook authoring row requires a tenant-owned secret even
	// though this plan has no command credential references.
	commandWebhookCredential(t, j, input.SecretID, "acme")
	trigger, err := j.CreateCommandAutomationWebhookTrigger(ctx, "acme", input)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationWebhookTriggerStateIfRevision(ctx, "acme", trigger.ID, CommandAutomationWebhookActive, trigger.Revision); err != nil {
		t.Fatal(err)
	}
	admission := CommandRunAdmission{
		ReceiptID: input.ReceiptID, GateDigest: input.GateDigest, DefinitionSHA256: input.DefinitionSHA256,
		ActorID: input.ActorID, TriggerKind: CommandRunTriggerWebhook, TriggerID: trigger.ID, TriggerEventID: "delivery-1",
	}
	if _, err := j.CreateCommandRun(ctx, "acme", "cmdrun_webhook_fence_1", plan.ID, plan.CurrentVersion, admission); err != nil {
		t.Fatalf("active webhook admission: %v", err)
	}
	active, err := j.GetCommandAutomationWebhookTriggerForTenant(ctx, "acme", trigger.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationWebhookTriggerStateIfRevision(ctx, "acme", trigger.ID, CommandAutomationWebhookDisabled, active.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := j.CreateCommandRun(ctx, "acme", "cmdrun_webhook_fence_2", plan.ID, plan.CurrentVersion, admission); !errors.Is(err, ErrCommandRunBindingMismatch) {
		t.Fatalf("disabled webhook admission = %v, want binding mismatch", err)
	}
}
