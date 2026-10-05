package journal

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestCreateAndFindWebhookTrigger(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	tokenID, err := NewTokenID()
	if err != nil {
		t.Fatal(err)
	}
	id, err := j.CreateWebhookTrigger(ctx, "wf_1", tokenID, "cred_abc", "stripe", []byte(`{"event":"invoice.paid"}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := j.FindWebhookByToken(ctx, tokenID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != id || got.WorkflowID != "wf_1" || got.SecretID != "cred_abc" || got.Provider != "stripe" {
		t.Fatalf("got %+v", got)
	}
	if string(got.Config) != `{"event":"invoice.paid"}` {
		t.Fatalf("config = %s", got.Config)
	}
}

func TestCreateWebhookTriggerInheritsWorkflowTenant(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if err := j.CreateWorkflowInTenant(ctx, "wf_acme", "tenant-webhook", "hash", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatalf("create tenant workflow: %v", err)
	}
	tokenID, err := NewTokenID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.CreateWebhookTrigger(ctx, "wf_acme", tokenID, "cred_acme", "automation-v1", nil); err != nil {
		t.Fatalf("create webhook trigger: %v", err)
	}
	got, err := j.FindWebhookByToken(ctx, tokenID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TenantID != "acme" {
		t.Fatalf("trigger tenant = %q, want acme", got.TenantID)
	}
}

func TestCreateWebhookTriggerRefusesCrossTenantSecret(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if err := j.CreateWorkflowInTenant(ctx, "wf_webhook_owner", "tenant-webhook-owner", "h", "0.1.0", json.RawMessage(`{}`), "tenant-a"); err != nil {
		t.Fatal(err)
	}
	mustInsert := func(id, tenant string) {
		t.Helper()
		if _, err := j.db.ExecContext(ctx, j.bind(`INSERT INTO credentials (id, tenant_id, name, service, provider, blob) VALUES ($1,$2,$3,$4,$5,$6)`), id, tenant, id, "reactor-webhook", "shared-secret", []byte("sentinel")); err != nil {
			t.Fatalf("insert credential: %v", err)
		}
	}
	mustInsert("cred_webhook_owner", "tenant-a")
	mustInsert("cred_webhook_foreign", "tenant-b")

	if _, err := j.CreateWebhookTrigger(ctx, "wf_webhook_owner", "whk_foreign", "cred_webhook_foreign", "generic", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant webhook secret was accepted as %v, want ErrNotFound", err)
	}
	if _, err := j.CreateWebhookTrigger(ctx, "wf_webhook_owner", "whk_owner", "cred_webhook_owner", "generic", nil); err != nil {
		t.Fatalf("same-tenant webhook secret was refused: %v", err)
	}
}

func TestCreateWebhookTriggerUnknownWorkflowReturnsNotFound(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()

	_, err := j.CreateWebhookTrigger(context.Background(), "wf_missing", "whk_missing", "cred", "generic", nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestCreateCronTriggerInheritsWorkflowTenant(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_cron_acme", "tenant-cron", "hash", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	id, err := j.CreateCronTrigger(ctx, "wf_cron_acme", []byte(`{"spec":"0 9 * * *"}`))
	if err != nil {
		t.Fatal(err)
	}
	triggers, err := j.ListTriggersForWorkflow(ctx, "wf_cron_acme")
	if err != nil || len(triggers) != 1 {
		t.Fatalf("triggers = %+v, %v", triggers, err)
	}
	if triggers[0].ID != id || triggers[0].TenantID != "acme" {
		t.Fatalf("trigger = %+v, want id %q in acme", triggers[0], id)
	}
}

func TestFindWebhookMissing(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	if _, err := j.FindWebhookByToken(context.Background(), "whk_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestGetActiveWebhookTriggerFencesStateAndTenant(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_webhook_active", "webhook-active", "h", "1", json.RawMessage(`{}`), "tenant-a"); err != nil {
		t.Fatal(err)
	}
	triggerID, err := j.CreateWebhookTrigger(ctx, "wf_webhook_active", "whk_active_lookup", "cred_active_lookup", "generic", []byte(`{"sync":false}`))
	if err != nil {
		t.Fatal(err)
	}
	active, err := j.GetActiveWebhookTrigger(ctx, triggerID)
	if err != nil || active.ID != triggerID || active.TenantID != "tenant-a" {
		t.Fatalf("active webhook = %+v, %v", active, err)
	}
	if err := j.SetTriggerState(ctx, triggerID, "disabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.GetActiveWebhookTrigger(ctx, triggerID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled webhook lookup = %v, want ErrNotFound", err)
	}
}

func TestRecordWebhookDeliveryDeduplicates(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	first, err := j.RecordWebhookDelivery(ctx, "trg_a", "stripe", "evt_123")
	if err != nil {
		t.Fatal(err)
	}
	if !first {
		t.Fatal("first record should report new")
	}
	second, err := j.RecordWebhookDelivery(ctx, "trg_a", "stripe", "evt_123")
	if err != nil {
		t.Fatal(err)
	}
	if second {
		t.Fatal("duplicate record should report not-new")
	}
	// Different provider with same delivery_id is its own row.
	third, err := j.RecordWebhookDelivery(ctx, "trg_a", "github", "evt_123")
	if err != nil {
		t.Fatal(err)
	}
	if !third {
		t.Fatal("different provider should record as new")
	}
}

func TestWebhookDeliveryLeaseLifecycle(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	const (
		triggerID = "trg_lease"
		provider  = "generic"
		delivery  = "evt_lease"
		digest    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)

	first, err := j.ClaimWebhookDelivery(ctx, triggerID, provider, delivery, digest, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if first.State != WebhookDeliveryClaimed || first.ClaimToken == "" {
		t.Fatalf("first claim = %+v, want owned lease", first)
	}

	active, err := j.ClaimWebhookDelivery(ctx, triggerID, provider, delivery, digest, now.Add(30*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if active.State != WebhookDeliveryInProgress || !active.LeaseExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("active duplicate = %+v, want in-progress until %s", active, now.Add(time.Minute))
	}

	mismatch, err := j.ClaimWebhookDelivery(ctx, triggerID, provider, delivery, "different", now.Add(30*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if mismatch.State != WebhookDeliveryPayloadMismatch {
		t.Fatalf("payload mismatch = %+v", mismatch)
	}

	reclaimed, err := j.ClaimWebhookDelivery(ctx, triggerID, provider, delivery, digest, now.Add(61*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if reclaimed.State != WebhookDeliveryClaimed || reclaimed.ClaimToken == first.ClaimToken {
		t.Fatalf("expired lease was not independently reclaimed: first=%+v reclaimed=%+v", first, reclaimed)
	}

	if err := j.CompleteWebhookDelivery(ctx, triggerID, provider, delivery, first.ClaimToken, "run_stale", now.Add(62*time.Second)); !errors.Is(err, ErrWebhookDeliveryClaimLost) {
		t.Fatalf("stale owner completion = %v, want ErrWebhookDeliveryClaimLost", err)
	}
	if err := j.ReleaseWebhookDelivery(ctx, triggerID, provider, delivery, first.ClaimToken); !errors.Is(err, ErrWebhookDeliveryClaimLost) {
		t.Fatalf("stale owner release = %v, want ErrWebhookDeliveryClaimLost", err)
	}

	if err := j.CompleteWebhookDelivery(ctx, triggerID, provider, delivery, reclaimed.ClaimToken, "run_42", now.Add(62*time.Second)); err != nil {
		t.Fatal(err)
	}
	completed, err := j.ClaimWebhookDelivery(ctx, triggerID, provider, delivery, digest, now.Add(3*time.Minute), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != WebhookDeliveryCompleted || completed.RunID != "run_42" {
		t.Fatalf("completed replay = %+v, want run_42", completed)
	}
}

func TestWebhookDeliveryReleaseAllowsImmediateRetry(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

	first, err := j.ClaimWebhookDelivery(ctx, "trg_release", "generic", "evt_release", "digest", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.ReleaseWebhookDelivery(ctx, "trg_release", "generic", "evt_release", first.ClaimToken); err != nil {
		t.Fatal(err)
	}
	second, err := j.ClaimWebhookDelivery(ctx, "trg_release", "generic", "evt_release", "digest", now.Add(time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if second.State != WebhookDeliveryClaimed || second.ClaimToken == first.ClaimToken {
		t.Fatalf("retry after release = %+v", second)
	}
}

func TestWebhookLegacyCompletedReceiptAcceptsUnknownDigest(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

	// Migration 0028 uses an empty digest for pre-existing receipts because
	// their original bodies are unavailable. They must remain completed dedup
	// successes rather than turning every historical provider retry into 409.
	const q = `INSERT INTO webhook_deliveries
		(trigger_id, provider, delivery_id, received_at, payload_sha256, claim_token, completed_at)
		VALUES ($1, $2, $3, $4, '', '', $5)`
	if _, err := j.db.ExecContext(ctx, j.bind(q), "trg_legacy", "generic", "evt_legacy",
		j.formatTime(now), j.formatTime(now)); err != nil {
		t.Fatal(err)
	}
	claim, err := j.ClaimWebhookDelivery(ctx, "trg_legacy", "generic", "evt_legacy",
		"newly-computed-digest", now.Add(time.Minute), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if claim.State != WebhookDeliveryCompleted {
		t.Fatalf("legacy receipt = %+v, want completed", claim)
	}
}

// TestWebhookDedupIsPerTrigger pins a defect that was live without any tenancy
// involved. The dedup key was (provider, delivery_id) alone, a namespace shared
// by every trigger in the install, and for the generic provider delivery_id
// comes verbatim from the caller's X-Webhook-Delivery header.
//
// So two workflows subscribed to the same GitHub org event received one
// delivery id fanned out to both URLs, the first to arrive claimed it, and the
// second workflow was answered 200 {"deduped":true} and NEVER RAN. Across
// tenants it is a deliberate denial of delivery: post to your own trigger
// carrying the victim's delivery id and their automation stops while their
// upstream keeps seeing success.
func TestWebhookDedupIsPerTrigger(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	const provider, delivery = "github", "evt_shared"

	mine, err := j.RecordWebhookDelivery(ctx, "trg_mine", provider, delivery)
	if err != nil {
		t.Fatal(err)
	}
	if !mine {
		t.Fatal("first trigger should record as new")
	}

	// The SAME delivery id arriving at a DIFFERENT trigger must still dispatch.
	theirs, err := j.RecordWebhookDelivery(ctx, "trg_theirs", provider, delivery)
	if err != nil {
		t.Fatal(err)
	}
	if !theirs {
		t.Fatal("another trigger's delivery was suppressed: one trigger can silence another's webhooks")
	}

	// Dedup still works WITHIN a trigger, which is the actual purpose.
	repeat, err := j.RecordWebhookDelivery(ctx, "trg_mine", provider, delivery)
	if err != nil {
		t.Fatal(err)
	}
	if repeat {
		t.Fatal("a genuine replay to the same trigger should be deduped")
	}

	// Rollback is scoped too: releasing one trigger's claim must not release
	// another's, or a failed dispatch would re-open a neighbour's replay window.
	if err := j.DeleteWebhookDelivery(ctx, "trg_mine", provider, delivery); err != nil {
		t.Fatal(err)
	}
	again, err := j.RecordWebhookDelivery(ctx, "trg_mine", provider, delivery)
	if err != nil {
		t.Fatal(err)
	}
	if !again {
		t.Fatal("after rollback the sender's retry should be treated as fresh")
	}
	stillClaimed, err := j.RecordWebhookDelivery(ctx, "trg_theirs", provider, delivery)
	if err != nil {
		t.Fatal(err)
	}
	if stillClaimed {
		t.Fatal("rolling back one trigger's claim also released another's")
	}
}

func TestNewTokenIDIsUnique(t *testing.T) {
	t.Parallel()
	a, _ := NewTokenID()
	b, _ := NewTokenID()
	if a == b || a == "" || b == "" {
		t.Fatalf("got %q and %q", a, b)
	}
	if len(a) != len("whk_")+32 {
		t.Fatalf("unexpected length: %s", a)
	}
}

func TestMarkTriggerFiredAndError(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	tok, _ := NewTokenID()
	id, _ := j.CreateWebhookTrigger(ctx, "wf_1", tok, "cred_x", "generic", nil)

	if err := j.MarkTriggerError(ctx, id, "boom"); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkTriggerFired(ctx, id); err != nil {
		t.Fatal(err)
	}
	got, _ := j.FindWebhookByToken(ctx, tok)
	if got.LastError != "" {
		t.Fatalf("error not cleared: %q", got.LastError)
	}
	if got.LastFiredAt == nil {
		t.Fatal("last_fired_at not set")
	}
}
