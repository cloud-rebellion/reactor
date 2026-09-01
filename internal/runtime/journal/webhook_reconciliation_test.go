package journal

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestFindCompletedWebhookDeliveryRunIsStrictlyScoped(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	tokenA, err := NewTokenID()
	if err != nil {
		t.Fatal(err)
	}
	triggerA, err := j.CreateWebhookTrigger(ctx, "wf_1", tokenA, "cred_a", "automation-v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	tokenB, err := NewTokenID()
	if err != nil {
		t.Fatal(err)
	}
	triggerB, err := j.CreateWebhookTrigger(ctx, "wf_1", tokenB, "cred_b", "automation-v1", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := j.CreateRun(ctx, "run_webhook", "wf_1", "webhook", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	claim, err := j.ClaimWebhookDelivery(ctx, triggerA, "automation-v1", "event/with/slash", "digest", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CompleteWebhookDelivery(ctx, triggerA, "automation-v1", "event/with/slash",
		claim.ClaimToken, "run_webhook", now); err != nil {
		t.Fatal(err)
	}

	got, err := j.FindCompletedWebhookDeliveryRun(ctx, triggerA, "automation-v1", "event/with/slash")
	if err != nil {
		t.Fatal(err)
	}
	if got.RunID != "run_webhook" || got.Status != "running" {
		t.Fatalf("delivery run = %+v", got)
	}

	for _, tc := range []struct {
		name       string
		triggerID  string
		provider   string
		deliveryID string
	}{
		{name: "other trigger", triggerID: triggerB, provider: "automation-v1", deliveryID: "event/with/slash"},
		{name: "other provider", triggerID: triggerA, provider: "hash-v1", deliveryID: "event/with/slash"},
		{name: "other delivery", triggerID: triggerA, provider: "automation-v1", deliveryID: "other"},
		{name: "empty trigger", provider: "automation-v1", deliveryID: "event/with/slash"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := j.FindCompletedWebhookDeliveryRun(ctx, tc.triggerID, tc.provider, tc.deliveryID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("got %v, want ErrNotFound", err)
			}
		})
	}

	incomplete, err := j.ClaimWebhookDelivery(ctx, triggerA, "automation-v1", "evt_incomplete", "digest", now, time.Minute)
	if err != nil || incomplete.State != WebhookDeliveryClaimed {
		t.Fatalf("incomplete claim = %+v, %v", incomplete, err)
	}
	if _, err := j.FindCompletedWebhookDeliveryRun(ctx, triggerA, "automation-v1", "evt_incomplete"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("incomplete receipt got %v, want ErrNotFound", err)
	}
}

func TestFindCompletedWebhookDeliveryRunRejectsMismatchedRunOwnership(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if err := j.CreateWorkflowInTenant(ctx, "wf_other", "other-workflow", "hash", "0.1.0", json.RawMessage(`{}`), "other"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_other", "wf_other", "webhook", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	tokenID, err := NewTokenID()
	if err != nil {
		t.Fatal(err)
	}
	triggerID, err := j.CreateWebhookTrigger(ctx, "wf_1", tokenID, "cred", "automation-v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	claim, err := j.ClaimWebhookDelivery(ctx, triggerID, "automation-v1", "evt_cross_tenant", "digest", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CompleteWebhookDelivery(ctx, triggerID, "automation-v1", "evt_cross_tenant",
		claim.ClaimToken, "run_other", now); err != nil {
		t.Fatal(err)
	}

	if _, err := j.FindCompletedWebhookDeliveryRun(ctx, triggerID, "automation-v1", "evt_cross_tenant"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant run got %v, want ErrNotFound", err)
	}
}
