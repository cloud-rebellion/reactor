package journal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestNotificationDeliverySnapshotAndPerChannelRetry(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	testNotificationDeliverySnapshotAndPerChannelRetry(t, j, "run_1", "wf_1")
}

func TestNotificationDeliveryEmptySnapshotAllowsTerminalAck(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	testNotificationDeliveryEmptySnapshotAllowsTerminalAck(t, j, "run_1", "wf_1")
}

func testNotificationDeliveryEmptySnapshotAllowsTerminalAck(t *testing.T, j *Journal, runID, workflowID string) {
	t.Helper()
	ctx := context.Background()
	if err := j.MarkRunFinished(ctx, runID, "succeeded"); err != nil {
		t.Fatal(err)
	}
	claim, err := j.ClaimTerminalEffect(ctx, runID, "succeeded", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := j.BeginNotificationDelivery(ctx, claim, workflowID)
	if err != nil {
		t.Fatal(err)
	}
	page, more, err := j.PendingNotificationDeliveryPage(ctx, claim, snap, "", 16)
	if err != nil || more || len(page) != 0 {
		t.Fatalf("empty snapshot page=%+v more=%v err=%v", page, more, err)
	}
	if err := j.MarkTerminalEffectDeliveredForClaim(ctx, claim); err != nil {
		t.Fatal(err)
	}
}

func testNotificationDeliverySnapshotAndPerChannelRetry(t *testing.T, j *Journal, runID, workflowID string) {
	t.Helper()
	ctx := context.Background()
	ids := make([]string, 3)
	for i, name := range []string{"alpha", "bravo", "charlie"} {
		id, err := j.CreateNotificationChannel(ctx, name, ChannelKindGenericWebhook,
			json.RawMessage(`{"url":"https://example.invalid/notify"}`))
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id
	}
	for _, id := range ids[:2] {
		if err := j.AddNotificationRoute(ctx, workflowID, id, "failed"); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.MarkRunFinished(ctx, runID, "failed"); err != nil {
		t.Fatal(err)
	}
	claim, err := j.ClaimTerminalEffect(ctx, runID, "failed", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// An older daemon may send, but it cannot acknowledge the terminal effect
	// without first recording a route snapshot and per-channel successes.
	if err := j.MarkTerminalEffectDeliveredForClaim(ctx, claim); err == nil || !strings.Contains(err.Error(), "notification deliveries not acknowledged") {
		t.Fatalf("old-writer acknowledgement = %v", err)
	}
	snap, err := j.BeginNotificationDelivery(ctx, claim, workflowID)
	if err != nil {
		t.Fatal(err)
	}
	page, more, err := j.PendingNotificationDeliveryPage(ctx, claim, snap, "", 1)
	if err != nil || !more || len(page) != 1 {
		t.Fatalf("first pending page = %+v more=%v err=%v", page, more, err)
	}
	if err := j.MarkNotificationDelivery(ctx, claim, snap, page[0].ChannelID); err != nil {
		t.Fatal(err)
	}
	remainingID := ids[0]
	if page[0].ChannelID == ids[0] {
		remainingID = ids[1]
	}
	if err := j.MarkTerminalEffectDeliveredForClaim(ctx, claim); err == nil || !strings.Contains(err.Error(), "notification deliveries not acknowledged") {
		t.Fatalf("partial acknowledgement = %v", err)
	}
	if err := j.ReleaseTerminalEffectForClaim(ctx, claim, "one provider failed"); err != nil {
		t.Fatal(err)
	}
	// Editing routes after the first attempt must not grow or shrink this
	// generation's recipients. Only the second original channel stays pending.
	if err := j.DeleteNotificationRoute(ctx, workflowID, remainingID); err != nil {
		t.Fatal(err)
	}
	if err := j.AddNotificationRoute(ctx, workflowID, ids[2], "failed"); err != nil {
		t.Fatal(err)
	}
	retry, err := j.ClaimTerminalEffect(ctx, runID, "failed", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := j.BeginNotificationDelivery(ctx, retry, workflowID)
	if err != nil || resumed != snap {
		t.Fatalf("retry snapshot = %+v, err=%v; want %+v", resumed, err, snap)
	}
	pending, more, err := j.PendingNotificationDeliveryPage(ctx, retry, resumed, "", 16)
	if err != nil || more || len(pending) != 1 || pending[0].ChannelID != remainingID {
		t.Fatalf("retry pending = %+v more=%v err=%v", pending, more, err)
	}
	if err := j.MarkNotificationDelivery(ctx, claim, snap, remainingID); !errors.Is(err, ErrTerminalEffectClaimLost) {
		t.Fatalf("lost claim ack = %v", err)
	}
	if _, _, err := j.PendingNotificationDeliveryPage(ctx, claim, snap, "", 16); !errors.Is(err, ErrTerminalEffectClaimLost) {
		t.Fatalf("lost claim read = %v", err)
	}
	if err := j.MarkNotificationDelivery(ctx, retry, snap, remainingID); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkTerminalEffectDeliveredForClaim(ctx, retry); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkNotificationDelivery(ctx, retry, snap, remainingID); !errors.Is(err, ErrTerminalEffectClaimLost) {
		t.Fatalf("ack after terminal effect delivered = %v", err)
	}
}

func TestNotificationDeliveryRedriveGenerationAndDeletedChannel(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	testNotificationDeliveryRedriveGenerationAndDeletedChannel(t, j, "run_1", "wf_1")
}

func testNotificationDeliveryRedriveGenerationAndDeletedChannel(t *testing.T, j *Journal, runID, workflowID string) {
	t.Helper()
	ctx := context.Background()
	id, err := j.CreateNotificationChannel(ctx, "ops", ChannelKindGenericWebhook, json.RawMessage(`{"url":"https://example.invalid"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.AddNotificationRoute(ctx, workflowID, id, "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, runID, "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	first, err := j.ClaimTerminalEffect(ctx, runID, "failed_dlq", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	oldSnap, err := j.BeginNotificationDelivery(ctx, first, workflowID)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.MarkNotificationDelivery(ctx, first, oldSnap, id); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkTerminalEffectDeliveredForClaim(ctx, first); err != nil {
		t.Fatal(err)
	}
	// A redrive can finish with the same status. The new generation must not
	// inherit the old success receipt or allow the old callback to ack it.
	if err := j.SetRunStatus(ctx, runID, "running"); err != nil {
		t.Fatal(err)
	}
	// StartDeadLetterRetryItem resets the terminal effect in the same
	// transaction that reopens the run. Reproduce that receipt reset here;
	// this fixture has no dead-letter item to pass its exact-attempt gate.
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE terminal_effects
		SET attempts = 0, claimed_at = NULL, claim_token = NULL,
			delivered_at = NULL, last_error = NULL WHERE run_id = $1`), runID); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, runID, "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	second, err := j.ClaimTerminalEffect(ctx, runID, "failed_dlq", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newSnap, err := j.BeginNotificationDelivery(ctx, second, workflowID)
	if err != nil {
		t.Fatal(err)
	}
	if newSnap.Generation != oldSnap.Generation+1 {
		t.Fatalf("generation %d after %d", newSnap.Generation, oldSnap.Generation)
	}
	if _, err := j.BeginNotificationDelivery(ctx, first, workflowID); !errors.Is(err, ErrTerminalEffectClaimLost) {
		t.Fatalf("stale same-status snapshot = %v", err)
	}
	if err := j.MarkNotificationDelivery(ctx, first, oldSnap, id); !errors.Is(err, ErrTerminalEffectClaimLost) {
		t.Fatalf("stale same-status delivery ack = %v", err)
	}
	page, more, err := j.PendingNotificationDeliveryPage(ctx, second, newSnap, "", 16)
	if err != nil || more || len(page) != 1 || page[0].ChannelID != id {
		t.Fatalf("new generation pending = %+v more=%v err=%v", page, more, err)
	}
	if err := j.SkipNotificationDelivery(ctx, second, newSnap, id); !errors.Is(err, ErrTerminalEffectClaimLost) {
		t.Fatalf("skip of existing channel = %v", err)
	}
	if err := j.DeleteNotificationRoute(ctx, workflowID, id); err != nil {
		t.Fatal(err)
	}
	if err := j.DeleteNotificationChannel(ctx, id); err != nil {
		t.Fatal(err)
	}
	page, more, err = j.PendingNotificationDeliveryPage(ctx, second, newSnap, "", 16)
	if err != nil || more || len(page) != 1 || !page[0].Missing {
		t.Fatalf("deleted destination = %+v more=%v err=%v", page, more, err)
	}
	if err := j.SkipNotificationDelivery(ctx, second, newSnap, id); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkTerminalEffectDeliveredForClaim(ctx, second); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationDeliveryRouteReadBoundsAndTenantFence(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.MarkRunFinished(ctx, "run_1", "failed"); err != nil {
		t.Fatal(err)
	}
	claim, err := j.ClaimTerminalEffect(ctx, "run_1", "failed", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.PendingNotificationDeliveryPage(ctx, claim, NotificationSnapshot{}, "", 17); err == nil {
		t.Fatal("oversized pending page accepted")
	}
	// Insert one deliberately oversized legacy route directly. The snapshot
	// query projects NULL instead of materializing its status blob.
	channelID := "nch_large_status"
	if _, err := j.db.ExecContext(ctx, j.bind(`INSERT INTO notification_channels
		(id, tenant_id, name, kind, config_json, config_crypto_version)
		VALUES ($1, $2, $3, $4, $5, 0)`), channelID, DefaultTenant, "large-status", ChannelKindGenericWebhook, `{}`); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`INSERT INTO workflow_notification_routes
		(workflow_id, channel_id, on_statuses) VALUES ($1, $2, $3)`),
		"wf_1", channelID, strings.Repeat("f", maxNotificationStatusesBytes+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.BeginNotificationDelivery(ctx, claim, "wf_1"); err == nil || !strings.Contains(err.Error(), "statuses exceed") {
		t.Fatalf("oversized route = %v", err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE workflow_notification_routes SET on_statuses = 'failed' WHERE channel_id = $1`), channelID); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE notification_channels SET tenant_id = 'other' WHERE id = $1`), channelID); err != nil {
		t.Fatal(err)
	}
	if _, err := j.BeginNotificationDelivery(ctx, claim, "wf_1"); err == nil || !strings.Contains(err.Error(), "crosses tenant") {
		t.Fatalf("cross-tenant route = %v", err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE notification_channels SET tenant_id = $1 WHERE id = $2`), DefaultTenant, channelID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxSnapshotNotificationRoutes; i++ {
		id := fmt.Sprintf("nch_bulk_%03d", i)
		if _, err := j.db.ExecContext(ctx, j.bind(`INSERT INTO notification_channels
			(id, tenant_id, name, kind, config_json, config_crypto_version)
			VALUES ($1, $2, $3, $4, $5, 0)`), id, DefaultTenant, id, ChannelKindGenericWebhook, `{}`); err != nil {
			t.Fatal(err)
		}
		if _, err := j.db.ExecContext(ctx, j.bind(`INSERT INTO workflow_notification_routes
			(workflow_id, channel_id, on_statuses) VALUES ($1, $2, 'failed')`), "wf_1", id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := j.BeginNotificationDelivery(ctx, claim, "wf_1"); err == nil || !strings.Contains(err.Error(), "routes exceed") {
		t.Fatalf("oversized route set = %v", err)
	}
	var snapshots int
	if err := j.db.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM notification_dispatches WHERE run_id = $1`), "run_1").Scan(&snapshots); err != nil || snapshots != 0 {
		t.Fatalf("failed snapshot left %d rows: %v", snapshots, err)
	}
}

func TestNotificationDeliveryTenantChangeAfterSnapshotFailsClosed(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	testNotificationDeliveryTenantChangeAfterSnapshotFailsClosed(t, j, "run_1", "wf_1")
}

func testNotificationDeliveryTenantChangeAfterSnapshotFailsClosed(t *testing.T, j *Journal, runID, workflowID string) {
	t.Helper()
	ctx := context.Background()
	id, err := j.CreateNotificationChannel(ctx, "tenant-fence", ChannelKindGenericWebhook, json.RawMessage(`{"url":"https://example.invalid"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.AddNotificationRoute(ctx, workflowID, id, "failed"); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, runID, "failed"); err != nil {
		t.Fatal(err)
	}
	claim, err := j.ClaimTerminalEffect(ctx, runID, "failed", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := j.BeginNotificationDelivery(ctx, claim, workflowID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE notification_channels SET tenant_id = 'other' WHERE id = $1`), id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.PendingNotificationDeliveryPage(ctx, claim, snap, "", 16); err == nil || !strings.Contains(err.Error(), "changed tenant") {
		t.Fatalf("cross-tenant pending read = %v", err)
	}
	if err := j.MarkNotificationDelivery(ctx, claim, snap, id); !errors.Is(err, ErrTerminalEffectClaimLost) {
		t.Fatalf("cross-tenant success receipt = %v", err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE notification_channels SET tenant_id = $1 WHERE id = $2`), DefaultTenant, id); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkNotificationDelivery(ctx, claim, snap, id); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkTerminalEffectDeliveredForClaim(ctx, claim); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationTerminalGenerationTransitions(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	assertGeneration := func(want int64) {
		t.Helper()
		var got int64
		if err := j.db.QueryRowContext(ctx, j.bind(`SELECT terminal_generation FROM runs WHERE id = $1`), "run_1").Scan(&got); err != nil || got != want {
			t.Fatalf("generation=%d want=%d err=%v", got, want, err)
		}
	}
	assertGeneration(0)
	for _, transition := range []struct {
		status string
		want   int64
	}{
		{"failed", 1}, {"failed", 1}, {"failed_dlq", 2},
		{"running", 2}, {"failed_dlq", 3},
	} {
		if err := j.SetRunStatus(ctx, "run_1", transition.status); err != nil {
			t.Fatal(err)
		}
		assertGeneration(transition.want)
	}
}
