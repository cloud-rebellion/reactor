package journal

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
)

// TestWebhookDeliveryLeasePostgres exercises the portable claim queries
// against PostgreSQL when CI (or a developer) supplies an isolated database.
// The default unit suite stays self-contained on SQLite.
func TestWebhookDeliveryLeasePostgres(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL to run the PostgreSQL webhook lease contract")
	}
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(ctx, log, rawURL); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}
	db, engine, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if engine != migrate.EnginePostgres {
		t.Fatalf("REACTOR_TEST_POSTGRES_URL selected %s, want postgres", engine)
	}
	j := New(db, EnginePostgres)

	// The table is deliberately not FK-bound to triggers, so a unique synthetic
	// key keeps this test isolated and cleanup is one exact DELETE.
	suffix := time.Now().UTC().Format("20060102T150405.000000000")
	triggerID := "trg_pg_" + suffix
	deliveryID := "evt_pg_" + suffix
	defer func() {
		_ = j.DeleteWebhookDelivery(context.Background(), triggerID, "generic", deliveryID)
	}()

	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	first, err := j.ClaimWebhookDelivery(ctx, triggerID, "generic", deliveryID, "digest", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if first.State != WebhookDeliveryClaimed {
		t.Fatalf("first postgres claim = %+v", first)
	}
	active, err := j.ClaimWebhookDelivery(ctx, triggerID, "generic", deliveryID, "digest", now.Add(30*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if active.State != WebhookDeliveryInProgress {
		t.Fatalf("active postgres claim = %+v", active)
	}
	reclaimed, err := j.ClaimWebhookDelivery(ctx, triggerID, "generic", deliveryID, "digest", now.Add(61*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if reclaimed.State != WebhookDeliveryClaimed || reclaimed.ClaimToken == first.ClaimToken {
		t.Fatalf("reclaimed postgres claim = %+v", reclaimed)
	}
	if err := j.CompleteWebhookDelivery(ctx, triggerID, "generic", deliveryID,
		reclaimed.ClaimToken, "run_pg", now.Add(62*time.Second)); err != nil {
		t.Fatal(err)
	}
	completed, err := j.ClaimWebhookDelivery(ctx, triggerID, "generic", deliveryID, "digest", now.Add(2*time.Minute), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != WebhookDeliveryCompleted || completed.RunID != "run_pg" {
		t.Fatalf("completed postgres claim = %+v", completed)
	}
}
