package migrate

import (
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	dbpkg "github.com/bright-interaction/reactor/internal/db"
)

// TestWebhookDeliveryLeaseMigrationPreservesLegacyReceipts stages a real
// SQLite database at 0027. A from-scratch migration alone cannot prove how the
// new state classifies rows that were already acknowledged before 0028.
func TestWebhookDeliveryLeaseMigrationPreservesLegacyReceipts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	dbPath := filepath.Join(t.TempDir(), "webhook-lease.db")
	url := "sqlite://" + dbPath

	if err := upTo(ctx, log, url, 27); err != nil {
		t.Fatalf("migrate to 0027: %v", err)
	}
	db, err := sql.Open("sqlite", sqliteDSNWithPragmas(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	const receivedAt = "2026-08-31T12:00:00.000Z"
	if _, err := db.ExecContext(ctx, `INSERT INTO webhook_deliveries
		(trigger_id, provider, delivery_id, received_at) VALUES (?,?,?,?)`,
		"trg_legacy", "generic", "evt_legacy", receivedAt); err != nil {
		t.Fatalf("seed legacy receipt: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if err := upTo(ctx, log, url, 28); err != nil {
		t.Fatalf("migrate 0027 -> 0028: %v", err)
	}
	db, err = sql.Open("sqlite", sqliteDSNWithPragmas(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var (
		payloadHash, claimToken, completedAt string
		leaseExpires, runID                  sql.NullString
	)
	if err := db.QueryRowContext(ctx, `SELECT payload_sha256, claim_token,
		lease_expires_at, completed_at, run_id FROM webhook_deliveries
		WHERE trigger_id = ? AND provider = ? AND delivery_id = ?`,
		"trg_legacy", "generic", "evt_legacy").Scan(
		&payloadHash, &claimToken, &leaseExpires, &completedAt, &runID,
	); err != nil {
		t.Fatal(err)
	}
	if payloadHash != "" || claimToken != "" || leaseExpires.Valid || runID.Valid {
		t.Fatalf("legacy receipt gained active claim data: hash=%q token=%q lease=%v run=%v",
			payloadHash, claimToken, leaseExpires, runID)
	}
	if completedAt != receivedAt {
		t.Fatalf("legacy completed_at = %q, want received_at %q", completedAt, receivedAt)
	}

	var indexes int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master
		WHERE type='index' AND name='webhook_deliveries_active_lease_idx'`).Scan(&indexes); err != nil {
		t.Fatal(err)
	}
	if indexes != 1 {
		t.Fatalf("active lease index count = %d, want 1", indexes)
	}
}

// TestWebhookDeliveryLeaseMigrationsStayMirrored pins the PostgreSQL side of
// the portable schema even on developer machines that do not run a live
// PostgreSQL service. Runtime lease transitions are exercised through SQLite;
// CI can additionally apply the embedded Postgres migration in its normal
// database migration job.
func TestWebhookDeliveryLeaseMigrationsStayMirrored(t *testing.T) {
	t.Parallel()
	pg, err := dbpkg.Migrations.ReadFile("migrations/postgres/0028_webhook_delivery_leases.sql")
	if err != nil {
		t.Fatal(err)
	}
	sqlite, err := dbpkg.Migrations.ReadFile("migrations/sqlite/0028_webhook_delivery_leases.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{
		"payload_sha256", "claim_token", "lease_expires_at", "completed_at", "run_id",
	} {
		if !strings.Contains(string(pg), column) {
			t.Errorf("postgres 0028 missing %s", column)
		}
		if !strings.Contains(string(sqlite), column) {
			t.Errorf("sqlite 0028 missing %s", column)
		}
	}
	if !strings.Contains(string(pg), "lease_expires_at TIMESTAMPTZ") ||
		!strings.Contains(string(pg), "completed_at TIMESTAMPTZ") {
		t.Error("postgres lease timestamps must remain TIMESTAMPTZ")
	}
	if !strings.Contains(string(sqlite), "lease_expires_at TEXT") ||
		!strings.Contains(string(sqlite), "completed_at TEXT") {
		t.Error("sqlite lease timestamps must remain ISO-8601 TEXT")
	}
}
