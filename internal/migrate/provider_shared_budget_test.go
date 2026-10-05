package migrate

import (
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"testing"
)

func TestProviderSharedBudgetMigrationLeavesLegacyReceiptsOnRollback(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	dbPath := filepath.Join(t.TempDir(), "provider-budget.db")
	rawURL := "sqlite://" + dbPath
	if err := upTo(ctx, log, rawURL, 58); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSNWithPragmas(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `INSERT INTO oauth_providers
		(provider_id, name, auth_url, token_url) VALUES ('salesforce', 'Salesforce',
		'https://login.salesforce.com/auth', 'https://login.salesforce.com/token')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO oauth_connections
		(id, tenant_id, provider_id, name, token_encrypted, status)
		VALUES ('conn-1', 'tenant-a', 'salesforce', 'main', ?, 'connected')`, []byte("sealed")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO provider_account_budgets
		(tenant_id, connection_id, requests_per_min, max_concurrent)
		VALUES ('tenant-a', 'conn-1', 30, 2)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO provider_account_permits
		(id, tenant_id, connection_id, granted_at, expires_at)
		VALUES ('permit-1', 'tenant-a', 'conn-1', '2026-10-04T12:00:00.000Z', '2026-10-04T12:01:00.000Z')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := upTo(ctx, log, rawURL, 59); err != nil {
		t.Fatalf("apply shared-account migration: %v", err)
	}
	if err := downSQLiteTo(ctx, log, rawURL, 58); err != nil {
		t.Fatalf("rollback shared-account migration: %v", err)
	}
	db, err = sql.Open("sqlite", sqliteDSNWithPragmas(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM provider_account_permits
		WHERE id = 'permit-1'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("rollback erased old connection receipt: count=%d err=%v", count, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM provider_shared_account_budgets`).Scan(&count); err == nil {
		t.Fatal("rollback left shared budget table behind")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := upTo(ctx, log, rawURL, 59); err != nil {
		t.Fatalf("reapply shared-account migration: %v", err)
	}
}
