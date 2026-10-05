package migrate

import (
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandDefinitionBackfillReceiptRefusesRollbackWithBackfilledRows(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	dbPath := filepath.Join(t.TempDir(), "command-definition-backfill.db")
	rawURL := "sqlite://" + dbPath
	if err := upTo(ctx, log, rawURL, 71); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSNWithPragmas(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `INSERT INTO command_automations
		(id, tenant_id, name, current_version) VALUES ('cmd_backfill_guard', 'default', 'backfill-guard', 1)`); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	if _, err := db.ExecContext(ctx, `INSERT INTO command_automation_versions
		(automation_id, version, definition_json, definition_crypto_version,
		 definition_plaintext_bytes, definition_sha256, definition_canonical_sha256)
		VALUES ('cmd_backfill_guard', 1, ?, 1, 2, ?, ?)`,
		`{"__reactor_payload_envelope":"reactor-payload:v1:fake"}`, digest, digest); err != nil {
		t.Fatal(err)
	}
	if err := downSQLiteTo(ctx, log, rawURL, 70); err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
		t.Fatalf("rollback with backfill receipt = %v", err)
	}
	var canonical string
	if err := db.QueryRowContext(ctx, `SELECT definition_canonical_sha256 FROM command_automation_versions
		WHERE automation_id = 'cmd_backfill_guard'`).Scan(&canonical); err != nil || canonical != digest {
		t.Fatalf("failed rollback changed receipt: digest=%q err=%v", canonical, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE command_automation_versions
		SET definition_canonical_sha256 = NULL WHERE automation_id = 'cmd_backfill_guard'`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := downSQLiteTo(ctx, log, rawURL, 70); err != nil {
		t.Fatalf("rollback after receipt cleared: %v", err)
	}
}
