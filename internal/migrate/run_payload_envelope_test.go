package migrate

import (
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPayloadMigrationRefusesRollbackWithEncryptedRows(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	dbPath := filepath.Join(t.TempDir(), "payload-migration.db")
	rawURL := "sqlite://" + dbPath
	if err := upTo(ctx, log, rawURL, 60); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSNWithPragmas(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `INSERT INTO workflows
		(id, tenant_id, slug, code_hash, sdk_version, dag_json)
		VALUES ('wf_payload_migration', 'default', 'payload-migration', 'h', '0.1.0', '{}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO runs
		(id, workflow_id, trigger_kind, trigger_meta, status, tenant_id, payload_crypto_version, payload_plaintext_bytes)
		VALUES ('run_encrypted', 'wf_payload_migration', 'manual', '{"__reactor_payload_envelope":"fake"}', 'queued', 'default', 1, 2)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO journal_payload_keys (id, wrapped_key) VALUES ('v1', ?)`, []byte("fake-wrapped-key")); err != nil {
		t.Fatal(err)
	}
	if err := downSQLiteTo(ctx, log, rawURL, 59); err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
		t.Fatalf("rollback with encrypted row = %v", err)
	}
	var version int
	if err := db.QueryRowContext(ctx, `SELECT payload_crypto_version FROM runs WHERE id = 'run_encrypted'`).Scan(&version); err != nil || version != 1 {
		t.Fatalf("failed rollback lost marker: version=%d err=%v", version, err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM runs WHERE id = 'run_encrypted'`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := downSQLiteTo(ctx, log, rawURL, 59); err != nil {
		t.Fatalf("rollback after encrypted row removed: %v", err)
	}
}
