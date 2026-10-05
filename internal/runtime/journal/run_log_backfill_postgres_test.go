package journal

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
)

func TestPostgresBackfillLegacyRunLogsPreservesExactRead(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for PostgreSQL run-log backfill test")
	}
	engine, err := migrate.EngineFromURL(rawURL)
	if err != nil || engine != migrate.EnginePostgres {
		t.Fatalf("test URL must be PostgreSQL: %v", err)
	}
	u, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(strings.ToLower(strings.Trim(u.Path, "/")), "test") {
		t.Fatal("PostgreSQL test database name must contain test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	base, _, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	schema := fmt.Sprintf("run_log_backfill_%d", time.Now().UnixNano())
	if _, err := base.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer base.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	scopedURL := u.String()
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), scopedURL); err != nil {
		t.Fatal(err)
	}
	db, _, err := migrate.Open(scopedURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var validIndex bool
	var indexDefinition string
	if err := db.QueryRowContext(ctx, `SELECT indisvalid, pg_get_indexdef(indexrelid)
		FROM pg_index WHERE indexrelid = 'run_logs_legacy_backfill_idx'::regclass`).
		Scan(&validIndex, &indexDefinition); err != nil || !validIndex ||
		!strings.Contains(indexDefinition, "payload_crypto_version = 0") {
		t.Fatalf("PostgreSQL legacy backfill partial index valid=%t definition=%q err=%v", validIndex, indexDefinition, err)
	}
	j := New(db, EnginePostgres)
	if err := j.CreateWorkflowInTenant(ctx, "wf_log_backfill_pg", "log-backfill-pg", "h", "0.1.0", []byte(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_log_backfill_pg", "wf_log_backfill_pg", "manual", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	const legacy = "synthetic-postgres-private-log å界"
	if err := j.SaveRunLogs(ctx, "run_log_backfill_pg", []string{legacy}); err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{0x61}, 32)
	if err := j.EnablePayloadEncryption(ctx, master, nil); err != nil {
		t.Fatal(err)
	}
	converted, more, err := j.BackfillLegacyRunLogs(ctx, 1)
	if err != nil || converted != 1 || more {
		t.Fatalf("PostgreSQL backfill converted=%d more=%t err=%v", converted, more, err)
	}
	var stored string
	var version, plainBytes int
	if err := db.QueryRowContext(ctx, `SELECT line, payload_crypto_version, plaintext_bytes
		FROM run_logs WHERE run_id = $1 AND seq = 0`, "run_log_backfill_pg").Scan(&stored, &version, &plainBytes); err != nil {
		t.Fatal(err)
	}
	if version != 1 || plainBytes != len(legacy) || strings.Contains(stored, legacy) {
		t.Fatalf("PostgreSQL legacy log remains plaintext: version=%d bytes=%d", version, plainBytes)
	}
	restarted := New(db, EnginePostgres)
	if err := restarted.LoadPayloadEncryption(ctx, master, nil); err != nil {
		t.Fatal(err)
	}
	if logs, err := restarted.GetRunLogsPageForTenant(ctx, "run_log_backfill_pg", "acme", 1, 0); err != nil || len(logs) != 1 || logs[0] != legacy {
		t.Fatalf("PostgreSQL backfilled exact read = %v, %v", logs, err)
	}
	converted, more, err = restarted.BackfillLegacyRunLogs(ctx, 1)
	if err != nil || converted != 0 || more {
		t.Fatalf("PostgreSQL idempotent backfill converted=%d more=%t err=%v", converted, more, err)
	}
}
