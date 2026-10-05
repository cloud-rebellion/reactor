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

func TestPostgresRunLogsPayloadEnvelopeAndOldWriterCutover(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for PostgreSQL run-log encryption test")
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
	schema := fmt.Sprintf("run_log_crypto_%d", time.Now().UnixNano())
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
	j := New(db, EnginePostgres)
	if err := j.CreateWorkflowInTenant(ctx, "wf_run_log_pg", "run-log-pg", "h", "0.1.0", []byte(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_log_pg", "wf_run_log_pg", "manual", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.SaveRunLogs(ctx, "run_log_pg", []string{"legacy"}); err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{0x59}, 32)
	if err := j.EnablePayloadEncryption(ctx, master, nil); err != nil {
		t.Fatal(err)
	}
	const secret = "synthetic-postgres-private-log"
	if err := j.SaveRunLogs(ctx, "run_log_pg", []string{secret}); err != nil {
		t.Fatal(err)
	}
	if err := j.SaveRunLogs(ctx, "run_log_pg", []string{secret}); err != nil {
		t.Fatal(err)
	}
	var raw string
	var version, plainBytes int
	if err := db.QueryRowContext(ctx, `SELECT line, payload_crypto_version, plaintext_bytes
		FROM run_logs WHERE run_id = $1 AND seq = 1`, "run_log_pg").Scan(&raw, &version, &plainBytes); err != nil {
		t.Fatal(err)
	}
	if version != 1 || plainBytes != len(secret) || strings.Contains(raw, secret) {
		t.Fatalf("PostgreSQL persisted plaintext run log: version=%d bytes=%d", version, plainBytes)
	}
	if got, err := j.GetRunLogsPageForTenant(ctx, "run_log_pg", "acme", 10, 0); err != nil ||
		len(got) != 2 || got[0] != "legacy" || got[1] != secret {
		t.Fatalf("PostgreSQL scoped run-log read = %v, %v", got, err)
	}
	if page, err := j.GetRunLogsPageForTenantBounded(ctx, "run_log_pg", "acme", 1, 1, 4); err != nil ||
		len(page) != 1 || page[0].Bytes != len(secret) || !page[0].Truncated || page[0].Text != "" {
		t.Fatalf("PostgreSQL bounded run-log read = %+v, %v", page, err)
	}
	reader := New(db, EnginePostgres)
	if err := reader.LoadPayloadEncryption(ctx, master, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := reader.GetRunLogs(ctx, "run_log_pg"); err != nil || len(got) != 2 || got[1] != secret {
		t.Fatalf("PostgreSQL restart read = %v, %v", got, err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO run_logs (run_id, seq, line) VALUES ($1, $2, $3)`,
		"run_log_pg", 2, "old-writer-private"); err == nil || !strings.Contains(err.Error(), "encrypted run log required") {
		t.Fatalf("PostgreSQL old writer bypassed run-log fence: %v", err)
	}
	if err := j.LogRunArtifactFence(ctx, "run_log_pg"); err != nil {
		t.Fatal(err)
	}
	var marker string
	if err := db.QueryRowContext(ctx, `SELECT line FROM run_logs WHERE run_id = $1 AND kind = 'artifact_fence'`,
		"run_log_pg").Scan(&marker); err != nil || strings.Contains(marker, WorkflowArtifactFenceRunLog) {
		t.Fatalf("PostgreSQL artifact marker at rest: err=%v plaintext=%t", err, strings.Contains(marker, WorkflowArtifactFenceRunLog))
	}
	if got, err := j.GetRunLogs(ctx, "run_log_pg"); err != nil || len(got) != 3 || got[2] != WorkflowArtifactFenceRunLog {
		t.Fatalf("PostgreSQL artifact marker read = %v, %v", got, err)
	}
}
