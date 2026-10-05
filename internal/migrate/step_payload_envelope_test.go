package migrate

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dbpkg "github.com/bright-interaction/reactor/internal/db"
	"github.com/pressly/goose/v3"
)

func TestSQLiteStepPayloadRollbackGuard(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rawURL := "sqlite://" + filepath.Join(t.TempDir(), "step-migration.db")
	if err := upTo(ctx, log, rawURL, 61); err != nil {
		t.Fatal(err)
	}
	db, _, err := Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `INSERT INTO workflows
		(id, tenant_id, slug, code_hash, sdk_version, dag_json) VALUES ('wf_step_down', 'default', 'step-down', 'h', '0.1.0', '{}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO runs
		(id, workflow_id, tenant_id, trigger_kind, trigger_meta, status)
		VALUES ('run_step_down', 'wf_step_down', 'default', 'manual', '{}', 'queued')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO steps
		(run_id, step_name, seq, attempt, input_hash, status, started_at,
		 payload_crypto_version, output_jsonb, output_plaintext_bytes)
		VALUES ('run_step_down', 'step', 1, 1, 'h', 'succeeded', '2026-01-01T00:00:00Z', 1, '{}', 2)`); err != nil {
		t.Fatal(err)
	}
	if err := downSQLiteTo(ctx, log, rawURL, 60); err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
		t.Fatalf("SQLite rollback with encrypted step = %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM steps WHERE run_id = 'run_step_down'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO journal_payload_keys (id, wrapped_key) VALUES ('v1', x'01')`); err != nil {
		t.Fatal(err)
	}
	if err := downSQLiteTo(ctx, log, rawURL, 60); err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
		t.Fatalf("SQLite rollback with active key = %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM journal_payload_keys WHERE id = 'v1'`); err != nil {
		t.Fatal(err)
	}
	if err := downSQLiteTo(ctx, log, rawURL, 60); err != nil {
		t.Fatalf("SQLite rollback after removing encrypted row and inactive key: %v", err)
	}
}

func TestPostgresStepPayloadRollbackGuard(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for PostgreSQL migration test")
	}
	engine, err := EngineFromURL(rawURL)
	if err != nil || engine != EnginePostgres {
		t.Fatalf("test URL must be PostgreSQL: %v", err)
	}
	u, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(strings.ToLower(strings.Trim(u.Path, "/")), "test") {
		t.Fatal("test database name must contain test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	base, _, err := Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	schema := fmt.Sprintf("step_migration_%d", time.Now().UnixNano())
	if _, err := base.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer base.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	scopedURL := u.String()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := upTo(ctx, log, scopedURL, 61); err != nil {
		t.Fatal(err)
	}
	db, _, err := Open(scopedURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `INSERT INTO workflows
		(id, tenant_id, slug, code_hash, sdk_version, dag_json)
		VALUES ('wf_step_down_pg', 'default', 'step-down-pg', 'h', '0.1.0', '{}'::jsonb)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO runs
		(id, workflow_id, tenant_id, trigger_kind, trigger_meta, status)
		VALUES ('run_step_down_pg', 'wf_step_down_pg', 'default', 'manual', '{}'::jsonb, 'queued')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO steps
		(run_id, step_name, seq, attempt, input_hash, status, started_at,
		 payload_crypto_version, output_jsonb, output_plaintext_bytes)
		VALUES ('run_step_down_pg', 'step', 1, 1, 'h', 'succeeded', now(), 1, '{}'::jsonb, 2)`); err != nil {
		t.Fatal(err)
	}
	down := func() error {
		sub, err := fs.Sub(dbpkg.Migrations, "migrations/postgres")
		if err != nil {
			return err
		}
		gooseMu.Lock()
		defer gooseMu.Unlock()
		goose.SetBaseFS(sub)
		goose.SetLogger(gooseSlogAdapter{log: log})
		if err := goose.SetDialect("postgres"); err != nil {
			return err
		}
		return goose.DownToContext(ctx, db, ".", 60)
	}
	if err := down(); err == nil || !strings.Contains(err.Error(), "cannot roll back step payload encryption") {
		t.Fatalf("PostgreSQL rollback with encrypted step = %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM steps WHERE run_id = 'run_step_down_pg'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO journal_payload_keys (id, wrapped_key) VALUES ('v1', $1)`, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := down(); err == nil || !strings.Contains(err.Error(), "journal key is active") {
		t.Fatalf("PostgreSQL rollback with active key = %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM journal_payload_keys WHERE id = 'v1'`); err != nil {
		t.Fatal(err)
	}
	if err := down(); err != nil {
		t.Fatalf("PostgreSQL rollback after removing encrypted row and inactive key: %v", err)
	}
}
