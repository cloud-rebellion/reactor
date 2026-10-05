package migrate

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	dbpkg "github.com/bright-interaction/reactor/internal/db"
	"github.com/pressly/goose/v3"
)

func TestPostgresRunPayloadMigrationRollbackGuard(t *testing.T) {
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
	schema := fmt.Sprintf("payload_migration_%d", time.Now().UnixNano())
	if _, err := base.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer base.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	scopedURL := u.String()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := upTo(ctx, log, scopedURL, 60); err != nil {
		t.Fatal(err)
	}
	db, _, err := Open(scopedURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `INSERT INTO workflows
		(id, tenant_id, slug, code_hash, sdk_version, dag_json)
		VALUES ('wf_payload_rollback_pg', 'default', 'payload-rollback-pg', 'h', '0.1.0', '{}'::jsonb)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO runs
		(id, workflow_id, trigger_kind, trigger_meta, status, tenant_id, payload_crypto_version, payload_plaintext_bytes)
		VALUES ('run_payload_rollback_pg', 'wf_payload_rollback_pg', 'manual', '{}'::jsonb, 'queued', 'default', 1, 2)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO journal_payload_keys (id, wrapped_key) VALUES ('v1', $1)`, []byte("fake-wrap")); err != nil {
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
		return goose.DownToContext(ctx, db, ".", 59)
	}
	if err := down(); err == nil || !strings.Contains(err.Error(), "cannot roll back run payload encryption") {
		t.Fatalf("rollback with v1 row = %v", err)
	}
	var version int
	if err := db.QueryRowContext(ctx, `SELECT payload_crypto_version FROM runs WHERE id = 'run_payload_rollback_pg'`).Scan(&version); err != nil || version != 1 {
		t.Fatalf("failed rollback damaged row: version=%d err=%v", version, err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM runs WHERE id = 'run_payload_rollback_pg'`); err != nil {
		t.Fatal(err)
	}
	if err := down(); err != nil {
		t.Fatalf("rollback after removing encrypted row: %v", err)
	}
}
