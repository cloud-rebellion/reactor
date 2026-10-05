package journal

import (
	"context"
	"encoding/json"
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

func TestPostgresReapExpiredLeasesBoundedBatch(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for the PostgreSQL reaper batch contract")
	}
	engine, err := migrate.EngineFromURL(rawURL)
	if err != nil || engine != migrate.EnginePostgres {
		t.Fatalf("test URL must be PostgreSQL: engine=%q err=%v", engine, err)
	}
	u, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(strings.ToLower(strings.Trim(u.Path, "/")), "test") {
		t.Fatal("PostgreSQL test database name must contain test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	base, _, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	schema := fmt.Sprintf("reap_batch_%d", time.Now().UnixNano())
	if _, err := base.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer base.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	scopedURL := u.String()
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), scopedURL); err != nil {
		t.Fatalf("migrate isolated PostgreSQL schema: %v", err)
	}
	db, engine, err := migrate.Open(scopedURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if engine != migrate.EnginePostgres {
		t.Fatalf("opened engine %q, want PostgreSQL", engine)
	}
	j := New(db, EnginePostgres)
	const workflowID = "wf_reap_batch_pg"
	if err := j.CreateWorkflow(ctx, workflowID, "reap-batch-pg", "hash", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	const prefix = "run_reap_batch_pg"
	liveRunID, liveOwner := seedReapBatch(t, ctx, j, workflowID, prefix)
	assertReapBatchDrains(t, ctx, j, prefix, liveRunID, liveOwner)

	// A row locked by a concurrent renewal must be skipped without blocking.
	// The next tick can recover it after that transaction releases the lock.
	const lockedRunID = "run_reap_batch_pg_locked"
	if err := j.CreateRun(ctx, lockedRunID, workflowID, "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO leases (run_id, worker_id, expires_at)
		VALUES ($1, $2, $3)`, lockedRunID, "locked-owner", time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	holder, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	var held string
	if err := holder.QueryRowContext(ctx, `SELECT run_id FROM leases WHERE run_id = $1 FOR UPDATE`, lockedRunID).Scan(&held); err != nil {
		t.Fatal(err)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 0 {
		t.Fatalf("locked expired lease reap = %d, %v; want skipped", n, err)
	}
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("unlocked expired lease reap = %d, %v; want one", n, err)
	}
}
