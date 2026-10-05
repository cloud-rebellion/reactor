package journal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
)

func TestPostgresDeadLetterEncryptedConcurrentOrderAndCutover(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for PostgreSQL dead-letter encryption test")
	}
	engine, err := migrate.EngineFromURL(rawURL)
	if err != nil || engine != migrate.EnginePostgres {
		t.Fatalf("test URL must be PostgreSQL: %v", err)
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
	schema := fmt.Sprintf("dlq_payload_%d", time.Now().UnixNano())
	if _, err := base.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer base.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	scopedURL := u.String()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(ctx, log, scopedURL); err != nil {
		t.Fatal(err)
	}
	db, _, err := migrate.Open(scopedURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j := New(db, EnginePostgres)
	if err := j.CreateWorkflowInTenant(ctx, "wf_dlq_pg", "dlq-pg", "h", "0.1.0", []byte(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_dlq_pg", "wf_dlq_pg", "manual", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	// A transaction already writing v0 must finish before first-key setup.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO dead_letter
		(id, run_id, step_name, failure_order, error_text, payload)
		VALUES ('dlq_pre_key', 'run_dlq_pg', 'legacy', 1, 'pre-key', '{}'::jsonb)`); err != nil {
		t.Fatal(err)
	}
	initDone := make(chan error, 1)
	go func() { initDone <- j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x68}, 32), nil) }()
	select {
	case err := <-initDone:
		t.Fatalf("key initialized before old DLQ transaction committed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-initDone; err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO dead_letter
		(id, run_id, step_name, failure_order, error_text, payload)
		VALUES ('dlq_late_v0', 'run_dlq_pg', 'late', 2, 'private', '{}'::jsonb)`); err == nil || !strings.Contains(err.Error(), "encrypted dead_letter required") {
		t.Fatalf("old PostgreSQL writer bypassed DLQ fence: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE dead_letter SET error_text = 'late' WHERE id = 'dlq_pre_key'`); err == nil || !strings.Contains(err.Error(), "encrypted dead_letter required") {
		t.Fatalf("old PostgreSQL update bypassed DLQ fence: %v", err)
	}
	const parallel = 8
	var wg sync.WaitGroup
	errs := make(chan error, parallel)
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func(seq int) {
			defer wg.Done()
			errs <- j.MoveStepAttemptToDeadLetter(ctx, "run_dlq_pg", "send", int64(seq), 1,
				"private-pg-failure", json.RawMessage(fmt.Sprintf(` { "private": "pg-%d" } `, seq)))
		}(i + 1)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent keyed DLQ write: %v", err)
		}
	}
	items, err := j.ListDeadLetterItemsForTenant(ctx, 20, 0, "acme")
	if err != nil || len(items) != parallel+1 {
		t.Fatalf("PostgreSQL DLQ inventory = %d, %v", len(items), err)
	}
	orders := make(map[int64]bool)
	for _, item := range items {
		if orders[item.FailureOrder] || item.FailureOrder < 1 || item.FailureOrder > parallel+1 {
			t.Fatalf("duplicate or nonmonotonic DLQ order: %+v", items)
		}
		orders[item.FailureOrder] = true
		if item.ID == "dlq_pre_key" {
			continue
		}
		if item.ErrorText != "private-pg-failure" || !bytes.Contains(item.Payload, []byte(`"private"`)) {
			t.Fatalf("PostgreSQL keyed DLQ read = %+v", item)
		}
		var storedError string
		var storedPayload []byte
		var version int
		if err := db.QueryRowContext(ctx, `SELECT error_text, payload, payload_crypto_version
			FROM dead_letter WHERE id = $1`, item.ID).Scan(&storedError, &storedPayload, &version); err != nil {
			t.Fatal(err)
		}
		if version != 1 || strings.Contains(storedError, "private-pg-failure") || bytes.Contains(storedPayload, []byte("pg-")) {
			t.Fatalf("PostgreSQL DLQ plaintext at rest: error=%q payload=%q version=%d", storedError, storedPayload, version)
		}
		if _, err := db.ExecContext(ctx, `UPDATE dead_letter SET error_text = 'plaintext' WHERE id = $1`, item.ID); err == nil {
			t.Fatal("old PostgreSQL writer replaced keyed DLQ error with plaintext")
		}
		if _, err := db.ExecContext(ctx, `UPDATE dead_letter SET payload = '{}'::jsonb WHERE id = $1`, item.ID); err == nil {
			t.Fatal("old PostgreSQL writer replaced keyed DLQ payload with plaintext")
		}
	}
}
