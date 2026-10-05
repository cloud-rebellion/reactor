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
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
)

func TestPostgresRunPayloadConcurrentKeyInitializationAndOldWriterFence(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for PostgreSQL encryption test")
	}
	engine, err := migrate.EngineFromURL(rawURL)
	if err != nil || engine != migrate.EnginePostgres {
		t.Fatalf("test URL must be PostgreSQL: %v", err)
	}
	u, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(strings.ToLower(strings.Trim(u.Path, "/")), "test") {
		t.Fatal("PostgreSQL test database name must contain test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	base, _, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	schema := fmt.Sprintf("payload_crypto_%d", time.Now().UnixNano())
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
		t.Fatalf("migrate isolated schema: %v", err)
	}
	db1, _, err := migrate.Open(scopedURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db1.Close()
	db2, _, err := migrate.Open(scopedURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	j1, j2 := New(db1, EnginePostgres), New(db2, EnginePostgres)
	master := bytes.Repeat([]byte{0x7d}, 32)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, j := range []*Journal{j1, j2} {
		wg.Add(1)
		go func(j *Journal) { defer wg.Done(); errs <- j.EnablePayloadEncryption(ctx, master, nil) }(j)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent key initialization: %v", err)
		}
	}
	var keyCount int
	if err := db1.QueryRowContext(ctx, `SELECT COUNT(*) FROM journal_payload_keys`).Scan(&keyCount); err != nil || keyCount != 1 {
		t.Fatalf("wrapped key count = %d, %v", keyCount, err)
	}
	const workflowID = "wf_payload_pg"
	if err := j1.CreateWorkflowInTenant(ctx, workflowID, "payload-pg", "h", "0.1.0", []byte(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	input := []byte(` { "secret": "postgres-isolated-synthetic" } `)
	if err := j1.CreateQueuedRun(ctx, "run_payload_pg", workflowID, "manual", input); err != nil {
		t.Fatal(err)
	}
	var rawMeta, rawInput []byte
	if err := db2.QueryRowContext(ctx, `SELECT trigger_meta, trigger_input FROM runs WHERE id = $1`, "run_payload_pg").Scan(&rawMeta, &rawInput); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawMeta, []byte("postgres-isolated-synthetic")) || bytes.Contains(rawInput, []byte("postgres-isolated-synthetic")) {
		t.Fatal("plaintext trigger data persisted in PostgreSQL")
	}
	got, err := j2.GetRun(ctx, "run_payload_pg")
	if err != nil || !bytes.Equal(got.ExecutionInput(), input) {
		t.Fatalf("cross-node replay = %q, %v", got.ExecutionInput(), err)
	}
	bounded, err := j2.GetRunForTenantInputBounded(ctx, "run_payload_pg", "acme", len(input))
	if err != nil || !bytes.Equal(bounded.ExecutionInput(), input) {
		t.Fatalf("cross-node bounded exact input = %q, %v", bounded.ExecutionInput(), err)
	}
	meta, err := j2.GetRunForTenantMetadata(ctx, "run_payload_pg", "acme", len(input))
	if err != nil || !bytes.Equal(meta.TriggerMeta, input) {
		t.Fatalf("cross-node bounded metadata = %q, %v", meta.TriggerMeta, err)
	}
	if _, err := db2.ExecContext(ctx, `INSERT INTO runs (id, workflow_id, trigger_kind, trigger_meta, status, tenant_id)
		VALUES ($1, $2, 'manual', '{}'::jsonb, 'queued', 'acme')`, "run_old_writer_pg", workflowID); err == nil || !strings.Contains(err.Error(), "encrypted run required") {
		t.Fatalf("old PostgreSQL writer was not fenced: %v", err)
	}
	if err := New(db2, EnginePostgres).EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x6c}, 32), nil); err == nil {
		t.Fatal("mismatched master created a second key")
	}
}
