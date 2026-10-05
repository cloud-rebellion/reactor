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
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
)

func TestPostgresStepPayloadEnvelopeAndOldWriterCutover(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for PostgreSQL step encryption test")
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
	schema := fmt.Sprintf("step_payload_%d", time.Now().UnixNano())
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
	if err := j.CreateWorkflowInTenant(ctx, "wf_step_pg", "step-pg", "h", "0.1.0", []byte(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_step_pg", "wf_step_pg", "manual", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordStepStartSeq(ctx, "run_step_pg", "legacy", 1, 1, "", "h"); err != nil {
		t.Fatal(err)
	}
	// The pre-key old writer holds a share lock on the migration gate. Key
	// initialization must wait for that transaction to commit, then reject
	// all later v0 outcome updates.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE steps SET output_jsonb = '{"before":true}'::jsonb
		WHERE run_id = 'run_step_pg' AND seq = 1`); err != nil {
		t.Fatal(err)
	}
	initDone := make(chan error, 1)
	master := bytes.Repeat([]byte{0x75}, 32)
	go func() { initDone <- j.EnablePayloadEncryption(ctx, master, nil) }()
	select {
	case err := <-initDone:
		t.Fatalf("key initialized before old step transaction committed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-initDone; err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE steps SET output_jsonb = '{"late":true}'::jsonb
		WHERE run_id = 'run_step_pg' AND seq = 1`); err == nil || !strings.Contains(err.Error(), "encrypted step required") {
		t.Fatalf("old PostgreSQL writer bypassed step fence: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO steps
		(run_id, step_name, seq, attempt, input_hash, status, started_at, output_jsonb)
		VALUES ('run_step_pg', 'direct-insert', 9, 1, 'h', 'succeeded', now(), '{"secret":"old binary"}'::jsonb)`); err == nil || !strings.Contains(err.Error(), "encrypted step required") {
		t.Fatalf("old PostgreSQL direct INSERT bypassed step fence: %v", err)
	}
	for _, seq := range []int64{2, 3} {
		if _, err := j.RecordStepStartSeq(ctx, "run_step_pg", "repeat", seq, 1, "idem", "hash"); err != nil {
			t.Fatal(err)
		}
		output := json.RawMessage(fmt.Sprintf(` { "private": "pg-only-value", "seq": %d } `, seq))
		if err := j.RecordStepEndSeq(ctx, "run_step_pg", "repeat", seq, 1, output, ""); err != nil {
			t.Fatal(err)
		}
		got, _, err := j.FindCachedOutputBySeq(ctx, "run_step_pg", seq)
		if err != nil || !bytes.Equal(got, output) {
			t.Fatalf("PostgreSQL exact replay seq %d = %q, %v", seq, got, err)
		}
	}
	var stored []byte
	if err := db.QueryRowContext(ctx, `SELECT output_jsonb FROM steps
		WHERE run_id = 'run_step_pg' AND seq = 2`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("pg-only-value")) {
		t.Fatalf("PostgreSQL output persisted plaintext: %q", stored)
	}
	page, chars, err := j.ReadStepOutputPageForTenant(ctx, "run_step_pg", "acme", "repeat", 2, 1, 2, 8)
	if err != nil || chars < 20 || len(page.OutputJSONB) != 8 {
		t.Fatalf("PostgreSQL exact page = %q / %d, %v", page.OutputJSONB, chars, err)
	}
	if steps, err := j.ListStepsPageForTenantBounded(ctx, "run_step_pg", "foreign", 10, 0, 64, 64); err != nil || len(steps) != 0 {
		t.Fatalf("foreign PostgreSQL step scope = %+v, %v", steps, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE steps SET output_jsonb = $1::jsonb
		WHERE run_id = 'run_step_pg' AND seq = 2`, stored); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE steps SET output_jsonb = (SELECT output_jsonb FROM steps
		WHERE run_id = 'run_step_pg' AND seq = 3) WHERE run_id = 'run_step_pg' AND seq = 2`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.FindCachedOutputBySeq(ctx, "run_step_pg", 2); err == nil {
		t.Fatal("cross-ordinal ciphertext swap authenticated")
	}
}
