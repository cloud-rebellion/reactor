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

func TestPostgresCommandExecutionPayloadAndOldWriterCutover(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for PostgreSQL command payload test")
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
	schema := fmt.Sprintf("command_crypto_%d", time.Now().UnixNano())
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
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_pg_crypto", "pg-crypto", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, plan)
	admission := boundCommandRunAdmission(t, "acme", plan.ID, 1, definition, strings.Repeat("c", 64), "alice")
	run, err := j.CreateCommandRun(ctx, "acme", "cmdrun_pg_crypto", plan.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x5c}, 32), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE command_run_steps SET stdout_text = $1 WHERE run_id = $2 AND step_seq = 1`, "old-writer-private", run.ID); err == nil || !strings.Contains(err.Error(), "encrypted command output required") {
		t.Fatalf("old PG step writer = %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE command_runs SET error_text = $1 WHERE id = $2`, "old-writer-private", run.ID); err == nil || !strings.Contains(err.Error(), "encrypted command output required") {
		t.Fatalf("old PG run writer = %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO command_run_step_attempts
		(run_id, step_seq, attempt, claim_owner, claim_token, status, started_at, updated_at, stdout_text)
		VALUES ($1, 1, 9, 'old-worker', 'old-token', 'running', now(), now(), 'old-insert-private')`, run.ID); err == nil || !strings.Contains(err.Error(), "encrypted command output required") {
		t.Fatalf("old PG attempt insert = %v", err)
	}
	claim, err := j.ClaimCommandRun(ctx, run.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	step, err := j.ClaimCommandRunStep(ctx, run.ID, "worker-a", claim.ClaimToken, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.AppendCommandRunStepOutput(ctx, run.ID, "worker-a", claim.ClaimToken, 1, step.Attempt, "stdout", []byte("postgres-private-output")); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordCommandRunStepResult(ctx, run.ID, "worker-a", claim.ClaimToken, 1, step.Attempt, 1, nil, nil, "postgres-private-error"); err != nil {
		t.Fatal(err)
	}
	if err := j.FinishCommandRun(ctx, run.ID, "worker-a", claim.ClaimToken, CommandRunFailed, "postgres-private-run-error"); err != nil {
		t.Fatal(err)
	}
	var out, runError string
	var outVersion, runVersion int
	if err := db.QueryRowContext(ctx, `SELECT stdout_text, stdout_crypto_version FROM command_run_steps WHERE run_id = $1 AND step_seq = 1`, run.ID).Scan(&out, &outVersion); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT error_text, error_crypto_version FROM command_runs WHERE id = $1`, run.ID).Scan(&runError, &runVersion); err != nil {
		t.Fatal(err)
	}
	if outVersion != 1 || runVersion != 1 || strings.Contains(out, "postgres-private-output") || strings.Contains(runError, "postgres-private-run-error") {
		t.Fatalf("PG plaintext persisted: versions=%d/%d", outVersion, runVersion)
	}
	page, err := j.ReadCommandRunDiagnosticPageForTenant(ctx, "acme", run.ID, CommandDiagnosticStdout, 1, 1, 0, 32)
	if err != nil || string(page.Content) != "postgres-private-output" {
		t.Fatalf("PG diagnostic = %+v, %v", page, err)
	}
	got, err := j.GetCommandRunForTenant(ctx, "acme", run.ID)
	if err != nil || got.ErrorText != "postgres-private-run-error" {
		t.Fatalf("PG run = %+v, %v", got, err)
	}
}
