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

func TestPostgresCommandDefinitionEnvelopeAndOldWriterCutover(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for PostgreSQL command definition test")
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
	schema := fmt.Sprintf("command_definition_crypto_%d", time.Now().UnixNano())
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
	definition := []byte(`{"steps":[{"name":"check","command":"printf pg-private-command","purpose":"Check private output","timeout_seconds":30}]}`)
	legacy, err := j.CreateCommandAutomation(ctx, "acme", "cmd_pg_def_legacy", "pg-def-legacy", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	commandWebhookCredential(t, j, "cred_pg_def_crypto", "acme")
	if err := j.CreateWorkflowInTenant(ctx, "wf_pg_def_source", "pg-def-source", "h", "0.1.0", []byte(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x71}, 32), nil); err != nil {
		t.Fatal(err)
	}
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_pg_def_crypto", "pg-def-crypto", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	var cryptoVersion, plainBytes int
	var digest string
	if err := db.QueryRowContext(ctx, `SELECT definition_json::text, definition_crypto_version, definition_plaintext_bytes, definition_sha256
		FROM command_automation_versions WHERE automation_id = $1 AND version = 1`, plan.ID).Scan(&stored, &cryptoVersion, &plainBytes, &digest); err != nil {
		t.Fatal(err)
	}
	if cryptoVersion != 1 || plainBytes < 1 || digest != commandDefinitionDigest(t, definition) || strings.Contains(stored, "pg-private-command") {
		t.Fatalf("PG command definition persisted plaintext: version=%d bytes=%d digest=%q", cryptoVersion, plainBytes, digest)
	}
	if _, err := j.GetCommandAutomationVersion(ctx, "acme", plan.ID, 1); err != nil {
		t.Fatalf("PG exact keyed definition: %v", err)
	}
	if _, err := j.GetCommandAutomationVersion(ctx, "acme", legacy.ID, 1); err != nil {
		t.Fatalf("PG historical definition: %v", err)
	}
	if _, err := j.CreateCommandAutomationSchedule(ctx, "acme", commandScheduleInput(t, "acme", plan, definition, "alice")); err != nil {
		t.Fatalf("PG encrypted schedule binding: %v", err)
	}
	if _, err := j.CreateCommandAutomationWebhookTrigger(ctx, "acme", commandWebhookInput(t, "acme", plan, definition, "cred_pg_def_crypto", "cmdwhk_pg_def_crypto")); err != nil {
		t.Fatalf("PG encrypted webhook binding: %v", err)
	}
	if _, err := j.CreateCommandAutomationChainTrigger(ctx, "acme", commandChainInput(t, "acme", plan, definition, "wf_pg_def_source")); err != nil {
		t.Fatalf("PG encrypted chain binding: %v", err)
	}
	enableCommandPlanForRun(t, j, ctx, plan)
	admission := boundCommandRunAdmission(t, "acme", plan.ID, 1, definition, strings.Repeat("d", 64), "alice")
	if _, err := j.CreateCommandRun(ctx, "acme", "cmdrun_pg_def_crypto", plan.ID, 1, admission); err != nil {
		t.Fatalf("PG encrypted run admission: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO command_automation_versions (automation_id, version, definition_json)
		VALUES ($1, 2, $2)`, legacy.ID, string(definition)); err == nil || !strings.Contains(err.Error(), "encrypted command definition required") {
		t.Fatalf("PG old writer inserted plaintext definition: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE command_automation_versions SET definition_json = $1 WHERE automation_id = $2 AND version = 1`,
		strings.Replace(string(definition), "pg-private-command", "changed-command", 1), legacy.ID); err == nil || !strings.Contains(err.Error(), "encrypted command definition required") {
		t.Fatalf("PG old writer changed historical definition: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE command_automation_versions
		SET definition_json = $1, definition_crypto_version = 0, definition_plaintext_bytes = NULL, definition_sha256 = NULL
		WHERE automation_id = $2 AND version = 1`, string(definition), plan.ID); err == nil {
		t.Fatal("PG encrypted definition downgraded to plaintext")
	}
	legacyBefore, err := j.GetCommandAutomationVersion(ctx, "acme", legacy.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	legacySummaryBefore, _, err := j.ListCommandAutomationVersionSummariesPage(ctx, "acme", legacy.ID, 1, 0)
	if err != nil || len(legacySummaryBefore) != 1 {
		t.Fatalf("PG legacy summary = %+v, %v", legacySummaryBefore, err)
	}
	converted, more, err := j.BackfillLegacyCommandDefinitions(ctx, 1)
	if err != nil || converted != 1 || more {
		t.Fatalf("PG command definition backfill converted=%d more=%v err=%v", converted, more, err)
	}
	legacyAfter, err := j.GetCommandAutomationVersion(ctx, "acme", legacy.ID, 1)
	if err != nil || !bytes.Equal(legacyAfter.DefinitionJSON, legacyBefore.DefinitionJSON) {
		t.Fatalf("PG exact legacy definition changed after backfill: %v", err)
	}
	legacySummaryAfter, _, err := j.ListCommandAutomationVersionSummariesPage(ctx, "acme", legacy.ID, 1, 0)
	if err != nil || len(legacySummaryAfter) != 1 ||
		legacySummaryAfter[0].DefinitionSHA256 != legacySummaryBefore[0].DefinitionSHA256 {
		t.Fatalf("PG review digest changed after backfill: %+v, %v", legacySummaryAfter, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT definition_json::text, definition_crypto_version,
		definition_plaintext_bytes, definition_sha256 FROM command_automation_versions
		WHERE automation_id = $1 AND version = 1`, legacy.ID).
		Scan(&stored, &cryptoVersion, &plainBytes, &digest); err != nil {
		t.Fatal(err)
	}
	if cryptoVersion != 1 || plainBytes != len(legacyBefore.DefinitionJSON) ||
		strings.Contains(stored, "pg-private-command") {
		t.Fatalf("PG historical definition remained plaintext after backfill: version=%d bytes=%d", cryptoVersion, plainBytes)
	}
}
