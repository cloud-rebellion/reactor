package migrate

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestMailSendInventoryMigrationBackfillsExistingIntentTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	rawURL := "sqlite://" + filepath.Join(t.TempDir(), "mail-intent-backfill.db")
	if err := upTo(ctx, log, rawURL, 74); err != nil {
		t.Fatal(err)
	}
	db, engine, err := Open(rawURL)
	if err != nil || engine != EngineSQLite {
		t.Fatalf("open pre-upgrade DB: %v, %s", err, engine)
	}
	j := journal.New(db, journal.EngineSQLite)
	for _, tc := range []struct{ tenant, workflowID, runID string }{
		{"acme", "wf_mail_old_acme", "run_mail_old_acme"},
		{"other", "wf_mail_old_other", "run_mail_old_other"},
	} {
		if err := j.CreateWorkflowInTenant(ctx, tc.workflowID, "mail-old-"+tc.tenant, "hash", "0.1.0", json.RawMessage(`{}`), tc.tenant); err != nil {
			t.Fatal(err)
		}
		if err := j.CreateRun(ctx, tc.runID, tc.workflowID, "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO mail_send_intents
			(id, run_id, step_name, seq, attempt, idempotency_key_sha256, request_sha256, status, created_at)
			VALUES (?, ?, 'send', 1, 1, ?, ?, 'admitted', '2026-10-05T12:00:00.000Z')`,
			"intent_"+tc.tenant, tc.runID, strings.Repeat("a", 64), strings.Repeat("b", 64)); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := upTo(ctx, log, rawURL, 75); err != nil {
		t.Fatalf("upgrade existing mail intents: %v", err)
	}
	db, _, err = Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, tenant := range []string{"acme", "other"} {
		var got string
		if err := db.QueryRowContext(ctx, `SELECT tenant_id FROM mail_send_intents WHERE id = ?`, "intent_"+tenant).Scan(&got); err != nil || got != tenant {
			t.Fatalf("backfilled %s intent tenant = %q, %v", tenant, got, err)
		}
	}
	// A draining old process still writes the 0074 insert shape, omitting the
	// new tenant column. The database must stamp the run owner, not default.
	j = journal.New(db, journal.EngineSQLite)
	if err := j.CreateRun(ctx, "run_mail_legacy_writer", "wf_mail_old_acme", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO mail_send_intents
		(id, run_id, step_name, seq, attempt, idempotency_key_sha256, request_sha256, status, created_at)
		VALUES ('intent_legacy_writer', 'run_mail_legacy_writer', 'send', 1, 1, ?, ?, 'admitted', '2026-10-05T12:00:01.000Z')`,
		strings.Repeat("a", 64), strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := db.QueryRowContext(ctx, `SELECT tenant_id FROM mail_send_intents WHERE id = 'intent_legacy_writer'`).Scan(&got); err != nil || got != "acme" {
		t.Fatalf("legacy writer intent tenant = %q, %v", got, err)
	}
}
