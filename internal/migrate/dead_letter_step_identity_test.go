package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	dbpkg "github.com/bright-interaction/reactor/internal/db"
)

func TestDeadLetterStepIdentityUpgradeRollbackReapply(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	dbPath := filepath.Join(t.TempDir(), "dead-letter-identity.db")
	url := "sqlite://" + dbPath

	if err := upTo(ctx, log, url, 31); err != nil {
		t.Fatalf("migrate to 0031: %v", err)
	}
	db, err := sql.Open("sqlite", sqliteDSNWithPragmas(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO workflows
		(id, tenant_id, slug, code_hash, sdk_version, dag_json) VALUES (?,?,?,?,?,?)`,
		"wf_legacy", "default", "legacy", "h", "0.1.0", `{}`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO runs
		(id, workflow_id, tenant_id, trigger_kind, trigger_meta, status) VALUES (?,?,?,?,?,?)`,
		"run_legacy", "wf_legacy", "default", "manual", `{}`, "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	// Give both rows the same timestamp: 0032 must still backfill one stable,
	// unique per-run order rather than relying on wall-clock resolution.
	for _, row := range []struct{ id, step string }{{"dlq_a", "A"}, {"dlq_b", "B"}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO dead_letter
			(id, run_id, step_name, error_text, payload, moved_at) VALUES (?,?,?,?,?,?)`,
			row.id, "run_legacy", row.step, "boom", `{}`, "2026-09-01T10:00:00.000Z"); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	assertUp := func(label string) {
		t.Helper()
		if err := upTo(ctx, log, url, 32); err != nil {
			t.Fatalf("%s migrate to 0032: %v", label, err)
		}
		db, err := sql.Open("sqlite", sqliteDSNWithPragmas(dbPath))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		rows, err := db.QueryContext(ctx, `SELECT id, step_seq, step_attempt, failure_order
			FROM dead_letter WHERE run_id=? ORDER BY failure_order`, "run_legacy")
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for rows.Next() {
			var id string
			var seq, attempt sql.NullInt64
			var order int64
			if err := rows.Scan(&id, &seq, &attempt, &order); err != nil {
				t.Fatal(err)
			}
			if seq.Valid || attempt.Valid {
				t.Fatalf("%s legacy row %s gained guessed attempt identity", label, id)
			}
			got = append(got, fmt.Sprintf("%s:%d", id, order))
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		if strings.Join(got, ",") != "dlq_a:1,dlq_b:2" {
			t.Fatalf("%s failure-order backfill = %v", label, got)
		}

		if _, err := db.ExecContext(ctx, `INSERT INTO dead_letter
			(id, run_id, step_name, step_seq, step_attempt, failure_order, error_text, payload)
			VALUES (?,?,?,?,?,?,?,?)`, "dlq_exact", "run_legacy", "A", 7, 3, 3, "boom", `{}`); err != nil {
			t.Fatalf("%s insert exact identity: %v", label, err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO dead_letter
			(id, run_id, step_name, step_seq, step_attempt, failure_order, error_text, payload)
			VALUES (?,?,?,?,?,?,?,?)`, "dlq_duplicate", "run_legacy", "A", 7, 3, 4, "again", `{}`); err == nil {
			t.Fatalf("%s duplicate exact attempt was accepted", label)
		}
	}

	assertUp("first")
	if err := downSQLiteTo(ctx, log, url, 31); err != nil {
		t.Fatalf("rollback 0032: %v", err)
	}
	// The first assertion inserted an exact row. Rolling back intentionally
	// erases only its new identity/order columns; all DLQ payload rows survive.
	// Remove that extra row so the deterministic legacy backfill remains the
	// same two-row fixture on reapply.
	db, err = sql.Open("sqlite", sqliteDSNWithPragmas(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM dead_letter WHERE id=?`, "dlq_exact"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	assertUp("reapply")
}

func TestDeadLetterStepIdentityMigrationsStayMirrored(t *testing.T) {
	t.Parallel()
	pg, err := dbpkg.Migrations.ReadFile("migrations/postgres/0032_dead_letter_step_identity.sql")
	if err != nil {
		t.Fatal(err)
	}
	sqlite, err := dbpkg.Migrations.ReadFile("migrations/sqlite/0032_dead_letter_step_identity.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"step_seq", "step_attempt", "failure_order", "dead_letter_step_attempt_uidx", "dead_letter_failure_order_uidx"} {
		if !strings.Contains(string(pg), token) {
			t.Errorf("postgres 0032 missing %s", token)
		}
		if !strings.Contains(string(sqlite), token) {
			t.Errorf("sqlite 0032 missing %s", token)
		}
	}
}
