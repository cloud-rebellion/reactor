package migrate

import (
	"context"
	"database/sql"
	"io/fs"
	"log/slog"
	"path/filepath"
	"testing"

	dbpkg "github.com/bright-interaction/reactor/internal/db"
	"github.com/pressly/goose/v3"
)

func TestWorkflowArtifactPinsUpgradeRollbackReapply(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	dbPath := filepath.Join(t.TempDir(), "artifact-pins.db")
	url := "sqlite://" + dbPath
	if err := upTo(ctx, log, url, 30); err != nil {
		t.Fatalf("migrate to 0030: %v", err)
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
	if _, err := db.ExecContext(ctx, `INSERT INTO workflow_versions
		(workflow_id, version, sdk_version, code_hash, dag_json) VALUES (?,?,?,?,?)`,
		"wf_legacy", 1, "0.1.0", "h", `{}`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO runs
		(id, workflow_id, tenant_id, trigger_kind, trigger_meta, status) VALUES (?,?,?,?,?,?)`,
		"run_legacy", "wf_legacy", "default", "manual", `{}`, "suspended"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	assertUp := func(label string) {
		t.Helper()
		if err := upTo(ctx, log, url, 31); err != nil {
			t.Fatalf("%s migrate to 0031: %v", label, err)
		}
		db, err := sql.Open("sqlite", sqliteDSNWithPragmas(dbPath))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		var versionPin, runPin sql.NullString
		if err := db.QueryRowContext(ctx, `SELECT artifact_sha256 FROM workflow_versions
			WHERE workflow_id=? AND version=1`, "wf_legacy").Scan(&versionPin); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, `SELECT workflow_artifact_sha256 FROM runs WHERE id=?`, "run_legacy").Scan(&runPin); err != nil {
			t.Fatal(err)
		}
		if versionPin.Valid || runPin.Valid {
			t.Fatalf("%s legacy rows were assigned guessed artifact pins: version=%v run=%v", label, versionPin, runPin)
		}
		if _, err := db.ExecContext(ctx, `UPDATE workflow_versions SET artifact_sha256=? WHERE workflow_id=?`, "ABC", "wf_legacy"); err == nil {
			t.Fatalf("%s artifact CHECK accepted non-canonical digest", label)
		}
	}

	assertUp("first")
	if err := downSQLiteTo(ctx, log, url, 30); err != nil {
		t.Fatalf("rollback 0031: %v", err)
	}
	assertUp("reapply")
}

func downSQLiteTo(ctx context.Context, log *slog.Logger, rawURL string, version int64) error {
	db, _, err := Open(rawURL)
	if err != nil {
		return err
	}
	defer db.Close()
	sub, err := fs.Sub(dbpkg.Migrations, "migrations/sqlite")
	if err != nil {
		return err
	}
	gooseMu.Lock()
	defer gooseMu.Unlock()
	goose.SetBaseFS(sub)
	goose.SetLogger(gooseSlogAdapter{log: log})
	if err := goose.SetDialect("sqlite3"); err != nil {
		return err
	}
	return goose.DownToContext(ctx, db, ".", version)
}
