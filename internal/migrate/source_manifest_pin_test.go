package migrate

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
)

func TestSourceManifestPinMigrationOnlyGrantsLegacyPolicyToExistingVersions(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "source-pin.db")
	if err := upTo(ctx, log, dbURL, 55); err != nil {
		t.Fatal(err)
	}
	db, _, err := Open(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO workflows
		(id, tenant_id, slug, code_hash, sdk_version, dag_json) VALUES (?,?,?,?,?,?)`,
		"wf_source_migration", "default", "source-migration", "h", "0.1.0", `{}`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO workflow_versions
		(workflow_id, version, sdk_version, code_hash, artifact_sha256, dag_json) VALUES (?,?,?,?,?,?)`,
		"wf_source_migration", 1, "0.1.0", "h", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", `{}`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := upTo(ctx, log, dbURL, 56); err != nil {
		t.Fatal(err)
	}
	db, _, err = Open(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var legacyPin sql.NullString
	var legacyPolicy int
	if err := db.QueryRowContext(ctx, `SELECT source_manifest_sha256, source_proof_version
		FROM workflow_versions WHERE workflow_id=? AND version=1`, "wf_source_migration").Scan(&legacyPin, &legacyPolicy); err != nil {
		t.Fatal(err)
	}
	if legacyPin.Valid || legacyPolicy != 1 {
		t.Fatalf("old row source proof = pin:%v policy:%d, want null/1", legacyPin, legacyPolicy)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO workflow_versions
		(workflow_id, version, sdk_version, code_hash, artifact_sha256, dag_json) VALUES (?,?,?,?,?,?)`,
		"wf_source_migration", 2, "0.1.0", "h", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", `{}`); err != nil {
		t.Fatal(err)
	}
	var newPolicy int
	if err := db.QueryRowContext(ctx, `SELECT source_proof_version FROM workflow_versions
		WHERE workflow_id=? AND version=2`, "wf_source_migration").Scan(&newPolicy); err != nil {
		t.Fatal(err)
	}
	if newPolicy != 2 {
		t.Fatalf("new unpinned row policy = %d, want strict policy 2", newPolicy)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO workflow_versions
		(workflow_id, version, sdk_version, code_hash, artifact_sha256, source_manifest_sha256, dag_json) VALUES (?,?,?,?,?,?,?)`,
		"wf_source_migration", 3, "0.1.0", "h", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "invalid", `{}`); err == nil {
		t.Fatal("invalid source manifest digest passed schema check")
	}
}
