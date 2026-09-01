package migrate

import (
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	dbpkg "github.com/bright-interaction/reactor/internal/db"
)

func TestTriggerTenantBackfillUsesWorkflowOwnerAndOnlyDedicatedCredentials(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	dbPath := filepath.Join(t.TempDir(), "trigger-tenant.db")
	dbURL := "sqlite://" + dbPath
	if err := upTo(ctx, log, dbURL, 29); err != nil {
		t.Fatalf("migrate to 0029: %v", err)
	}
	db, err := sql.Open("sqlite", sqliteDSNWithPragmas(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, workflow := range []struct{ id, tenant, slug string }{
		{id: "wf_acme", tenant: "acme", slug: "acme-flow"},
		{id: "wf_globex", tenant: "globex", slug: "globex-flow"},
	} {
		if _, err := db.ExecContext(ctx, `INSERT INTO workflows
			(id, tenant_id, slug, code_hash, sdk_version, dag_json)
			VALUES (?, ?, ?, 'hash', '1', '{}')`, workflow.id, workflow.tenant, workflow.slug); err != nil {
			t.Fatalf("seed workflow %s: %v", workflow.id, err)
		}
	}
	for _, credential := range []struct {
		id, service, provider string
	}{
		{id: "cred_dedicated", service: "reactor-webhook", provider: "shared-secret"},
		{id: "cred_shared", service: "reactor-webhook", provider: "shared-secret"},
		{id: "cred_operator", service: "operator-managed", provider: "shared-secret"},
		{id: "cred_collision", service: "reactor-webhook", provider: "shared-secret"},
	} {
		if _, err := db.ExecContext(ctx, `INSERT INTO credentials
			(id, tenant_id, name, service, blob, provider)
			VALUES (?, 'default', ?, ?, X'01', ?)`,
			credential.id, credential.id, credential.service, credential.provider); err != nil {
			t.Fatalf("seed credential %s: %v", credential.id, err)
		}
	}
	// This name already exists in acme, so moving the default-tenant source row
	// there would violate UNIQUE(tenant_id, name). The migration must skip it
	// rather than block the entire production upgrade.
	if _, err := db.ExecContext(ctx, `INSERT INTO credentials
		(id, tenant_id, name, service, blob, provider)
		VALUES ('cred_collision_existing', 'acme', 'cred_collision', 'operator-managed', X'01', 'manual')`); err != nil {
		t.Fatalf("seed target-tenant name collision: %v", err)
	}
	for _, trigger := range []struct {
		id, workflow, kind, token, secret string
	}{
		{id: "trg_dedicated", workflow: "wf_acme", kind: "webhook", token: "whk_dedicated", secret: "cred_dedicated"},
		{id: "trg_shared_acme", workflow: "wf_acme", kind: "webhook", token: "whk_shared_a", secret: "cred_shared"},
		{id: "trg_shared_globex", workflow: "wf_globex", kind: "webhook", token: "whk_shared_g", secret: "cred_shared"},
		{id: "trg_operator", workflow: "wf_acme", kind: "webhook", token: "whk_operator", secret: "cred_operator"},
		{id: "trg_collision", workflow: "wf_acme", kind: "webhook", token: "whk_collision", secret: "cred_collision"},
		{id: "trg_cron", workflow: "wf_globex", kind: "cron"},
	} {
		if _, err := db.ExecContext(ctx, `INSERT INTO triggers
			(id, tenant_id, workflow_id, kind, token_id, secret_id)
			VALUES (?, 'default', ?, ?, NULLIF(?, ''), NULLIF(?, ''))`,
			trigger.id, trigger.workflow, trigger.kind, trigger.token, trigger.secret); err != nil {
			t.Fatalf("seed trigger %s: %v", trigger.id, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if err := upTo(ctx, log, dbURL, 30); err != nil {
		t.Fatalf("migrate 0029 -> 0030: %v", err)
	}
	db, err = sql.Open("sqlite", sqliteDSNWithPragmas(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for triggerID, wantTenant := range map[string]string{
		"trg_dedicated":     "acme",
		"trg_shared_acme":   "acme",
		"trg_shared_globex": "globex",
		"trg_operator":      "acme",
		"trg_collision":     "acme",
		"trg_cron":          "globex",
	} {
		var got string
		if err := db.QueryRowContext(ctx, `SELECT tenant_id FROM triggers WHERE id = ?`, triggerID).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != wantTenant {
			t.Errorf("trigger %s tenant = %q, want %q", triggerID, got, wantTenant)
		}
	}
	for credentialID, wantTenant := range map[string]string{
		"cred_dedicated":          "acme",
		"cred_shared":             "default",
		"cred_operator":           "default",
		"cred_collision":          "default",
		"cred_collision_existing": "acme",
	} {
		var got string
		if err := db.QueryRowContext(ctx, `SELECT tenant_id FROM credentials WHERE id = ?`, credentialID).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != wantTenant {
			t.Errorf("credential %s tenant = %q, want %q", credentialID, got, wantTenant)
		}
	}
}

func TestTriggerTenantBackfillMigrationsStayMirrored(t *testing.T) {
	t.Parallel()
	pg, err := dbpkg.Migrations.ReadFile("migrations/postgres/0030_trigger_tenant_backfill.sql")
	if err != nil {
		t.Fatal(err)
	}
	sqlite, err := dbpkg.Migrations.ReadFile("migrations/sqlite/0030_trigger_tenant_backfill.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"UPDATE triggers",
		"workflows.id = triggers.workflow_id",
		"service = 'reactor-webhook'",
		"provider = 'shared-secret'",
		"SELECT COUNT(*)",
	} {
		if !strings.Contains(string(pg), required) {
			t.Errorf("postgres 0030 missing %q", required)
		}
		if !strings.Contains(string(sqlite), required) {
			t.Errorf("sqlite 0030 missing %q", required)
		}
	}
}
