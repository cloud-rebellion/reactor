package journal

import (
	"context"
	"errors"
	"testing"
)

func seedCommandGrantCredential(t *testing.T, j *Journal, id, tenant string) {
	t.Helper()
	if _, err := j.db.ExecContext(context.Background(), j.bind(
		`INSERT INTO credentials (id, tenant_id, name, service, blob) VALUES ($1,$2,$3,$4,$5)`),
		id, tenant, "name-"+id, "svc", []byte("x")); err != nil {
		t.Fatalf("seed credential %s: %v", id, err)
	}
}

func TestCommandSecretGrantsAreStrictAndTenantScoped(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	automation, err := j.CreateCommandAutomation(ctx, "acme", "cmd_grant_acme", "grant-plan", "", "", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.CreateCommandAutomation(ctx, "other", "cmd_grant_other", "grant-plan", "", "", "mallory", definition); err != nil {
		t.Fatal(err)
	}
	seedCommandGrantCredential(t, j, "cred_acme", "acme")
	seedCommandGrantCredential(t, j, "cred_other", "other")

	// A fresh or empty ACL is strict deny, with no ErrACLEmpty permissive mode.
	ok, err := j.HasCommandGrant(ctx, "acme", automation.ID, "cred_acme")
	if err != nil || ok {
		t.Fatalf("empty command ACL = ok=%v err=%v, want false,nil", ok, err)
	}
	if ok, err := j.HasCommandGrant(ctx, "acme", automation.ID, "missing"); err != nil || ok {
		t.Fatalf("missing credential = ok=%v err=%v, want false,nil", ok, err)
	}
	if ok, err := j.HasCommandGrant(ctx, "other", automation.ID, "cred_acme"); err != nil || ok {
		t.Fatalf("cross-tenant automation lookup = ok=%v err=%v, want false,nil", ok, err)
	}

	if err := j.GrantCommandSecret(ctx, "acme", automation.ID, "cred_acme", "alice", "backup access"); err != nil {
		t.Fatal(err)
	}
	if ok, err := j.HasCommandGrant(ctx, "acme", automation.ID, "cred_acme"); err != nil || !ok {
		t.Fatalf("granted command ACL = ok=%v err=%v, want true,nil", ok, err)
	}
	// Re-grant updates operator metadata without creating a second row.
	if err := j.GrantCommandSecret(ctx, "acme", automation.ID, "cred_acme", "bob", "updated"); err != nil {
		t.Fatal(err)
	}
	rows, more, err := j.ListCommandSecretGrantsPage(ctx, "acme", automation.ID, 10, 0)
	if err != nil || more || len(rows) != 1 {
		t.Fatalf("grant list = rows=%+v more=%v err=%v", rows, more, err)
	}
	if rows[0].AutomationID != automation.ID || rows[0].TenantID != "acme" || rows[0].CredentialID != "cred_acme" || rows[0].GrantedBy != "bob" || rows[0].Note != "updated" || rows[0].GrantedAt.IsZero() {
		t.Fatalf("grant row = %+v", rows[0])
	}

	// The resource-owner check rejects cross-tenant grant and missing targets.
	if err := j.GrantCommandSecret(ctx, "acme", automation.ID, "cred_other", "alice", ""); err == nil {
		t.Fatal("cross-tenant command grant should be refused")
	}
	if !errors.Is(j.GrantCommandSecret(ctx, "acme", "unknown", "cred_acme", "alice", ""), ErrGrantTarget) {
		t.Fatal("unknown automation command grant should return ErrGrantTarget")
	}
	if !errors.Is(j.GrantCommandSecret(ctx, "acme", automation.ID, "unknown", "alice", ""), ErrGrantTarget) {
		t.Fatal("unknown credential command grant should return ErrGrantTarget")
	}
	if rows, _, err := j.ListCommandSecretGrantsPage(ctx, "other", automation.ID, 10, 0); !errors.Is(err, ErrGrantTarget) || rows != nil {
		t.Fatalf("cross-tenant list = rows=%+v err=%v, want target error", rows, err)
	}

	if err := j.RevokeCommandSecret(ctx, "acme", automation.ID, "cred_acme"); err != nil {
		t.Fatal(err)
	}
	if ok, err := j.HasCommandGrant(ctx, "acme", automation.ID, "cred_acme"); err != nil || ok {
		t.Fatalf("revoked command ACL = ok=%v err=%v, want false,nil", ok, err)
	}
	if err := j.RevokeCommandSecret(ctx, "acme", automation.ID, "cred_acme"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke = %v, want ErrNotFound", err)
	}
}

func TestCommandSecretGrantListIsBoundedAndTenantScoped(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	first, err := j.CreateCommandAutomation(ctx, "acme", "cmd_grant_page_a", "grant-page-a", "", "", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	second, err := j.CreateCommandAutomation(ctx, "acme", "cmd_grant_page_b", "grant-page-b", "", "", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	seedCommandGrantCredential(t, j, "cred_page_a", "acme")
	seedCommandGrantCredential(t, j, "cred_page_b", "acme")
	if err := j.GrantCommandSecret(ctx, "acme", first.ID, "cred_page_a", "alice", ""); err != nil {
		t.Fatal(err)
	}
	if err := j.GrantCommandSecret(ctx, "acme", second.ID, "cred_page_b", "alice", ""); err != nil {
		t.Fatal(err)
	}
	rows, more, err := j.ListAllCommandSecretGrantsPage(ctx, "acme", 1, 0)
	if err != nil || !more || len(rows) != 1 {
		t.Fatalf("first inventory page = rows=%+v more=%v err=%v", rows, more, err)
	}
	rows, more, err = j.ListAllCommandSecretGrantsPage(ctx, "acme", 1, 1)
	if err != nil || more || len(rows) != 1 {
		t.Fatalf("second inventory page = rows=%+v more=%v err=%v", rows, more, err)
	}
	if rows[0].TenantID != "acme" {
		t.Fatalf("tenant leaked in inventory: %+v", rows[0])
	}
	if rows, more, err := j.ListCommandSecretGrantsPage(ctx, "acme", first.ID, 1, 0); err != nil || more || len(rows) != 1 {
		t.Fatalf("automation list = rows=%+v more=%v err=%v", rows, more, err)
	}
	if _, _, err := j.ListCommandSecretGrantsPage(ctx, "acme", first.ID, 501, 0); err == nil {
		t.Fatal("oversized command grant page should fail")
	}
}

func TestCommandSecretGrantSupportsOAuthNamespaceWithTenantFence(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"oauth","command":"true","purpose":"Use OAuth","timeout_seconds":30}]}`)
	automation, err := j.CreateCommandAutomation(ctx, "acme", "cmd_grant_oauth", "oauth-plan", "", "", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := j.db.ExecContext(ctx, j.bind(q), args...); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	mustExec(`INSERT INTO oauth_providers (provider_id, name, auth_url, token_url) VALUES ($1,$2,$3,$4)`, "provider_cmd", "Provider", "https://auth.example", "https://token.example")
	mustExec(`INSERT INTO oauth_connections (id, tenant_id, provider_id, name, token_encrypted) VALUES ($1,$2,$3,$4,$5)`, "conn_cmd", "acme", "provider_cmd", "connection", []byte("encrypted"))
	if err := j.GrantCommandSecret(ctx, "acme", automation.ID, "oauth:conn_cmd", "alice", "oauth access"); err != nil {
		t.Fatal(err)
	}
	if ok, err := j.HasCommandGrant(ctx, "acme", automation.ID, "oauth:conn_cmd"); err != nil || !ok {
		t.Fatalf("oauth grant = ok=%v err=%v", ok, err)
	}
	rows, more, err := j.ListCommandSecretGrantsPage(ctx, "acme", automation.ID, 10, 0)
	if err != nil || more || len(rows) != 1 || rows[0].CredentialID != "oauth:conn_cmd" {
		t.Fatalf("oauth list = rows=%+v more=%v err=%v", rows, more, err)
	}
}
