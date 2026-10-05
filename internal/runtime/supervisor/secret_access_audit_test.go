package supervisor

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/vault"
)

type revokeGrantAfterOAuthResolution struct {
	stubOAuthResolver
	revoke func(context.Context) error
}

func (r revokeGrantAfterOAuthResolution) RawToken(ctx context.Context, connectionID, tenantID string) (string, error) {
	token, err := r.stubOAuthResolver.RawToken(ctx, connectionID, tenantID)
	if err != nil {
		return "", err
	}
	if err := r.revoke(ctx); err != nil {
		return "", err
	}
	return token, nil
}

func TestVaultSecretFetchAuditsBeforeValueRelease(t *testing.T) {
	j, v, db := newACLEnv(t)
	ctx := context.Background()
	if err := j.GrantSecret(ctx, "wf_acl", "cred_secret", "admin", ""); err != nil {
		t.Fatal(err)
	}
	sup := &Supervisor{
		WorkflowSlug: "acl-test", RunID: "run_acl", Mode: "live", Journal: j, Vault: v,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	first := fetchSecret(t, sup, "cred_secret")
	if first.NotFound || string(first.Value) != "the-plaintext" {
		t.Fatalf("granted fetch = %+v", first)
	}
	rows, err := j.ListRuntimeSecretAccessForTenant(ctx, journal.DefaultTenant, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].RunID != "run_acl" || rows[0].WorkflowID != "wf_acl" ||
		rows[0].SecretRef != "cred_secret" || rows[0].SecretKind != "vault" || rows[0].At.IsZero() {
		t.Fatalf("vault access receipt = %+v", rows)
	}
	raw, _ := json.Marshal(rows)
	if strings.Contains(string(raw), "the-plaintext") || strings.Contains(string(raw), first.Fingerprint) && first.Fingerprint != "" {
		t.Fatalf("runtime audit stored secret material: %s", raw)
	}
	// Remove only the audit store. Tenant identity, grant, and vault remain
	// healthy, so the second denial proves the receipt is a release gate.
	if _, err := db.ExecContext(ctx, `DROP TABLE runtime_secret_access_audit`); err != nil {
		t.Fatal(err)
	}
	second := fetchSecret(t, sup, "cred_secret")
	if !second.NotFound || len(second.Value) != 0 || second.Fingerprint != "" {
		t.Fatalf("vault value crossed wire without durable audit: %+v", second)
	}
}

func TestSecretFetchOnlyRevealsDuringLiveExecution(t *testing.T) {
	j, v, _ := newACLEnv(t)
	ctx := context.Background()
	if err := j.GrantSecret(ctx, "wf_acl", "cred_secret", "admin", ""); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"dry_run", "replay", ""} {
		t.Run(mode, func(t *testing.T) {
			sup := &Supervisor{
				WorkflowSlug: "acl-test", RunID: "run_acl", Mode: mode,
				Journal: j, Vault: v, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}
			reply := fetchSecret(t, sup, "cred_secret")
			if !reply.NotFound || len(reply.Value) != 0 || reply.Fingerprint != "" {
				t.Fatalf("mode %q released a live secret: %+v", mode, reply)
			}
		})
	}
	receipts, err := j.ListRuntimeSecretAccessForTenant(ctx, journal.DefaultTenant, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 0 {
		t.Fatalf("non-live secret fetches wrote access receipts: %+v", receipts)
	}
}

func TestSecretFetchDeniesWhenLiveRunIsNoLongerExecuting(t *testing.T) {
	for _, state := range []struct {
		name      string
		status    string
		cancelled bool
	}{
		{name: "queued", status: "queued"},
		{name: "suspended", status: "suspended"},
		{name: "succeeded", status: "succeeded"},
		{name: "failed", status: "failed"},
		{name: "cancelled", status: "cancelled"},
		{name: "cancel_requested", status: "running", cancelled: true},
	} {
		t.Run(state.name, func(t *testing.T) {
			j, v, db := newACLEnv(t)
			ctx := context.Background()
			if err := j.GrantSecret(ctx, "wf_acl", "cred_secret", "admin", ""); err != nil {
				t.Fatal(err)
			}
			cancelled := 0
			if state.cancelled {
				cancelled = 1
			}
			if _, err := db.ExecContext(ctx,
				`UPDATE runs SET status = ?, cancel_requested = ? WHERE id = ?`,
				state.status, cancelled, "run_acl"); err != nil {
				t.Fatal(err)
			}
			sup := &Supervisor{
				WorkflowSlug: "acl-test", RunID: "run_acl", Mode: "live", Journal: j, Vault: v,
				Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}
			reply := fetchSecret(t, sup, "cred_secret")
			if !reply.NotFound || len(reply.Value) != 0 || reply.Fingerprint != "" {
				t.Fatalf("run status %q, cancellation %t released a secret: %+v", state.status, state.cancelled, reply)
			}
			receipts, err := j.ListRuntimeSecretAccessForTenant(ctx, journal.DefaultTenant, 10, 0)
			if err != nil || len(receipts) != 0 {
				t.Fatalf("inactive run wrote release receipts: %+v, %v", receipts, err)
			}
		})
	}
}

func TestOAuthSecretFetchAuditsBeforeTokenRelease(t *testing.T) {
	ctx := context.Background()
	j, db := oauthACLFixture(t, "tenant-a", "tenant-a")
	if err := j.GrantSecret(ctx, "wf_1", "oauth:conn_abc", "admin", ""); err != nil {
		t.Fatal(err)
	}
	v, err := vault.NewStore(vault.NewMemoryBackend(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sup := &Supervisor{
		WorkflowSlug: "mailer", RunID: "run_1", Mode: "live", Journal: j, Vault: v,
		OAuthTokens: stubOAuthResolver{token: strings.Join([]string{"ya29.P", "RIVATE"}, ""), wantTenant: "tenant-a"},
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	first := fetchSecret(t, sup, "oauth:conn_abc")
	if first.NotFound || string(first.Value) != "ya29.PRIVATE" {
		t.Fatalf("granted oauth fetch = %+v", first)
	}
	rows, err := j.ListRuntimeSecretAccessForTenant(ctx, "tenant-a", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].SecretRef != "oauth:conn_abc" || rows[0].SecretKind != "oauth" || rows[0].TenantID != "tenant-a" {
		t.Fatalf("oauth access receipt = %+v", rows)
	}
	foreign, err := j.ListRuntimeSecretAccessForTenant(ctx, "tenant-b", 10, 0)
	if err != nil || len(foreign) != 0 {
		t.Fatalf("foreign tenant audit view = %+v, %v", foreign, err)
	}
	raw, _ := json.Marshal(rows)
	if strings.Contains(string(raw), "ya29.PRIVATE") {
		t.Fatalf("runtime audit stored oauth token: %s", raw)
	}
	if _, err := db.ExecContext(ctx, `DROP TABLE runtime_secret_access_audit`); err != nil {
		t.Fatal(err)
	}
	second := fetchSecret(t, sup, "oauth:conn_abc")
	if !second.NotFound || len(second.Value) != 0 {
		t.Fatalf("oauth token crossed wire without durable audit: %+v", second)
	}
}

func TestOAuthSecretFetchDeniesGrantRevokedDuringTokenResolution(t *testing.T) {
	for _, tc := range []struct {
		name       string
		permissive bool
	}{
		{name: "strict"},
		{name: "legacy-permissive", permissive: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			j, _ := oauthACLFixture(t, "tenant-a", "tenant-a")
			if err := j.GrantSecret(ctx, "wf_1", "oauth:conn_abc", "admin", ""); err != nil {
				t.Fatal(err)
			}
			v, err := vault.NewStore(vault.NewMemoryBackend(), make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			revoked := false
			sup := &Supervisor{
				WorkflowSlug: "mailer", RunID: "run_1", Mode: "live", Journal: j, Vault: v,
				ACLPermissive: tc.permissive,
				OAuthTokens: revokeGrantAfterOAuthResolution{
					stubOAuthResolver: stubOAuthResolver{token: strings.Join([]string{"ya29.P", "RIVATE"}, ""), wantTenant: "tenant-a"},
					revoke: func(ctx context.Context) error {
						revoked = true
						return j.RevokeSecret(ctx, "wf_1", "oauth:conn_abc")
					},
				},
				Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}
			reply := fetchSecret(t, sup, "oauth:conn_abc")
			if !revoked || !reply.NotFound || len(reply.Value) != 0 || reply.Fingerprint != "" {
				t.Fatalf("revocation during token resolution released a value: revoked=%t reply=%+v", revoked, reply)
			}
		})
	}
}

func TestOAuthSecretFetchDeniesAfterRunCancellationRequested(t *testing.T) {
	ctx := context.Background()
	j, db := oauthACLFixture(t, "tenant-a", "tenant-a")
	if err := j.GrantSecret(ctx, "wf_1", "oauth:conn_abc", "admin", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE runs SET cancel_requested = 1 WHERE id = ?`, "run_1"); err != nil {
		t.Fatal(err)
	}
	v, err := vault.NewStore(vault.NewMemoryBackend(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sup := &Supervisor{
		WorkflowSlug: "mailer", RunID: "run_1", Mode: "live", Journal: j, Vault: v,
		OAuthTokens: stubOAuthResolver{token: strings.Join([]string{"ya29.P", "RIVATE"}, ""), wantTenant: "tenant-a"},
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	reply := fetchSecret(t, sup, "oauth:conn_abc")
	if !reply.NotFound || len(reply.Value) != 0 || reply.Fingerprint != "" {
		t.Fatalf("cancel-requested run released OAuth token: %+v", reply)
	}
	receipts, err := j.ListRuntimeSecretAccessForTenant(ctx, "tenant-a", 10, 0)
	if err != nil || len(receipts) != 0 {
		t.Fatalf("cancel-requested run wrote token release receipt: %+v, %v", receipts, err)
	}
}
