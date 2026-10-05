package commandrunner

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/vault"
)

type fakeCredentialGrants struct {
	allowed map[string]bool
}

func (f fakeCredentialGrants) HasCommandGrant(_ context.Context, _, _, credentialID string) (bool, error) {
	return f.allowed[credentialID], nil
}

type fakeCredentialTenants map[string]string

func (f fakeCredentialTenants) SecretTenant(_ context.Context, credentialID string) (string, error) {
	tenant, ok := f[credentialID]
	if !ok {
		return "", errors.New("missing")
	}
	return tenant, nil
}

type fakeCredentialVault map[string][]byte

func (f fakeCredentialVault) Get(_ context.Context, id string) (*vault.Secret, error) {
	value, ok := f[id]
	if !ok {
		return nil, vault.ErrNotFound
	}
	return vault.NewSecret(value), nil
}

type fakeOAuthResolver map[string]string

func (f fakeOAuthResolver) RawTokenAllowed(_ context.Context, connectionID, tenantID string) (bool, error) {
	if tenantID != "acme" {
		return false, errors.New("wrong tenant")
	}
	_, ok := f[connectionID]
	return ok, nil
}

func (f fakeOAuthResolver) RawToken(ctx context.Context, connectionID, tenantID string) (string, error) {
	allowed, err := f.RawTokenAllowed(ctx, connectionID, tenantID)
	if err != nil {
		return "", err
	}
	value, ok := f[connectionID]
	if !allowed || !ok {
		return "", errors.New("missing")
	}
	return value, nil
}

type deniedRawOAuthResolver struct{ rawCalls int }

func (*deniedRawOAuthResolver) RawTokenAllowed(context.Context, string, string) (bool, error) {
	return false, nil
}

func (r *deniedRawOAuthResolver) RawToken(context.Context, string, string) (string, error) {
	r.rawCalls++
	return "must-not-release", nil
}

func TestVaultCredentialMaterializerRequiresTenantAndCommandGrant(t *testing.T) {
	m := VaultCredentialMaterializer{
		Grants:  fakeCredentialGrants{allowed: map[string]bool{"cred_api": true}},
		Tenants: fakeCredentialTenants{"cred_api": "acme"},
		Vault:   fakeCredentialVault{"cred_api": []byte("api-token")},
	}
	mat, err := m.Materialize(context.Background(), "acme", "cmd_1", 1, 1, []string{"cred_api"})
	if err != nil || len(mat.Bindings) != 1 || string(mat.Bindings[0].Value) != "api-token" {
		t.Fatalf("materialize = %+v err=%v", mat, err)
	}
	if mat.Bindings[0].Environment != CredentialEnvironmentName("cred_api") {
		t.Fatalf("environment = %q", mat.Bindings[0].Environment)
	}
	mat.Clear()
	if len(mat.Bindings) != 0 {
		t.Fatalf("clear retained bindings: %+v", mat.Bindings)
	}
	if _, err := m.Materialize(context.Background(), "other", "cmd_1", 1, 1, []string{"cred_api"}); err == nil {
		t.Fatal("cross-tenant materialization unexpectedly succeeded")
	}
	m.Grants = fakeCredentialGrants{allowed: map[string]bool{}}
	if _, err := m.Materialize(context.Background(), "acme", "cmd_1", 1, 1, []string{"cred_api"}); err == nil {
		t.Fatal("ungranted materialization unexpectedly succeeded")
	}
}

func TestVaultCredentialMaterializerOAuthUsesTenantScopedResolver(t *testing.T) {
	m := VaultCredentialMaterializer{
		Grants:      fakeCredentialGrants{allowed: map[string]bool{"oauth:conn": true}},
		Tenants:     fakeCredentialTenants{"oauth:conn": "acme"},
		OAuthTokens: fakeOAuthResolver{"conn": "oauth-token"},
	}
	if !m.SupportsForTenant(context.Background(), "acme", "oauth:conn") || m.SupportsForTenant(context.Background(), "other", "oauth:conn") {
		t.Fatal("tenant-scoped OAuth resolver support was incorrect")
	}
	mat, err := m.Materialize(context.Background(), "acme", "cmd_1", 1, 1, []string{"oauth:conn"})
	if err != nil || len(mat.Bindings) != 1 || string(mat.Bindings[0].Value) != "oauth-token" {
		t.Fatalf("oauth materialize = %+v err=%v", mat, err)
	}
	mat.Clear()
	withoutResolver := m
	withoutResolver.OAuthTokens = nil
	if _, err := withoutResolver.Materialize(context.Background(), "acme", "cmd_1", 1, 1, []string{"oauth:conn"}); err == nil {
		t.Fatal("oauth materialization without resolver unexpectedly succeeded")
	}
}

func TestVaultCredentialMaterializerRejectsBrokerOnlyOAuthBeforeRunAndStep(t *testing.T) {
	resolver := &deniedRawOAuthResolver{}
	m := VaultCredentialMaterializer{
		Grants:      fakeCredentialGrants{allowed: map[string]bool{"oauth:conn": true}},
		Tenants:     fakeCredentialTenants{"oauth:conn": "acme"},
		OAuthTokens: resolver,
	}
	ids := []string{"oauth:conn"}
	if m.SupportsForTenant(context.Background(), "acme", ids[0]) {
		t.Fatal("broker-only connection appeared usable by the command resolver")
	}
	if err := m.Check(context.Background(), "acme", "cmd_1", 1, ids); err == nil || !strings.Contains(err.Error(), "host-brokered") {
		t.Fatalf("broker-only OAuth preflight = %v, want refusal", err)
	}
	mat, err := m.Materialize(context.Background(), "acme", "cmd_1", 1, 1, ids)
	if err == nil || !strings.Contains(err.Error(), "host-brokered") || len(mat.Bindings) != 0 || resolver.rawCalls != 0 {
		t.Fatalf("broker-only OAuth materialization = %+v, %v, raw calls=%d; want refusal before token fetch", mat, err, resolver.rawCalls)
	}
}

func TestVaultCredentialMaterializerRejectsOversizedValues(t *testing.T) {
	t.Parallel()
	m := VaultCredentialMaterializer{
		Grants:  fakeCredentialGrants{allowed: map[string]bool{"cred_api": true, "oauth:conn": true}},
		Tenants: fakeCredentialTenants{"cred_api": "acme", "oauth:conn": "acme"},
		Vault:   fakeCredentialVault{"cred_api": bytes.Repeat([]byte("x"), vault.MaxSecretBytes+1)},
		OAuthTokens: fakeOAuthResolver{
			"conn": strings.Repeat("y", vault.MaxSecretBytes+1),
		},
	}
	if _, err := m.Materialize(context.Background(), "acme", "cmd_1", 1, 1, []string{"cred_api"}); err == nil || !strings.Contains(err.Error(), "maximum supported size") {
		t.Fatalf("oversized vault value err=%v", err)
	}
	if _, err := m.Materialize(context.Background(), "acme", "cmd_1", 1, 1, []string{"oauth:conn"}); err == nil || !strings.Contains(err.Error(), "maximum supported size") {
		t.Fatalf("oversized oauth value err=%v", err)
	}
}
