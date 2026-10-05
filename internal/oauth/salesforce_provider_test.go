package oauth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Existing connections migrated by 0062 are explicitly legacy_raw. Insert a
// fixture in that state instead of downgrading a new broker-only connection.
func insertLegacyRawTestConnection(st *Store, tenantID, providerID, name string, token tokenBlob) (Connection, error) {
	enc, err := st.saveTokenBlob(connectionTokenIdentity(tenantID, providerID, name), token)
	if err != nil {
		return Connection{}, err
	}
	id := newID("conn_")
	_, err = st.db.ExecContext(context.Background(), st.bind(`INSERT INTO oauth_connections
		(id, tenant_id, provider_id, name, token_encrypted, expires_at, status, token_access_mode, legacy_raw_reason)
		VALUES ($1,$2,$3,$4,$5,$6,'connected','legacy_raw','grandfathered')`),
		id, tenantID, providerID, name, enc, st.timeVal(token.Expiry))
	return Connection{ID: id, TenantID: tenantID, ProviderID: providerID, Name: name,
		TokenAccessMode: "legacy_raw", Status: "connected"}, err
}

func TestKnownSalesforceOAuthEndpoint(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"https://login.salesforce.com/services/oauth2/authorize",
		"https://TEST.SALESFORCE.COM:443/services/oauth2/token",
		"https://acme--dev.sandbox.my.salesforce.com/services/oauth2/token",
		"https://acme.my.site.com/services/oauth2/authorize",
		"https://acme.force.com/services/oauth2/token",
		"https://login.salesforce.com./services/oauth2/token",
	} {
		if !isKnownSalesforceOAuthEndpoint(raw) {
			t.Errorf("known Salesforce endpoint %q was not classified", raw)
		}
	}
	for _, raw := range []string{
		"https://accounts.example.test/services/oauth2/token",
		"https://login.salesforce.com.evil.test/services/oauth2/token",
		"https://acme.my.site.com.evil.test/services/oauth2/token",
		"https://force.com.evil.test/services/oauth2/token",
	} {
		if isKnownSalesforceOAuthEndpoint(raw) {
			t.Errorf("unrelated host %q was classified as Salesforce", raw)
		}
	}
}

func TestProviderAliasesCannotRegisterKnownSalesforceEndpoints(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()
	base := Provider{
		ProviderID: "custom-crm", Name: "CRM",
		AuthURL:  "https://accounts.example.test/authorize",
		TokenURL: "https://accounts.example.test/token", Enabled: true,
	}
	if err := st.UpsertProvider(ctx, base, ""); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []Provider{
		{ProviderID: base.ProviderID, AuthURL: "https://login.salesforce.com/services/oauth2/authorize", TokenURL: base.TokenURL},
		{ProviderID: base.ProviderID, AuthURL: base.AuthURL, TokenURL: "https://test.salesforce.com/services/oauth2/token"},
		{ProviderID: "site-alias", AuthURL: "https://acme.my.site.com/services/oauth2/authorize", TokenURL: base.TokenURL},
	} {
		if err := st.UpsertProvider(ctx, candidate, ""); err == nil {
			t.Fatalf("alias %q accepted Salesforce endpoint", candidate.ProviderID)
		}
	}
	stored, err := st.GetProvider(ctx, base.ProviderID)
	if err != nil || stored.AuthURL != base.AuthURL || stored.TokenURL != base.TokenURL {
		t.Fatalf("rejected update changed provider: %+v, %v", stored, err)
	}
	if err := st.UpsertProvider(ctx, Provider{
		ProviderID: "salesforce", Name: "Salesforce",
		AuthURL:  "https://login.salesforce.com/services/oauth2/authorize",
		TokenURL: "https://login.salesforce.com/services/oauth2/token", Enabled: true,
	}, ""); err != nil {
		t.Fatalf("canonical Salesforce provider rejected: %v", err)
	}
}

func TestRawTokenAllowedChecksExistingProviderEndpoints(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.UpsertProvider(ctx, Provider{
		ProviderID: "other", Name: "Other",
		AuthURL:  "https://accounts.example.test/authorize",
		TokenURL: "https://accounts.example.test/token", Enabled: true,
	}, ""); err != nil {
		t.Fatal(err)
	}
	conn, err := insertLegacyRawTestConnection(st, "tenant-a", "other", "account", tokenBlob{AccessToken: "opaque", Expiry: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := st.RawTokenAllowed(ctx, conn.ID, "tenant-a")
	if err != nil || !allowed {
		t.Fatalf("unrelated OAuth provider denied: allowed=%v err=%v", allowed, err)
	}
	if token, err := st.RawToken(ctx, conn.ID, "tenant-a"); err != nil || token != "opaque" {
		t.Fatalf("unrelated raw OAuth token = %q, %v", token, err)
	}
	if allowed, err := st.RawTokenAllowed(ctx, conn.ID, "tenant-b"); allowed || !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant policy lookup = %v, %v", allowed, err)
	}
	// Simulate an alias registered before this rule, or an out-of-band edit.
	if _, err := st.db.ExecContext(ctx, st.bind(`UPDATE oauth_providers SET token_url = $1 WHERE provider_id = $2`),
		"https://login.salesforce.com/services/oauth2/token", "other"); err != nil {
		t.Fatal(err)
	}
	if allowed, err := st.RawTokenAllowed(ctx, conn.ID, "tenant-a"); err != nil || allowed {
		t.Fatalf("existing Salesforce alias allowed: allowed=%v err=%v", allowed, err)
	}
	if token, err := st.RawToken(ctx, conn.ID, "tenant-a"); token != "" || !errors.Is(err, ErrRawTokenDenied) {
		t.Fatalf("existing alias raw token = %q, %v", token, err)
	}
	if _, err := st.db.ExecContext(ctx, st.bind(`UPDATE oauth_providers SET token_url = $1, auth_url = $2 WHERE provider_id = $3`),
		"https://accounts.example.test/token", "https://acme.my.site.com/services/oauth2/authorize", "other"); err != nil {
		t.Fatal(err)
	}
	if allowed, err := st.RawTokenAllowed(ctx, conn.ID, "tenant-a"); err != nil || allowed {
		t.Fatalf("existing Experience Cloud alias allowed: allowed=%v err=%v", allowed, err)
	}
}

func TestRawTokenRechecksProviderAfterTokenResolution(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.UpsertProvider(ctx, Provider{
		ProviderID: "other", Name: "Other",
		AuthURL:  "https://accounts.example.test/authorize",
		TokenURL: "https://accounts.example.test/token", Enabled: true,
	}, ""); err != nil {
		t.Fatal(err)
	}
	conn, err := insertLegacyRawTestConnection(st, "tenant-a", "other", "account", tokenBlob{
		AccessToken: "not-for-child", Expiry: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	var updateErr error
	st.now = func() time.Time {
		// RawTokenAllowed has already passed. Change the provider while Token
		// checks freshness, before RawToken's final joined read.
		once.Do(func() {
			_, updateErr = st.db.ExecContext(ctx, st.bind(`UPDATE oauth_providers SET token_url=$1 WHERE provider_id=$2`),
				"https://login.salesforce.com/services/oauth2/token", "other")
		})
		return time.Now()
	}
	token, err := st.RawToken(ctx, conn.ID, "tenant-a")
	if updateErr != nil {
		t.Fatal(updateErr)
	}
	if token != "" || !errors.Is(err, ErrRawTokenDenied) {
		t.Fatalf("provider changed during token resolution: token=%q err=%v", token, err)
	}
}

func TestRawTokenRechecksProviderDisabledDuringResolution(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.UpsertProvider(ctx, Provider{ProviderID: "other", Name: "Other",
		AuthURL: "https://accounts.example.test/authorize", TokenURL: "https://accounts.example.test/token", Enabled: true}, ""); err != nil {
		t.Fatal(err)
	}
	conn, err := insertLegacyRawTestConnection(st, "tenant-a", "other", "account", tokenBlob{
		AccessToken: "must-not-release", Expiry: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	var updateErr error
	st.now = func() time.Time {
		once.Do(func() {
			_, updateErr = st.db.ExecContext(ctx, `UPDATE oauth_providers SET enabled=0 WHERE provider_id='other'`)
		})
		return time.Now()
	}
	token, err := st.RawToken(ctx, conn.ID, "tenant-a")
	if updateErr != nil {
		t.Fatal(updateErr)
	}
	if token != "" || !errors.Is(err, ErrRawTokenDenied) {
		t.Fatalf("disabled provider released token=%q err=%v", token, err)
	}
}

func TestRawTokenRechecksConnectionStatusAfterTokenResolution(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.UpsertProvider(ctx, Provider{
		ProviderID: "other", Name: "Other",
		AuthURL:  "https://accounts.example.test/authorize",
		TokenURL: "https://accounts.example.test/token", Enabled: true,
	}, ""); err != nil {
		t.Fatal(err)
	}
	conn, err := insertLegacyRawTestConnection(st, "tenant-a", "other", "account", tokenBlob{
		AccessToken: "not-for-child", Expiry: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	var updateErr error
	st.now = func() time.Time {
		// Simulate revocation after policy preflight, while Token checks
		// freshness. The final joined read must see the revoked status.
		once.Do(func() {
			_, updateErr = st.db.ExecContext(ctx, st.bind(`UPDATE oauth_connections SET status=$1 WHERE id=$2`),
				"revoked", conn.ID)
		})
		return time.Now()
	}
	token, err := st.RawToken(ctx, conn.ID, "tenant-a")
	if updateErr != nil {
		t.Fatal(updateErr)
	}
	if token != "" || !errors.Is(err, ErrRawTokenDenied) {
		t.Fatalf("connection revoked during token resolution: token=%q err=%v", token, err)
	}
}
