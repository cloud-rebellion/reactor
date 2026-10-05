package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/bright-interaction/reactor/internal/vault"
)

func TestProviderClientSecretIsIdentityBoundAndMigratesV1(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()
	for _, id := range []string{"provider-a", "provider-b"} {
		if err := st.UpsertProvider(ctx, Provider{
			ProviderID: id,
			Name:       id,
			AuthURL:    "https://accounts.example/auth",
			TokenURL:   "https://accounts.example/token",
			ClientID:   "client-" + id,
			Enabled:    true,
		}, "secret-"+id); err != nil {
			t.Fatal(err)
		}
	}
	var aBlob []byte
	if err := st.db.QueryRowContext(ctx, "SELECT client_secret_encrypted FROM oauth_providers WHERE provider_id = ?", "provider-a").Scan(&aBlob); err != nil {
		t.Fatal(err)
	}
	if len(aBlob) == 0 || aBlob[0] != vault.VersionV2 || bytes.Contains(aBlob, []byte("secret-provider-a")) {
		t.Fatalf("provider client secret is not bound encrypted data: version=%x", aBlob[0])
	}
	// A row-copy attack must fail authentication under provider-b's identity.
	if _, err := st.db.ExecContext(ctx, "UPDATE oauth_providers SET client_secret_encrypted = ? WHERE provider_id = ?", aBlob, "provider-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetProvider(ctx, "provider-b"); err == nil {
		t.Fatal("copied provider client-secret blob decrypted under another provider id")
	}

	// Existing v1 rows remain readable and are migrated on first access.
	legacy, err := vault.Encrypt(st.masterKey, []byte("legacy-provider-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE oauth_providers SET client_secret_encrypted = ? WHERE provider_id = ?", legacy, "provider-a"); err != nil {
		t.Fatal(err)
	}
	p, err := st.GetProvider(ctx, "provider-a")
	if err != nil || p.ClientSecret != "legacy-provider-secret" {
		t.Fatalf("legacy provider secret read: provider=%+v err=%v", p, err)
	}
	var migrated []byte
	if err := st.db.QueryRowContext(ctx, "SELECT client_secret_encrypted FROM oauth_providers WHERE provider_id = ?", "provider-a").Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if len(migrated) == 0 || migrated[0] != vault.VersionV2 {
		t.Fatalf("legacy provider secret was not migrated: version=%x", migrated[0])
	}
}

func TestConnectionTokenIsIdentityBoundAndMigratesV1(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.UpsertProvider(ctx, Provider{
		ProviderID: "provider",
		Name:       "provider",
		AuthURL:    "https://accounts.example/auth",
		TokenURL:   "https://accounts.example/token",
		Enabled:    true,
	}, ""); err != nil {
		t.Fatal(err)
	}
	a, err := st.upsertConnection(ctx, "acme", "provider", "account-a", "", tokenBlob{AccessToken: "access-a"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.upsertConnection(ctx, "acme", "provider", "account-b", "", tokenBlob{AccessToken: "access-b"})
	if err != nil {
		t.Fatal(err)
	}
	var aBlob []byte
	if err := st.db.QueryRowContext(ctx, "SELECT token_encrypted FROM oauth_connections WHERE id = ?", a.ID).Scan(&aBlob); err != nil {
		t.Fatal(err)
	}
	if len(aBlob) == 0 || aBlob[0] != vault.VersionV2 || bytes.Contains(aBlob, []byte("access-a")) {
		t.Fatalf("connection token is not bound encrypted data: version=%x", aBlob[0])
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE oauth_connections SET token_encrypted = ? WHERE id = ?", aBlob, b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Token(ctx, b.ID, "acme"); err == nil {
		t.Fatal("copied connection token blob decrypted under another connection identity")
	}

	legacyRaw, err := json.Marshal(tokenBlob{AccessToken: "legacy-access"})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := vault.Encrypt(st.masterKey, legacyRaw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE oauth_connections SET token_encrypted = ? WHERE id = ?", legacy, a.ID); err != nil {
		t.Fatal(err)
	}
	got, err := st.Token(ctx, a.ID, "acme")
	if err != nil || got != "legacy-access" {
		t.Fatalf("legacy connection token read: got=%q err=%v", got, err)
	}
	var migrated []byte
	if err := st.db.QueryRowContext(ctx, "SELECT token_encrypted FROM oauth_connections WHERE id = ?", a.ID).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if len(migrated) == 0 || migrated[0] != vault.VersionV2 {
		t.Fatalf("legacy connection token was not migrated: version=%x", migrated[0])
	}
}
