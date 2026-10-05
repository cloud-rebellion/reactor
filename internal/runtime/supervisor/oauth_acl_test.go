package supervisor

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/oauth"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/wire"
	"github.com/bright-interaction/reactor/internal/vault"
	_ "modernc.org/sqlite"
)

// stubOAuthResolver stands in for *oauth.Store. It enforces the same tenant
// scoping the real resolver does, so a test that reaches it proves the ACL let
// the fetch through rather than that the stub is permissive.
type stubOAuthResolver struct {
	token      string
	wantTenant string
	provider   string
	origin     string
	accountKey string
}

type noRawTokenResolver struct{ *oauth.Store }

func (noRawTokenResolver) RawToken(context.Context, string, string) (string, error) {
	panic("raw token resolution must not run for a Salesforce provider alias")
}

func (s stubOAuthResolver) Token(_ context.Context, _, tenantID string) (string, error) {
	if tenantID != s.wantTenant {
		return "", sql.ErrNoRows
	}
	return s.token, nil
}

func (s stubOAuthResolver) RawToken(ctx context.Context, connectionID, tenantID string) (string, error) {
	allowed, err := s.RawTokenAllowed(ctx, connectionID, tenantID)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", oauth.ErrRawTokenDenied
	}
	return s.Token(ctx, connectionID, tenantID)
}

func (s stubOAuthResolver) ConnectionProvider(_ context.Context, _, tenantID string) (string, error) {
	if tenantID != s.wantTenant {
		return "", sql.ErrNoRows
	}
	if s.provider != "" {
		return s.provider, nil
	}
	return "google", nil
}

func (s stubOAuthResolver) RawTokenAllowed(_ context.Context, _, tenantID string) (bool, error) {
	if tenantID != s.wantTenant {
		return false, sql.ErrNoRows
	}
	return s.provider != "salesforce", nil
}

func (s stubOAuthResolver) SalesforceSession(_ context.Context, _, tenantID string) (string, string, error) {
	if tenantID != s.wantTenant || s.provider != "salesforce" {
		return "", "", sql.ErrNoRows
	}
	return s.token, s.origin, nil
}

func (s stubOAuthResolver) SalesforceBrokerSession(_ context.Context, _, tenantID string) (string, string, string, error) {
	if tenantID != s.wantTenant || s.provider != "salesforce" {
		return "", "", "", sql.ErrNoRows
	}
	key := s.accountKey
	if key == "" {
		key = strings.Repeat("a", 64)
	}
	return s.token, s.origin, key, nil
}

func (s stubOAuthResolver) SalesforceBrokerSessionCurrent(_ context.Context, _, tenantID, token, origin, accountKey string) (bool, error) {
	if tenantID != s.wantTenant || s.provider != "salesforce" {
		return false, nil
	}
	key := s.accountKey
	if key == "" {
		key = strings.Repeat("a", 64)
	}
	return token == s.token && origin == s.origin && accountKey == key, nil
}

func (s stubOAuthResolver) GenericBrokerSession(context.Context, string, string) (oauth.BrokerSession, error) {
	return oauth.BrokerSession{}, oauth.ErrBrokerPolicyUnavailable
}

func (s stubOAuthResolver) BrokerPolicyCurrent(context.Context, oauth.BrokerSession) (bool, error) {
	return false, nil
}

func (s stubOAuthResolver) ConnectionActive(_ context.Context, tenantID, _, providerID string) (bool, error) {
	return tenantID == s.wantTenant && providerID == s.provider, nil
}

// oauthACLFixture builds a migrated db with one workflow + run in wfTenant and
// one oauth connection in connTenant, and returns the journal.
func oauthACLFixture(t *testing.T, wfTenant, connTenant string) (*journal.Journal, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "oauth.db")
	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(ctx, silent, "sqlite://"+dbPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	j := journal.New(db, journal.EngineSQLite)

	if err := j.CreateWorkflowInTenant(ctx, "wf_1", "mailer", "h", "0.1.0", json.RawMessage(`{}`), wfTenant); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_1", "wf_1", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO oauth_providers (provider_id, name, auth_url, token_url, enabled) VALUES (?,?,?,?,1)`,
		"google", "Google", "https://example.test/auth", "https://example.test/token"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO oauth_connections (id, tenant_id, provider_id, name, token_encrypted, token_access_mode, legacy_raw_reason) VALUES (?,?,?,?,?,'legacy_raw','grandfathered')`,
		"conn_abc", connTenant, "google", "work", []byte("sealed")); err != nil {
		t.Fatal(err)
	}
	return j, db
}

func fetchSecret(t *testing.T, sup *Supervisor, id string) wire.SecretReply {
	t.Helper()
	var buf bytes.Buffer
	disp := &dispatcher{sup: sup, enc: wire.NewEncoder(&buf), writeMu: &sync.Mutex{}}
	req, err := wire.Wrap(1, 0, wire.KindSecretFetch, wire.SecretFetch{ID: id})
	if err != nil {
		t.Fatal(err)
	}
	if err := disp.handleSecretFetch(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	frame, err := wire.NewDecoder(&buf).Decode()
	if err != nil {
		t.Fatal(err)
	}
	var sr wire.SecretReply
	if err := wire.Unwrap(frame, &sr); err != nil {
		t.Fatal(err)
	}
	return sr
}

// TestOAuthSecretFetchWorksUnderStrictACL pins the regression where the whole
// Connections feature was inert on a default install.
//
// The tenant defence-in-depth check called CredentialTenant() with the literal
// "oauth:<connection-id>" string. That id never names a credentials row, so the
// lookup returned ErrNotFound and the fetch was denied before the oauth branch
// below it ever ran. GrantSecret refused the grant for the same reason, so the
// operator could not even express the authorisation. Net effect: `oauth:` ids
// only worked with REACTOR_VAULT_ACL_PERMISSIVE=1, which opens the entire vault
// to every workflow.
//
// The two id namespaces live in different tables (credentials vs
// oauth_connections), so every ownership lookup has to dispatch on the prefix.
func TestOAuthSecretFetchWorksUnderStrictACL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j, _ := oauthACLFixture(t, "tenant-a", "tenant-a")

	// The operator authorises the workflow for the connection. This must be
	// expressible at all; it used to fail with "grant target does not exist".
	if err := j.GrantSecret(ctx, "wf_1", "oauth:conn_abc", "admin", ""); err != nil {
		t.Fatalf("GrantSecret for an oauth id failed: %v\nThe operator cannot express the authorisation, so the ACL can never be satisfied.", err)
	}

	masterKey := make([]byte, 32)
	v, err := vault.NewStore(vault.NewMemoryBackend(), masterKey)
	if err != nil {
		t.Fatal(err)
	}
	sup := &Supervisor{
		WorkflowSlug:  "mailer",
		RunID:         "run_1",
		Mode:          "live",
		Journal:       j,
		Vault:         v,
		OAuthTokens:   stubOAuthResolver{token: "ya29.LIVE", wantTenant: "tenant-a"},
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		ACLPermissive: false, // the documented default
	}

	sr := fetchSecret(t, sup, "oauth:conn_abc")
	if sr.NotFound || string(sr.Value) != "ya29.LIVE" {
		t.Fatalf("granted oauth fetch denied under the default strict ACL (NotFound=%v value=%q); the Connections feature cannot work without REACTOR_VAULT_ACL_PERMISSIVE=1",
			sr.NotFound, string(sr.Value))
	}
}

// TestOAuthSecretFetchDeniedWithoutGrant proves the fix did not simply exempt
// oauth ids from the ACL: the grant is still required.
func TestOAuthSecretFetchDeniedWithoutGrant(t *testing.T) {
	t.Parallel()
	j, db := oauthACLFixture(t, "tenant-a", "tenant-a")
	// Seed an unrelated grant so the table is non-empty; otherwise the fetch
	// would be denied by the empty-ACL branch and prove nothing about grants.
	if _, err := db.Exec(
		`INSERT INTO workflow_secret_grants (workflow_id, credential_id) VALUES (?,?)`,
		"wf_1", "oauth:conn_other"); err != nil {
		t.Fatal(err)
	}
	masterKey := make([]byte, 32)
	v, _ := vault.NewStore(vault.NewMemoryBackend(), masterKey)
	sup := &Supervisor{
		WorkflowSlug:  "mailer",
		RunID:         "run_1",
		Mode:          "live",
		Journal:       j,
		Vault:         v,
		OAuthTokens:   stubOAuthResolver{token: "ya29.LIVE", wantTenant: "tenant-a"},
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		ACLPermissive: false,
	}
	if sr := fetchSecret(t, sup, "oauth:conn_abc"); !sr.NotFound {
		t.Fatalf("ungranted oauth fetch was ALLOWED (value=%q); the fix must not exempt oauth ids from the grant check", string(sr.Value))
	}
}

func TestOAuthSecretFetchDeniesExistingSalesforceProviderAlias(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j, db := oauthACLFixture(t, "tenant-a", "tenant-a")
	if err := j.GrantSecret(ctx, "wf_1", "oauth:conn_abc", "admin", ""); err != nil {
		t.Fatal(err)
	}
	// This row represents a provider configured before alias registration was
	// refused. The live boundary must reject it even with a workflow grant.
	if _, err := db.ExecContext(ctx,
		`UPDATE oauth_providers SET auth_url = ? WHERE provider_id = 'google'`,
		"https://login.salesforce.com/services/oauth2/authorize"); err != nil {
		t.Fatal(err)
	}
	masterKey := make([]byte, 32)
	v, err := vault.NewStore(vault.NewMemoryBackend(), masterKey)
	if err != nil {
		t.Fatal(err)
	}
	sup := &Supervisor{
		WorkflowSlug: "mailer", RunID: "run_1", Mode: "live",
		Journal: j, Vault: v,
		OAuthTokens: noRawTokenResolver{oauth.New(db, oauth.EngineSQLite, masterKey)},
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if sr := fetchSecret(t, sup, "oauth:conn_abc"); !sr.NotFound || len(sr.Value) != 0 {
		t.Fatalf("Salesforce alias returned raw token: %+v", sr)
	}
}

// TestOAuthGrantRefusedAcrossTenants keeps the disclosure guard honest for the
// oauth namespace: a workflow in one tenant must not be grantable a connection
// owned by another.
func TestOAuthGrantRefusedAcrossTenants(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j, _ := oauthACLFixture(t, "tenant-a", "tenant-b")

	if err := j.GrantSecret(ctx, "wf_1", "oauth:conn_abc", "admin", ""); err == nil {
		t.Fatal("cross-tenant oauth grant was ACCEPTED; a tenant-a workflow can be authorised for a tenant-b connection")
	}
}

// TestOAuthSecretFetchDeniedAcrossTenants is the runtime half: even with a
// grant row written directly (as one could have been before the guard existed),
// a connection owned by another tenant must not resolve.
func TestOAuthSecretFetchDeniedAcrossTenants(t *testing.T) {
	t.Parallel()
	j, db := oauthACLFixture(t, "tenant-a", "tenant-b")
	if _, err := db.Exec(
		`INSERT INTO workflow_secret_grants (workflow_id, credential_id) VALUES (?,?)`,
		"wf_1", "oauth:conn_abc"); err != nil {
		t.Fatal(err)
	}
	masterKey := make([]byte, 32)
	v, _ := vault.NewStore(vault.NewMemoryBackend(), masterKey)
	sup := &Supervisor{
		WorkflowSlug: "mailer",
		RunID:        "run_1",
		Mode:         "live",
		Journal:      j,
		Vault:        v,
		// Deliberately permissive stub: if the ACL lets the call through, the
		// stub would hand back a token, so a pass here means the guard held.
		OAuthTokens:   stubOAuthResolver{token: "ya29.LEAKED", wantTenant: "tenant-a"},
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		ACLPermissive: false,
	}
	if sr := fetchSecret(t, sup, "oauth:conn_abc"); !sr.NotFound {
		t.Fatalf("CROSS-TENANT OAUTH DISCLOSURE: tenant-a run resolved a tenant-b connection (value=%q)", string(sr.Value))
	}
}
