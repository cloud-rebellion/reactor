package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBrokerPolicyRequiresReviewAndNeverReenablesRawToken(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.UpsertProvider(ctx, Provider{ProviderID: "acme-api", Name: "Acme",
		AuthURL: "https://login.acme.example/authorize", TokenURL: "https://login.acme.example/token", Enabled: true}, ""); err != nil {
		t.Fatal(err)
	}
	conn, err := st.upsertConnection(ctx, "tenant-a", "acme-api", "main", "operator", tokenBlob{
		AccessToken: "private-access-token", Expiry: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := st.ListConnections(ctx, "tenant-a"); err != nil || len(rows) != 1 ||
		rows[0].TokenAccessMode != "broker_only" || rows[0].BrokerPolicyVersion != 0 {
		t.Fatalf("new generic connection is not pending review: %+v, %v", rows, err)
	}
	if allowed, err := st.RawTokenAllowed(ctx, conn.ID, "tenant-a"); err != nil || allowed {
		t.Fatalf("pending connection raw token allowed=%v err=%v", allowed, err)
	}
	if _, err := st.GenericBrokerSession(ctx, "tenant-a", conn.ID); !errors.Is(err, ErrBrokerPolicyUnavailable) {
		t.Fatalf("unreviewed broker session = %v", err)
	}
	if _, err := st.ApproveBrokerPolicy(ctx, "other", conn.ID, "admin", 0, "https://api.acme.example", "/v1/accounts", "GET"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant approval = %v", err)
	}
	policy, err := st.ApproveBrokerPolicy(ctx, "tenant-a", conn.ID, "admin", 0,
		"https://api.acme.example", "/v1/accounts", "GET")
	if err != nil || policy.Version != 1 {
		t.Fatalf("approve policy = %+v, %v", policy, err)
	}
	if _, err := st.ApproveBrokerPolicy(ctx, "tenant-a", conn.ID, "admin", 0,
		"https://api.acme.example", "/v2", "GET"); !errors.Is(err, ErrBrokerPolicyConflict) {
		t.Fatalf("stale approval = %v", err)
	}
	session, err := st.GenericBrokerSession(ctx, "tenant-a", conn.ID)
	if err != nil || session.BearerToken() != "private-access-token" || session.APIOrigin != "https://api.acme.example" {
		t.Fatalf("reviewed session = %v, %v", session, err)
	}
	if current, err := st.BrokerPolicyCurrent(ctx, session); err != nil || !current {
		t.Fatalf("reviewed policy current=%v err=%v", current, err)
	}
	serialized, _ := json.Marshal(session)
	if strings.Contains(string(serialized), "private-access-token") ||
		strings.Contains(fmt.Sprintf("%+v", session), "private-access-token") ||
		strings.Contains(fmt.Sprintf("%#v", session), "private-access-token") {
		t.Fatal("broker session serialized live token")
	}
	if _, err := st.RawToken(ctx, conn.ID, "tenant-a"); !errors.Is(err, ErrRawTokenDenied) {
		t.Fatalf("approved broker leaked raw token: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE oauth_connections SET token_access_mode='legacy_raw' WHERE id=?`, conn.ID); err == nil {
		t.Fatal("broker-only connection downgraded to raw-token mode")
	}
	policy, err = st.ApproveBrokerPolicy(ctx, "tenant-a", conn.ID, "second-admin", 1,
		"https://api.acme.example", "/v2", "GET")
	if err != nil || policy.Version != 2 {
		t.Fatalf("re-review = %+v, %v", policy, err)
	}
	if current, err := st.BrokerPolicyCurrent(ctx, session); err != nil || current {
		t.Fatalf("old session remained current after revision: %v, %v", current, err)
	}
	var reviews int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oauth_api_policy_reviews WHERE connection_id=?`, conn.ID).Scan(&reviews); err != nil || reviews != 2 {
		t.Fatalf("review history = %d, %v", reviews, err)
	}
	if _, err := st.db.ExecContext(ctx, `DELETE FROM oauth_api_policies WHERE connection_id=?`, conn.ID); err != nil {
		t.Fatal(err)
	}
	if allowed, err := st.RawTokenAllowed(ctx, conn.ID, "tenant-a"); err != nil || allowed {
		t.Fatalf("policy deletion re-enabled raw token: %v, %v", allowed, err)
	}
	if _, err := st.GenericBrokerSession(ctx, "tenant-a", conn.ID); !errors.Is(err, ErrBrokerPolicyUnavailable) {
		t.Fatalf("deleted policy still brokered: %v", err)
	}
	policy, err = st.ApproveBrokerPolicy(ctx, "tenant-a", conn.ID, "third-admin", 0,
		"https://api.acme.example", "/v3", "GET")
	if err != nil || policy.Version != 3 {
		t.Fatalf("restore after deleted current policy = %+v, %v", policy, err)
	}
}

func TestBrokerOriginAndPathValidation(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"", "http://api.example.com", "https://localhost", "https://127.0.0.1",
		"https://169.254.169.254", "https://api.example.com/", "https://user:pw@api.example.com",
		"https://api.example.com?x=1", "https://api.example.com#frag", "https://api.example.com.evil.test/../",
		"https://api_example.com", "https://api.example.com:0", "https://api.example.com:65536",
	} {
		if got, err := ValidateBrokerAPIOrigin(bad); err == nil {
			t.Errorf("unsafe origin %q accepted as %q", bad, got)
		}
	}
	for _, good := range []string{"https://api.example.com", "https://api.example.com:8443"} {
		if got, err := ValidateBrokerAPIOrigin(good); err != nil || got != good {
			t.Errorf("safe origin %q = %q, %v", good, got, err)
		}
	}
	for _, bad := range []string{
		"https://evil.example/v1", "//evil.example/v1", "/v1/accountx", "/v1/../private",
		"/v1/%2e%2e/private", "/v1/%252e%252e/private", "/v1/\\evil",
		"/v1/accounts#frag", "/v1/accounts\r\nAuthorization: x", "/v1/accounts%2fprivate",
	} {
		if got, err := ValidateBrokerPath(bad, "/v1/account"); err == nil {
			t.Errorf("unsafe path %q accepted as %q", bad, got)
		}
	}
	for _, good := range []string{"/v1/account", "/v1/account/123?fields=id%2Cname"} {
		if got, err := ValidateBrokerPath(good, "/v1/account"); err != nil || got != good {
			t.Errorf("safe path %q = %q, %v", good, got, err)
		}
	}
}

func TestNewEmailConnectionsUseBrokerAndTrackCanonicalEndpoints(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()
	for _, tc := range []struct{ provider, auth, token, safeScope, broadScope string }{
		{"google", "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token",
			"openid email profile https://www.googleapis.com/auth/gmail.send", "https://www.googleapis.com/auth/gmail.readonly"},
		{"microsoft", "https://login.microsoftonline.com/common/oauth2/v2.0/authorize", "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			"openid email profile offline_access https://graph.microsoft.com/Mail.Send", "https://graph.microsoft.com/Mail.Read"},
	} {
		if err := st.UpsertProvider(ctx, Provider{ProviderID: tc.provider, Name: tc.provider,
			AuthURL: tc.auth, TokenURL: tc.token, Scopes: tc.safeScope, Enabled: true}, ""); err != nil {
			t.Fatal(err)
		}
		conn, err := st.upsertConnectionWithRequestedScopes(ctx, "tenant-a", tc.provider, "mail", "operator",
			tokenBlob{AccessToken: "mail-token"}, tc.safeScope)
		if err != nil {
			t.Fatal(err)
		}
		if allowed, err := st.RawTokenAllowed(ctx, conn.ID, "tenant-a"); err != nil || allowed || conn.TokenAccessMode != "broker_only" {
			t.Fatalf("new %s mail connection released raw token: %v, %v, %+v", tc.provider, allowed, err, conn)
		}
		if session, err := st.MailBrokerSession(ctx, "tenant-a", conn.ID); err != nil || session.BearerToken() != "mail-token" {
			t.Fatalf("canonical %s mail broker session = %v, %v", tc.provider, session, err)
		}
		broad, err := st.upsertConnectionWithRequestedScopes(ctx, "tenant-a", tc.provider, "broad", "operator", tokenBlob{
			AccessToken: "broad-token", Scope: tc.safeScope + " " + tc.broadScope,
		}, tc.safeScope)
		if err != nil {
			t.Fatal(err)
		}
		if allowed, err := st.RawTokenAllowed(ctx, broad.ID, "tenant-a"); err != nil || allowed || broad.TokenAccessMode != "broker_only" {
			t.Fatalf("broad granted %s scope got raw access: %v, %v, %+v", tc.provider, allowed, err, broad)
		}
		if _, err := st.MailBrokerSession(ctx, "tenant-a", broad.ID); !errors.Is(err, ErrMailBrokerUnavailable) {
			t.Fatalf("broad %s scope admitted by mail broker: %v", tc.provider, err)
		}
		if _, err := st.db.ExecContext(ctx, `UPDATE oauth_providers SET scopes=? WHERE provider_id=?`,
			tc.safeScope+" "+tc.broadScope, tc.provider); err != nil {
			t.Fatal(err)
		}
		if _, err := st.MailBrokerSession(ctx, "tenant-a", conn.ID); !errors.Is(err, ErrMailBrokerUnavailable) {
			t.Fatalf("widened configured %s scopes kept mail broker access: %v", tc.provider, err)
		}
		if _, err := st.db.ExecContext(ctx, `UPDATE oauth_providers SET scopes=? WHERE provider_id=?`, tc.safeScope, tc.provider); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `UPDATE oauth_providers SET token_url='https://other.example/token' WHERE provider_id=?`, tc.provider); err != nil {
			t.Fatal(err)
		}
		if _, err := st.MailBrokerSession(ctx, "tenant-a", conn.ID); !errors.Is(err, ErrMailBrokerUnavailable) {
			t.Fatalf("edited %s endpoint kept mail broker access: %v", tc.provider, err)
		}
		alias, err := st.upsertConnectionWithRequestedScopes(ctx, "tenant-a", tc.provider, "alias", "operator",
			tokenBlob{AccessToken: "alias-token"}, tc.safeScope)
		if err != nil {
			t.Fatal(err)
		}
		if allowed, err := st.RawTokenAllowed(ctx, alias.ID, "tenant-a"); err != nil || allowed {
			t.Fatalf("new %s alias got raw exception: %v, %v", tc.provider, allowed, err)
		}
	}
}

func TestLegacyEmailAdapterKeepsRawModeAcrossReconnectWhileBrokerCanSend(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()
	scopes := "openid email profile https://www.googleapis.com/auth/gmail.send"
	if err := st.UpsertProvider(ctx, Provider{ProviderID: "google", Name: "Google", Enabled: true,
		AuthURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: "https://oauth2.googleapis.com/token",
		Scopes: scopes}, ""); err != nil {
		t.Fatal(err)
	}
	const tenant, name = "tenant-a", "legacy-mail"
	oldToken, err := st.saveTokenBlob(connectionTokenIdentity(tenant, "google", name), tokenBlob{
		AccessToken: "legacy-token", Scope: scopes,
	})
	if err != nil {
		t.Fatal(err)
	}
	id := newID("conn_")
	if _, err := st.db.ExecContext(ctx, st.bind(`INSERT INTO oauth_connections
		(id,tenant_id,provider_id,name,token_encrypted,scopes,status,token_access_mode,legacy_raw_reason)
		VALUES ($1,$2,'google',$3,$4,$5,'connected','legacy_raw','email_adapter')`),
		id, tenant, name, oldToken, scopes); err != nil {
		t.Fatal(err)
	}
	if token, err := st.RawToken(ctx, id, tenant); err != nil || token != "legacy-token" {
		t.Fatalf("legacy mail token = %q, %v", token, err)
	}
	conn, err := st.upsertConnectionWithRequestedScopes(ctx, tenant, "google", name, "operator",
		tokenBlob{AccessToken: "reconnected-token"}, scopes)
	if err != nil || conn.ID != id || conn.TokenAccessMode != "legacy_raw" {
		t.Fatalf("legacy mail reconnect changed mode or id: %+v, %v", conn, err)
	}
	var reason string
	if err := st.db.QueryRowContext(ctx, st.bind(`SELECT legacy_raw_reason FROM oauth_connections WHERE id=$1`), id).Scan(&reason); err != nil || reason != "email_adapter" {
		t.Fatalf("legacy mail reason after reconnect = %q, %v", reason, err)
	}
	if token, err := st.RawToken(ctx, id, tenant); err != nil || token != "reconnected-token" {
		t.Fatalf("legacy mail raw compatibility lost: %q, %v", token, err)
	}
	if session, err := st.MailBrokerSession(ctx, tenant, id); err != nil || session.BearerToken() != "reconnected-token" {
		t.Fatalf("legacy mail broker migration unavailable: %v, %v", session, err)
	}
}

func TestEmailScopeSnapshotRejectsProviderNarrowingBeforeCallback(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()
	broad := "openid email profile https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/gmail.readonly"
	safe := "openid email profile https://www.googleapis.com/auth/gmail.send"
	provider := Provider{ProviderID: "google", Name: "Google", ClientID: "test-client", Enabled: true,
		AuthURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: "https://oauth2.googleapis.com/token", Scopes: broad}
	if err := st.UpsertProvider(ctx, provider, ""); err != nil {
		t.Fatal(err)
	}
	authURL, err := st.StartAuth(ctx, "tenant-a", "google", "mail", "https://reactor.example/oauth/callback", "operator")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(authURL)
	if err != nil || u.Query().Get("scope") != broad {
		t.Fatalf("authorization requested wrong scope: %q, %v", authURL, err)
	}
	provider.Scopes = safe
	if err := st.UpsertProvider(ctx, provider, ""); err != nil {
		t.Fatal(err)
	}
	st.http = &http.Client{Transport: tokenResponseTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"access_token":"broad-token","expires_in":3600}`)), Request: r}, nil
	})}
	conn, err := st.CompleteAuth(ctx, u.Query().Get("state"), "test-code")
	if err != nil {
		t.Fatal(err)
	}
	if conn.TokenAccessMode != "broker_only" || conn.Scopes != broad {
		t.Fatalf("scope change relabeled broad grant: %+v", conn)
	}
	if allowed, err := st.RawTokenAllowed(ctx, conn.ID, "tenant-a"); err != nil || allowed {
		t.Fatalf("broad requested scope released raw token: %v, %v", allowed, err)
	}
}

func TestDisabledProviderDeniesLegacyGenericAndSalesforceRuntime(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.UpsertProvider(ctx, Provider{ProviderID: "custom", Name: "Custom",
		AuthURL: "https://login.acme.example/auth", TokenURL: "https://login.acme.example/token", Enabled: true}, ""); err != nil {
		t.Fatal(err)
	}
	legacy, err := insertLegacyRawTestConnection(st, "tenant-a", "custom", "legacy", tokenBlob{AccessToken: "legacy-token"})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := st.upsertConnection(ctx, "tenant-a", "custom", "broker", "operator", tokenBlob{AccessToken: "broker-token"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApproveBrokerPolicy(ctx, "tenant-a", broker.ID, "reviewer", 0, "https://api.acme.example", "/v1", "GET"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE oauth_providers SET enabled=0 WHERE provider_id='custom'`); err != nil {
		t.Fatal(err)
	}
	if allowed, err := st.RawTokenAllowed(ctx, legacy.ID, "tenant-a"); err != nil || allowed {
		t.Fatalf("disabled legacy raw eligible=%v err=%v", allowed, err)
	}
	if _, err := st.RawToken(ctx, legacy.ID, "tenant-a"); !errors.Is(err, ErrRawTokenDenied) {
		t.Fatalf("disabled legacy raw token=%v", err)
	}
	if _, err := st.GenericBrokerSession(ctx, "tenant-a", broker.ID); !errors.Is(err, ErrBrokerPolicyUnavailable) {
		t.Fatalf("disabled generic broker session=%v", err)
	}
	sf := salesforceStore(t)
	sfConn, err := sf.upsertConnection(ctx, "tenant-a", "salesforce", "sf", "operator", tokenBlob{
		AccessToken: "sf-token", SalesforceAPIOrigin: "https://acme.my.salesforce.com", SalesforceOrgID: "00Dx0000000BV7z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sf.db.ExecContext(ctx, `UPDATE oauth_providers SET enabled=0 WHERE provider_id='salesforce'`); err != nil {
		t.Fatal(err)
	}
	if token, _, _, err := sf.SalesforceBrokerSession(ctx, sfConn.ID, "tenant-a"); token != "" || err == nil {
		t.Fatalf("disabled Salesforce session token=%q err=%v", token, err)
	}
}
