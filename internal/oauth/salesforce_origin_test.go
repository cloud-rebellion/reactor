package oauth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/vault"
)

func TestValidateSalesforceAPIOrigin(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"https://Acme.my.salesforce.com/", "https://acme.my.salesforce.com"},
		{"https://na123.salesforce.com", "https://na123.salesforce.com"},
		{"https://acme--dev.sandbox.my.salesforce.com", "https://acme--dev.sandbox.my.salesforce.com"},
	} {
		got, err := validateSalesforceAPIOrigin(tc.input)
		if err != nil || got != tc.want {
			t.Fatalf("origin %q = %q, %v; want %q", tc.input, got, err, tc.want)
		}
	}
	for _, input := range []string{
		"", " http://acme.my.salesforce.com", "http://acme.my.salesforce.com",
		"https://salesforce.com", "https://salesforce.com.evil.test",
		"https://acme.my.salesforce.com.evil.test", "https://127.0.0.1",
		"https://169.254.169.254", "https://[::1]",
		"https://user:password@acme.my.salesforce.com",
		"https://acme.my.salesforce.com:443",
		"https://acme.my.salesforce.com/services/data",
		"https://acme.my.salesforce.com/?key=secret",
		"https://acme.my.salesforce.com#fragment",
		"https://acme..my.salesforce.com", "https://-acme.my.salesforce.com",
		"https://acme.my.salesforce.com.", "https://☃.my.salesforce.com",
		"https://acme.my.salesforce.com" + strings.Repeat(" ", maxSalesforceAPIOriginBytes),
	} {
		if got, err := validateSalesforceAPIOrigin(input); err == nil || got != "" {
			t.Fatalf("unsafe origin %q accepted as %q", input, got)
		}
	}
}

func salesforceStore(t *testing.T) *Store {
	t.Helper()
	st := newTestStore(t)
	if err := st.UpsertProvider(context.Background(), Provider{
		ProviderID: "salesforce", Name: "Salesforce",
		AuthURL:  "https://login.salesforce.com/services/oauth2/authorize",
		TokenURL: "https://login.salesforce.com/services/oauth2/token",
		ClientID: "client", Enabled: true,
	}, ""); err != nil {
		t.Fatal(err)
	}
	return st
}

func startSalesforceAuth(t *testing.T, st *Store) string {
	t.Helper()
	authURL, err := st.StartAuth(context.Background(), "acme", "salesforce", "Main", "https://reactor.example/oauth/callback", "operator")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("state")
}

func TestSalesforceAPIOriginIsTenantScopedAndSurvivesRefresh(t *testing.T) {
	st := salesforceStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	st.now = func() time.Time { return now }
	refreshes := 0
	st.http = &http.Client{Transport: tokenResponseTransport(func(r *http.Request) (*http.Response, error) {
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		body := `{"access_token":"initial-token","refresh_token":"refresh-secret","expires_in":120,"instance_url":"https://Acme.my.salesforce.com/"}`
		if r.Form.Get("grant_type") == "refresh_token" {
			refreshes++
			body = `{"access_token":"refreshed-token","expires_in":120}`
			if refreshes == 2 {
				body = `{"access_token":"moved-token","expires_in":120,"instance_url":"https://acme--moved.sandbox.my.salesforce.com/"}`
			}
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	conn, err := st.CompleteAuth(ctx, startSalesforceAuth(t, st), "authorization-code")
	if err != nil {
		t.Fatal(err)
	}
	checkOrigin := func(want string) {
		t.Helper()
		got, err := st.SalesforceAPIOrigin(ctx, conn.ID, "acme")
		if err != nil || got != want || strings.Contains(got, "token") || strings.Contains(got, "secret") {
			t.Fatalf("Salesforce metadata = %q, %v; want %q", got, err, want)
		}
	}
	checkSession := func(wantToken, wantOrigin string) {
		t.Helper()
		token, origin, err := st.SalesforceSession(ctx, conn.ID, "acme")
		if err != nil || token != wantToken || origin != wantOrigin {
			t.Fatalf("Salesforce session = token %q, origin %q, %v", token, origin, err)
		}
		if token, origin, err := st.SalesforceSession(ctx, conn.ID, "other"); !errors.Is(err, ErrNotFound) || token != "" || origin != "" {
			t.Fatalf("cross-tenant Salesforce session = token %q, origin %q, %v", token, origin, err)
		}
	}
	checkOrigin("https://acme.my.salesforce.com")
	checkSession("initial-token", "https://acme.my.salesforce.com")
	for _, tenant := range []string{"", "other"} {
		if got, err := st.SalesforceAPIOrigin(ctx, conn.ID, tenant); !errors.Is(err, ErrNotFound) || got != "" {
			t.Fatalf("tenant %q saw origin %q, %v", tenant, got, err)
		}
	}
	var encrypted []byte
	if err := st.db.QueryRowContext(ctx, "SELECT token_encrypted FROM oauth_connections WHERE id = ?", conn.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte("initial-token")) || bytes.Contains(encrypted, []byte("acme.my.salesforce.com")) {
		t.Fatal("OAuth token or org origin was stored in plaintext")
	}
	now = now.Add(3 * time.Minute)
	if got, err := st.Token(ctx, conn.ID, "acme"); err != nil || got != "refreshed-token" {
		t.Fatalf("first refresh = %q, %v", got, err)
	}
	checkOrigin("https://acme.my.salesforce.com")
	checkSession("refreshed-token", "https://acme.my.salesforce.com")
	now = now.Add(3 * time.Minute)
	if got, err := st.Token(ctx, conn.ID, "acme"); err != nil || got != "moved-token" {
		t.Fatalf("second refresh = %q, %v", got, err)
	}
	checkOrigin("https://acme--moved.sandbox.my.salesforce.com")
	checkSession("moved-token", "https://acme--moved.sandbox.my.salesforce.com")
}

func TestSalesforceTokenExchangeRejectsUnsafeOrMissingOrigin(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"missing", `{"access_token":"token"}`},
		{"private", `{"access_token":"token","instance_url":"https://127.0.0.1"}`},
		{"untrusted", `{"access_token":"token","instance_url":"https://salesforce.com.evil.test"}`},
		{"userinfo", `{"access_token":"token","instance_url":"https://user@acme.my.salesforce.com"}`},
		{"form encoded", "access_token=token&instance_url=https%3A%2F%2F169.254.169.254"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := salesforceStore(t)
			st.http = &http.Client{Transport: tokenResponseTransport(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(tc.body)), Request: r}, nil
			})}
			_, err := st.CompleteAuth(context.Background(), startSalesforceAuth(t, st), "authorization-code")
			if err == nil || strings.Contains(err.Error(), "salesforce.com.evil") || strings.Contains(err.Error(), "127.0.0.1") {
				t.Fatalf("unsafe token response error = %v", err)
			}
			rows, listErr := st.ListConnections(context.Background(), "acme")
			if listErr != nil || len(rows) != 0 {
				t.Fatalf("unsafe token response persisted connection: rows=%+v err=%v", rows, listErr)
			}
		})
	}
}

func TestSalesforceFormResponseAndLegacyOriginAvailability(t *testing.T) {
	st := salesforceStore(t)
	ctx := context.Background()
	st.http = &http.Client{Transport: tokenResponseTransport(func(r *http.Request) (*http.Response, error) {
		body := url.Values{
			"access_token": {"form-token"},
			"instance_url": {"https://na123.salesforce.com/"},
		}.Encode()
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	conn, err := st.CompleteAuth(ctx, startSalesforceAuth(t, st), "authorization-code")
	if err != nil {
		t.Fatal(err)
	}
	if origin, err := st.SalesforceAPIOrigin(ctx, conn.ID, "acme"); err != nil || origin != "https://na123.salesforce.com" {
		t.Fatalf("form response origin = %q, %v", origin, err)
	}
	legacy, err := st.upsertConnection(ctx, "acme", "salesforce", "Legacy", "operator", tokenBlob{AccessToken: "old-token"})
	if err != nil {
		t.Fatal(err)
	}
	if origin, err := st.SalesforceAPIOrigin(ctx, legacy.ID, "acme"); !errors.Is(err, ErrSalesforceAPIOriginUnavailable) || origin != "" {
		t.Fatalf("legacy origin = %q, %v", origin, err)
	}
	if _, err := st.upsertConnection(ctx, "acme", "salesforce", "Unsafe", "operator", tokenBlob{
		AccessToken: "token", SalesforceAPIOrigin: "https://evil.test",
	}); err == nil {
		t.Fatal("unsafe origin persisted through the internal save path")
	}
	// A copied or otherwise stale encrypted row is still checked when read.
	forged, err := vault.EncryptForID(st.masterKey, connectionTokenIdentity("acme", "salesforce", "Legacy"),
		[]byte(`{"access_token":"old-token","salesforce_api_origin":"https://evil.test"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE oauth_connections SET token_encrypted = ? WHERE id = ?", forged, legacy.ID); err != nil {
		t.Fatal(err)
	}
	if origin, err := st.SalesforceAPIOrigin(ctx, legacy.ID, "acme"); !errors.Is(err, ErrSalesforceAPIOriginUnavailable) || origin != "" {
		t.Fatalf("untrusted persisted origin = %q, %v", origin, err)
	}
}

func TestSalesforceRefreshRejectsUntrustedNewOriginWithoutReplacingOld(t *testing.T) {
	st := salesforceStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	st.now = func() time.Time { return now }
	conn, err := st.upsertConnection(ctx, "acme", "salesforce", "Main", "operator", tokenBlob{
		AccessToken: "old-token", RefreshToken: "refresh-secret", Expiry: now.Add(-time.Minute),
		SalesforceAPIOrigin: "https://acme.my.salesforce.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	var before, after []byte
	if err := st.db.QueryRowContext(ctx, "SELECT token_encrypted FROM oauth_connections WHERE id = ?", conn.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	st.http = &http.Client{Transport: tokenResponseTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"access_token":"new-token","instance_url":"https://evil.test","expires_in":3600}`)), Request: r}, nil
	})}
	if token, err := st.Token(ctx, conn.ID, "acme"); err == nil || token != "" {
		t.Fatalf("unsafe refresh token = %q, %v", token, err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT token_encrypted FROM oauth_connections WHERE id = ?", conn.ID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("unsafe refresh replaced the previous encrypted token and origin")
	}
	if origin, err := st.SalesforceAPIOrigin(ctx, conn.ID, "acme"); err != nil || origin != "https://acme.my.salesforce.com" {
		t.Fatalf("previous origin = %q, %v", origin, err)
	}
}

func TestSalesforceSessionUsesReconnectedTokenAndOriginDuringRefresh(t *testing.T) {
	st := salesforceStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	st.now = func() time.Time { return now }
	conn, err := st.upsertConnection(ctx, "acme", "salesforce", "Main", "operator", tokenBlob{
		AccessToken: "expired", RefreshToken: "old-refresh", Expiry: now.Add(-time.Minute),
		SalesforceAPIOrigin: "https://old.my.salesforce.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	st.http = &http.Client{Transport: tokenResponseTransport(func(r *http.Request) (*http.Response, error) {
		if _, err := st.upsertConnection(ctx, "acme", "salesforce", "Main", "operator", tokenBlob{
			AccessToken: "reconnected", RefreshToken: "new-refresh", Expiry: now.Add(time.Hour),
			SalesforceAPIOrigin: "https://new.my.salesforce.com",
		}); err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"access_token":"stale-refresh","expires_in":3600,"instance_url":"https://old.my.salesforce.com"}`)), Request: r}, nil
	})}
	token, origin, err := st.SalesforceSession(ctx, conn.ID, "acme")
	if err != nil || token != "reconnected" || origin != "https://new.my.salesforce.com" {
		t.Fatalf("session paired stale refresh with reconnect: token=%q origin=%q err=%v", token, origin, err)
	}
}
