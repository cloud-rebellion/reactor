package oauth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/bright-interaction/reactor/internal/migrate"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "o.db")
	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(context.Background(), silent, "sqlite://"+dbPath); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return New(db, EngineSQLite, key)
}

// fakeProvider returns access1/refresh1 for the auth-code grant and access2 for
// a refresh grant, so the test can distinguish the two.
func fakeProvider(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.FormValue("grant_type") {
		case "authorization_code":
			if r.FormValue("code_verifier") == "" {
				t.Error("auth-code exchange missing PKCE code_verifier")
			}
			_, _ = io.WriteString(w, `{"access_token":"access1","refresh_token":"refresh1","expires_in":100,"token_type":"Bearer","scope":"a b"}`)
		case "refresh_token":
			if r.FormValue("refresh_token") != "refresh1" {
				t.Errorf("refresh grant got refresh_token=%q", r.FormValue("refresh_token"))
			}
			_, _ = io.WriteString(w, `{"access_token":"access2","expires_in":100,"token_type":"Bearer"}`)
		default:
			http.Error(w, "bad grant", http.StatusBadRequest)
		}
	}))
}

func TestOAuthFlowEndToEnd(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()
	clock := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	st.now = func() time.Time { return clock }

	ts := fakeProvider(t)
	defer ts.Close()

	if err := st.UpsertProvider(ctx, Provider{
		ProviderID: "fake", Name: "Fake", AuthURL: ts.URL + "/auth", TokenURL: ts.URL + "/token",
		ClientID: "cid", Scopes: "a b", Enabled: true,
	}, "topsecret"); err != nil {
		t.Fatal(err)
	}

	// StartAuth builds the authorize URL + records state.
	authURL, err := st.StartAuth(ctx, "acme", "fake", "Marketing Gmail", "https://app.example/oauth/callback", "user1")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	q := u.Query()
	if q.Get("client_id") != "cid" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorize URL missing params: %s", authURL)
	}
	state := q.Get("state")
	if state == "" {
		t.Fatal("no state in authorize URL")
	}

	// CompleteAuth exchanges the code -> stores an encrypted connection.
	conn, err := st.CompleteAuth(ctx, state, "thecode")
	if err != nil {
		t.Fatal(err)
	}
	if conn.TenantID != "acme" || conn.Status != "connected" {
		t.Fatalf("connection = %+v", conn)
	}

	// State is single-use.
	if _, err := st.CompleteAuth(ctx, state, "thecode"); err == nil {
		t.Fatal("expected reused state to be rejected")
	}

	// Token returns the access token; fresh, so no refresh.
	tok, err := st.Token(ctx, conn.ID, "acme")
	if err != nil || tok != "access1" {
		t.Fatalf("token = %q err=%v, want access1", tok, err)
	}

	// Cross-tenant access is denied.
	if _, err := st.Token(ctx, conn.ID, "other"); err == nil {
		t.Fatal("expected cross-tenant token access to be denied")
	}

	// Advance past expiry -> Token refreshes -> access2.
	clock = clock.Add(200 * time.Second)
	tok, err = st.Token(ctx, conn.ID, "acme")
	if err != nil || tok != "access2" {
		t.Fatalf("refreshed token = %q err=%v, want access2", tok, err)
	}

	// Listing shows one connection for the tenant, none for another.
	if got, _ := st.ListConnections(ctx, "acme"); len(got) != 1 {
		t.Fatalf("acme connections = %d, want 1", len(got))
	}
	if got, _ := st.ListConnections(ctx, "other"); len(got) != 0 {
		t.Fatalf("other connections = %d, want 0 (isolation)", len(got))
	}
}

func TestOAuthProfileBasicAndAuthParams(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()
	st.now = func() time.Time { return time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC) }

	var gotUser, gotPass string
	var bodyHadSecret bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotUser, gotPass, _ = r.BasicAuth()
		bodyHadSecret = r.FormValue("client_secret") != ""
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"a1","token_type":"Bearer","expires_in":100}`)
	}))
	defer ts.Close()

	st.ProfileFor = func(string) Profile {
		return Profile{TokenAuthStyle: "basic", AuthParams: map[string]string{"owner": "user"}}
	}
	if err := st.UpsertProvider(ctx, Provider{
		ProviderID: "basicprov", AuthURL: ts.URL + "/auth", TokenURL: ts.URL + "/token",
		ClientID: "cid", Enabled: true,
	}, "sekret"); err != nil {
		t.Fatal(err)
	}

	authURL, err := st.StartAuth(ctx, "acme", "basicprov", "Conn", "https://app/cb", "u")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	if u.Query().Get("owner") != "user" {
		t.Fatalf("authorize URL missing AuthParams owner=user: %s", authURL)
	}
	if _, err := st.CompleteAuth(ctx, u.Query().Get("state"), "code"); err != nil {
		t.Fatal(err)
	}
	if gotUser != "cid" || gotPass != "sekret" {
		t.Fatalf("token Basic auth = %q:%q, want cid:sekret", gotUser, gotPass)
	}
	if bodyHadSecret {
		t.Fatal("client_secret must not be in the body when TokenAuthStyle=basic")
	}
}

func TestProviderRequiresSecureURL(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	err := st.UpsertProvider(context.Background(), Provider{
		ProviderID: "bad", AuthURL: "http://evil.example/auth", TokenURL: "https://evil.example/token", Enabled: true,
	}, "")
	if err == nil {
		t.Fatal("expected non-loopback http auth_url to be rejected")
	}
}

func TestStartAuthRejectsUnsafeRedirectURI(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.UpsertProvider(ctx, Provider{
		ProviderID: "provider", Name: "Provider", AuthURL: "https://accounts.example/authorize",
		TokenURL: "https://accounts.example/token", ClientID: "client", Enabled: true,
	}, "secret"); err != nil {
		t.Fatal(err)
	}
	for _, redirect := range []string{
		"",
		"https://user:pass@reactor.example/oauth/callback",
		"https://reactor.example/oauth/callback?state=caller",
	} {
		if _, err := st.StartAuth(ctx, "acme", "provider", "Account", redirect, "actor"); err == nil {
			t.Fatalf("StartAuth(%q) succeeded; want unsafe redirect refusal", redirect)
		}
	}
}

func TestListConnectionsPageBoundsAndFiltersInSQL(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()
	for _, providerID := range []string{"alpha", "beta"} {
		if err := st.UpsertProvider(ctx, Provider{
			ProviderID: providerID, Name: providerID, AuthURL: "https://accounts.example/authorize",
			TokenURL: "https://accounts.example/token", Enabled: true,
		}, ""); err != nil {
			t.Fatal(err)
		}
	}
	for i, row := range []struct {
		id, tenant, provider, name string
	}{
		{"conn-a1", "acme", "alpha", "A1"},
		{"conn-a2", "acme", "alpha", "A2"},
		{"conn-b1", "acme", "beta", "B1"},
		{"conn-other", "other", "alpha", "Other"},
	} {
		_, err := st.db.ExecContext(ctx, st.bind(`INSERT INTO oauth_connections
			(id, tenant_id, provider_id, name, token_encrypted, scopes, status, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`),
			row.id, row.tenant, row.provider, row.name, []byte(fmt.Sprintf("opaque-%d", i)), "openid", "connected", "test")
		if err != nil {
			t.Fatal(err)
		}
	}

	page, more, err := st.ListConnectionsPage(ctx, "acme", "alpha", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].ID != "conn-a1" || !more {
		t.Fatalf("first page = %+v, more=%v", page, more)
	}
	page, more, err = st.ListConnectionsPage(ctx, "acme", "alpha", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].ID != "conn-a2" || more {
		t.Fatalf("second page = %+v, more=%v", page, more)
	}
	page, more, err = st.ListConnectionsPage(ctx, "acme", "beta", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].ID != "conn-b1" || more {
		t.Fatalf("provider page = %+v, more=%v", page, more)
	}
	if _, _, err := st.ListConnectionsPage(ctx, "acme", "", 501, 0); err == nil {
		t.Fatal("expected oversized connection page to be rejected")
	}
}

func TestDeleteConnectionIsTenantScopedAndReportsMissing(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.UpsertProvider(ctx, Provider{
		ProviderID: "provider", Name: "Provider", AuthURL: "https://accounts.example/authorize",
		TokenURL: "https://accounts.example/token", Enabled: true,
	}, ""); err != nil {
		t.Fatal(err)
	}
	_, err := st.db.ExecContext(ctx, st.bind(`INSERT INTO oauth_connections
		(id, tenant_id, provider_id, name, token_encrypted, scopes, status, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`),
		"conn-delete", "acme", "provider", "Account", []byte("encrypted"), "openid", "connected", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteConnection(ctx, "conn-delete", "other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant delete error = %v, want ErrNotFound", err)
	}
	if got, err := st.ListConnections(ctx, "acme"); err != nil || len(got) != 1 {
		t.Fatalf("cross-tenant delete changed owner row: got=%d err=%v", len(got), err)
	}
	if err := st.DeleteConnection(ctx, "conn-delete", "acme"); err != nil {
		t.Fatalf("owner delete: %v", err)
	}
	if err := st.DeleteConnection(ctx, "conn-delete", "acme"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("repeat delete error = %v, want ErrNotFound", err)
	}
}
