package server

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/bright-interaction/reactor/internal/auth"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/oauth"
	"github.com/go-chi/chi/v5"
)

func serverWithOAuth(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "c.db")
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
		key[i] = byte(i + 7)
	}
	return &Server{Log: silent, OAuth: oauth.New(db, oauth.EngineSQLite, key)}
}

func TestConnectionsFlow(t *testing.T) {
	t.Parallel()
	s := serverWithOAuth(t)
	admin := auth.User{ID: "a", Role: auth.RoleAdmin, TenantID: "acme"}
	member := auth.User{ID: "m", Role: auth.RoleMember, TenantID: "acme"}

	// Admin configures a provider (https required, so use a real https URL).
	form := url.Values{
		"provider_id": {"google"}, "name": {"Google"},
		"auth_url":  {"https://accounts.google.com/o/oauth2/v2/auth"},
		"token_url": {"https://oauth2.googleapis.com/token"},
		"client_id": {"cid.apps.googleusercontent.com"}, "scopes": {"email"}, "enabled": {"on"},
	}
	preq := httptest.NewRequest(http.MethodPost, "/oauth-providers", strings.NewReader(form.Encode()))
	preq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	preq = preq.WithContext(withUser(preq.Context(), admin))
	prec := httptest.NewRecorder()
	s.oauthProvidersUpsert(prec, preq)
	if prec.Code != http.StatusSeeOther {
		t.Fatalf("provider upsert = %d, want 303", prec.Code)
	}

	// A member is forbidden from the provider admin page.
	fr := httptest.NewRequest(http.MethodGet, "/oauth-providers", nil).WithContext(withUser(context.Background(), member))
	frec := httptest.NewRecorder()
	s.oauthProviders(frec, fr)
	if frec.Code != http.StatusForbidden {
		t.Fatalf("member provider page = %d, want 403", frec.Code)
	}

	// The member sees the connect form on /connections.
	cr := httptest.NewRequest(http.MethodGet, "/connections", nil).WithContext(withUser(context.Background(), member))
	crec := httptest.NewRecorder()
	s.connections(crec, cr)
	if crec.Code != http.StatusOK || !strings.Contains(crec.Body.String(), "/connections/google/start") {
		t.Fatalf("connections page code=%d, missing connect form", crec.Code)
	}

	// Starting the flow redirects to Google's authorize URL with PKCE + state.
	sr := httptest.NewRequest(http.MethodPost, "/connections/google/start",
		strings.NewReader(url.Values{"name": {"Marketing Gmail"}}.Encode()))
	sr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sr = sr.WithContext(withUser(sr.Context(), member))
	sr = withChiParam(sr, "provider", "google")
	srec := httptest.NewRecorder()
	s.connectionsStart(srec, sr)
	if srec.Code != http.StatusSeeOther {
		t.Fatalf("start = %d, want 303", srec.Code)
	}
	loc := srec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://accounts.google.com/o/oauth2/v2/auth") ||
		!strings.Contains(loc, "code_challenge=") || !strings.Contains(loc, "state=") {
		t.Fatalf("authorize redirect malformed: %s", loc)
	}
}

func TestOAuthCallbackIsReachableWithoutDashboardSession(t *testing.T) {
	t.Parallel()
	s := serverWithOAuth(t)
	// Use a fully configured legacy auth gate so the assertion proves the
	// callback is explicitly public rather than merely passing because auth is
	// absent. Provider error callbacks do not need a state exchange and still
	// exercise the production callback route and HTML response.
	s.BasicAuth = BasicAuthConfig{User: "admin", PasswordSHA256: hashPass("secret")}
	r := chi.NewRouter()
	s.Mount(r)
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?error=access_denied", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Connection failed") {
		t.Fatalf("OAuth callback status=%d body=%q; want public callback page", rec.Code, rec.Body.String())
	}
}
