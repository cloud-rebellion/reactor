package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/auth"
	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	_ "modernc.org/sqlite"
)

type emptyAuthStore struct{}

func (emptyAuthStore) Authenticate(context.Context, string, string) (auth.User, error) {
	return auth.User{}, errors.New("no users")
}

func (emptyAuthStore) ResolveSessionWithState(context.Context, string) (auth.User, auth.SessionState, error) {
	return auth.User{}, auth.SessionState{}, errors.New("no sessions")
}

func (emptyAuthStore) ResolveAPIToken(context.Context, string) (auth.User, error) {
	return auth.User{}, errors.New("no tokens")
}

func (emptyAuthStore) CountUsers(context.Context) (int, error) { return 0, nil }

func (emptyAuthStore) HasMFA(context.Context, string) (bool, error) { return false, nil }

func newMCPAuthStore(t *testing.T, seedUser bool) (*auth.Store, func()) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "mcp-auth.db")
	dbURL := "sqlite://" + dbPath
	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(context.Background(), silent, dbURL); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store := auth.New(db, auth.EngineSQLite)
	if seedUser {
		if _, err := store.CreateUser(context.Background(), "alice", "secret-pass", auth.RoleAdmin); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
	}
	return store, func() { _ = db.Close() }
}

// newAuthServer builds a httptest.Server with a real auth store + a
// seeded admin user. Returns the URL, the journal, and the auth store
// so tests can mint sessions / tokens directly when needed.
func newAuthServer(t *testing.T, allowNoAuth bool) (string, *journal.Journal, *auth.Store, func()) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "s.db")
	url := "sqlite://" + dbPath
	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(context.Background(), silent, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	j := journal.New(db, journal.EngineSQLite)
	cred := credentials.New(db, credentials.EngineSQLite)
	reg := registry.New(filepath.Join(dir, "workflows"))
	store := auth.New(db, auth.EngineSQLite)
	if _, err := store.CreateUser(context.Background(), "alice", "secret-pass", auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		Journal:     j,
		Credentials: cred,
		Registry:    reg,
		Auth:        store,
		Log:         silent,
		Version:     "test",
		BasicAuth:   BasicAuthConfig{AllowNoAuth: allowNoAuth},
	}
	r := chi.NewRouter()
	s.Mount(r)
	srv := httptest.NewServer(r)
	cleanup := func() { srv.Close(); db.Close() }
	return srv.URL, j, store, cleanup
}

func TestUnauthRequestRedirectsToLogin(t *testing.T) {
	t.Parallel()
	url, _, _, cleanup := newAuthServer(t, false)
	defer cleanup()

	cl := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, _ := http.NewRequest(http.MethodGet, url+"/", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login") {
		t.Fatalf("Location = %q, want /login...", loc)
	}
}

func TestReadyzBypassesSessionAuthAfterUsersAreProvisioned(t *testing.T) {
	t.Parallel()
	_, _, store, cleanup := newAuthServer(t, false)
	defer cleanup()
	called := false
	h := SessionAuth(SessionAuthConfig{Store: store})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.URL.Path != "/readyz" {
			t.Fatalf("path = %q, want /readyz", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if resp.Code != http.StatusNoContent || !called {
		t.Fatalf("readyz session bypass status=%d called=%t, want 204/true", resp.Code, called)
	}
}

func TestLoginPostMintsSession(t *testing.T) {
	t.Parallel()
	url, _, _, cleanup := newAuthServer(t, false)
	defer cleanup()

	cl := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	form := makeForm("username", "alice", "password", "secret-pass", "next", "/users")
	resp := mustPostFormAuth(t, cl, url+"/login", form)
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 303\n%s", resp.StatusCode, body)
	}
	if resp.Header.Get("Location") != "/users" {
		t.Fatalf("Location = %q", resp.Header.Get("Location"))
	}
	cookie := pickCookie(resp.Cookies(), SessionCookieName)
	if cookie == nil || cookie.Value == "" {
		t.Fatalf("session cookie missing: %+v", resp.Cookies())
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie missing security attrs: %+v", cookie)
	}

	// Authenticated GET succeeds.
	req, _ := http.NewRequest(http.MethodGet, url+"/", nil)
	req.AddCookie(cookie)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("post-login GET status = %d", resp2.StatusCode)
	}
}

func TestBearerTokenAuthenticates(t *testing.T) {
	t.Parallel()
	url, _, store, cleanup := newAuthServer(t, false)
	defer cleanup()

	users, _ := store.ListUsers(context.Background())
	if len(users) == 0 {
		t.Fatal("no seeded user")
	}
	raw, _, err := store.MintAPIToken(context.Background(), users[0].ID, "ci", 0)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, url+"/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bearer GET status = %d", resp.StatusCode)
	}
	// HTTP auth-scheme names are case-insensitive; MCP clients may emit a
	// lower-case scheme while retrying the same connection.
	req, _ = http.NewRequest(http.MethodGet, url+"/", nil)
	req.Header.Set("Authorization", "bearer "+raw)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lower-case bearer GET status = %d", resp.StatusCode)
	}
}

func TestMCPDedicatedBearerTokenAuthenticatesOnlyTheMCPRoute(t *testing.T) {
	t.Parallel()
	_, _, store, cleanup := newAuthServer(t, false)
	defer cleanup()
	var got auth.User
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = UserFromContext(r.Context())
	})
	h := SessionAuth(SessionAuthConfig{
		Store:    store,
		MCPToken: "stage-mesh-style-secret",
		MCPUser:  auth.User{ID: "mcp-http", Role: auth.RoleAdmin, TenantID: "acme"},
	})(next)
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer stage-mesh-style-secret")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK || got.ID != "mcp-http" || got.Role != auth.RoleAdmin || got.TenantID != "acme" {
		t.Fatalf("dedicated MCP token identity = %+v status=%d", got, resp.Code)
	}

	got = auth.User{}
	req = httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "bearer stage-mesh-style-secret")
	resp = httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK || got.ID != "mcp-http" || got.Role != auth.RoleAdmin || got.TenantID != "acme" {
		t.Fatalf("lower-case dedicated MCP token identity = %+v status=%d", got, resp.Code)
	}

	got = auth.User{}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer stage-mesh-style-secret")
	req.Header.Set("Accept", "application/json")
	resp = httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized || got.ID != "" {
		t.Fatalf("dedicated MCP token escaped /mcp: identity=%+v status=%d", got, resp.Code)
	}
}

func TestMCPDedicatedBearerRemainsRequiredWhenLegacyNoAuthHasNoUsers(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := SessionAuth(SessionAuthConfig{
		Store:             emptyAuthStore{},
		LegacyAllowNoAuth: true,
		MCPToken:          "stage-mesh-style-secret",
		MCPUser:           auth.User{ID: "mcp-http", Role: auth.RoleAdmin, TenantID: "acme"},
	})(next)
	for _, header := range []string{"", "Bearer wrong"} {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		resp := httptest.NewRecorder()
		h.ServeHTTP(resp, req)
		if resp.Code != http.StatusUnauthorized {
			t.Fatalf("header %q status=%d, want 401", header, resp.Code)
		}
		if got, want := resp.Header().Get("WWW-Authenticate"), mcpBearerChallenge; got != want {
			t.Fatalf("header %q challenge=%q, want %q", header, got, want)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer stage-mesh-style-secret")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusNoContent {
		t.Fatalf("valid dedicated bearer status=%d, want 204", resp.Code)
	}
}

func TestMCPBearerFailuresAdvertiseTheBearerChallenge(t *testing.T) {
	t.Parallel()
	_, _, store, cleanup := newAuthServer(t, false)
	defer cleanup()

	for _, tc := range []struct {
		name   string
		header string
	}{
		{name: "missing", header: ""},
		{name: "empty", header: "Bearer   "},
		{name: "invalid", header: "Bearer wrong"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := SessionAuth(SessionAuthConfig{
				Store:    store,
				MCPToken: "stage-mesh-style-secret",
				MCPUser:  auth.User{ID: "mcp-http", Role: auth.RoleAdmin, TenantID: "acme"},
			})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
			req.Header.Set("Accept", "application/json")
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			if resp.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.Code)
			}
			if got, want := resp.Header().Get("WWW-Authenticate"), mcpBearerChallenge; got != want {
				t.Fatalf("WWW-Authenticate = %q, want %q", got, want)
			}
		})
	}
}

func TestMCPDedicatedBearerTokenPassesTheAdminRouteGate(t *testing.T) {
	t.Parallel()
	_, _, store, cleanup := newAuthServer(t, false)
	defer cleanup()
	s := &Server{
		Auth:           store,
		MCPBearerToken: "stage-mesh-style-secret",
		MCPBearerUser:  auth.User{ID: "mcp-http", Role: auth.RoleAdmin, TenantID: "acme"},
		MCPHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	r := chi.NewRouter()
	s.mountMiddleware(r)
	r.Group(func(ar chi.Router) {
		ar.Use(s.requireAdminMW)
		s.mountMCPRoute(ar)
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer stage-mesh-style-secret")
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	if resp.Code != http.StatusNoContent {
		t.Fatalf("dedicated MCP token route status=%d body=%s", resp.Code, resp.Body.String())
	}
}

func TestMCPDedicatedBearerIsEnforcedWithoutAuthStore(t *testing.T) {
	t.Parallel()
	h := SessionAuth(SessionAuthConfig{
		MCPToken: "embedded-mcp-secret",
		MCPUser:  auth.User{TenantID: "acme"},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFromContext(r.Context())
		if !ok || u.ID != "mcp-http" || u.Role != auth.RoleAdmin || u.TenantID != "acme" {
			t.Fatalf("dedicated bearer identity = %+v, ok=%t", u, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, header := range []string{"", "Bearer wrong", "Basic embedded-mcp-secret"} {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
		req.Header.Set("Accept", "application/json")
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		resp := httptest.NewRecorder()
		h.ServeHTTP(resp, req)
		if resp.Code != http.StatusUnauthorized {
			t.Fatalf("header %q status=%d, want 401", header, resp.Code)
		}
		if got := resp.Header().Get("WWW-Authenticate"); got != mcpBearerChallenge {
			t.Fatalf("header %q challenge=%q, want %q", header, got, mcpBearerChallenge)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "bearer embedded-mcp-secret")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusNoContent {
		t.Fatalf("valid dedicated bearer status=%d, want 204", resp.Code)
	}
}

func TestMCPBearerTakesPrecedenceOverDashboardSessionCookie(t *testing.T) {
	t.Parallel()
	_, _, store, cleanup := newAuthServer(t, false)
	defer cleanup()
	users, err := store.ListUsers(context.Background())
	if err != nil || len(users) != 1 {
		t.Fatalf("users = %+v, err=%v", users, err)
	}
	cookie, err := store.CreateSession(context.Background(), users[0].ID, "ua", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var got auth.User
	h := SessionAuth(SessionAuthConfig{
		Store:    store,
		MCPToken: "stage-mesh-style-secret",
		MCPUser:  auth.User{ID: "mcp-http", Role: auth.RoleAdmin, TenantID: "acme"},
	})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = UserFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	req.Header.Set("Authorization", "Bearer stage-mesh-style-secret")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK || got.ID != "mcp-http" || got.TenantID != "acme" {
		t.Fatalf("MCP bearer did not override dashboard cookie: identity=%+v status=%d", got, resp.Code)
	}
}

func TestMCPRejectsDashboardCookieAndBasicWithoutBearer(t *testing.T) {
	t.Parallel()
	store, cleanup := newMCPAuthStore(t, true)
	defer cleanup()
	users, err := store.ListUsers(context.Background())
	if err != nil || len(users) != 1 {
		t.Fatalf("users = %+v, err=%v", users, err)
	}
	cookie, err := store.CreateSession(context.Background(), users[0].ID, "ua", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	h := SessionAuth(SessionAuthConfig{Store: store})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	for _, authMethod := range []string{"cookie", "basic", "cookie-and-basic", "invalid-bearer-with-cookie"} {
		t.Run(authMethod, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
			req.Header.Set("Accept", "application/json")
			if authMethod == "cookie" || authMethod == "cookie-and-basic" || authMethod == "invalid-bearer-with-cookie" {
				req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
			}
			if authMethod == "basic" || authMethod == "cookie-and-basic" {
				req.SetBasicAuth("alice", "secret-pass")
			}
			if authMethod == "invalid-bearer-with-cookie" {
				req.Header.Set("Authorization", "Bearer invalid")
			}
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			if resp.Code != http.StatusUnauthorized || resp.Header().Get("WWW-Authenticate") != mcpBearerChallenge || called {
				t.Fatalf("auth %s: status=%d challenge=%q handler_called=%t", authMethod, resp.Code, resp.Header().Get("WWW-Authenticate"), called)
			}
		})
	}
}

func TestMCPPerUserAPIBearerKeepsTenantIdentity(t *testing.T) {
	t.Parallel()
	store, cleanup := newMCPAuthStore(t, true)
	defer cleanup()
	users, err := store.ListUsers(context.Background())
	if err != nil || len(users) != 1 {
		t.Fatalf("users = %+v, err=%v", users, err)
	}
	raw, _, err := store.MintAPIToken(context.Background(), users[0].ID, "mcp", 0)
	if err != nil {
		t.Fatal(err)
	}
	var got auth.User
	h := SessionAuth(SessionAuthConfig{
		Store: store, MCPToken: "dedicated-service-token",
		MCPUser: auth.User{ID: "mcp-http", Role: auth.RoleAdmin, TenantID: "other-tenant"},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = UserFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+raw)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusNoContent || got.ID != users[0].ID || got.TenantID != users[0].TenantID {
		t.Fatalf("per-user MCP identity = %+v status=%d", got, resp.Code)
	}
}

func TestMCPLocalNoAuthBootstrapRequiresExplicitOptIn(t *testing.T) {
	t.Parallel()
	for _, allow := range []bool{false, true} {
		h := SessionAuth(SessionAuthConfig{Store: emptyAuthStore{}, LegacyAllowNoAuth: allow})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
		resp := httptest.NewRecorder()
		h.ServeHTTP(resp, req)
		want := http.StatusUnauthorized
		if allow {
			want = http.StatusNoContent
		}
		if resp.Code != want {
			t.Fatalf("allow_no_auth=%t: status=%d, want %d", allow, resp.Code, want)
		}
	}
}

func TestMCPNoAuthBootstrapDoesNotAcceptConfiguredBasicCredentials(t *testing.T) {
	t.Parallel()
	store, cleanup := newMCPAuthStore(t, false)
	defer cleanup()
	called := false
	s := &Server{
		Auth: store,
		BasicAuth: BasicAuthConfig{
			User: "legacy", PasswordSHA256: hashPass("secret-pass"), AllowNoAuth: true,
		},
	}
	router := chi.NewRouter()
	s.mountMiddleware(router)
	router.Post("/mcp", func(http.ResponseWriter, *http.Request) { called = true })
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	req.SetBasicAuth("legacy", "secret-pass")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized || resp.Header().Get("WWW-Authenticate") != mcpBearerChallenge || called {
		t.Fatalf("configured Basic MCP: status=%d challenge=%q handler_called=%t", resp.Code, resp.Header().Get("WWW-Authenticate"), called)
	}
}

func TestMCPBearerRejectionIncludesBearerChallenge(t *testing.T) {
	t.Parallel()
	_, _, store, cleanup := newAuthServer(t, false)
	defer cleanup()
	h := SessionAuth(SessionAuthConfig{
		Store:    store,
		MCPToken: "stage-mesh-style-secret",
		MCPUser:  auth.User{ID: "mcp-http", Role: auth.RoleAdmin, TenantID: "acme"},
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("rejected bearer reached the MCP handler")
	}))

	for _, bearer := range []string{"Bearer wrong-secret", "Bearer "} {
		t.Run(bearer, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
			req.Header.Set("Authorization", bearer)
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			if resp.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.Code)
			}
			if got, want := resp.Header().Get("WWW-Authenticate"), mcpBearerChallenge; got != want {
				t.Fatalf("WWW-Authenticate = %q, want %q", got, want)
			}
		})
	}
}

func TestRBACMemberBlockedFromWorkflowDelete(t *testing.T) {
	t.Parallel()
	url, j, store, cleanup := newAuthServer(t, false)
	defer cleanup()

	ctx := context.Background()
	// Create a member account and a workflow.
	if _, err := store.CreateUser(ctx, "bob", "secret-pass", auth.RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflow(ctx, "wf_x", "x-flow", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	// Mint a session for bob via direct store call so the test
	// bypasses the login form.
	cookie, _ := store.CreateSession(ctx, lookupUserID(t, store, "bob"), "ua", "1.2.3.4", 1<<30)

	cl := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, _ := http.NewRequest(http.MethodPost, url+"/workflows/x-flow/delete", strings.NewReader(""))
	req.Header.Set("Origin", url)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 403\n%s", resp.StatusCode, body)
	}
}

func TestRBACAdminCanDeleteWorkflow(t *testing.T) {
	t.Parallel()
	url, j, store, cleanup := newAuthServer(t, false)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_x", "x-flow", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	// Move the seeded run for wf_1 from newTestJournal's fixture isn't
	// applicable here because newAuthServer doesn't seed it; the new
	// workflow has no runs so delete should proceed.

	cookie, _ := store.CreateSession(ctx, lookupUserID(t, store, "alice"), "", "", 1<<30)
	cl := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, _ := http.NewRequest(http.MethodPost, url+"/workflows/x-flow/delete", strings.NewReader(""))
	req.Header.Set("Origin", url)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 303\n%s", resp.StatusCode, body)
	}
}

func TestLogoutClearsSessionCookie(t *testing.T) {
	t.Parallel()
	url, _, store, cleanup := newAuthServer(t, false)
	defer cleanup()
	cookie, _ := store.CreateSession(context.Background(), lookupUserID(t, store, "alice"), "", "", 1<<30)

	cl := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, _ := http.NewRequest(http.MethodPost, url+"/logout", strings.NewReader(""))
	req.Header.Set("Origin", url)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout status = %d, want 303", resp.StatusCode)
	}
	cleared := pickCookie(resp.Cookies(), SessionCookieName)
	if cleared == nil || cleared.MaxAge != -1 {
		t.Fatalf("logout did not clear cookie; got %+v", cleared)
	}
	// The session row should be gone (cookie value no longer resolves).
	if _, err := store.ResolveSession(context.Background(), cookie); err == nil {
		t.Fatal("session row still resolves after logout")
	}
}

func makeForm(kv ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

func mustPostFormAuth(t *testing.T, cl *http.Client, target string, form url.Values) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if u, err := url.Parse(target); err == nil {
		req.Header.Set("Origin", u.Scheme+"://"+u.Host)
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func pickCookie(list []*http.Cookie, name string) *http.Cookie {
	for _, c := range list {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func lookupUserID(t *testing.T, store *auth.Store, username string) string {
	t.Helper()
	users, _ := store.ListUsers(context.Background())
	for _, u := range users {
		if u.Username == username {
			return u.ID
		}
	}
	t.Fatalf("user %q not seeded", username)
	return ""
}
