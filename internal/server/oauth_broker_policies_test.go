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

	"github.com/bright-interaction/reactor/internal/auth"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/oauth"
	"github.com/go-chi/chi/v5"
	_ "modernc.org/sqlite"
)

func TestOAuthBrokerPolicyRouteRequiresAdminAndCSRF(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "broker.db")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(context.Background(), log, "sqlite://"+dbPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := oauth.New(db, oauth.EngineSQLite, make([]byte, 32))
	if err := store.UpsertProvider(context.Background(), oauth.Provider{ProviderID: "acme",
		AuthURL: "https://login.acme.example/auth", TokenURL: "https://login.acme.example/token", Enabled: true}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO oauth_connections
		(id, tenant_id, provider_id, name, token_encrypted, status) VALUES
		('conn-review', 'tenant-a', 'acme', 'Main', x'01', 'connected')`); err != nil {
		t.Fatal(err)
	}
	s := &Server{OAuth: store, Log: log, BasicAuth: BasicAuthConfig{AllowNoAuth: true}}
	r := chi.NewRouter()
	s.Mount(r)
	depth := map[string]int{}
	if err := chi.Walk(r, func(method, route string, _ http.Handler, mws ...func(http.Handler) http.Handler) error {
		depth[method+" "+route] = len(mws)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if depth["GET /oauth-broker-policies"] <= depth["GET /connections"] ||
		depth["POST /oauth-broker-policies/{id}"] <= depth["GET /connections"] {
		t.Fatalf("broker review routes not in admin group: %+v", depth)
	}
	member := auth.User{ID: "member", Username: "member", Role: auth.RoleMember, TenantID: "tenant-a"}
	admin := auth.User{ID: "admin", Username: "reviewer", Role: auth.RoleAdmin, TenantID: "tenant-a"}
	form := url.Values{"api_origin": {"https://api.acme.example"}, "path_prefix": {"/v1"},
		"method": {"GET"}, "expected_version": {"0"}}
	request := func(user auth.User, method, target, origin string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		req = req.WithContext(withUser(req.Context(), user))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}
	if got := request(member, http.MethodGet, "/oauth-broker-policies", ""); got.Code != http.StatusForbidden {
		t.Fatalf("member GET review page=%d", got.Code)
	}
	if got := request(member, http.MethodPost, "/oauth-broker-policies/conn-review", "http://example.com"); got.Code != http.StatusForbidden {
		t.Fatalf("member POST approval=%d", got.Code)
	}
	if got := request(admin, http.MethodPost, "/oauth-broker-policies/conn-review", ""); got.Code != http.StatusForbidden {
		t.Fatalf("missing Origin approval=%d", got.Code)
	}
	if got := request(admin, http.MethodPost, "/oauth-broker-policies/conn-review", "https://evil.test"); got.Code != http.StatusForbidden {
		t.Fatalf("cross-origin approval=%d", got.Code)
	}
	if got := request(admin, http.MethodPost, "/oauth-broker-policies/conn-review", "http://example.com"); got.Code != http.StatusSeeOther {
		t.Fatalf("admin same-origin approval=%d body=%s", got.Code, got.Body.String())
	}
	policy, err := store.GetBrokerPolicy(context.Background(), "tenant-a", "conn-review")
	if err != nil || policy.Version != 1 || policy.ReviewedBy != "reviewer" {
		t.Fatalf("review receipt=%+v err=%v", policy, err)
	}
	var mode string
	if err := db.QueryRow(`SELECT token_access_mode FROM oauth_connections WHERE id='conn-review'`).Scan(&mode); err != nil || mode != "broker_only" {
		t.Fatalf("approved mode=%q err=%v", mode, err)
	}
}
