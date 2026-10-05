package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/auth"
	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/graph"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// TestGraphJSONIsAdminGated pins an estate-wide read leak. /graph.json
// serialises every tenant's workflow slugs, the full workflow->credential
// grant matrix, credential names/services/rotation errors and dead-letter
// error text, and its handler discards *http.Request entirely, so viewerScope
// cannot be consulted even in principle. It was mounted on the MEMBER router
// while the identical MCP query_graph tool already sat behind requireAdminMW.
//
// The underlying hazard is that authorization in Mount is POSITIONAL: a route
// is admin-gated only because its mount call happens to sit inside the
// r.Group block, so moving one line silently exposes it with no test failing.
// Asserting on middleware depth catches that, where reading the source does not.
func TestGraphJSONIsAdminGated(t *testing.T) {
	t.Parallel()
	s := &Server{
		Journal:     &journal.Journal{},
		Credentials: &credentials.Repo{},
		Graph:       &graph.Graph{},
		MCPHandler:  http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	r := chi.NewRouter()
	s.Mount(r)

	depth := map[string]int{}
	if err := chi.Walk(r, func(method, route string, _ http.Handler, mws ...func(http.Handler) http.Handler) error {
		depth[method+" "+route] = len(mws)
		return nil
	}); err != nil {
		t.Fatalf("walk routes: %v", err)
	}

	graphDepth, ok := depth["GET /graph.json"]
	if !ok {
		t.Fatal("/graph.json is not registered; wire s.Graph in this test")
	}
	adminDepth, ok := depth["GET /audit"]
	if !ok {
		t.Fatal("/audit is not registered; it is the admin-gated reference route")
	}
	mcpDepth, ok := depth["POST /mcp"]
	if !ok {
		t.Fatal("/mcp is not registered; wire MCPHandler in this test")
	}
	memberDepth, ok := depth["GET /runs"]
	if !ok {
		t.Fatal("/runs is not registered; it is the member reference route")
	}
	if graphDepth != adminDepth {
		t.Fatalf("/graph.json middleware depth = %d, want %d (same as admin-gated /audit)", graphDepth, adminDepth)
	}
	if graphDepth <= memberDepth {
		t.Fatalf("/graph.json depth %d must exceed member-route depth %d", graphDepth, memberDepth)
	}
	if mcpDepth != adminDepth {
		t.Fatalf("/mcp middleware depth = %d, want %d (same as admin-gated /audit)", mcpDepth, adminDepth)
	}
}

// TestRequireAdminMW is the regression test for the RBAC ship-blocker
// where privileged mutations (workflow code, credentials, triggers) were
// reachable by any authenticated member. The route-group gate must 403 a
// member, allow an admin, and pass through entirely when auth is unwired.
func TestRequireAdminMW(t *testing.T) {
	t.Parallel()

	reached := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	cases := []struct {
		name     string
		wired    bool
		user     *auth.User
		wantCode int
	}{
		{"auth unwired passes through", false, nil, http.StatusOK},
		{"admin allowed", true, &auth.User{ID: "u1", Role: auth.RoleAdmin}, http.StatusOK},
		{"member forbidden", true, &auth.User{ID: "u2", Role: auth.RoleMember}, http.StatusForbidden},
		{"anonymous unauthorized", true, nil, http.StatusUnauthorized},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := &Server{}
			if tc.wired {
				// A non-nil AuthAdmin so s.Auth == nil is false; the
				// gate logic itself never calls into the store.
				s.Auth = &auth.Store{}
			}
			h := s.requireAdminMW(http.HandlerFunc(reached))

			req := httptest.NewRequest(http.MethodPost, "/credentials", nil)
			if tc.user != nil {
				req = req.WithContext(withUser(req.Context(), *tc.user))
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("code = %d, want %d", rec.Code, tc.wantCode)
			}
		})
	}
}
