package server

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestMCPRouteIsPostOnly keeps the transport contract at the router boundary.
// A handler-level method check is still useful, but registering the route with
// chi.Handle would make every verb reach that handler and could turn a future
// handler change into an accidental second MCP transport.
func TestMCPRouteIsPostOnly(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	s := &Server{
		BasicAuth: BasicAuthConfig{AllowNoAuth: true},
		MCPHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	r := chi.NewRouter()
	s.Mount(r)

	for _, method := range []string{http.MethodGet, http.MethodPut} {
		req := httptest.NewRequest(method, "/mcp", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /mcp status = %d, want 405", method, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != http.MethodPost {
			t.Errorf("%s /mcp Allow = %q, want %q", method, got, http.MethodPost)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("POST /mcp status = %d, want 204", rec.Code)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("MCP handler calls = %d, want only the POST request", got)
	}
}
