package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/auth"
	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/mcp"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestMailSendResolutionHTTPMCPRefusesNoAuthBootstrapAndMember(t *testing.T) {
	j := journalForServerTest(t)
	ctx := context.Background()
	const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := j.CreateWorkflowInTenant(ctx, "wf_mail_route", "mail-route", "hash", "0.1.0", json.RawMessage(`{}`), journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_mail_route", "wf_mail_route", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.ClaimStepAttemptSeq(ctx, "run_mail_route", "send", 1, 3, "private-key", "input"); err != nil {
		t.Fatal(err)
	}
	admitted, err := j.AdmitMailSend(ctx, "run_mail_route", "", "send", 1, 1, "private-key", digest,
		journal.MailSendTarget{ProviderID: "google", ConnectionID: "conn_route"})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, "run_mail_route", "failed"); err != nil {
		t.Fatal(err)
	}
	tool := &mcp.Server{
		Journal: j, Scopes: &mcp.WriteScopes{MailReconciliation: true},
		TenantIDFromContext: func(ctx context.Context) string {
			if user, ok := UserFromContext(ctx); ok {
				return user.TenantID
			}
			return journal.DefaultTenant
		},
		ActorIDFromContext: func(ctx context.Context) string {
			if user, ok := UserFromContext(ctx); ok {
				return user.ID
			}
			return "mcp"
		},
		MailReconciliationAuthorized: func(ctx context.Context) bool {
			user, ok := UserFromContext(ctx)
			return ok && user.IsAdmin()
		},
	}
	s := &Server{Journal: j, Credentials: &credentials.Repo{}, MCPHandler: tool,
		BasicAuth: BasicAuthConfig{AllowNoAuth: true},
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil))}
	router := chi.NewRouter()
	s.Mount(router)
	params := map[string]any{"name": "reactor_resolve_mail_send", "arguments": map[string]any{
		"run_id": "run_mail_route", "intent_id": admitted.IntentID, "confirm_intent_id": admitted.IntentID,
		"seq": 1, "target_provider_id": "google", "target_connection_id": "conn_route",
		"decision": "closed_unverified", "evidence_kind": "manual_decision", "evidence_sha256": digest,
	}}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
	if err != nil {
		t.Fatal(err)
	}
	call := func(user *auth.User) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if user != nil {
			req = req.WithContext(withUser(req.Context(), *user))
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, result := call(nil); code != http.StatusOK || !strings.Contains(result, `"isError":true`) {
		t.Fatalf("no-auth bootstrap resolution status=%d body=%s", code, result)
	}
	member := auth.User{ID: "member", TenantID: journal.DefaultTenant, Role: auth.RoleMember}
	if code, result := call(&member); code != http.StatusOK || !strings.Contains(result, `"isError":true`) {
		t.Fatalf("member resolution status=%d body=%s", code, result)
	}
	admin := auth.User{ID: "admin", TenantID: journal.DefaultTenant, Role: auth.RoleAdmin}
	if code, result := call(&admin); code != http.StatusOK || strings.Contains(result, `"isError":true`) ||
		!strings.Contains(result, admitted.IntentID) {
		t.Fatalf("admin resolution status=%d body=%s", code, result)
	}
}
