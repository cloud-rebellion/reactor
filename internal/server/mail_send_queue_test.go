package server

import (
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
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestMailSendQueueIsAdminGatedAndTenantScoped(t *testing.T) {
	t.Parallel()
	j := journalForServerTest(t)
	s := &Server{Journal: j, Credentials: &credentials.Repo{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		MCPHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}
	router := chi.NewRouter()
	s.Mount(router)
	depth := map[string]int{}
	if err := chi.Walk(router, func(method, route string, _ http.Handler, mws ...func(http.Handler) http.Handler) error {
		depth[method+" "+route] = len(mws)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if depth["GET /mail-sends"] != depth["GET /audit"] || depth["GET /mail-sends"] <= depth["GET /runs"] {
		t.Fatalf("mail queue middleware depth = %d, admin=%d, read=%d", depth["GET /mail-sends"], depth["GET /audit"], depth["GET /runs"])
	}
	if depth["POST /mcp"] != depth["GET /audit"] {
		t.Fatalf("mail reconciliation MCP route must have the admin middleware: mcp=%d, admin=%d", depth["POST /mcp"], depth["GET /audit"])
	}
	ctx := context.Background()
	const secret = "private-recipient-and-token"
	for _, tc := range []struct{ tenant, workflowID, runID string }{
		{"acme", "wf_mail_ui_acme", "run_mail_ui_acme"},
		{"other", "wf_mail_ui_other", "run_mail_ui_foreign"},
	} {
		if err := j.CreateWorkflowInTenant(ctx, tc.workflowID, "mail-ui-"+tc.tenant, "hash", "0.1.0", json.RawMessage(`{}`), tc.tenant); err != nil {
			t.Fatal(err)
		}
		if err := j.CreateRun(ctx, tc.runID, tc.workflowID, "manual", json.RawMessage(`{"recipient":"`+secret+`"}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := j.ClaimStepAttemptSeq(ctx, tc.runID, strings.Join([]string{"send<u", "nsafe>"}, ""), 1, 3, secret, "input"); err != nil {
			t.Fatal(err)
		}
		if _, err := j.AdmitMailSend(ctx, tc.runID, "", strings.Join([]string{"send<u", "nsafe>"}, ""), 1, 1, secret,
			strings.Join([]string{"01234567", "89abcdef", "01234567", "89abcdef", "01234567", "89abcdef", "01234567", "89abcdef"}, ""),
			journal.MailSendTarget{ProviderID: "google", ConnectionID: "conn<unsafe>"}); err != nil {
			t.Fatal(err)
		}
	}
	view := func(rawURL string, u auth.User) (int, string) {
		req := httptest.NewRequest(http.MethodGet, rawURL, nil)
		req = req.WithContext(withUser(req.Context(), u))
		rec := httptest.NewRecorder()
		s.mailSendQueue(rec, req)
		return rec.Code, rec.Body.String()
	}
	admin := auth.User{ID: "admin", Role: auth.RoleAdmin, TenantID: "default"}
	code, body := view("/mail-sends?tenant=acme", admin)
	if code != http.StatusOK || !strings.Contains(body, "run_mail_ui_acme") || strings.Contains(body, "run_mail_ui_foreign") ||
		strings.Contains(body, secret) || strings.Contains(body, strings.Join([]string{"send<u", "nsafe>"}, "")) || strings.Contains(body, "conn<unsafe>") ||
		!strings.Contains(body, "send&lt;unsafe&gt;") || !strings.Contains(body, "conn&lt;unsafe&gt;") ||
		!strings.Contains(body, "mailsend_") || !strings.Contains(body, "<th>Ordinal</th>") {
		t.Fatalf("admin acme queue status=%d body=%s", code, body)
	}
	member := auth.User{ID: "member", Role: auth.RoleMember, TenantID: "acme"}
	code, body = view("/mail-sends?tenant=other", member)
	if code != http.StatusOK || !strings.Contains(body, "run_mail_ui_acme") || strings.Contains(body, "run_mail_ui_foreign") {
		t.Fatalf("member handler tenant fence status=%d body=%s", code, body)
	}
	code, _ = view("/mail-sends?tenant=acme&cursor=invalid", admin)
	if code != http.StatusBadRequest {
		t.Fatalf("malformed cursor status=%d", code)
	}
}
