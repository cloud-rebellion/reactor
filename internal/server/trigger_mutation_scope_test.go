package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/auth"
)

func TestMemberTriggerMutationsCannotCrossSameSlugTenantBoundary(t *testing.T) {
	t.Parallel()
	j := journalForServerTest(t)
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_acme_shared_mutation", "shared-mutation", "h", "1", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_globex_shared_mutation", "shared-mutation", "h", "1", json.RawMessage(`{}`), "globex"); err != nil {
		t.Fatal(err)
	}
	acmeCron, err := j.CreateCronTrigger(ctx, "wf_acme_shared_mutation", []byte(`{"spec":"0 9 * * *"}`))
	if err != nil {
		t.Fatal(err)
	}
	globexCron, err := j.CreateCronTrigger(ctx, "wf_globex_shared_mutation", []byte(`{"spec":"0 10 * * *"}`))
	if err != nil {
		t.Fatal(err)
	}
	acmeWebhook, err := j.CreateWebhookTrigger(ctx, "wf_acme_shared_mutation", "whk_scope_webhook", "cred_scope_webhook", "generic", []byte(`{"created_by":"test"}`))
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{Journal: j, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	member := auth.User{ID: "member_acme", Role: auth.RoleMember, TenantID: "acme"}
	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(withUser(r.Context(), member)))
		})
	})
	router.Post("/workflows/{slug}/triggers/{trigger_id}/pause", s.triggerPause)
	router.Post("/workflows/{slug}/triggers/{trigger_id}/resume", s.triggerResume)
	router.Post("/workflows/{slug}/triggers/{trigger_id}/edit", s.triggerEditCron)
	router.Post("/workflows/{slug}/triggers/{trigger_id}/delete", s.workflowDeleteTrigger)

	request := func(target string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		body := ""
		if form != nil {
			body = form.Encode()
		}
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	// A member-controlled tenant query must not override the authenticated tenant,
	// and pairing the member's same slug with the foreign trigger id must stay 404.
	foreignBase := "/workflows/shared-mutation/triggers/" + globexCron
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"pause":  request(foreignBase+"/pause?tenant=globex", nil),
		"resume": request(foreignBase+"/resume?tenant=globex", nil),
		"edit": request(foreignBase+"/edit?tenant=globex", url.Values{
			"spec": {"* * * * *"},
		}),
		"delete": request(foreignBase+"/delete?tenant=globex", nil),
	} {
		if rec.Code != http.StatusNotFound {
			t.Errorf("foreign %s status = %d, want 404; body=%s", name, rec.Code, rec.Body.String())
		}
	}
	globexTriggers, err := j.ListTriggersForWorkflow(ctx, "wf_globex_shared_mutation")
	if err != nil || len(globexTriggers) != 1 {
		t.Fatalf("globex triggers = %+v, %v", globexTriggers, err)
	}
	if globexTriggers[0].State != "active" || string(globexTriggers[0].Config) != `{"spec":"0 10 * * *"}` {
		t.Fatalf("foreign trigger changed through acme route: %+v", globexTriggers[0])
	}

	if rec := request("/workflows/shared-mutation/triggers/"+acmeCron+"/pause", nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("same-workflow pause status = %d, want 303: %s", rec.Code, rec.Body.String())
	}
	acmeTriggers, err := j.ListTriggersForWorkflow(ctx, "wf_acme_shared_mutation")
	if err != nil {
		t.Fatal(err)
	}
	var acmeCronState string
	for _, trigger := range acmeTriggers {
		if trigger.ID == acmeCron {
			acmeCronState = trigger.State
		}
	}
	if acmeCronState != "disabled" {
		t.Fatalf("same-workflow cron state = %q, want disabled", acmeCronState)
	}

	// Even within the authorized workflow, the cron editor must not rewrite a
	// webhook trigger's verifier config.
	rec := request("/workflows/shared-mutation/triggers/"+acmeWebhook+"/edit", url.Values{
		"spec": {"* * * * *"},
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("webhook cron-edit status = %d, want 404: %s", rec.Code, rec.Body.String())
	}
	acmeTriggers, err = j.ListTriggersForWorkflow(ctx, "wf_acme_shared_mutation")
	if err != nil {
		t.Fatal(err)
	}
	for _, trigger := range acmeTriggers {
		if trigger.ID == acmeWebhook && string(trigger.Config) != `{"created_by":"test"}` {
			t.Fatalf("cron edit changed webhook config: %s", trigger.Config)
		}
	}
}
