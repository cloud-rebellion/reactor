package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// newPostClient returns a redirect-following-disabled client + a
// helper that POSTs with CSRF-compatible same-origin Origin header.
func postSameOrigin(t *testing.T, target string, form url.Values) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if u, err := url.Parse(target); err == nil {
		req.Header.Set("Origin", u.Scheme+"://"+u.Host)
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestNotificationsPageRendersAddForm(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t)
	body := getBody(t, srv.URL+"/notifications")
	s := string(body)
	for _, want := range []string{
		"Channels",
		"Add channel",
		"slack_webhook",
		"generic_webhook",
		"email_smtp",
		"No channels configured",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in /notifications", want)
		}
	}
}

func TestNotificationPagesUseBoundedTenantScopedChannelMetadata(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t)
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_channel_meta", "channel-meta", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= notificationPageSize; i++ {
		name := fmt.Sprintf("acme-channel-%03d", i)
		if _, err := j.CreateNotificationChannelInTenant(ctx, "acme", name, journal.ChannelKindGenericWebhook, json.RawMessage(`{"url":"https://example.invalid/hook"}`)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := j.CreateNotificationChannelInTenant(ctx, "globex", "zz-foreign-channel", journal.ChannelKindGenericWebhook, json.RawMessage(`{"url":"https://example.invalid/foreign"}`)); err != nil {
		t.Fatal(err)
	}

	adminFirst := string(getBody(t, srv.URL+"/notifications"))
	if !strings.Contains(adminFirst, "acme-channel-099") || strings.Contains(adminFirst, "acme-channel-100") || !strings.Contains(adminFirst, `/notifications?page=1`) {
		t.Fatal("admin first page did not bound and link the channel inventory")
	}
	adminSecond := string(getBody(t, srv.URL+"/notifications?page=1"))
	if !strings.Contains(adminSecond, "acme-channel-100") || !strings.Contains(adminSecond, "zz-foreign-channel") || !strings.Contains(adminSecond, `/notifications?page=0`) {
		t.Fatal("admin second page did not preserve the install-wide inventory")
	}

	workflowFirst := string(getBody(t, srv.URL+"/workflows/channel-meta?tenant=acme"))
	if !strings.Contains(workflowFirst, "acme-channel-099") || strings.Contains(workflowFirst, "acme-channel-100") || strings.Contains(workflowFirst, "zz-foreign-channel") || !strings.Contains(workflowFirst, `/workflows/channel-meta?tenant=acme&channel_page=1`) {
		t.Fatal("workflow first picker page was not bounded or tenant-scoped")
	}
	workflowSecond := string(getBody(t, srv.URL+"/workflows/channel-meta?tenant=acme&channel_page=1"))
	if !strings.Contains(workflowSecond, "acme-channel-100") || strings.Contains(workflowSecond, "zz-foreign-channel") || !strings.Contains(workflowSecond, `/workflows/channel-meta?tenant=acme&channel_page=0`) {
		t.Fatal("workflow second picker page lost tenant scope or pagination")
	}
}

func TestNotificationsCreateRejectsPlaintextSlackURL(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t)
	form := url.Values{
		"name":      {"ops"},
		"kind":      {"slack_webhook"},
		"slack_url": {"https://evil.example/hook"},
	}
	resp := postSameOrigin(t, srv.URL+"/notifications", form)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 422\n%s", resp.StatusCode, body)
	}
}

func TestNotificationsCreateSlackHappyPath(t *testing.T) {
	t.Parallel()
	srv, j, creds := newTestServer(t)
	if err := creds.Create(context.Background(), credentials.CreateParams{ID: "cred_slack", Name: "Slack webhook", TenantID: journal.DefaultTenant}); err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"name":                    {"ops"},
		"kind":                    {"slack_webhook"},
		"slack_url_credential_id": {"cred_slack"},
	}
	resp := postSameOrigin(t, srv.URL+"/notifications", form)
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 303\n%s", resp.StatusCode, body)
	}
	body := getBody(t, srv.URL+"/notifications")
	if !strings.Contains(string(body), "ops") {
		t.Fatal("created channel not listed on /notifications")
	}
	channels, err := j.ListNotificationChannels(context.Background())
	if err != nil || len(channels) != 1 {
		t.Fatalf("stored channels = %d, err = %v", len(channels), err)
	}
	if strings.Contains(string(channels[0].ConfigJSON), "hooks.slack.com") || !strings.Contains(string(channels[0].ConfigJSON), "cred_slack") {
		t.Fatalf("channel config was not a vault reference: %s", channels[0].ConfigJSON)
	}
}

func TestNotificationsCreateRejectsCrossTenantCredential(t *testing.T) {
	t.Parallel()
	srv, j, creds := newTestServer(t)
	if err := creds.Create(context.Background(), credentials.CreateParams{ID: "cred_other", Name: "Other webhook", TenantID: "other"}); err != nil {
		t.Fatal(err)
	}
	resp := postSameOrigin(t, srv.URL+"/notifications", url.Values{
		"name":                    {"ops"},
		"kind":                    {"slack_webhook"},
		"slack_url_credential_id": {"cred_other"},
	})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
	channels, err := j.ListNotificationChannels(context.Background())
	if err != nil || len(channels) != 0 {
		t.Fatalf("stored channels = %d, err = %v", len(channels), err)
	}
}

func TestNotificationFormRejectsInlineSecrets(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, kind string
		form       url.Values
	}{
		{"Slack webhook URL", journal.ChannelKindSlackWebhook, url.Values{"slack_url": {"https://hooks.slack.com/services/X/Y/Z"}}},
		{"webhook URL userinfo", journal.ChannelKindGenericWebhook, url.Values{"webhook_url": {"https://user:synthetic-secret@example.com/hook"}}},
		{"generic auth header", journal.ChannelKindGenericWebhook, url.Values{"webhook_url": {"https://example.com/hook"}, "webhook_header_name": {"X-Auth"}, "webhook_header_value": {"synthetic-secret"}}},
		{"SMTP password", journal.ChannelKindEmailSMTP, url.Values{"smtp_host": {"smtp.example.com"}, "smtp_from": {"a@example.com"}, "smtp_to": {"b@example.com"}, "smtp_password": {"synthetic-secret"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/notifications", strings.NewReader(tc.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if _, _, err := parseChannelConfig(tc.kind, req); err == nil {
				t.Fatal("inline secret was accepted")
			}
		})
	}
}

func TestNotificationsTestReturns503WhenNotifierNotWired(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t)
	ctx := context.Background()
	chID, err := j.CreateNotificationChannel(ctx, "ops", "generic_webhook", json.RawMessage(`{"url":"https://example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp := postSameOrigin(t, srv.URL+"/notifications/"+chID+"/test", url.Values{})
	if resp.StatusCode != http.StatusServiceUnavailable {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 503\n%s", resp.StatusCode, body)
	}
}

func TestWorkflowNotificationRouteRoundTrip(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t)
	ctx := context.Background()

	if err := j.CreateWorkflow(ctx, "wf_demo", "demo", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	chID, err := j.CreateNotificationChannel(ctx, "ops", "generic_webhook", json.RawMessage(`{"url":"https://example.com/hook"}`))
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"channel_id":  {chID},
		"on_statuses": {"failed,failed_dlq"},
	}
	resp := postSameOrigin(t, srv.URL+"/workflows/demo/notifications", form)
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("attach status = %d, want 303\n%s", resp.StatusCode, body)
	}

	routes, err := j.ListNotificationRoutesForWorkflow(ctx, "wf_demo")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].ChannelID != chID {
		t.Fatalf("routes = %+v", routes)
	}

	// Workflow detail page renders the route.
	body := getBody(t, srv.URL+"/workflows/demo")
	if !strings.Contains(string(body), "ops") {
		t.Fatal("workflow detail missing channel name")
	}
	if !strings.Contains(string(body), "failed,failed_dlq") {
		t.Fatal("workflow detail missing on_statuses")
	}

	// Detach via the per-workflow delete handler.
	resp = postSameOrigin(t, srv.URL+"/workflows/demo/notifications/"+chID+"/delete", url.Values{})
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("detach status = %d, want 303\n%s", resp.StatusCode, body)
	}
	routes, _ = j.ListNotificationRoutesForWorkflow(ctx, "wf_demo")
	if len(routes) != 0 {
		t.Fatalf("route survived detach: %+v", routes)
	}
}

func TestWorkflowNotificationAttachFormPreservesTenantScope(t *testing.T) {
	t.Parallel()
	html := renderNotificationRoutesSectionForTenant(
		"shared",
		nil,
		[]journal.NotificationChannelMetadata{{ID: "ch_acme", Name: "ops", Kind: journal.ChannelKindGenericWebhook}},
		false,
		"?tenant=acme",
	)
	want := `action="/workflows/shared/notifications?tenant=acme"`
	if !strings.Contains(html, want) {
		t.Fatalf("attach form lost tenant selector: missing %q in %s", want, html)
	}
}

func TestWorkflowNotificationAttachRedirectPreservesTenantScope(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t)
	ctx := context.Background()
	for _, tenant := range []string{"acme", "globex"} {
		if err := j.CreateWorkflowInTenant(ctx, "wf_shared_"+tenant, "shared", "h", "0.1.0", json.RawMessage(`{}`), tenant); err != nil {
			t.Fatal(err)
		}
	}
	channelID, err := j.CreateNotificationChannelInTenant(ctx, "acme", "ops", journal.ChannelKindGenericWebhook, json.RawMessage(`{"url":"https://example.com/hook"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp := postSameOrigin(t, srv.URL+"/workflows/shared/notifications?tenant=acme", url.Values{"channel_id": {channelID}})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("attach status = %d, want 303", resp.StatusCode)
	}
	if got, want := resp.Header.Get("Location"), "/workflows/shared?tenant=acme"; got != want {
		t.Fatalf("attach redirect = %q, want %q", got, want)
	}
}

// TestDuplicateChannelNameGivesAnActionableError covers the operator half of the
// per-tenant name change (migration 0027). The create handler used to pass
// err.Error() straight to the page, so a duplicate name rendered
// "journal: create notification channel: UNIQUE constraint failed:
// notification_channels.tenant_id, notification_channels.name" into the browser:
// it leaks the schema and tells the operator nothing about what to do next.
func TestDuplicateChannelNameGivesAnActionableError(t *testing.T) {
	t.Parallel()
	srv, _, creds := newTestServer(t)
	if err := creds.Create(context.Background(), credentials.CreateParams{ID: "cred_slack", Name: "Slack webhook", TenantID: journal.DefaultTenant}); err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"name":                    {"ops-slack"},
		"kind":                    {"slack_webhook"},
		"slack_url_credential_id": {"cred_slack"},
	}
	if resp := postSameOrigin(t, srv.URL+"/notifications", form); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("first create = %d, want 303", resp.StatusCode)
	}

	resp := postSameOrigin(t, srv.URL+"/notifications", form)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("duplicate create = %d, want 422", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	page := string(body)

	if !strings.Contains(page, "already have a channel named") {
		t.Fatalf("no actionable duplicate-name message in the page:\n%s", page)
	}
	// The name must be echoed so the operator knows which one collided.
	if !strings.Contains(page, "ops-slack") {
		t.Fatal("the message does not say which name was taken")
	}
	// And no driver internals.
	for _, leak := range []string{"UNIQUE constraint", "constraint failed", "notification_channels.tenant_id"} {
		if strings.Contains(page, leak) {
			t.Fatalf("the page leaks driver detail %q:\n%s", leak, page)
		}
	}
}
