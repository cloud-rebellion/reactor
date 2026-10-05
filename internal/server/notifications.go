package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// Notifier is the surface the dashboard uses to fire a test alert.
// Wired by the daemon; nil in read-only deployments.
type Notifier interface {
	TestChannel(ctx context.Context, channelID string) error
}

const notificationPageSize = 100

// Channel inventories are bounded on both dashboard surfaces. Invalid page
// numbers return the first page rather than allowing an unbounded SQL offset.
func notificationPageIndex(r *http.Request, key string) int {
	page, err := strconv.Atoi(r.URL.Query().Get(key))
	if err != nil || page < 0 || page > 10000 {
		return 0
	}
	return page
}

// notifications renders the channels list + the add-channel form.
//
// The unscoped metadata page is deliberate here. Every route in
// mountNotificationsRoutes sits inside the requireAdminMW group, and admin is a
// global role (viewerScope returns "" for it), so the only viewer who reaches
// this page is one entitled to the whole install. The member-facing workflow
// detail page uses a tenant-scoped metadata page because it is not admin-gated.
func (s *Server) notifications(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageIndex := notificationPageIndex(r, "page")
	channels, hasMore, err := s.Journal.ListNotificationChannelMetadataPage(ctx, notificationPageSize, pageIndex*notificationPageSize)
	if err != nil {
		s.errorPage(w, "list notification channels", err)
		return
	}
	tenants, current := s.availableTenants(r)
	s.renderPage(w, r, page{
		Title:   "Notifications",
		Heading: "Notifications",
		Body:    template.HTML(notificationsBodyPage(channels, "", tenants, current, pageIndex, hasMore)),
	})
}

// notificationsCreate handles POST /notifications.
func (s *Server) notificationsCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	kind := strings.TrimSpace(r.PostFormValue("kind"))
	if name == "" || kind == "" {
		s.notificationsError(w, r, "name and kind are required")
		return
	}

	cfg, credentialID, err := parseChannelConfig(kind, r)
	if err != nil {
		s.notificationsError(w, r, err.Error())
		return
	}
	// A scoped viewer is forced into their own tenant whatever the form says.
	tenantID := strings.TrimSpace(r.PostFormValue("tenant_id"))
	if scope := viewerScope(r); scope != "" {
		tenantID = scope
	}
	if tenantID == "" {
		tenantID = journal.DefaultTenant
	}
	if credentialID != "" {
		if s.Credentials == nil {
			s.notificationsError(w, r, "credential repository unavailable")
			return
		}
		if _, err := s.Credentials.GetMetadataByTenant(r.Context(), credentialID, tenantID); err != nil {
			s.notificationsError(w, r, "credential must exist in the channel's tenant")
			return
		}
	}
	if _, err := s.Journal.CreateNotificationChannelInTenant(r.Context(), tenantID, name, kind, cfg); err != nil {
		if errors.Is(err, journal.ErrChannelNameTaken) {
			// Names are unique per tenant, so this is always a collision inside
			// the operator's own tenant. Say so, and say which name, rather than
			// echoing a constraint error they cannot act on.
			s.notificationsError(w, r, fmt.Sprintf("you already have a channel named %q; pick another name or edit the existing one", name))
			return
		}
		s.notificationsError(w, r, err.Error())
		return
	}
	http.Redirect(w, r, "/notifications", http.StatusSeeOther)
}

// notificationsDelete drops the channel after rejecting if any
// workflow routes still reference it.
func (s *Server) notificationsDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Journal.DeleteNotificationChannel(r.Context(), id); err != nil {
		if errors.Is(err, journal.ErrChannelInUse) {
			http.Error(w, err.Error()+"; detach the per-workflow routes first", http.StatusConflict)
			return
		}
		s.errorPage(w, "delete notification channel", err)
		return
	}
	http.Redirect(w, r, "/notifications", http.StatusSeeOther)
}

// notificationsTest fires a synthetic message through the configured
// sender so the operator can confirm credentials + connectivity from
// the dashboard.
func (s *Server) notificationsTest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if s.Notifier == nil {
		http.Error(w, "notifier not wired on this deployment", http.StatusServiceUnavailable)
		return
	}
	if err := s.Notifier.TestChannel(r.Context(), id); err != nil {
		http.Error(w, "send failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/notifications", http.StatusSeeOther)
}

// workflowNotificationRouteCreate handles POST /workflows/{slug}/notifications.
// Form fields: channel_id, on_statuses (comma-separated; defaults to
// the journal's "failed,failed_dlq" baseline).
func (s *Server) workflowNotificationRouteCreate(w http.ResponseWriter, r *http.Request) {
	slug, ok := slugFromRequest(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	channelID := strings.TrimSpace(r.PostFormValue("channel_id"))
	if channelID == "" {
		http.Error(w, "channel_id is required", http.StatusBadRequest)
		return
	}
	onStatuses := strings.TrimSpace(r.PostFormValue("on_statuses"))
	if onStatuses == "" {
		onStatuses = "failed,failed_dlq"
	}
	wfID, err := s.workflowIDForViewer(r, slug)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			http.Error(w, "workflow not registered", http.StatusNotFound)
			return
		}
		s.errorPage(w, "lookup workflow", err)
		return
	}
	if err := s.Journal.AddNotificationRoute(r.Context(), wfID, channelID, onStatuses); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, workflowHrefFromRequest(r, slug), http.StatusSeeOther)
}

// workflowNotificationRouteDelete handles POST /workflows/{slug}/notifications/{channel_id}/delete.
func (s *Server) workflowNotificationRouteDelete(w http.ResponseWriter, r *http.Request) {
	slug, ok := slugFromRequest(w, r)
	if !ok {
		return
	}
	channelID := chi.URLParam(r, "channel_id")
	wfID, err := s.workflowIDForViewer(r, slug)
	if err != nil {
		s.errorPage(w, "lookup workflow", err)
		return
	}
	if err := s.Journal.DeleteNotificationRoute(r.Context(), wfID, channelID); err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			http.Error(w, "route not found", http.StatusNotFound)
			return
		}
		s.errorPage(w, "delete notification route", err)
		return
	}
	http.Redirect(w, r, workflowHrefFromRequest(r, slug), http.StatusSeeOther)
}

// notificationsError renders the notifications page with an inline
// error pill above the form so the operator does not lose context.
func (s *Server) notificationsError(w http.ResponseWriter, r *http.Request, msg string) {
	pageIndex := notificationPageIndex(r, "page")
	channels, hasMore, _ := s.Journal.ListNotificationChannelMetadataPage(r.Context(), notificationPageSize, pageIndex*notificationPageSize)
	tenants, current := s.availableTenants(r)
	w.WriteHeader(http.StatusUnprocessableEntity)
	s.renderPage(w, r, page{
		Title:   "Notifications",
		Heading: "Notifications",
		Body:    template.HTML(notificationsBodyPage(channels, msg, tenants, current, pageIndex, hasMore)),
	})
}

// parseChannelConfig validates and serialises non-secret form fields. Secret
// values are referenced by credential ID and checked against the selected
// tenant before the channel is created.
func parseChannelConfig(kind string, r *http.Request) (json.RawMessage, string, error) {
	switch kind {
	case journal.ChannelKindSlackWebhook:
		if strings.TrimSpace(r.PostFormValue("slack_url")) != "" {
			return nil, "", errors.New("store the Slack webhook URL in the vault; plaintext URLs are not accepted")
		}
		credentialID := strings.TrimSpace(r.PostFormValue("slack_url_credential_id"))
		if credentialID == "" || len(credentialID) > 256 {
			return nil, "", errors.New("Slack webhook URL credential id is required and must be at most 256 bytes")
		}
		cfg, err := json.Marshal(map[string]string{"url_credential_id": credentialID})
		return cfg, credentialID, err
	case journal.ChannelKindGenericWebhook:
		endpoint := strings.TrimSpace(r.PostFormValue("webhook_url"))
		parsed, parseErr := url.Parse(endpoint)
		if parseErr != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || len(endpoint) > 2048 {
			return nil, "", errors.New("webhook URL must be an absolute http(s) URL without userinfo and at most 2048 bytes")
		}
		headerName := strings.TrimSpace(r.PostFormValue("webhook_header_name"))
		headerValue := strings.TrimSpace(r.PostFormValue("webhook_header_value"))
		headerCredID := strings.TrimSpace(r.PostFormValue("webhook_header_credential_id"))
		if len(headerName) > 128 || len(headerCredID) > 256 {
			return nil, "", errors.New("webhook header name or credential id is too long")
		}
		if headerValue != "" {
			return nil, "", errors.New("store the webhook auth header in the vault; plaintext header values are not accepted")
		}
		if (headerName == "") != (headerCredID == "") {
			return nil, "", errors.New("webhook auth header name and credential id must be supplied together")
		}
		cfg := map[string]any{"url": endpoint}
		if headerName != "" {
			// Reference a vault credential for the header value; the secret
			// is resolved at send time and never stored in config_json.
			cfg["header_name"] = headerName
			cfg["header_credential_id"] = headerCredID
		}
		encoded, err := json.Marshal(cfg)
		return encoded, headerCredID, err
	case journal.ChannelKindEmailSMTP:
		host := strings.TrimSpace(r.PostFormValue("smtp_host"))
		port := strings.TrimSpace(r.PostFormValue("smtp_port"))
		from := strings.TrimSpace(r.PostFormValue("smtp_from"))
		to := strings.TrimSpace(r.PostFormValue("smtp_to"))
		user := strings.TrimSpace(r.PostFormValue("smtp_username"))
		pass := r.PostFormValue("smtp_password")
		passCredID := strings.TrimSpace(r.PostFormValue("smtp_password_credential_id"))
		if host == "" || from == "" || to == "" {
			return nil, "", errors.New("smtp host, from, and to are required")
		}
		if pass != "" {
			return nil, "", errors.New("store the SMTP password in the vault; plaintext passwords are not accepted")
		}
		if passCredID == "" {
			return nil, "", errors.New("SMTP password credential id is required")
		}
		if len(passCredID) > 256 || len(host) > 255 || len(from) > 320 || len(to) > 4096 || len(user) > 320 {
			return nil, "", errors.New("SMTP field is too long")
		}
		portInt := 587
		if port != "" {
			var err error
			portInt, err = strconv.Atoi(port)
			if err != nil {
				return nil, "", errors.New("smtp port must be an integer")
			}
		}
		if portInt < 1 || portInt > 65535 {
			return nil, "", errors.New("smtp port must be between 1 and 65535")
		}
		cfg := map[string]any{
			"host":     host,
			"port":     portInt,
			"from":     from,
			"to":       to,
			"username": user,
		}
		cfg["password_credential_id"] = passCredID
		encoded, err := json.Marshal(cfg)
		return encoded, passCredID, err
	}
	return nil, "", fmt.Errorf("unknown channel kind %q", kind)
}

// notificationsBody renders the page contents.
func notificationsBody(channels []journal.NotificationChannelMetadata, errMsg string, tenants []journal.Tenant, currentTenant string) string {
	return notificationsBodyPage(channels, errMsg, tenants, currentTenant, 0, false)
}

func notificationsBodyPage(channels []journal.NotificationChannelMetadata, errMsg string, tenants []journal.Tenant, currentTenant string, pageIndex int, hasMore bool) string {
	var b strings.Builder
	if errMsg != "" {
		b.WriteString(`<div class="err" style="background:#fff;border:1px solid var(--err);padding:12px 16px;margin:0 0 16px;border-radius:3px;">` +
			template.HTMLEscapeString(errMsg) + `</div>`)
	}
	b.WriteString(`<h2>Channels</h2>`)
	if len(channels) == 0 {
		if pageIndex > 0 {
			b.WriteString(`<p class="empty">No channels on this page.</p>`)
		} else {
			b.WriteString(`<p class="empty">No channels configured. Use the form below to add one, then attach it to a workflow on the workflow detail page.</p>`)
		}
	} else {
		b.WriteString(`<table><thead><tr><th>Name</th><th>Kind</th><th>Created</th><th></th></tr></thead><tbody>`)
		for _, c := range channels {
			fmt.Fprintf(&b, `<tr><td>%s</td><td><code>%s</code></td><td class="muted">%s</td><td>
<form method="POST" action="/notifications/%s/test" class="form-inline"><button type="submit">Send test</button></form>
<form method="POST" action="/notifications/%s/delete" class="form-inline" data-confirm="Delete channel %s? Active per-workflow routes block the delete."><button type="submit" class="btn-link">delete</button></form>
</td></tr>`,
				template.HTMLEscapeString(c.Name),
				template.HTMLEscapeString(c.Kind),
				formatTime(c.CreatedAt),
				template.URLQueryEscaper(c.ID),
				template.URLQueryEscaper(c.ID),
				// data-confirm is an HTML attribute now, so HTMLEscapeString.
				template.HTMLEscapeString(c.Name),
			)
		}
		b.WriteString(`</tbody></table>`)
	}
	if pageIndex > 0 || hasMore {
		b.WriteString(`<nav aria-label="Channel pages">`)
		if pageIndex > 0 {
			fmt.Fprintf(&b, `<a href="/notifications?page=%d">Previous</a> `, pageIndex-1)
		}
		fmt.Fprintf(&b, `<span>Page %d</span>`, pageIndex+1)
		if hasMore {
			fmt.Fprintf(&b, ` <a href="/notifications?page=%d">Next</a>`, pageIndex+1)
		}
		b.WriteString(`</nav>`)
	}

	b.WriteString(`<h2>Add channel</h2>`)
	b.WriteString(`<form method="POST" action="/notifications" class="form">
  <label>Name <input type="text" name="name" required autocomplete="off" placeholder="e.g. ops-slack, on-call-email"></label>` +
		tenantSelect(tenants, currentTenant) + `
  <label>Kind
    <select name="kind" required data-reveal-prefix="fields-">
      <option value="">choose...</option>
      <option value="slack_webhook">Slack (incoming webhook)</option>
      <option value="generic_webhook">Generic JSON webhook</option>
      <option value="email_smtp">Email (SMTP)</option>
    </select>
  </label>
  <fieldset id="fields-slack_webhook" class="kind-fields js-reveal-target" hidden>
    <legend>Slack</legend>
    <label>Webhook URL credential id <input type="text" name="slack_url_credential_id" placeholder="cred_..." autocomplete="off"></label>
  </fieldset>
  <fieldset id="fields-generic_webhook" class="kind-fields js-reveal-target" hidden>
    <legend>Generic webhook</legend>
    <label>Webhook URL <input type="url" name="webhook_url" placeholder="https://example.com/reactor"></label>
    <label>Optional auth header name <input type="text" name="webhook_header_name" placeholder="X-Auth-Token"></label>
    <label>Auth header credential id <input type="text" name="webhook_header_credential_id" placeholder="cred_..." autocomplete="off"></label>
  </fieldset>
  <fieldset id="fields-email_smtp" class="kind-fields js-reveal-target" hidden>
    <legend>Email (SMTP)</legend>
    <label>SMTP host <input type="text" name="smtp_host" placeholder="smtp.gmail.com"></label>
    <label>SMTP port <input type="number" name="smtp_port" value="587" min="1" max="65535"></label>
    <label>From <input type="email" name="smtp_from" placeholder="alerts@example.com"></label>
    <label>To <input type="text" name="smtp_to" placeholder="ops@example.com[, oncall@example.com]"></label>
    <label>Username <input type="text" name="smtp_username" autocomplete="off"></label>
    <label>Password credential id <input type="text" name="smtp_password_credential_id" placeholder="cred_..." autocomplete="off"></label>
  </fieldset>
  <p class="muted">Store Slack webhook URLs, SMTP passwords, and webhook auth headers as <a href="/credentials/new">vault credentials</a> in the selected tenant before creating a channel. Reactor resolves them only when sending.</p>
  <p class="muted">After creating, attach the channel to specific workflows on the workflow detail page. By default, channels fire on <code>failed</code> + <code>failed_dlq</code> terminal status; you can broaden to <code>succeeded</code> per workflow.</p>
  <button type="submit" class="btn-primary">Create channel</button>
</form>`)
	return b.String()
}

// renderNotificationRoutesSection draws the per-workflow notification
// routes on the workflow detail page (called by workflowDetailBody).
func renderNotificationRoutesSection(slug string, routes []journal.NotificationRouteWithChannel, allChannels []journal.NotificationChannelMetadata, readOnly bool) string {
	return renderNotificationRoutesSectionForTenant(slug, routes, allChannels, readOnly, "")
}

// renderNotificationRoutesSectionForTenant is the tenant-aware variant used
// by the dashboard. A global admin may view a duplicate slug with ?tenant=;
// every attach/detach form must preserve that selector or the POST can target
// another tenant's workflow.
func renderNotificationRoutesSectionForTenant(slug string, routes []journal.NotificationRouteWithChannel, allChannels []journal.NotificationChannelMetadata, readOnly bool, actionQuery string) string {
	return renderNotificationRoutesSectionForTenantPage(slug, routes, allChannels, readOnly, actionQuery, 0, false)
}

func renderNotificationRoutesSectionForTenantPage(slug string, routes []journal.NotificationRouteWithChannel, allChannels []journal.NotificationChannelMetadata, readOnly bool, actionQuery string, pageIndex int, hasMore bool) string {
	var b strings.Builder
	b.WriteString(`<h2>Notifications</h2>`)
	if len(routes) == 0 {
		b.WriteString(`<p class="muted">No channels attached. Pick one below to receive alerts when this workflow's runs terminate.</p>`)
	} else {
		b.WriteString(`<table><thead><tr><th>Channel</th><th>Kind</th><th>Fires on</th><th></th></tr></thead><tbody>`)
		for _, r := range routes {
			actions := ""
			if !readOnly {
				actions = fmt.Sprintf(`<form method="POST" action="/workflows/%s/notifications/%s/delete%s" class="form-inline" data-confirm="Detach %s from this workflow?"><button type="submit" class="btn-link">detach</button></form>`,
					template.URLQueryEscaper(slug), template.URLQueryEscaper(r.ChannelID), actionQuery, template.HTMLEscapeString(r.ChannelName))
			}
			fmt.Fprintf(&b, `<tr><td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td>%s</td></tr>`,

				template.HTMLEscapeString(r.ChannelName),
				template.HTMLEscapeString(r.ChannelKind),
				template.HTMLEscapeString(r.OnStatuses),
				actions,
			)
		}
		b.WriteString(`</tbody></table>`)
	}

	// Add form (only when at least one channel exists; otherwise point
	// the operator at /notifications to create one first).
	if readOnly {
		b.WriteString(`<p class="muted">Notification routing is admin-only.</p>`)
		return b.String()
	}
	if len(allChannels) == 0 && pageIndex == 0 {
		b.WriteString(`<p class="muted">No channels exist yet. <a href="/notifications">Create a channel</a> first.</p>`)
		return b.String()
	}
	if len(allChannels) == 0 {
		b.WriteString(`<p class="muted">No channels on this page.</p>`)
	} else {
		fmt.Fprintf(&b, `<h3>Attach channel</h3>
<form method="POST" action="/workflows/%s/notifications%s" class="form">
  <label>Channel <select name="channel_id" required>`, template.URLQueryEscaper(slug), actionQuery)
		routed := map[string]bool{}
		for _, r := range routes {
			routed[r.ChannelID] = true
		}
		for _, c := range allChannels {
			if routed[c.ID] {
				continue
			}
			fmt.Fprintf(&b, `<option value="%s">%s (%s)</option>`,
				template.HTMLEscapeString(c.ID),
				template.HTMLEscapeString(c.Name),
				template.HTMLEscapeString(c.Kind),
			)
		}
		b.WriteString(`</select></label>
  <label>Fire on (comma-separated) <input type="text" name="on_statuses" value="failed,failed_dlq" placeholder="failed,failed_dlq[,succeeded]"></label>
  <p class="muted">Defaults to <code>failed,failed_dlq</code>. Add <code>succeeded</code> if you want positive confirmation alerts too.</p>
  <button type="submit" class="btn-primary">Attach</button>
</form>`)
	}
	if pageIndex > 0 || hasMore {
		b.WriteString(`<nav aria-label="Channel picker pages">`)
		pageHref := func(page int) string {
			separator := "?"
			if actionQuery != "" {
				separator = "&"
			}
			return fmt.Sprintf("/workflows/%s%s%schannel_page=%d", template.URLQueryEscaper(slug), actionQuery, separator, page)
		}
		if pageIndex > 0 {
			fmt.Fprintf(&b, `<a href="%s">Previous</a> `, pageHref(pageIndex-1))
		}
		fmt.Fprintf(&b, `<span>Channel page %d</span>`, pageIndex+1)
		if hasMore {
			fmt.Fprintf(&b, ` <a href="%s">Next</a>`, pageHref(pageIndex+1))
		}
		b.WriteString(`</nav>`)
	}
	return b.String()
}
