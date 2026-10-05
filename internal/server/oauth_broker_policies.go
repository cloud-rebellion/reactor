package server

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/bright-interaction/reactor/internal/oauth"
	"github.com/go-chi/chi/v5"
)

// oauthBrokerPolicies is an admin-only, bounded review surface. The POST is
// mounted under requireAdminMW and the global CSRF middleware; this handler
// repeats the role check as defense in depth for direct callers.
func (s *Server) oauthBrokerPolicies(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	if s.OAuth == nil {
		http.Error(w, "oauth not wired", http.StatusServiceUnavailable)
		return
	}
	pageIndex, err := strconv.Atoi(r.URL.Query().Get("page"))
	if r.URL.Query().Get("page") == "" {
		pageIndex = 0
	}
	if err != nil && r.URL.Query().Get("page") != "" || pageIndex < 0 || pageIndex > 200 {
		http.Error(w, "invalid page", http.StatusBadRequest)
		return
	}
	const pageSize = 50
	conns, more, err := s.OAuth.ListConnectionsPage(r.Context(), "", "", pageSize, pageIndex*pageSize)
	if err != nil {
		s.errorPage(w, "list OAuth broker policies", err)
		return
	}
	var b strings.Builder
	b.WriteString(`<p>Approve a fixed public HTTPS API origin and one path prefix for host-brokered GET. Existing raw-token connections switch permanently to broker-only when approved. New generic connections wait for review before use. Gmail and Microsoft email sends still use an explicit legacy raw-token exception.</p>`)
	if msg := r.URL.Query().Get("ok"); msg != "" {
		b.WriteString(`<p class="tag tag-on">` + template.HTMLEscapeString(msg) + `</p>`)
	}
	if msg := r.URL.Query().Get("err"); msg != "" {
		b.WriteString(`<p class="err">` + template.HTMLEscapeString(msg) + `</p>`)
	}
	for _, conn := range conns {
		policy, err := s.OAuth.GetBrokerPolicy(r.Context(), conn.TenantID, conn.ID)
		if err != nil && !errors.Is(err, oauth.ErrNotFound) {
			s.errorPage(w, "load OAuth broker policy", err)
			return
		}
		origin, prefix := "", "/"
		if err == nil {
			origin, prefix = policy.APIOrigin, policy.PathPrefix
		}
		fmt.Fprintf(&b, `<section><h2><code>%s</code>: %s</h2><p>Tenant <code>%s</code>; provider <code>%s</code>; mode <strong>%s</strong>; review v%d by %s</p>
<form method="POST" action="/oauth-broker-policies/%s" class="form">
<input type="hidden" name="expected_version" value="%d">
<label>Reviewed API origin <input name="api_origin" required value="%s" placeholder="https://api.example.com"></label>
<label>Allowed path prefix <input name="path_prefix" required value="%s" placeholder="/v1/"></label>
<input type="hidden" name="method" value="GET">
<button type="submit" class="btn-primary">Approve GET policy</button></form></section>`,
			template.HTMLEscapeString(conn.ID), template.HTMLEscapeString(conn.Name),
			template.HTMLEscapeString(conn.TenantID), template.HTMLEscapeString(conn.ProviderID),
			template.HTMLEscapeString(conn.TokenAccessMode), policy.Version,
			template.HTMLEscapeString(policy.ReviewedBy), urlEsc(conn.ID), policy.Version,
			template.HTMLEscapeString(origin), template.HTMLEscapeString(prefix))
	}
	if pageIndex > 0 {
		fmt.Fprintf(&b, `<a href="/oauth-broker-policies?page=%d">Previous</a> `, pageIndex-1)
	}
	if more {
		fmt.Fprintf(&b, `<a href="/oauth-broker-policies?page=%d">Next</a>`, pageIndex+1)
	}
	s.renderPage(w, r, page{Title: "OAuth broker policies", Heading: "OAuth broker policies", Body: template.HTML(b.String())})
}

func (s *Server) oauthBrokerPolicyApprove(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	if s.OAuth == nil {
		http.Error(w, "oauth not wired", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid review form", http.StatusBadRequest)
		return
	}
	connectionID := chi.URLParam(r, "id")
	tenantID, err := s.OAuth.ConnectionTenant(r.Context(), connectionID)
	if err != nil {
		http.Error(w, "connection unavailable", http.StatusNotFound)
		return
	}
	version, err := strconv.ParseInt(r.PostFormValue("expected_version"), 10, 64)
	if err != nil {
		http.Error(w, "invalid review version", http.StatusBadRequest)
		return
	}
	user, ok := UserFromContext(r.Context())
	if !ok || !user.IsAdmin() {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	reviewer := user.Username
	if reviewer == "" {
		reviewer = user.ID
	}
	_, err = s.OAuth.ApproveBrokerPolicy(r.Context(), tenantID, connectionID, reviewer, version,
		strings.TrimSpace(r.PostFormValue("api_origin")), strings.TrimSpace(r.PostFormValue("path_prefix")),
		r.PostFormValue("method"))
	if err != nil {
		http.Redirect(w, r, "/oauth-broker-policies?err="+urlEsc(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/oauth-broker-policies?ok="+urlEsc("Policy reviewed and enabled"), http.StatusSeeOther)
}
