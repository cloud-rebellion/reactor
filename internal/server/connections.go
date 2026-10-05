package server

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/oauth"
)

// viewerTenant is the tenant a request's viewer belongs to (their own tenant,
// or "default"). Unlike viewerScope it never returns "" -- connections and the
// account view are always anchored to a concrete tenant.
func viewerTenant(r *http.Request) string {
	if u, ok := UserFromContext(r.Context()); ok && u.TenantID != "" {
		return u.TenantID
	}
	return "default"
}

// oauthRedirectURI builds the callback URL the provider redirects back to. It
// must match the value registered with the provider.
func oauthRedirectURI(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	// Honor the proxy's forwarded scheme/host only when the request genuinely
	// came through a trusted proxy, mirroring expectedOrigin (CSRF). Behind
	// Caddy with a public hostname this makes redirect_uri match what was
	// registered with the provider; trusting these headers unconditionally
	// would let any client spoof the OAuth callback host.
	if isTrustedProxyRequest(r) {
		if v := forwardedProto(r); v != "" {
			scheme = v
		}
		if v := forwardedHost(r); v != "" {
			host = v
		}
	}
	return scheme + "://" + host + "/oauth/callback"
}

// connections is the customer-facing page to connect + manage third-party
// accounts via OAuth. Tenant-scoped to the viewer's own tenant.
func (s *Server) connections(w http.ResponseWriter, r *http.Request) {
	if s.OAuth == nil {
		render(w, layout, page{Title: "Connections", Heading: "Connections",
			Body: template.HTML(`<p class="muted">OAuth connections are not wired on this deployment.</p>`)})
		return
	}
	ctx := r.Context()
	tenant := viewerTenant(r)
	conns, err := s.OAuth.ListConnections(ctx, tenant)
	if err != nil {
		s.errorPage(w, "list connections", err)
		return
	}
	providers, _ := s.OAuth.ListProviders(ctx)
	s.renderPage(w, r, page{
		Title:   "Connections",
		Heading: "Connections",
		Body:    template.HTML(connectionsBody(conns, providers, tenant, r.URL.Query().Get("ok"), r.URL.Query().Get("err"))),
	})
}

// connectionsStart kicks off the OAuth flow for a provider, redirecting the
// browser to the provider's authorize page.
func (s *Server) connectionsStart(w http.ResponseWriter, r *http.Request) {
	if s.OAuth == nil {
		http.Error(w, "oauth not wired", http.StatusServiceUnavailable)
		return
	}
	providerID := chi.URLParam(r, "provider")
	name := strings.TrimSpace(r.PostFormValue("name"))
	createdBy := ""
	if u, ok := UserFromContext(r.Context()); ok {
		createdBy = u.Username
	}
	authURL, err := s.OAuth.StartAuth(r.Context(), viewerTenant(r), providerID, name, oauthRedirectURI(r), createdBy)
	if err != nil {
		http.Redirect(w, r, "/connections?err="+urlEsc(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// oauthCallback handles the provider redirect back, completing the connection.
func (s *Server) oauthCallback(w http.ResponseWriter, r *http.Request) {
	if s.OAuth == nil {
		http.Error(w, "oauth not wired", http.StatusServiceUnavailable)
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		renderOAuthCallback(w, false, "", e)
		return
	}
	conn, err := s.OAuth.CompleteAuth(r.Context(), q.Get("state"), q.Get("code"))
	if err != nil {
		renderOAuthCallback(w, false, "", err.Error())
		return
	}
	renderOAuthCallback(w, true, conn.Name, "")
}

// renderOAuthCallback writes the tiny page the provider redirects back to. When
// the flow ran in a popup (the Integrations page) oauth-callback.js posts the
// result to the opener and closes the window; otherwise it falls back to the
// Integrations page. No inline JS (CSP-safe).
func renderOAuthCallback(w http.ResponseWriter, ok bool, name, errMsg string) {
	okv := "0"
	msg := "Connection failed."
	if ok {
		okv = "1"
		msg = "Connected."
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Connecting</title></head><body>`+
		`<div id="oauth-result" data-ok="%s" data-name="%s" data-err="%s" hidden></div>`+
		`<p>%s You can close this window.</p>`+
		`<script src="/assets/oauth-callback.js"></script></body></html>`,
		okv, template.HTMLEscapeString(name), template.HTMLEscapeString(errMsg), template.HTMLEscapeString(msg))
}

// connectionsDelete disconnects an account (tenant-guarded).
func (s *Server) connectionsDelete(w http.ResponseWriter, r *http.Request) {
	if s.OAuth == nil {
		http.Error(w, "oauth not wired", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.OAuth.DeleteConnection(r.Context(), id, viewerTenant(r)); err != nil {
		s.errorPage(w, "disconnect", err)
		return
	}
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

func connectionsBody(conns []oauth.Connection, providers []oauth.Provider, tenant, ok, errMsg string) string {
	var b strings.Builder
	if errMsg != "" {
		b.WriteString(`<div class="err" style="background:#fff;border:1px solid var(--err);padding:12px 16px;margin:0 0 16px;border-radius:3px;">` +
			template.HTMLEscapeString(errMsg) + `</div>`)
	}
	if ok != "" {
		b.WriteString(`<div style="background:#dfb;border:1px solid #0a5;padding:12px 16px;margin:0 0 16px;border-radius:3px;">Connected ` +
			template.HTMLEscapeString(ok) + `.</div>`)
	}
	b.WriteString(`<p class="muted">Connect a third-party account once; workflows then act as it using a token that refreshes automatically. Reference it in a workflow as the credential id <code>oauth:&lt;connection id&gt;</code>. Your tokens are encrypted at rest and never shown here.</p>`)

	// Connected accounts.
	b.WriteString(`<h2>Connected accounts</h2>`)
	if len(conns) == 0 {
		b.WriteString(`<p class="empty">No connected accounts yet. Connect one below.</p>`)
	} else {
		b.WriteString(`<table><thead><tr><th>Provider</th><th>Name</th><th>Connection id</th><th>Status</th><th>API access</th><th></th></tr></thead><tbody>`)
		for _, c := range conns {
			tag := `<span class="tag tag-on">connected</span>`
			if c.Status != "connected" {
				tag = `<span class="tag tag-off">` + template.HTMLEscapeString(c.Status) + `</span>`
			}
			access := "Pending API review"
			if c.ProviderID == "salesforce" {
				access = "Salesforce GET broker"
			} else if c.TokenAccessMode == "legacy_raw" {
				access = "Legacy raw token"
			} else if c.TokenAccessMode == "broker_only" && c.BrokerPolicyVersion > 0 {
				access = "Brokered GET reviewed"
			} else if c.TokenAccessMode == "broker_only" {
				access = "Broker-only; review required before GET"
			}
			fmt.Fprintf(&b, `<tr><td><code>%s</code></td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td><form method="POST" action="/connections/%s/delete" class="form-inline" data-confirm="Disconnect %s?"><button type="submit" class="btn-link">disconnect</button></form></td></tr>`,
				template.HTMLEscapeString(c.ProviderID), template.HTMLEscapeString(c.Name),
				template.HTMLEscapeString(c.ID), tag, template.HTMLEscapeString(access),
				urlEsc(c.ID), template.HTMLEscapeString(c.Name))
		}
		b.WriteString(`</tbody></table>`)
	}

	// Connect new (enabled providers only).
	b.WriteString(`<h2>Connect an account</h2>`)
	var enabled []oauth.Provider
	for _, p := range providers {
		if p.Enabled && p.ClientID != "" {
			enabled = append(enabled, p)
		}
	}
	if len(enabled) == 0 {
		b.WriteString(`<p class="muted">No providers are configured yet. An admin can add them on the <a href="/oauth-providers">OAuth providers</a> page.</p>`)
		return b.String()
	}
	for _, p := range enabled {
		label := p.Name
		if label == "" {
			label = p.ProviderID
		}
		fmt.Fprintf(&b, `<form method="POST" action="/connections/%s/start" class="form-inline" style="margin:6px 0;">
  <span style="min-width:120px;display:inline-block;"><strong>%s</strong></span>
  <input type="text" name="name" placeholder="name this connection" required>
  <button type="submit" class="btn-primary">Connect</button>
</form>`, urlEsc(p.ProviderID), template.HTMLEscapeString(label))
	}
	return b.String()
}
