package server

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/catalog"
	"github.com/bright-interaction/reactor/internal/oauth"
)

// oauthProviders is the admin page to configure OAuth providers (the client
// app credentials + endpoints). Connections on the /connections page can only
// use enabled providers.
func (s *Server) oauthProviders(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	if s.OAuth == nil {
		render(w, layout, page{Title: "OAuth providers", Heading: "OAuth providers",
			Body: template.HTML(`<p class="muted">OAuth is not wired on this deployment.</p>`)})
		return
	}
	list, err := s.OAuth.ListProviders(r.Context())
	if err != nil {
		s.errorPage(w, "list providers", err)
		return
	}
	s.renderPage(w, r, page{
		Title:   "OAuth providers",
		Heading: "OAuth providers",
		Body:    template.HTML(oauthProvidersBody(list, oauthRedirectURI(r), r.URL.Query().Get("err"))),
	})
}

func (s *Server) oauthProvidersUpsert(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.PostFormValue("provider_id"))
	if id == "" {
		http.Redirect(w, r, "/oauth-providers?err="+urlEsc("provider id is required"), http.StatusSeeOther)
		return
	}
	p := oauth.Provider{
		ProviderID: id,
		Name:       strings.TrimSpace(r.PostFormValue("name")),
		AuthURL:    strings.TrimSpace(r.PostFormValue("auth_url")),
		TokenURL:   strings.TrimSpace(r.PostFormValue("token_url")),
		ClientID:   strings.TrimSpace(r.PostFormValue("client_id")),
		Scopes:     strings.TrimSpace(r.PostFormValue("scopes")),
		Enabled:    r.PostFormValue("enabled") == "on",
	}
	if err := s.OAuth.UpsertProvider(r.Context(), p, r.PostFormValue("client_secret")); err != nil {
		http.Redirect(w, r, "/oauth-providers?err="+urlEsc(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/oauth-providers", http.StatusSeeOther)
}

func (s *Server) oauthProvidersDelete(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	if err := s.OAuth.DeleteProvider(r.Context(), chi.URLParam(r, "id")); err != nil {
		s.errorPage(w, "delete provider", err)
		return
	}
	http.Redirect(w, r, "/oauth-providers", http.StatusSeeOther)
}

func oauthProvidersBody(list []oauth.Provider, redirectURI, errMsg string) string {
	var b strings.Builder
	if errMsg != "" {
		b.WriteString(`<div class="err" style="background:#fff;border:1px solid var(--err);padding:12px 16px;margin:0 0 16px;border-radius:3px;">` +
			template.HTMLEscapeString(errMsg) + `</div>`)
	}
	fmt.Fprintf(&b, `<p class="muted">Register your OAuth app per provider. Set the provider's redirect/callback URL to <code>%s</code>. Client secrets are encrypted at rest and never shown back. Disabling a provider blocks new consent, token release, and brokered requests for its existing connections.</p>`,
		template.HTMLEscapeString(redirectURI))
	b.WriteString(`<p><a href="/oauth-broker-policies">Review connection API policies</a></p>`)

	if len(list) > 0 {
		b.WriteString(`<table><thead><tr><th>Provider</th><th>Client id</th><th>Secret</th><th>Scopes</th><th>Status</th><th></th></tr></thead><tbody>`)
		for _, p := range list {
			secret := `<span class="muted">not set</span>`
			if p.HasSecret {
				secret = `<span class="tag tag-on">set</span>`
			}
			status := `<span class="tag tag-off">disabled</span>`
			if p.Enabled {
				status = `<span class="tag tag-on">enabled</span>`
			}
			cid := `<span class="muted">not set</span>`
			if p.ClientID != "" {
				cid = `<code>` + template.HTMLEscapeString(p.ClientID) + `</code>`
			}
			fmt.Fprintf(&b, `<tr><td><code>%s</code><br><span class="muted">%s</span></td><td>%s</td><td>%s</td><td class="muted">%s</td><td>%s</td><td><form method="POST" action="/oauth-providers/%s/delete" class="form-inline" data-confirm="Delete provider %s? Its connections are removed too."><button type="submit" class="btn-link">delete</button></form></td></tr>`,
				template.HTMLEscapeString(p.ProviderID), template.HTMLEscapeString(p.Name),
				cid, secret, template.HTMLEscapeString(p.Scopes), status,
				urlEsc(p.ProviderID), template.HTMLEscapeString(p.ProviderID))
		}
		b.WriteString(`</tbody></table>`)
	}

	b.WriteString(`<h2>Add or update provider</h2>`)
	b.WriteString(`<p class="muted">Quick-add a common provider below, then paste the Client id + secret from your own OAuth app. The endpoints and a sensible default scope set are filled for you; edit them if you like.</p>`)

	// Preset quick-add buttons. oauth-presets.js fills the form below on click;
	// the operator only supplies client id + secret. CSP-safe (external JS).
	b.WriteString(`<div class="oauth-presets">`)
	for _, svc := range catalog.OAuthServices() {
		note := svc.AuthScheme + " | Docs: " + svc.Docs
		fmt.Fprintf(&b, `<button type="button" class="oauth-preset" data-provider-id="%s" data-name="%s" data-auth-url="%s" data-token-url="%s" data-scopes="%s" data-note="%s">%s</button>`,
			template.HTMLEscapeString(svc.ID), template.HTMLEscapeString(svc.Name),
			template.HTMLEscapeString(svc.AuthURL), template.HTMLEscapeString(svc.TokenURL),
			template.HTMLEscapeString(svc.Scopes), template.HTMLEscapeString(note),
			template.HTMLEscapeString(svc.Name))
	}
	b.WriteString(`</div><p id="oauth-preset-note" class="muted oauth-preset-note"></p>`)

	b.WriteString(`<form method="POST" action="/oauth-providers" class="form" id="oauth-provider-form">
  <label>Provider id <input type="text" name="provider_id" required autocomplete="off" placeholder="google"></label>
  <label>Display name <input type="text" name="name" autocomplete="off" placeholder="Google"></label>
  <label>Authorize URL <input type="text" name="auth_url" required autocomplete="off" placeholder="https://accounts.google.com/o/oauth2/v2/auth"></label>
  <label>Token URL <input type="text" name="token_url" required autocomplete="off" placeholder="https://oauth2.googleapis.com/token"></label>
  <label>Client id <input type="text" name="client_id" autocomplete="off"></label>
  <label>Client secret (leave blank to keep current) <input type="password" name="client_secret" autocomplete="new-password"></label>
  <label>Scopes (space-separated) <input type="text" name="scopes" autocomplete="off" placeholder="https://www.googleapis.com/auth/gmail.send"></label>
  <label class="form-inline"><input type="checkbox" name="enabled"> Enabled (allow connections and runtime use)</label>
  <button type="submit" class="btn-primary">Save provider</button>
</form>`)
	b.WriteString(`<script src="/assets/oauth-presets.js"></script>`)
	return b.String()
}
