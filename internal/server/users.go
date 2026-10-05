package server

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/auth"
)

// AuthAdmin is the surface the /users + /tokens pages call into.
// Wired to *auth.Store; defined as an interface so tests can stub.
type AuthAdmin interface {
	ListUsers(ctx context.Context) ([]auth.User, error)
	GetUser(ctx context.Context, id string) (auth.User, error)
	CreateUser(ctx context.Context, username, password string, role auth.Role) (string, error)
	SetUserRole(ctx context.Context, id string, role auth.Role) error
	SetUserTenant(ctx context.Context, id, tenantID string) error
	SetUserDisabled(ctx context.Context, id string, disabled bool) error
	DeleteUser(ctx context.Context, id string) error
	CountAdmins(ctx context.Context) (int, error)
	CountUsers(ctx context.Context) (int, error)

	Authenticate(ctx context.Context, username, password string) (auth.User, error)
	// SetPassword is the admin reset (no old password needed); ChangePassword
	// is the self-service rotate and verifies the current one. Both revoke the
	// user's live sessions.
	SetPassword(ctx context.Context, userID, newPassword string) error
	ChangePassword(ctx context.Context, userID, current, next string) error
	CreateSession(ctx context.Context, userID, userAgent, ip string, ttl time.Duration) (string, error)
	DestroySession(ctx context.Context, cookieValue string) error
	DestroyAllSessionsForUser(ctx context.Context, userID string) error
	ResolveSession(ctx context.Context, cookieValue string) (auth.User, error)

	MintAPIToken(ctx context.Context, userID, name string, ttl time.Duration) (rawToken, tokenID string, err error)
	ListAPITokens(ctx context.Context, userID string) ([]auth.APIToken, error)
	RevokeAPIToken(ctx context.Context, id, userID string) error
	ResolveAPIToken(ctx context.Context, raw string) (auth.User, error)

	// MFA: session assurance + factor management.
	ResolveSessionWithState(ctx context.Context, cookieValue string) (auth.User, auth.SessionState, error)
	CreatePendingSession(ctx context.Context, userID, userAgent, ip string, ttl time.Duration) (string, error)
	ClearSessionMFAPending(ctx context.Context, cookieValue string) error
	MarkSessionElevated(ctx context.Context, cookieValue string, window time.Duration) error
	HasMFA(ctx context.Context, userID string) (bool, error)
	ListMFAFactors(ctx context.Context, userID string) (auth.MFAFactors, error)
	WebAuthnAvailable() bool
	TOTPAvailable() bool

	BeginWebAuthnRegistration(ctx context.Context, u auth.User) (optionsJSON []byte, challengeID string, err error)
	FinishWebAuthnRegistration(ctx context.Context, u auth.User, challengeID string, responseBody []byte, name string) error
	BeginWebAuthnAssertion(ctx context.Context, u auth.User, purpose string) (optionsJSON []byte, challengeID string, err error)
	FinishWebAuthnAssertion(ctx context.Context, u auth.User, purpose, challengeID string, responseBody []byte) error
	DeleteWebAuthnCredential(ctx context.Context, userID, rowID string) error
	RenameWebAuthnCredential(ctx context.Context, userID, rowID, name string) error

	BeginTOTPEnrollment(ctx context.Context, u auth.User) (secret, otpauthURL string, err error)
	ConfirmTOTP(ctx context.Context, userID, code string) error
	VerifyTOTP(ctx context.Context, userID, code string) (bool, error)
	DisableTOTP(ctx context.Context, userID string) error
	HasConfirmedTOTP(ctx context.Context, userID string) (bool, error)

	GenerateRecoveryCodes(ctx context.Context, userID string) ([]string, error)
	ConsumeRecoveryCode(ctx context.Context, userID, code string) (bool, error)
	CountUnusedRecoveryCodes(ctx context.Context, userID string) (int, error)
}

const defaultAPITokenTTL = 90 * 24 * time.Hour

// sessionStoreAdapter narrows AuthAdmin to the subset SessionAuth needs.
// Trivial pass-through; defined here so the server package can wire
// the middleware without exporting the narrow interface.
type sessionStoreAdapter struct{ a AuthAdmin }

func (s sessionStoreAdapter) Authenticate(ctx context.Context, username, password string) (auth.User, error) {
	return s.a.Authenticate(ctx, username, password)
}
func (s sessionStoreAdapter) ResolveSession(ctx context.Context, cookieValue string) (auth.User, error) {
	return s.a.ResolveSession(ctx, cookieValue)
}
func (s sessionStoreAdapter) ResolveSessionWithState(ctx context.Context, cookieValue string) (auth.User, auth.SessionState, error) {
	return s.a.ResolveSessionWithState(ctx, cookieValue)
}
func (s sessionStoreAdapter) HasMFA(ctx context.Context, userID string) (bool, error) {
	return s.a.HasMFA(ctx, userID)
}
func (s sessionStoreAdapter) ResolveAPIToken(ctx context.Context, raw string) (auth.User, error) {
	return s.a.ResolveAPIToken(ctx, raw)
}
func (s sessionStoreAdapter) CountUsers(ctx context.Context) (int, error) {
	return s.a.CountUsers(ctx)
}

// loginGet renders the login form. Pre-populates the "next" query
// param into a hidden field so the post-auth redirect lands where
// the operator was trying to go.
func (s *Server) loginGet(w http.ResponseWriter, r *http.Request) {
	next := safeNextPath(r.URL.Query().Get("next"))
	s.renderPage(w, r, page{
		Title:   "Sign in",
		Heading: "Sign in",
		Body:    template.HTML(loginBody(next, "")),
	})
}

// loginPost validates credentials, mints a session, sets the cookie,
// redirects to ?next= or /.
func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		http.Error(w, "auth not wired on this deployment", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	next := safeNextPath(r.PostFormValue("next"))

	throttleKey := clientIP(r) + "|" + strings.ToLower(username)
	if s.loginThrottle().locked(throttleKey) {
		s.renderPage(w, r, page{
			Title:   "Sign in",
			Heading: "Sign in",
			Body:    template.HTML(loginBody(next, "Too many failed attempts. Wait 15 minutes and try again.")),
		})
		return
	}

	u, err := s.Auth.Authenticate(r.Context(), username, password)
	if err != nil {
		s.loginThrottle().recordFailure(throttleKey)
		s.renderPage(w, r, page{
			Title:   "Sign in",
			Heading: "Sign in",
			Body:    template.HTML(loginBody(next, "Invalid username or password.")),
		})
		return
	}
	s.loginThrottle().reset(throttleKey)

	// If the user has a second factor enrolled, mint a PENDING session and send
	// them to the MFA challenge. A pending session grants nothing but the MFA +
	// logout routes until the factor clears (enforced in SessionAuth). Otherwise
	// mint a full session as before.
	hasMFA, err := s.Auth.HasMFA(r.Context(), u.ID)
	if err != nil {
		s.errorPage(w, "check mfa", err)
		return
	}
	var cookie string
	dest := next
	if hasMFA {
		cookie, err = s.Auth.CreatePendingSession(r.Context(), u.ID, r.UserAgent(), clientIP(r), 7*24*time.Hour)
		dest = "/login/mfa?next=" + url.QueryEscape(next)
	} else {
		cookie, err = s.Auth.CreateSession(r.Context(), u.ID, r.UserAgent(), clientIP(r), 7*24*time.Hour)
	}
	if err != nil {
		s.errorPage(w, "create session", err)
		return
	}
	s.setSessionCookie(w, r, cookie)
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// setSessionCookie writes the standard hardened session cookie.
func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookie(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int((7 * 24 * time.Hour).Seconds()),
	})
}

// safeNextPath sanitises a post-login redirect target. Only same-origin
// absolute paths are allowed: it must start with a single "/" and must
// not be a protocol-relative ("//host") or backslash-smuggled ("/\host")
// URL, both of which browsers treat as cross-origin. Anything else falls
// back to "/". Closes the open-redirect via ?next=//evil.com.
func safeNextPath(next string) string {
	next = strings.TrimSpace(next)
	if next == "" || next[0] != '/' {
		return "/"
	}
	if strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	return next
}

// secureCookie decides whether the session cookie gets the Secure flag.
// Direct TLS sets it; behind the documented TLS-terminating proxy r.TLS
// is nil, so the operator opts in via Server.SecureCookies (wired from
// REACTOR_SECURE_COOKIES / an https dashboard URL). We deliberately do
// NOT trust X-Forwarded-Proto since the proxy set is not configured here.
func (s *Server) secureCookie(r *http.Request) bool {
	return r.TLS != nil || s.SecureCookies
}

// logout destroys the session, clears the cookie, redirects to /login.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" && s.Auth != nil {
		_ = s.Auth.DestroySession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// users renders the user-management page (admin-only).
func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	list, err := s.Auth.ListUsers(r.Context())
	if err != nil {
		s.errorPage(w, "list users", err)
		return
	}
	me, _ := UserFromContext(r.Context())
	s.renderPage(w, r, page{
		Title:   "Users",
		Heading: "Users",
		Body:    template.HTML(usersBody(list, me, "")),
	})
}

// usersCreate handles POST /users (admin-only).
func (s *Server) usersCreate(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	role := auth.Role(strings.TrimSpace(r.PostFormValue("role")))
	if role == "" {
		role = auth.RoleMember
	}
	tenant := strings.TrimSpace(r.PostFormValue("tenant_id"))
	if tenant == "" {
		tenant = "default"
	}
	// Validate the tenant before creating the user. SetUserTenant also checks
	// this at the auth boundary, but preflight avoids leaving a newly-created
	// user behind when the form names a tenant that no longer exists.
	if s.Journal != nil {
		if _, err := s.Journal.GetTenant(r.Context(), tenant); err != nil {
			s.usersError(w, r, fmt.Sprintf("tenant %q is unavailable: %v", tenant, err))
			return
		}
	}
	id, err := s.Auth.CreateUser(r.Context(), username, password, role)
	if err != nil {
		s.usersError(w, r, err.Error())
		return
	}
	if tErr := s.Auth.SetUserTenant(r.Context(), id, tenant); tErr != nil {
		// Do not report success with a user stranded in the schema default.
		// Roll back the identity because the user was not created in the
		// tenant the operator selected.
		if rollbackErr := s.Auth.DeleteUser(r.Context(), id); rollbackErr != nil && s.Log != nil {
			s.Log.Warn("usersCreate: rollback after tenant assignment failure failed", "id", id, "err", rollbackErr)
		}
		s.usersError(w, r, fmt.Sprintf("assign tenant %q: %v", tenant, tErr))
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// usersSetTenant moves a user to a tenant (admin-only), scoping their
// dashboard to that tenant's workflows + runs.
func (s *Server) usersSetTenant(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	tenant := strings.TrimSpace(r.PostFormValue("tenant_id"))
	if err := s.Auth.SetUserTenant(r.Context(), id, tenant); err != nil {
		s.errorPage(w, "set tenant", err)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// usersSetRole flips a user's role. The "cannot demote last admin"
// guard lives here so the journal layer stays simple.
func (s *Server) usersSetRole(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	role := auth.Role(strings.TrimSpace(r.PostFormValue("role")))
	if role == auth.RoleMember {
		// Hold adminMu across the guard + the demotion so a concurrent
		// demote can't also pass the last-admin check.
		s.adminMu.Lock()
		defer s.adminMu.Unlock()
		if err := s.guardLastAdminFor(r.Context(), id); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
	}
	if err := s.Auth.SetUserRole(r.Context(), id, role); err != nil {
		s.errorPage(w, "set role", err)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// usersDisable / usersEnable flip the disabled flag.
func (s *Server) usersDisable(w http.ResponseWriter, r *http.Request) {
	s.setUserDisabled(w, r, true)
}
func (s *Server) usersEnable(w http.ResponseWriter, r *http.Request) {
	s.setUserDisabled(w, r, false)
}

func (s *Server) setUserDisabled(w http.ResponseWriter, r *http.Request, disabled bool) {
	if !requireAdmin(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	if disabled {
		s.adminMu.Lock()
		defer s.adminMu.Unlock()
		if err := s.guardLastAdminFor(r.Context(), id); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		_ = s.Auth.DestroyAllSessionsForUser(r.Context(), id)
	}
	if err := s.Auth.SetUserDisabled(r.Context(), id, disabled); err != nil {
		s.errorPage(w, "set disabled", err)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// usersDelete removes a user (and their sessions/tokens via FK cascade).
func (s *Server) usersDelete(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	if err := s.guardLastAdminFor(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err := s.Auth.DeleteUser(r.Context(), id); err != nil {
		s.errorPage(w, "delete user", err)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// guardLastAdminFor returns an error when the target id is the only
// remaining active admin and the caller is about to demote / disable
// / delete them.
func (s *Server) guardLastAdminFor(ctx context.Context, id string) error {
	target, err := s.Auth.GetUser(ctx, id)
	if err != nil {
		return err
	}
	if !target.IsAdmin() || target.Disabled {
		return nil
	}
	n, err := s.Auth.CountAdmins(ctx)
	if err != nil {
		return err
	}
	if n <= 1 {
		return errors.New("cannot remove the last active admin; promote another user first")
	}
	return nil
}

func (s *Server) usersError(w http.ResponseWriter, r *http.Request, msg string) {
	list, _ := s.Auth.ListUsers(r.Context())
	me, _ := UserFromContext(r.Context())
	w.WriteHeader(http.StatusUnprocessableEntity)
	s.renderPage(w, r, page{
		Title:   "Users",
		Heading: "Users",
		Body:    template.HTML(usersBody(list, me, msg)),
	})
}

// tokens renders the calling user's API tokens page. Members + admins
// both see their own tokens; admins do not see other users' tokens
// (each user's tokens stay theirs).
func (s *Server) tokens(w http.ResponseWriter, r *http.Request) {
	me, ok := UserFromContext(r.Context())
	if !ok {
		http.Error(w, "not signed in", http.StatusUnauthorized)
		return
	}
	list, err := s.Auth.ListAPITokens(r.Context(), me.ID)
	if err != nil {
		s.errorPage(w, "list tokens", err)
		return
	}
	// One-time flash: the raw token just minted.
	flash := s.flash.take(w, r)
	s.renderPage(w, r, page{
		Title:   "API tokens",
		Heading: "API tokens",
		Body:    template.HTML(tokensBody(list, flash["new_token"])),
	})
}

// tokensCreate mints a new token, stashes the raw value in the flash
// store so it surfaces on the next page load exactly once, then
// redirects.
func (s *Server) tokensCreate(w http.ResponseWriter, r *http.Request) {
	me, ok := UserFromContext(r.Context())
	if !ok {
		http.Error(w, "not signed in", http.StatusUnauthorized)
		return
	}
	if !s.requireStepUp(w, r, me, false) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	ttl := defaultAPITokenTTL
	if rawDays := strings.TrimSpace(r.PostFormValue("ttl_days")); rawDays != "" {
		parsed, parseErr := strconv.Atoi(rawDays)
		if parseErr != nil || parsed < 1 || parsed > 3650 {
			http.Error(w, "ttl_days must be between 1 and 3650", http.StatusBadRequest)
			return
		}
		ttl = time.Duration(parsed) * 24 * time.Hour
	}
	raw, tokenID, err := s.Auth.MintAPIToken(r.Context(), me.ID, name, ttl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.flash.put(w, r, map[string]string{"new_token": raw}); err != nil {
		// A token whose raw value was never delivered cannot be used or
		// recovered. Revoke it with a short context detached from a client
		// cancellation so a flash-store outage does not leave an invisible
		// active credential behind.
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		rollbackErr := s.Auth.RevokeAPIToken(rollbackCtx, tokenID, me.ID)
		cancel()
		s.errorPage(w, "flash put", withRollbackError(err, rollbackErr))
		return
	}
	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

// tokensRevoke revokes a token by id (only for the calling user).
func (s *Server) tokensRevoke(w http.ResponseWriter, r *http.Request) {
	me, ok := UserFromContext(r.Context())
	if !ok {
		http.Error(w, "not signed in", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.Auth.RevokeAPIToken(r.Context(), id, me.ID); err != nil {
		s.errorPage(w, "revoke token", err)
		return
	}
	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

// requireAdminMW is the route-group middleware form of requireAdmin. It
// gates every privileged mutation (workflow code, credentials, triggers,
// notifications, codegen, uploads, DLQ retry). When auth is not wired
// (s.Auth == nil, used by tests and minimal installs) it passes through.
// In the anonymous bootstrap path (no users yet AND AllowNoAuth) it also
// passes through so the operator isn't locked out of first-run setup;
// SessionAuth only forwards an unauthenticated request under exactly that
// condition.
func (s *Server) requireAdminMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Auth == nil {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := UserFromContext(r.Context()); !ok && s.BasicAuth.AllowNoAuth {
			next.ServeHTTP(w, r)
			return
		}
		if !requireAdmin(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAdmin writes a 403 + returns false when the request's
// resolved user is missing or not an admin.
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	u, ok := UserFromContext(r.Context())
	if !ok {
		http.Error(w, "not signed in", http.StatusUnauthorized)
		return false
	}
	if !u.IsAdmin() {
		http.Error(w, "admin only", http.StatusForbidden)
		return false
	}
	return true
}

// loginBody is the sign-in form.
func loginBody(next, errMsg string) string {
	var b strings.Builder
	if errMsg != "" {
		b.WriteString(`<div class="err" style="background:#fff;border:1px solid var(--err);padding:12px 16px;margin:0 0 16px;border-radius:3px;">` +
			template.HTMLEscapeString(errMsg) + `</div>`)
	}
	fmt.Fprintf(&b, `<form method="POST" action="/login" class="form" style="max-width:400px;">
  <input type="hidden" name="next" value="%s">
  <label>Username <input type="text" name="username" required autocomplete="username" autofocus></label>
  <label>Password <input type="password" name="password" required autocomplete="current-password"></label>
  <button type="submit" class="btn-primary">Sign in</button>
</form>
<p class="muted">Lost your password? Ask an admin to mint a fresh one for you via the Users page.</p>`,
		template.HTMLEscapeString(next),
	)
	return b.String()
}

// usersBody renders the management table + the add-user form.
func usersBody(list []auth.User, me auth.User, errMsg string) string {
	var b strings.Builder
	if errMsg != "" {
		b.WriteString(`<div class="err" style="background:#fff;border:1px solid var(--err);padding:12px 16px;margin:0 0 16px;border-radius:3px;">` +
			template.HTMLEscapeString(errMsg) + `</div>`)
	}
	b.WriteString(`<table><thead><tr><th>Username</th><th>Role</th><th>Tenant</th><th>Status</th><th>Last login</th><th></th></tr></thead><tbody>`)
	for _, u := range list {
		status := `<span class="tag tag-on">active</span>`
		if u.Disabled {
			status = `<span class="tag tag-off">disabled</span>`
		}
		lastLogin := "-"
		if u.LastLoginAt != nil {
			lastLogin = u.LastLoginAt.UTC().Format("2006-01-02 15:04Z")
		}
		actions := ""
		if u.ID != me.ID {
			otherRole := auth.RoleAdmin
			if u.IsAdmin() {
				otherRole = auth.RoleMember
			}
			actions += fmt.Sprintf(`<form method="POST" action="/users/%s/role" class="form-inline"><input type="hidden" name="role" value="%s"><button type="submit" class="btn-link">make %s</button></form>`,
				template.URLQueryEscaper(u.ID), string(otherRole), string(otherRole))
			if u.Disabled {
				actions += fmt.Sprintf(`<form method="POST" action="/users/%s/enable" class="form-inline"><button type="submit" class="btn-link">enable</button></form>`,
					template.URLQueryEscaper(u.ID))
			} else {
				actions += fmt.Sprintf(`<form method="POST" action="/users/%s/disable" class="form-inline"><button type="submit" class="btn-link">disable</button></form>`,
					template.URLQueryEscaper(u.ID))
			}
			actions += fmt.Sprintf(`<form method="POST" action="/users/%s/password" class="form-inline" data-confirm="Issue a new password for %s? Every session they hold is signed out."><input type="password" name="password" placeholder="new password" required minlength="8" size="14" autocomplete="new-password"> <button type="submit" class="btn-link">set password</button></form>`,
				template.URLQueryEscaper(u.ID), template.HTMLEscapeString(u.Username))
			actions += fmt.Sprintf(`<form method="POST" action="/users/%s/delete" class="form-inline" data-confirm="Delete user %s?"><button type="submit" class="btn-link">delete</button></form>`,
				// HTMLEscapeString now, not JSEscapeString: the message moved
				// from an inline JS string literal into an HTML attribute, and
				// the CSP blocks inline handlers so the old onsubmit never ran
				// at all. In an attribute a JS-escaped quote is NOT neutralised.
				template.URLQueryEscaper(u.ID), template.HTMLEscapeString(u.Username))
		} else {
			actions = `<span class="muted">(you)</span>`
		}
		tenant := u.TenantID
		if tenant == "" {
			tenant = "default"
		}
		tenantCell := fmt.Sprintf(`<form method="POST" action="/users/%s/tenant" class="form-inline"><input type="text" name="tenant_id" value="%s" size="10" style="font-family:monospace;"> <button type="submit" class="btn-link">set</button></form>`,
			template.URLQueryEscaper(u.ID), template.HTMLEscapeString(tenant))
		fmt.Fprintf(&b, `<tr><td><code>%s</code></td><td><code>%s</code></td><td>%s</td><td>%s</td><td class="muted">%s</td><td>%s</td></tr>`,
			template.HTMLEscapeString(u.Username),
			template.HTMLEscapeString(string(u.Role)),
			tenantCell, status, lastLogin, actions,
		)
	}
	b.WriteString(`</tbody></table>`)

	b.WriteString(`<h2>Add user</h2>`)
	b.WriteString(`<form method="POST" action="/users" class="form">
  <label>Username <input type="text" name="username" required autocomplete="off"></label>
  <label>Password (min 8 chars) <input type="password" name="password" required autocomplete="new-password"></label>
  <label>Role <select name="role"><option value="member">member</option><option value="admin">admin</option></select></label>
  <label>Tenant <input type="text" name="tenant_id" autocomplete="off" placeholder="default"></label>
  <p class="muted">Members see only their own tenant's workflows + runs; admins see everything. Members can see + edit workflows, credentials, knowledge, and notifications. Admins additionally manage users + the global lifecycle (delete workflows, delete credentials, demote/disable accounts).</p>
  <button type="submit" class="btn-primary">Create user</button>
</form>`)
	return b.String()
}

// tokensBody renders the API tokens table + the mint form. flash is
// the one-time raw token surfaced on the post-mint redirect.
func tokensBody(list []auth.APIToken, flashRaw string) string {
	var b strings.Builder
	if flashRaw != "" {
		fmt.Fprintf(&b, `<div class="callout" style="background:#fff8e1;border:1px solid #f0c469;padding:12px 16px;margin:0 0 16px;border-radius:3px;">
  <p><strong>Token minted.</strong> Copy it now; it will not be shown again. Use it as <code>Authorization: Bearer %s</code> on requests to this dashboard.</p>
  <pre>%s</pre>
</div>`, template.HTMLEscapeString(flashRaw), template.HTMLEscapeString(flashRaw))
	}
	b.WriteString(`<h2>Your tokens</h2>`)
	if len(list) == 0 {
		b.WriteString(`<p class="muted">No tokens yet. Mint one below for CI scripts or third-party integrations.</p>`)
	} else {
		b.WriteString(`<table><thead><tr><th>Name</th><th>Created</th><th>Last used</th><th>Expires</th><th>Status</th><th></th></tr></thead><tbody>`)
		for _, t := range list {
			status := `<span class="tag tag-on">active</span>`
			if t.Revoked {
				status = `<span class="tag tag-off">revoked</span>`
			}
			lastUsed := "-"
			if t.LastUsedAt != nil {
				lastUsed = t.LastUsedAt.UTC().Format("2006-01-02 15:04Z")
			}
			expires := "-"
			if t.ExpiresAt != nil {
				expires = t.ExpiresAt.UTC().Format("2006-01-02")
			}
			actions := ""
			if !t.Revoked {
				actions = fmt.Sprintf(`<form method="POST" action="/tokens/%s/revoke" class="form-inline" data-confirm="Revoke token %s? CI scripts using it will start failing."><button type="submit" class="btn-link">revoke</button></form>`,
					// HTML attribute now (see the delete-user site above).
					template.URLQueryEscaper(t.ID), template.HTMLEscapeString(t.Name))
			}
			fmt.Fprintf(&b, `<tr><td>%s</td><td class="muted">%s</td><td class="muted">%s</td><td class="muted">%s</td><td>%s</td><td>%s</td></tr>`,
				template.HTMLEscapeString(t.Name),
				t.CreatedAt.UTC().Format("2006-01-02 15:04Z"),
				lastUsed, expires, status, actions,
			)
		}
		b.WriteString(`</tbody></table>`)
	}
	b.WriteString(`<h2>Mint a token</h2>`)
	b.WriteString(`<form method="POST" action="/tokens" class="form">
  <label>Name <input type="text" name="name" required autocomplete="off" placeholder="ci-deploy, laptop, integration-test"></label>
  <label>Lifetime <select name="ttl_days"><option value="30">30 days</option><option value="90" selected>90 days</option><option value="365">1 year</option><option value="3650">10 years</option></select></label>
  <p class="muted">The token expires automatically and is shown once on the next page load; copy it immediately. It has the same permissions your user account has.</p>
  <button type="submit" class="btn-primary">Mint token</button>
</form>`)
	return b.String()
}
