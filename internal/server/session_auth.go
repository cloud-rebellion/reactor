package server

import (
	"context"
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"

	"github.com/bright-interaction/reactor/internal/auth"
)

// SessionCookieName is the dashboard's session cookie name.
const SessionCookieName = "reactor_sess"

// mcpBearerChallenge is returned with HTTP 401 responses from the MCP
// connection boundary. MCP clients use the challenge to distinguish an
// authentication failure from a transport or JSON-RPC failure; it also keeps
// this route aligned with the Stage bearer-auth contract.
const mcpBearerChallenge = `Bearer realm="reactor-mcp"`

// userCtxKey is the context key the session middleware uses to stash
// the resolved user; per-request handlers read it via UserFromContext.
type userCtxKey struct{}

// UserFromContext returns the user the auth middleware resolved for
// this request. Returns ok=false on routes that bypass auth (healthz,
// webhook, signal) or when the daemon ships without auth wired.
func UserFromContext(ctx context.Context) (auth.User, bool) {
	u, ok := ctx.Value(userCtxKey{}).(auth.User)
	return u, ok
}

// sessionStateCtxKey / sessionCookieCtxKey carry the resolved session's MFA
// assurance level and its raw cookie value, so step-up-gated handlers can read
// the elevation window and mint a fresh one against the right session.
type sessionStateCtxKey struct{}
type sessionCookieCtxKey struct{}

// SessionStateFromContext returns the resolved session's MFA assurance level.
func SessionStateFromContext(ctx context.Context) (auth.SessionState, bool) {
	st, ok := ctx.Value(sessionStateCtxKey{}).(auth.SessionState)
	return st, ok
}

// sessionCookieFromContext returns the raw session cookie value for the request,
// used to target ClearSessionMFAPending / MarkSessionElevated at this session.
func sessionCookieFromContext(ctx context.Context) string {
	v, _ := ctx.Value(sessionCookieCtxKey{}).(string)
	return v
}

func withSessionState(ctx context.Context, st auth.SessionState) context.Context {
	return context.WithValue(ctx, sessionStateCtxKey{}, st)
}

func withSessionCookie(ctx context.Context, cookie string) context.Context {
	return context.WithValue(ctx, sessionCookieCtxKey{}, cookie)
}

// authStore is the surface the middleware needs from the auth store.
// Defined here at the consumer so tests can stub.
type authStore interface {
	Authenticate(ctx context.Context, username, password string) (auth.User, error)
	ResolveSessionWithState(ctx context.Context, cookieValue string) (auth.User, auth.SessionState, error)
	ResolveAPIToken(ctx context.Context, raw string) (auth.User, error)
	CountUsers(ctx context.Context) (int, error)
	HasMFA(ctx context.Context, userID string) (bool, error)
}

// SessionAuthConfig wires the multi-source auth middleware. The
// middleware is mounted alongside (and BEFORE) the legacy BasicAuth
// middleware in the chain; it short-circuits the legacy gate when it
// successfully resolves a session OR an API token, OR when there is
// at least one user in the users table (in which case the legacy
// env-var BasicAuth no longer applies).
type SessionAuthConfig struct {
	// Store resolves sessions + tokens + falls back to user-table
	// BasicAuth (replacing the env-var BasicAuth) when a request
	// arrives with Authorization: Basic.
	Store authStore

	// LegacyAllowNoAuth mirrors BasicAuthConfig.AllowNoAuth; when no
	// users exist AND no env-var creds are set AND this is true, the
	// middleware passes traffic through. Otherwise 503.
	LegacyAllowNoAuth bool
	// LegacyBasicAuthConfigured prevents the MCP no-auth bootstrap exception
	// from accepting Basic credentials when an operator also supplied them.
	LegacyBasicAuthConfigured bool

	// MCPToken is an optional dedicated bearer credential for the HTTP MCP
	// route. It mirrors the Stage/Mesh service-token connection shape while
	// keeping the existing per-user API-token path intact. MCPUser is the
	// bounded identity assigned only after the dedicated token matches.
	MCPToken string
	MCPUser  auth.User
}

// bearerAuthorization accepts the HTTP authentication scheme without
// depending on its presentation casing. RFC 9110 defines auth-scheme as
// case-insensitive; MCP clients commonly send "Bearer", but lower-case
// "bearer" is equally valid. The second return value distinguishes a
// recognized-but-empty bearer credential so /mcp can reject it with the
// dedicated challenge instead of falling through to another identity source.
func bearerAuthorization(header string) (string, bool) {
	fields := strings.Fields(header)
	if len(fields) == 0 || !strings.EqualFold(fields[0], "Bearer") {
		return "", false
	}
	if len(fields) == 1 {
		return "", true
	}
	return strings.Join(fields[1:], " "), true
}

// SessionAuth returns the middleware. Resolution order:
//
//  1. On `/mcp`, only an `Authorization: Bearer` connection identity is
//     accepted when the auth store is configured. A cookie or Basic credential
//     cannot silently change the tenant bound to an MCP client. Explicit
//     local no-auth bootstrap remains available with no users or MCP token.
//  2. Cookie `reactor_sess` -> session store lookup.
//  3. `Authorization: Bearer <token>` -> api_tokens store lookup.
//  4. `Authorization: Basic <user>:<pw>` -> Authenticate via the users
//     table when at least one user exists, else fall back to the
//     legacy env-var BasicAuth (the layer below this one).
//  5. None of the above + no users + no env creds -> redirect to
//     /login when a browser arrives (Accept: text/html), else 401.
//
// Public routes (healthz, readyz, webhook, signal, login, assets, docs) skip
// the gate.
// /mcp remains authenticated so its dedicated or per-user bearer identity
// reaches the admin and tenant-scoping layers.
func SessionAuth(cfg SessionAuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isSessionAuthExempt(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			if cfg.Store == nil {
				// A dedicated MCP bearer is an independent connection contract,
				// not a database API-token lookup. Keep enforcing it even in a
				// minimal/embedded deployment that has no auth store wired; otherwise
				// BasicAuth's explicit no-auth mode would accidentally expose /mcp
				// without the configured Stage/Mesh-style bearer credential.
				if r.URL.Path == "/mcp" && strings.TrimSpace(cfg.MCPToken) != "" {
					raw, ok := bearerAuthorization(r.Header.Get("Authorization"))
					if !ok || raw == "" || subtle.ConstantTimeCompare([]byte(raw), []byte(cfg.MCPToken)) != 1 {
						rejectMCPBearer(w, "Unauthorized")
						return
					}
					u := cfg.MCPUser
					if u.ID == "" {
						u.ID = "mcp-http"
					}
					if u.Role == "" {
						u.Role = auth.RoleAdmin
					}
					r = r.WithContext(withUser(r.Context(), u))
				}
				// No store wired (test/embedded deployments); defer to the legacy
				// BasicAuth middleware for all other routes.
				next.ServeHTTP(w, r)
				return
			}

			ctx := r.Context()

			// MCP is a bearer-only connection surface when the auth store is
			// configured. Never let a dashboard cookie or Basic credential
			// select its tenant or role, including when the Bearer is absent.
			if r.URL.Path == "/mcp" {
				if raw, ok := bearerAuthorization(r.Header.Get("Authorization")); ok {
					if raw == "" {
						rejectMCPBearer(w, "unauthorized")
						return
					}
					if u, err := cfg.Store.ResolveAPIToken(ctx, raw); err == nil {
						r = r.WithContext(withUser(r.Context(), u))
						next.ServeHTTP(w, r)
						return
					}
					if cfg.MCPToken != "" && subtle.ConstantTimeCompare([]byte(raw), []byte(cfg.MCPToken)) == 1 {
						u := cfg.MCPUser
						if u.ID == "" {
							u.ID = "mcp-http"
						}
						if u.Role == "" {
							u.Role = auth.RoleAdmin
						}
						r = r.WithContext(withUser(r.Context(), u))
						next.ServeHTTP(w, r)
						return
					}
					rejectMCPBearer(w, "unauthorized")
					return
				}
				// Local bootstrap can intentionally run with no users and no
				// bearer. Startup validates that this configuration binds only
				// to loopback; a configured MCP token always takes precedence.
				if cfg.LegacyAllowNoAuth && !cfg.LegacyBasicAuthConfigured && cfg.MCPToken == "" {
					if n, err := cfg.Store.CountUsers(ctx); err == nil && n == 0 {
						next.ServeHTTP(w, r)
						return
					}
				}
				rejectMCPBearer(w, "Unauthorized")
				return
			}

			// (1) cookie -> session.
			if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
				u, st, err := cfg.Store.ResolveSessionWithState(ctx, c.Value)
				if err == nil {
					ctx = withUser(ctx, u)
					ctx = withSessionState(ctx, st)
					ctx = withSessionCookie(ctx, c.Value)
					// A pending session (password accepted, second factor still
					// owed) may reach only the MFA-completion + logout routes;
					// everything else bounces to the challenge. This is the gate
					// that makes "has a factor" actually enforce the factor.
					if st.MFAPending && !isMFACompletionRoute(r.URL.Path) {
						if wantsHTML(r) {
							http.Redirect(w, r, "/login/mfa?next="+url.QueryEscape(r.URL.Path), http.StatusSeeOther)
						} else {
							http.Error(w, "MFA required", http.StatusUnauthorized)
						}
						return
					}
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				// Bad cookie: clear it so the browser does not keep
				// retrying.
				http.SetCookie(w, &http.Cookie{
					Name: SessionCookieName, Value: "", Path: "/", MaxAge: -1,
					HttpOnly: true, SameSite: http.SameSiteStrictMode,
				})
			}

			// (2) Bearer token. API tokens are a SEPARATE, non-interactive
			// credential class (own table, no factor dimension), minted only by
			// an already-authenticated session. They intentionally skip the
			// mfa_pending gate, and because this branch never stashes a session
			// state, requireStepUp always fails for a token, so a token cannot
			// reach step-up-gated surfaces either.
			if raw, ok := bearerAuthorization(r.Header.Get("Authorization")); ok {
				if raw != "" {
					if u, err := cfg.Store.ResolveAPIToken(ctx, raw); err == nil {
						r = r.WithContext(withUser(ctx, u))
						next.ServeHTTP(w, r)
						return
					}
				}
			}

			// (3) Basic against the users table.
			if user, pass, ok := r.BasicAuth(); ok && user != "" {
				if u, err := cfg.Store.Authenticate(ctx, user, pass); err == nil {
					// HTTP Basic is single-factor (password only). A user who has
					// enrolled a second factor must NOT be able to satisfy a
					// request with their password alone here; that would defeat
					// the mfa_pending gate the interactive cookie login builds.
					// Refuse and direct them to the dashboard sign-in flow.
					// Fail closed: a HasMFA lookup error denies rather than grants.
					hasMFA, herr := cfg.Store.HasMFA(ctx, u.ID)
					if herr != nil {
						http.Error(w, "auth error", http.StatusInternalServerError)
						return
					}
					if hasMFA {
						if wantsHTML(r) {
							http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.Path), http.StatusSeeOther)
						} else {
							http.Error(w, "multi-factor authentication required: sign in via the dashboard, not HTTP Basic", http.StatusUnauthorized)
						}
						return
					}
					r = r.WithContext(withUser(ctx, u))
					next.ServeHTTP(w, r)
					return
				}
				// Falls through to (4); BasicAuth credentials might
				// still match the legacy env-var BasicAuth below.
			}

			// (4) No user resolved + no users in DB + AllowNoAuth ->
			// pass through; else require login.
			if n, err := cfg.Store.CountUsers(ctx); err == nil && n == 0 {
				// No users provisioned yet. The legacy BasicAuth in the
				// chain below handles the env-var path (or 503 / pass).
				next.ServeHTTP(w, r)
				return
			}

			// Users exist + no resolved identity -> redirect or 401.
			if wantsHTML(r) {
				http.Redirect(w, r, "/login?next="+r.URL.Path, http.StatusSeeOther)
				return
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		})
	}
}

// rejectMCPBearer writes a challenge for the bearer-only connection contract.
// Keep this scoped to /mcp: dashboard callers may still authenticate with a
// session cookie or HTTP Basic and must not receive a misleading bearer
// challenge from those surfaces.
func rejectMCPBearer(w http.ResponseWriter, message string) {
	w.Header().Set("WWW-Authenticate", mcpBearerChallenge)
	http.Error(w, message, http.StatusUnauthorized)
}

// isSessionAuthExempt mirrors isPublicRoute but also exempts /login
// and /assets so the operator can reach the login form + its CSS
// without already being logged in.
func isSessionAuthExempt(path string) bool {
	switch {
	case path == "/healthz":
		return true
	case path == "/readyz":
		// Readiness is an unauthenticated probe just like liveness. It must
		// reach the dependency checks even when the users table already has
		// accounts; otherwise this middleware would turn a healthy probe into
		// a login redirect/401 before BasicAuth can apply its public-route
		// exemption.
		return true
	case path == "/oauth/callback":
		// The provider redirect carries no dashboard credentials. The OAuth
		// store's single-use state and PKCE verifier are the callback
		// capability, so requiring a session here would make MCP-started
		// consent fail for a browser that is not signed in (or whose session
		// expired while the provider was open).
		return true
	case path == "/login":
		return true
	case strings.HasPrefix(path, "/webhook/"):
		return true
	case strings.HasPrefix(path, "/command-webhook/"):
		return true
	case strings.HasPrefix(path, "/signal/"):
		return true
	case strings.HasPrefix(path, "/assets/"):
		return true
	case path == "/docs" || strings.HasPrefix(path, "/docs/"):
		// Docs are public so an operator on /login can still read
		// them while figuring out how to sign in.
		return true
	}
	// /mcp is intentionally NOT exempt: it runs through SessionAuth so an
	// MCP client must present a Bearer API token (per-user identity +
	// RBAC) instead of relying on the legacy shared BasicAuth.
	return false
}

// isMFACompletionRoute lists what a pending (second-factor-owed) session may
// reach: the MFA challenge page + its ceremony endpoints, and logout. Kept in
// sync with the /login/mfa* routes mounted in mountAuthRoutes.
func isMFACompletionRoute(path string) bool {
	return path == "/login/mfa" || strings.HasPrefix(path, "/login/mfa/") || path == "/logout"
}

func wantsHTML(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/html") ||
		strings.Contains(accept, "*/*") ||
		accept == ""
}

func withUser(ctx context.Context, u auth.User) context.Context {
	return context.WithValue(ctx, userCtxKey{}, u)
}
