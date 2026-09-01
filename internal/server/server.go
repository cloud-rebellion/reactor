// Package server is the daemon's HTTP surface: webhook receiver +
// signal route from internal/runtime/webhook, plus status pages
// (server-rendered HTML for v1 since the SvelteKit dashboard is week
// 11 work). Templates are inline so the binary stays self-contained.
//
// Routes:
//
//	GET  /healthz           liveness probe (returns 200 + JSON)
//	GET  /                  home: workflows + recent runs
//	GET  /runs              full runs list
//	GET  /runs/{id}         run timeline
//	GET  /credentials       credentials with rotation state
//	GET  /credentials/{id}  credential detail + audit log
//	POST /webhook/{token}   trigger payload (HMAC-verified)
//	POST /signal/{token}    AwaitSignal external delivery
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/flarereport"
	"github.com/bright-interaction/reactor/internal/graph"
	"github.com/bright-interaction/reactor/internal/knowledge"
	"github.com/bright-interaction/reactor/internal/oauth"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runlogs"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/webhook"
	"github.com/bright-interaction/reactor/internal/vault"
)

// Server wires every HTTP-facing component together. The daemon
// constructs one + serves it; tests can mount sub-routers selectively.
type Server struct {
	Journal     *journal.Journal
	Credentials *credentials.Repo
	OAuth       *oauth.Store
	Registry    *registry.FileRegistry
	Knowledge   *knowledge.Store
	Graph       *graph.Graph
	Webhook     *webhook.Receiver
	Log         *slog.Logger
	Version     string

	// WorkflowsRoot is the parent directory for workflow source files
	// (workflow.go + dag.json), not the binary registry. Used by the
	// /workflows/{slug} route to render code + DAG panes. Defaults to
	// the registry's Root when empty so codegen-emitted workflows
	// (which land at <root>/workflows/<slug>/) work without extra
	// configuration.
	WorkflowsRoot string

	// CodeValidator runs the same vet + lint + build chain the codegen
	// orchestrator uses, on every editor save. When nil, the editor
	// save routes return 503 (the daemon was started without the
	// validator wired). Defined as the bare interface below so the
	// server package doesn't drag in internal/codegen at compile time.
	CodeValidator CodeValidator

	// CodeCommitter commits the new file to git after a successful
	// validate. Optional; nil → no commit (REACTOR_GIT_BACKED=false path).
	CodeCommitter CodeCommitter

	// LogBuffer holds per-run log lines so /runs/{id}/tail can stream
	// them via SSE. Optional; nil → tail endpoint returns 503.
	LogBuffer *runlogs.Buffer

	// RunCanceller stops a running or suspended run. Optional; nil → the
	// /runs/{id}/cancel route returns 503 + the Cancel button is hidden.
	RunCanceller RunCanceller

	// BasicAuth gates every route except /healthz + /webhook/* +
	// /signal/* (those have their own auth contracts: HMAC for webhook,
	// 128-bit token for signal, intentionally-public for healthz).
	// Empty User or PasswordSHA256 disables auth (local-demo mode).
	BasicAuth BasicAuthConfig

	// SecureCookies forces the Secure flag on the session cookie even
	// when r.TLS is nil (the daemon sits behind a TLS-terminating proxy
	// like Caddy). Wired from REACTOR_SECURE_COOKIES or an https
	// dashboard URL. Direct-TLS deployments get Secure regardless.
	SecureCookies bool

	// RateLimit caps requests per source IP. Burst is bucket capacity;
	// Refill is the steady-state per-second rate. Zero on either field
	// disables the limiter.
	RateLimit RateLimitConfig

	// Vault is the credential store used by the dashboard's create-
	// credential form. When nil, /credentials/new returns 503 (the
	// daemon was started without write surfaces wired).
	Vault *vault.Store

	// Rotator triggers a manual rotation when the operator clicks
	// "Rotate now" on the credential detail page. When nil, the
	// rotate route returns 503.
	Rotator CredentialRotator

	// Generator drives the codegen prompt bar on the home page. When
	// non-nil the form is rendered + POST /generate is mounted; nil
	// means the operator falls back to the `reactor generate` CLI.
	// Surfaced as an interface so the server doesn't drag internal/
	// codegen + its Anthropic client into read-only deployments.
	Generator WorkflowGenerator

	// State directory; `<State>/workflows/<slug>/workflow` is where
	// generated workflow binaries land. Required by the codegen prompt
	// bar's auto-build step. Falls back to s.Registry.Root when empty.
	State string

	// MCPHandler, when non-nil, is mounted at POST /mcp as the
	// Streamable HTTP MCP transport. The daemon constructs an
	// *mcp.Server (which is http.Handler) and passes it in. Remote
	// AI clients that can't speak stdio (cloud-hosted Claude, web
	// IDEs, custom HTTP gateways) connect here. The existing
	// BasicAuth + RateLimit middleware applies automatically.
	MCPHandler http.Handler

	// DLQRetry powers the "Retry from DLQ" button on /runs/{id}.
	// Daemon wires *dispatcher.Dispatcher.
	DLQRetry DLQRetrier

	// KnowledgeWrite powers /knowledge/new + the action buttons on
	// /knowledge/{id}. Daemon wires *knowledge.Store.
	KnowledgeWrite KnowledgeWriter

	// WorkflowRegister powers /workflows/new (upload + register flow
	// for operators with Go source on disk who don't want to invoke
	// the codegen path). Daemon wires a small adapter that drives
	// the same go-vet + lint + build chain.
	WorkflowRegister WorkflowRegistrar

	// Metrics is the Prometheus-text counter set exposed at /metrics.
	// When nil, the route returns 503. Dispatcher / rotators / MCP
	// increment the relevant gauges.
	Metrics *Metrics

	// ManualDispatch powers the "Run now" button on the home page +
	// workflow detail. Daemon wires *dispatcher.Dispatcher.
	ManualDispatch ManualDispatcher

	// Notifier handles "send test alert" + (in a future iteration)
	// inline channel diagnostics. Daemon wires *notifier.Notifier; nil
	// disables the test button.
	Notifier Notifier

	// Auth is the user + session + API token surface. When nil, the
	// dashboard falls back to the legacy env-var BasicAuth gate; when
	// wired, the session middleware short-circuits BasicAuth for any
	// request that resolves a session, an API token, or a real user
	// from the users table.
	Auth AuthAdmin

	// flash is the single-use encrypted store for one-time payloads surfaced
	// on the next page load (e.g. a freshly-minted webhook HMAC secret). When
	// Journal is wired, the ciphertext is shared across replicas while the
	// decryption capability remains only in the browser cookie.
	flash *flashStore

	// loginLimiter throttles failed logins (brute-force lockout). Lazily
	// initialised so tests + minimal mounts don't have to wire it.
	loginLimiter   *loginThrottle
	loginLimiterMu sync.Mutex

	// adminMu serializes admin-removing mutations (demote / disable /
	// delete) with the last-admin guard so two concurrent requests can't
	// both pass the "more than one admin" check and zero out the admins.
	// An in-process mutex is sufficient because Reactor runs as a single
	// daemon.
	adminMu sync.Mutex

	// analytics cache: the home page's rollup GROUP-BYs the whole runs
	// table + runs one query per workflow. Cache it for a few seconds so a
	// burst of page loads (or many tabs) doesn't re-scan history each time.
	analyticsMu    sync.Mutex
	analyticsCache journal.Analytics
	analyticsAt    time.Time
	analyticsOK    bool
}

// analyticsTTL is how long a computed home-page rollup is reused.
const analyticsTTL = 10 * time.Second

// cachedAnalytics returns the home-page rollup, recomputing only when the
// cached copy is older than analyticsTTL. On a recompute error it returns
// the last good value (if any) so a transient DB hiccup doesn't blank the
// dashboard.
func (s *Server) cachedAnalytics(ctx context.Context) (journal.Analytics, error) {
	s.analyticsMu.Lock()
	defer s.analyticsMu.Unlock()
	if s.analyticsOK && time.Since(s.analyticsAt) < analyticsTTL {
		return s.analyticsCache, nil
	}
	a, err := s.Journal.AnalyticsSummary(ctx)
	if err != nil {
		if s.analyticsOK {
			return s.analyticsCache, nil // serve stale rather than fail
		}
		return a, err
	}
	s.analyticsCache = a
	s.analyticsAt = time.Now()
	s.analyticsOK = true
	return a, nil
}

// loginThrottle returns the lazily-initialised failed-login limiter.
func (s *Server) loginThrottle() *loginThrottle {
	s.loginLimiterMu.Lock()
	defer s.loginLimiterMu.Unlock()
	if s.loginLimiter == nil {
		s.loginLimiter = newLoginThrottle()
	}
	return s.loginLimiter
}

// WorkflowGenerator is the minimal surface the codegen prompt bar
// invokes. The daemon wires *codegen.Generator here. Decoupled to
// avoid the server package importing internal/codegen (which would
// pull the Anthropic client into every read-only deployment).
type WorkflowGenerator interface {
	GenerateFromBrief(ctx context.Context, brief string) (slug, path, version string, err error)
}

// CredentialRotator is the manual-rotate surface the dashboard calls into.
// The daemon wires the existing *rotators.Runner here. Minimal interface
// avoids the server package importing internal/rotators (which would pull
// in the AWS SigV4 + GitHub sealed-box code unnecessarily for read-only
// deployments).
type CredentialRotator interface {
	RotateOne(ctx context.Context, credentialID string) error

	// ProviderCapabilities describes what rotating a given provider will
	// actually do, so the dashboard can say so before the click instead of only
	// in the audit trail afterwards. canAutoRotate=false means rotation records
	// a reminder and leaves the value untouched. mintsValueLocally=true means
	// rotation DISCARDS the stored secret and generates a new random one, which
	// on an externally issued key is destruction rather than rotation.
	//
	// Exposed through this interface rather than by importing internal/rotators
	// so read-only deployments still avoid the AWS SigV4 + sealed-box
	// dependencies (the reason this interface exists at all).
	ProviderCapabilities(provider string) (canAutoRotate, mintsValueLocally bool, err error)
}

// DLQRetrier is the dashboard's "Retry from DLQ" button surface. The
// daemon wires *dispatcher.Dispatcher here. Decoupled so the server
// package doesn't pull in supervisor + vault on read-only mounts.
type DLQRetrier interface {
	RetryDeadLetter(ctx context.Context, dlqID string) (status string, err error)
}

// KnowledgeWriter is the dashboard's knowledge-corpus write surface.
// The daemon wires *knowledge.Store. Add returns the new entry id;
// the lifecycle verbs all take an id and return error only.
type KnowledgeWriter interface {
	AddEntry(ctx context.Context, topic, title, body, createdBy string, tags []string) (string, error)
	SupersedeEntry(ctx context.Context, id, supersededBy string) error
	PromoteEntry(ctx context.Context, id string) error
	StaleEntry(ctx context.Context, id string) error
}

// WorkflowRegistrar is the dashboard's "register an existing workflow"
// surface. Accepts a directory containing main.go + dag.json, runs the
// validator chain, builds the binary, inserts the workflows row.
type WorkflowRegistrar interface {
	// tenantID owns the resulting workflow; empty means the default tenant.
	// Without it the dashboard's upload path could not express ownership and
	// every workflow landed in "default" regardless of the operator's choice,
	// which is what kept tenancy inert on the workflow side.
	RegisterFromDir(ctx context.Context, slug, dir, tenantID string) (workflowID string, err error)
}

// CodeValidator is the editor save's validation surface. The daemon
// wires the existing codegen.GoBuildValidator here so a save runs the
// same gates as a generate. The minimal shape avoids an import cycle.
type CodeValidator interface {
	Validate(ctx context.Context, dir, slug, workflowGo, dagJSON string) error
}

// CodeCommitter mirrors codegen.Committer's signature; the daemon wires
// the existing GitCommitter here.
type CodeCommitter interface {
	Commit(ctx context.Context, dir, slug, msg string) error
}

// RateLimitConfig is exposed via Server config so tests can crank it
// up + production deployments can tune per-host.
type RateLimitConfig struct {
	Burst  int
	Refill float64
}

// Mount registers every route on the given chi router. Middleware
// wraps in order: SecurityHeaders (always), RateLimit (if configured),
// BasicAuth (always; fail-closed when creds are unset unless
// AllowNoAuth is true), CSRF (always; exempts /webhook, /signal, /mcp).
//
// Routes are mounted via per-feature helpers so a missing capability
// (e.g. Vault nil for read-only deployments) skips an entire route
// group at one site rather than scattering 20 nil-checks across one
// function.
func (s *Server) Mount(r chi.Router) {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	if s.flash == nil {
		if s.Journal != nil {
			s.flash = newFlashStore(s.Journal)
		} else {
			s.flash = newFlashStore()
		}
	}
	s.flash.secureCookies = s.SecureCookies
	s.mountMiddleware(r)
	// Member-accessible surfaces: read views, running existing workflows,
	// the knowledge/graph reads, MCP, public webhook + docs, and the auth
	// routes (which gate their own admin-only handlers internally).
	s.mountReadRoutes(r)
	s.mountManualDispatchRoute(r)
	s.mountRunCancelRoute(r)
	// Knowledge reads are member-visible again, but TENANT-SCOPED in the
	// handlers: the corpus mixes shared playbooks (no tenant, everyone) with
	// per-tenant post-mortems (stamped from the run). Gating the whole page to
	// admins closed the leak by removing the feature; scoping keeps both.
	s.mountKnowledgeRoutes(r)
	s.mountWebhookRoutes(r)
	s.mountAuthRoutes(r)
	s.mountTenantsRoutes(r)
	r.Get("/account", s.account)
	r.Get("/postmortems", s.postmortems)
	r.Get("/templates", s.templates)
	s.mountConnectionRoutes(r)
	s.mountDocsRoutes(r)

	// Admin-only mutations. Authoring/saving workflow code is host code
	// execution; creating/rotating/granting credentials, triggers, and
	// notification channels are all privileged. A single route-group gate
	// covers every one of them instead of relying on per-handler checks
	// (which previously guarded only two routes). When auth is not wired
	// (tests, --insecure-no-auth bootstrap) the gate passes through.
	r.Group(func(ar chi.Router) {
		ar.Use(s.requireAdminMW)
		// MCP is host-adjacent authoring/introspection (workflow build = code
		// execution; read tools are not tenant-scoped). Gate it behind admin
		// like every other write surface so a member token cannot reach the
		// cross-tenant read tools or any future write tool wired over HTTP.
		s.mountMCPRoute(ar)
		// /graph.json serialises the WHOLE estate graph: every tenant's
		// workflow slugs, the full workflow->credential grant matrix,
		// credential names/services/rotation errors, and dead-letter error
		// text. Its handler discards *http.Request, so viewerScope can't even
		// be consulted. It was mounted on the member router, which contradicted
		// the admin gate already applied to the identical MCP query_graph tool
		// two lines up. Same data, same gate.
		s.mountGraphRoute(ar)
		s.mountVaultRoutes(ar)
		s.mountCredentialOpRoutes(ar)
		s.mountWorkflowEditRoutes(ar)
		s.mountTriggerWriteRoutes(ar)
		s.mountWorkflowLifecycleRoutes(ar)
		s.mountGenerateRoute(ar)
		s.mountDLQRoute(ar)
		s.mountKnowledgeWriteRoutes(ar)
		s.mountWorkflowUploadRoutes(ar)
		s.mountAuditRoute(ar)
		s.mountNotificationsRoutes(ar)
	})
}

func (s *Server) mountDocsRoutes(r chi.Router) {
	r.Get("/docs", s.docsIndex)
	r.Get("/docs/{page}", s.docPage)
}

// mountConnectionRoutes mounts the OAuth connections (member, tenant-scoped)
// and the provider config (admin-only, gated in-handler). Handlers no-op
// gracefully when OAuth isn't wired.
func (s *Server) mountConnectionRoutes(r chi.Router) {
	r.Get("/integrations", s.integrations)
	r.Get("/connections", s.connections)
	r.Post("/connections/{provider}/start", s.connectionsStart)
	r.Post("/connections/{id}/delete", s.connectionsDelete)
	r.Get("/oauth/callback", s.oauthCallback)
	r.Get("/oauth-providers", s.oauthProviders)
	r.Post("/oauth-providers", s.oauthProvidersUpsert)
	r.Post("/oauth-providers/{id}/delete", s.oauthProvidersDelete)
}

// mountTenantsRoutes mounts the tenant + quota admin page and the billing-plan
// catalog. Each handler gates itself with requireAdmin (same pattern as the
// /users routes).
func (s *Server) mountTenantsRoutes(r chi.Router) {
	r.Get("/tenants", s.tenants)
	r.Post("/tenants", s.tenantsUpsert)
	r.Post("/tenants/{id}/delete", s.tenantsDelete)
	r.Post("/tenants/{id}/plan", s.tenantsAssignPlan)
	r.Get("/tenants/{id}/export", s.tenantExport)
	r.Post("/tenants/{id}/erase", s.tenantErase)
	r.Get("/plans", s.plans)
	r.Post("/plans", s.plansUpsert)
	r.Post("/plans/{id}/delete", s.plansDelete)
}

func (s *Server) mountAuthRoutes(r chi.Router) {
	if s.Auth == nil {
		return
	}
	r.Get("/login", s.loginGet)
	r.Post("/login", s.loginPost)
	r.Post("/logout", s.logout)
	r.Get("/tokens", s.tokens)
	r.Post("/tokens", s.tokensCreate)
	r.Post("/tokens/{id}/revoke", s.tokensRevoke)
	r.Get("/users", s.users)
	r.Post("/users", s.usersCreate)
	r.Post("/users/{id}/role", s.usersSetRole)
	r.Post("/users/{id}/tenant", s.usersSetTenant)
	r.Post("/users/{id}/disable", s.usersDisable)
	r.Post("/users/{id}/enable", s.usersEnable)
	r.Post("/users/{id}/delete", s.usersDelete)
	// Password reset (admin, gated in-handler) + self-service change. Without
	// these the login page's "ask an admin to mint a fresh one" was a promise
	// no surface could keep.
	r.Post("/users/{id}/password", s.usersSetPassword)
	r.Post("/account/password", s.accountChangePassword)

	// Second-factor challenge at login (reachable by a pending session only).
	r.Get("/login/mfa", s.mfaChallenge)
	r.Post("/login/mfa/webauthn/begin", s.mfaLoginWebAuthnBegin)
	r.Post("/login/mfa/webauthn/finish", s.mfaLoginWebAuthnFinish)
	r.Post("/login/mfa/totp", s.mfaLoginTOTP)
	r.Post("/login/mfa/recovery", s.mfaLoginRecovery)

	// Self-service factor management (every signed-in user; own factors only).
	// Mutations are step-up gated once the user already has a factor.
	r.Get("/security", s.security)
	r.Post("/security/webauthn/register/begin", s.securityWebAuthnRegisterBegin)
	r.Post("/security/webauthn/register/finish", s.securityWebAuthnRegisterFinish)
	r.Post("/security/webauthn/{id}/delete", s.securityWebAuthnDelete)
	r.Post("/security/webauthn/{id}/rename", s.securityWebAuthnRename)
	r.Post("/security/totp/begin", s.securityTOTPBegin)
	r.Post("/security/totp/confirm", s.securityTOTPConfirm)
	r.Post("/security/totp/disable", s.securityTOTPDisable)
	r.Post("/security/recovery/regenerate", s.securityRecoveryRegenerate)
	// Step-up ("sudo") assertion for the mutations above.
	r.Post("/security/stepup/begin", s.securityStepUpBegin)
	r.Post("/security/stepup/finish", s.securityStepUpFinish)
	r.Post("/security/stepup/totp", s.securityStepUpTOTP)
}

func (s *Server) mountNotificationsRoutes(r chi.Router) {
	if s.Journal == nil {
		return
	}
	r.Get("/notifications", s.notifications)
	r.Post("/notifications", s.notificationsCreate)
	r.Post("/notifications/{id}/delete", s.notificationsDelete)
	r.Post("/notifications/{id}/test", s.notificationsTest)
	r.Post("/workflows/{slug}/notifications", s.workflowNotificationRouteCreate)
	r.Post("/workflows/{slug}/notifications/{channel_id}/delete", s.workflowNotificationRouteDelete)
}

// mountMiddleware wires the security middleware stack in the order
// every route depends on. Always-on (no capability gate).
func (s *Server) mountMiddleware(r chi.Router) {
	// Outermost on purpose: nothing else in this stack recovers panics,
	// so this must catch them from every layer below, report to Flare,
	// and render the 500 itself (it does not re-panic).
	r.Use(flarereport.FlareRecoverer)
	r.Use(SecurityHeaders)
	if s.RateLimit.Burst > 0 && s.RateLimit.Refill > 0 {
		r.Use(RateLimit(s.RateLimit.Burst, s.RateLimit.Refill))
	}
	// Session/API-token middleware runs BEFORE the legacy BasicAuth
	// gate so a session cookie or Bearer token short-circuits the
	// env-var path. When no users exist yet the middleware is a
	// no-op so the very first daemon boot still falls back to the
	// env-var BasicAuth (or fails closed per Pass A).
	if s.Auth != nil {
		r.Use(SessionAuth(SessionAuthConfig{
			Store:             sessionStoreAdapter{a: s.Auth},
			LegacyAllowNoAuth: s.BasicAuth.AllowNoAuth,
		}))
	}
	r.Use(BasicAuth(s.BasicAuth))
	r.Use(CSRF)
}

// mountReadRoutes registers the always-present read surfaces:
// healthz, metrics, home, runs list/detail, credentials list/detail,
// workflow detail, assets, onboarding. None gated by a capability;
// every route uses the journal so a daemon spawned without one would
// have crashed earlier. Tests that care only about a subset can mount
// the helpers they need rather than calling full Mount.
func (s *Server) mountReadRoutes(r chi.Router) {
	r.Get("/healthz", s.healthz)
	r.Get("/metrics", s.metrics)
	r.Get("/", s.home)
	r.Get("/onboarding", s.onboarding)
	r.Get("/assets/*", s.assets)
	r.Get("/runs", s.runs)
	r.Get("/runs/{id}", s.runDetail)
	r.Get("/runs/{id}/tail", s.runTail)
	r.Get("/runs/{id}/status", s.runStatus)
	r.Get("/errors", s.errorsPage)
	r.Get("/credentials", s.credentials)
	r.Get("/credentials/{id}", s.credentialDetail)
	r.Get("/workflows/{slug}", s.workflowDetail)
}

func (s *Server) mountVaultRoutes(r chi.Router) {
	if s.Vault == nil {
		return
	}
	r.Get("/credentials/new", s.credentialNewForm)
	r.Post("/credentials", s.credentialCreate)
}

// mountCredentialOpRoutes covers Rotate + Grant + Revoke + manual
// value update. Each has a different capability dependency so the
// gates split intentionally.
func (s *Server) mountCredentialOpRoutes(r chi.Router) {
	if s.Rotator != nil {
		r.Post("/credentials/{id}/rotate", s.credentialRotate)
	}
	if s.Journal != nil {
		r.Post("/credentials/{id}/grants", s.credentialGrant)
		r.Post("/credentials/{id}/grants/{workflow_id}/revoke", s.credentialRevoke)
	}
	if s.Vault != nil && s.Credentials != nil {
		r.Post("/credentials/{id}/value", s.credentialUpdateValue)
	}
	if s.Credentials != nil {
		r.Post("/credentials/{id}/delete", s.credentialDelete)
	}
	if s.Credentials != nil {
		// Rotation delivery targets. Without these routes rotation_targets was
		// settable only by hand-written SQL, so every credential had none and a
		// rotated value was stored but delivered nowhere.
		r.Post("/credentials/{id}/targets", s.credentialTargetAdd)
		r.Post("/credentials/{id}/targets/{index}/delete", s.credentialTargetDelete)
	}
}

func (s *Server) mountWorkflowEditRoutes(r chi.Router) {
	if s.WorkflowsRoot == "" {
		return
	}
	r.Post("/workflows/{slug}/code", s.workflowSaveCode)
	r.Post("/workflows/{slug}/dag", s.workflowSaveDAG)
	// Code-aware node editor: fetch / save one step's source for the drawer.
	r.Get("/workflows/{slug}/node/{step}/code", s.workflowNodeCode)
	r.Post("/workflows/{slug}/node/{step}/code", s.workflowSaveNodeCode)
}

func (s *Server) mountTriggerWriteRoutes(r chi.Router) {
	if s.Journal == nil {
		return
	}
	// Chain + cron trigger creation only needs the journal; the
	// per-kind handler returns 503 when Vault is nil and the operator
	// picks kind=webhook (which needs vault for the HMAC secret).
	// Management routes (delete/pause/resume/edit) likewise only need
	// the journal.
	r.Post("/workflows/{slug}/triggers", s.workflowCreateTrigger)
	r.Post("/workflows/{slug}/triggers/{trigger_id}/delete", s.workflowDeleteTrigger)
	r.Post("/workflows/{slug}/triggers/{trigger_id}/pause", s.triggerPause)
	r.Post("/workflows/{slug}/triggers/{trigger_id}/resume", s.triggerResume)
	r.Post("/workflows/{slug}/triggers/{trigger_id}/edit", s.triggerEditCron)
}

func (s *Server) mountWorkflowLifecycleRoutes(r chi.Router) {
	if s.Journal == nil {
		return
	}
	r.Post("/workflows/{slug}/enable", s.workflowEnable)
	r.Post("/workflows/{slug}/disable", s.workflowDisable)
	r.Post("/workflows/{slug}/delete", s.workflowDelete)
	r.Post("/workflows/{slug}/minutes-saved", s.workflowSetMinutesSaved)
	r.Post("/workflows/{slug}/rate-limit", s.workflowSetRateLimit)
}

func (s *Server) mountManualDispatchRoute(r chi.Router) {
	if s.ManualDispatch == nil {
		return
	}
	r.Post("/workflows/{slug}/run", s.workflowRun)
}

func (s *Server) mountRunCancelRoute(r chi.Router) {
	if s.RunCanceller == nil {
		return
	}
	r.Post("/runs/{id}/cancel", s.runCancel)
}

func (s *Server) mountKnowledgeRoutes(r chi.Router) {
	if s.Knowledge == nil {
		return
	}
	r.Get("/knowledge", s.knowledge)
	r.Get("/knowledge/{id}", s.knowledgeDetail)
}

func (s *Server) mountGraphRoute(r chi.Router) {
	if s.Graph == nil {
		return
	}
	r.Get("/graph.json", s.graphJSON)
}

func (s *Server) mountGenerateRoute(r chi.Router) {
	if s.Generator == nil {
		return
	}
	r.Post("/generate", s.generateWorkflow)
}

func (s *Server) mountMCPRoute(r chi.Router) {
	if s.MCPHandler == nil {
		return
	}
	r.Handle("/mcp", s.MCPHandler)
}

func (s *Server) mountDLQRoute(r chi.Router) {
	if s.DLQRetry == nil {
		return
	}
	r.Post("/dlq/{id}/retry", s.dlqRetry)
}

func (s *Server) mountKnowledgeWriteRoutes(r chi.Router) {
	if s.KnowledgeWrite == nil {
		return
	}
	r.Get("/knowledge/new", s.knowledgeNewForm)
	r.Post("/knowledge", s.knowledgeCreate)
	r.Post("/knowledge/{id}/promote", s.knowledgePromote)
	r.Post("/knowledge/{id}/stale", s.knowledgeStale)
	r.Post("/knowledge/{id}/supersede", s.knowledgeSupersede)
}

func (s *Server) mountWorkflowUploadRoutes(r chi.Router) {
	if s.WorkflowRegister == nil {
		return
	}
	r.Get("/workflows/new", s.workflowNewForm)
	r.Post("/workflows", s.workflowCreate)
}

func (s *Server) mountAuditRoute(r chi.Router) {
	if s.Journal == nil || s.Credentials == nil {
		return
	}
	r.Get("/audit", s.globalAudit)
}

func (s *Server) mountWebhookRoutes(r chi.Router) {
	if s.Webhook == nil {
		return
	}
	s.Webhook.Mount(r)
}

// healthz returns a tiny JSON liveness response. Includes the version
// so an operator can confirm which build is running.
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":      true,
		"version": s.Version,
	})
}

// home shows the operator's headline rollup (runs counted, time saved,
// duration), the workflow list, and the 20 most recent runs in one
// page. On first boot (no workflows registered yet) auto-redirects to
// /onboarding so a fresh `docker run reactor` lands on the welcome
// flow before the dashboard surfaces zeros across the board.
// viewerScope returns the tenant a request's viewer is restricted to for the
// read views, or "" when they see everything. Admins and unauthenticated
// (no-auth / first-boot) viewers are global; members are scoped to their own
// tenant. This is the dashboard's tenant-isolation boundary.
func viewerScope(r *http.Request) string {
	u, ok := UserFromContext(r.Context())
	if !ok || u.IsAdmin() {
		return ""
	}
	return u.TenantID
}

// runInScope reports whether the request's viewer may act on runID. Global
// viewers always may; members only on their own tenant's runs. A missing run
// is out of scope.
func (s *Server) runInScope(r *http.Request, runID string) bool {
	scope := viewerScope(r)
	if scope == "" {
		return true
	}
	info, err := s.Journal.GetRun(r.Context(), runID)
	return err == nil && info.TenantID == scope
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	scope := viewerScope(r)
	var (
		wfs []journal.Workflow
		err error
	)
	if scope != "" {
		wfs, err = s.Journal.ListWorkflowsByTenant(ctx, scope)
	} else {
		wfs, err = s.Journal.ListWorkflows(ctx)
	}
	if err != nil {
		s.errorPage(w, "list workflows", err)
		return
	}
	// Only the global first-boot (no workflows anywhere) goes to onboarding; a
	// scoped member with none just sees an empty home.
	if len(wfs) == 0 && scope == "" {
		http.Redirect(w, r, "/onboarding", http.StatusSeeOther)
		return
	}
	var runs []journal.RunInfo
	if scope != "" {
		runs, err = s.Journal.ListRuns(ctx, journal.RunFilter{TenantID: scope, Limit: 20})
	} else {
		runs, err = s.Journal.ListRecentRuns(ctx, 20)
	}
	if err != nil {
		s.errorPage(w, "list runs", err)
		return
	}
	// Estate-wide analytics (aggregate counts + a per-workflow table that names
	// other tenants' slugs) are NOT tenant-scoped, so only compute them for
	// global viewers (admins). A member gets a zero strip rather than a
	// cross-tenant metadata leak. (Per-tenant analytics is a product follow-up.)
	var analytics journal.Analytics
	if viewerScope(r) == "" {
		var aErr error
		if analytics, aErr = s.cachedAnalytics(ctx); aErr != nil {
			// Don't fail the page if analytics can't be computed (e.g. a
			// transient sqlite write contention). Log + render with zeros
			// so the operator still sees workflows + recent runs.
			s.Log.Warn("home: analytics summary failed", "err", aErr)
		}
	}
	available, _ := s.Registry.List()
	availableSet := map[string]bool{}
	for _, slug := range available {
		availableSet[slug] = true
	}

	// Distributed-mode fleet: count workers heartbeating in the last 30s.
	// Returns 0 in local mode (no workers register), so the fleet line
	// stays hidden there.
	workerCount, workerCap, _ := s.Journal.WorkerCapacity(ctx, 30*time.Second)

	s.renderPage(w, r, page{
		Title:   "Reactor",
		Heading: "Reactor",
		Body: template.HTML(homeBody(homeData{
			ShowTenant:       scope == "",
			Workflows:        wfs,
			Available:        availableSet,
			Runs:             runs,
			GeneratorEnabled: s.Generator != nil,
			Analytics:        analytics,
			WorkerCount:      workerCount,
			WorkerCapacity:   workerCap,
		})),
	})
}

// runs lists runs with optional workflow_id + status filters and
// limit/offset paging. Defaults: limit=50, offset=0. Limit clamped to
// [1, 200] so a curious operator can't drag the daemon down with
// limit=999999.
func (s *Server) runs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	filter := journal.RunFilter{
		WorkflowID: strings.TrimSpace(q.Get("workflow_id")),
		TenantID:   viewerScope(r), // "" for admins (global), else the member's tenant
		Status:     strings.TrimSpace(q.Get("status")),
		Limit:      parseIntDefault(q.Get("limit"), 50),
		Offset:     parseIntDefault(q.Get("offset"), 0),
	}
	if filter.Limit < 1 {
		filter.Limit = 1
	}
	if filter.Limit > 200 {
		filter.Limit = 200
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	runs, err := s.Journal.ListRuns(ctx, filter)
	if err != nil {
		s.errorPage(w, "list runs", err)
		return
	}
	total, err := s.Journal.CountRuns(ctx, filter)
	if err != nil {
		s.errorPage(w, "count runs", err)
		return
	}
	var wfs []journal.Workflow
	if filter.TenantID != "" {
		wfs, err = s.Journal.ListWorkflowsByTenant(ctx, filter.TenantID)
	} else {
		wfs, err = s.Journal.ListWorkflows(ctx)
	}
	if err != nil {
		s.errorPage(w, "list workflows", err)
		return
	}
	s.renderPage(w, r, page{
		Title:   "Runs",
		Heading: "Runs",
		Body:    template.HTML(runsListBody(runs, wfs, filter, total)),
	})
}

// runDetail shows a run's metadata + step timeline.
func (s *Server) runDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	info, err := s.Journal.GetRun(r.Context(), id)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			http.Error(w, "run not found", http.StatusNotFound)
			return
		}
		s.errorPage(w, "get run", err)
		return
	}
	// Tenant isolation: a member may not view another tenant's run. 404 (not
	// 403) so the run's existence isn't leaked.
	if scope := viewerScope(r); scope != "" && info.TenantID != scope {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	steps, err := s.Journal.ListSteps(r.Context(), id)
	if err != nil {
		s.errorPage(w, "list steps", err)
		return
	}
	// Find any open DLQ row so the page can render a Retry button.
	dlqID := ""
	if info.Status == "failed_dlq" && s.DLQRetry != nil {
		if item, ferr := s.Journal.FindDeadLetterByRun(r.Context(), id); ferr == nil {
			dlqID = item.ID
		}
	}
	// Logs: prefer the live in-memory ring; fall back to the persisted
	// rows once the ring has expired (e.g. reading a run from last night).
	var logs []string
	if s.LogBuffer != nil {
		logs = s.LogBuffer.Snapshot(id)
	}
	if len(logs) == 0 {
		logs, _ = s.Journal.GetRunLogs(r.Context(), id)
	}
	canCancel := s.RunCanceller != nil && (info.Status == "running" || info.Status == "suspended")
	// Flow diagram: overlay the run's per-step status + output on the workflow
	// DAG. Best-effort -- a missing/unparseable DAG just omits the diagram.
	flow := ""
	if dag, dErr := s.Journal.WorkflowDAG(r.Context(), info.WorkflowID); dErr == nil {
		flow = runFlowDiagram(dag, steps)
	}
	s.renderPage(w, r, page{
		Title:   "Run " + info.ID,
		Heading: "Run " + info.ID,
		Body:    template.HTML(runDetailBody(info, steps, flow, dlqID, logs, canCancel)),
	})
}

// runStatus serves GET /runs/{id}/status as JSON for the live page's finalize
// poll: it reports the current status + whether the run reached a terminal
// state, so the client knows when to stop streaming and re-render the final
// timeline.
func (s *Server) runStatus(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	info, err := s.Journal.GetRun(r.Context(), id)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			http.Error(w, "run not found", http.StatusNotFound)
			return
		}
		s.errorPage(w, "get run", err)
		return
	}
	if scope := viewerScope(r); scope != "" && info.TenantID != scope {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":   info.Status,
		"terminal": isTerminalStatus(info.Status),
	})
}

// isTerminalStatus reports whether a run has finished (no further updates).
func isTerminalStatus(status string) bool {
	switch status {
	case "succeeded", "failed", "failed_dlq", "cancelled":
		return true
	}
	return false
}

// credentials shows the vault list with rotation state.
func (s *Server) credentials(w http.ResponseWriter, r *http.Request) {
	creds, err := s.Credentials.List(r.Context())
	if err != nil {
		s.errorPage(w, "list credentials", err)
		return
	}
	// Tenant isolation: members see only their own tenant's credentials
	// (names/services/rotation state are sensitive metadata); admins see all.
	if scope := viewerScope(r); scope != "" {
		filtered := creds[:0]
		for _, c := range creds {
			if c.TenantID == scope {
				filtered = append(filtered, c)
			}
		}
		creds = filtered
	}
	grantCounts := s.grantCountsByCredential(r.Context())
	s.renderPage(w, r, page{
		Title:   "Credentials",
		Heading: "Credentials",
		Body:    template.HTML(credentialsBody(creds, grantCounts)),
	})
}

// credentialDetail shows one credential's audit log.
func (s *Server) credentialDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	c, err := s.Credentials.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, credentials.ErrNotFound) {
			http.Error(w, "credential not found", http.StatusNotFound)
			return
		}
		s.errorPage(w, "get credential", err)
		return
	}
	// Tenant isolation: a member may only view their own tenant's credential.
	if scope := viewerScope(r); scope != "" && c.TenantID != scope {
		http.Error(w, "credential not found", http.StatusNotFound)
		return
	}
	rows, _ := s.Credentials.ListAudit(r.Context(), id, 100)
	grantedWorkflows := s.workflowsGrantedAccess(r.Context(), id)
	var flash string
	if s.flash != nil {
		flash = s.flash.take(w, r)["rotate_outcome"]
	}
	hint, mintsLocally := s.rotateHint(c.Provider)
	s.renderPage(w, r, page{
		Title:   "Credential " + c.Name,
		Heading: "Credential " + c.Name,
		Body: template.HTML(credentialDetailBody(c, rows, grantedWorkflows, flash,
			rotateView{hint: hint, mintsLocally: mintsLocally})),
	})
}

// rotateHint states what "Rotate now" will actually do for this provider, so the
// effect is legible BEFORE the click rather than only in the audit trail after.
func (s *Server) rotateHint(provider string) (hint string, mintsLocally bool) {
	if s.Rotator == nil {
		return "rotation is not wired in this build.", false
	}
	canAuto, mintsLocal, err := s.Rotator.ProviderCapabilities(provider)
	switch {
	case err != nil:
		return "unknown provider: rotation will fail.", false
	case !canAuto:
		return "records a reminder only: this provider cannot roll the credential, so the stored value will NOT change.", false
	case mintsLocal:
		return "generates a NEW RANDOM secret and replaces the stored value; correct only for a secret Reactor itself issues.", true
	default:
		return "rolls the credential at its source, stores the new value, then delivers it to each rotation target.", false
	}
}

// grantCountsByCredential returns credential_id -> number of workflows
// granted access. Empty map on journal error so the page still renders
// (operators see zeros rather than an error wall).
func (s *Server) grantCountsByCredential(ctx context.Context) map[string]int {
	if s.Journal == nil {
		return nil
	}
	grants, err := s.Journal.ListGrants(ctx)
	if err != nil {
		s.Log.Warn("server: grant count lookup failed", "err", err)
		return nil
	}
	out := make(map[string]int, len(grants))
	for _, g := range grants {
		out[g.CredentialID]++
	}
	return out
}

// workflowsGrantedAccess returns the workflow slugs (preferred) or ids
// (fallback) granted access to the given credential. Slugs are friendlier
// in the dashboard than opaque ids.
func (s *Server) workflowsGrantedAccess(ctx context.Context, credentialID string) []string {
	if s.Journal == nil {
		return nil
	}
	grants, err := s.Journal.ListGrants(ctx)
	if err != nil {
		return nil
	}
	var out []string
	for _, g := range grants {
		if g.CredentialID != credentialID {
			continue
		}
		slug, err := s.Journal.WorkflowSlugByID(ctx, g.WorkflowID)
		if err != nil || slug == "" {
			out = append(out, g.WorkflowID)
		} else {
			out = append(out, slug)
		}
	}
	return out
}

func (s *Server) errorPage(w http.ResponseWriter, op string, err error) {
	// Log the full detail server-side; show the browser only the stable
	// operation label, never the raw err.Error() (which can leak SQL
	// fragments, file paths, or internal addresses).
	s.Log.Error("server: handler error", "op", op, "err", err)
	w.WriteHeader(http.StatusInternalServerError)
	render(w, layout, page{
		Title:   "Error",
		Heading: "Error",
		Body: template.HTML(`<p class="err">Something went wrong while handling: ` +
			template.HTMLEscapeString(op) +
			`. The details were logged server-side.</p>`),
	})
}

// Page shell + base CSS + render() now live in render.go.

type homeData struct {
	// ShowTenant is set when the viewer can see more than one tenant (an admin).
	// Slugs are unique only PER TENANT, so a bare /workflows/<slug> link is
	// ambiguous for them and one tenant's workflow would be unreachable; the
	// links carry ?tenant= so clicking through lands on the row you clicked.
	ShowTenant       bool
	Workflows        []journal.Workflow
	Available        map[string]bool
	Runs             []journal.RunInfo
	GeneratorEnabled bool
	Analytics        journal.Analytics
	WorkerCount      int
	WorkerCapacity   int
}

func homeBody(d homeData) string {
	var b strings.Builder
	// Fleet line: shown only in distributed mode (i.e. when workers have
	// registered a heartbeat). Lets a non-developer see the queue draining
	// + how many workers are running, no CLI required.
	if d.WorkerCount > 0 {
		fmt.Fprintf(&b, `<p class="muted">Fleet: <strong>%d</strong> worker(s) active, %d total concurrency, <strong>%d</strong> run(s) queued.</p>`,
			d.WorkerCount, d.WorkerCapacity, d.Analytics.RunsByStatus["queued"])
	}
	b.WriteString(renderAnalyticsStrip(d.Analytics))
	b.WriteString(`<h2>Author a workflow</h2>`)
	b.WriteString(`<p>Reactor's builder is your AI coding client. Ask <strong>Claude Code</strong> or <strong>Codex</strong> (connected over MCP with <code>--allow-write</code>) something like "build a Reactor workflow that emails a welcome message when a webhook fires" and it writes + registers the Go. New here? See the <a href="/onboarding">setup walkthrough</a> (2 commands).</p>`)
	if d.GeneratorEnabled {
		b.WriteString(`<h3>Or generate it here (optional)</h3>`)
		b.WriteString(`<form method="POST" action="/generate" class="form">
  <label>Brief
    <textarea name="brief" rows="5" required placeholder="Describe in plain English what the workflow should do. Reference credentials by name (e.g. crm-api-key) so the generated code can vault.MustGet() them at run time."></textarea>
  </label>
  <p class="muted">Claude reads your environment lens (services, credential metadata, knowledge corpus) and emits a workflow.go + dag.json. The orchestrator then runs go vet + reactor lint + go build with retries, commits to git, builds the binary, and registers it. Synchronous; usually 15-45s.</p>
  <button type="submit" class="btn-primary">Generate</button>
</form>`)
	}
	b.WriteString(`<h2>Workflows</h2>`)
	b.WriteString(`<p><a href="/workflows/new" class="btn-secondary">Upload workflow (tar.gz)</a></p>`)
	if len(d.Workflows) == 0 {
		b.WriteString(`<p class="empty">No workflows yet. Ask your connected AI client (Claude Code / Codex) to build one over MCP, scaffold with <code>reactor new</code>, or upload a tarball.</p>`)
	} else {
		if d.ShowTenant {
			b.WriteString(`<table><thead><tr><th>Slug</th><th>Tenant</th><th>ID</th><th>SDK</th><th>Binary</th><th>Updated</th><th></th></tr></thead><tbody>`)
		} else {
			b.WriteString(`<table><thead><tr><th>Slug</th><th>ID</th><th>SDK</th><th>Binary</th><th>Updated</th><th></th></tr></thead><tbody>`)
		}
		for _, w := range d.Workflows {
			binStatus := `<span class="warn">missing</span>`
			if d.Available[w.Slug] {
				binStatus = `<span class="tag tag-on">deployed</span>`
			}
			runBtn := ""
			if d.Available[w.Slug] {
				runBtn = fmt.Sprintf(`<form method="POST" action="/workflows/%s/run" class="form-inline"><button type="submit" class="btn-link">run now</button></form>`,
					template.URLQueryEscaper(w.Slug))
			}
			// ?tenant= only for a viewer who can see several tenants; a member's
			// own scope already resolves the slug unambiguously.
			href := "/workflows/" + template.URLQueryEscaper(w.Slug)
			tenantCell := ""
			if d.ShowTenant {
				href += "?tenant=" + template.URLQueryEscaper(w.TenantID)
				tenantCell = fmt.Sprintf(`<td><code>%s</code></td>`, template.HTMLEscapeString(w.TenantID))
			}
			fmt.Fprintf(&b, `<tr><td><a href="%s"><code>%s</code></a></td>%s<td><code>%s</code></td><td>%s</td><td>%s</td><td class="muted">%s</td><td>%s</td></tr>`,
				href, template.HTMLEscapeString(w.Slug), tenantCell,
				template.HTMLEscapeString(w.ID), template.HTMLEscapeString(w.SDKVersion), binStatus, formatTime(w.UpdatedAt), runBtn)
		}
		b.WriteString(`</tbody></table>`)
	}
	b.WriteString(`<h2>Recent runs</h2>`)
	b.WriteString(runsTable(d.Runs))
	return b.String()
}

// runsListBody renders the /runs page with workflow + status filters
// and prev/next paging.
func runsListBody(runs []journal.RunInfo, wfs []journal.Workflow, f journal.RunFilter, total int) string {
	var b strings.Builder
	b.WriteString(`<form method="get" action="/runs" class="filters">`)
	b.WriteString(`<label>Workflow <select name="workflow_id"><option value="">all</option>`)
	for _, w := range wfs {
		sel := ""
		if w.ID == f.WorkflowID {
			sel = ` selected`
		}
		fmt.Fprintf(&b, `<option value="%s"%s>%s</option>`,
			template.HTMLEscapeString(w.ID), sel, template.HTMLEscapeString(w.Slug))
	}
	b.WriteString(`</select></label>`)
	b.WriteString(`<label>Status <select name="status"><option value="">any</option>`)
	for _, st := range []string{"queued", "running", "succeeded", "failed", "failed_dlq", "suspended", "cancelled"} {
		sel := ""
		if st == f.Status {
			sel = ` selected`
		}
		fmt.Fprintf(&b, `<option value="%s"%s>%s</option>`, st, sel, st)
	}
	b.WriteString(`</select></label>`)
	fmt.Fprintf(&b, `<label>Per page <input type="number" name="limit" min="1" max="200" value="%d"></label>`, f.Limit)
	b.WriteString(`<button type="submit">Apply</button> <a href="/runs" class="muted">Reset</a></form>`)

	fmt.Fprintf(&b, `<p class="muted">%d run(s) match. Showing %d-%d.</p>`,
		total, minInt(f.Offset+1, total), minInt(f.Offset+len(runs), total))
	b.WriteString(runsTable(runs))

	prevOffset := f.Offset - f.Limit
	if prevOffset < 0 {
		prevOffset = 0
	}
	hasPrev := f.Offset > 0
	hasNext := f.Offset+len(runs) < total
	b.WriteString(`<p class="pager">`)
	if hasPrev {
		fmt.Fprintf(&b, `<a href="%s">&larr; Prev</a> `, runsURL(f, prevOffset))
	}
	if hasNext {
		fmt.Fprintf(&b, `<a href="%s">Next &rarr;</a>`, runsURL(f, f.Offset+f.Limit))
	}
	b.WriteString(`</p>`)
	return b.String()
}

// runsURL rebuilds the /runs query string with a new offset, preserving
// the active filters.
func runsURL(f journal.RunFilter, offset int) string {
	v := url.Values{}
	if f.WorkflowID != "" {
		v.Set("workflow_id", f.WorkflowID)
	}
	if f.Status != "" {
		v.Set("status", f.Status)
	}
	v.Set("limit", strconv.Itoa(f.Limit))
	v.Set("offset", strconv.Itoa(offset))
	return "/runs?" + v.Encode()
}

func parseIntDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func runsTable(runs []journal.RunInfo) string {
	if len(runs) == 0 {
		return `<p class="empty">No runs yet. Fire one via the "Run now" button on a workflow row above, or set up a webhook / cron trigger on the workflow detail page.</p>`
	}
	var b strings.Builder
	b.WriteString(`<table><thead><tr><th>Run</th><th>Workflow</th><th>Trigger</th><th>Status</th><th>Started</th><th>Finished</th></tr></thead><tbody>`)
	for _, r := range runs {
		fmt.Fprintf(&b, `<tr><td><a href="/runs/%s"><code>%s</code></a></td><td><code>%s</code></td><td>%s</td><td><span class="tag tag-%s">%s</span></td><td class="muted">%s</td><td class="muted">%s</td></tr>`,
			template.URLQueryEscaper(r.ID), template.HTMLEscapeString(r.ID),
			template.HTMLEscapeString(r.WorkflowID),
			template.HTMLEscapeString(r.TriggerKind),
			template.HTMLEscapeString(r.Status), template.HTMLEscapeString(r.Status),
			formatTime(r.StartedAt), formatTime(r.FinishedAt))
	}
	b.WriteString(`</tbody></table>`)
	return b.String()
}

func runDetailBody(info journal.RunInfo, steps []journal.StepRow, flow, dlqID string, logs []string, canCancel bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<table><tr><th>Workflow</th><td><code>%s</code></td></tr>`, template.HTMLEscapeString(info.WorkflowID))
	fmt.Fprintf(&b, `<tr><th>Trigger</th><td>%s</td></tr>`, template.HTMLEscapeString(info.TriggerKind))
	fmt.Fprintf(&b, `<tr><th>Status</th><td><span class="tag tag-%s">%s</span></td></tr>`,
		template.HTMLEscapeString(info.Status), template.HTMLEscapeString(info.Status))
	fmt.Fprintf(&b, `<tr><th>Started</th><td>%s</td></tr>`, formatTime(info.StartedAt))
	fmt.Fprintf(&b, `<tr><th>Finished</th><td>%s</td></tr>`, formatTime(info.FinishedAt))
	b.WriteString(`</table>`)

	// Cancel: shown only while the run is still running or suspended.
	if canCancel {
		fmt.Fprintf(&b, `<form method="POST" action="/runs/%s/cancel" class="form-inline" data-confirm="Cancel this run? A running step is killed; a suspended run will not resume.">
  <button type="submit" class="btn-link">Cancel run</button>
</form>`, template.URLQueryEscaper(info.ID))
	}

	if dlqID != "" {
		fmt.Fprintf(&b, `<h2>Dead-letter</h2>
<form method="POST" action="/dlq/%s/retry" class="form-inline">
  <p class="muted">This run terminated in failed_dlq. Retrying re-spawns the supervisor with the original RunID; the journal cache short-circuits every previously-succeeded step so only the failed step re-runs.</p>
  <button type="submit" class="btn-primary">Retry from DLQ</button>
</form>`, template.URLQueryEscaper(dlqID))
	}

	// Flow diagram (how it ran + where the data ended up), when a DAG exists.
	if flow != "" {
		b.WriteString(flow)
	}

	b.WriteString(`<h2>Steps</h2>`)
	if len(steps) == 0 {
		b.WriteString(`<p class="empty">No steps recorded.</p>`)
	} else {
		b.WriteString(`<table><thead><tr><th>Step</th><th>Attempt</th><th>Status</th><th>Duration</th><th>Output / Error</th></tr></thead><tbody>`)
		for _, s := range steps {
			dur := ""
			if !s.StartedAt.IsZero() && !s.FinishedAt.IsZero() {
				dur = fmt.Sprintf("%dms", s.FinishedAt.Sub(s.StartedAt).Milliseconds())
			}
			detail := ""
			if s.ErrorText != "" {
				detail = `<span class="err">` + template.HTMLEscapeString(truncate(s.ErrorText, 240)) + `</span>`
			} else if len(s.OutputJSONB) > 0 && string(s.OutputJSONB) != "null" {
				detail = `<details><summary>output_jsonb</summary><pre>` +
					template.HTMLEscapeString(prettyJSON(string(s.OutputJSONB))) +
					`</pre></details>`
			}
			fmt.Fprintf(&b, `<tr><td><code>%s</code></td><td>%d</td><td><span class="tag tag-%s">%s</span></td><td class="muted">%s</td><td>%s</td></tr>`,
				template.HTMLEscapeString(s.StepName), s.Attempt,
				template.HTMLEscapeString(s.Status), template.HTMLEscapeString(s.Status),
				dur, detail)
		}
		b.WriteString(`</tbody></table>`)
	}

	// Logs: while the run is live, an empty pane that run-live.js fills over SSE
	// (the stream replays the buffer first, so history + tail both appear);
	// once terminal, the persisted lines render statically.
	live := !isTerminalStatus(info.Status)
	fmt.Fprintf(&b, `<h2>Logs%s</h2>`, liveBadge(live))
	switch {
	case live:
		// Empty pane; the SSE snapshot replay + tail populate it.
		b.WriteString(`<pre id="run-log" class="runlog"></pre>`)
	case len(logs) == 0:
		b.WriteString(`<p class="empty">No logs recorded for this run.</p>`)
	default:
		b.WriteString(`<pre id="run-log" class="runlog">`)
		for _, line := range logs {
			b.WriteString(template.HTMLEscapeString(line))
			b.WriteString("\n")
		}
		b.WriteString(`</pre>`)
	}

	// Live driver: streams logs + polls status to finalize. Marker carries the
	// run id + status so run-live.js knows whether to stream. No-op when the
	// run is already terminal.
	fmt.Fprintf(&b, `<div id="run-live" data-run-id="%s" data-status="%s" hidden></div>`,
		template.HTMLEscapeString(info.ID), template.HTMLEscapeString(info.Status))
	b.WriteString(`<script src="/assets/run-live.js"></script>`)
	return b.String()
}

// liveBadge renders a small pulsing "live" tag next to the Logs heading while
// a run is still executing.
func liveBadge(live bool) string {
	if !live {
		return ""
	}
	return ` <span class="live-dot" title="streaming live"></span>`
}

func credentialsBody(creds []credentials.Credential, grantCounts map[string]int) string {
	if len(creds) == 0 {
		return `<p class="empty">No credentials yet.</p><p><a href="/credentials/new" class="btn-primary">Add credential</a></p>`
	}
	var b strings.Builder
	b.WriteString(`<p><a href="/credentials/new" class="btn-primary">Add credential</a></p>`)
	b.WriteString(`<table><thead><tr><th>Name</th><th>Provider</th><th>Auto</th><th>Interval</th><th>Last rotated</th><th>Granted to</th><th>Error</th></tr></thead><tbody>`)
	for _, c := range creds {
		auto := `<span class="tag tag-off">off</span>`
		if c.AutoRotate {
			auto = `<span class="tag tag-on">on</span>`
		}
		errCell := ""
		if c.LastRotationError != "" {
			errCell = `<span class="err">` + template.HTMLEscapeString(truncate(c.LastRotationError, 80)) + `</span>`
		}
		grantCell := grantCountCell(grantCounts[c.ID])
		fmt.Fprintf(&b, `<tr><td><a href="/credentials/%s">%s</a></td><td>%s</td><td>%s</td><td>%dd</td><td class="muted">%s</td><td>%s</td><td>%s</td></tr>`,
			template.URLQueryEscaper(c.ID),
			template.HTMLEscapeString(c.Name),
			template.HTMLEscapeString(c.Provider),
			auto, c.RotationIntervalDays,
			formatTime(c.LastRotatedAt), grantCell, errCell)
	}
	b.WriteString(`</tbody></table>`)
	return b.String()
}

func grantCountCell(n int) string {
	switch {
	case n == 0:
		return `<span class="tag tag-warn" title="No workflow has been granted access. Run reactor vault grant to authorise one.">0 workflows</span>`
	case n == 1:
		return `<span class="tag tag-on">1 workflow</span>`
	default:
		return fmt.Sprintf(`<span class="tag tag-on">%d workflows</span>`, n)
	}
}

func grantedWorkflowsCell(slugs []string) string {
	if len(slugs) == 0 {
		return `<span class="tag tag-warn">none</span> <span class="muted">run <code>reactor vault grant</code> to authorise a workflow</span>`
	}
	parts := make([]string, 0, len(slugs))
	for _, s := range slugs {
		parts = append(parts, `<code>`+template.HTMLEscapeString(s)+`</code>`)
	}
	return strings.Join(parts, ", ")
}

// rotationTargetsSection renders where a rotated value gets delivered, and the
// form to add one. Rotation's differentiator is that consumers pick up the new
// value without a restart, and this was previously invisible AND unreachable:
// rotation_targets had no setter, no caller and no UI, so every credential had
// zero targets and rotation delivered nowhere while reporting success. An empty
// list now says so in as many words instead of rendering nothing at all.
func rotationTargetsSection(c credentials.Credential) string {
	var b strings.Builder
	b.WriteString(`<h2>Rotation delivery targets</h2>`)
	if len(c.RotationTargets) == 0 {
		b.WriteString(`<p class="notice">No delivery targets. A rotation will store the new value in the vault and deliver it nowhere, so anything already holding the old value keeps using it. Add a target below.</p>`)
	} else {
		b.WriteString(`<table><thead><tr><th>Kind</th><th>URL / path</th><th>Key name</th><th>Auth secret</th><th>Grace</th><th></th></tr></thead><tbody>`)
		for i, t := range c.RotationTargets {
			keyName := t.KeyName
			if keyName == "" {
				keyName = "-"
			}
			secretID := t.SecretID
			if secretID == "" {
				secretID = "-"
			}
			fmt.Fprintf(&b, `<tr><td><code>%s</code></td><td><code>%s</code></td><td><code>%s</code></td><td><code>%s</code></td><td>%ds</td><td>`+
				`<form method="POST" action="/credentials/%s/targets/%d/delete" class="form-inline" data-confirm="Remove this %s target? Future rotations will stop delivering to it.">`+
				`<button type="submit" class="btn-link">remove</button></form></td></tr>`,
				template.HTMLEscapeString(t.Kind), template.HTMLEscapeString(t.URL),
				template.HTMLEscapeString(keyName), template.HTMLEscapeString(secretID),
				t.GraceSeconds, template.URLQueryEscaper(c.ID), i, template.HTMLEscapeString(t.Kind))
		}
		b.WriteString(`</tbody></table>`)
		b.WriteString(`<p class="muted">Per-target delivery results are recorded in the audit trail below as <code>rotate.delivery_success</code> / <code>rotate.delivery_failure</code>.</p>`)
	}

	// One form covers every kind: the Target shape is uniform and only the
	// meaning of URL / key name changes, which the per-kind help text states.
	fmt.Fprintf(&b, `<form method="POST" action="/credentials/%s/targets" class="form">
  <label>Kind
    <select name="kind" required data-reveal-prefix="target-help-">`, template.URLQueryEscaper(c.ID))
	for _, k := range credentials.TargetKinds {
		fmt.Fprintf(&b, `<option value="%s">%s</option>`,
			template.HTMLEscapeString(k.Kind), template.HTMLEscapeString(k.Label))
	}
	b.WriteString(`</select>
  </label>`)
	for _, k := range credentials.TargetKinds {
		need := "URL required."
		if k.NeedsKeyName {
			need += " Key name required."
		}
		if k.NeedsSecretID {
			need += " Auth secret required."
		}
		fmt.Fprintf(&b, `<p id="target-help-%s" class="js-reveal-target muted" hidden>%s <strong>URL:</strong> %s%s</p>`,
			template.HTMLEscapeString(k.Kind), template.HTMLEscapeString(need),
			template.HTMLEscapeString(k.URLHint),
			keyNameHintHTML(k.KeyNameHint))
	}
	b.WriteString(`
  <label>URL / path <input type="text" name="url" required autocomplete="off" placeholder="see the note above for this kind"></label>
  <label>Key name <input type="text" name="key_name" autocomplete="off" placeholder="required for most kinds"></label>
  <label>Auth secret (vault credential id) <input type="text" name="secret_id" autocomplete="off" placeholder="cred_... holding the HMAC secret or API token for this target"></label>
  <label>Grace seconds <input type="number" name="grace_seconds" min="0" value="0"></label>
  <button type="submit">Add target</button>
</form>`)
	return b.String()
}

func keyNameHintHTML(hint string) string {
	if hint == "" {
		return ""
	}
	return " <strong>Key name:</strong> " + template.HTMLEscapeString(hint)
}

// rotateView carries the precomputed, provider-specific rotation copy so the
// body stays a pure renderer and the server package keeps its narrow-interface
// boundary to internal/rotators.
type rotateView struct {
	hint         string
	mintsLocally bool
}

func credentialDetailBody(c credentials.Credential, rows []credentials.AuditEntry, grantedWorkflows []string, flash string, rot rotateView) string {
	var b strings.Builder
	if flash != "" {
		fmt.Fprintf(&b, `<p class="notice">%s</p>`, template.HTMLEscapeString(flash))
	}
	fmt.Fprintf(&b, `<table>
<tr><th>ID</th><td><code>%s</code></td></tr>
<tr><th>Service</th><td>%s</td></tr>
<tr><th>Provider</th><td>%s</td></tr>
<tr><th>Auto rotate</th><td>%v</td></tr>
<tr><th>Interval</th><td>%d days</td></tr>
<tr><th>Last rotated</th><td>%s</td></tr>
<tr><th>Granted to</th><td>%s</td></tr>
<tr><th>Last error</th><td><span class="err">%s</span></td></tr>
</table>`,
		template.HTMLEscapeString(c.ID),
		template.HTMLEscapeString(c.Service),
		template.HTMLEscapeString(c.Provider),
		c.AutoRotate, c.RotationIntervalDays,
		formatTime(c.LastRotatedAt),
		grantedWorkflowsCell(grantedWorkflows),
		template.HTMLEscapeString(c.LastRotationError),
	)

	b.WriteString(rotationTargetsSection(c))

	b.WriteString(`<h2>Actions</h2>`)
	// A value-replacing provider (shared-secret) discards the stored secret and
	// generates a new random one. On an externally issued key that is
	// destruction, not rotation, and the primary-styled button used to fire with
	// no confirmation at all.
	rotateConfirm := ""
	if rot.mintsLocally {
		rotateConfirm = ` data-confirm="Provider ` + template.HTMLEscapeString(c.Provider) +
			` REPLACES the stored value with a NEW RANDOM secret. The current value is discarded and cannot be recovered. If this credential was issued by another service, that service keeps the old value and the integration will break. Continue?"`
	}
	fmt.Fprintf(&b, `<form method="POST" action="/credentials/%s/rotate" class="form-inline"%s>
  <button type="submit" class="btn-primary">Rotate now</button>
  <span class="muted">%s</span>
</form>`, template.URLQueryEscaper(c.ID), rotateConfirm, template.HTMLEscapeString(rot.hint))

	fmt.Fprintf(&b, `<form method="POST" action="/credentials/%s/delete" class="form-inline" data-confirm="Delete this credential? The secret is removed from the vault and cannot be recovered. The row is kept as a tombstone so the audit trail survives, and the name becomes reusable.">
  <button type="submit" class="btn-link">Delete credential</button>
  <span class="muted">refused while any workflow still holds a grant.</span>
</form>`, template.URLQueryEscaper(c.ID))

	fmt.Fprintf(&b, `<form id="manual-update" method="POST" action="/credentials/%s/value" class="form-inline" data-confirm="Overwrite the stored value? Any in-flight workflows holding the old value continue with it; new fetches see the new value.">
  <label>Manual update <input type="password" name="value" required placeholder="new plaintext, encrypted on write" autocomplete="new-password"></label>
  <button type="submit">Update value</button>
</form>
<p class="muted">Use when an operator has a new value from upstream (e.g. a new key from the provider's own dashboard). The provider's automatic rotation pipeline is bypassed; last_rotated_at still bumps so the schedule resets.</p>`,
		template.URLQueryEscaper(c.ID))

	b.WriteString(`<h2>Grants</h2>`)
	b.WriteString(`<p class="muted">Workflows authorised to read this credential at run time. Empty list under strict ACL = no workflow can fetch.</p>`)
	if len(grantedWorkflows) > 0 {
		b.WriteString(`<ul class="grant-list">`)
		for _, wf := range grantedWorkflows {
			fmt.Fprintf(&b, `<li><code>%s</code> <form method="POST" action="/credentials/%s/grants/%s/revoke" class="form-inline"><button type="submit" class="btn-link">revoke</button></form></li>`,
				template.HTMLEscapeString(wf),
				template.URLQueryEscaper(c.ID),
				template.URLQueryEscaper(wf),
			)
		}
		b.WriteString(`</ul>`)
	}
	fmt.Fprintf(&b, `<form method="POST" action="/credentials/%s/grants" class="form-inline">
  <label>Grant access to workflow <input type="text" name="workflow_id" placeholder="workflow slug or id" required autocomplete="off"></label>
  <button type="submit">Grant</button>
</form>`, template.URLQueryEscaper(c.ID))

	b.WriteString(`<h2>Audit log</h2>`)
	if len(rows) == 0 {
		b.WriteString(`<p class="empty">No audit entries.</p>`)
		return b.String()
	}
	b.WriteString(`<table><thead><tr><th>At</th><th>Action</th><th>Actor</th><th>Detail</th></tr></thead><tbody>`)
	for _, r := range rows {
		actor := r.ActorKind
		if r.ActorID != "" {
			actor += ":" + r.ActorID
		}
		fmt.Fprintf(&b, `<tr><td class="muted">%s</td><td><code>%s</code></td><td>%s</td><td><code>%s</code></td></tr>`,
			formatTime(r.At),
			template.HTMLEscapeString(r.Action),
			template.HTMLEscapeString(actor),
			template.HTMLEscapeString(truncate(string(r.Detail), 160)),
		)
	}
	b.WriteString(`</tbody></table>`)
	return b.String()
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04:05Z")
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// TLSConfig optionally turns the listener into HTTPS. Both fields
// must be set; either path empty disables TLS and the server uses
// plain HTTP. Production deploys mount cert + key from a secret
// manager (or a Caddy / Traefik sidecar) and pass them in here.
type TLSConfig struct {
	CertFile string
	KeyFile  string
}

// Run starts the HTTP(S) server and blocks until ctx is cancelled.
// The listener is closed gracefully via http.Server.Shutdown.
func (s *Server) Run(ctx context.Context, addr string) error {
	return s.RunWithTLS(ctx, addr, TLSConfig{})
}

// RunWithTLS is Run plus an optional TLS config. When tls.CertFile +
// tls.KeyFile are both set, the server boots over HTTPS via
// ListenAndServeTLS; otherwise it falls back to plain HTTP. The
// SecurityHeaders middleware notices r.TLS != nil and emits HSTS
// automatically, so flipping this flag is the only HTTPS change
// operators need to make.
func (s *Server) RunWithTLS(ctx context.Context, addr string, tls TLSConfig) error {
	router := chi.NewRouter()
	s.Mount(router)
	srv := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}
	useTLS := tls.CertFile != "" && tls.KeyFile != ""
	errCh := make(chan error, 1)
	go func() {
		scheme := "http"
		if useTLS {
			scheme = "https"
		}
		s.Log.Info("server: listening", "addr", addr, "scheme", scheme)
		var err error
		if useTLS {
			err = srv.ListenAndServeTLS(tls.CertFile, tls.KeyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// workflowIDForViewer resolves a slug from the URL to a workflow id WITHIN the
// viewer's tenant.
//
// Slugs are unique per tenant, not globally (UNIQUE (tenant_id, slug)), but the
// dashboard addresses workflows by slug. The unscoped WorkflowIDBySlug answers
// "WHERE slug = $1 ORDER BY created_at DESC LIMIT 1", so once two tenants owned
// the same slug it returned whichever registered it most recently. For a member
// that meant resolving to ANOTHER tenant's workflow, and while the scope check
// downstream then correctly returned 404, the member could no longer open a
// workflow they actually own: the newer tenant's row shadowed theirs permanently.
//
// viewerScope is "" for an admin, and WorkflowIDBySlugInTenant falls back to the
// unscoped lookup on an empty tenant, so admin behaviour is unchanged.
// An admin has no scope of their own, so for them a bare slug is genuinely
// ambiguous once two tenants own it: the unscoped lookup hands back whichever is
// newest and the other tenant's workflow becomes unreachable through the UI
// entirely. `?tenant=` lets them say which one they mean, and the workflow list
// links carry it (see workflowHref). A MEMBER's scope always wins, so the
// parameter can never be used to reach across a boundary.
func (s *Server) workflowIDForViewer(r *http.Request, slug string) (string, error) {
	scope := viewerScope(r)
	if scope == "" {
		scope = strings.TrimSpace(r.URL.Query().Get("tenant"))
	}
	return s.Journal.WorkflowIDBySlugInTenant(r.Context(), slug, scope)
}

// workflowHref builds the dashboard link for a workflow, disambiguating by tenant
// when the viewer can see more than one. Members get a bare path since their
// scope already pins the resolution.
func workflowHref(r *http.Request, slug, ownerTenant string) string {
	if viewerScope(r) != "" || ownerTenant == "" {
		return "/workflows/" + url.PathEscape(slug)
	}
	return "/workflows/" + url.PathEscape(slug) + "?tenant=" + url.QueryEscape(ownerTenant)
}
