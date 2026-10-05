// Package flarereport wires error reporting to the house Flare
// instance (Sentry wire protocol). Everything here is a no-op unless
// FLARE_DSN is set, so dev runs and self-hosts boot unchanged.
package flarereport

import (
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	sentry "github.com/getsentry/sentry-go"
)

// InitFlare wires error reporting to the house Flare instance (Sentry-wire
// protocol) when FLARE_DSN is set in the environment. The DSN is injected by
// the Hephaestus flare-provision deploy step; without it this is a no-op so
// dev runs and self-hosts boot unchanged.
func InitFlare(service, release string) bool {
	dsn := os.Getenv("FLARE_DSN")
	if dsn == "" {
		return false
	}
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              dsn,
		Release:          release,
		ServerName:       service,
		EnableTracing:    true,
		TracesSampleRate: tracesSampleRate(),
		BeforeSend:       scrubEvent,
		BeforeSendTransaction: func(e *sentry.Event, _ *sentry.EventHint) *sentry.Event {
			return scrubEvent(e, nil)
		},
	})
	if err != nil {
		slog.Warn("flare: error reporting disabled (sentry init failed)", "error", err)
		return false
	}
	slog.Info("flare: error reporting enabled", "service", service)
	startHeartbeat(service)
	installLogShipper(service)
	return true
}

// scrubEvent strips request and environment detail sentry-go attaches
// unconditionally, i.e. OUTSIDE its own SendDefaultPII guard. Without this the
// panic path exfiltrated live secrets:
//
//   - QueryString is set unconditionally (sentry-go interfaces.go), so any
//     panic during GET /oauth/callback?code=...&state=... shipped the live
//     OAuth authorization code to the Flare backend and into its issue UI.
//     Same exposure on /login?next=, /tenants?err=, /connections?err=.
//   - Referer is not on sentry's header denylist and routinely carries the full
//     previous URL, including any token in its query string.
//   - Modules attaches the full Go dependency graph with exact versions to
//     EVERY event, including the 2-minute liveness heartbeat, which is a
//     continuous version-inventory beacon rather than error reporting.
//
// A comment elsewhere in this package used to claim BeforeSend already scrubbed
// the event path. It did not exist; this is that function.
func scrubEvent(event *sentry.Event, _ *sentry.EventHint) *sentry.Event {
	if event == nil {
		return nil
	}
	event.Modules = nil
	if event.Request != nil {
		event.Request.QueryString = ""
		event.Request.Data = ""
		event.Request.Cookies = ""
		for key := range event.Request.Headers {
			// Header maps can come from sentry-go's canonical net/http path or
			// from an integration that supplied a plain map. Compare folded
			// names so lower-case "authorization" and "cookie" cannot bypass
			// the scrub just because they were not canonicalised first.
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "authorization", "proxy-authorization", "cookie", "set-cookie",
				"referer", "referrer", "x-api-key", "x-auth-token", "x-csrf-token",
				"x-forwarded-for", "x-real-ip":
				delete(event.Request.Headers, key)
			}
		}
		// The URL itself can carry a token in the path on a future route; keep
		// only scheme+host+path, never a fragment/query or userinfo. Parse
		// first so a URL such as https://user:pass@example/path cannot leak
		// credentials even though it has no query string.
		if parsed, err := url.Parse(event.Request.URL); err == nil {
			parsed.User = nil
			parsed.RawQuery = ""
			parsed.Fragment = ""
			event.Request.URL = parsed.String()
		} else if i := strings.IndexAny(event.Request.URL, "?#"); i >= 0 {
			event.Request.URL = event.Request.URL[:i]
		}
	}
	return event
}

// FlareRecoverer captures panics to Flare and renders a plain 500.
// Reactor mounts no other recovery middleware, so unlike the dockyard
// variant this one must NOT re-panic: with nothing above it a re-panic
// would reach net/http, which aborts the connection without a
// response. Mount it first so it wraps the whole chain. Safe to mount
// when InitFlare was a no-op: capture calls on an uninitialized hub do
// nothing.
func FlareRecoverer(next http.Handler) http.Handler {
	traced := flareTracer(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					// net/http's sentinel for deliberately aborting a
					// response; swallowing it would break handlers
					// that panic with it on purpose.
					panic(rec)
				}
				hub := sentry.CurrentHub().Clone()
				hub.Scope().SetRequest(r)
				hub.RecoverWithContext(r.Context(), rec)
				hub.Flush(2 * time.Second)
				slog.Error("http: panic recovered", "method", r.Method, "path", r.URL.Path, "panic", rec)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		traced.ServeHTTP(w, r)
	})
}

// CaptureErr reports a non-panic error to Flare. No-op when reporting is
// disabled. Use for errors that are handled but should page someone.
func CaptureErr(err error) {
	if err == nil {
		return
	}
	sentry.CaptureException(err)
}
