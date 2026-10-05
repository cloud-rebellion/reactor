package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// SecurityHeaders adds the response-header floor every public endpoint
// gets. CSP is intentionally tight (no inline scripts, no third-party
// origins) because the status pages are server-rendered Go html/template
// with one inline <style> block and no script tags. HSTS only fires
// when the request actually arrived over TLS so plain-HTTP demos don't
// pin browsers into broken state.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		// script-src 'self' allows the dashboard's embedded cytoscape +
		// init scripts under /assets/. Inline scripts are still blocked
		// (no 'unsafe-inline'); workflow detail passes DAG data via
		// a <script type="application/json"> island so no
		// inline-execution path is opened up.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"connect-src 'self'; "+
				"font-src 'self'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'none'")
		// HSTS only fires when the request actually arrived over TLS, OR
		// when X-Forwarded-Proto: https was set by an explicitly trusted
		// proxy peer (or loopback). Honoring XFP from arbitrary
		// sources lets any attacker pin a domain to HTTPS-only via a
		// plain-HTTP request, which can wedge a misconfigured site for
		// the entire max-age window (here: 2 years).
		if r.TLS != nil || (forwardedProto(r) == "https" && isTrustedProxyRequest(r)) {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// BasicAuthConfig configures the BasicAuth middleware.
type BasicAuthConfig struct {
	// User is the username an operator types into the browser prompt.
	User string

	// PasswordSHA256 is the SHA-256 hash of the password (hex-encoded).
	// Hashing avoids holding the plaintext in memory across the
	// middleware's lifetime + makes the env-var presentation safe
	// (operators paste the hash, not the password) once the daemon
	// runs in production.
	//
	// May also carry an argon2id PHC string (starts with $argon2id$);
	// the middleware sniffs the prefix and routes to the right verifier.
	// Argon2id is the recommended default; raw SHA-256 stays supported
	// for backwards compatibility with v0.x setups.
	PasswordSHA256 string

	// AllowNoAuth is the explicit opt-in to run the dashboard with no
	// authentication. When false (default) and User+PasswordSHA256 are
	// empty, BasicAuth refuses every request with 503; operators are
	// expected to either configure credentials or pass this flag (via
	// --insecure-no-auth on `reactor serve`) when they really mean it.
	AllowNoAuth bool

	// Realm shows up in the browser auth prompt.
	Realm string
}

// BasicAuth returns middleware that enforces HTTP Basic auth against
// the configured credentials. Comparison is constant-time on both
// fields so a wrong-username request takes the same time as a wrong-
// password request.
//
// When User + PasswordSHA256 are both empty, BasicAuth is a no-op and
// the middleware passes through. This lets `reactor serve` ship with
// auth opt-in (REACTOR_BASIC_AUTH_USER + REACTOR_BASIC_AUTH_PASSWORD_SHA256 env)
// without breaking the local-demo flow that doesn't set them.
//
// Skips auth on the routes that have their own auth gate:
//
//	POST /webhook/{token}    HMAC verified at the journal layer
//	POST /command-webhook/{token} dedicated command-plan HMAC + trigger fence
//	POST /signal/{token}     128-bit token capability
//	GET  /healthz            liveness probes need to be unauthenticated
//	GET  /readyz             readiness probes need to be unauthenticated
func BasicAuth(cfg BasicAuthConfig) func(http.Handler) http.Handler {
	credsMissing := cfg.User == "" || cfg.PasswordSHA256 == ""
	allowNoAuth := credsMissing && cfg.AllowNoAuth
	wantUser := []byte(cfg.User)
	verify := newPasswordVerifier(cfg.PasswordSHA256)
	realm := cfg.Realm
	if realm == "" {
		realm = "reactor"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isPublicRoute(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			// SessionAuth runs first in the chain (F3); if it already
			// resolved a user, skip the legacy BasicAuth gate entirely.
			if _, ok := UserFromContext(r.Context()); ok {
				next.ServeHTTP(w, r)
				return
			}
			if credsMissing {
				if allowNoAuth {
					next.ServeHTTP(w, r)
					return
				}
				// Fail closed. Operators who really want an unauth
				// dashboard set --insecure-no-auth on `reactor serve`,
				// which routes through AllowNoAuth=true above.
				http.Error(w,
					"dashboard is not configured with credentials; set REACTOR_BASIC_AUTH_USER + REACTOR_BASIC_AUTH_PASSWORD_SHA256, or pass --insecure-no-auth to allow unauthenticated access",
					http.StatusServiceUnavailable)
				return
			}
			user, pass, ok := r.BasicAuth()
			userOK := ok && subtle.ConstantTimeCompare([]byte(user), wantUser) == 1
			passOK := ok && verify(pass)
			if !userOK || !passOK {
				w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isPublicRoute(path string) bool {
	switch {
	case path == "/healthz":
		return true
	case path == "/readyz":
		return true
	case path == "/oauth/callback":
		// OAuth providers redirect the browser here without a Reactor
		// session. CompleteAuth authenticates the callback with the short-lived,
		// single-use state + PKCE verifier recorded when consent started; a
		// dashboard cookie is neither required nor reliable after a cross-site
		// provider round trip (and MCP consent may be started for a user who has
		// no dashboard session at all).
		return true
	case path == "/login":
		// Login is by definition reached without a session; exempt so
		// the BasicAuth fail-closed branch does not pre-empt the form.
		return true
	case strings.HasPrefix(path, "/webhook/"):
		return true
	case strings.HasPrefix(path, "/command-webhook/"):
		return true
	case strings.HasPrefix(path, "/signal/"):
		return true
	case strings.HasPrefix(path, "/assets/"):
		// CSS + cytoscape JS load on the login page too.
		return true
	case path == "/docs" || strings.HasPrefix(path, "/docs/"):
		// Docs are public so an operator on /login can still read
		// them while figuring out how to sign in.
		return true
	}
	return false
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	const hex = "0123456789abcdef"
	out := make([]byte, len(h)*2)
	for i, b := range h {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}
	return string(out)
}

// CSRF returns middleware that rejects state-changing requests whose
// Origin (or Referer, when Origin is absent) does not match the
// dashboard's own origin. Single-origin server-rendered dashboards
// don't need per-form tokens; an Origin gate gives equivalent
// protection against CSRF without threading state through every
// template render.
//
// Modern browsers attach Origin to every cross-site fetch/form POST
// by default, and SameSite=Lax cookie default already blocks third-
// party-initiated POSTs from carrying BasicAuth. The Origin check is
// belt-and-suspenders for older browsers + extension-initiated
// requests + any path where SameSite was not honoured.
//
// Skipped methods: GET, HEAD, OPTIONS (idempotent / read-only).
// Skipped paths: webhook + signal + healthz + readyz + mcp (those have their
// own auth + are explicitly cross-origin by design).
//
// The "expected" scheme://host is computed from r.Host + r.TLS so
// the daemon doesn't need to know its public URL ahead of time.
// Trusted-proxy callers may set X-Forwarded-Host and X-Forwarded-Proto
// to override; those are honoured only when isTrustedProxyRequest is
// true, matching the SecurityHeaders HSTS gate.
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isStateChangingMethod(r.Method) || isCSRFExempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		expected := expectedOrigin(r)
		if expected == "" {
			http.Error(w, "csrf: cannot derive expected origin", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			if !equalOrigin(origin, expected) {
				http.Error(w, "csrf: Origin mismatch", http.StatusForbidden)
				return
			}
		} else if ref := r.Header.Get("Referer"); ref != "" {
			if !refererMatchesOrigin(ref, expected) {
				http.Error(w, "csrf: Referer mismatch", http.StatusForbidden)
				return
			}
		} else {
			http.Error(w, "csrf: missing Origin/Referer on state-changing request", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isStateChangingMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

func isCSRFExempt(path string) bool {
	switch {
	case path == "/healthz":
		return true
	case path == "/readyz":
		return true
	case strings.HasPrefix(path, "/webhook/"):
		return true
	case strings.HasPrefix(path, "/command-webhook/"):
		return true
	case strings.HasPrefix(path, "/signal/"):
		return true
	case path == "/mcp" || strings.HasPrefix(path, "/mcp/"):
		return true
	}
	return false
}

func expectedOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if isTrustedProxyRequest(r) {
		if v := forwardedProto(r); v != "" {
			scheme = v
		}
		if v := forwardedHost(r); v != "" {
			host = v
		}
	}
	if host == "" {
		return ""
	}
	return scheme + "://" + host
}

func equalOrigin(got, expected string) bool {
	return strings.EqualFold(strings.TrimRight(got, "/"), strings.TrimRight(expected, "/"))
}

func refererMatchesOrigin(referer, expected string) bool {
	// Compare scheme + host only; the path component of Referer is
	// arbitrary on legitimate requests.
	idx := strings.Index(referer, "://")
	if idx == -1 {
		return false
	}
	// Find end of host (next '/' or '?').
	rest := referer[idx+3:]
	end := len(rest)
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		end = i
	}
	got := referer[:idx+3+end]
	return equalOrigin(got, expected)
}

// RateLimit returns middleware that enforces a simple token-bucket
// rate limit per source IP. Public endpoints (webhook + signal) are
// the primary target; status pages are also limited for parity.
//
// burst is the bucket capacity (max instantaneous requests); refill is
// the steady-state requests-per-second once the bucket drains.
//
// Implementation is a tiny in-process map keyed by remote IP, no
// external dep. Replaces by a real limiter (e.g. golang.org/x/time/rate)
// when the daemon needs cross-instance limits in week 11.
func RateLimit(burst int, refill float64) func(http.Handler) http.Handler {
	if burst <= 0 || refill <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	limiter := newIPLimiter(burst, refill)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.allow(clientIP(r)) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "rate limit", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// TrustedProxyPolicy lists socket peers allowed to supply forwarded headers.
// Loopback is trusted by default for local reverse-proxy deployments; private
// network peers are not trusted unless an operator names their IP or CIDR.
type TrustedProxyPolicy struct {
	prefixes []netip.Prefix
}

// ParseTrustedProxyCIDRs parses a comma-separated list of exact proxy IPs or
// CIDRs. The policy is immutable after construction and scoped to one server.
func ParseTrustedProxyCIDRs(raw string) (TrustedProxyPolicy, error) {
	var p TrustedProxyPolicy
	if strings.TrimSpace(raw) == "" {
		return p, nil
	}
	if len(raw) > 4096 {
		return TrustedProxyPolicy{}, fmt.Errorf("trusted proxy CIDRs: configuration exceeds 4096 bytes")
	}
	entries := strings.Split(raw, ",")
	if len(entries) > 32 {
		return TrustedProxyPolicy{}, fmt.Errorf("trusted proxy CIDRs: more than 32 entries")
	}
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return TrustedProxyPolicy{}, fmt.Errorf("trusted proxy CIDRs: empty entry")
		}
		if ip, err := netip.ParseAddr(entry); err == nil {
			if ip.Zone() != "" {
				return TrustedProxyPolicy{}, fmt.Errorf("trusted proxy CIDRs: zone is not allowed in %q", entry)
			}
			ip = ip.Unmap()
			p.prefixes = append(p.prefixes, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(entry)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
			return TrustedProxyPolicy{}, fmt.Errorf("trusted proxy CIDRs: invalid IP or CIDR %q", entry)
		}
		if prefix.Bits() == 0 {
			return TrustedProxyPolicy{}, fmt.Errorf("trusted proxy CIDRs: all-address range %q is not allowed", entry)
		}
		p.prefixes = append(p.prefixes, prefix.Masked())
	}
	return p, nil
}

func (p TrustedProxyPolicy) trusted(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return true
	}
	for _, prefix := range p.prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

type trustedProxyPolicyKey struct{}

// TrustedProxyContext makes one server's proxy policy available to all
// forwarded-header consumers without process-global mutable configuration.
func TrustedProxyContext(policy TrustedProxyPolicy) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), trustedProxyPolicyKey{}, policy)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func requestTrustedProxyPolicy(r *http.Request) TrustedProxyPolicy {
	p, _ := r.Context().Value(trustedProxyPolicyKey{}).(TrustedProxyPolicy)
	return p
}

// clientIP extracts the source IP. X-Forwarded-For is honoured only when the
// socket peer is trusted, and only as a bounded chain of valid IP addresses.
// The nearest untrusted hop (walking from right to left) is the client; this
// prevents a caller-supplied leftmost value from bypassing rate limits when
// a real proxy appends rather than replaces X-Forwarded-For.
//
// Uses net.SplitHostPort so IPv6 addresses like "[::1]:8080" parse
// correctly (LastIndex on ":" mangles them).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr without a port (rare, but possible behind some
		// transports / tests) -- fall back to the raw value.
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	if !requestTrustedProxyPolicy(r).trusted(peer) {
		return peer.String()
	}
	const maxXFFBytes, maxXFFHops = 4096, 32
	var hops []netip.Addr
	var total int
	for _, value := range r.Header.Values("X-Forwarded-For") {
		total += len(value)
		if total > maxXFFBytes {
			return peer.String()
		}
		for _, part := range strings.Split(value, ",") {
			if len(hops) >= maxXFFHops {
				return peer.String()
			}
			ip, err := netip.ParseAddr(strings.TrimSpace(part))
			if err != nil || ip.Zone() != "" {
				return peer.String()
			}
			hops = append(hops, ip.Unmap())
		}
	}
	policy := requestTrustedProxyPolicy(r)
	for i := len(hops) - 1; i >= 0; i-- {
		if !policy.trusted(hops[i]) {
			return hops[i].String()
		}
	}
	return peer.String()
}

// isTrustedProxy reports the safe default used without explicit policy.
func isTrustedProxy(host string) bool {
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return false
	}
	return (TrustedProxyPolicy{}).trusted(ip)
}

// isTrustedProxyRequest is the *http.Request convenience wrapper. Pulls
// the host out of RemoteAddr the same way clientIP does so the X-
// Forwarded-Proto trust gate matches the X-Forwarded-For trust gate.
func isTrustedProxyRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Zone() == "" && requestTrustedProxyPolicy(r).trusted(ip)
}

// Forwarded origin values must be singular and syntactically usable. Multiple
// values or comma-joined proxy chains have ambiguous meaning, so ignore them.
func forwardedProto(r *http.Request) string {
	values := r.Header.Values("X-Forwarded-Proto")
	if len(values) != 1 {
		return ""
	}
	if values[0] == "http" || values[0] == "https" {
		return values[0]
	}
	return ""
}

func forwardedHost(r *http.Request) string {
	values := r.Header.Values("X-Forwarded-Host")
	if len(values) != 1 || values[0] == "" || strings.ContainsAny(values[0], ", \t\r\n\\/?#@") || strings.HasSuffix(values[0], ":") {
		return ""
	}
	u, err := url.Parse("http://" + values[0])
	if err != nil || u.Host != values[0] || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	return values[0]
}

// ipLimiter is a refill-bucket per IP. Burst tokens fill at refill/sec.
// Buckets that have not seen a request inside the idle window are
// evicted on the next .allow() call so a botnet or IPv6 spray cannot
// inflate the map until the daemon OOMs.
type ipLimiter struct {
	burst        int
	refill       float64
	idleEvictAge time.Duration
	maxBuckets   int
	mu           sync.Mutex
	buckets      map[string]*bucket
	lastSweep    time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newIPLimiter(burst int, refill float64) *ipLimiter {
	return &ipLimiter{
		burst:        burst,
		refill:       refill,
		buckets:      map[string]*bucket{},
		idleEvictAge: 10 * time.Minute,
		maxBuckets:   50_000,
	}
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.maybeSweepLocked(now)
	b, ok := l.buckets[ip]
	if !ok {
		// Hard ceiling: refuse the request rather than admit one more
		// unbounded entry to the map. Once the sweep has freed older
		// IPs, the limiter accepts new ones again.
		if len(l.buckets) >= l.maxBuckets {
			return false
		}
		b = &bucket{tokens: float64(l.burst), last: now}
		l.buckets[ip] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.refill
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// maybeSweepLocked evicts buckets that have not seen a request inside
// idleEvictAge. Runs at most every minute so a hot path doesn't pay
// a full-map walk on every call.
func (l *ipLimiter) maybeSweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < time.Minute {
		return
	}
	l.lastSweep = now
	cutoff := now.Add(-l.idleEvictAge)
	for ip, b := range l.buckets {
		if b.last.Before(cutoff) {
			delete(l.buckets, ip)
		}
	}
}
