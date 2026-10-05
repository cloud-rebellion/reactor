package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestOAuthHTTPClientBlocksTailscaleEvenWithPrivateAccess(t *testing.T) {
	t.Parallel()

	s := New(nil, EngineSQLite, make([]byte, 32))
	transport, ok := s.http.Transport.(*http.Transport)
	if !ok || transport.DialContext == nil {
		t.Fatalf("oauth transport = %T, want safe http.Transport", s.http.Transport)
	}
	_, err := transport.DialContext(context.Background(), "tcp", "100.64.0.1:443")
	if err == nil || !strings.Contains(err.Error(), "ssrf: refusing") {
		t.Fatalf("Tailscale token endpoint dial error = %v, want SSRF refusal", err)
	}
}

// TestTokenExchangeDoesNotFollowRedirects closes the pivot that made this an
// SSRF primitive for a third party rather than only for an admin.
//
// The token exchange used a bare &http.Client{}, which follows up to 10
// redirects. A malicious or compromised upstream OAuth provider could answer
// the token request with a 302 into the internal network (or at the cloud
// metadata endpoint) and Reactor would dutifully follow it. The shared
// safehttp client refuses redirects outright, which is why every other
// outbound caller in the daemon uses it.
func TestTokenExchangeDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	var internalHits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		internalHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"SHOULD_NEVER_BE_REACHED"}`))
	}))
	defer internal.Close()

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL, http.StatusFound)
	}))
	defer provider.Close()

	s := New(nil, EngineSQLite, make([]byte, 32))
	p := Provider{ProviderID: "evil", ClientID: "id", TokenURL: provider.URL}

	_, err := s.exchange(context.Background(), p, url.Values{"grant_type": {"authorization_code"}})
	if err == nil {
		t.Fatal("redirect was followed and the exchange succeeded; a hostile provider can pivot the token request into the internal network")
	}
	if n := internalHits.Load(); n != 0 {
		t.Fatalf("the redirect target was contacted %d time(s); redirects must not be followed", n)
	}
}

// TestTokenExchangeDoesNotEchoResponseBody closes the read primitive.
//
// A non-2xx token response put up to 300 bytes of the body straight into the
// returned error, and that error surfaces to the operator. Combined with a
// redirect (or an admin-set internal token_url) that turns the exchange into
// "fetch an internal URL and show me the response", which is exactly the
// exfiltration shape already fixed in the Slack and webhook notifiers.
func TestTokenExchangeDoesNotEchoResponseBody(t *testing.T) {
	t.Parallel()

	const secret = "AKIAIOSFODNN7EXAMPLE-internal-metadata-payload"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(secret))
	}))
	defer srv.Close()

	s := New(nil, EngineSQLite, make([]byte, 32))
	p := Provider{ProviderID: "x", ClientID: "id", TokenURL: srv.URL}

	_, err := s.exchange(context.Background(), p, url.Values{"grant_type": {"authorization_code"}})
	if err == nil {
		t.Fatal("expected an error on a 403 token response")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the token endpoint's response body leaked into the operator-visible error: %v", err)
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("the error should still name the status code so the failure is diagnosable, got: %v", err)
	}
}
