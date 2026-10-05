package server

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestTrustedProxyPolicyDefaultAndExplicitPeers(t *testing.T) {
	policy, err := ParseTrustedProxyCIDRs("10.4.5.9, 192.168.42.0/24, fd12::5")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true}, {"::1", true},
		{"10.4.5.9", true}, {"10.4.5.10", false},
		{"192.168.42.18", true}, {"192.168.43.18", false},
		{"fd12::5", true}, {"fd12::6", false},
	} {
		ip := netip.MustParseAddr(tc.ip)
		if got := policy.trusted(ip); got != tc.want {
			t.Errorf("trusted(%s) = %v, want %v", ip, got, tc.want)
		}
	}
	if (TrustedProxyPolicy{}).trusted(netip.MustParseAddr("10.4.5.9")) {
		t.Fatal("private peer trusted without explicit policy")
	}
	for _, raw := range []string{"10.0.0.1,", "not-an-ip", "10.0.0.0/nope", "::ffff:10.0.0.0/120", "0.0.0.0/0", "::/0", strings.Repeat("1", 4097), strings.Repeat("10.0.0.1,", 33)} {
		if _, err := ParseTrustedProxyCIDRs(raw); err == nil {
			t.Errorf("accepted invalid or unbounded proxy policy %q", raw)
		}
	}
}

func TestClientIPUsesNearestUntrustedHopAndRejectsBadChains(t *testing.T) {
	policy, err := ParseTrustedProxyCIDRs("10.4.5.9,10.4.5.8")
	if err != nil {
		t.Fatal(err)
	}
	h := TrustedProxyContext(policy)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(clientIP(r)))
	}))
	for _, tc := range []struct {
		name   string
		remote string
		xff    []string
		want   string
	}{
		{"direct private ignores xff", "10.4.5.10:1234", []string{"198.51.100.2"}, "10.4.5.10"},
		{"appended spoof ignored", "10.4.5.9:1234", []string{"198.51.100.1, 203.0.113.44, 10.4.5.8"}, "203.0.113.44"},
		{"multiple xff fields", "10.4.5.9:1234", []string{"198.51.100.1", "203.0.113.44, 10.4.5.8"}, "203.0.113.44"},
		{"all trusted falls back to socket", "10.4.5.9:1234", []string{"10.4.5.8"}, "10.4.5.9"},
		{"malformed hop falls back to socket", "10.4.5.9:1234", []string{"garbage, 203.0.113.44"}, "10.4.5.9"},
		{"oversize xff falls back to socket", "10.4.5.9:1234", []string{strings.Repeat("1", 4097)}, "10.4.5.9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://reactor.internal/", nil)
			req.RemoteAddr = tc.remote
			for _, v := range tc.xff {
				req.Header.Add("X-Forwarded-For", v)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if got := w.Body.String(); got != tc.want {
				t.Fatalf("client IP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRotatingXFFCannotBypassRateLimit(t *testing.T) {
	policy, err := ParseTrustedProxyCIDRs("10.4.5.9")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		remote string
		xff1   string
		xff2   string
	}{
		{"direct private caller", "10.4.5.10:1234", "198.51.100.1", "198.51.100.2"},
		{"proxy appends attacker xff", "10.4.5.9:1234", "198.51.100.1, 203.0.113.44", "198.51.100.2, 203.0.113.44"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := TrustedProxyContext(policy)(RateLimit(1, 0.001)(silentHandler))
			for i, xff := range []string{tc.xff1, tc.xff2} {
				req := httptest.NewRequest(http.MethodGet, "http://reactor.internal/", nil)
				req.RemoteAddr = tc.remote
				req.Header.Set("X-Forwarded-For", xff)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, req)
				want := http.StatusOK
				if i == 1 {
					want = http.StatusTooManyRequests
				}
				if w.Code != want {
					t.Fatalf("request %d got %d, want %d", i+1, w.Code, want)
				}
			}
		})
	}
}

func TestForwardedOriginRequiresExplicitPeerAndSingleValidHeaders(t *testing.T) {
	policy, err := ParseTrustedProxyCIDRs("10.4.5.9")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		remote    string
		proto     string
		host      string
		origin    string
		wantCSRF  int
		wantHSTS  bool
		wantOAuth string
	}{
		{"private direct spoof ignored", "10.4.5.10:1234", "https", "evil.example", "https://evil.example", http.StatusForbidden, false, "http://reactor.internal/oauth/callback"},
		{"explicit proxy accepted", "10.4.5.9:1234", "https", "public.example", "https://public.example", http.StatusOK, true, "https://public.example/oauth/callback"},
		{"comma joined values ignored", "10.4.5.9:1234", "https,http", "evil.example,public.example", "https://evil.example", http.StatusForbidden, false, "http://reactor.internal/oauth/callback"},
		{"unsafe forwarded host ignored", "10.4.5.9:1234", "https", "evil.example/path", "https://evil.example", http.StatusForbidden, true, "https://reactor.internal/oauth/callback"},
		{"forwarded host credentials ignored", "10.4.5.9:1234", "https", "user@evil.example", "https://evil.example", http.StatusForbidden, true, "https://reactor.internal/oauth/callback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://reactor.internal/credentials", nil)
			req.RemoteAddr = tc.remote
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("X-Forwarded-Proto", tc.proto)
			req.Header.Set("X-Forwarded-Host", tc.host)
			h := TrustedProxyContext(policy)(SecurityHeaders(CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(oauthRedirectURI(r)))
			}))))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tc.wantCSRF {
				t.Fatalf("CSRF status = %d, want %d", w.Code, tc.wantCSRF)
			}
			if got := w.Header().Get("Strict-Transport-Security") != ""; got != tc.wantHSTS {
				t.Fatalf("HSTS presence = %v, want %v", got, tc.wantHSTS)
			}
			// The rejected CSRF cases cannot reach the handler; inspect the
			// same request's callback derivation independently.
			var gotOAuth string
			TrustedProxyContext(policy)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				gotOAuth = oauthRedirectURI(r)
			})).ServeHTTP(httptest.NewRecorder(), req)
			if gotOAuth != tc.wantOAuth {
				t.Fatalf("OAuth callback = %q, want %q", gotOAuth, tc.wantOAuth)
			}
		})
	}
}

func TestForwardedOriginRejectsDuplicateHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://reactor.internal/", nil)
	req.Header.Add("X-Forwarded-Proto", "https")
	req.Header.Add("X-Forwarded-Proto", "http")
	req.Header.Add("X-Forwarded-Host", "public.example")
	req.Header.Add("X-Forwarded-Host", "evil.example")
	if got := forwardedProto(req); got != "" {
		t.Fatalf("duplicate forwarded proto accepted: %q", got)
	}
	if got := forwardedHost(req); got != "" {
		t.Fatalf("duplicate forwarded host accepted: %q", got)
	}
}
