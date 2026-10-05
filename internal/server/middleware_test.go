package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/auth"
)

// hashPass shapes a password the way operators would when they paste a
// hash into the env var: lowercase hex of sha256.
func hashPass(p string) string {
	h := sha256.Sum256([]byte(p))
	return hex.EncodeToString(h[:])
}

// silentHandler is the dummy backend the middleware tests wrap.
var silentHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
})

func TestSecurityHeadersAlwaysSet(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(SecurityHeaders(silentHandler))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	for _, h := range []string{
		"X-Content-Type-Options", "X-Frame-Options",
		"Referrer-Policy", "Permissions-Policy",
		"Content-Security-Policy",
	} {
		if v := resp.Header.Get(h); v == "" {
			t.Errorf("missing header %s", h)
		}
	}
	if v := resp.Header.Get("X-Frame-Options"); v != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", v)
	}
	// HSTS only fires on TLS; this is plain HTTP so should be absent.
	if v := resp.Header.Get("Strict-Transport-Security"); v != "" {
		t.Errorf("HSTS leaked on plain HTTP: %q", v)
	}
}

func TestBasicAuthFailsClosedWhenUnconfigured(t *testing.T) {
	t.Parallel()
	mw := BasicAuth(BasicAuthConfig{})
	srv := httptest.NewServer(mw(silentHandler))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (auth must fail closed when User+Hash empty unless AllowNoAuth is set)", resp.StatusCode)
	}
}

func TestBasicAuthAllowNoAuthOptIn(t *testing.T) {
	t.Parallel()
	mw := BasicAuth(BasicAuthConfig{AllowNoAuth: true})
	srv := httptest.NewServer(mw(silentHandler))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (AllowNoAuth=true must let traffic through)", resp.StatusCode)
	}
}

func TestBasicAuthAcceptsArgon2idPHC(t *testing.T) {
	t.Parallel()
	// Generated with EncodeArgon2idPHC("secret", []byte("0123456789abcdef"), 65536, 2, 1).
	phc := EncodeArgon2idPHC("secret", []byte("0123456789abcdef"), 65536, 2, 1)
	mw := BasicAuth(BasicAuthConfig{User: "alice", PasswordSHA256: phc})
	srv := httptest.NewServer(mw(silentHandler))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.SetBasicAuth("alice", "secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("argon2id good creds: status = %d, want 200", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.SetBasicAuth("alice", "wrong")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("argon2id wrong creds: status = %d, want 401", resp.StatusCode)
	}
}

func TestBasicAuthRequiresCredentialsWhenConfigured(t *testing.T) {
	t.Parallel()
	mw := BasicAuth(BasicAuthConfig{User: "alice", PasswordSHA256: hashPass("secret")})
	srv := httptest.NewServer(mw(silentHandler))
	defer srv.Close()

	// no creds -> 401
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no creds: status = %d, want 401", resp.StatusCode)
	}
	if v := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(v, "Basic ") {
		t.Fatalf("missing WWW-Authenticate Basic challenge: %q", v)
	}

	// wrong password -> 401
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.SetBasicAuth("alice", "wrong")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong pass: status = %d, want 401", resp.StatusCode)
	}

	// wrong user -> 401
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.SetBasicAuth("eve", "secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong user: status = %d, want 401", resp.StatusCode)
	}

	// right -> 200
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.SetBasicAuth("alice", "secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("good creds: status = %d, want 200", resp.StatusCode)
	}
}

func TestBasicAuthSkipsPublicRoutes(t *testing.T) {
	t.Parallel()
	mw := BasicAuth(BasicAuthConfig{User: "alice", PasswordSHA256: hashPass("secret")})
	h := mw(silentHandler)
	for _, path := range []string{"/healthz", "/readyz", "/oauth/callback", "/webhook/whk_x", "/command-webhook/cmdwhk_x", "/signal/sig_x"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://reactor.test"+path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("public path %s: status = %d, want 200", path, rec.Code)
			}
		})
	}
}

func TestOAuthCallbackSkipsSessionAuth(t *testing.T) {
	t.Parallel()
	// A provider redirect is authenticated by the OAuth state's single-use
	// state + PKCE verifier, not by a Reactor dashboard session. Keep this
	// route public so an MCP-started consent flow can finish in a browser that
	// is not signed in.
	called := false
	h := SessionAuth(SessionAuthConfig{Store: &auth.Store{}})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?state=st_test&code=code", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || !called {
		t.Fatalf("OAuth callback status=%d called=%t; want unauthenticated callback to reach handler", rec.Code, called)
	}
}

func TestRateLimitTriggers429(t *testing.T) {
	t.Parallel()
	// Burst of 3 with 0.001 refill so the test's quick burst exceeds.
	mw := RateLimit(3, 0.001)
	srv := httptest.NewServer(mw(silentHandler))
	defer srv.Close()

	// First three requests fit in the bucket; the fourth exceeds.
	var statuses []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(srv.URL + "/")
			if err != nil {
				return
			}
			resp.Body.Close()
			mu.Lock()
			statuses = append(statuses, resp.StatusCode)
			mu.Unlock()
		}()
	}
	wg.Wait()

	deadline := time.After(time.Second)
	for {
		mu.Lock()
		count := len(statuses)
		mu.Unlock()
		if count >= 5 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("only saw %d responses", count)
		case <-time.After(10 * time.Millisecond):
		}
	}

	got429 := 0
	got200 := 0
	for _, s := range statuses {
		switch s {
		case http.StatusOK:
			got200++
		case http.StatusTooManyRequests:
			got429++
		}
	}
	if got200 < 1 || got200 > 3 {
		t.Errorf("expected 1..3 200s, got %d", got200)
	}
	if got429 < 2 {
		t.Errorf("expected at least 2 429s, got %d", got429)
	}
}

func TestHSTSDoesNotLeakOnSpoofedXFP(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(SecurityHeaders(silentHandler))
	defer srv.Close()
	// Plain HTTP request with an attacker-supplied XFP header. The
	// request arrives at the test server from the loopback go client
	// (which IS a trusted proxy by our gate), so to prove the spoofing
	// path is closed, simulate an untrusted RemoteAddr by hitting the
	// handler directly with a synthetic request instead of going over
	// the loopback transport.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.7:54321" // public IP, not a trusted proxy
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	SecurityHeaders(silentHandler).ServeHTTP(w, req)
	if v := w.Header().Get("Strict-Transport-Security"); v != "" {
		t.Fatalf("HSTS leaked from spoofed XFP+plain HTTP source 203.0.113.7: %q", v)
	}
}

func TestHSTSFiresFromTrustedProxyXFP(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321" // loopback, trusted
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	SecurityHeaders(silentHandler).ServeHTTP(w, req)
	if v := w.Header().Get("Strict-Transport-Security"); v == "" {
		t.Fatal("HSTS should fire when a trusted proxy reports XFP=https")
	}
}

func TestIsTrustedProxy(t *testing.T) {
	t.Parallel()
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.0.0.5", false},
		{"192.168.1.1", false},
		{"172.16.0.1", false},
		{"172.31.255.254", false},
		{"fd12:3456::1", false},
		// Private peers are no longer implicitly trusted proxies.
		{"172.0.0.1", false},
		{"172.15.0.1", false},
		{"172.32.0.1", false},
		{"172.250.0.1", false},
		// Public addresses:
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2001:db8::1", false},
		// Garbage / non-IP:
		{"", false},
		{"not-an-ip", false},
		{"[::1]", false},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			if got := isTrustedProxy(tc.host); got != tc.want {
				t.Errorf("isTrustedProxy(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestClientIPParsesIPv6(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{"ipv4 no xff", "203.0.113.5:54321", "", "203.0.113.5"},
		{"ipv6 loopback no xff", "[::1]:8080", "", "::1"},
		{"ipv6 public no xff", "[2001:db8::1]:443", "", "2001:db8::1"},
		{"untrusted proxy ignores xff", "203.0.113.5:54321", "evil.example", "203.0.113.5"},
		{"trusted v4 proxy uses xff", "127.0.0.1:54321", "203.0.113.99", "203.0.113.99"},
		{"trusted v6 proxy uses xff", "[::1]:54321", "203.0.113.99", "203.0.113.99"},
		{"private peer ignores xff", "10.0.0.1:54321", "203.0.113.99, 10.0.0.1", "10.0.0.1"},
		// 172.250.x.x previously matched the buggy HasPrefix "172." and
		// would have trusted the XFF; with the fix it must not.
		{"172.250 not trusted", "172.250.0.1:54321", "evil.example", "172.250.0.1"},
		{"172.16 private ignored", "172.16.0.1:54321", "203.0.113.7", "172.16.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{
				RemoteAddr: tc.remoteAddr,
				Header:     http.Header{},
			}
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := clientIP(r); got != tc.want {
				t.Errorf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRateLimitDisabledWhenZero(t *testing.T) {
	t.Parallel()
	mw := RateLimit(0, 0)
	srv := httptest.NewServer(mw(silentHandler))
	defer srv.Close()
	for i := 0; i < 50; i++ {
		resp, err := http.Get(srv.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("burst %d: status = %d, want 200 (limiter must be a no-op)", i, resp.StatusCode)
		}
	}
}
