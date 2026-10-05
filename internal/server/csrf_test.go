package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCSRFAllowsSafeMethods(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(CSRF(silentHandler))
	defer srv.Close()
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		req, _ := http.NewRequest(m, srv.URL+"/credentials", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", m, resp.StatusCode)
		}
	}
}

func TestCSRFRejectsCrossOriginPost(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(CSRF(silentHandler))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/credentials", strings.NewReader(""))
	req.Header.Set("Origin", "https://attacker.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestCSRFAcceptsSameOriginPost(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(CSRF(silentHandler))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/credentials", strings.NewReader(""))
	req.Header.Set("Origin", srv.URL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestCSRFRejectsMissingOriginAndReferer(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(CSRF(silentHandler))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/credentials", strings.NewReader(""))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestCSRFExemptsWebhookCommandWebhookSignalMCP(t *testing.T) {
	t.Parallel()
	h := CSRF(silentHandler)
	for _, path := range []string{"/webhook/whk_x", "/command-webhook/cmdwhk_x", "/signal/sig_x", "/mcp", "/mcp/v1"} {
		req := httptest.NewRequest(http.MethodPost, "http://reactor.test"+path, strings.NewReader(""))
		req.Header.Set("Origin", "https://attacker.example.com")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200 (exempt path must skip CSRF check)", path, rec.Code)
		}
	}
}

func TestCSRFAcceptsRefererFallback(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(CSRF(silentHandler))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/credentials", strings.NewReader(""))
	req.Header.Set("Referer", srv.URL+"/some/page?with=query")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (Referer same-origin should pass)", resp.StatusCode)
	}
}
