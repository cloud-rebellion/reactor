package http

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestInjectedClientDoesNotForwardCredentialHeadersOnRedirect(t *testing.T) {
	var targetHits int
	// A regular http.Client follows redirects by default, forwarding custom
	// headers even when the redirect leaves the original origin.
	injected := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Host {
		case "api.example.test":
			if got := r.Header.Get("X-Api-Key"); got != "test-secret" {
				t.Errorf("source received API key %q", got)
			}
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{"https://attacker.example.test/steal"}},
				Body:       io.NopCloser(strings.NewReader("redirect")),
			}, nil
		case "attacker.example.test":
			targetHits++
			if got := r.Header.Get("X-Api-Key"); got != "" {
				t.Errorf("redirect target received API key %q", got)
			}
			return testResponse(http.StatusOK, nil, "{}"), nil
		default:
			t.Fatalf("unexpected request host %q", r.URL.Host)
			return nil, nil
		}
	})}
	client := &Client{HTTPClient: injected, Headers: map[string]string{"X-Api-Key": "test-secret"}, CredentialOrigin: "https://api.example.test", Retry: Retry{Max: 1}}
	status, _, _, err := client.GetRaw(context.Background(), "https://api.example.test/start")
	if err != nil || status != http.StatusFound {
		t.Fatalf("redirect response = status %d, err %v; want 302", status, err)
	}
	if targetHits != 0 {
		t.Fatalf("redirect target received %d request(s)", targetHits)
	}
	if injected.CheckRedirect != nil {
		t.Fatal("SDK changed the caller-owned HTTP client")
	}
}
