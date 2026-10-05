package flarereport

import (
	"strings"
	"testing"

	sentry "github.com/getsentry/sentry-go"
)

func TestScrubEventRemovesRequestSecretsRegardlessOfHeaderCasing(t *testing.T) {
	event := &sentry.Event{Request: &sentry.Request{
		URL:         "https://oauth-user:oauth-pass@example.test/oauth/callback?code=one-time-code#fragment",
		QueryString: "code=one-time-code",
		Data:        "client_secret=should-not-ship",
		Cookies:     "reactor_sess=session-value",
		Headers: map[string]string{
			"authorization": "Bearer bearer-value",
			"Cookie":        "reactor_sess=session-value",
			"X-API-Key":     "api-key-value",
			"Referrer":      "https://example.test/?code=one-time-code",
			"X-Request-ID":  "request-123",
		},
	}}

	got := scrubEvent(event, nil)
	if got != event {
		t.Fatal("scrubEvent must preserve the event pointer")
	}
	request := got.Request
	if request.QueryString != "" || request.Data != "" || request.Cookies != "" {
		t.Fatalf("request sensitive fields were not cleared: %#v", request)
	}
	for _, key := range []string{"authorization", "Cookie", "X-API-Key", "Referrer"} {
		if _, ok := request.Headers[key]; ok {
			t.Fatalf("sensitive request header %q survived scrub: %#v", key, request.Headers)
		}
	}
	if request.Headers["X-Request-ID"] != "request-123" {
		t.Fatalf("ordinary request header was removed: %#v", request.Headers)
	}
	if strings.Contains(request.URL, "oauth-user") || strings.Contains(request.URL, "oauth-pass") ||
		strings.Contains(request.URL, "code=") || strings.Contains(request.URL, "#fragment") {
		t.Fatalf("request URL still contains credentials or query data: %q", request.URL)
	}
	if request.URL != "https://example.test/oauth/callback" {
		t.Fatalf("request URL = %q, want sanitized origin and path", request.URL)
	}
}
