package hash

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/sdk/esign"
	ahttp "github.com/bright-interaction/reactor/sdk/http"
)

func validRequest() SignatureRequest {
	return SignatureRequest{
		TemplateID:  "29ddcd70-1d59-41fc-8e25-bad316eea84d",
		Name:        "Partner agreement",
		Variables:   map[string]string{"customer.name": "Ada Lovelace"},
		LawfulBasis: "contract",
		Recipients: []Recipient{{
			Role: "signer", Email: "ada@example.com", Name: "Ada Lovelace", Locale: "en",
		}},
	}
}

func TestCreateAndSendContract(t *testing.T) {
	t.Parallel()
	var received SignatureRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != requestPath {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer hash-secret" {
			t.Errorf("Authorization = %q", got)
		}
		if got := request.Header.Get("Idempotency-Key"); got != "event-42" {
			t.Errorf("Idempotency-Key = %q", got)
		}
		if got := request.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"automation_request_id":"req-1","document_id":"doc-1","status":"sent","replayed":false}`)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "hash-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.CreateAndSend(context.Background(), "event-42", validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if result.AutomationRequestID != "req-1" || result.DocumentID != "doc-1" || result.Status != "sent" || result.Replayed {
		t.Fatalf("result = %+v", result)
	}
	if received.TemplateID != validRequest().TemplateID || received.Variables["customer.name"] != "Ada Lovelace" {
		t.Fatalf("request = %+v", received)
	}
}

func TestCreateAndSendBlocksDryRunBeforeNetwork(t *testing.T) {
	t.Setenv("REACTOR_MODE", "dry_run")
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("dry-run Hash request reached the server")
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "hash-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateAndSend(context.Background(), "event-42", validRequest())
	if !errors.Is(err, ahttp.ErrDryRun) {
		t.Fatalf("dry-run error = %v, want ErrDryRun", err)
	}
}

func TestCreateAndSendPerformsOneAttempt(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "customer content must not leak", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "hash-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateAndSend(context.Background(), "event-42", validRequest())
	if err == nil || !IsRetryable(err) {
		t.Fatalf("got %v, want retryable error", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want exactly one", calls.Load())
	}
	if strings.Contains(err.Error(), "customer content") {
		t.Fatalf("error leaked response body: %v", err)
	}
}

func TestCreateAndSendDoesNotFollowRedirect(t *testing.T) {
	t.Parallel()
	var redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	client, err := NewClient(source.URL, "hash-secret", source.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateAndSend(context.Background(), "event-42", validRequest())
	if err == nil {
		t.Fatal("expected redirect response error")
	}
	if redirected.Load() != 0 {
		t.Fatal("client followed redirect and risked forwarding credentials")
	}
}

func TestAPIErrorClassificationAndRetryAfter(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "17")
		w.Header().Set("X-Request-ID", "request_123")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"code":"rate_limited","error":"ada@example.com"}`)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "hash-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateAndSend(context.Background(), "event-42", validRequest())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("got %T %v, want APIError", err, err)
	}
	if apiErr.Status != http.StatusTooManyRequests || apiErr.Code != "rate_limited" || apiErr.RequestID != "request_123" || apiErr.RetryAfter != 17*time.Second {
		t.Fatalf("APIError = %+v", apiErr)
	}
	if !IsRetryable(err) {
		t.Fatal("429 should be retryable")
	}
	if strings.Contains(err.Error(), "ada@example.com") {
		t.Fatalf("error leaked response body: %v", err)
	}
}

func TestStableClientErrorsArePermanent(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "hash-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateAndSend(context.Background(), "event-42", validRequest())
	if err == nil || IsRetryable(err) {
		t.Fatalf("got %v, want permanent conflict", err)
	}
}

func TestCreateAndSendAcceptsTerminalReplayStatus(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"automation_request_id":"req-1","document_id":"doc-1","status":"declined","replayed":true}`)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "hash-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.CreateAndSend(context.Background(), "event-42", validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "declined" || !result.Replayed {
		t.Fatalf("result = %+v", result)
	}
}

func TestCreateAndSendRetriesAmbiguousSuccessResponses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
	}{
		{name: "malformed 201", status: http.StatusCreated, body: `{"automation_request_id":`},
		{name: "trailing 201", status: http.StatusCreated, body: `{"automation_request_id":"req-1","document_id":"doc-1","status":"sent","replayed":false}{}`},
		{name: "duplicate result field", status: http.StatusCreated, body: `{"automation_request_id":"req-1","document_id":"doc-1","document_id":"doc-2","status":"sent","replayed":false}`},
		{name: "invalid UTF-8", status: http.StatusCreated, body: "{\"automation_request_id\":\"req-1\",\"document_id\":\"doc-\xff\",\"status\":\"sent\",\"replayed\":false}"},
		{name: "excessive JSON depth", status: http.StatusCreated, body: `{"automation_request_id":"req-1","document_id":"doc-1","status":"sent","replayed":false,"extra":` + strings.Repeat("[", 102) + "0" + strings.Repeat("]", 102) + `}`},
		{name: "unexpected 202", status: http.StatusAccepted, body: `{}`},
		{name: "missing replay flag", status: http.StatusCreated, body: `{"automation_request_id":"req-1","document_id":"doc-1","status":"sent"}`},
		{name: "created claims replay", status: http.StatusCreated, body: `{"automation_request_id":"req-1","document_id":"doc-1","status":"sent","replayed":true}`},
		{name: "ok claims fresh", status: http.StatusOK, body: `{"automation_request_id":"req-1","document_id":"doc-1","status":"sent","replayed":false}`},
		{name: "control in result id", status: http.StatusCreated, body: `{"automation_request_id":"req-1\nforged","document_id":"doc-1","status":"sent","replayed":false}`},
		{name: "wrong content type", status: http.StatusCreated, contentType: "text/plain", body: `{"automation_request_id":"req-1","document_id":"doc-1","status":"sent","replayed":false}`},
		{name: "unknown success status", status: http.StatusOK, body: `{"automation_request_id":"req-1","document_id":"doc-1","status":"mystery","replayed":false}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				contentType := test.contentType
				if contentType == "" {
					contentType = "application/json"
				}
				w.Header().Set("Content-Type", contentType)
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()

			client, err := NewClient(server.URL, "hash-secret", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.CreateAndSend(context.Background(), "event-42", validRequest())
			var ambiguous *AmbiguousResponseError
			if !errors.As(err, &ambiguous) || !IsRetryable(err) {
				t.Fatalf("got %T %v, want retryable AmbiguousResponseError", err, err)
			}
		})
	}
}

func TestCreateAndSendClassifiesOversizedBodiesByHTTPOutcome(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		status    int
		retryable bool
	}{
		{name: "service unavailable", status: http.StatusServiceUnavailable, retryable: true},
		{name: "too early", status: http.StatusTooEarly, retryable: true},
		{name: "bad request", status: http.StatusBadRequest, retryable: false},
		{name: "created", status: http.StatusCreated, retryable: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, strings.Repeat("x", maxResponseBodyBytes+1))
			}))
			defer server.Close()

			client, err := NewClient(server.URL, "hash-secret", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.CreateAndSend(context.Background(), "event-42", validRequest())
			if err == nil || IsRetryable(err) != test.retryable {
				t.Fatalf("got %T %v retryable=%v, want retryable=%v", err, err, IsRetryable(err), test.retryable)
			}
		})
	}
}

func TestNewClientURLPolicy(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"",
		"http://hash.example.com",
		"https://user:pass@hash.example.com",
		"https://hash.example.com?org=other",
		"https://hash.example.com/proxy-prefix",
	} {
		if _, err := NewClient(raw, "key", nil); err == nil {
			t.Fatalf("NewClient(%q) unexpectedly succeeded", raw)
		}
	}
	if _, err := NewClient("https://hash.example.com", "key", nil); err != nil {
		t.Fatalf("HTTPS client: %v", err)
	}
	if _, err := NewClient("http://127.0.0.1:8080", "key", nil); err != nil {
		t.Fatalf("loopback client: %v", err)
	}
}

func TestDefaultClientUsesConnectTimeSSRFGuard(t *testing.T) {
	t.Parallel()
	client, err := NewClient("https://hash.example.com", "key", nil)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok || transport.DialContext == nil {
		t.Fatalf("default client transport = %T, want SSRF-safe http.Transport", client.httpClient.Transport)
	}
	_, err = transport.DialContext(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil || !strings.Contains(err.Error(), "ssrf: refusing") {
		t.Fatalf("default client dial error = %v, want connect-time SSRF refusal", err)
	}
}

func TestNewClientRejectsMalformedAPIKey(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"", " key", "key\n", "bad\x00key"} {
		if _, err := NewClient("https://hash.example.com", key, nil); err == nil {
			t.Fatalf("NewClient accepted malformed API key %q", key)
		}
	}
}

func TestParseRetryAfterIsBounded(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	if got := parseRetryAfter("999999999999999999999", now); got != 0 {
		t.Fatalf("overflow delay = %s, want 0", got)
	}
	if got := parseRetryAfter("3600", now); got != maxRetryAfter {
		t.Fatalf("large seconds delay = %s, want %s", got, maxRetryAfter)
	}
	if got := parseRetryAfter(now.Add(time.Hour).Format(http.TimeFormat), now); got != maxRetryAfter {
		t.Fatalf("large date delay = %s, want %s", got, maxRetryAfter)
	}
}

func TestCreateAndSendValidatesIdempotencyKey(t *testing.T) {
	t.Parallel()
	client, err := NewClient("https://hash.example.com", "key", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"", " key", "bad\nkey", strings.Repeat("x", 201)} {
		if _, err := client.CreateAndSend(context.Background(), key, validRequest()); err == nil {
			t.Fatalf("key %q unexpectedly accepted", key)
		}
	}
}

func TestRecipientsDropsProviderCorrelationFields(t *testing.T) {
	t.Parallel()
	got := Recipients([]esign.Recipient{{
		ExternalID: "crm-contact-1", Role: "signer", Name: "Ada", Email: "ada@example.com", Locale: "sv", SigningOrder: 2,
	}})
	if len(got) != 1 || got[0].Role != "signer" || got[0].OrderIndex != 2 {
		t.Fatalf("recipients = %+v", got)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "crm-contact-1") {
		t.Fatalf("provider external ID crossed Hash boundary: %s", raw)
	}
}
