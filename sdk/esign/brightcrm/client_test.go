package brightcrm

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
)

func validLifecycleEvent() esign.LifecycleEvent {
	return esign.LifecycleEvent{
		EventID:             "e4bcf071-6c66-4787-8fb1-41f87f419a16",
		Kind:                "document.completed",
		OccurredAt:          time.Date(2026, time.September, 1, 10, 30, 0, 0, time.UTC),
		AutomationRequestID: "f6a451f9-fb04-46af-8234-113113fe3a0d",
		DocumentID:          "20f574e1-dd6f-41d8-bc8a-38e088512b55",
	}
}

func TestDeliverLifecycleEventContract(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != lifecyclePath || request.URL.RawQuery != "" {
			t.Errorf("request = %s %s", request.Method, request.URL.String())
		}
		if got := request.Header.Get("Authorization"); got != "Bearer crm-secret" {
			t.Errorf("Authorization = %q", got)
		}
		if got := request.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if len(body) != 5 {
			t.Errorf("body keys = %v, want exactly five", body)
		}
		for _, key := range []string{"event_id", "kind", "occurred_at", "automation_request_id", "document_id"} {
			if _, ok := body[key]; !ok {
				t.Errorf("body missing %s", key)
			}
		}
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(writer, `{"accepted":true,"deduped":false}`)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "crm-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := client.DeliverLifecycleEvent(context.Background(), validLifecycleEvent())
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Accepted || receipt.Deduped {
		t.Fatalf("receipt = %+v", receipt)
	}
}

func TestDeliverLifecycleEventAcceptsStrictReplayReceipt(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"accepted":true,"deduped":true}`)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "crm-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := client.DeliverLifecycleEvent(context.Background(), validLifecycleEvent())
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Accepted || !receipt.Deduped {
		t.Fatalf("receipt = %+v", receipt)
	}
}

func TestDeliverLifecycleEventPerformsOneAttemptAndDropsResponseBody(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		writer.Header().Set("Retry-After", "17")
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(writer, "ada@example.com must never reach workflow logs")
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "crm-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.DeliverLifecycleEvent(context.Background(), validLifecycleEvent())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !IsRetryable(err) || apiErr.RetryAfter != 17*time.Second {
		t.Fatalf("error = %T %v, retry_after=%s", err, err, apiErr.RetryAfter)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want exactly one", calls.Load())
	}
	if strings.Contains(err.Error(), "ada@example.com") {
		t.Fatalf("error leaked response body: %v", err)
	}
}

func TestDeliverLifecycleEventDoesNotFollowRedirect(t *testing.T) {
	t.Parallel()
	var redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		redirected.Add(1)
		if request.Header.Get("Authorization") != "" {
			t.Error("redirect destination received bearer credential")
		}
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	client, err := NewClient(source.URL, "crm-secret", source.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeliverLifecycleEvent(context.Background(), validLifecycleEvent()); err == nil {
		t.Fatal("redirect response accepted")
	}
	if redirected.Load() != 0 {
		t.Fatalf("redirect destination calls = %d", redirected.Load())
	}
}

func TestLifecycleAPIStatusClassification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		status    int
		retryable bool
	}{
		{status: http.StatusBadRequest},
		{status: http.StatusUnauthorized},
		{status: http.StatusConflict},
		{status: http.StatusRequestTimeout, retryable: true},
		{status: http.StatusTooEarly, retryable: true},
		{status: http.StatusTooManyRequests, retryable: true},
		{status: http.StatusInternalServerError, retryable: true},
		{status: http.StatusServiceUnavailable, retryable: true},
	}
	for _, test := range tests {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(test.status)
			}))
			defer server.Close()
			client, err := NewClient(server.URL, "crm-secret", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.DeliverLifecycleEvent(context.Background(), validLifecycleEvent())
			if err == nil || IsRetryable(err) != test.retryable {
				t.Fatalf("error = %T %v, retryable=%v; want %v", err, err, IsRetryable(err), test.retryable)
			}
		})
	}
}

func TestLifecycleAmbiguousSuccessIsRetryable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
	}{
		{name: "204", status: http.StatusNoContent, contentType: "application/json"},
		{name: "malformed", status: http.StatusAccepted, contentType: "application/json", body: `{"accepted":`},
		{name: "wrong content type", status: http.StatusAccepted, contentType: "text/plain", body: `{"accepted":true,"deduped":false}`},
		{name: "unknown member", status: http.StatusAccepted, contentType: "application/json", body: `{"accepted":true,"deduped":false,"event_id":"private"}`},
		{name: "duplicate member", status: http.StatusAccepted, contentType: "application/json", body: `{"accepted":true,"accepted":true,"deduped":false}`},
		{name: "missing member", status: http.StatusAccepted, contentType: "application/json", body: `{"accepted":true}`},
		{name: "not accepted", status: http.StatusAccepted, contentType: "application/json", body: `{"accepted":false,"deduped":false}`},
		{name: "202 deduped", status: http.StatusAccepted, contentType: "application/json", body: `{"accepted":true,"deduped":true}`},
		{name: "200 not deduped", status: http.StatusOK, contentType: "application/json", body: `{"accepted":true,"deduped":false}`},
		{name: "oversized", status: http.StatusAccepted, contentType: "application/json", body: strings.Repeat("x", maxResponseBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", test.contentType)
				writer.WriteHeader(test.status)
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()
			client, err := NewClient(server.URL, "crm-secret", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.DeliverLifecycleEvent(context.Background(), validLifecycleEvent())
			var ambiguous *AmbiguousResponseError
			if !errors.As(err, &ambiguous) || !IsRetryable(err) {
				t.Fatalf("error = %T %v, want retryable ambiguity", err, err)
			}
		})
	}
}

func TestLifecycleJSONContentTypeIsExact(t *testing.T) {
	t.Parallel()
	for _, values := range [][]string{{"application/json"}, {"application/json; charset=utf-8"}} {
		if !hasJSONContentType(values) {
			t.Fatalf("valid content type %#v rejected", values)
		}
	}
	for _, values := range [][]string{nil, {"text/plain"}, {"application/json; charset=iso-8859-1"}, {"application/json; profile=v1"}, {"application/json", "text/plain"}} {
		if hasJSONContentType(values) {
			t.Fatalf("ambiguous content type %#v accepted", values)
		}
	}
}

func TestLifecycleClientRejectsInvalidConfigurationAndEvent(t *testing.T) {
	t.Parallel()
	for _, baseURL := range []string{
		"", " http://localhost", "http://crm.example.com", "https://user:pass@crm.example.com",
		"https://crm.example.com/prefix", "https://crm.example.com?tenant=other",
	} {
		if _, err := NewClient(baseURL, "key", nil); err == nil {
			t.Fatalf("base URL %q accepted", baseURL)
		}
	}
	for _, bearer := range []string{"", " key", "key\n", strings.Repeat("x", maxBearerCredential+1)} {
		if _, err := NewClient("https://crm.example.com", bearer, nil); err == nil {
			t.Fatalf("bearer %q accepted", bearer)
		}
	}
	if _, err := NewClient("http://127.0.0.1:8080", "key", nil); err != nil {
		t.Fatalf("loopback development URL rejected: %v", err)
	}

	client, err := NewClient("https://crm.example.com", "key", nil)
	if err != nil {
		t.Fatal(err)
	}
	event := validLifecycleEvent()
	event.DocumentID = ""
	if _, err := client.DeliverLifecycleEvent(context.Background(), event); err == nil {
		t.Fatal("invalid event accepted")
	}
}

func TestLifecycleRetryAfterIsBounded(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
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

func TestLifecycleRetryMarkers(t *testing.T) {
	t.Parallel()
	if IsRetryable(context.Canceled) {
		t.Fatal("caller cancellation must not retry")
	}
	if !IsRetryable(context.DeadlineExceeded) {
		t.Fatal("deadline failure should retry")
	}
	if !IsRetryable(&TransportError{err: errors.New("network")}) {
		t.Fatal("transport failure should retry")
	}
}
