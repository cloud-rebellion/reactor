package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"testing"
)

func TestTransportErrorCannotExposeRequestOrCredential(t *testing.T) {
	const cursor = "private-cursor-123"
	const token = "private-bearer-456"
	client := &Client{
		Bearer: token, CredentialOrigin: "https://api.example.test",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("proxy failed for %s with %s: %w", r.URL, r.Header.Get("Authorization"), io.EOF)
		})},
	}
	err := client.Get(context.Background(), "https://api.example.test/items?cursor="+cursor, nil)
	if !errors.Is(err, ErrTransport) || !errors.Is(err, io.EOF) {
		t.Fatalf("transport failure lost safe classification: %v", err)
	}
	for _, forbidden := range []string{cursor, token, "api.example.test", "proxy failed"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("transport failure exposed %q: %v", forbidden, err)
		}
	}

	client.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected transport error for " + r.URL.String() + " with " + r.Header.Get("Authorization"))
	})
	_, _, _, err = client.GetRaw(context.Background(), "https://api.example.test/items?cursor="+cursor)
	if !errors.Is(err, ErrTransport) || strings.Contains(err.Error(), cursor) || strings.Contains(err.Error(), token) {
		t.Fatalf("arbitrary transport text reached workflow: %v", err)
	}
}

func TestTransportErrorKeepsSafeCancellationAndNetworkCategories(t *testing.T) {
	const sensitiveURL = "https://api.example.test/items?token=private"
	for _, tc := range []struct {
		name  string
		cause error
		want  error
	}{
		{name: "canceled", cause: context.Canceled, want: context.Canceled},
		{name: "deadline", cause: context.DeadlineExceeded, want: context.DeadlineExceeded},
		{name: "unexpected EOF", cause: io.ErrUnexpectedEOF, want: io.ErrUnexpectedEOF},
		{name: "closed", cause: net.ErrClosed, want: net.ErrClosed},
		{name: "reset", cause: syscall.ECONNRESET, want: syscall.ECONNRESET},
		{name: "refused", cause: syscall.ECONNREFUSED, want: syscall.ECONNREFUSED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := safeTransportError(&url.Error{Op: "Get " + sensitiveURL, URL: sensitiveURL,
				Err: fmt.Errorf("sensitive wrapper %s: %w", sensitiveURL, tc.cause)})
			if !errors.Is(err, tc.want) || strings.Contains(err.Error(), sensitiveURL) || strings.Contains(err.Error(), "sensitive wrapper") {
				t.Fatalf("transport classification or redaction failed: %v", err)
			}
		})
	}
	err := safeTransportError(&url.Error{Op: "Get", URL: sensitiveURL, Err: sensitiveTimeoutError{}})
	if !errors.Is(err, ErrTransportTimeout) || !errors.Is(err, ErrTransport) ||
		!IsRetryable(err) || strings.Contains(err.Error(), "private") {
		t.Fatalf("timeout classification or redaction failed: %v", err)
	}
}

type sensitiveTimeoutError struct{}

func (sensitiveTimeoutError) Error() string   { return "private upstream timeout details" }
func (sensitiveTimeoutError) Timeout() bool   { return true }
func (sensitiveTimeoutError) Temporary() bool { return true }

func TestRequestBodyReplayErrorCannotExposeBodyOrCredential(t *testing.T) {
	const body = "private-customer-payload"
	const token = "private-bearer-456"
	requests := 0
	client := &Client{
		Bearer: token, CredentialOrigin: "https://api.example.test",
		Retry: Retry{Max: 2},
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			requests++
			return testResponse(http.StatusServiceUnavailable, nil, "unavailable"), nil
		})},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://api.example.test/items?cursor=private-cursor", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.GetBody = func() (io.ReadCloser, error) {
		return nil, fmt.Errorf("replay %s with %s to %s", body, token, req.URL)
	}
	_, err = client.Do(req)
	if !errors.Is(err, ErrRequestBodyReplay) || requests != 1 {
		t.Fatalf("replay failure=%v requests=%d", err, requests)
	}
	for _, forbidden := range []string{body, token, "private-cursor", "api.example.test"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("replay failure exposed %q: %v", forbidden, err)
		}
	}

	// A broken custom replay callback must not turn a retried request into an
	// empty-body request after the provider has already seen attempt one.
	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://api.example.test/items", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.GetBody = func() (io.ReadCloser, error) { return nil, nil }
	_, err = client.Do(req)
	if !errors.Is(err, ErrRequestBodyReplay) || requests != 2 {
		t.Fatalf("nil replay body=%v requests=%d", err, requests)
	}
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		req, err = http.NewRequestWithContext(context.Background(), http.MethodGet,
			"https://api.example.test/items", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.GetBody = func() (io.ReadCloser, error) {
			return nil, fmt.Errorf("replay %s: %w", body, cause)
		}
		_, err = client.Do(req)
		if !errors.Is(err, cause) || strings.Contains(err.Error(), body) {
			t.Fatalf("replay cancellation or redaction failed: %v", err)
		}
	}
	if requests != 4 {
		t.Fatalf("broken replays should make exactly one request each: %d", requests)
	}
}
