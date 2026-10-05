package http

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAuthoredJSONMutationsUsePinnedOriginAndDecodeResponses(t *testing.T) {
	for _, tc := range []struct {
		name, method string
		call         func(*Client, context.Context, any) error
	}{
		{"put", http.MethodPut, func(c *Client, ctx context.Context, out any) error {
			return c.PutJSON(ctx, "https://api.example.test/v1/items/42", map[string]string{"name": "updated"}, out)
		}},
		{"patch", http.MethodPatch, func(c *Client, ctx context.Context, out any) error {
			return c.PatchJSON(ctx, "https://api.example.test/v1/items/42", map[string]string{"name": "updated"}, out)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &Client{
				Bearer: "test-secret", CredentialOrigin: "https://api.example.test",
				HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					body, err := io.ReadAll(req.Body)
					if err != nil || req.Method != tc.method || req.URL.Host != "api.example.test" ||
						req.Header.Get("Authorization") != "Bearer test-secret" ||
						req.Header.Get("Content-Type") != "application/json" || string(body) != `{"name":"updated"}` {
						t.Errorf("mutation request: method=%s origin=%s content-type=%s body=%q err=%v", req.Method, req.URL.Host, req.Header.Get("Content-Type"), body, err)
					}
					return testResponse(http.StatusOK, nil, `{"id":"42"}`), nil
				})},
			}
			var out struct {
				ID string `json:"id"`
			}
			if err := tc.call(client, context.Background(), &out); err != nil || out.ID != "42" || calls != 1 {
				t.Fatalf("mutation result: out=%+v calls=%d err=%v", out, calls, err)
			}
		})
	}
}

func TestAuthoredBodylessMutationsAcceptEmptyNoContentResponse(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		for _, status := range []int{http.StatusNoContent, http.StatusResetContent} {
			client := &Client{
				Bearer: "test-secret", CredentialOrigin: "https://api.example.test",
				HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.Method != method || req.Body != nil || req.Header.Get("Authorization") != "Bearer test-secret" {
						t.Errorf("unexpected %s request: method=%s body=%v", method, req.Method, req.Body)
					}
					return testResponse(status, nil, ""), nil
				})},
			}
			var out map[string]any
			var err error
			if method == http.MethodPut {
				err = client.Put(context.Background(), "https://api.example.test/v1/items/42", &out)
			} else {
				err = client.Delete(context.Background(), "https://api.example.test/v1/items/42", &out)
			}
			if err != nil || out != nil {
				t.Fatalf("%s status %d: out=%v err=%v", method, status, out, err)
			}
		}
	}
}

func TestAuthoredMutationsDoNotRetryWithoutProviderIdempotencyContract(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			hits := 0
			client := &Client{
				Bearer: "test-secret", CredentialOrigin: "https://api.example.test",
				Retry: Retry{Max: 3, BaseDelay: time.Millisecond},
				HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					hits++
					return testResponse(http.StatusInternalServerError, nil, "provider may have committed"), nil
				})},
			}
			var err error
			switch method {
			case http.MethodPut:
				err = client.PutJSON(context.Background(), "https://api.example.test/items/42", map[string]int{"x": 1}, nil)
			case http.MethodPatch:
				err = client.PatchJSON(context.Background(), "https://api.example.test/items/42", map[string]int{"x": 1}, nil)
			case http.MethodDelete:
				err = client.Delete(context.Background(), "https://api.example.test/items/42", nil)
			}
			var apiErr *Error
			if !errors.As(err, &apiErr) || apiErr.Status != http.StatusInternalServerError || hits != 1 {
				t.Fatalf("ambiguous mutation: err=%v hits=%d, want one HTTP 500", err, hits)
			}
		})
	}
}

func TestAuthoredMutationsRetryWithConfirmedProviderIdempotency(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			hits := 0
			firstBody := ""
			client := &Client{
				Bearer: "test-secret", CredentialOrigin: "https://api.example.test",
				Headers: map[string]string{"Idempotency-Key": "provider-confirmed-key"},
				Retry:   Retry{Max: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond, UnsafeWithIdempotencyKey: true},
				HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					hits++
					body := ""
					if req.Body != nil {
						raw, err := io.ReadAll(req.Body)
						if err != nil {
							t.Errorf("read attempt body: %v", err)
						}
						body = string(raw)
					}
					if req.Method != method || req.Header.Get("Idempotency-Key") != "provider-confirmed-key" {
						t.Errorf("attempt %d lost method or provider key", hits)
					}
					if hits == 1 {
						firstBody = body
						return testResponse(http.StatusInternalServerError, nil, "transient"), nil
					}
					if body != firstBody {
						t.Errorf("retry changed request body: first=%q retry=%q", firstBody, body)
					}
					return testResponse(http.StatusNoContent, nil, ""), nil
				})},
			}
			var err error
			switch method {
			case http.MethodPut:
				err = client.PutJSON(context.Background(), "https://api.example.test/items/42", map[string]int{"x": 1}, nil)
			case http.MethodPatch:
				err = client.PatchJSON(context.Background(), "https://api.example.test/items/42", map[string]int{"x": 1}, nil)
			case http.MethodDelete:
				err = client.Delete(context.Background(), "https://api.example.test/items/42", nil)
			}
			if err != nil || hits != 2 {
				t.Fatalf("confirmed mutation retry: err=%v hits=%d", err, hits)
			}
		})
	}
}

func TestAuthoredMutationsInheritDryRunAndOriginFences(t *testing.T) {
	calls := 0
	client := &Client{
		Bearer: "test-secret", CredentialOrigin: "https://api.example.test",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return testResponse(http.StatusOK, nil, `{}`), nil
		})},
	}
	methods := []func() error{
		func() error {
			return client.PutJSON(context.Background(), "https://evil.example.test/items", map[string]int{"x": 1}, nil)
		},
		func() error { return client.Put(context.Background(), "https://evil.example.test/items", nil) },
		func() error {
			return client.PatchJSON(context.Background(), "https://evil.example.test/items", map[string]int{"x": 1}, nil)
		},
		func() error { return client.Delete(context.Background(), "https://evil.example.test/items", nil) },
	}
	for _, call := range methods {
		if err := call(); !errors.Is(err, ErrCredentialOrigin) {
			t.Fatalf("foreign-origin mutation = %v, want ErrCredentialOrigin", err)
		}
	}
	if calls != 0 {
		t.Fatalf("foreign origin reached transport %d times", calls)
	}
	t.Setenv("REACTOR_MODE", "dry_run")
	for _, call := range methods {
		if err := call(); !errors.Is(err, ErrDryRun) {
			t.Fatalf("dry-run mutation = %v, want ErrDryRun", err)
		}
	}
	if calls != 0 {
		t.Fatalf("dry-run mutation reached transport %d times", calls)
	}
}

func TestAuthoredMutationsBoundAndRedactRequestAndResponseData(t *testing.T) {
	const private = "customer-secret-canary"
	calls := 0
	client := &Client{
		Bearer: "test-secret", CredentialOrigin: "https://api.example.test",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return testResponse(http.StatusUnprocessableEntity, nil, private), nil
		})},
	}
	if err := client.PutJSON(context.Background(), "https://api.example.test/%zz?token=secret", map[string]int{"x": 1}, nil); !errors.Is(err, ErrRequestURL) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("invalid request URL leaked data: %v", err)
	}
	if err := client.PatchJSON(context.Background(), "https://api.example.test/items", failingJSON(private), nil); !errors.Is(err, ErrRequestBody) || strings.Contains(err.Error(), private) {
		t.Fatalf("JSON encode error leaked data: %v", err)
	}
	if err := client.PutJSON(context.Background(), "https://api.example.test/items", strings.Repeat("x", maxJSONRequestBytes), nil); !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf("oversized JSON request = %v, want ErrRequestTooLarge", err)
	}
	if calls != 0 {
		t.Fatalf("invalid or oversized request reached transport %d times", calls)
	}
	err := client.Delete(context.Background(), "https://api.example.test/items", nil)
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnprocessableEntity || apiErr.Body != private || strings.Contains(err.Error(), private) {
		t.Fatalf("provider error handling: err=%v typed=%+v", err, apiErr)
	}
	if calls != 1 {
		t.Fatalf("provider request count = %d, want one", calls)
	}
	client.HTTPClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return testResponse(http.StatusOK, nil, strings.Repeat("x", maxResponseBytes+1)), nil
	})
	if err := client.Delete(context.Background(), "https://api.example.test/items", nil); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversized mutation response = %v, want bounded-read failure", err)
	}
	client.HTTPClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return testResponse(http.StatusOK, nil, `{}`), nil
	})
	out := failingResponseJSON(private)
	if err := client.PutJSON(context.Background(), "https://api.example.test/items", map[string]int{"x": 1}, &out); !errors.Is(err, ErrResponseDecode) || strings.Contains(err.Error(), private) {
		t.Fatalf("JSON decode error leaked provider data: %v", err)
	}
	client.HTTPClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       failingResponseReader{errors.New(private)},
		}, nil
	})
	if err := client.Delete(context.Background(), "https://api.example.test/items", nil); !errors.Is(err, ErrResponseRead) || strings.Contains(err.Error(), private) {
		t.Fatalf("response read error leaked provider data: %v", err)
	}
}

func TestAuthoredJSONMutationAcceptsExactBodyLimitWithoutEncoderNewline(t *testing.T) {
	writes := 0
	client := &Client{HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		writes++
		if req.Method != http.MethodPut || req.ContentLength != maxJSONRequestBytes {
			t.Errorf("boundary request: method=%s content length=%d", req.Method, req.ContentLength)
		}
		count, err := io.Copy(io.Discard, req.Body)
		if err != nil || count != maxJSONRequestBytes {
			t.Errorf("boundary body: bytes=%d err=%v", count, err)
		}
		return testResponse(http.StatusNoContent, nil, ""), nil
	})}}
	// A JSON string adds two quote bytes. Encoder's trailing newline is removed
	// before request construction and is not counted against the wire cap.
	body := strings.Repeat("x", maxJSONRequestBytes-2)
	if err := client.PutJSON(context.Background(), "https://api.example.test/items", body, nil); err != nil || writes != 1 {
		t.Fatalf("exact-limit JSON request: err=%v writes=%d", err, writes)
	}
}

type failingJSON string

func (s failingJSON) MarshalJSON() ([]byte, error) { return nil, errors.New(string(s)) }

type failingResponseJSON string

func (s *failingResponseJSON) UnmarshalJSON([]byte) error { return errors.New(string(*s)) }

type failingResponseReader struct{ err error }

func (r failingResponseReader) Read([]byte) (int, error) { return 0, r.err }
func (failingResponseReader) Close() error               { return nil }
