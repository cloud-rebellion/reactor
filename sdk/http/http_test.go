package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	reactor "github.com/bright-interaction/reactor/sdk"
)

func TestClientGetHappyPath(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			t.Errorf("missing bearer header: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("User-Agent") != "test/1.0" {
			t.Errorf("user-agent = %q", r.Header.Get("User-Agent"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"hello": "world"})
	}))
	defer srv.Close()

	c := &Client{HTTPClient: srv.Client(), Bearer: "secret-token", CredentialOrigin: srv.URL, UserAgent: "test/1.0"}
	var out map[string]string
	if err := c.Get(context.Background(), srv.URL, &out); err != nil {
		t.Fatalf("get: %v", err)
	}
	if out["hello"] != "world" {
		t.Fatalf("unexpected body: %v", out)
	}
}

func TestClientGetRawUsesBoundedSDKResponseSurface(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		w.Header().Set("X-Source", "cms")
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()

	c := &Client{HTTPClient: srv.Client(), Retry: Retry{Max: 1}}
	status, headers, body, err := c.GetRaw(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("get raw: %v", err)
	}
	if status != http.StatusOK || headers["X-Source"] != "cms" || string(body) != "<html>ok</html>" {
		t.Fatalf("raw response = status %d headers %v body %q", status, headers, body)
	}
}

func TestClientGetRawRejectsOversizedResponse(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", maxResponseBytes+1))
	}))
	defer srv.Close()

	_, _, _, err := (&Client{HTTPClient: srv.Client(), Retry: Retry{Max: 1}}).GetRaw(context.Background(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized response error = %v, want explicit size failure", err)
	}
}

func TestDefaultClientRefusesRedirectsWithCredentials(t *testing.T) {
	t.Parallel()
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		if got := r.Header.Get("X-Api-Key"); got != "" {
			t.Errorf("redirect target received API key %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()

	c := &Client{Headers: map[string]string{"X-Api-Key": "secret"}, CredentialOrigin: source.URL, Retry: Retry{Max: 1}}
	status, _, _, err := c.GetRaw(context.Background(), source.URL)
	if err != nil {
		t.Fatalf("get raw: %v", err)
	}
	if status != http.StatusFound {
		t.Fatalf("status = %d, want %d from source", status, http.StatusFound)
	}
	if got := targetHits.Load(); got != 0 {
		t.Fatalf("redirect target received %d request(s)", got)
	}
}

func TestClientPostJSONReplaysBodyAfterRetry(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		if n == 1 {
			http.Error(w, "temporary", http.StatusInternalServerError)
			return
		}
		if string(body) != "{\"name\":\"reactor\"}" {
			t.Errorf("retry body = %q, want original JSON", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{}")
	}))
	defer srv.Close()

	err := (&Client{
		HTTPClient:       srv.Client(),
		Headers:          map[string]string{"Idempotency-Key": "stable-create-key"},
		CredentialOrigin: srv.URL,
		Retry:            Retry{Max: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond, UnsafeWithIdempotencyKey: true},
	}).PostJSON(context.Background(), srv.URL, map[string]string{"name": "reactor"}, nil)
	if err != nil {
		t.Fatalf("post json: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("hits = %d, want 2", hits.Load())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func testResponse(status int, headers http.Header, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body))}
}

func TestClientDoesNotRetryUnprotectedMutation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		key     string
		optIn   bool
		wantHit int
	}{
		{name: "no key", optIn: true, wantHit: 1},
		{name: "key without provider opt in", key: "stable-key", wantHit: 1},
		{name: "key and provider opt in", key: "stable-key", optIn: true, wantHit: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits int
			client := &Client{
				HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					hits++
					body, err := io.ReadAll(req.Body)
					if err != nil || string(body) != `{"create":"once"}` {
						t.Errorf("attempt %d body = %q, err = %v", hits, body, err)
					}
					if hits == 1 {
						return testResponse(http.StatusInternalServerError, nil, "committed but response failed"), nil
					}
					return testResponse(http.StatusOK, nil, `{}`), nil
				})},
				Headers:          map[string]string{"Idempotency-Key": tc.key},
				CredentialOrigin: "https://example.test",
				Retry: Retry{Max: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond,
					UnsafeWithIdempotencyKey: tc.optIn},
			}
			err := client.PostJSON(context.Background(), "https://example.test/create", map[string]string{"create": "once"}, nil)
			if tc.wantHit == 1 {
				var apiErr *Error
				if !errors.As(err, &apiErr) || apiErr.Status != http.StatusInternalServerError {
					t.Fatalf("unprotected mutation error = %v, want HTTP 500", err)
				}
			} else if err != nil {
				t.Fatalf("protected mutation retry: %v", err)
			}
			if hits != tc.wantHit {
				t.Fatalf("hits = %d, want %d", hits, tc.wantHit)
			}
		})
	}
}

func TestClientDoesNotRetryAmbiguousMutationTransportFailure(t *testing.T) {
	var hits int
	client := &Client{
		HTTPClient: &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			hits++
			return nil, io.EOF
		})},
		Retry: Retry{Max: 3, BaseDelay: time.Millisecond},
	}
	err := client.PostJSON(context.Background(), "https://example.test/create", map[string]string{"create": "once"}, nil)
	if !errors.Is(err, io.EOF) || hits != 1 {
		t.Fatalf("ambiguous mutation transport failure = %v, hits = %d; want EOF and one request", err, hits)
	}
}

func TestClientRetriesRateLimitOnRead(t *testing.T) {
	var hits int
	client := &Client{
		HTTPClient: &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			hits++
			if hits == 1 {
				return testResponse(http.StatusTooManyRequests, http.Header{"Retry-After": []string{"0"}}, "slow down"), nil
			}
			return testResponse(http.StatusOK, nil, `{}`), nil
		})},
		Retry: Retry{Max: 2, BaseDelay: time.Second},
	}
	if err := client.Get(context.Background(), "https://example.test/list", nil); err != nil {
		t.Fatalf("rate-limited read: %v", err)
	}
	if hits != 2 {
		t.Fatalf("hits = %d, want 2", hits)
	}
}

func TestClientDoesNotRetryBeforeLongRetryAfter(t *testing.T) {
	var hits int
	client := &Client{
		HTTPClient: &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			hits++
			return testResponse(http.StatusTooManyRequests, http.Header{"Retry-After": []string{"3600"}}, "slow down"), nil
		})},
		Retry: Retry{Max: 3, BaseDelay: time.Millisecond},
	}
	err := client.Get(context.Background(), "https://example.test/list", nil)
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusTooManyRequests || apiErr.RetryAfter != maxRetryAfterWait || !apiErr.RetryAfterLong {
		t.Fatalf("long rate limit error = %v, want typed 429 and bounded long-delay hint", err)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1", hits)
	}
}

func TestClientRejectsUnboundedRetryConfigurationBeforeNetwork(t *testing.T) {
	for _, tc := range []struct {
		name  string
		retry Retry
	}{
		{name: "negative attempts", retry: Retry{Max: -1}},
		{name: "attempt storm", retry: Retry{Max: maxHTTPAttempts + 1}},
		{name: "negative base", retry: Retry{Max: 2, BaseDelay: -time.Second}},
		{name: "negative ceiling", retry: Retry{Max: 2, MaxDelay: -time.Second}},
		{name: "long base", retry: Retry{Max: 2, BaseDelay: maxRetryAfterWait + time.Second, MaxDelay: maxRetryAfterWait + time.Second}},
		{name: "long ceiling", retry: Retry{Max: 2, MaxDelay: maxRetryAfterWait + time.Second}},
		{name: "base exceeds ceiling", retry: Retry{Max: 2, BaseDelay: 2 * time.Second, MaxDelay: time.Second}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits int
			client := &Client{
				Retry: tc.retry,
				HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					hits++
					return testResponse(http.StatusOK, nil, `{}`), nil
				})},
			}
			err := client.Get(context.Background(), "https://api.example.test/items", nil)
			if !errors.Is(err, ErrRetryConfig) || !reactor.IsPermanent(err) || hits != 0 {
				t.Fatalf("retry config error = %v, permanent = %t, hits = %d", err, reactor.IsPermanent(err), hits)
			}
		})
	}
}

func TestProviderErrorAndTransportURLStayOutOfStepErrorText(t *testing.T) {
	const secret = "sensitive-cursor-and-customer@example.test"
	client := &Client{HTTPClient: &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return testResponse(http.StatusTooManyRequests, nil, `{"detail":"`+secret+`"}`), nil
	})}}
	err := client.Get(context.Background(), "https://api.example.test/items", nil)
	var providerErr *Error
	if !errors.As(err, &providerErr) || !strings.Contains(providerErr.Body, secret) || strings.Contains(err.Error(), secret) {
		t.Fatalf("provider error leaked body: err=%v typed=%+v", err, providerErr)
	}

	client.HTTPClient.Transport = roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: "Get", URL: "https://api.example.test/items?cursor=" + secret, Err: io.EOF}
	})
	err = client.Get(context.Background(), "https://api.example.test/items?cursor="+secret, nil)
	if !errors.Is(err, io.EOF) || strings.Contains(err.Error(), secret) {
		t.Fatalf("transport error leaked cursor or lost classification: %v", err)
	}

	client.HTTPClient.Transport = roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return testResponse(http.StatusOK, nil, `{"detail":"`+secret+`"`), nil
	})
	err = client.Get(context.Background(), "https://api.example.test/items", &struct{}{})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("malformed JSON error leaked provider body: %v", err)
	}
}

func TestClientWaitsForRetryAfterWithoutReissuingRequest(t *testing.T) {
	var hits int
	client := &Client{
		HTTPClient: &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			hits++
			return testResponse(http.StatusTooManyRequests, http.Header{"Retry-After": []string{"1"}}, "slow down"), nil
		})},
		Retry: Retry{Max: 2, BaseDelay: time.Millisecond},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := client.Get(ctx, "https://example.test/list", nil)
	if !errors.Is(err, context.DeadlineExceeded) || hits != 1 {
		t.Fatalf("rate-limit wait = %v, hits = %d; want deadline and one request", err, hits)
	}
}

func TestRetryAfterParsesBoundedHTTPForms(t *testing.T) {
	now := time.Date(2026, time.October, 4, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, raw string
		want      time.Duration
		valid     bool
		tooLong   bool
	}{
		{name: "seconds", raw: "17", want: 17 * time.Second, valid: true},
		{name: "date", raw: now.Add(30 * time.Second).Format(http.TimeFormat), want: 30 * time.Second, valid: true},
		{name: "past date", raw: now.Add(-time.Minute).Format(http.TimeFormat), valid: true},
		{name: "huge seconds", raw: "3600", want: maxRetryAfterWait, valid: true, tooLong: true},
		{name: "huge date", raw: now.Add(time.Hour).Format(http.TimeFormat), want: maxRetryAfterWait, valid: true, tooLong: true},
		{name: "overflow", raw: "999999999999999999999", want: maxRetryAfterWait, valid: true, tooLong: true},
		{name: "invalid", raw: "next week", valid: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, valid, tooLong := retryAfter(tc.raw, now)
			if d != tc.want || valid != tc.valid || tooLong != tc.tooLong {
				t.Fatalf("retryAfter(%q) = (%s, %t, %t), want (%s, %t, %t)", tc.raw, d, valid, tooLong, tc.want, tc.valid, tc.tooLong)
			}
		})
	}
}

func TestWorkflowClientBlocksPrivateDestinationEvenWithCustomClient(t *testing.T) {
	t.Setenv("REACTOR_WORKFLOW", "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("must not reach"))
	}))
	defer srv.Close()
	c := &Client{HTTPClient: srv.Client(), Retry: Retry{Max: 1}}
	if _, _, _, err := c.GetRaw(context.Background(), srv.URL); err == nil {
		t.Fatal("workflow HTTP client reached a private destination")
	}
}

func TestWorkflowClientsReusePolicySeparatedSafeTransports(t *testing.T) {
	t.Setenv("REACTOR_WORKFLOW", "1")
	publicA := (&Client{}).client()
	publicB := (&Client{HTTPClient: &http.Client{}}).client()
	privateA := (&Client{AllowPrivateNetwork: true}).client()
	privateB := (&Client{AllowPrivateNetwork: true, HTTPClient: &http.Client{}}).client()
	if publicA != publicB || privateA != privateB || publicA == privateA {
		t.Fatal("workflow HTTP clients must share one transport per network policy and ignore custom clients")
	}
}

func TestWorkflowClientPrivateDestinationRequiresExplicitOptIn(t *testing.T) {
	t.Setenv("REACTOR_WORKFLOW", "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("allowed"))
	}))
	defer srv.Close()
	c := &Client{AllowPrivateNetwork: true, Retry: Retry{Max: 1}}
	_, _, body, err := c.GetRaw(context.Background(), srv.URL)
	if err != nil || string(body) != "allowed" {
		t.Fatalf("explicit private-network opt-in: body=%q err=%v", body, err)
	}
}

func TestWorkflowClientBlocksOutboundHTTPDuringDryRun(t *testing.T) {
	t.Setenv("REACTOR_MODE", "dry_run")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("dry-run HTTP request reached the server")
	}))
	defer srv.Close()

	c := &Client{HTTPClient: srv.Client(), AllowPrivateNetwork: true, Retry: Retry{Max: 1}}
	if _, _, _, err := c.GetRaw(context.Background(), srv.URL); !errors.Is(err, ErrDryRun) {
		t.Fatalf("dry-run error = %v, want ErrDryRun", err)
	}
}

func TestClientRetryOn5xx(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := hits.Add(1)
		if n < 3 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := &Client{
		HTTPClient: srv.Client(),
		Retry:      Retry{Max: 4, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond},
	}
	var out map[string]bool
	if err := c.Get(context.Background(), srv.URL, &out); err != nil {
		t.Fatalf("get: %v", err)
	}
	if hits.Load() != 3 {
		t.Fatalf("hits = %d, want 3 (two 500s + one 200)", hits.Load())
	}
}

func TestClientNon2xxReturnsError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()
	c := &Client{HTTPClient: srv.Client(), Retry: Retry{Max: 1}}
	err := c.Get(context.Background(), srv.URL, nil)
	if err == nil {
		t.Fatalf("want error")
	}
	apiErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("err type = %T, want *Error", err)
	}
	if apiErr.Status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", apiErr.Status)
	}
}

func TestIsRetryable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{&Error{Status: 500}, true},
		{&Error{Status: 502}, true},
		{&Error{Status: 408}, true},
		{&Error{Status: 429}, true},
		{&Error{Status: 400}, false},
		{&Error{Status: 404}, false},
		{context.DeadlineExceeded, false},
		{ErrRetryConfig, false},
		{reactor.Permanent(ErrRetryConfig), false},
		{ErrRequestURL, false},
		{ErrResponseDecode, false},
		{ErrPageURL, false},
		{errors.New("unknown authoring failure"), false},
		{ErrTransport, true},
		{io.EOF, true},
		{syscall.ECONNRESET, true},
	}
	for _, tc := range cases {
		if got := IsRetryable(tc.err); got != tc.want {
			t.Errorf("IsRetryable(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestClientStaticHeaders(t *testing.T) {
	var gotAuth, gotVer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotVer = r.Header.Get("Notion-Version")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	// Headers cover non-Bearer auth (a raw token) + a version pin, and a
	// Headers Authorization overrides the Bearer default.
	c := &Client{Bearer: "should-be-overridden", CredentialOrigin: srv.URL, Headers: map[string]string{
		"Authorization":  "raw-token-123",
		"Notion-Version": "2022-06-28",
	}}
	if err := c.Get(context.Background(), srv.URL, nil); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "raw-token-123" {
		t.Fatalf("Authorization = %q, want raw-token-123 (Headers should win over Bearer)", gotAuth)
	}
	if gotVer != "2022-06-28" {
		t.Fatalf("Notion-Version = %q", gotVer)
	}
}
