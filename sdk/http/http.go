// Package http is the workflow-side HTTP client helper. AI-generated
// workflows import this instead of building net/http calls from scratch
// so retry, timeout, JSON encoding, and bearer auth all converge on
// one tested implementation.
//
// All requests must carry context.Context with a timeout (the
// codegen lint rule h_timeout enforces this) so this package never
// dials without a deadline.
package http

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bright-interaction/reactor/internal/safehttp"
	reactor "github.com/bright-interaction/reactor/sdk"
)

// DefaultClient is a preconfigured instance callers may reuse. Its bounded
// timeout and connection pooling match the codegen prompt's guidance.
var DefaultClient = &Client{
	Retry: Retry{
		Max:       3,
		BaseDelay: 250 * time.Millisecond,
		MaxDelay:  10 * time.Second,
		Jitter:    true,
	},
}

var defaultHostClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		// Headers may contain API keys and other upstream credentials. Never
		// forward them to a redirect target outside the configured URL.
		return http.ErrUseLastResponse
	},
}

// Workflow clients are shared per network policy so retries and many workflow
// instances reuse the guarded transports and their idle connection pools.
var workflowPublicClient = safehttp.Client(false)
var workflowPrivateClient = safehttp.Client(true)

const (
	maxResponseBytes    = 4 << 20
	maxJSONRequestBytes = 16 << 20
	maxHTTPAttempts     = 10
)

// Keep short rate-limit waits local; longer waits need a durable Step retry so
// one throttled provider cannot occupy a worker for minutes.
const maxRetryAfterWait = reactor.MaxAutomaticRetryAfter

// ErrDryRun is returned before any network request when a workflow is being
// reviewed in Reactor's dry-run mode. Connectors built on this package inherit
// the same side-effect fence.
var ErrDryRun = errors.New("reactor: outbound HTTP is disabled during dry run")

// ErrCredentialOrigin means a credential-bearing request had no trusted origin
// pin, or its destination did not exactly match that origin. Its text never
// includes the URL, which may contain sensitive query parameters.
var ErrCredentialOrigin = errors.New("reactor: credential request requires a matching pinned origin")

// ErrRequestURL does not echo an invalid URL, which can carry API keys and
// pagination cursors in its query string.
var ErrRequestURL = errors.New("reactor: invalid outbound HTTP request")

// ErrRequestBody is returned when a JSON body cannot be encoded without
// copying a custom marshaler's potentially sensitive error into Step logs.
var ErrRequestBody = errors.New("reactor: could not encode request JSON")

// ErrRequestBodyReplay hides custom GetBody errors, which may echo the body,
// request URL, or credential headers while preparing a retry.
var ErrRequestBodyReplay = errors.New("reactor: could not replay request body")

// ErrRequestTooLarge keeps generated JSON mutations within a bounded payload.
var ErrRequestTooLarge = errors.New("reactor: request JSON exceeds 16 MiB limit")

// ErrRetryConfig is a permanent authoring error. An accidental huge attempt
// count or delay must not hold a worker slot or flood an upstream service.
var ErrRetryConfig = errors.New("reactor: invalid outbound HTTP retry configuration (attempts 0..10, delays up to 30s, base no greater than max)")

// Provider body read and decode errors are sanitized because custom readers
// and JSON unmarshalers can return errors containing untrusted response data.
var (
	ErrResponseRead     = errors.New("reactor: could not read provider response")
	ErrResponseTooLarge = errors.New("reactor: response exceeds 4 MiB limit")
	ErrResponseDecode   = errors.New("reactor: invalid provider JSON response")
	// ErrTransport hides arbitrary transport text, which can include the full
	// request URL, credential headers, or a provider-supplied cursor.
	ErrTransport        = errors.New("reactor: outbound HTTP transport failed")
	ErrTransportTimeout = fmt.Errorf("%w: timeout", ErrTransport)
)

// IsDryRun reports whether the current workflow execution is a review dry run.
// Workflow authors can use this to select a fixture or skip an external
// mutation; outbound SDK requests are blocked independently by Client.Do.
func IsDryRun() bool { return os.Getenv("REACTOR_MODE") == "dry_run" }

// Client wraps net/http.Client with retry + jitter + bearer auth
// helpers. Construct one per upstream + reuse so connection pooling
// works.
type Client struct {
	HTTPClient *http.Client
	Retry      Retry

	// CredentialOrigin is the trusted scheme and authority for credential-bearing
	// requests, e.g. "https://api.example.com". Set it from reviewed provider
	// configuration, never from webhook or provider response data. When Bearer,
	// Headers, or an explicit request credential is present, Do refuses a missing
	// or mismatched pin before adding headers or making a network request.
	CredentialOrigin string

	// AllowPrivateNetwork opts a reviewed workflow into loopback, RFC1918,
	// and other private destinations. Workflow subprocesses use the SSRF-safe
	// client by default; link-local and metadata ranges remain blocked even
	// when this is true.
	AllowPrivateNetwork bool

	// Bearer, when non-empty, is sent as Authorization: Bearer <value>
	// on every request. Workflows fetch this via vault.MustGet so the
	// value is encrypted at rest + redacted on accidental log.
	Bearer string

	// UserAgent override; defaults to "reactor-sdk/0.1".
	UserAgent string

	// Headers are static headers sent on every request. Use this for auth
	// shapes Bearer does not cover: a raw token (ClickUp "Authorization: <t>"),
	// an API-key header (Storyblok, Shortcut), a version pin (Notion-Version),
	// or HTTP Basic ("Authorization: Basic <base64>"). Set per upstream and
	// reuse the client. Values here win over the Bearer default.
	Headers map[string]string
}

// Retry configures the exponential-backoff-with-jitter retry loop. The
// codegen prompt's h_retry-jitter entry teaches this shape; mirroring
// it in the SDK reduces what the AI has to emit per workflow.
//
// Mirrors the field semantics of sdk.ExpBackoff (Max, Base, Cap) so
// authors learn one shape: BaseDelay aliases Base, MaxDelay aliases
// Cap. RetryFromExpBackoff is the one-liner adapter when an author
// already constructed an reactor.ExpBackoff for a Step retry policy.
type Retry struct {
	Max       int           // total attempts (0 or 1 = no retry; maximum 10)
	BaseDelay time.Duration // delay before attempt 2 (alias of reactor.ExpBackoff.Base); 0 defaults to 250ms
	MaxDelay  time.Duration // upper bound on per-attempt delay (alias of reactor.ExpBackoff.Cap); 0 defaults to 10s
	Jitter    bool          // when true, sleep is uniform[0, computed]
	// UnsafeWithIdempotencyKey permits retries of mutations only when the
	// request carries a non-empty Idempotency-Key header. Set this only after
	// confirming that the upstream honors that header for this operation.
	UnsafeWithIdempotencyKey bool
}

// RetryFromExpBackoff converts the reactor SDK's RetryPolicy shape to
// the http.Client Retry shape. Jitter defaults to true so http
// retries pick up the full-jitter behaviour ExpBackoff already
// provides for Step retries.
//
// Usage:
//
//	c := &http.Client{Retry: http.RetryFromExpBackoff(reactor.ExpBackoff{Max: 5, Base: 100*time.Millisecond})}
func RetryFromExpBackoff(max int, base, ceiling time.Duration) Retry {
	return Retry{
		Max:       max,
		BaseDelay: base,
		MaxDelay:  ceiling,
		Jitter:    true,
	}
}

// Get fetches url and decodes the JSON response into out. Non-2xx responses
// return a typed Error whose loggable text excludes the upstream body.
func (c *Client) Get(ctx context.Context, url string, out any) error {
	req, err := newRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	return c.doDecode(req, out)
}

// GetRaw fetches a response without requiring JSON decoding. It keeps the
// same context, timeout, retry, and header policy as Get and PostJSON, while
// returning bounded response bytes for HTML or other text APIs. Workflow code
// should use this instead of importing net/http directly.
func (c *Client) GetRaw(ctx context.Context, url string) (status int, headers map[string]string, body []byte, err error) {
	req, err := newRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, readErr := readBounded(resp.Body)
	if readErr != nil {
		return resp.StatusCode, nil, nil, fmt.Errorf("read response: %w", readErr)
	}
	headers = make(map[string]string, len(resp.Header))
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}
	return resp.StatusCode, headers, raw, nil
}

// PostJSON sends a JSON body + decodes the JSON response into out.
func (c *Client) PostJSON(ctx context.Context, url string, body, out any) error {
	return c.jsonMutation(ctx, http.MethodPost, url, body, out)
}

// PutJSON replaces or creates a resource with a JSON body. Like PostJSON, it
// makes one attempt unless the caller has opted into provider-confirmed
// Idempotency-Key retries on the Client.
func (c *Client) PutJSON(ctx context.Context, url string, body, out any) error {
	return c.jsonMutation(ctx, http.MethodPut, url, body, out)
}

// Put sends a bodyless PUT for provider actions that require an empty request
// body, such as publishing a previously created resource. Use PutJSON when the
// provider expects a JSON representation instead.
func (c *Client) Put(ctx context.Context, url string, out any) error {
	req, err := newRequest(ctx, http.MethodPut, url, nil)
	if err != nil {
		return err
	}
	return c.doDecode(req, out)
}

// PatchJSON applies a partial JSON update. It does not retry a mutation unless
// the provider's Idempotency-Key contract is explicitly enabled on the Client.
func (c *Client) PatchJSON(ctx context.Context, url string, body, out any) error {
	return c.jsonMutation(ctx, http.MethodPatch, url, body, out)
}

// Delete removes a resource and optionally decodes a JSON response. An empty
// 204 or 205 response succeeds even when out is non-nil. It does not retry by
// default because an upstream failure may happen after the deletion commits.
func (c *Client) Delete(ctx context.Context, url string, out any) error {
	req, err := newRequest(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	return c.doDecode(req, out)
}

func (c *Client) jsonMutation(ctx context.Context, method, url string, body, out any) error {
	var encoded boundedJSONBuffer
	if err := json.NewEncoder(&encoded).Encode(body); err != nil {
		if errors.Is(err, ErrRequestTooLarge) {
			return ErrRequestTooLarge
		}
		return ErrRequestBody
	}
	// Encoder appends a newline; omit it so the wire format remains identical
	// to json.Marshal and the limit applies to the actual HTTP body.
	raw := encoded.Bytes()
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return ErrRequestBody
	}
	raw = raw[:len(raw)-1]
	req, err := newRequest(ctx, method, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.doDecode(req, out)
}

// boundedJSONBuffer limits retained request bytes during encoding. Go's
// standard JSON encoder still builds its internal buffer before Write, so a
// configured workflow cgroup or host memory limit is the backstop for a custom
// marshaler or an enormous value. This avoids json.Marshal's extra full-size
// copy; it does not guarantee bounded peak encoder memory by itself.
type boundedJSONBuffer struct{ bytes.Buffer }

func (b *boundedJSONBuffer) Write(p []byte) (int, error) {
	if len(p) > maxJSONRequestBytes+1-b.Len() { // include Encoder's newline
		return 0, ErrRequestTooLarge
	}
	return b.Buffer.Write(p)
}

func newRequest(ctx context.Context, method, target string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, ErrRequestURL
	}
	return req, nil
}

// Do executes req under the retry policy. Returns the response body
// + status. The caller is responsible for closing the body when not
// using the JSON helpers.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if IsDryRun() {
		return nil, ErrDryRun
	}
	if req == nil || req.URL == nil {
		return nil, errors.New("reactor: HTTP request is required")
	}
	if (c.CredentialOrigin != "" || c.Bearer != "" || len(c.Headers) != 0 || hasRequestCredential(req)) &&
		!matchesCredentialOrigin(c.CredentialOrigin, req.URL) {
		return nil, reactor.Permanent(ErrCredentialOrigin)
	}
	if err := c.validateRetry(); err != nil {
		return nil, reactor.Permanent(err)
	}
	c.applyHeaders(req)
	canRetry := c.canRetry(req)
	maxAttempts := c.maxAttempts()
	attempt := 0
	for {
		attempt++
		resp, err := c.client().Do(req)
		if !canRetry || attempt >= maxAttempts || !retryableResponse(resp, err) {
			if err != nil {
				return nil, fmt.Errorf("attempt %d/%d: %w", attempt, maxAttempts, safeTransportError(err))
			}
			return resp, nil
		}
		delay := c.delay(attempt)
		if resp != nil {
			if after, valid, tooLong := retryAfter(resp.Header.Get("Retry-After"), time.Now()); valid {
				if tooLong {
					// Do not retry before the upstream permits it. Leave the
					// response available so the caller can reschedule the Step.
					return resp, nil
				}
				delay = after
			}
			// Drain only a bounded amount; a failing upstream can return an
			// unbounded body and must not hold a worker indefinitely.
			_, _ = io.CopyN(io.Discard, resp.Body, 64<<10)
			resp.Body.Close()
		}
		// net/http closes and consumes a request body after Do returns. Reset
		// replayable bodies before a retry; resending a POST with an empty body
		// turns a transient upstream failure into silent data loss.
		if req.Body != nil {
			if req.GetBody == nil {
				return nil, ErrRequestBodyReplay
			}
			body, bodyErr := req.GetBody()
			if bodyErr != nil {
				if body != nil {
					body.Close()
				}
				if errors.Is(bodyErr, context.Canceled) {
					return nil, context.Canceled
				}
				if errors.Is(bodyErr, context.DeadlineExceeded) {
					return nil, context.DeadlineExceeded
				}
				return nil, ErrRequestBodyReplay
			}
			if body == nil {
				return nil, ErrRequestBodyReplay
			}
			req.Body = body
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-req.Context().Done():
			timer.Stop()
			return nil, req.Context().Err()
		}
	}
}

func hasRequestCredential(req *http.Request) bool {
	if req.URL.User != nil {
		return true
	}
	for _, header := range []string{
		"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key",
		"Api-Key", "X-Auth-Token", "X-Client-Secret",
	} {
		if req.Header.Get(header) != "" {
			return true
		}
	}
	// A few providers carry credentials in query parameters. This recognizes
	// common names, but cannot infer every provider-specific key. Authors must
	// set CredentialOrigin for any other credential-bearing query shape.
	if req.URL.RawQuery != "" {
		values, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil {
			return true
		}
		for key := range values {
			key = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", ""), "_", ""))
			switch key {
			case "key", "apikey", "apitoken", "accesstoken", "token", "clientsecret", "password", "secret":
				return true
			}
		}
	}
	return false
}

func matchesCredentialOrigin(raw string, target *url.URL) bool {
	if raw == "" || target == nil {
		return false
	}
	pin, err := url.Parse(raw)
	if err != nil || pin == nil || (!strings.EqualFold(pin.Scheme, "https") && !strings.EqualFold(pin.Scheme, "http")) ||
		pin.Host == "" || pin.User != nil || pin.Opaque != "" || pin.Path != "" ||
		pin.RawPath != "" || pin.RawQuery != "" || pin.Fragment != "" || pin.ForceQuery {
		return false
	}
	if !strings.EqualFold(target.Scheme, pin.Scheme) || target.User != nil || target.Opaque != "" ||
		!strings.EqualFold(target.Hostname(), pin.Hostname()) || pin.Hostname() == "" {
		return false
	}
	pinPort, pinOK := effectiveOriginPort(pin)
	targetPort, targetOK := effectiveOriginPort(target)
	return pinOK && targetOK && pinPort == targetPort
}

func effectiveOriginPort(u *url.URL) (int, bool) {
	if u == nil || u.Host == "" || strings.HasSuffix(u.Host, ":") {
		return 0, false
	}
	if raw := u.Port(); raw != "" {
		port, err := strconv.Atoi(raw)
		return port, err == nil && port >= 1 && port <= 65535
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return 443, true
	case "http":
		return 80, true
	default:
		return 0, false
	}
}

// net/http wraps transport failures in url.Error, whose text embeds the full
// request URL. The inner error is not trustworthy either: proxy and custom
// transport errors can repeat query values or credential headers. Preserve
// only safe sentinel categories, never the original error text or URL Op.
func safeTransportError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, io.EOF):
		return fmt.Errorf("%w: %w", ErrTransport, io.EOF)
	case errors.Is(err, io.ErrUnexpectedEOF):
		return fmt.Errorf("%w: %w", ErrTransport, io.ErrUnexpectedEOF)
	case errors.Is(err, net.ErrClosed):
		return fmt.Errorf("%w: %w", ErrTransport, net.ErrClosed)
	case errors.Is(err, syscall.ECONNRESET):
		return fmt.Errorf("%w: %w", ErrTransport, syscall.ECONNRESET)
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Errorf("%w: %w", ErrTransport, syscall.ECONNREFUSED)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ErrTransportTimeout
	}
	return ErrTransport
}

func (c *Client) canRetry(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return c.Retry.UnsafeWithIdempotencyKey && strings.TrimSpace(req.Header.Get("Idempotency-Key")) != ""
	}
}

func retryableResponse(resp *http.Response, err error) bool {
	if err != nil {
		return true
	}
	if resp == nil {
		return false
	}
	return resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
}

// retryAfter parses the standard delta-seconds or HTTP-date forms. A delay
// above our bounded in-worker wait is reported separately so Do can return the
// response rather than disobey a provider's rate-limit window.
func retryAfter(raw string, now time.Time) (delay time.Duration, valid, tooLong bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false, false
	}
	if allDigits(raw) {
		seconds, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return maxRetryAfterWait, true, true
		}
		if seconds > int64(maxRetryAfterWait/time.Second) {
			return maxRetryAfterWait, true, true
		}
		return time.Duration(seconds) * time.Second, true, false
	}
	date, err := http.ParseTime(raw)
	if err != nil {
		return 0, false, false
	}
	delay = date.Sub(now)
	if delay < 0 {
		delay = 0
	}
	if delay > maxRetryAfterWait {
		return maxRetryAfterWait, true, true
	}
	return delay, true, false
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func (c *Client) doDecode(req *http.Request, out any) error {
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, readErr := readBounded(resp.Body)
	if readErr != nil {
		return fmt.Errorf("read response: %w", readErr)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil || (len(body) == 0 && (resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusResetContent)) {
			return nil
		}
		if err := json.Unmarshal(body, out); err != nil {
			return ErrResponseDecode
		}
		return nil
	}
	after, valid, tooLong := retryAfter(resp.Header.Get("Retry-After"), time.Now())
	if !valid {
		after = 0
	}
	return &Error{Status: resp.StatusCode, Body: string(body), RetryAfter: after, RetryAfterLong: tooLong}
}

func readBounded(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxResponseBytes+1))
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, ErrResponseRead
	}
	if len(body) > maxResponseBytes {
		return nil, ErrResponseTooLarge
	}
	return body, nil
}

func (c *Client) applyHeaders(req *http.Request) {
	if c.Bearer != "" && req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+c.Bearer)
	}
	// Static headers (custom auth, version pins). Set after Bearer so they win.
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	ua := c.UserAgent
	if ua == "" {
		ua = "reactor-sdk/0.1"
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", ua)
	}
}

func (c *Client) client() *http.Client {
	if os.Getenv("REACTOR_WORKFLOW") == "1" {
		// Workflow code cannot bypass this branch with a custom net/http
		// transport because direct net/http imports are rejected by the
		// authoring gate.
		if c.AllowPrivateNetwork {
			return workflowPrivateClient
		}
		return workflowPublicClient
	}
	if c.HTTPClient != nil {
		// An injected client may follow redirects and copy custom credential
		// headers such as X-Api-Key to another origin. Preserve its transport,
		// timeout, and connection pool without trusting its redirect policy.
		return &http.Client{
			Transport: c.HTTPClient.Transport,
			Timeout:   c.HTTPClient.Timeout,
			Jar:       c.HTTPClient.Jar,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return defaultHostClient
}

func (c *Client) maxAttempts() int {
	if c.Retry.Max < 1 {
		return 1
	}
	return c.Retry.Max
}

func (c *Client) validateRetry() error {
	if c.Retry.Max < 0 || c.Retry.Max > maxHTTPAttempts || c.Retry.BaseDelay < 0 || c.Retry.MaxDelay < 0 {
		return ErrRetryConfig
	}
	base := c.Retry.BaseDelay
	if base == 0 {
		base = 250 * time.Millisecond
	}
	ceiling := c.Retry.MaxDelay
	if ceiling == 0 {
		ceiling = 10 * time.Second
	}
	if base > ceiling || ceiling > maxRetryAfterWait {
		return ErrRetryConfig
	}
	return nil
}

// delay returns the per-attempt sleep. Exponential backoff with full
// jitter: delay = uniform(0, min(maxDelay, base * 2^(attempt-1))).
func (c *Client) delay(attempt int) time.Duration {
	base := c.Retry.BaseDelay
	if base <= 0 {
		base = 250 * time.Millisecond
	}
	max := c.Retry.MaxDelay
	if max <= 0 {
		max = 10 * time.Second
	}
	d := base
	for i := 1; i < attempt; i++ {
		if d >= max/2 {
			d = max
			break
		}
		d *= 2
	}
	if !c.Retry.Jitter {
		return d
	}
	// crypto/rand to avoid math/rand which is banned by reactor lint.
	n, err := rand.Int(rand.Reader, big.NewInt(int64(d)))
	if err != nil {
		return d
	}
	return time.Duration(n.Int64())
}

// Error is the typed non-2xx error returned by Get / PostJSON. Callers
// can errors.As to read the status + body without parsing the message.
type Error struct {
	Status int
	// Body is untrusted provider data. It remains available for an adapter to
	// inspect deliberately, but Error() never copies it into Step logs.
	Body string
	// RetryAfter is the provider's requested delay, capped at 30 seconds.
	// RetryAfterLong says the provider requested longer than that cap; do not
	// retry after only RetryAfter in that case.
	RetryAfter     time.Duration
	RetryAfterLong bool
}

// RetryAfterDelay implements reactor.RetryAfterHint. The in-worker retry
// budget is deliberately bounded: a longer provider window needs an explicit
// durable reschedule or operator redrive, never an early automatic retry.
func (e *Error) RetryAfterDelay() (time.Duration, bool) {
	if e == nil {
		return 0, true
	}
	if e.RetryAfterLong {
		return 0, false
	}
	if e.RetryAfter < 0 {
		return 0, true
	}
	return e.RetryAfter, true
}

func (e *Error) Error() string {
	return fmt.Sprintf("HTTP %d", e.Status)
}

// IsRetryable reports whether err looks transient enough that the caller's
// outer Step retry should reschedule. A permanent authoring or data error
// must not become a retry just because it is not an HTTP status.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	if reactor.IsPermanent(err) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}
	var apiErr *Error
	if errors.As(err, &apiErr) {
		return apiErr.Status >= 500 || apiErr.Status == 408 || apiErr.Status == 429
	}
	if errors.Is(err, ErrTransport) || errors.Is(err, ErrResponseRead) || errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	return false
}
