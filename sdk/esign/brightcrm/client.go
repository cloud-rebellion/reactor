// Package brightcrm delivers provider-neutral e-signature lifecycle events to
// BrightCRM's tenant-bound integration endpoint.
package brightcrm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/bright-interaction/reactor/sdk/esign"
	"github.com/bright-interaction/reactor/sdk/esign/internal/strictjson"
)

const (
	lifecyclePath       = "/api/v1/integrations/hash/esign-events"
	defaultTimeout      = 20 * time.Second
	maxResponseBytes    = 8 << 10
	maxRetryAfter       = 5 * time.Minute
	maxBearerCredential = 16 << 10
)

// Client calls one operator-configured BrightCRM deployment. The base URL and
// bearer credential must never come from a webhook event.
type Client struct {
	baseURL    *url.URL
	bearer     string
	httpClient *http.Client
}

// Receipt is BrightCRM's bounded acknowledgement. A 202 is a newly accepted
// event; a 200 is an idempotent replay of an event already accepted.
type Receipt struct {
	Accepted bool `json:"accepted"`
	Deduped  bool `json:"deduped"`
}

type receiptWire struct {
	Accepted *bool `json:"accepted"`
	Deduped  *bool `json:"deduped"`
}

// NewClient constructs a single-attempt client. Reactor's outer Step owns all
// retry timing. HTTP is allowed only for loopback development and tests.
func NewClient(baseURL, bearer string, httpClient *http.Client) (*Client, error) {
	endpoint, err := parseBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if err := validateBearer(bearer); err != nil {
		return nil, err
	}

	client := httpClient
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	} else {
		clone := *client
		client = &clone
		if client.Timeout <= 0 {
			client.Timeout = defaultTimeout
		}
	}
	// Never forward the tenant bearer to another origin through a redirect.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &Client{baseURL: endpoint, bearer: bearer, httpClient: client}, nil
}

// DeliverLifecycleEvent posts exactly the five-field lifecycle projection and
// performs one HTTP attempt. BrightCRM deduplicates by event_id; a malformed
// success response is ambiguous and must be retried with the same event.
func (c *Client) DeliverLifecycleEvent(ctx context.Context, event esign.LifecycleEvent) (Receipt, error) {
	var receipt Receipt
	if c == nil || c.baseURL == nil || c.httpClient == nil {
		return receipt, errors.New("brightcrm lifecycle: nil or uninitialized client")
	}
	if err := event.Validate(); err != nil {
		return receipt, errors.New("brightcrm lifecycle: invalid event")
	}
	body, err := json.Marshal(event)
	if err != nil {
		return receipt, errors.New("brightcrm lifecycle: encode event")
	}
	endpoint := c.baseURL.ResolveReference(&url.URL{Path: lifecyclePath})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return receipt, errors.New("brightcrm lifecycle: build request")
	}
	request.Header.Set("Authorization", "Bearer "+c.bearer)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "reactor-hash-lifecycle/0.1")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return receipt, &TransportError{err: err}
	}
	defer response.Body.Close()

	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	tooLarge := len(responseBody) > maxResponseBytes
	if tooLarge {
		responseBody = nil
	}

	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusAccepted {
		if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
			return receipt, &AmbiguousResponseError{Status: response.StatusCode}
		}
		return receipt, &APIError{
			Status:     response.StatusCode,
			RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"), time.Now()),
		}
	}
	if readErr != nil || tooLarge || !hasJSONContentType(response.Header.Values("Content-Type")) {
		return receipt, &AmbiguousResponseError{Status: response.StatusCode}
	}

	var wire receiptWire
	if err := strictjson.Decode(responseBody, &wire); err != nil || wire.Accepted == nil || wire.Deduped == nil {
		return receipt, &AmbiguousResponseError{Status: response.StatusCode}
	}
	if !*wire.Accepted || (response.StatusCode == http.StatusOK) != *wire.Deduped {
		return receipt, &AmbiguousResponseError{Status: response.StatusCode}
	}
	return Receipt{Accepted: true, Deduped: *wire.Deduped}, nil
}

// APIError is a sanitized non-success response. It intentionally retains no
// body, URL, or header other than the bounded Retry-After delay.
type APIError struct {
	Status     int
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	if e == nil {
		return "brightcrm lifecycle: API error"
	}
	return fmt.Sprintf("brightcrm lifecycle: API status %d", e.Status)
}

// TransportError preserves retry classification without exposing credentials
// or upstream response content.
type TransportError struct{ err error }

func (e *TransportError) Error() string { return "brightcrm lifecycle: transport failure" }
func (e *TransportError) Unwrap() error { return e.err }

// AmbiguousResponseError means BrightCRM returned 2xx but Reactor could not
// prove that the expected tenant-bound event was accepted. Retry is required
// so the CRM's event_id idempotency record can resolve the outcome.
type AmbiguousResponseError struct{ Status int }

func (e *AmbiguousResponseError) Error() string {
	if e == nil || e.Status == 0 {
		return "brightcrm lifecycle: ambiguous success response"
	}
	return fmt.Sprintf("brightcrm lifecycle: ambiguous success response status %d", e.Status)
}

// IsRetryable reports whether a bounded outer Reactor Step may reschedule the
// same event. Conflict is deliberately permanent: it means one event_id was
// reused with different content and requires operator review.
func IsRetryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status == http.StatusRequestTimeout ||
			apiErr.Status == http.StatusTooEarly ||
			apiErr.Status == http.StatusTooManyRequests ||
			apiErr.Status >= http.StatusInternalServerError
	}
	var ambiguous *AmbiguousResponseError
	if errors.As(err, &ambiguous) {
		return true
	}
	var transport *TransportError
	return errors.As(err, &transport)
}

func parseBaseURL(raw string) (*url.URL, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return nil, errors.New("brightcrm lifecycle: base URL is required without surrounding whitespace")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("brightcrm lifecycle: base URL must be absolute")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("brightcrm lifecycle: base URL must not contain credentials, query, or fragment")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopback(parsed.Hostname())) {
		return nil, errors.New("brightcrm lifecycle: base URL must use HTTPS (HTTP is allowed only on loopback)")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("brightcrm lifecycle: base URL must not contain a path")
	}
	parsed.Path = ""
	return parsed, nil
}

func validateBearer(bearer string) error {
	if bearer == "" || len(bearer) > maxBearerCredential || bearer != strings.TrimSpace(bearer) {
		return errors.New("brightcrm lifecycle: bearer credential is invalid")
	}
	for _, char := range bearer {
		if unicode.IsControl(char) {
			return errors.New("brightcrm lifecycle: bearer credential is invalid")
		}
	}
	return nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func hasJSONContentType(values []string) bool {
	if len(values) != 1 {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(values[0])
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return false
	}
	if len(parameters) == 0 {
		return true
	}
	charset, ok := parameters["charset"]
	return len(parameters) == 1 && ok && strings.EqualFold(charset, "utf-8")
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		if seconds > int(maxRetryAfter/time.Second) {
			return maxRetryAfter
		}
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	delay := when.Sub(now)
	if delay > maxRetryAfter {
		return maxRetryAfter
	}
	return delay
}
