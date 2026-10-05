// Package hash adapts provider-neutral Reactor workflows to Hash's atomic,
// idempotent signature-request API.
package hash

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

	"github.com/bright-interaction/reactor/internal/safehttp"
	"github.com/bright-interaction/reactor/sdk/esign"
	"github.com/bright-interaction/reactor/sdk/esign/internal/strictjson"
	ahttp "github.com/bright-interaction/reactor/sdk/http"
)

const (
	requestPath          = "/api/automation/v1/signature-requests"
	defaultTimeout       = 30 * time.Second
	maxResponseBodyBytes = 64 << 10
	maxRetryAfter        = 5 * time.Minute
)

// Client calls one Hash deployment. BaseURL and APIKey must come from trusted
// workflow configuration and Reactor's vault, never from webhook input.
type Client struct {
	baseURL    *url.URL
	apiKey     string
	httpClient *http.Client
}

// SignatureRequest is Hash's normalized create-and-send command. TemplateID is
// resolved from an operator-owned profile mapping before this adapter is called.
type SignatureRequest struct {
	TemplateID  string            `json:"template_id"`
	Name        string            `json:"name,omitempty"`
	Variables   map[string]string `json:"variables"`
	Recipients  []Recipient       `json:"recipients"`
	LawfulBasis string            `json:"lawful_basis"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
}

// Recipient is the Hash automation API recipient representation.
type Recipient struct {
	Role       string `json:"role"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	OrderIndex int32  `json:"order_index"`
	Locale     string `json:"locale,omitempty"`
}

// SignatureResult is safe to journal and log. Hash intentionally returns no
// signer bearer links from the automation API.
type SignatureResult struct {
	AutomationRequestID string `json:"automation_request_id"`
	DocumentID          string `json:"document_id"`
	Status              string `json:"status"`
	Replayed            bool   `json:"replayed"`
}

// signatureResultWire preserves presence for required scalar fields. Decoding
// directly into SignatureResult would make a missing replay flag
// indistinguishable from the valid JSON value false.
type signatureResultWire struct {
	AutomationRequestID string `json:"automation_request_id"`
	DocumentID          string `json:"document_id"`
	Status              string `json:"status"`
	Replayed            *bool  `json:"replayed"`
}

// NewClient constructs a single-attempt Hash client. The outer Reactor Step
// owns retry scheduling; the Hash Idempotency-Key makes every retry safe.
// Plain HTTP is accepted only for loopback development and tests.
func NewClient(baseURL, apiKey string, httpClient *http.Client) (*Client, error) {
	endpoint, err := parseBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if apiKey == "" || apiKey != strings.TrimSpace(apiKey) {
		return nil, errors.New("hash: API key is required without surrounding whitespace")
	}
	for _, char := range apiKey {
		if unicode.IsControl(char) {
			return nil, errors.New("hash: API key contains control characters")
		}
	}

	client := httpClient
	if client == nil {
		// Use Reactor's dial-time SSRF guard for the default workflow client.
		// URL parsing alone cannot prevent a public hostname from rebinding to
		// a private address between validation and connect. Literal loopback is
		// retained for local development; metadata and link-local ranges remain
		// blocked regardless of this development exception.
		client = safehttp.Client(isLoopback(endpoint.Hostname()))
		client.Timeout = defaultTimeout
	} else {
		clone := *client
		client = &clone
		if client.Timeout <= 0 {
			client.Timeout = defaultTimeout
		}
	}
	// A redirect could forward the bearer key and command to another origin.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &Client{baseURL: endpoint, apiKey: apiKey, httpClient: client}, nil
}

// CreateAndSend creates recipients and sends one block-template document. It
// performs exactly one HTTP attempt. A caller may safely retry the method with
// the same idempotency key and byte-equivalent request.
func (c *Client) CreateAndSend(ctx context.Context, idempotencyKey string, request SignatureRequest) (SignatureResult, error) {
	var result SignatureResult
	if ahttp.IsDryRun() {
		return result, ahttp.ErrDryRun
	}
	if c == nil || c.baseURL == nil || c.httpClient == nil {
		return result, errors.New("hash: nil or uninitialized client")
	}
	if err := validateIdempotencyKey(idempotencyKey); err != nil {
		return result, err
	}
	if strings.TrimSpace(request.TemplateID) == "" {
		return result, errors.New("hash: template ID is required")
	}
	if len(request.Recipients) == 0 {
		return result, errors.New("hash: at least one recipient is required")
	}
	if request.LawfulBasis == "" {
		request.LawfulBasis = "contract"
	}
	if request.Variables == nil {
		request.Variables = map[string]string{}
	}

	body, err := json.Marshal(request)
	if err != nil {
		return result, fmt.Errorf("hash: encode signature request: %w", err)
	}
	endpoint := c.baseURL.ResolveReference(&url.URL{Path: requestPath})
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return result, fmt.Errorf("hash: build signature request: %w", err)
	}
	httpRequest.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Idempotency-Key", idempotencyKey)
	httpRequest.Header.Set("User-Agent", "reactor-hash-esign/0.1")

	response, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return result, &TransportError{err: err}
	}
	defer response.Body.Close()

	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBodyBytes+1))
	tooLarge := len(responseBody) > maxResponseBodyBytes
	if tooLarge {
		responseBody = nil
	}

	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
			return result, &AmbiguousResponseError{Status: response.StatusCode}
		}
		return result, &APIError{
			Status:     response.StatusCode,
			Code:       responseCode(responseBody, response.StatusCode),
			RequestID:  safeHeader(response.Header.Get("X-Request-ID")),
			RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"), time.Now()),
		}
	}
	if readErr != nil || tooLarge || !hasExactJSONContentType(response.Header.Values("Content-Type")) {
		return result, &AmbiguousResponseError{Status: response.StatusCode}
	}

	var wire signatureResultWire
	if err := strictjson.Decode(responseBody, &wire); err != nil {
		return SignatureResult{}, &AmbiguousResponseError{Status: response.StatusCode}
	}
	if err := validateResult(wire); err != nil {
		return SignatureResult{}, &AmbiguousResponseError{Status: response.StatusCode}
	}
	if (response.StatusCode == http.StatusCreated && *wire.Replayed) ||
		(response.StatusCode == http.StatusOK && !*wire.Replayed) {
		return SignatureResult{}, &AmbiguousResponseError{Status: response.StatusCode}
	}
	return SignatureResult{
		AutomationRequestID: wire.AutomationRequestID,
		DocumentID:          wire.DocumentID,
		Status:              wire.Status,
		Replayed:            *wire.Replayed,
	}, nil
}

// Recipients converts provider-neutral event recipients to the Hash adapter
// representation without carrying CRM-specific fields across the boundary.
func Recipients(input []esign.Recipient) []Recipient {
	output := make([]Recipient, 0, len(input))
	for _, recipient := range input {
		output = append(output, Recipient{
			Role:       recipient.Role,
			Email:      recipient.Email,
			Name:       recipient.Name,
			OrderIndex: recipient.SigningOrder,
			Locale:     recipient.Locale,
		})
	}
	return output
}

// APIError describes a sanitized non-success response. It never retains the
// upstream response body because that body may contain customer data.
type APIError struct {
	Status     int
	Code       string
	RequestID  string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	if e == nil {
		return "hash: API error"
	}
	message := fmt.Sprintf("hash: API status %d", e.Status)
	if e.Code != "" {
		message += " code=" + e.Code
	}
	if e.RequestID != "" {
		message += " request_id=" + e.RequestID
	}
	return message
}

// TransportError keeps retry classification while avoiding URLs or response
// data in logs returned to the workflow.
type TransportError struct{ err error }

func (e *TransportError) Error() string { return "hash: transport failure" }
func (e *TransportError) Unwrap() error { return e.err }

// AmbiguousResponseError means Hash returned a 2xx response but Reactor could
// not safely recover the committed command result. Retrying with the same
// idempotency key is required to recover the original request and document
// identifiers without creating another document.
type AmbiguousResponseError struct{ Status int }

func (e *AmbiguousResponseError) Error() string {
	if e == nil || e.Status == 0 {
		return "hash: ambiguous success response"
	}
	return fmt.Sprintf("hash: ambiguous success response status %d", e.Status)
}

// IsRetryable reports whether an outer Reactor Step should retry. Hash owns
// command idempotency, so transport failures, timeouts, 408, 425, 429, and
// 5xx are safe to reschedule. Caller cancellation is not retried.
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
	var ambiguousErr *AmbiguousResponseError
	if errors.As(err, &ambiguousErr) {
		return true
	}
	var transportErr *TransportError
	return errors.As(err, &transportErr)
}

func parseBaseURL(raw string) (*url.URL, error) {
	if raw != strings.TrimSpace(raw) || raw == "" {
		return nil, errors.New("hash: base URL is required without surrounding whitespace")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("hash: base URL must be absolute")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("hash: base URL must not contain credentials, query, or fragment")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopback(parsed.Hostname())) {
		return nil, errors.New("hash: base URL must use HTTPS (HTTP is allowed only on loopback)")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("hash: base URL must not contain a path")
	}
	parsed.Path = ""
	return parsed, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateIdempotencyKey(key string) error {
	if key == "" || len(key) > 200 || key != strings.TrimSpace(key) {
		return errors.New("hash: idempotency key must contain 1 to 200 bytes without surrounding whitespace")
	}
	for _, char := range key {
		if unicode.IsControl(char) {
			return errors.New("hash: idempotency key contains control characters")
		}
	}
	return nil
}

func validateResult(result signatureResultWire) error {
	if !validResultIdentifier(result.AutomationRequestID) || !validResultIdentifier(result.DocumentID) {
		return errors.New("hash: success response omitted request or document ID")
	}
	if result.Replayed == nil {
		return errors.New("hash: success response omitted replay flag")
	}
	switch result.Status {
	case "sent", "in_progress", "changes_requested", "finalizing", "completed", "declined", "voided", "expired":
		return nil
	default:
		return errors.New("hash: success response contained an unknown status")
	}
}

func validResultIdentifier(value string) bool {
	if value == "" || len(value) > 200 || value != strings.TrimSpace(value) {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func hasExactJSONContentType(values []string) bool {
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

func responseCode(body []byte, status int) string {
	var value struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(body, &value) == nil {
		if code := safeHeader(value.Code); code != "" {
			return code
		}
	}
	return "http_" + strconv.Itoa(status)
}

func safeHeader(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 100 {
		value = value[:100]
	}
	for _, char := range value {
		if unicode.IsControl(char) || !(unicode.IsLetter(char) || unicode.IsDigit(char) || strings.ContainsRune("-_.:/", char)) {
			return ""
		}
	}
	return value
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
