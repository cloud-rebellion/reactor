// Package codegen drives the AI generation pipeline: take a natural-language
// brief, call the Anthropic Messages API with tool-use to force structured
// output (workflow.go + dag.json + workflow_test.go), validate the result
// in a temp dir, retry on validation failure, commit to git on success.
//
// The Anthropic client lives in this file as a thin HTTP wrapper. We
// intentionally avoid the official Go SDK to keep the dep tree small and
// shield Reactor from upstream API churn during the SDK's pre-1.0 era.
//
// Configuration via env:
//
//	ANTHROPIC_API_KEY   required, passed as x-api-key header
//	ANTHROPIC_BASE_URL  optional, defaults to https://api.anthropic.com.
//	                    Useful for proxies, Bedrock-compatible gateways, tests.
//	ANTHROPIC_MODEL     optional, defaults to claude-opus-4-8
//	ANTHROPIC_VERSION   optional, defaults to 2023-06-01
package codegen

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// DefaultModel is the model used for codegen. Opus is the right pick: code
// quality matters more than latency here, and a workflow is a one-shot
// generation that doesn't need streaming. Override with ANTHROPIC_MODEL.
const DefaultModel = "claude-opus-4-8"

// DefaultMessagesURL is the standard Anthropic Messages endpoint.
const DefaultMessagesURL = "https://api.anthropic.com/v1/messages"

// DefaultAPIVersion pins the anthropic-version header.
const DefaultAPIVersion = "2023-06-01"

const maxAnthropicResponseBytes = 8 << 20

// AnthropicClient is the thin HTTP client. Safe for concurrent use; the
// underlying http.Client owns its connection pool.
type AnthropicClient struct {
	HTTPClient *http.Client
	APIKey     string
	BaseURL    string
	Version    string
}

// NewAnthropicFromEnv loads the client from env vars. Returns an error if
// ANTHROPIC_API_KEY is unset; callers should refuse to start the codegen
// HTTP handler in that case.
func NewAnthropicFromEnv() (*AnthropicClient, error) {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		return nil, errors.New("codegen: ANTHROPIC_API_KEY not set")
	}
	c := &AnthropicClient{
		APIKey:  key,
		BaseURL: os.Getenv("ANTHROPIC_BASE_URL"),
		Version: os.Getenv("ANTHROPIC_VERSION"),
	}
	if c.BaseURL == "" {
		c.BaseURL = "https://api.anthropic.com"
	}
	if err := validateAnthropicBaseURL(c.BaseURL); err != nil {
		return nil, err
	}
	if c.Version == "" {
		c.Version = DefaultAPIVersion
	}
	c.HTTPClient = &http.Client{
		Timeout: 120 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return c, nil
}

// A codegen request carries both an API credential and the authoring prompt.
// Only TLS endpoints may receive either, except a literal loopback address
// used by a local development gateway or test server.
func validateAnthropicBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return errors.New("codegen: model base URL must be an absolute HTTPS URL without userinfo, query, or fragment")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		ip := net.ParseIP(u.Hostname())
		if ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return errors.New("codegen: model base URL must use HTTPS or literal loopback HTTP")
}

// MessagesRequest is the subset of the Messages API we use. Tools forces a
// structured output by giving Claude exactly one tool to call.
type MessagesRequest struct {
	Model       string      `json:"model"`
	MaxTokens   int         `json:"max_tokens"`
	System      string      `json:"system,omitempty"`
	Messages    []Message   `json:"messages"`
	Tools       []Tool      `json:"tools,omitempty"`
	ToolChoice  *ToolChoice `json:"tool_choice,omitempty"`
	Temperature *float64    `json:"temperature,omitempty"`
}

// Message is one user/assistant turn. ContentBlocks lets us send tool_result
// blocks alongside text without ad-hoc string formatting.
type Message struct {
	Role    string         `json:"role"` // "user" | "assistant"
	Content []ContentBlock `json:"content"`
}

// ContentBlock is a single piece of message content.
type ContentBlock struct {
	Type      string          `json:"type"` // "text" | "tool_use" | "tool_result"
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`          // tool_use id
	Name      string          `json:"name,omitempty"`        // tool_use name
	Input     json.RawMessage `json:"input,omitempty"`       // tool_use input
	ToolUseID string          `json:"tool_use_id,omitempty"` // tool_result link
	IsError   bool            `json:"is_error,omitempty"`    // tool_result error flag
}

// Tool advertises a callable tool. The schema forces the AI's structured
// output to match a JSON shape we control.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// ToolChoice forces the model to call a specific tool. This is the
// structured-output mechanism: rather than parsing prose, we force the
// model into a tool call with the exact JSON shape we need.
type ToolChoice struct {
	Type string `json:"type"`           // "auto" | "any" | "tool"
	Name string `json:"name,omitempty"` // when Type = "tool"
}

// MessagesResponse is the subset of the response we read.
type MessagesResponse struct {
	ID         string         `json:"id"`
	Model      string         `json:"model"`
	Role       string         `json:"role"`
	StopReason string         `json:"stop_reason"`
	Content    []ContentBlock `json:"content"`
	Usage      Usage          `json:"usage"`
}

// Usage is the token bookkeeping the API returns.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// SendMessages POSTs the request and returns the parsed response. Non-2xx
// responses surface as APIError so callers can act on the status code +
// API error type (rate limit, invalid request, overloaded, etc.).
func (c *AnthropicClient) SendMessages(ctx context.Context, req MessagesRequest) (*MessagesResponse, error) {
	if err := validateAnthropicBaseURL(c.BaseURL); err != nil {
		return nil, err
	}
	if req.Model == "" {
		req.Model = DefaultModel
	}
	if req.MaxTokens == 0 {
		req.MaxTokens = 8192
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("codegen: marshal request: %w", err)
	}

	url := c.BaseURL + "/v1/messages"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("codegen: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.APIKey)
	httpReq.Header.Set("anthropic-version", c.Version)

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("codegen: http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxAnthropicResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("codegen: read body: %w", err)
	}
	if len(respBody) > maxAnthropicResponseBytes {
		return nil, fmt.Errorf("codegen: response exceeds %d-byte limit", maxAnthropicResponseBytes)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr APIError
		if jerr := json.Unmarshal(respBody, &apiErr); jerr == nil && apiErr.Body.Type != "" {
			apiErr.StatusCode = resp.StatusCode
			return nil, &apiErr
		}
		return nil, fmt.Errorf("codegen: anthropic %d", resp.StatusCode)
	}

	var out MessagesResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("codegen: decode response: %w", err)
	}
	return &out, nil
}

// APIError is the typed error the API returns for non-2xx responses.
type APIError struct {
	StatusCode int
	Body       ErrorBody `json:"error"`
}

// ErrorBody matches the Anthropic error shape.
type ErrorBody struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// Error implements error.
func (e *APIError) Error() string {
	// Provider messages can echo submitted prompts or gateway headers. Keep
	// the typed body for retry decisions but never promote it into logs or UI.
	return fmt.Sprintf("anthropic %d", e.StatusCode)
}

// IsRateLimited reports whether the error is a 429 / overloaded response.
// Callers can sleep + retry on these.
func (e *APIError) IsRateLimited() bool {
	return e.StatusCode == 429 ||
		e.Body.Type == "rate_limit_error" ||
		e.Body.Type == "overloaded_error"
}
