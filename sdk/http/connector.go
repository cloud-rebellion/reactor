package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

const maxConnectorBodyBytes = 256 << 10

// ErrConnectorUnavailable means this workflow host has not offered the
// credential-aware connector broker. No direct-token fallback is attempted.
var ErrConnectorUnavailable = errors.New("reactor: connector broker is unavailable")

// ConnectorResponse is the bounded, token-free response returned by the host.
// Workflow code never receives the provider's bearer token or request origin.
type ConnectorResponse struct {
	Status       int
	Body         []byte
	RetryAfterMs int64
	ErrorCode    string
}

// ConnectorRequestFunc is bound by sdk/runtime after the host advertises the
// connector capability in Hello. It sends a fixed-origin request over the
// private workflow pipe; it does not run a workflow-selected net/http client.
type ConnectorRequestFunc func(context.Context, string, string, string) (ConnectorResponse, error)

type connectorRequestBinding struct{ request ConnectorRequestFunc }

var connectorRequester atomic.Pointer[connectorRequestBinding]

// BindConnectorRequester installs the runtime's host-pipe requester. The
// returned function restores the previous binding for in-process tests.
func BindConnectorRequester(request ConnectorRequestFunc) func() {
	var binding *connectorRequestBinding
	if request != nil {
		binding = &connectorRequestBinding{request: request}
	}
	previous := connectorRequester.Swap(binding)
	return func() { connectorRequester.Store(previous) }
}

// ConnectorGet fetches JSON through the host broker using an OAuth
// connection ID and a relative provider path. The current host contract
// supports Salesforce and operator-reviewed generic OAuth GET. It verifies
// tenant ownership, workflow grant, current reviewed origin/prefix, and a
// live lease before attaching a token. This helper
// never accepts an Authorization header or absolute URL from workflow code.
func ConnectorGet(ctx context.Context, credentialID, path string, out any) error {
	if IsDryRun() {
		return ErrDryRun
	}
	if ctx == nil {
		return errors.New("reactor: connector request requires a context")
	}
	if !validConnectorCredentialID(credentialID) || !validConnectorPath(path) {
		return errors.New("reactor: invalid connector request")
	}
	binding := connectorRequester.Load()
	if binding == nil || binding.request == nil {
		return ErrConnectorUnavailable
	}
	response, err := binding.request(ctx, credentialID, "GET", path)
	if err != nil {
		return fmt.Errorf("connector broker: %w", err)
	}
	if len(response.Body) > maxConnectorBodyBytes {
		return errors.New("reactor: connector response exceeds 256 KiB")
	}
	if response.ErrorCode == "upstream_status" && response.Status >= 100 && response.Status <= 599 {
		after, withinWait := connectorRetryAfter(response.RetryAfterMs)
		return &Error{Status: response.Status, RetryAfter: after, RetryAfterLong: !withinWait}
	}
	if response.ErrorCode != "" {
		return &ConnectorError{Code: safeConnectorErrorCode(response.ErrorCode), RetryAfterMs: response.RetryAfterMs}
	}
	if response.Status < 100 || response.Status > 599 {
		return errors.New("reactor: connector broker returned an invalid status")
	}
	if response.Status < 200 || response.Status >= 300 {
		after, withinWait := connectorRetryAfter(response.RetryAfterMs)
		return &Error{Status: response.Status, Body: string(response.Body), RetryAfter: after, RetryAfterLong: !withinWait}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(response.Body, out); err != nil {
		return fmt.Errorf("decode connector response: %w", err)
	}
	return nil
}

// ConnectorError is a host refusal without provider response data. Its text
// contains only a bounded machine code, never a URL, token, or response body.
type ConnectorError struct {
	Code         string
	RetryAfterMs int64
}

func (e *ConnectorError) Error() string {
	if e == nil {
		return "connector broker refused request"
	}
	return "connector broker refused request: " + safeConnectorErrorCode(e.Code)
}

// RetryAfterDelay lets a durable Step honor a shared account cooldown.
func (e *ConnectorError) RetryAfterDelay() (time.Duration, bool) {
	if e == nil {
		return 0, true
	}
	return connectorRetryAfter(e.RetryAfterMs)
}

func connectorRetryAfter(ms int64) (time.Duration, bool) {
	if ms <= 0 {
		return 0, true
	}
	if ms > int64(maxRetryAfterWait/time.Millisecond) {
		return maxRetryAfterWait, false
	}
	return time.Duration(ms) * time.Millisecond, true
}

func safeConnectorErrorCode(code string) string {
	if code == "" || len(code) > 64 {
		return "broker_failure"
	}
	for _, r := range code {
		if r != '_' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return "broker_failure"
		}
	}
	return code
}

func validConnectorCredentialID(value string) bool {
	if !strings.HasPrefix(value, "oauth:") || len(value) <= len("oauth:") || len(value) > 256 {
		return false
	}
	return strings.IndexFunc(value, func(r rune) bool { return r < 0x21 || r == 0x7f }) < 0
}

func validConnectorPath(path string) bool {
	if len(path) < 2 || len(path) > 4096 || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") ||
		strings.ContainsAny(path, "\\#\r\n") || strings.Contains(path, "://") {
		return false
	}
	return true
}
