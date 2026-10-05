package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

// WebhookSender posts a JSON-encoded Event to an arbitrary URL.
// Config shape:
//
//	{
//	  "url": "https://example.com/reactor",
//	  "headers": {"X-Auth-Token": "..."}   // optional
//	}
//
// The payload carries terminal metadata but omits raw step errors, which can
// contain untrusted data or secrets.
type WebhookSender struct {
	Client *http.Client
}

// NewWebhookSender returns a sender with an SSRF-hardened *http.Client.
// Set REACTOR_WEBHOOK_ALLOW_PRIVATE=1 to permit loopback/private targets
// (internal services); the cloud-metadata + link-local range stays
// blocked regardless.
func NewWebhookSender() *WebhookSender {
	return &WebhookSender{Client: ssrfSafeClient(os.Getenv("REACTOR_WEBHOOK_ALLOW_PRIVATE") == "1")}
}

// Kind implements Sender.
func (s *WebhookSender) Kind() string { return "generic_webhook" }

// Send posts the JSON-encoded event + any configured headers.
func (s *WebhookSender) Send(ctx context.Context, cfg json.RawMessage, ev Event) error {
	var c struct {
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
	}
	if err := json.Unmarshal(cfg, &c); err != nil {
		return fmt.Errorf("webhook: parse config: %w", err)
	}
	if c.URL == "" {
		return fmt.Errorf("webhook: missing url in config")
	}
	if u, err := url.Parse(c.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("webhook: url must be an absolute http(s) URL")
	}

	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("webhook: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: invalid request URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "reactor-notifier/1.0")
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	client := s.Client
	if client == nil {
		// Keep the safety property even when a caller constructs
		// WebhookSender directly instead of using NewWebhookSender.
		client = ssrfSafeClient(os.Getenv("REACTOR_WEBHOOK_ALLOW_PRIVATE") == "1")
	}
	resp, err := client.Do(req)
	if err != nil {
		return safePostError("webhook", err)
	}
	defer resp.Body.Close()
	// Drain (bounded) so the connection can be reused, but do NOT echo the
	// response body into the error: for an SSRF target the body is exactly
	// what an attacker wants exfiltrated into the dashboard log line.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: endpoint returned status %d", resp.StatusCode)
	}
	return nil
}
