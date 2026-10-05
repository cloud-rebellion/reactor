package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

// SlackSender posts a Block Kit message to an Incoming Webhook URL.
// Config shape: {"url": "https://hooks.slack.com/services/..."}
type SlackSender struct {
	Client *http.Client
}

// NewSlackSender returns a sender with an SSRF-hardened client (connect-time
// IP check + no redirect-follow), so a hooks.slack.com DNS-rebind or an open
// redirect can't turn the webhook into an internal-network read primitive.
func NewSlackSender() *SlackSender {
	return &SlackSender{Client: ssrfSafeClient(os.Getenv("REACTOR_WEBHOOK_ALLOW_PRIVATE") == "1")}
}

// Kind implements Sender.
func (s *SlackSender) Kind() string { return "slack_webhook" }

// Send posts the alert. Surfaces non-2xx as an error so the dispatcher
// log shows the actual webhook failure.
func (s *SlackSender) Send(ctx context.Context, cfg json.RawMessage, ev Event) error {
	var c struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(cfg, &c); err != nil {
		return fmt.Errorf("slack: parse config: %w", err)
	}
	if c.URL == "" {
		return fmt.Errorf("slack: missing url in config")
	}

	payload := slackBody(ev)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("slack: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack: invalid request URL")
	}
	req.Header.Set("Content-Type", "application/json")
	client := s.Client
	if client == nil {
		// Keep the safety property even when a caller constructs SlackSender
		// directly instead of using NewSlackSender.
		client = ssrfSafeClient(os.Getenv("REACTOR_WEBHOOK_ALLOW_PRIVATE") == "1")
	}
	resp, err := client.Do(req)
	if err != nil {
		return safePostError("slack", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		// Do NOT echo the response body into the error: it flows back to the
		// dashboard (notificationsTest) and an SSRF-redirected target's body
		// would be an exfiltration read primitive. Status code only.
		return fmt.Errorf("slack: status %d", resp.StatusCode)
	}
	return nil
}

// slackBody renders the Block Kit payload. Plain-text fallback is
// always included so notifications-only clients (without Block Kit
// support) still get a readable line.
func slackBody(ev Event) map[string]any {
	headline := alertHeadline(ev)
	text := alertPlainText(ev)
	blocks := []any{
		map[string]any{
			"type": "header",
			"text": map[string]any{"type": "plain_text", "text": headline, "emoji": true},
		},
		map[string]any{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": alertMarkdown(ev),
			},
		},
	}
	if ev.DashboardURL != "" {
		blocks = append(blocks, map[string]any{
			"type": "actions",
			"elements": []any{
				map[string]any{
					"type":  "button",
					"text":  map[string]any{"type": "plain_text", "text": "Open run", "emoji": true},
					"url":   ev.DashboardURL,
					"style": "primary",
				},
			},
		})
	}
	return map[string]any{
		"text":   text, // top-level fallback (mobile notifications)
		"blocks": blocks,
	}
}
