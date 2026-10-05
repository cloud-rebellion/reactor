package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/credentials"
)

func TestMCPCreateSMTPChannelPort465UsesImplicitTLS(t *testing.T) {
	s, j, creds := newTestServer(t, false)
	s.TenantID = "acme"
	s.Scopes = &WriteScopes{Notifications: true}
	ctx := context.Background()
	if err := creds.Create(ctx, credentials.CreateParams{ID: "smtp-credential", Name: "smtp-credential", TenantID: "acme", Service: "smtp", Provider: "shared-secret"}); err != nil {
		t.Fatal(err)
	}
	base := map[string]any{
		"host": "smtp.example.test", "port": 465, "username": "alerts@example.test",
		"from": "alerts@example.test", "to": "ops@example.test", "password_credential_id": "smtp-credential",
	}
	created := callOperationalTool(t, s, "reactor_create_notification_channel", map[string]any{
		"name": "implicit-tls-alerts", "kind": "email_smtp", "config": base,
	}, false)
	var receipt struct {
		ChannelID string `json:"channel_id"`
	}
	if err := json.Unmarshal(created, &receipt); err != nil || receipt.ChannelID == "" {
		t.Fatalf("create SMTP channel receipt = %s, %v", created, err)
	}
	channel, err := j.GetNotificationChannel(ctx, receipt.ChannelID)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		Port     int  `json:"port"`
		StartTLS bool `json:"starttls"`
	}
	if err := json.Unmarshal(channel.ConfigJSON, &stored); err != nil || stored.Port != 465 || stored.StartTLS {
		t.Fatalf("stored SMTP channel must select implicit TLS: %s, %v", channel.ConfigJSON, err)
	}
	if strings.Contains(string(channel.ConfigJSON), `"password":`) || strings.Contains(string(created), "smtp-credential") {
		t.Fatalf("SMTP secret value or credential leaked in MCP receipt/storage: receipt=%s stored=%s", created, channel.ConfigJSON)
	}
	base["starttls"] = true
	rejected := callOperationalTool(t, s, "reactor_create_notification_channel", map[string]any{
		"name": "conflicting-tls-alerts", "kind": "email_smtp", "config": base,
	}, true)
	if !strings.Contains(string(rejected), "implicit TLS") {
		t.Fatalf("conflicting STARTTLS should explain port 465 mode: %s", rejected)
	}
	channels, err := j.ListNotificationChannelsByTenant(ctx, "acme")
	if err != nil || len(channels) != 1 {
		t.Fatalf("conflicting SMTP channel persisted: channels=%d err=%v", len(channels), err)
	}
}
