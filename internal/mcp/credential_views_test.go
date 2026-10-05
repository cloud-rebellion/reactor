package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/credentials"
)

func TestHTTPMCPCredentialViewsRedactRotationProviderDetails(t *testing.T) {
	s, _, creds := newTestServer(t, false)
	s.TenantID = "acme"
	ctx := context.Background()
	if err := creds.Create(ctx, credentials.CreateParams{
		ID: "cred-redact", Name: "redact", TenantID: "acme", Service: "payments", Provider: "cloudflare",
	}); err != nil {
		t.Fatal(err)
	}
	rotationSecret := "rotation-secret-value"
	if err := creds.RecordError(ctx, "cred-redact", "provider_rotate: https://api.example.test/token?access_token="+rotationSecret); err != nil {
		t.Fatal(err)
	}
	page := callOperationalTool(t, s, "reactor_list_credentials", map[string]any{"limit": 1}, false)
	text := string(page)
	if strings.Contains(text, rotationSecret) || strings.Contains(text, "api.example.test") {
		t.Fatalf("credential inventory leaked rotation details: %s", page)
	}
	if !strings.Contains(text, `"last_rotation_error":{"code":"provider_rotate","present":true,"status":"redacted"}`) {
		t.Fatalf("credential inventory omitted the safe rotation receipt: %s", page)
	}

	auditSecret := "delivery-secret-value"
	detail, _ := json.Marshal(map[string]string{
		"provider": "cloudflare",
		"kind":     "webhook",
		"status":   "500",
		"url":      "https://hooks.example.test/reload?token=" + auditSecret,
		"error":    "upstream response contained " + auditSecret,
		"unknown":  "do-not-forward",
	})
	if err := creds.AppendAudit(ctx, credentials.AuditEntry{
		CredentialID: "cred-redact", Action: "rotate.delivery_failure", ActorKind: "scheduler", Detail: detail,
	}); err != nil {
		t.Fatal(err)
	}
	audit := callOperationalTool(t, s, "reactor_get_credential_audit", map[string]any{"credential_id": "cred-redact", "limit": 1}, false)
	auditText := string(audit)
	for _, forbidden := range []string{auditSecret, "hooks.example.test", "upstream response", "do-not-forward"} {
		if strings.Contains(auditText, forbidden) {
			t.Fatalf("credential audit leaked %q: %s", forbidden, audit)
		}
	}
	for _, want := range []string{`"detail_redacted":true`, `"url_present":true`, `"error_present":true`, `"provider":"cloudflare"`, `"kind":"webhook"`} {
		if !strings.Contains(auditText, want) {
			t.Fatalf("credential audit omitted %s: %s", want, audit)
		}
	}
}
