package notifier

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestResolveChannelSecrets(t *testing.T) {
	ctx := context.Background()
	resolve := func(_ context.Context, tenantID, id string) (string, error) {
		if tenantID != "tenant-a" {
			return "", errors.New("wrong tenant")
		}
		if id == "cred_ok" {
			return "s3cr3t", nil
		}
		return "", errors.New("no such credential")
	}

	t.Run("smtp password credential injected", func(t *testing.T) {
		in := json.RawMessage(`{"host":"smtp.x","password_credential_id":"cred_ok"}`)
		out, err := resolveChannelSecrets(ctx, "tenant-a", "email_smtp", in, resolve)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = json.Unmarshal(out, &m)
		if m["password"] != "s3cr3t" {
			t.Fatalf("password = %v, want resolved secret", m["password"])
		}
	})

	t.Run("slack webhook credential injected", func(t *testing.T) {
		in := json.RawMessage(`{"url_credential_id":"cred_ok"}`)
		out, err := resolveChannelSecrets(ctx, "tenant-a", "slack_webhook", in, resolve)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = json.Unmarshal(out, &m)
		if m["url"] != "s3cr3t" || m["url_credential_id"] != "cred_ok" {
			t.Fatalf("slack config = %v, want resolved url plus reference", m)
		}
	})

	t.Run("webhook header credential injected", func(t *testing.T) {
		in := json.RawMessage(`{"url":"https://x","header_name":"X-Auth","header_credential_id":"cred_ok"}`)
		out, err := resolveChannelSecrets(ctx, "tenant-a", "generic_webhook", in, resolve)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), `"X-Auth":"s3cr3t"`) {
			t.Fatalf("header not injected: %s", out)
		}
	})

	t.Run("no reference returns config unchanged", func(t *testing.T) {
		in := json.RawMessage(`{"host":"smtp.x","password":"plaintext"}`)
		out, err := resolveChannelSecrets(ctx, "tenant-a", "email_smtp", in, resolve)
		if err != nil || string(out) != string(in) {
			t.Fatalf("expected unchanged config, got %s err=%v", out, err)
		}
	})

	t.Run("unresolvable credential errors (fail closed)", func(t *testing.T) {
		in := json.RawMessage(`{"host":"smtp.x","password_credential_id":"cred_missing"}`)
		if _, err := resolveChannelSecrets(ctx, "tenant-a", "email_smtp", in, resolve); err == nil {
			t.Fatal("expected an error for an unresolvable credential")
		}
	})

	t.Run("missing resolver errors (fail closed)", func(t *testing.T) {
		in := json.RawMessage(`{"url_credential_id":"cred_ok"}`)
		if _, err := resolveChannelSecrets(ctx, "tenant-a", "slack_webhook", in, nil); err == nil || !strings.Contains(err.Error(), "vault resolver unavailable") {
			t.Fatalf("resolve error = %v, want missing resolver", err)
		}
	})
}
