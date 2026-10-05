package http

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestConnectorGetUsesBoundHostBrokerAndTypedResponses(t *testing.T) {
	called := 0
	restore := BindConnectorRequester(func(_ context.Context, credentialID, method, path string) (ConnectorResponse, error) {
		called++
		if credentialID != "oauth:conn-1" || method != "GET" || path != "/services/data/v60.0/query?q=Account" {
			t.Fatalf("broker request = %q %q %q", credentialID, method, path)
		}
		return ConnectorResponse{Status: 200, Body: []byte(`{"records":[{"id":"001"}]}`)}, nil
	})
	defer restore()
	var result struct {
		Records []struct {
			ID string `json:"id"`
		} `json:"records"`
	}
	if err := ConnectorGet(context.Background(), "oauth:conn-1", "/services/data/v60.0/query?q=Account", &result); err != nil {
		t.Fatal(err)
	}
	if called != 1 || len(result.Records) != 1 || result.Records[0].ID != "001" {
		t.Fatalf("broker call count=%d result=%+v", called, result)
	}
}

func TestConnectorGetFailsClosedWithoutBrokerOrValidRelativePath(t *testing.T) {
	restore := BindConnectorRequester(nil)
	defer restore()
	if err := ConnectorGet(context.Background(), "oauth:conn-1", "/services/data/v60.0/query", nil); !errors.Is(err, ErrConnectorUnavailable) {
		t.Fatalf("missing host broker = %v", err)
	}
	for _, path := range []string{"https://api.example.test/data", "//evil.test/data", "/data#fragment", "/data\\escape", "/data\nleak"} {
		if err := ConnectorGet(context.Background(), "oauth:conn-1", path, nil); err == nil || errors.Is(err, ErrConnectorUnavailable) {
			t.Fatalf("unsafe relative path %q = %v", path, err)
		}
	}
	if err := ConnectorGet(context.Background(), "oauth:", "/data", nil); err == nil {
		t.Fatal("empty connection id accepted")
	}
}

func TestConnectorGetReturnsBoundedSafeProviderAndBudgetErrors(t *testing.T) {
	secret := "provider-echoed-secret"
	restore := BindConnectorRequester(func(context.Context, string, string, string) (ConnectorResponse, error) {
		return ConnectorResponse{Status: 429, Body: []byte(secret), RetryAfterMs: 3600_000}, nil
	})
	defer restore()
	err := ConnectorGet(context.Background(), "oauth:conn-1", "/data", nil)
	var httpErr *Error
	if !errors.As(err, &httpErr) || !httpErr.RetryAfterLong || strings.Contains(err.Error(), secret) || httpErr.Body != secret {
		t.Fatalf("provider 429 = %v, typed=%+v", err, httpErr)
	}
	BindConnectorRequester(func(context.Context, string, string, string) (ConnectorResponse, error) {
		return ConnectorResponse{Status: 429, ErrorCode: "upstream_status", RetryAfterMs: 4200}, nil
	})
	err = ConnectorGet(context.Background(), "oauth:conn-1", "/data", nil)
	if !errors.As(err, &httpErr) || httpErr.Status != 429 || httpErr.RetryAfter != 4200*time.Millisecond || httpErr.Body != "" {
		t.Fatalf("host-sanitized upstream 429 = %v, typed=%+v", err, httpErr)
	}
	BindConnectorRequester(func(context.Context, string, string, string) (ConnectorResponse, error) {
		return ConnectorResponse{ErrorCode: "rate_limited", RetryAfterMs: 4500}, nil
	})
	err = ConnectorGet(context.Background(), "oauth:conn-1", "/data", nil)
	var brokerErr *ConnectorError
	if !errors.As(err, &brokerErr) || brokerErr.Code != "rate_limited" {
		t.Fatalf("budget refusal = %v", err)
	}
	if delay, ok := brokerErr.RetryAfterDelay(); !ok || delay != 4500*time.Millisecond {
		t.Fatalf("budget retry hint = %s, %v", delay, ok)
	}
	BindConnectorRequester(func(context.Context, string, string, string) (ConnectorResponse, error) {
		return ConnectorResponse{Status: 200, Body: []byte(strings.Repeat("x", maxConnectorBodyBytes+1))}, nil
	})
	if err := ConnectorGet(context.Background(), "oauth:conn-1", "/data", nil); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized broker response = %v", err)
	}
}

func TestConnectorGetDryRunNeverCallsBroker(t *testing.T) {
	t.Setenv("REACTOR_MODE", "dry_run")
	restore := BindConnectorRequester(func(context.Context, string, string, string) (ConnectorResponse, error) {
		t.Fatal("dry run sent connector request")
		return ConnectorResponse{}, nil
	})
	defer restore()
	if err := ConnectorGet(context.Background(), "oauth:conn-1", "/data", nil); !errors.Is(err, ErrDryRun) {
		t.Fatalf("dry-run connector request = %v", err)
	}
}
