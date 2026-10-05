package flarereport

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestParseDSNForLogsRequiresSecureOrLoopbackTransport(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		dsn  string
		want bool
	}{
		{name: "https", dsn: "https://key@flare.example/123", want: true},
		{name: "loopback http", dsn: "http://key@127.0.0.1:8080/123", want: true},
		{name: "localhost http", dsn: "http://key@localhost/123", want: true},
		{name: "remote http", dsn: "http://key@flare.example/123", want: false},
		{name: "missing scheme", dsn: "key@flare.example/123", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, got := parseDSNForLogs(tt.dsn)
			if got != tt.want {
				t.Fatalf("parseDSNForLogs(%q) ok = %v, want %v", tt.dsn, got, tt.want)
			}
		})
	}
}

func TestLogShipHTTPClientUsesSafeTransport(t *testing.T) {
	t.Parallel()
	client := logShipHTTPClient()
	if client.Timeout != 5*time.Second {
		t.Fatalf("timeout = %s, want 5s", client.Timeout)
	}
	if client.CheckRedirect == nil {
		t.Fatal("CheckRedirect is nil")
	}
	if err := client.CheckRedirect(nil, nil); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("redirect policy error = %v, want refusal", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.DialContext == nil {
		t.Fatalf("transport = %T, want safe http.Transport", client.Transport)
	}
	_, err := transport.DialContext(context.Background(), "tcp", "169.254.169.254:80")
	if err == nil || !strings.Contains(err.Error(), "ssrf: refusing") {
		t.Fatalf("metadata dial error = %v, want SSRF refusal", err)
	}
}

func TestIsSensitiveLogKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		// Sensitive: value must be redacted before shipping to Flare.
		{"password", true},
		{"user.password", true},
		{"agent_token", true},
		{"authorization", true},
		{"Cookie", true},
		{"db_credential", true},
		{"api_key", true},
		{"apiKey", true},
		{"access_key", true},
		{"private_key", true},
		{"vault_key", true},
		{"new_value", true},
		{"jwt", true},
		{"session_id", true},
		{"flare_dsn", true},
		{"bearer", true},
		// Not sensitive: legit keys must pass through untouched.
		{"error", false},
		{"server_id", false},
		{"command_id", false},
		{"count", false},
		{"keyboard", false},
		{"monkey", false},
		{"duration_ms", false},
		{"trace_id", false},
	}
	for _, tt := range tests {
		if got := isSensitiveLogKey(tt.key); got != tt.want {
			t.Errorf("isSensitiveLogKey(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

func TestIsShipSafeLogKeyUsesOperationalAllowlist(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"run_id", true},
		{"http.status", true},
		{"duration_ms", true},
		{"error", false},
		{"url", false},
		{"to", false},
		{"spec", false},
		{"workflow.stderr", false},
		{"credential_name", false},
		{"token", false},
	}
	for _, tt := range tests {
		if got := isShipSafeLogKey(tt.key); got != tt.want {
			t.Errorf("isShipSafeLogKey(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

func TestValidTraceIDRejectsArbitraryValues(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{value: "0123456789abcdef", want: true},
		{value: "0123456789abcdef0123456789abcdef", want: true},
		{value: "customer@example.com", want: false},
		{value: "0123456789abcde", want: false},
		{value: "0123456789abcdeg", want: false},
	} {
		if got := validTraceID(tc.value); got != tc.want {
			t.Errorf("validTraceID(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}
