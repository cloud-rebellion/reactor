package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var reactorTestMasterKey = strings.Repeat("01234567"+"89abcdef", 4)

func TestParseServeFlagsMCPScopesAreExplicit(t *testing.T) {
	key := reactorTestMasterKey
	cfg, err := parseServeFlags([]string{
		"--db", "sqlite://reactor.db",
		"--root", t.TempDir(),
		"--master-key", key,
		"--addr", "127.0.0.1:7777",
		"--mcp-allow-authoring",
		"--mcp-allow-triggers",
		"--mcp-allow-notifications",
		"--mcp-allow-dispatch",
		"--mcp-allow-secrets",
		"--mcp-allow-knowledge",
		"--mcp-allow-diagnostics",
		"--mcp-allow-data-export",
		"--mcp-allow-data-lifecycle",
		"--mcp-allow-mail-reconciliation",
		"--cgroup-root", "/sys/fs/cgroup",
		"--require-workflow-cgroup",
		"--mcp-token", "test-mcp-token",
		"--mcp-tenant", "acme",
	})
	if err != nil {
		t.Fatalf("parse serve flags: %v", err)
	}
	if !cfg.mcpTriggers || !cfg.mcpNotifications || !cfg.mcpAuthoring || !cfg.mcpDispatch || !cfg.mcpSecrets || !cfg.mcpKnowledge || !cfg.mcpDiagnostics || !cfg.mcpDataExport || !cfg.mcpDataLifecycle || !cfg.mcpMailReconciliation {
		t.Fatalf("MCP scopes not parsed: %+v", cfg)
	}
	if !cfg.requireCgroup {
		t.Fatalf("strict workflow cgroup flag not parsed: %+v", cfg)
	}
	if cfg.mcpToken != "test-mcp-token" || cfg.mcpTenant != "acme" {
		t.Fatalf("dedicated MCP bearer settings not parsed: token=%q tenant=%q", cfg.mcpToken, cfg.mcpTenant)
	}

	readOnly, err := parseServeFlags([]string{
		"--db", "sqlite://reactor.db",
		"--root", t.TempDir(),
		"--master-key", key,
		"--addr", "127.0.0.1:7777",
	})
	if err != nil {
		t.Fatalf("parse read-only serve flags: %v", err)
	}
	if readOnly.mcpTriggers || readOnly.mcpNotifications || readOnly.mcpAuthoring || readOnly.mcpDispatch || readOnly.mcpSecrets || readOnly.mcpKnowledge || readOnly.mcpDiagnostics || readOnly.mcpDataExport || readOnly.mcpDataLifecycle || readOnly.mcpMailReconciliation {
		t.Fatalf("MCP scopes must default to read-only: %+v", readOnly)
	}
}

func TestParseServeFlagsValidatesTrustedProxyCIDRs(t *testing.T) {
	t.Setenv("REACTOR_TRUSTED_PROXY_CIDRS", "")
	key := reactorTestMasterKey
	base := []string{"--db", "sqlite://reactor.db", "--root", t.TempDir(), "--master-key", key}
	if _, err := parseServeFlags(append(append([]string{}, base...), "--trusted-proxy-cidrs", "10.4.5.9,192.168.42.0/24")); err != nil {
		t.Fatalf("explicit proxy peers rejected: %v", err)
	}
	if _, err := parseServeFlags(append(append([]string{}, base...), "--trusted-proxy-cidrs", "10.4.5.9,not-an-ip")); err == nil || !strings.Contains(err.Error(), "trusted proxy CIDRs") {
		t.Fatalf("invalid proxy policy error = %v, want fail-closed startup", err)
	}
}

func TestParseServeFlagsKeepsCommandRunnerLocalOnly(t *testing.T) {
	key := reactorTestMasterKey
	image := "reactor@sha256:" + strings.Repeat("a", 64)
	_, err := parseServeFlags([]string{
		"--db", "postgres://localhost/reactor", "--root", t.TempDir(), "--master-key", key,
		"--addr", "127.0.0.1:7777",
		"--mode", "distributed", "--command-runner-enabled", "--command-single-tenant",
		"--command-docker-image", image, "--command-targets", "local",
	})
	if err == nil || !strings.Contains(err.Error(), "--mode local") {
		t.Fatalf("distributed command runner error = %v, want local-mode refusal", err)
	}
}

func TestStrictWorkflowCgroupRequiresExplicitRoot(t *testing.T) {
	key := reactorTestMasterKey
	_, err := parseServeFlags([]string{
		"--db", "sqlite://reactor.db",
		"--root", t.TempDir(),
		"--master-key", key,
		"--require-workflow-cgroup",
	})
	if err == nil || !strings.Contains(err.Error(), "requires --cgroup-root") {
		t.Fatalf("strict cgroup without root error = %v, want explicit root refusal", err)
	}
}

func TestMCPOAuthRedirectURIUsesOnlyValidatedOperatorOrigin(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "https origin", raw: "https://reactor.example", want: "https://reactor.example/oauth/callback"},
		{name: "loopback http", raw: "http://127.0.0.1:7777/", want: "http://127.0.0.1:7777/oauth/callback"},
		{name: "empty disables", raw: "", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mcpOAuthRedirectURI(tc.raw)
			if err != nil || got != tc.want {
				t.Fatalf("mcpOAuthRedirectURI(%q) = %q, %v; want %q", tc.raw, got, err, tc.want)
			}
		})
	}
	for _, raw := range []string{
		"http://reactor.example",
		"https://reactor.example/path",
		"https://reactor.example?host=attacker",
		"https://user:pass@reactor.example",
	} {
		if got, err := mcpOAuthRedirectURI(raw); err == nil || got != "" {
			t.Fatalf("mcpOAuthRedirectURI(%q) = %q, %v; want refusal", raw, got, err)
		}
	}
}

func TestParseServeFlagsRequiresTLSCertificateAndKeyTogether(t *testing.T) {
	key := reactorTestMasterKey
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "certificate only", args: []string{"--tls-cert", "/etc/reactor/cert.pem"}},
		{name: "key only", args: []string{"--tls-key", "/etc/reactor/key.pem"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{
				"--db", "sqlite://reactor.db",
				"--root", t.TempDir(),
				"--master-key", key,
			}, tc.args...)
			if _, err := parseServeFlags(args); err == nil || !strings.Contains(strings.ToLower(err.Error()), "tls") {
				t.Fatalf("parseServeFlags error = %v, want TLS pair refusal", err)
			}
		})
	}
}

func TestServeRequiresPrivateStateRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateStateRoot(root); err != nil {
		t.Fatalf("owned legacy state root rejected: %v", err)
	}
	if info, err := os.Stat(root); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("legacy state root mode after startup = %v, %v; want 0700", info, err)
	}
	if err := os.Chmod(root, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateStateRoot(root); err == nil || !strings.Contains(err.Error(), "writable by group or other") {
		t.Fatalf("writable state root error = %v, want permission refusal", err)
	}
	if info, err := os.Stat(root); err != nil || info.Mode().Perm() != 0o770 {
		t.Fatalf("writable state root mode = %v, %v; want unchanged 0770", info, err)
	}

	target := filepath.Join(t.TempDir(), "real-root")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateStateRoot(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink state root error = %v, want symlink refusal", err)
	}
}

func TestLoadMasterKeyRequiresPrivateRegularFile(t *testing.T) {
	root := t.TempDir()
	keyPath := filepath.Join(root, "master.key")
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("a", 64)), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMasterKey("", keyPath, root); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("shared master key error = %v, want permission refusal", err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadMasterKey("", keyPath, root)
	if err != nil || got != strings.Repeat("a", 64) {
		t.Fatalf("private master key = %q, err=%v", got, err)
	}
	link := filepath.Join(root, "key-link")
	if err := os.Symlink(keyPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMasterKey("", link, root); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink master key error = %v, want symlink refusal", err)
	}
}

func TestRedactDB(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		// previously panicked on the 10-char "postgres:/" because the old
		// implementation indexed [:11] under a len > 9 guard.
		{"postgres:/", "postgres:/"},
		{"postgres", "postgres"},
		{"", ""},
		{"sqlite://./reactor.db", "sqlite://./reactor.db"},
		{"postgres://user:pass@host/db", "postgres://[redacted]"},
		{"postgresql://user:pass@host/db", "postgres://[redacted]"},
	}
	for _, tc := range cases {
		got := redactDB(tc.in)
		if got != tc.want {
			t.Fatalf("redactDB(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
