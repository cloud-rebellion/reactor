package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMCPInstallCodexApplyPreservesOtherServersAndBearerPlaceholder(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CODEX_HOME", root)
	t.Setenv("REACTOR_API_TOKEN", "synthetic-token-never-persist")
	path := filepath.Join(root, "config.toml")
	const original = "model = \"gpt-6.1-sol\"\n\n[mcp_servers.stage]\nurl = \"https://stage.example/mcp\"\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(t, func() error {
		return cmdMCPInstall([]string{
			"--client", "codex", "--apply", "--url", "https://reactor.example/mcp",
			"--token-env", "REACTOR_API_TOKEN",
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, path) {
		t.Fatalf("apply receipt omitted config path: %q", out)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if !strings.HasPrefix(got, original) || !strings.Contains(got, codexTOMLSnippet("https://reactor.example/mcp", "REACTOR_API_TOKEN", true)) ||
		strings.Contains(got, "synthetic-token-never-persist") {
		t.Fatalf("Codex config lost existing content, lacked Reactor, or stored a bearer: %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("Codex config mode = %v; want 0600", info.Mode().Perm())
	}
	backups, err := filepath.Glob(path + ".bak-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups = %v, err=%v; want one", backups, err)
	}
	backedUp, err := os.ReadFile(backups[0])
	if err != nil || string(backedUp) != original {
		t.Fatalf("original config backup = %q, err=%v", backedUp, err)
	}
	if _, err := captureStdout(t, func() error {
		return cmdMCPInstall([]string{
			"--client", "codex", "--apply", "--url", "https://reactor.example/mcp",
			"--token-env", "REACTOR_API_TOKEN",
		})
	}); err != nil {
		t.Fatalf("identical reapply: %v", err)
	}
	backupsAfter, err := filepath.Glob(path + ".bak-*")
	if err != nil || len(backupsAfter) != 1 {
		t.Fatalf("identical reapply created a new backup: %v, err=%v", backupsAfter, err)
	}
}

func TestMCPInstallCodexApplyRefusesConflictingEntryWithoutMutation(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CODEX_HOME", root)
	path := filepath.Join(root, "config.toml")
	const original = "[mcp_servers.reactor]\nurl = \"https://old.example/mcp\"\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := captureStdout(t, func() error {
		return cmdMCPInstall([]string{"--client", "codex", "--apply"})
	})
	if err == nil || !strings.Contains(err.Error(), "already has a Reactor") {
		t.Fatalf("conflicting entry error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != original {
		t.Fatalf("conflicting config changed: %q, err=%v", raw, err)
	}
}

func TestMCPInstallCodexApplyRejectsDuplicateEvenWhenOneEntryMatches(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CODEX_HOME", root)
	t.Setenv("REACTOR_API_TOKEN", "synthetic-token-never-persist")
	path := filepath.Join(root, "config.toml")
	const endpoint = "https://reactor.example/mcp"
	original := codexTOMLSnippet(endpoint, "REACTOR_API_TOKEN", true) + "\n[mcp_servers.reactor]\nurl = \"https://other.example/mcp\"\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := captureStdout(t, func() error {
		return cmdMCPInstall([]string{"--client", "codex", "--apply", "--url", endpoint, "--token-env", "REACTOR_API_TOKEN"})
	})
	if err == nil || !strings.Contains(err.Error(), "already has a Reactor") {
		t.Fatalf("duplicate entry error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != original {
		t.Fatalf("duplicate config changed: %q, err=%v", raw, err)
	}
}

func TestMCPInstallCodexApplyRefusesEquivalentTOMLSpellings(t *testing.T) {
	for _, tc := range []struct {
		name, original string
	}{
		{"spaced dotted key", "[mcp_servers . reactor]\nurl = \"https://old.example/mcp\"\n"},
		{"parent table with inline child", "[mcp_servers]\nreactor = { url = \"https://old.example/mcp\" }\n"},
		{"quoted dotted key", "[mcp_servers.\"reactor\"]\nurl = \"https://old.example/mcp\"\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("CODEX_HOME", root)
			path := filepath.Join(root, "config.toml")
			if err := os.WriteFile(path, []byte(tc.original), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := captureStdout(t, func() error {
				return cmdMCPInstall([]string{"--client", "codex", "--apply"})
			})
			if err == nil || !strings.Contains(err.Error(), "already has a Reactor") {
				t.Fatalf("existing TOML entry error = %v", err)
			}
			raw, err := os.ReadFile(path)
			if err != nil || string(raw) != tc.original {
				t.Fatalf("existing TOML config changed: %q, err=%v", raw, err)
			}
		})
	}
}

func TestMCPInstallCodexApplyRejectsSymlinkConfig(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.toml")
	target := filepath.Join(root, "elsewhere.toml")
	if err := os.WriteFile(target, []byte("model = \"keep\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := applyCodexMCPConfig(path, codexTOMLSnippet("http://127.0.0.1:7777/mcp", "REACTOR_MCP_TOKEN", false)); err == nil {
		t.Fatal("symlinked config was overwritten")
	}
	raw, err := os.ReadFile(target)
	if err != nil || string(raw) != "model = \"keep\"\n" {
		t.Fatalf("symlink target changed: %q, err=%v", raw, err)
	}
}

func TestMCPInstallCodexApplyRefusesConcurrentInstallLock(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CODEX_HOME", root)
	path := filepath.Join(root, "config.toml")
	lockPath := path + ".reactor-install.lock"
	if err := os.WriteFile(lockPath, []byte("another installer"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := captureStdout(t, func() error {
		return cmdMCPInstall([]string{"--client", "codex", "--apply"})
	})
	if err == nil || !strings.Contains(err.Error(), "install lock exists") {
		t.Fatalf("concurrent install error = %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("config changed under an install lock: %v", err)
	}
}

func TestCodexConfigRecheckDetectsExternalChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("model = \"new\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkCodexConfigUnchanged(path, []byte("model = \"old\"\n"), true); err == nil {
		t.Fatal("changed config was accepted")
	}
	if err := checkCodexConfigUnchanged(path, nil, false); err == nil {
		t.Fatal("new config was accepted when original was absent")
	}
}

func TestMCPInstallCodexLoopbackWithoutBearerOmitsEnvSetting(t *testing.T) {
	t.Setenv("REACTOR_MCP_TOKEN", "")
	out, err := captureStdout(t, func() error {
		return cmdMCPInstall([]string{"--client", "codex"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "[mcp_servers.reactor]") || strings.Contains(out, "bearer_token_env_var") {
		t.Fatalf("loopback no-auth registration should not require an unset bearer: %q", out)
	}
}
