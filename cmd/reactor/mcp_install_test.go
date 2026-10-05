package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/mcp"
)

// captureStdout swaps os.Stdout for a pipe, runs fn, returns what was
// written. Lets us assert the JSON snippet shape without hitting the
// real terminal.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, _ := os.Pipe()
	orig := os.Stdout
	os.Stdout = w
	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	err := fn()
	w.Close()
	<-done
	os.Stdout = orig
	return buf.String(), err
}

func TestMCPInstallEachClientPrintsValidJSON(t *testing.T) {
	t.Setenv("REACTOR_MCP_TOKEN", "synthetic-token-never-persist")
	for _, c := range availableClients {
		c := c
		t.Run(c, func(t *testing.T) {
			out, err := captureStdout(t, func() error {
				return cmdMCPInstall([]string{"--client", c})
			})
			if err != nil {
				t.Fatalf("install %s: %v", c, err)
			}
			// Codex uses ~/.codex/config.toml (TOML), not the mcpServers JSON.
			if c == "codex" {
				for _, want := range []string{"[mcp_servers.reactor]", "url = \"http://127.0.0.1:7777/mcp\"", "bearer_token_env_var = \"REACTOR_MCP_TOKEN\"", "startup_timeout_sec = 20"} {
					if !strings.Contains(out, want) {
						t.Fatalf("codex output missing %q\n--output--\n%s", want, out)
					}
				}
				return
			}
			// Strip the comment header lines so json.Unmarshal sees valid JSON.
			body := stripComments(out)
			var any interface{}
			if err := json.Unmarshal([]byte(body), &any); err != nil {
				t.Fatalf("install %s output is not JSON: %v\n--output--\n%s", c, err, out)
			}
			if !strings.Contains(out, `"type": "http"`) || !strings.Contains(out, `"url": "http://127.0.0.1:7777/mcp"`) {
				t.Fatalf("install %s output is not an HTTP MCP registration\n--output--\n%s", c, out)
			}
		})
	}
}

func TestMCPInstallRejectsUnknownClient(t *testing.T) {
	t.Parallel()
	err := cmdMCPInstall([]string{"--client", "nope"})
	if err == nil || !strings.Contains(err.Error(), "unknown client") {
		t.Fatalf("got %v, want unknown-client error", err)
	}
}

func TestMCPInstallUsesRequestedHTTPURL(t *testing.T) {
	t.Setenv("REACTOR_API_TOKEN", "rtr_remote_test")
	out, err := captureStdout(t, func() error {
		return cmdMCPInstall([]string{"--client", "generic", "--url", "https://reactor.internal.example/mcp", "--token-env", "REACTOR_API_TOKEN"})
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !strings.Contains(out, `"type": "http"`) || !strings.Contains(out, `"url": "https://reactor.internal.example/mcp"`) {
		t.Fatalf("custom HTTP URL missing from registration:\n%s", out)
	}
	if strings.Contains(out, `"command"`) || strings.Contains(out, `"args"`) {
		t.Fatalf("HTTP registration unexpectedly contains stdio fields:\n%s", out)
	}
	if !strings.Contains(out, `"Authorization": "Bearer ${REACTOR_API_TOKEN}"`) {
		t.Fatalf("remote HTTP registration omitted bearer placeholder:\n%s", out)
	}
}

func TestMCPInstallRejectsUnauthenticatedRemoteEndpoint(t *testing.T) {
	t.Setenv("REACTOR_MCP_TOKEN", "")
	err := cmdMCPInstall([]string{"--client", "generic", "--url", "https://reactor.internal.example/mcp"})
	if err == nil || !strings.Contains(err.Error(), "remote endpoint requires a bearer token") {
		t.Fatalf("got %v, want remote bearer requirement", err)
	}
}

func TestMCPInstallRejectsRemotePlainHTTP(t *testing.T) {
	t.Parallel()
	err := cmdMCPInstall([]string{"--client", "generic", "--url", "http://reactor.internal.example/mcp"})
	if err == nil || !strings.Contains(err.Error(), "remote plain HTTP") {
		t.Fatalf("got %v, want remote-HTTP refusal", err)
	}
	err = cmdMCPInstall([]string{"--client", "generic", "--url", "http://localhost.localdomain/mcp"})
	if err == nil || !strings.Contains(err.Error(), "remote plain HTTP") {
		t.Fatalf("localhost.localdomain error = %v, want remote-HTTP refusal", err)
	}
}

func TestMCPInstallNormalizesEndpointWhitespaceBeforeRendering(t *testing.T) {
	t.Setenv("REACTOR_API_TOKEN", "synthetic-token-never-persist")
	out, err := captureStdout(t, func() error {
		return cmdMCPInstall([]string{"--client", "codex", "--url", "  https://reactor.example/mcp  ", "--token-env", "REACTOR_API_TOKEN"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "url = \"https://reactor.example/mcp\"") || strings.Contains(out, "url = \"  https://") {
		t.Fatalf("installer rendered unnormalized URL: %q", out)
	}
}

func TestMCPInstallRejectsNonMCPPath(t *testing.T) {
	t.Parallel()
	err := cmdMCPInstall([]string{"--client", "generic", "--url", "https://reactor.example.com/api/mcp"})
	if err == nil || !strings.Contains(err.Error(), "path must be /mcp") {
		t.Fatalf("got %v, want /mcp path refusal", err)
	}
}

func TestMCPInstallIncludesBearerAndClaudeCodeProjectRecipe(t *testing.T) {
	t.Setenv("REACTOR_API_TOKEN", "rtr_test_token")
	out, err := captureStdout(t, func() error {
		return cmdMCPInstall([]string{
			"--client", "claude-code",
			"--url", "https://reactor.internal.example/mcp",
			"--token-env", "REACTOR_API_TOKEN",
		})
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	for _, want := range []string{
		"claude mcp add reactor 'https://reactor.internal.example/mcp' --transport http --scope project",
		`--header 'Authorization: Bearer ${REACTOR_API_TOKEN}'`,
		`"headers": {`,
		`"Authorization": "Bearer ${REACTOR_API_TOKEN}"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("authenticated Claude Code registration missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "rtr_test_token") {
		t.Fatalf("installer leaked the bearer into generated output:\n%s", out)
	}
}

func TestMCPInstallRejectsLiteralTokenWithoutNamedEnvironment(t *testing.T) {
	t.Parallel()
	err := cmdMCPInstall([]string{"--client", "generic", "--token", "rtr_literal"})
	if err == nil || !strings.Contains(err.Error(), "values are never embedded") {
		t.Fatalf("error = %v, want safe token-env guidance", err)
	}
}

func TestMCPInstallRejectsLiteralTokenEvenWithNamedEnvironment(t *testing.T) {
	t.Setenv("REACTOR_MCP_TOKEN", "synthetic-token-never-persist")
	err := cmdMCPInstall([]string{"--client", "generic", "--token", "rtr_literal"})
	if err == nil || !strings.Contains(err.Error(), "never embedded or accepted") {
		t.Fatalf("error = %v, want literal-token rejection", err)
	}
}

func TestMCPInstallClaudeCodeUsesProjectMCPConfig(t *testing.T) {
	snippet, path, err := buildSnippet("claude-code", "http://127.0.0.1:7777/mcp", false, "REACTOR_MCP_TOKEN")
	if err != nil {
		t.Fatalf("build snippet: %v", err)
	}
	if path != ".mcp.json" {
		t.Fatalf("Claude Code config path = %q, want .mcp.json", path)
	}
	if snippet == nil {
		t.Fatal("nil snippet")
	}
}

func TestMCPInstallJSONApplyPreservesConnectionsAndRefusesReplacement(t *testing.T) {
	t.Setenv("REACTOR_API_TOKEN", "rtr_secret_value")
	path := filepath.Join(t.TempDir(), ".mcp.json")
	original := []byte(`{"mcpServers":{"stage":{"type":"http","url":"https://stage.example/mcp"}},"otherSetting":true}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	snippet, _, err := buildSnippet("claude-code", "https://reactor.example/mcp", true, "REACTOR_API_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if err := applyToClientConfig(path, snippet); err != nil {
		t.Fatal(err)
	}
	installed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		MCPServers map[string]struct {
			Type    string            `json:"type"`
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
		} `json:"mcpServers"`
		OtherSetting bool `json:"otherSetting"`
	}
	if err := json.Unmarshal(installed, &config); err != nil {
		t.Fatal(err)
	}
	if !config.OtherSetting || config.MCPServers["stage"].URL != "https://stage.example/mcp" ||
		config.MCPServers["reactor"].URL != "https://reactor.example/mcp" ||
		config.MCPServers["reactor"].Headers["Authorization"] != "Bearer ${REACTOR_API_TOKEN}" {
		t.Fatalf("installed JSON lost another setting or the environment-backed connection: %s", installed)
	}
	if strings.Contains(string(installed), "rtr_secret_value") {
		t.Fatalf("installed JSON contains a literal bearer: %s", installed)
	}
	backups, err := filepath.Glob(path + ".bak-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups = %v, %v; want one", backups, err)
	}
	backup, err := os.ReadFile(backups[0])
	if err != nil || !bytes.Equal(backup, original) {
		t.Fatalf("backup differs from original: %v", err)
	}
	if err := applyToClientConfig(path, snippet); err != nil {
		t.Fatalf("identical registration should be idempotent: %v", err)
	}
	conflict, _, err := buildSnippet("claude-code", "https://other.example/mcp", true, "REACTOR_API_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if err := applyToClientConfig(path, conflict); err == nil || !strings.Contains(err.Error(), "different Reactor entry") {
		t.Fatalf("conflicting endpoint was accepted: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, installed) {
		t.Fatalf("conflicting apply changed the client config: %v", err)
	}
	backups, err = filepath.Glob(path + ".bak-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("idempotent/conflicting apply produced backups = %v, %v; want one", backups, err)
	}
}

func TestMCPInstallJSONApplyRejectsAmbiguousOrRedirectedConfig(t *testing.T) {
	snippet, _, err := buildSnippet("claude-code", "https://reactor.example/mcp", true, "REACTOR_API_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{`null`, `{"mcpServers":null}`, `{"mcpServers":[]}`} {
		path := filepath.Join(t.TempDir(), ".mcp.json")
		if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := applyToClientConfig(path, snippet); err == nil {
			t.Fatalf("ambiguous client config %q was replaced", input)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != input {
			t.Fatalf("ambiguous client config %q changed: %q, %v", input, got, err)
		}
	}
	target := filepath.Join(t.TempDir(), "actual.json")
	if err := os.WriteFile(target, []byte(`{"mcpServers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(filepath.Dir(target), ".mcp.json")
	if err := os.Symlink(target, linked); err != nil {
		t.Fatal(err)
	}
	if err := applyToClientConfig(linked, snippet); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlinked client config was accepted: %v", err)
	}
}

func TestMCPInstallClineApplyRequiresManualSettings(t *testing.T) {
	err := cmdMCPInstall([]string{"--client", "cline", "--apply"})
	if err == nil || !strings.Contains(err.Error(), "not supported for Cline") {
		t.Fatalf("Cline apply = %v; want refusal", err)
	}
}

func TestClaudeCodeRecipeOmitsPlaceholderBearerWithoutAuth(t *testing.T) {
	got := claudeCodeAddCommand("http://127.0.0.1:7777/mcp", false, "REACTOR_MCP_TOKEN")
	if strings.Contains(got, "--header") || strings.Contains(got, "REACTOR_API_TOKEN") {
		t.Fatalf("unauthenticated recipe contains a credential placeholder: %q", got)
	}
}

func TestClaudeCodeRecipeShellQuotesEndpointAndBearerPlaceholder(t *testing.T) {
	got := claudeCodeAddCommand("https://reactor.example/mcp", true, "REACTOR_API_TOKEN")
	if want := "claude mcp add reactor 'https://reactor.example/mcp'"; !strings.Contains(got, want) {
		t.Fatalf("endpoint is not shell-quoted: got %q, want substring %q", got, want)
	}
	if want := "--header 'Authorization: Bearer ${REACTOR_API_TOKEN}'"; !strings.Contains(got, want) {
		t.Fatalf("bearer placeholder is not shell-quoted: got %q, want substring %q", got, want)
	}
	if strings.Contains(got, "Bearer rtr_") {
		t.Fatalf("recipe contains a literal bearer: %q", got)
	}
}

func TestMCPCheckPerformsAuthenticatedInitializeWithoutLeakingBody(t *testing.T) {
	var gotAuth, gotAccept, gotProtocol string
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotAuth = req.Header.Get("Authorization")
		gotAccept = req.Header.Get("Accept")
		gotProtocol = req.Header.Get(mcp.MCPProtocolVersionHeader)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"reactor","version":"test"}}}`)),
			Header:     make(http.Header),
		}, nil
	})}
	got, err := checkMCP(context.Background(), "https://reactor.example.com/mcp", "rtr_test", client)
	if err != nil {
		t.Fatalf("checkMCP: %v", err)
	}
	if got.Name != "reactor" || got.Version != "test" || got.Protocol != mcp.ProtocolVersion {
		t.Fatalf("result = %+v", got)
	}
	if gotAuth != "Bearer rtr_test" || gotAccept != "application/json, text/event-stream" || gotProtocol != mcp.ProtocolVersion {
		t.Fatalf("headers auth=%q accept=%q protocol=%q", gotAuth, gotAccept, gotProtocol)
	}
}

func TestMCPCheckRedactsNonSuccessBody(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       io.NopCloser(strings.NewReader(`secret-proxy-body`)),
			Header:     make(http.Header),
		}, nil
	})}
	_, err := checkMCP(context.Background(), "https://reactor.example.com/mcp", "bad", client)
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") || strings.Contains(err.Error(), "secret-proxy-body") {
		t.Fatalf("error = %v, want redacted HTTP status", err)
	}
}

func TestMCPCheckRejectsRedirectWithoutForwardingBearer(t *testing.T) {
	for _, target := range []string{
		"https://reactor.example.com/other",
		"https://redirect.reactor.example.com/mcp",
	} {
		t.Run(target, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls != 1 || req.URL.String() != "https://reactor.example.com/mcp" {
					t.Fatalf("MCP check followed redirect to %s with Authorization %q", req.URL, req.Header.Get("Authorization"))
				}
				return &http.Response{
					StatusCode: http.StatusTemporaryRedirect,
					Body:       io.NopCloser(strings.NewReader("proxy redirect details")),
					Header:     http.Header{"Location": []string{target}},
				}, nil
			})}
			_, err := checkMCP(context.Background(), "https://reactor.example.com/mcp", "rtr_test", client)
			if err == nil || !strings.Contains(err.Error(), "HTTP 307") || strings.Contains(err.Error(), "proxy redirect details") || calls != 1 {
				t.Fatalf("redirect result = calls %d, err %v; want one exact request and a redacted HTTP 307", calls, err)
			}
		})
	}
}

func TestMCPCheckRejectsIncompatibleProtocol(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"old-reactor","version":"test"}}}`)),
			Header:     make(http.Header),
		}, nil
	})}
	_, err := checkMCP(context.Background(), "https://reactor.example.com/mcp", "rtr_test", client)
	if err == nil || !strings.Contains(err.Error(), "incompatible protocol") || !strings.Contains(err.Error(), mcp.ProtocolVersion) {
		t.Fatalf("error = %v, want protocol mismatch", err)
	}
}

func TestMCPCheckRejectsAnotherMCPServer(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"mesh","version":"test"}}}`)),
			Header:     make(http.Header),
		}, nil
	})}
	_, err := checkMCP(context.Background(), "https://reactor.example.com/mcp", "rtr_test", client)
	if err == nil || !strings.Contains(err.Error(), "endpoint is not Reactor") {
		t.Fatalf("wrong-server check = %v, want Reactor identity error", err)
	}
}

func TestMCPCheckRejectsInvalidInitializeEnvelope(t *testing.T) {
	for _, response := range []string{
		`{"id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"reactor","version":"test"}}}`,
		`{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"reactor","version":"test"}}}`,
	} {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(response)),
				Header:     make(http.Header),
			}, nil
		})}
		_, err := checkMCP(context.Background(), "https://reactor.example.com/mcp", "rtr_test", client)
		if err == nil || !strings.Contains(err.Error(), "invalid JSON-RPC envelope") {
			t.Fatalf("invalid-envelope check = %v, want JSON-RPC envelope error", err)
		}
	}
}

func TestMCPCheckBearerReadsNamedEnvironment(t *testing.T) {
	t.Setenv("REACTOR_API_TOKEN", "api-test-token")
	got, err := mcpCheckBearer("", "REACTOR_API_TOKEN")
	if err != nil || got != "api-test-token" {
		t.Fatalf("named environment bearer = %q, %v", got, err)
	}
	if _, err := mcpCheckBearer("", "BAD-ENV-NAME"); err == nil {
		t.Fatal("invalid token environment name accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestMCPInstallRequiresClient(t *testing.T) {
	t.Parallel()
	err := cmdMCPInstall([]string{})
	if err == nil || !strings.Contains(err.Error(), "--client required") {
		t.Fatalf("got %v, want --client required error", err)
	}
}

func stripComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}
