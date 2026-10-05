package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// codexTOMLSnippet renders the Codex CLI MCP config block. Codex reads
// ~/.codex/config.toml and registers HTTP MCP servers as [mcp_servers.*].
// bearer_token_env_var is the same credential handoff used by the Stage
// connection, so the token never lands in config.toml or shell history.
func codexTOMLSnippet(endpoint, tokenEnv string, authRequested bool) string {
	block := fmt.Sprintf("[mcp_servers.reactor]\nurl = %s\n", strconv.Quote(endpoint))
	if authRequested {
		block += fmt.Sprintf("bearer_token_env_var = %s\n", strconv.Quote(tokenEnv))
	}
	return block + "startup_timeout_sec = 20\ntool_timeout_sec = 1860\n"
}

// availableClients is the list shown in usage + accepted by --client.
var availableClients = []string{
	"claude-desktop",
	"claude-code",
	"codex",
	"cursor",
	"continue",
	"cline",
	"generic",
}

// cmdMCPInstall prints (or applies, with --apply) the registration the
// named MCP client expects for Reactor. The snippet shape varies per
// client, but all supported clients point at the daemon's Streamable HTTP
// endpoint. The daemon itself is started with `reactor serve`.
func cmdMCPInstall(args []string) error {
	fs := flag.NewFlagSet("mcp install", flag.ContinueOnError)
	client := fs.String("client", "", "MCP client name (required): "+strings.Join(availableClients, ", "))
	apply := fs.Bool("apply", false, "modify the client's config file in place (default: print only)")
	endpoint := fs.String("url", envFirstOr("http://127.0.0.1:7777/mcp", "REACTOR_MCP_URL"), "daemon MCP HTTP endpoint (default: http://127.0.0.1:7777/mcp)")
	token := fs.String("token", "", "unsupported legacy flag; use --token-env so bearer values stay out of argv")
	tokenEnv := fs.String("token-env", "REACTOR_MCP_TOKEN", "environment variable the client reads for the bearer token; the value is never written to config")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if *client == "" {
		return errors.New("mcp install: --client required (one of " + strings.Join(availableClients, ", ") + ")")
	}
	if !knownClient(*client) {
		return fmt.Errorf("mcp install: unknown client %q (have: %s)", *client, strings.Join(availableClients, ", "))
	}
	*endpoint = strings.TrimSpace(*endpoint)
	if err := validateMCPEndpoint(*endpoint); err != nil {
		return err
	}
	*tokenEnv = strings.TrimSpace(*tokenEnv)
	if !validEnvName(*tokenEnv) {
		return fmt.Errorf("mcp install: --token-env must be a valid environment variable name")
	}
	// Literal token arguments are visible in shell history and process lists.
	// Accepting them as a compatibility signal still teaches an unsafe path.
	if *token != "" {
		return fmt.Errorf("mcp install: --token values are never embedded or accepted; export %s and use --token-env %s", *tokenEnv, *tokenEnv)
	}
	authRequested := strings.TrimSpace(os.Getenv(*tokenEnv)) != ""
	// A generated registration is the operator's complete connection recipe.
	// If it targets a remote host, omitting the bearer would produce a snippet
	// that can never pass Reactor's /mcp connection gate (and may tempt an
	// operator to weaken that gate). Loopback development may intentionally use
	// the daemon's explicit no-auth mode; remote registrations must carry the
	// same environment-backed bearer contract used by Stage/Mesh.
	if !authRequested && !mcpEndpointIsLoopback(*endpoint) {
		return fmt.Errorf("mcp install: remote endpoint requires a bearer token; export %s before installing", *tokenEnv)
	}

	// Codex CLI reads ~/.codex/config.toml (TOML, not JSON), so it takes a
	// different snippet shape than the mcpServers-JSON clients.
	if *client == "codex" {
		if *apply {
			path, err := codexMCPConfigPath()
			if err != nil {
				return err
			}
			if err := applyCodexMCPConfig(path, codexTOMLSnippet(*endpoint, *tokenEnv, authRequested)); err != nil {
				return err
			}
			fmt.Printf("reactor MCP entry is configured in %s\n", path)
			return nil
		}
		fmt.Println("# reactor MCP snippet for codex")
		fmt.Println("# (paste into ~/.codex/config.toml, merging with any existing [mcp_servers.*] tables)")
		fmt.Print(codexTOMLSnippet(*endpoint, *tokenEnv, authRequested))
		return nil
	}

	snippet, configPath, err := buildSnippet(*client, *endpoint, authRequested, *tokenEnv)
	if err != nil {
		return err
	}

	pretty, err := json.MarshalIndent(snippet, "", "  ")
	if err != nil {
		return err
	}

	if !*apply {
		fmt.Printf("# reactor MCP snippet for %s\n", *client)
		if configPath != "" {
			fmt.Printf("# (paste into %s, merging with existing mcpServers)\n", configPath)
		}
		if *client == "claude-code" {
			// Keep the same connection recipe used by Stage: Claude Code's
			// project-scoped command writes the .mcp.json registration for us.
			fmt.Printf("# Claude Code equivalent: %s\n", claudeCodeAddCommand(*endpoint, authRequested, *tokenEnv))
		}
		fmt.Println(string(pretty))
		return nil
	}
	if configPath == "" {
		return fmt.Errorf("mcp install: --apply not supported for client %q (snippet is freeform)", *client)
	}
	if *client == "cline" {
		return errors.New("mcp install: --apply is not supported for Cline; add the printed snippet to its VS Code settings")
	}
	return applyToClientConfig(configPath, snippet)
}

// validateMCPEndpoint keeps the generated client registration on the same
// transport boundary as the daemon: loopback may use plain HTTP for local
// development, while every remote endpoint must be HTTPS. Rejecting a path,
// query, or userinfo mismatch here prevents a copied snippet from silently
// targeting a different handler or leaking a bearer token to an unintended URL.
func validateMCPEndpoint(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("mcp install: --url must be an absolute HTTP(S) /mcp endpoint")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("mcp install: --url scheme must be http or https")
	}
	if u.Path != "/mcp" {
		return fmt.Errorf("mcp install: --url path must be /mcp")
	}
	host := strings.ToLower(u.Hostname())
	loopback := isLoopbackMCPHost(host)
	if u.Scheme == "http" && !loopback {
		return fmt.Errorf("mcp install: refusing remote plain HTTP endpoint %q; use HTTPS", raw)
	}
	return nil
}

func mcpEndpointIsLoopback(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return false
	}
	return isLoopbackMCPHost(strings.ToLower(u.Hostname()))
}

func isLoopbackMCPHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func claudeCodeAddCommand(endpoint string, authRequested bool, tokenEnv string) string {
	// Keep both the endpoint and header as single-quoted shell arguments. In
	// particular, `${TOKEN_ENV}` must reach Claude Code literally so its MCP
	// config can resolve the environment variable when it connects. Double
	// quotes would make the invoking shell expand the bearer into argv and may
	// persist the secret in the generated project config.
	cmd := fmt.Sprintf("claude mcp add reactor %s --transport http --scope project", shellQuote(endpoint))
	if authRequested {
		// Keep the secret in the environment, not in shell history, argv, or
		// the project-scoped .mcp.json that this command creates. Claude Code
		// expands ${VAR} when it loads the project MCP registration.
		cmd += " --header " + shellQuote("Authorization: Bearer ${"+tokenEnv+"}")
	}
	return cmd
}

// shellQuote returns a POSIX-shell-safe single-quoted argument. The MCP
// installer prints copy/paste commands; quoting untrusted URL text and the
// literal environment placeholder prevents command substitution, whitespace
// splitting, and accidental bearer expansion by the invoking shell.
func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func knownClient(name string) bool {
	for _, c := range availableClients {
		if c == name {
			return true
		}
	}
	return false
}

// buildSnippet returns (snippet-json-shape, default-config-path-for-this-client, error).
// The snippet is always rooted at "mcpServers.reactor" because that's
// the de-facto MCP convention every client we target follows.
func buildSnippet(client, endpoint string, authRequested bool, tokenEnv string) (any, string, error) {
	server := map[string]any{
		"type": "http",
		"url":  endpoint,
	}
	if authRequested {
		// The flag is only a signal that authentication is desired. Never put
		// its value into a generated file; clients read the dedicated variable
		// from their process environment at connection time.
		server["headers"] = map[string]string{"Authorization": "Bearer ${" + tokenEnv + "}"}
	}
	wrapper := map[string]any{
		"mcpServers": map[string]any{
			"reactor": server,
		},
	}
	switch client {
	case "claude-desktop":
		return wrapper, claudeDesktopConfigPath(), nil
	case "claude-code":
		// Claude Code's project-scoped HTTP registration is stored in .mcp.json.
		// This is also the shape written by `claude mcp add --scope project`.
		return wrapper, ".mcp.json", nil
	case "cursor":
		// cursor reads ~/.cursor/mcp.json with the same shape.
		return wrapper, expandHome("~/.cursor/mcp.json"), nil
	case "continue":
		// continue.dev's config.json uses "mcpServers" too (since v0.9).
		return wrapper, expandHome("~/.continue/config.json"), nil
	case "cline":
		// cline reads VS Code settings; tell the operator where without
		// trying to merge VS Code's bigger config file ourselves.
		return wrapper, "(your VS Code settings.json under cline.mcpServers)", nil
	case "generic":
		// Pure HTTP block; clients speaking the shared 2025-03-26 contract can
		// lift this in directly.
		return server, "", nil
	}
	return nil, "", fmt.Errorf("mcp install: unhandled client %q", client)
}

func validEnvName(name string) bool {
	if name == "" || (name[0] != '_' && (name[0] < 'A' || name[0] > 'Z') && (name[0] < 'a' || name[0] > 'z')) {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func claudeDesktopConfigPath() string {
	switch runtime.GOOS {
	case "darwin":
		return expandHome("~/Library/Application Support/Claude/claude_desktop_config.json")
	case "windows":
		return os.ExpandEnv("$APPDATA/Claude/claude_desktop_config.json")
	default:
		return expandHome("~/.config/Claude/claude_desktop_config.json")
	}
}

func expandHome(p string) string {
	if !strings.HasPrefix(p, "~") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, strings.TrimPrefix(p, "~"))
}

// applyToClientConfig adds Reactor to a JSON MCP client config. A different
// Reactor entry is an operator-owned connection: never silently replace its
// endpoint or bearer environment. Stage through a private file and atomically
// rename so a client cannot read half of a new registration.
func applyToClientConfig(path string, snippet any) error {
	wrapper, ok := snippet.(map[string]any)
	if !ok {
		return errors.New("mcp install: snippet shape unexpected")
	}
	servers, _ := wrapper["mcpServers"].(map[string]any)
	newReactor, ok := servers["reactor"]
	if !ok {
		return errors.New("mcp install: snippet missing mcpServers.reactor")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mcp install: create client config directory: %w", err)
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("mcp install: client config directory must be a real directory")
	}
	lockPath := path + ".reactor-install.lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("mcp install: client config install lock exists; wait for the other install or inspect a stale lock")
		}
		return fmt.Errorf("mcp install: lock client config: %w", err)
	}
	defer os.Remove(lockPath)
	if err := lock.Close(); err != nil {
		return fmt.Errorf("mcp install: close client config lock: %w", err)
	}
	var raw []byte
	existed := false
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("mcp install: client config must be a regular file")
		}
		existed = true
		raw, err = os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("mcp install: read client config: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("mcp install: inspect client config: %w", err)
	}
	existing := map[string]any{}
	if existed {
		if err := json.Unmarshal(raw, &existing); err != nil {
			return fmt.Errorf("mcp install: client config must be a JSON object: %w", err)
		}
		if existing == nil {
			return errors.New("mcp install: client config must be a JSON object")
		}
	}
	mergedServers := map[string]any{}
	if existingServers, present := existing["mcpServers"]; present {
		var valid bool
		mergedServers, valid = existingServers.(map[string]any)
		if !valid {
			return errors.New("mcp install: client mcpServers must be a JSON object")
		}
	}
	if current, present := mergedServers["reactor"]; present {
		currentJSON, currentErr := json.Marshal(current)
		newJSON, newErr := json.Marshal(newReactor)
		if currentErr != nil || newErr != nil || !bytes.Equal(currentJSON, newJSON) {
			return errors.New("mcp install: client already has a different Reactor entry; inspect it before changing the connection")
		}
		return nil
	}
	mergedServers["reactor"] = newReactor
	existing["mcpServers"] = mergedServers
	out, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return err
	}
	if existed {
		if err := backupMCPJSONConfig(path, raw); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, ".reactor-mcp-config-*")
	if err != nil {
		return fmt.Errorf("mcp install: stage client config: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("mcp install: protect client config: %w", err)
	}
	if _, err := tmp.Write(append(out, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("mcp install: stage client config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("mcp install: sync client config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("mcp install: close client config: %w", err)
	}
	if err := checkMCPJSONConfigUnchanged(path, raw, existed); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("mcp install: activate client config: %w", err)
	}
	fmt.Printf("wrote reactor MCP entry to %s\n", path)
	return nil
}

func checkMCPJSONConfigUnchanged(path string, original []byte, existed bool) error {
	info, err := os.Lstat(path)
	if !existed {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("mcp install: recheck client config: %w", err)
		}
		return errors.New("mcp install: client config changed during install; inspect it before retrying")
	}
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("mcp install: client config changed during install; inspect it before retrying")
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("mcp install: recheck client config: %w", err)
	}
	if !bytes.Equal(current, original) {
		return errors.New("mcp install: client config changed during install; inspect it before retrying")
	}
	return nil
}

func backupMCPJSONConfig(path string, raw []byte) error {
	backup := fmt.Sprintf("%s.bak-%d", path, time.Now().UnixNano())
	f, err := os.OpenFile(backup, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("mcp install: back up client config: %w", err)
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return fmt.Errorf("mcp install: back up client config: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("mcp install: sync client config backup: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("mcp install: close client config backup: %w", err)
	}
	return nil
}
