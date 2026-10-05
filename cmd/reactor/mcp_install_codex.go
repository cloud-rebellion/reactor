package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// codexMCPConfigPath follows Codex's user-level configuration root. A custom
// CODEX_HOME must already exist, matching the client contract; do not silently
// create a different client profile when its configured root is misspelled.
func codexMCPConfigPath() (string, error) {
	root := strings.TrimSpace(os.Getenv("CODEX_HOME"))
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("mcp install: locate Codex home: %w", err)
		}
		root = filepath.Join(home, ".codex")
	} else if !filepath.IsAbs(root) {
		return "", errors.New("mcp install: CODEX_HOME must be an absolute existing directory")
	} else if info, err := os.Lstat(root); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("mcp install: CODEX_HOME must be a real existing directory")
	}
	return filepath.Join(root, "config.toml"), nil
}

// applyCodexMCPConfig appends one self-contained TOML table to an existing
// config. It never rewrites another server table or tries to interpret arbitrary
// TOML. A different Reactor entry is a conflict for an operator to inspect.
func applyCodexMCPConfig(path, block string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mcp install: create Codex config directory: %w", err)
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("mcp install: Codex config directory must be a real directory")
	}
	// Serialize Reactor installers before reading. Atomic rename protects
	// readers from partial files, but without this lock two concurrent applies
	// could both see no Reactor entry and silently overwrite one another.
	lockPath := path + ".reactor-install.lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("mcp install: Codex config install lock exists; wait for the other install or inspect a stale lock")
		}
		return fmt.Errorf("mcp install: lock Codex config: %w", err)
	}
	defer os.Remove(lockPath)
	if err := lock.Close(); err != nil {
		return fmt.Errorf("mcp install: close Codex config lock: %w", err)
	}
	var raw []byte
	existed := false
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("mcp install: Codex config must be a regular file")
		}
		existed = true
		raw, err = os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("mcp install: read Codex config: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("mcp install: inspect Codex config: %w", err)
	}
	// Catch ordinary and quoted Reactor table spellings, as well as nested
	// tool-policy tables. Refusing ambiguous existing content is safer than
	// appending a duplicate TOML table or discarding custom policy.
	reactorTables := 0
	ambiguous := false
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		trimmed := strings.TrimSpace(string(line))
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// TOML allows whitespace around dotted keys. Normalize it before
		// checking for an existing Reactor table; otherwise appending a
		// second spelling can invalidate the whole client configuration.
		compact := strings.ReplaceAll(strings.ReplaceAll(trimmed, " ", ""), "\t", "")
		if compact == "[mcp_servers.reactor]" {
			reactorTables++
			continue
		}
		// A parent table or inline map can already define a Reactor child
		// on another line. Without parsing arbitrary TOML, leave these for
		// manual review rather than risk a duplicate table.
		if (strings.Contains(compact, "mcp_servers") && strings.Contains(compact, "reactor")) ||
			strings.HasPrefix(compact, "[mcp_servers]") ||
			strings.HasPrefix(compact, "[[mcp_servers") ||
			strings.HasPrefix(compact, "mcp_servers=") {
			ambiguous = true
		}
	}
	if bytes.Contains(raw, []byte(block)) && reactorTables == 1 && !ambiguous {
		return nil
	}
	if reactorTables > 0 || ambiguous {
		return errors.New("mcp install: Codex already has a Reactor or ambiguous MCP entry; inspect config.toml before changing it")
	}
	if len(raw) > 0 {
		if err := backupCodexConfig(path, raw); err != nil {
			return err
		}
	}
	var updated bytes.Buffer
	updated.Write(raw)
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		updated.WriteByte('\n')
	}
	if len(raw) > 0 {
		updated.WriteByte('\n')
	}
	updated.WriteString(block)
	tmp, err := os.CreateTemp(dir, ".reactor-mcp-config-*")
	if err != nil {
		return fmt.Errorf("mcp install: stage Codex config: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("mcp install: protect Codex config: %w", err)
	}
	if _, err := tmp.Write(updated.Bytes()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("mcp install: stage Codex config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("mcp install: sync Codex config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("mcp install: close Codex config: %w", err)
	}
	if err := checkCodexConfigUnchanged(path, raw, existed); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("mcp install: activate Codex config: %w", err)
	}
	return nil
}

// Other tools do not honor Reactor's install lock. Detect a changed or
// replaced config before activating the staged file so an ordinary concurrent
// edit is not silently lost. This is a best-effort drift check, not a lock for
// external writers that mutate in the final instant before rename.
func checkCodexConfigUnchanged(path string, original []byte, existed bool) error {
	info, err := os.Lstat(path)
	if !existed {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("mcp install: recheck Codex config: %w", err)
		}
		return errors.New("mcp install: Codex config changed during install; inspect it before retrying")
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("mcp install: Codex config changed during install; inspect it before retrying")
		}
		return fmt.Errorf("mcp install: recheck Codex config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("mcp install: Codex config changed during install; inspect it before retrying")
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("mcp install: recheck Codex config: %w", err)
	}
	if !bytes.Equal(current, original) {
		return errors.New("mcp install: Codex config changed during install; inspect it before retrying")
	}
	return nil
}

func backupCodexConfig(path string, raw []byte) error {
	backup := fmt.Sprintf("%s.bak-%d", path, time.Now().UnixNano())
	f, err := os.OpenFile(backup, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("mcp install: back up Codex config: %w", err)
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return fmt.Errorf("mcp install: back up Codex config: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("mcp install: sync Codex config backup: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("mcp install: close Codex config backup: %w", err)
	}
	return nil
}
