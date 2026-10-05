package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestPayloadBackfillCommandDefinitionsRequiresExistingKeyAndSealsLegacyRow(t *testing.T) {
	t.Setenv("REACTOR_MASTER_KEY", "")
	t.Setenv("ARACHNE_MASTER_KEY", "")
	ctx := context.Background()
	dbURL, j := newSeededDB(t)
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"printf cli-private-command","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, journal.DefaultTenant, "cmd_cli_backfill", "cli-backfill", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	master := bytes.Repeat([]byte{0x71}, 32)
	keyFile := filepath.Join(root, "master.key")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(master)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"backfill-command-definitions", "--db", dbURL, "--root", root, "--master-key-file", keyFile, "--limit", "1"}
	if err := cmdPayload(ctx, args); err == nil || !strings.Contains(err.Error(), "journal key is not initialized") {
		t.Fatalf("unkeyed backfill = %v", err)
	}
	if err := j.EnablePayloadEncryption(ctx, master, nil); err != nil {
		t.Fatal(err)
	}
	if err := cmdPayload(ctx, args); err != nil {
		t.Fatalf("keyed backfill: %v", err)
	}
	db, _, err := migrate.Open(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var stored string
	var version int
	if err := db.QueryRowContext(ctx, `SELECT definition_json, definition_crypto_version
		FROM command_automation_versions WHERE automation_id = ? AND version = 1`, plan.ID).Scan(&stored, &version); err != nil {
		t.Fatal(err)
	}
	if version != 1 || strings.Contains(stored, "cli-private-command") {
		t.Fatalf("CLI backfill left plaintext: version=%d", version)
	}
	if err := cmdPayload(ctx, args); err != nil {
		t.Fatalf("idempotent backfill: %v", err)
	}
}

func TestPayloadBackfillRunLogsRequiresExistingKeyAndPreservesExactRead(t *testing.T) {
	t.Setenv("REACTOR_MASTER_KEY", "")
	t.Setenv("ARACHNE_MASTER_KEY", "")
	ctx := context.Background()
	dbURL, j := newSeededDB(t)
	const line = "synthetic historical run log value"
	if err := j.SaveRunLogs(ctx, "run_t", []string{line}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	master := bytes.Repeat([]byte{0x72}, 32)
	keyFile := filepath.Join(root, "master.key")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(master)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"backfill-run-logs", "--db", dbURL, "--root", root, "--master-key-file", keyFile, "--limit", "1"}
	if err := cmdPayload(ctx, args); err == nil || !strings.Contains(err.Error(), "journal key is not initialized") {
		t.Fatalf("unkeyed run-log backfill = %v", err)
	}
	if err := j.EnablePayloadEncryption(ctx, master, nil); err != nil {
		t.Fatal(err)
	}
	if err := cmdPayload(ctx, args); err != nil {
		t.Fatalf("keyed run-log backfill: %v", err)
	}
	db, _, err := migrate.Open(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var stored string
	var version int
	if err := db.QueryRowContext(ctx, `SELECT line, payload_crypto_version
		FROM run_logs WHERE run_id = ? AND seq = 0`, "run_t").Scan(&stored, &version); err != nil {
		t.Fatal(err)
	}
	if version != 1 || strings.Contains(stored, line) {
		t.Fatalf("CLI backfill left a plaintext run log: version=%d", version)
	}
	got, err := j.GetRunLogs(ctx, "run_t")
	if err != nil || len(got) != 1 || got[0] != line {
		t.Fatalf("exact run-log read changed: lines=%q err=%v", got, err)
	}
	if err := cmdPayload(ctx, args); err != nil {
		t.Fatalf("idempotent run-log backfill: %v", err)
	}
}
