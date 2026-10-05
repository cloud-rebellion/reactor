package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// TestRunLeaderTasksSignalsReadinessAfterLocalStartup verifies that the
// readiness fence is reached only after the local cron driver and all leader
// loops have been launched. This protects /readyz from advertising an HTTP/MCP
// endpoint while trigger processing is still being initialised.
func TestRunLeaderTasksSignalsReadinessAfterLocalStartup(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("chmod state root: %v", err)
	}
	dbURL := "sqlite://" + filepath.Join(root, "reactor.db")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &serveConfig{
		dbURL:            dbURL,
		root:             root,
		masterKey:        mustReadinessMasterKey(t),
		mode:             "local",
		tickInterval:     time.Hour,
		rotationInterval: time.Hour,
		cronReload:       0,
	}
	deps, err := openServeDeps(context.Background(), log, cfg)
	if err != nil {
		t.Fatalf("open serve deps: %v", err)
	}
	t.Cleanup(func() { _ = deps.db.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	deps.leaderReady = func() { close(ready) }
	done := make(chan error, 1)
	go func() { done <- runLeaderTasks(ctx, log, cfg, deps) }()

	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("leader startup did not signal readiness")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("leader shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("leader did not stop after context cancellation")
	}
}

func mustReadinessMasterKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func TestCommandAutomationRuntimeReadyWithdrawsWithoutRunner(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	dbURL := "sqlite://" + filepath.Join(root, "runtime-ready.db")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	deps, err := openServeDeps(context.Background(), log, &serveConfig{
		dbURL: dbURL, root: root, masterKey: mustReadinessMasterKey(t), mcpTenant: "acme", mode: "local",
	})
	if err != nil {
		t.Fatalf("open serve deps: %v", err)
	}
	t.Cleanup(func() { _ = deps.db.Close() })
	if !commandAutomationRuntimeReady(deps.journal, "acme", false) {
		t.Fatal("runner-disabled daemon with no active command triggers should be ready")
	}

	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := deps.journal.CreateCommandAutomation(context.Background(), "acme", "cmd_ready", "ready", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	_, normalized, err := commandautomations.Normalize(definition)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(normalized)
	definitionSHA256 := hex.EncodeToString(digest[:])
	gateSum := sha256.Sum256([]byte("readiness-gate"))
	gateDigest := hex.EncodeToString(gateSum[:])
	input := journal.CommandAutomationScheduleInput{
		ID:                "cmdsched_ready",
		AutomationID:      plan.ID,
		AutomationVersion: plan.CurrentVersion,
		DefinitionSHA256:  definitionSHA256,
		ReceiptID:         commandautomations.ReceiptIDForGateDigest("acme", plan.ID, plan.CurrentVersion, definitionSHA256, gateDigest),
		GateDigest:        gateDigest,
		ActorID:           "alice",
		Spec:              "0 9 * * *",
		Timezone:          "UTC",
	}
	schedule, err := deps.journal.CreateCommandAutomationSchedule(context.Background(), "acme", input)
	if err != nil {
		t.Fatal(err)
	}
	if err := deps.journal.SetCommandAutomationEnabledIfStateAndVersion(context.Background(), "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	if err := deps.journal.SetCommandAutomationScheduleStateIfRevision(context.Background(), "acme", schedule.ID, journal.CommandAutomationScheduleActive, schedule.Revision); err != nil {
		t.Fatal(err)
	}
	if commandAutomationRuntimeReady(deps.journal, "acme", false) {
		t.Fatal("runner-disabled daemon advertised ready with active command schedule")
	}
	if !commandAutomationRuntimeReady(deps.journal, "acme", true) {
		t.Fatal("live command runner should keep readiness independent of trigger receipts")
	}
}
