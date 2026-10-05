package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/codegen"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestMCPStdioDispatchUsesDispatcherAndWaitsForLocalRun(t *testing.T) {
	setMCPAcceptanceSDK(t)
	root := t.TempDir()
	dbURL := "sqlite://" + filepath.Join(root, "reactor.db")
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(context.Background(), log, dbURL); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, engine, err := migrate.Open(dbURL)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	j := journal.New(db, journal.EngineSQLite)
	built, err := codegen.BuildAndRegisterSource(context.Background(), j, codegen.BuildSourceRequest{
		Slug: "stdio-e2e", MainGo: mcpAcceptanceWorkflowSource("stdio-e2e"),
		DAGJSON: mcpAcceptanceDAG, StateRoot: root, TenantID: journal.DefaultTenant,
	})
	if err != nil {
		db.Close()
		t.Fatalf("build workflow through canonical authoring path: %v", err)
	}
	db.Close()
	if engine != migrate.EngineSQLite {
		t.Fatalf("engine = %v, want sqlite", engine)
	}

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		t.Fatal(err)
	}
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	defer func() {
		os.Stdin, os.Stdout = oldIn, oldOut
		inR.Close()
		outR.Close()
	}()

	done := make(chan error, 1)
	go func() {
		done <- cmdMCPStdio(context.Background(), log, []string{
			"--db", dbURL,
			"--root", root,
			"--master-key", strings.Repeat("42", 32),
			"--allow-dispatch",
		})
	}()
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"reactor_dispatch_workflow","arguments":{"slug":"stdio-e2e","payload":{"source":"stdio"}}}}` + "\n"
	if _, err := io.WriteString(inW, request); err != nil {
		t.Fatal(err)
	}
	if err := inW.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stdio MCP: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stdio MCP did not drain the dispatched run")
	}
	if err := outW.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(outR)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &response); err != nil {
		t.Fatalf("decode MCP response %q: %v", raw, err)
	}
	if len(response.Result.Content) != 1 {
		t.Fatalf("MCP response content = %+v", response.Result.Content)
	}
	var dispatchResult struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal([]byte(response.Result.Content[0].Text), &dispatchResult); err != nil {
		t.Fatalf("decode dispatch result %q: %v", response.Result.Content[0].Text, err)
	}
	if dispatchResult.RunID == "" {
		t.Fatalf("dispatch result omitted run id: %q", response.Result.Content[0].Text)
	}

	verifyDB, _, err := migrate.Open(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer verifyDB.Close()
	verifyJournal := journal.New(verifyDB, journal.EngineSQLite)
	if err := verifyJournal.LoadPayloadEncryption(context.Background(), bytes.Repeat([]byte{0x42}, 32), nil); err != nil {
		t.Fatalf("load dispatch journal data key: %v", err)
	}
	run, err := verifyJournal.GetRun(context.Background(), dispatchResult.RunID)
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	if run.Status != "succeeded" || run.WorkflowArtifactSHA256 != built.ArtifactSHA256 {
		t.Fatalf("stdio run = %+v, want succeeded with artifact %s", run, built.ArtifactSHA256)
	}
}
