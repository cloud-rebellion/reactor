package main

import (
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/bright-interaction/reactor/internal/registry"
)

// Generate and build an immutable local candidate through the documented CLI
// path. No database or registration/activation operation is supplied.
func TestFlareIncidentDraftScaffoldBuildsWithoutRegistration(t *testing.T) {
	reactorRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("REACTOR_SDK_REPLACE", reactorRoot)
	t.Setenv("ARACHNE_SDK_REPLACE", "")
	destination, stateRoot := t.TempDir(), t.TempDir()
	const slug = "client-incident-review"
	if err := cmdNew(context.Background(), slog.Default(), []string{"flare-incident-draft", slug, "--dest=" + destination}); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(destination, slug)
	if _, err := parser.ParseFile(token.NewFileSet(), filepath.Join(source, "main.go"), nil, parser.AllErrors); err != nil {
		t.Fatalf("generated workflow is not valid Go: %v", err)
	}
	var dag struct {
		Triggers []struct {
			Provider string `json:"provider"`
		} `json:"triggers"`
		Steps []struct {
			Name string `json:"name"`
		} `json:"steps"`
	}
	body, err := os.ReadFile(filepath.Join(source, "dag.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &dag); err != nil {
		t.Fatalf("invalid generated DAG: %v", err)
	}
	if len(dag.Triggers) != 1 || dag.Triggers[0].Provider != "flare-v1" || len(dag.Steps) != 2 || dag.Steps[0].Name != "flare-fresh-triage" || dag.Steps[1].Name != "flare-confirm-draft" {
		t.Fatalf("scaffold advanced beyond the two evidence steps: %+v", dag)
	}
	if _, err := os.Stat(filepath.Join(source, "README.md")); err != nil {
		t.Fatal(err)
	}
	if err := cmdWorkflowBuild(context.Background(), []string{"--src=" + source, "--slug=" + slug, "--root=" + stateRoot}); err != nil {
		t.Fatalf("generated evidence workflow does not build against the current SDK: %v", err)
	}
	if _, err := registry.New(filepath.Join(stateRoot, "workflows")).BuildArtifact(slug); err != nil {
		t.Fatalf("local immutable candidate missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(source, "go.mod")); !os.IsNotExist(err) {
		t.Fatalf("build modified generated source with module metadata: %v", err)
	}
}
