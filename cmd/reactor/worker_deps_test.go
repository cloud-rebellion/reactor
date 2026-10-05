package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkerArtifactRootRequiresExistingRealWorkflowTree(t *testing.T) {
	privateRoot := t.TempDir()
	artifactRoot := filepath.Join(t.TempDir(), "artifacts")
	cfg := &serveConfig{root: privateRoot, workerArtifactRoot: artifactRoot}
	if got := cfg.executionArtifactRoot(); got != artifactRoot {
		t.Fatalf("execution artifact root = %q, want %q", got, artifactRoot)
	}
	if err := validateWorkerArtifactRoot(artifactRoot); err == nil {
		t.Fatal("missing artifact mount was accepted")
	}
	if _, err := os.Stat(artifactRoot); !os.IsNotExist(err) {
		t.Fatalf("missing artifact mount was created: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(artifactRoot, "workflows"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateWorkerArtifactRoot(artifactRoot); err != nil {
		t.Fatalf("real artifact tree rejected: %v", err)
	}
	if err := os.Remove(filepath.Join(artifactRoot, "workflows")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(privateRoot, filepath.Join(artifactRoot, "workflows")); err != nil {
		t.Fatal(err)
	}
	if err := validateWorkerArtifactRoot(artifactRoot); err == nil {
		t.Fatal("symlinked workflow tree was accepted")
	}
}
