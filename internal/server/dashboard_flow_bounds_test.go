package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkflowDetailDoesNotEmbedOversizedDAG(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dag.json"), []byte(`{"steps":[]}`+strings.Repeat("x", maxFlowDAGBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	dag, path, truncated := readFirstAvailableBounded(dir, maxFlowDAGBytes, "dag.json", "source/dag.json")
	if path != filepath.Join(dir, "dag.json") || !truncated || len(dag) != maxFlowDAGBytes {
		t.Fatalf("bounded DAG read = path %q bytes %d truncated %v; want path, %d bytes, true", path, len(dag), truncated, maxFlowDAGBytes)
	}

	html := workflowDetailBody(workflowDetailData{Slug: "oversized", DAGPath: path, DAG: string(dag), DAGTruncated: true, EditEnabled: true})
	if !strings.Contains(html, "was not embedded") || strings.Contains(html, `id="dag-data"`) || strings.Contains(html, `cytoscape.min.js`) {
		t.Fatalf("oversized DAG still rendered as an executable visual flow: %s", html)
	}
	if !strings.Contains(html, "dag.json editor is disabled") || strings.Contains(html, `action="/workflows/oversized/dag`) {
		t.Fatalf("oversized DAG still exposed a destructive truncated editor: %s", html)
	}
}

func TestWorkflowDetailDoesNotEmbedOversizedSource(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	marker := "source-marker-that-must-not-be-rendered"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(marker+strings.Repeat("x", maxFlowSourceBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	code, path, truncated := readFirstAvailableBounded(dir, maxFlowSourceBytes, "main.go", "workflow.go", "source/main.go")
	if path != filepath.Join(dir, "main.go") || !truncated || len(code) != maxFlowSourceBytes {
		t.Fatalf("bounded source read = path %q bytes %d truncated %v; want path, %d bytes, true", path, len(code), truncated, maxFlowSourceBytes)
	}

	html := workflowDetailBody(workflowDetailData{
		Slug: "oversized-source", CodePath: path, Code: string(code), CodeTruncated: true, EditEnabled: true,
	})
	if !strings.Contains(html, "exceeds the dashboard projection limit") || strings.Contains(html, `name="body"`) || strings.Contains(html, marker) || strings.Contains(html, `data-editable="true"`) {
		t.Fatalf("oversized source still rendered as editable dashboard code: %s", html)
	}
}

func TestMaterializeWorkflowSourceRejectsOversizedLegacyFile(t *testing.T) {
	t.Parallel()
	source := t.TempDir()
	workspace := filepath.Join(t.TempDir(), "workspace")
	path := filepath.Join(source, "helper.bin")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxWorkflowMaterializedFileBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := materializeWorkflowSource(source, workspace, strings.Repeat("f", 64)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized legacy source was materialized: %v", err)
	}
	if _, err := os.Stat(workspace); !os.IsNotExist(err) {
		t.Fatalf("failed materialization left workspace behind: %v", err)
	}
}
