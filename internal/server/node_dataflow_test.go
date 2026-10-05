package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	_ "modernc.org/sqlite"
)

const dataflowDAG = `{
  "steps": [
    {"name": "fetch", "kind": "step"},
    {"name": "transform", "kind": "step", "depends_on": ["fetch"]},
    {"name": "notify", "kind": "step", "depends_on": ["transform"]},
    {"name": "log", "kind": "side_effect", "depends_on": ["transform"]}
  ],
  "edges": [
    {"from": "fetch", "to": "transform"},
    {"from": "transform", "to": "notify"},
    {"from": "transform", "to": "log"}
  ]
}`

func names(cs []nodeConn) string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.Name
	}
	return strings.Join(out, ",")
}

func TestDagConnections_Middle(t *testing.T) {
	up, down := dagConnections([]byte(dataflowDAG), "transform")
	if names(up) != "fetch" {
		t.Fatalf("upstream = %q, want fetch", names(up))
	}
	if names(down) != "notify,log" {
		t.Fatalf("downstream = %q, want notify,log", names(down))
	}
}

func TestDagConnections_Source(t *testing.T) {
	up, down := dagConnections([]byte(dataflowDAG), "fetch")
	if len(up) != 0 {
		t.Fatalf("source node should have no upstream, got %q", names(up))
	}
	if names(down) != "transform" {
		t.Fatalf("downstream = %q, want transform", names(down))
	}
}

func TestDagConnections_KindCarried(t *testing.T) {
	up, _ := dagConnections([]byte(dataflowDAG), "notify")
	if len(up) != 1 || up[0].Name != "transform" || up[0].Kind != "step" {
		t.Fatalf("expected upstream transform(step), got %+v", up)
	}
}

func TestDagConnections_BadJSON(t *testing.T) {
	up, down := dagConnections([]byte("not json"), "x")
	if up != nil || down != nil {
		t.Fatalf("bad json should yield nil, nil")
	}
}

func TestDagConnections_VisualNodesAndEdges(t *testing.T) {
	visual := []byte(`{
  "nodes": [
    {"id": "fetch", "kind": "step"},
    {"id": "transform", "kind": "step"},
    {"id": "notify", "kind": "side_effect"}
  ],
  "edges": [
    {"from": "fetch", "to": "transform"},
    {"from": "transform", "to": "notify"}
  ]
}`)
	up, down := dagConnections(visual, "transform")
	if names(up) != "fetch" {
		t.Fatalf("visual upstream = %q, want fetch", names(up))
	}
	if names(down) != "notify" {
		t.Fatalf("visual downstream = %q, want notify", names(down))
	}
	if len(down) != 1 || down[0].Kind != "side_effect" {
		t.Fatalf("visual downstream kind = %+v, want side_effect", down)
	}
}

func TestDagConnections_VisualNodeNameFallback(t *testing.T) {
	visual := []byte(`{
  "nodes": [
    {"name": "fetch", "kind": "step"},
    {"name": "notify", "kind": "step"}
  ],
  "edges": [{"from": "fetch", "to": "notify"}]
}`)
	up, _ := dagConnections(visual, "notify")
	if len(up) != 1 || up[0].Name != "fetch" || up[0].Kind != "step" {
		t.Fatalf("visual name fallback upstream = %+v, want fetch(step)", up)
	}
}

func TestDagConnections_MixedGraphUsesExecutableStepsAndDropsStaleVisualEdges(t *testing.T) {
	mixed := []byte(`{
  "steps": [
    {"name":"send","kind":"step"},
    {"name":"notify","kind":"side_effect","depends_on":["visual-only"]}
  ],
  "nodes": [
    {"id":"send","kind":"side_effect"},
    {"id":"visual-only","kind":"step"}
  ],
  "edges": [
    {"from":"send","to":"visual-only"},
    {"from":"visual-only","to":"notify"},
    {"from":"send","to":"notify"}
  ]
}`)

	up, down := dagConnections(mixed, "notify")
	if len(up) != 0 {
		t.Fatalf("stale edges invented an executable predecessor: %+v", up)
	}

	_, down = dagConnections(mixed, "send")
	if len(down) != 0 {
		t.Fatalf("stale edges invented an executable successor: %+v", down)
	}
}

func TestDagConnectionsExecutableStepsIgnoreStaleEdgeBetweenRealSteps(t *testing.T) {
	dag := []byte(`{"steps":[{"name":"fetch","kind":"step"},{"name":"send","kind":"step"}],"edges":[{"from":"fetch","to":"send"}]}`)
	up, _ := dagConnections(dag, "send")
	_, down := dagConnections(dag, "fetch")
	if len(up) != 0 || len(down) != 0 {
		t.Fatalf("drawer invented a dependency from stale visual edge: upstream=%+v downstream=%+v", up, down)
	}
}

func TestDagConnectionsDuplicateExecutableDefinitionsKeepFirstTopology(t *testing.T) {
	// Imported/legacy rows can contain duplicate names even though new DAG
	// authoring rejects them. The drawer must use the same first-definition
	// precedence as the canvas and MCP flow projection, so a stale duplicate
	// cannot change a node's kind or invent a lineage edge.
	duplicate := []byte(`{
  "steps": [
    {"name":"send","kind":"step"},
    {"name":"hidden","kind":"step"},
    {"name":"send","kind":"side_effect","depends_on":["hidden"]},
    {"name":"notify","kind":"step","depends_on":["send"]}
  ]
}`)

	up, _ := dagConnections(duplicate, "notify")
	if len(up) != 1 || up[0].Name != "send" || up[0].Kind != "step" {
		t.Fatalf("duplicate upstream = %+v; want first send(step) only", up)
	}
	_, down := dagConnections(duplicate, "hidden")
	if len(down) != 0 {
		t.Fatalf("stale duplicate added downstream lineage: %+v", down)
	}
}

func TestDagConnectionsDuplicateVisualDefinitionsKeepFirstKind(t *testing.T) {
	duplicate := []byte(`{
  "nodes": [
    {"id":"send","kind":"step"},
    {"id":"send","kind":"side_effect"},
    {"id":"notify","kind":"step"}
  ],
  "edges": [{"from":"send","to":"notify"}]
}`)
	up, _ := dagConnections(duplicate, "notify")
	if len(up) != 1 || up[0].Name != "send" || up[0].Kind != "step" {
		t.Fatalf("duplicate visual upstream = %+v; want first send(step)", up)
	}
}

func TestRenderDAGSummaryUsesVisualNodeIDs(t *testing.T) {
	summary := renderDAGSummary(`{"nodes":[{"id":"fetch","kind":"step"}]}`)
	if !strings.Contains(summary, "<code>fetch</code>") {
		t.Fatalf("visual DAG summary omitted node id: %s", summary)
	}
}

func TestRenderDAGSummaryUsesExecutablePrecedenceAndIgnoresStaleEdges(t *testing.T) {
	summary := renderDAGSummary(`{
  "steps": [{"name":"send","kind":"step"},{"name":"notify","kind":"side_effect"}],
  "nodes": [{"id":"send","kind":"side_effect"},{"id":"visual-only","kind":"step"}],
  "edges": [{"from":"send","to":"notify"}]
}`)
	if strings.Contains(summary, "visual-only") {
		t.Fatalf("mixed DAG summary surfaced visual-only node: %s", summary)
	}
	if strings.Contains(summary, "<td>send</td>") {
		t.Fatalf("accessible summary invented a dependency from stale visual edge: %s", summary)
	}
	if !strings.Contains(summary, "<code>send</code></td><td>step</td>") {
		t.Fatalf("summary used stale visual node kind for executable send node: %s", summary)
	}
}

func TestRenderDAGSummaryExecutableStepsIgnoreStaleEdgeBetweenRealSteps(t *testing.T) {
	summary := renderDAGSummary(`{"steps":[{"name":"fetch","kind":"step"},{"name":"send","kind":"step"}],"edges":[{"from":"fetch","to":"send"}]}`)
	if !strings.Contains(summary, `<code>send</code></td><td>step</td><td><span class="muted">-</span>`) {
		t.Fatalf("accessible summary invented an edge between executable steps: %s", summary)
	}
}

func TestRenderDAGSummaryExecutableStepsIgnoreStaleEdgeBudget(t *testing.T) {
	staleEdges := strings.TrimSuffix(strings.Repeat(`{"from":"fetch","to":"send"},`, maxFlowEdges+1), ",")
	summary := renderDAGSummary(`{"steps":[{"name":"fetch","kind":"step"},{"name":"send","kind":"step"}],"edges":[` + staleEdges + `]}`)
	if !strings.Contains(summary, `<code>send</code>`) || strings.Contains(summary, "exceeds the visual summary limits") {
		t.Fatalf("ignored visual edges hid the executable step table: %s", summary)
	}
}

func TestRenderDAGSummaryUsesVisualEdges(t *testing.T) {
	summary := renderDAGSummary(`{
  "nodes": [{"id":"fetch","kind":"step"},{"id":"notify","kind":"side_effect"}],
  "edges": [{"from":"fetch","to":"notify"}]
}`)
	if !strings.Contains(summary, "<td>fetch</td>") {
		t.Fatalf("visual edge dependency missing from accessible summary: %s", summary)
	}
}

func TestRenderDAGSummaryDropsDanglingAndSelfDependencies(t *testing.T) {
	summary := renderDAGSummary(`{
  "steps": [
    {"name":"fetch","kind":"step","depends_on":["fetch","missing"]},
    {"name":"notify","kind":"side_effect","depends_on":["fetch"]}
  ],
  "edges": [{"from":"fetch","to":"notify"},{"from":"notify","to":"notify"},{"from":"missing","to":"notify"}]
}`)
	if strings.Contains(summary, "missing") {
		t.Fatalf("summary surfaced dangling dependency: %s", summary)
	}
	if strings.Contains(summary, "fetch, fetch") || strings.Contains(summary, "notify, notify") {
		t.Fatalf("summary surfaced self/duplicate dependency: %s", summary)
	}
	if !strings.Contains(summary, "<td>fetch</td>") {
		t.Fatalf("summary lost the valid visual dependency: %s", summary)
	}
}

func TestRenderDAGSummaryBoundsOversizedGraph(t *testing.T) {
	oversized := `{"steps":[{"name":"` + strings.Repeat("x", maxFlowIdentifier+1) + `"}]}`
	summary := renderDAGSummary(oversized)
	if !strings.Contains(summary, "oversized step definition") {
		t.Fatalf("oversized graph should render a bounded warning: %s", summary)
	}
}

func TestLatestStepOutputsBoundsHistoricalOutput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "dataflow.db")
	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(context.Background(), silent, "sqlite://"+dbPath); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	j := journal.New(db, journal.EngineSQLite)
	ctx := context.Background()
	dag := json.RawMessage(`{"steps":[{"name":"fetch"},{"name":"sink","depends_on":["fetch"]}]}`)
	artifact := strings.Repeat("a", 64)
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_dataflow_bound", "dataflow-bound", "hash", "0.1.0", artifact, dag); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRunPinned(ctx, "run_dataflow_bound", "wf_dataflow_bound", "manual", json.RawMessage(`{}`), 1, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordStepStartSeq(ctx, "run_dataflow_bound", "fetch", 1, 1, "key", "hash"); err != nil {
		t.Fatal(err)
	}
	large := json.RawMessage(`"` + strings.Repeat("x", maxNodeDataflowOutputBytes+32) + `"`)
	if err := j.RecordStepEndSeq(ctx, "run_dataflow_bound", "fetch", 1, 1, large, ""); err != nil {
		t.Fatal(err)
	}

	outputs, runID := (&Server{Journal: j}).latestStepOutputs(ctx, "dataflow-bound", journal.DefaultTenant, dag)
	if runID != "run_dataflow_bound" {
		t.Fatalf("sample run = %q, want run_dataflow_bound", runID)
	}
	fetch, ok := outputs["fetch"]
	if !ok {
		t.Fatalf("fetch output missing: %#v", outputs)
	}
	if len(fetch.Output) != 0 || !fetch.OutputTruncated || fetch.OutputBytes != len(large) {
		t.Fatalf("bounded fetch output = %+v; want omitted payload with explicit byte receipt", fetch)
	}

	// The drawer projection must carry the omission receipt through its
	// upstream connection, otherwise the browser would mislabel this as a
	// missing sample.
	dagDir := filepath.Join(dir, "workflow")
	if err := os.MkdirAll(dagDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dagDir, "dag.json"), dag, 0o600); err != nil {
		t.Fatal(err)
	}
	upstream, _, _ := (&Server{Journal: j}).nodeDataflow(ctx, "dataflow-bound", dagDir, "sink", journal.DefaultTenant)
	if len(upstream) != 1 || !upstream[0].OutputTruncated || upstream[0].OutputBytes != len(large) {
		t.Fatalf("drawer upstream = %+v; want propagated output truncation receipt", upstream)
	}
}

func TestLatestStepOutputsRespectsSelectedTenantForDuplicateSlug(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "tenant-dataflow.db")
	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(context.Background(), silent, "sqlite://"+dbPath); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	j := journal.New(db, journal.EngineSQLite)
	ctx := context.Background()
	dag := json.RawMessage(`{"steps":[{"name":"fetch"}]}`)
	for _, tenant := range []string{"acme", "globex"} {
		artifactDigit := "a"
		if tenant == "globex" {
			artifactDigit = "b"
		}
		artifact := strings.Repeat(artifactDigit, 64)
		if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_"+tenant, "shared-flow", "hash", "0.1.0", artifact, dag, tenant); err != nil {
			t.Fatal(err)
		}
		runID := "run_" + tenant
		if err := j.CreateRunPinned(ctx, runID, "wf_"+tenant, "manual", json.RawMessage(`{}`), 1, artifact); err != nil {
			t.Fatal(err)
		}
		if _, err := j.RecordStepStartSeq(ctx, runID, "fetch", 1, 1, "key-"+tenant, "hash"); err != nil {
			t.Fatal(err)
		}
		if err := j.RecordStepEndSeq(ctx, runID, "fetch", 1, 1, json.RawMessage(`{"tenant":"`+tenant+`"}`), ""); err != nil {
			t.Fatal(err)
		}
	}

	outputs, runID := (&Server{Journal: j}).latestStepOutputs(ctx, "shared-flow", "acme", dag)
	if runID != "run_acme" || string(outputs["fetch"].Output) != `{"tenant":"acme"}` {
		t.Fatalf("selected tenant dataflow = run %q output %s; want acme run/output", runID, outputs["fetch"].Output)
	}
}

func TestLatestStepOutputsRequiresCurrentVersionArtifactAndDAG(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j := journalForServerTest(t)
	srv := &Server{Journal: j}
	v1DAG := json.RawMessage(`{"steps":[{"name":"fetch","kind":"step"}]}`)
	v2DAG := json.RawMessage(`{"steps":[{"name":"fetch","kind":"step"},{"name":"sink","kind":"step","depends_on":["fetch"]}]}`)
	v1Artifact, v2Artifact := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_sample_version", "sample-version", "hash1", "0.1.0", v1Artifact, v1DAG); err != nil {
		t.Fatal(err)
	}
	assertNoSample := func(dag []byte) {
		t.Helper()
		outputs, runID := srv.latestStepOutputs(ctx, "sample-version", journal.DefaultTenant, dag)
		if len(outputs) != 0 || runID != "" {
			t.Fatalf("unfenced sample leaked: run=%q outputs=%+v", runID, outputs)
		}
	}
	addRun := func(id string, version int, artifact string, pinned bool) {
		t.Helper()
		var err error
		if pinned {
			err = j.CreateRunPinned(ctx, id, "wf_sample_version", "manual", json.RawMessage(`{}`), version, artifact)
		} else {
			err = j.CreateRun(ctx, id, "wf_sample_version", "manual", json.RawMessage(`{}`))
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := j.RecordStepStartSeq(ctx, id, "fetch", 1, 1, "idem", "input"); err != nil {
			t.Fatal(err)
		}
		if err := j.RecordStepEndSeq(ctx, id, "fetch", 1, 1, json.RawMessage(`{"from":"`+id+`"}`), ""); err != nil {
			t.Fatal(err)
		}
	}

	addRun("run_1_unpinned", 0, "", false)
	assertNoSample(v1DAG)
	addRun("run_2_v1", 1, v1Artifact, true)
	if outputs, runID := srv.latestStepOutputs(ctx, "sample-version", journal.DefaultTenant, v1DAG); runID != "run_2_v1" || string(outputs["fetch"].Output) != `{"from":"run_2_v1"}` {
		t.Fatalf("matching v1 sample = run %q output %s", runID, outputs["fetch"].Output)
	}
	assertNoSample(v2DAG) // The drawer source must match the reviewed version.
	if version, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_sample_version", "0.1.0", "hash2", v2Artifact, v2DAG); err != nil || version != 2 {
		t.Fatalf("record v2 = %d, %v", version, err)
	}
	assertNoSample(v1DAG)
	assertNoSample(v2DAG) // The newest run still belongs to v1.
	addRun("run_3_wrong_artifact", 2, v1Artifact, true)
	assertNoSample(v2DAG)
	addRun("run_4_v2", 2, v2Artifact, true)
	if outputs, runID := srv.latestStepOutputs(ctx, "sample-version", journal.DefaultTenant, v2DAG); runID != "run_4_v2" || string(outputs["fetch"].Output) != `{"from":"run_4_v2"}` {
		t.Fatalf("matching v2 sample = run %q output %s", runID, outputs["fetch"].Output)
	}
}
