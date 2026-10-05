package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/flowblocks"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// Exercise the real dashboard routes and their JSON islands, not only the
// individual render helpers. The current editor view must follow the current
// immutable version while a historical run retains its own pinned graph.
func TestHTTPVisualFlowAndHistoricalRunUseTheirOwnVersion(t *testing.T) {
	ctx := context.Background()
	stateRoot := t.TempDir()
	reg := registry.New(filepath.Join(stateRoot, "workflows"))
	j := journalForServerTest(t)
	const slug, workflowID, runID = "visual-acceptance", "wf_visual_acceptance", "run_visual_acceptance"
	const firstSource = `package main
import (
  "context"
  r "github.com/bright-interaction/reactor/sdk"
  b "github.com/bright-interaction/reactor/sdk/blocks"
)
func Run(ctx context.Context, flow r.Flow) error {
  _, err := r.Step(flow, ctx, "process", r.StepOpts{}, func(context.Context) (int, error) {
    yes, no := b.Split([]int{1, 2}, func(n int) bool { return n%2 == 0 })
    each := b.Iterate(yes, func(n int) int { return n * 2 })
    total := b.Aggregate(each, 0, func(sum, n int) int { return sum + n })
    joined, joinErr := b.JoinByKey(no, []int{total}, func(n int) int { return n }, func(n int) int { return n }, b.JoinFull, 10)
    if joinErr != nil { return 0, joinErr }
    return len(joined), nil
  })
  return err
}
`
	firstDAG := json.RawMessage(`{"steps":[{"name":"process","kind":"step","visual_flow":{"blocks":[{"id":"route","kind":"split"},{"id":"each","kind":"iterate"},{"id":"total","kind":"aggregate"},{"id":"join","kind":"merge","mode":"full_join","key":"id","max_rows":10}],"edges":[{"from":"route","to":"each","route":"yes"},{"from":"route","to":"join","route":"no"},{"from":"each","to":"total"},{"from":"total","to":"join"}]}}]}`)
	firstArtifact, firstHash, firstManifest := publishVisualAcceptanceArtifact(t, reg, slug, firstSource, firstDAG, "v1")
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, workflowID, slug, firstHash, "0.1.0", firstArtifact, firstDAG, journal.DefaultTenant, firstManifest); err != nil {
		t.Fatal(err)
	}

	s := &Server{Journal: j, Registry: reg, WorkflowsRoot: reg.Root, State: stateRoot,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), BasicAuth: BasicAuthConfig{AllowNoAuth: true}}
	r := chi.NewRouter()
	s.Mount(r)

	current := visualAcceptanceGET(t, r, "/workflows/"+slug)
	if !strings.Contains(current, "Durable flow proof verified") || !strings.Contains(current, `id="dag-canvas"`) ||
		!strings.Contains(current, `id="wf-blockflow-canvas"`) {
		t.Fatalf("current workflow page lacks verified visual flow: %s", current)
	}
	var canvasDAG struct {
		Steps []struct {
			Name string `json:"name"`
		} `json:"steps"`
	}
	visualAcceptanceIsland(t, current, "dag-data", &canvasDAG)
	if len(canvasDAG.Steps) != 1 || canvasDAG.Steps[0].Name != "process" {
		t.Fatalf("workflow canvas graph = %+v, want process", canvasDAG)
	}
	var blocks flowblocks.Projection
	visualAcceptanceIsland(t, current, "step-flows-data", &blocks)
	if !blocks.Complete || blocks.Provenance != "author_declared_annotation" || blocks.BehaviorVerified ||
		blocks.BlockCount != 4 || blocks.EdgeCount != 4 || len(blocks.Steps) != 1 {
		t.Fatalf("customer block projection = %+v", blocks)
	}
	for i, kind := range []string{"split", "iterate", "aggregate", "merge"} {
		if blocks.Steps[0].Blocks[i].Kind != kind {
			t.Fatalf("block %d = %+v, want %s", i, blocks.Steps[0].Blocks[i], kind)
		}
	}
	if !strings.Contains(current, "via yes") || !strings.Contains(current, "via no") || !strings.Contains(current, "mode: full join") ||
		!strings.Contains(current, "max rows: 10") || !strings.Contains(current, "author-declared annotations") {
		t.Fatalf("accessible block fallback omitted route, mode, bound, or trust label: %s", current)
	}

	if err := j.CreateRunPinned(ctx, runID, workflowID, "manual", json.RawMessage(`{"private":"synthetic-input"}`), 1, firstArtifact); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordStepStartSeq(ctx, runID, "process", 1, 1, "", firstHash); err != nil {
		t.Fatal(err)
	}
	input2, yes1, no1, input1 := 2, 1, 1, 1
	for _, receipt := range []journal.BlockReceipt{
		{BlockID: "route", Kind: "split", CallOrdinal: 1, InputRows: &input2, YesRows: &yes1, NoRows: &no1, Outcome: "succeeded"},
		{BlockID: "each", Kind: "iterate", CallOrdinal: 2, InputRows: &input1, OutputRows: 1, Outcome: "succeeded"},
		{BlockID: "total", Kind: "aggregate", CallOrdinal: 3, InputRows: &input1, OutputRows: 1, Outcome: "succeeded"},
		{BlockID: "join", Kind: "merge", CallOrdinal: 4, Mode: "full_join", LeftRows: 1, RightRows: 1, OutputRows: 2, MaxRows: 10, Outcome: "succeeded"},
	} {
		receipt.RunID, receipt.StepName, receipt.Seq, receipt.Attempt = runID, "process", 1, 1
		if err := j.AppendBlockReceipt(ctx, journal.DefaultTenant, "", receipt); err != nil {
			t.Fatalf("append %s receipt: %v", receipt.Kind, err)
		}
	}
	if err := j.RecordStepEndSeq(ctx, runID, "process", 1, 1, json.RawMessage(`{"count":2}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, runID, "succeeded"); err != nil {
		t.Fatal(err)
	}

	const secondSource = `package main
import (
  "context"
  r "github.com/bright-interaction/reactor/sdk"
)
func Run(ctx context.Context, flow r.Flow) error {
  _, err := r.Step(flow, ctx, "replacement", r.StepOpts{}, func(context.Context) (int, error) { return 1, nil })
  return err
}
`
	secondDAG := json.RawMessage(`{"steps":[{"name":"replacement","kind":"step"}]}`)
	secondArtifact, secondHash, secondManifest := publishVisualAcceptanceArtifact(t, reg, slug, secondSource, secondDAG, "v2")
	if version, err := j.RecordWorkflowVersionWithArtifact(ctx, workflowID, "0.2.0", secondHash, secondArtifact, secondDAG, secondManifest); err != nil || version != 2 {
		t.Fatalf("record replacement version = %d, %v", version, err)
	}
	current = visualAcceptanceGET(t, r, "/workflows/"+slug)
	visualAcceptanceIsland(t, current, "dag-data", &canvasDAG)
	if len(canvasDAG.Steps) != 1 || canvasDAG.Steps[0].Name != "replacement" ||
		strings.Contains(current, `id="step-flows-data"`) || !strings.Contains(current, "Durable flow proof verified") {
		t.Fatalf("current workflow page borrowed the historical graph: %s", current)
	}

	historical := visualAcceptanceGET(t, r, "/runs/"+runID)
	for _, want := range []string{"<code>1</code>", firstArtifact, "flow-succeeded", "process", "4 author-declared visual blocks &middot; 4 SDK-reported block IDs in this run",
		"input 2, yes 1, no 1 rows", "input 1, output 1", "left 1, right 1, output 2 rows", "via yes", "SDK-reported observation"} {
		if !strings.Contains(historical, want) {
			t.Fatalf("historical run page lacks %q: %s", want, historical)
		}
	}
	if strings.Contains(historical, "replacement") || strings.Contains(historical, "synthetic-input") ||
		strings.Count(historical, `class="flow-node `) != 1 {
		t.Fatalf("historical flow borrowed current graph, exposed trigger input, or promoted inner blocks to durable nodes: %s", historical)
	}
}

func TestWorkflowDetailSnapshotRejectsMixedWorkspaceAndImmutableVersion(t *testing.T) {
	currentCode := []byte("package main\nfunc Run() {}\n")
	staleCode := []byte("package main\nfunc Run() { println(1) }\n")
	currentDAG := []byte(`{"steps":[{"name":"current"}]}`)
	staleDAG := []byte(`{"steps":[{"name":"stale"}]}`)
	sum := sha256.Sum256(currentCode)
	version := journal.WorkflowVersion{Version: 2, ArtifactSHA256: strings.Repeat("a", 64),
		CodeHash: hex.EncodeToString(sum[:])[:16], DAG: currentDAG}
	if _, _, err := workflowDetailSnapshot(version, staleCode, false, staleDAG, false); err == nil {
		t.Fatal("stale editor source could be paired with a verified current-version graph")
	}
	dag, truncated, err := workflowDetailSnapshot(version, currentCode, false, staleDAG, false)
	if err != nil || truncated || string(dag) != string(currentDAG) {
		t.Fatalf("current graph = %q, truncated %v, err %v; want immutable version DAG", dag, truncated, err)
	}
	version.DAGTruncated = true
	dag, truncated, err = workflowDetailSnapshot(version, currentCode, false, staleDAG, false)
	if err != nil || !truncated || string(dag) != string(currentDAG) {
		t.Fatalf("bounded current graph = %q, truncated %v, err %v; want version omission flag", dag, truncated, err)
	}
}

func publishVisualAcceptanceArtifact(t *testing.T, reg *registry.FileRegistry, slug, source string, dag json.RawMessage, binaryTag string) (artifact, codeHash, manifestHash string) {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n# "+binaryTag+"\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	published, err := reg.PublishArtifact(slug, binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.ClaimTenant(slug, journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(filepath.Dir(published.Path), "source")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"main.go": []byte(source), "dag.json": dag}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := registry.BuildSourceManifest(files, []string{"main.go"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, registry.SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	codeSum, manifestSum := sha256.Sum256([]byte(source)), sha256.Sum256(manifest)
	return published.Digest, hex.EncodeToString(codeSum[:])[:16], hex.EncodeToString(manifestSum[:])
}

func visualAcceptanceGET(t *testing.T, handler http.Handler, path string) string {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, response.Code, response.Body.String())
	}
	if response.Body.Len() > 4<<20 {
		t.Fatalf("GET %s rendered %d bytes, want bounded page", path, response.Body.Len())
	}
	return response.Body.String()
}

func visualAcceptanceIsland(t *testing.T, page, id string, target any) {
	t.Helper()
	start := `<script type="application/json" id="` + id + `">`
	pos := strings.Index(page, start)
	if pos < 0 {
		t.Fatalf("rendered page lacks %s JSON island", id)
	}
	rest := page[pos+len(start):]
	end := strings.Index(rest, `</script>`)
	if end < 0 {
		t.Fatalf("rendered page has unterminated %s JSON island", id)
	}
	if err := json.Unmarshal([]byte(rest[:end]), target); err != nil {
		t.Fatalf("rendered %s cannot be parsed by browser: %v", id, err)
	}
}
