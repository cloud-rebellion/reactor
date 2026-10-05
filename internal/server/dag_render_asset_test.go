package server

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDAGRenderAssetPreservesVisualEdges guards the browser-side flow view's
// contract with the validated visual DAG shape. A nodes[]/edges[] graph must
// reach Cytoscape as its declared edges; otherwise the old fallback rendered
// a made-up linear chain and showed operators the wrong execution order.
func TestDAGRenderAssetPreservesVisualEdges(t *testing.T) {
	t.Parallel()
	body, err := assetsFS.ReadFile("assets/dag-render.js")
	if err != nil {
		t.Fatalf("read embedded dag-render.js: %v", err)
	}
	src := string(body)
	for _, want := range []string{
		"Array.isArray(dag.edges)",
		"!usesExecutableSteps && Array.isArray(dag.edges)",
		"addEdge(e.from, e.to)",
		"seenEdges = Object.create(null)",
		"seen = Object.create(null)",
		"var color = Object.create(null)",
		"steps.slice(0, MAX_NODES)",
		"edges.length >= MAX_EDGES",
		"Array.isArray(record.step.depends_on)",
		"displayText(label, id)",
		"MAX_LABEL_LENGTH",
		"MAX_INPUT_EDGES = 4096",
		"dag.edges.slice(0, MAX_INPUT_EDGES)",
		"Do not invent ordering",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("dag-render.js no longer handles explicit visual edges (%q missing)", want)
		}
	}
	if strings.Contains(src, "source: nodeId(steps[i - 1], i - 1)") {
		t.Fatal("dag-render.js fabricates a linear edge chain for a graph with no declared dependencies")
	}
	if strings.Contains(src, "dag.edges.slice(0, MAX_EDGES)") {
		t.Fatal("dag-render.js discards valid late edges before deduplicating the bounded graph")
	}
}

// Execute the actual customer renderer when Bun is available. The fixture has
// 513 schema-valid declared edges but only two distinct routes; a raw 512-edge
// slice used to hide the late route even though MCP review retained it.
func TestDAGRenderBrowserRetainsLateDistinctBranch(t *testing.T) {
	bun, err := exec.LookPath("bun")
	if err != nil {
		t.Skip("Bun is unavailable for the browser execution test")
	}
	cmd := exec.Command(bun, "test", "dag_render_browser.test.js")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("browser DAG acceptance test: %v\n%s", err, output)
	}
}

// A direct split->merge route must remain visible when a second branch has
// intermediate nodes. The browser render once put Merge beside Iterate, then
// drew the direct route through Iterate and Aggregate when layering was fixed.
func TestVisualAssetsKeepLongestPathAndBypassRoute(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"assets/dag-render.js", "assets/workflow-editor.js"} {
		body, err := assetsFS.ReadFile(name)
		if err != nil {
			t.Fatalf("read embedded %s: %v", name, err)
		}
		src := string(body)
		for _, want := range []string{"maximal: true", "depth[edge.data.target] > depth[edge.data.source] + 1", `selector: "edge[bypass]"`, `"curve-style": "unbundled-bezier"`} {
			if !strings.Contains(src, want) {
				t.Fatalf("%s omitted visual branch guard %q", name, want)
			}
		}
	}
}
