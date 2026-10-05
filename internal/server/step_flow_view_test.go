package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/flowblocks"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestWorkflowDetailRendersDeclaredBlockCanvasAndEscapedFallback(t *testing.T) {
	t.Parallel()
	dag := `{"steps":[{"name":"process","kind":"step","visual_flow":{"blocks":[{"id":"route","kind":"split","label":"<img src=x onerror=alert(1)>"},{"id":"join","kind":"merge"}],"edges":[{"from":"route","to":"join","route":"<ready>"}]}}]}`
	html := workflowDetailBody(workflowDetailData{Slug: "block-flow", DAG: dag, FlowProofStatus: "verified"})
	for _, want := range []string{`id="step-flows-data"`, `id="wf-blockflow-canvas"`, `Declared visual blocks inside steps`, `&lt;img src=x onerror=alert(1)&gt;`, `via &lt;ready&gt;`, `author-declared annotations`} {
		if !strings.Contains(html, want) {
			t.Fatalf("dashboard omitted block view/escaped fallback %q: %s", want, html)
		}
	}
	if strings.Contains(html, `<img src=x onerror=alert(1)>`) || strings.Contains(html, `<ready>`) {
		t.Fatal("untrusted block annotation reached HTML without escaping")
	}
}

func TestWorkflowJSONIslandsRemainParseableAndCannotCloseScript(t *testing.T) {
	t.Parallel()
	dag := `{"nodes":[{"id":"process","kind":"step","label":"</script><script>alert(1)</script>","visual_flow":{"blocks":[{"id":"route","kind":"split","label":"</script><img src=x>"}]}}]}`
	html := workflowDetailBody(workflowDetailData{Slug: "script-island", DAG: dag})
	for _, id := range []string{"dag-data", "step-flows-data"} {
		prefix := `<script type="application/json" id="` + id + `">`
		start := strings.Index(html, prefix)
		if start < 0 {
			t.Fatalf("missing %s JSON island", id)
		}
		rest := html[start+len(prefix):]
		end := strings.Index(rest, `</script>`)
		if end < 0 {
			t.Fatalf("unterminated %s JSON island", id)
		}
		content := rest[:end]
		if !json.Valid([]byte(content)) {
			t.Fatalf("%s island cannot be JSON.parse'd by browser: %s", id, content)
		}
		if strings.Contains(content, `</script>`) || !strings.Contains(content, `\u003c`) {
			t.Fatalf("%s island permits script breakout or omitted HTML escaping: %s", id, content)
		}
	}
}

func TestRunFlowDiagramLabelsBlockReceiptBoundary(t *testing.T) {
	t.Parallel()
	dag := []byte(`{"steps":[{"name":"process","kind":"step","visual_flow":{"blocks":[{"id":"route","kind":"split"},{"id":"sum","kind":"aggregate"}],"edges":[{"from":"route","to":"sum","route":"yes"}]}}]}`)
	html := runFlowDiagram(dag, []journal.StepRow{{StepName: "process", Status: "succeeded"}})
	for _, want := range []string{`2 author-declared visual blocks`, `The step receipt applies to the whole step`, `route`, `aggregate`, `via yes`} {
		if !strings.Contains(html, want) {
			t.Fatalf("run flow omitted block boundary %q: %s", want, html)
		}
	}
	if strings.Count(html, `class="flow-node `) != 1 {
		t.Fatalf("declared blocks were rendered as executable run nodes: %s", html)
	}
}

func TestMalformedVisualBlocksFailClosedOnDashboard(t *testing.T) {
	t.Parallel()
	dag := `{"steps":[{"name":"process","kind":"step","visual_flow":{"blocks":[{"id":"route","kind":"split"}],"edges":[{"from":"route","to":"missing"}]}}]}`
	html := workflowDetailBody(workflowDetailData{Slug: "broken-blocks", DAG: dag})
	if !strings.Contains(html, "Visual block annotations are invalid") || strings.Contains(html, `id="step-flows-data"`) {
		t.Fatalf("malformed annotation was presented as a graph: %s", html)
	}
	projection := flowblocks.FromDAG([]byte(dag), maxFlowDAGBytes)
	if projection.Complete || len(projection.Steps) != 0 {
		t.Fatalf("malformed projection was partial: %#v", projection)
	}
}

func TestDeclaredMergeModeIsVisibleWithoutExecutionClaim(t *testing.T) {
	flow := flowblocks.StepFlow{Step: "process", Blocks: []flowblocks.Block{{
		ID: "join", Kind: "merge", Label: "Join customers", Mode: "full_join", Key: "customer.id", MaxRows: 500,
	}}}
	html := renderDeclaredStepFlowSummary(flow)
	for _, want := range []string{"mode: full join", "customer.id", "max rows: 500", "this declaration does not prove inner block execution"} {
		if !strings.Contains(html, want) {
			t.Fatalf("merge review did not show %q: %s", want, html)
		}
	}
}

func TestRunFlowDiagramDistinguishesSDKReportedAndMissingMergeObservations(t *testing.T) {
	t.Parallel()
	dag := []byte(`{"steps":[{"name":"process","kind":"step","visual_flow":{"blocks":[{"id":"joined","kind":"merge","mode":"full_join","max_rows":10},{"id":"unseen","kind":"merge","mode":"full_join","max_rows":10}]}}]}`)
	receipts := []journal.BlockReceipt{{RunID: "run", StepName: "process", BlockID: "joined", Kind: "merge", Seq: 9,
		Attempt: 1, CallOrdinal: 3, Mode: "full_join", LeftRows: 2, RightRows: 3,
		OutputRows: 4, MaxRows: 10, Outcome: "succeeded"}}
	observed := []journal.ObservedBlockIdentity{{StepName: "process", BlockID: "joined"}}
	html := runFlowDiagramWithObservations(dag, []journal.StepRow{{StepName: "process", Seq: 1, Attempt: 1, Status: "succeeded"}}, false, receipts, observed, true)
	for _, want := range []string{"SDK-reported observation", "No SDK observation in this run", "latest shown: call 3, attempt 1", "left 2, right 3, output 4 rows", "Only the newest 100 block receipts are shown", "not independently verified behavior"} {
		if !strings.Contains(html, want) {
			t.Fatalf("run flow omitted %q: %s", want, html)
		}
	}
	if strings.Contains(html, "behavior verified") {
		t.Fatalf("flow overstated SDK report: %s", html)
	}
}

func TestDeclaredMergeReportMustMatchModeAndBound(t *testing.T) {
	t.Parallel()
	flow := flowblocks.StepFlow{Step: "process", Blocks: []flowblocks.Block{{ID: "join", Kind: "merge", Mode: "full_join", MaxRows: 10}}}
	observed := map[string]bool{"join": true}
	receipts := []journal.BlockReceipt{{BlockID: "join", Kind: "merge", Mode: "inner_join", MaxRows: 10}}
	html := renderDeclaredStepFlowSummaryWithObservations(flow, observed, receipts, false)
	if !strings.Contains(html, "SDK report differs from declared merge mode or bound") ||
		!strings.Contains(html, "latest shown: mode inner_join; max rows 10") ||
		strings.Contains(html, `<span class="tag tag-on">SDK-reported observation</span>`) {
		t.Fatalf("mismatched SDK report was presented as the declared full join: %s", html)
	}
	html = renderDeclaredStepFlowSummaryWithObservations(flow, observed, nil, true)
	if !strings.Contains(html, "SDK-reported block ID; mode and bound not shown") ||
		strings.Contains(html, `<span class="tag tag-on">SDK-reported observation</span>`) {
		t.Fatalf("identity-only SDK report was presented as a matching merge: %s", html)
	}
}

func TestDeclaredSplitShowsTypedCountsWithoutClaimingRouteWasVerified(t *testing.T) {
	t.Parallel()
	flow := flowblocks.StepFlow{Step: "process", Blocks: []flowblocks.Block{{ID: "route", Kind: "split"}},
		Edges: []flowblocks.Edge{{From: "route", To: "target", Route: "yes"}}}
	observed := map[string]bool{"route": true}
	input, yes, no := 3, 1, 2
	receipts := []journal.BlockReceipt{{BlockID: "route", Kind: "split", Seq: 2, Attempt: 1, CallOrdinal: 4,
		InputRows: &input, YesRows: &yes, NoRows: &no, Outcome: "succeeded"}}
	html := renderDeclaredStepFlowSummaryWithObservations(flow, observed, receipts, false)
	if !strings.Contains(html, "input 3, yes 1, no 2 rows") ||
		!strings.Contains(html, "latest shown: call 4, attempt 1") ||
		!strings.Contains(html, "cannot verify the predicate or declared routes") ||
		strings.Contains(html, "left 0, right 0") {
		t.Fatalf("split report was misrepresented: %s", html)
	}
	html = renderDeclaredStepFlowSummaryWithObservations(flow, observed, nil, true)
	if !strings.Contains(html, "SDK-reported split ID; counts not shown") || strings.Contains(html, "SDK-reported observation</span>") {
		t.Fatalf("identity-only split was overstated: %s", html)
	}
	receipts[0].Kind = "merge"
	html = renderDeclaredStepFlowSummaryWithObservations(flow, observed, receipts, false)
	if !strings.Contains(html, "SDK report differs from declared split") || strings.Contains(html, "input 3, yes 1") {
		t.Fatalf("mismatched split report was overstated: %s", html)
	}
}

func TestDeclaredCollectionsShowTypedCountsWithoutClaimingTransformWasVerified(t *testing.T) {
	t.Parallel()
	flow := flowblocks.StepFlow{Step: "process", Blocks: []flowblocks.Block{
		{ID: "each", Kind: "iterate"}, {ID: "sum", Kind: "aggregate"},
	}}
	observed := map[string]bool{"each": true, "sum": true}
	input := 3
	receipts := []journal.BlockReceipt{
		{BlockID: "each", Kind: "iterate", Seq: 1, Attempt: 1, CallOrdinal: 5, InputRows: &input, OutputRows: 3, Outcome: "succeeded"},
		{BlockID: "sum", Kind: "aggregate", Seq: 1, Attempt: 1, CallOrdinal: 6, InputRows: &input, OutputRows: 1, Outcome: "succeeded"},
	}
	html := renderDeclaredStepFlowSummaryWithObservations(flow, observed, receipts, false)
	if strings.Count(html, "SDK-reported observation</span>") != 2 ||
		!strings.Contains(html, "input 3, output 3") || !strings.Contains(html, "input 3, output 1") ||
		!strings.Contains(html, "latest shown: call 5, attempt 1") || !strings.Contains(html, "latest shown: call 6, attempt 1") ||
		!strings.Contains(html, "cannot verify a mapping or fold") || strings.Contains(html, "left 0, right 0") {
		t.Fatalf("collection receipts misrepresented: %s", html)
	}
	html = renderDeclaredStepFlowSummaryWithObservations(flow, observed, nil, true)
	if strings.Count(html, "SDK-reported block ID; counts not shown") != 2 || strings.Contains(html, "SDK-reported observation</span>") {
		t.Fatalf("identity-only collection receipts overstated: %s", html)
	}
	receipts[0].OutputRows = 2
	html = renderDeclaredStepFlowSummaryWithObservations(flow, observed, receipts, false)
	if !strings.Contains(html, "SDK report differs from declared collection operation") ||
		strings.Count(html, "SDK-reported observation</span>") != 1 {
		t.Fatalf("invalid iterate report shown as matching: %s", html)
	}
}

func TestRunFlowDiagramMarksUnsupportedBlockObservationsSeparately(t *testing.T) {
	t.Parallel()
	dag := []byte(`{"steps":[{"name":"process","kind":"step","visual_flow":{"blocks":[{"id":"join","kind":"merge","mode":"full_join","max_rows":10},{"id":"append","kind":"merge","mode":"append"},{"id":"route","kind":"split"},{"id":"each","kind":"iterate"},{"id":"sum","kind":"aggregate"}],"edges":[{"from":"route","to":"each","route":"yes"},{"from":"each","to":"sum"},{"from":"sum","to":"join"}]}}]}`)
	html := runFlowDiagramWithObservations(dag, []journal.StepRow{{StepName: "process", Seq: 1, Attempt: 1, Status: "succeeded"}}, false, nil, []journal.ObservedBlockIdentity{}, false)
	if strings.Count(html, "No SDK observation in this run") != 4 || strings.Count(html, "SDK observation unavailable for this block") != 1 {
		t.Fatalf("run flow confused unsupported blocks with an unobserved join: %s", html)
	}
	if !strings.Contains(html, "via yes") || strings.Contains(html, "observed edge") {
		t.Fatalf("declared route was lost or presented as observed: %s", html)
	}
}
