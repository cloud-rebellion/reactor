package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestBoundMCPFlowDisplayNeverCutsUTF8OrExceedsBudget(t *testing.T) {
	t.Parallel()

	got := boundMCPFlowDisplay(strings.Repeat("å", maxMCPFlowDisplayBytes))
	if !utf8.ValidString(got) {
		t.Fatalf("flow display is invalid UTF-8: %q", got)
	}
	if len([]byte(got)) > maxMCPFlowDisplayBytes {
		t.Fatalf("flow display bytes = %d, want <= %d", len([]byte(got)), maxMCPFlowDisplayBytes)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("flow display = %q, want truncation suffix", got)
	}
}

func TestFlowElementsBoundedDoesNotReturnDanglingEdges(t *testing.T) {
	t.Parallel()

	src := []byte(`{"steps":[
		{"name":"first","kind":"step"},
		{"name":"second","kind":"step","depends_on":["first"]},
		{"name":"third","kind":"step","depends_on":["second"]}
	]}`)
	nodes, edges, truncated := flowElementsBounded(src, 2, 10)
	if !truncated {
		t.Fatal("expected node cap to mark the flow truncated")
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(nodes))
	}
	seen := map[string]bool{}
	for _, node := range nodes {
		seen[node["id"].(string)] = true
	}
	if len(edges) != 1 || edges[0]["from"] != "first" || edges[0]["to"] != "second" {
		t.Fatalf("edges = %#v, want only the complete first -> second edge", edges)
	}
	for _, edge := range edges {
		if !seen[edge["from"].(string)] || !seen[edge["to"].(string)] {
			t.Fatalf("dangling edge = %#v for nodes %#v", edge, seen)
		}
	}
}

func TestFlowElementsBoundedMarksMalformedEdgeAsIncomplete(t *testing.T) {
	t.Parallel()

	src := []byte(`{"nodes":[{"id":"first","kind":"step"}],"edges":[{"from":"first","to":"missing"}]}`)
	nodes, edges, truncated := flowElementsBounded(src, 10, 10)
	if len(nodes) != 1 || len(edges) != 0 || !truncated {
		t.Fatalf("flow = nodes %#v edges %#v truncated %v; want one node, no dangling edge, truncated", nodes, edges, truncated)
	}
}

func TestFlowElementsBoundedMarksDecodeFailureAsIncomplete(t *testing.T) {
	t.Parallel()
	src := []byte(`{"steps":[{"name":"send","kind":"step","uses":"credential"}]}`)
	nodes, edges, truncated := flowElementsBounded(src, 10, 10)
	if len(nodes) != 0 || len(edges) != 0 || !truncated {
		t.Fatalf("undecodable DAG = nodes %#v edges %#v truncated %v; want incomplete flow", nodes, edges, truncated)
	}
}

func TestFlowElementsBoundedDeduplicatesGraphEdges(t *testing.T) {
	t.Parallel()

	steps := []byte(`{"steps":[
		{"name":"first","kind":"step"},
		{"name":"second","kind":"step","depends_on":["first","first"]}
	]}`)
	visual := []byte(`{"nodes":[{"id":"first","kind":"step"},{"id":"second","kind":"step"}],"edges":[{"from":"first","to":"second"},{"from":"first","to":"second"}]}`)
	for _, maxEdges := range []int{1, 10} {
		for _, tc := range []struct {
			name string
			dag  []byte
		}{
			{name: "steps", dag: steps},
			{name: "visual", dag: visual},
		} {
			_, edges, truncated := flowElementsBounded(tc.dag, 10, maxEdges)
			if truncated || len(edges) != 1 {
				t.Fatalf("%s flow with maxEdges=%d = edges %#v truncated %v; want one edge without truncation", tc.name, maxEdges, edges, truncated)
			}
		}
	}
}

func TestFlowTopologyViewReportsDeclaredSplitAndMerge(t *testing.T) {
	t.Parallel()
	nodes := []map[string]any{
		{"id": "source", "kind": "step"},
		{"id": "left", "kind": "step"},
		{"id": "right", "kind": "step"},
		{"id": "join", "kind": "step"},
	}
	edges := []map[string]any{
		{"from": "source", "to": "left"},
		{"from": "source", "to": "right"},
		{"from": "left", "to": "join"},
		{"from": "right", "to": "join"},
	}
	topology := flowTopologyView(nodes, edges, false)
	if topology["provenance"] != "declared_dag" || topology["complete"] != true {
		t.Fatalf("topology provenance/completeness = %#v, want declared_dag and complete", topology)
	}
	for key, want := range map[string]any{
		"node_count": 4, "edge_count": 4, "root_count": 1, "leaf_count": 1,
		"split_count": 1, "merge_count": 1, "has_split": true, "has_merge": true,
	} {
		if topology[key] != want {
			t.Errorf("topology[%q] = %#v, want %#v", key, topology[key], want)
		}
	}
	note, _ := topology["note"].(string)
	if !strings.Contains(note, "does not infer branch predicates") || !strings.Contains(note, "runtime step receipts") {
		t.Fatalf("topology note does not distinguish declared graph from run path: %q", note)
	}
}

func TestFlowTopologyViewMarksMissingGraphUnavailable(t *testing.T) {
	t.Parallel()
	topology := flowTopologyView(nil, nil, false)
	if topology["provenance"] != "unavailable" || topology["complete"] != true || topology["node_count"] != 0 || topology["edge_count"] != 0 {
		t.Fatalf("empty topology = %#v, want unavailable complete empty projection", topology)
	}
	note, _ := topology["note"].(string)
	if !strings.Contains(note, "No executable visual DAG was retained") {
		t.Fatalf("empty topology note = %q", note)
	}
}

func TestWorkflowFlowExposesDeclaredStepSubgraphWithoutClaimingExecution(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, false)
	dag := json.RawMessage(`{"nodes":[{"id":"process","kind":"step","visual_flow":{"blocks":[{"id":"route","kind":"split"},{"id":"each","kind":"iterate"},{"id":"total","kind":"aggregate"},{"id":"join","kind":"merge"}],"edges":[{"from":"route","to":"each","route":"yes"},{"from":"each","to":"total"},{"from":"total","to":"join"}]}}]}`)
	if err := j.CreateWorkflow(context.Background(), "wf_flow_blocks", "flow-blocks", "h", "0.1.0", dag); err != nil {
		t.Fatal(err)
	}
	flow := callOperationalTool(t, s, "reactor_get_workflow_flow", map[string]any{"slug": "flow-blocks"}, false)
	for _, want := range []string{`"step_flows":{"provenance":"author_declared_annotation"`, `"behavior_verified":false`, `"block_count":4`, `"edge_count":3`, `"route":"yes"`, `"flow_verification":"unverified"`, `"flow_valid":false`, `Durable steps have host-recorded outcomes`, `SDK-reported receipts`} {
		if !strings.Contains(strings.ToLower(string(flow)), strings.ToLower(want)) {
			t.Fatalf("flow missed bounded annotation/trust boundary %q: %s", want, flow)
		}
	}
	resource, err := s.readResource(context.Background(), "reactor://workflows/flow-blocks/flow")
	if err != nil {
		t.Fatal(err)
	}
	resourceJSON, err := json.Marshal(resource)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resourceJSON), `\"step_flows\":{\"provenance\":\"author_declared_annotation\"`) {
		t.Fatalf("flow resource omitted declared blocks: %s", resourceJSON)
	}
}

func TestFlowElementsBoundedUsesStepsWhenMixedAndDropsDanglingEdges(t *testing.T) {
	t.Parallel()
	src := []byte(`{"steps":[{"name":"send","kind":"step"}],"nodes":[
		{"id":"send","kind":"side_effect"},
		{"id":"visual-only","kind":"step"}
	],"edges":[{"from":"send","to":"missing"}]}`)
	nodes, edges, truncated := flowElementsBounded(src, 10, 10)
	if len(nodes) != 1 || nodes[0]["id"] != "send" || nodes[0]["kind"] != "step" {
		t.Fatalf("mixed flow nodes = %#v; want executable steps only", nodes)
	}
	if len(edges) != 0 || !truncated {
		t.Fatalf("mixed flow edges=%#v truncated=%v; want dangling edge dropped and marked", edges, truncated)
	}
}

func TestFlowElementsBoundedDoesNotBorrowVisualEdgesForExecutableSteps(t *testing.T) {
	t.Parallel()
	src := []byte(`{"steps":[{"name":"first","kind":"step"},{"name":"second","kind":"step"}],"edges":[{"from":"first","to":"second"}]}`)
	nodes, edges, truncated := flowElementsBounded(src, 10, 10)
	if len(nodes) != 2 || len(edges) != 0 || !truncated {
		t.Fatalf("mixed flow nodes=%#v edges=%#v truncated=%v; want two executable steps, no borrowed edge, incomplete projection", nodes, edges, truncated)
	}
}

func TestFlowElementsBoundedRejectsPathologicalInput(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString(`{"nodes":[`)
	for i := 0; i < maxMCPFlowInputEdges+1; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":"node-%d","kind":"step"}`, i)
	}
	b.WriteString(`]}`)
	nodes, edges, truncated := flowElementsBounded([]byte(b.String()), maxMCPFlowNodes, maxMCPFlowEdges)
	if len(nodes) > maxMCPFlowNodes || len(edges) > maxMCPFlowEdges || !truncated {
		t.Fatalf("pathological flow nodes=%d edges=%d truncated=%v; want bounded/truncated", len(nodes), len(edges), truncated)
	}
	oversized := []byte(`{"steps":[]}` + strings.Repeat(" ", maxMCPWorkflowDAGBytes))
	if nodes, edges, truncated := flowElementsBounded(oversized, maxMCPFlowNodes, maxMCPFlowEdges); nodes != nil || edges != nil || !truncated {
		t.Fatalf("oversized flow nodes=%#v edges=%#v truncated=%v; want rejected", nodes, edges, truncated)
	}
}

func TestMCPWorkflowFlowFailsClosedOnOversizedRetainedDAG(t *testing.T) {
	s, j, _ := newTestServer(t, false)
	dag := json.RawMessage(`{"steps":[],"padding":"` + strings.Repeat("x", maxMCPWorkflowDAGBytes+1024) + `"}`)
	if err := j.CreateWorkflow(context.Background(), "wf_flow_bound", "flow-bound", "h", "0.1.0", dag); err != nil {
		t.Fatal(err)
	}
	raw := callOperationalTool(t, s, "reactor_get_workflow_flow", map[string]any{"slug": "flow-bound"}, false)
	if !strings.Contains(string(raw), `"validated":false`) || !strings.Contains(string(raw), `"flow_valid":false`) || !strings.Contains(string(raw), `"dag_truncated":true`) || !strings.Contains(string(raw), `"dag_bytes":`) || !strings.Contains(string(raw), `"flow_verification":"unverified"`) || !strings.Contains(string(raw), `"flow_verification_reason":"workflow DAG exceeds the bounded MCP flow projection"`) || !strings.Contains(string(raw), `"flow_data_trust":"untrusted"`) || !strings.Contains(string(raw), `"topology":{"complete":false`) || !strings.Contains(string(raw), `"provenance":"unavailable"`) {
		t.Fatalf("oversized workflow flow was not fail-closed: %s", raw)
	}
	if strings.Contains(string(raw), `"validated":true`) {
		t.Fatalf("oversized workflow flow was marked validated: %s", raw)
	}
}

func TestWorkflowFlowReportsSourceProofSeparatelyFromSchemaValidation(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, false)
	if err := j.CreateWorkflow(context.Background(), "wf_flow_unverified", "flow-unverified", "h", "0.1.0", json.RawMessage(`{"steps":[{"name":"fetch","kind":"step"}]}`)); err != nil {
		t.Fatal(err)
	}
	flow := callOperationalTool(t, s, "reactor_get_workflow_flow", map[string]any{"slug": "flow-unverified"}, false)
	text := string(flow)
	for _, want := range []string{`"validated":true`, `"flow_valid":false`, `"flow_verification":"unverified"`, `"flow_verification_reason":"retained source and visual DAG proof was not checked"`, `"flow_data_trust":"untrusted"`, `"topology":{"complete":true`, `"provenance":"declared_dag"`, `"has_split":false`, `"has_merge":false`} {
		if !strings.Contains(text, want) {
			t.Fatalf("unverified flow missing %s: %s", want, flow)
		}
	}

	resource, err := s.readResource(context.Background(), "reactor://workflows/flow-unverified/flow")
	if err != nil {
		t.Fatalf("flow resource read failed: %v", err)
	}
	raw, err := json.Marshal(resource)
	if err != nil {
		t.Fatal(err)
	}
	resourceText := string(raw)
	for _, want := range []string{`\"validated\":true`, `\"flow_valid\":false`, `\"flow_verification\":\"unverified\"`, `\"flow_verification_reason\":\"retained source and visual DAG proof was not checked\"`, `\"flow_data_trust\":\"untrusted\"`, `\"topology\":{\"complete\":true`, `\"provenance\":\"declared_dag\"`} {
		if !strings.Contains(resourceText, want) {
			t.Fatalf("unverified flow resource missing %s: %s", want, raw)
		}
	}
}

func TestMetadataOnlyWorkflowFlowIsUnverifiedAcrossMCPReceipts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, j, _ := newTestServer(t, false)
	dag := json.RawMessage(`{"steps":[{"name":"fetch","kind":"step"}]}`)
	if err := j.CreateWorkflowInTenantDisabled(ctx, "wf_metadata_only_flow", "metadata-only-flow", "h", "0.1.0", dag, journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"reactor_get_workflow_flow", "reactor_review_workflow", "reactor_preflight_dispatch_workflow"} {
		raw := callOperationalTool(t, s, tool, map[string]any{"slug": "metadata-only-flow"}, false)
		var receipt struct {
			FlowValid        bool   `json:"flow_valid"`
			FlowVerification string `json:"flow_verification"`
			ArtifactStatus   string `json:"artifact_status"`
		}
		if err := json.Unmarshal(raw, &receipt); err != nil {
			t.Fatalf("%s: decode receipt: %v", tool, err)
		}
		if receipt.FlowValid || receipt.FlowVerification != "unverified" || receipt.ArtifactStatus != "missing" {
			t.Fatalf("%s: metadata-only graph was reported as verified: %s", tool, raw)
		}
	}
}

func TestWorkflowFlowReportsVerifiedSourceProof(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, false)
	s.StateRoot = t.TempDir()
	mainSource := []byte(`package main

import (
	"context"
	reactor "github.com/bright-interaction/reactor/sdk"
)

func Run(ctx context.Context, flow reactor.Flow) error {
	_, err := reactor.Step(flow, ctx, "fetch", reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
	return err
}
`)
	dag := []byte(`{"steps":[{"name":"fetch","kind":"step"}]}`)
	artifact := publishVerifiedTestArtifact(t, s, "flow-verified", []byte("flow-verified-artifact"), mainSource, dag)
	if err := j.CreateWorkflowInTenantWithArtifact(context.Background(), "wf_flow_verified", "flow-verified", sourceCodeHashForTest(mainSource), "0.1.0", artifact.Digest, dag, journal.DefaultTenant, sourceManifestPinForTest(t, artifact)); err != nil {
		t.Fatal(err)
	}
	flow := callOperationalTool(t, s, "reactor_get_workflow_flow", map[string]any{"slug": "flow-verified"}, false)
	text := string(flow)
	for _, want := range []string{`"validated":true`, `"flow_valid":true`, `"flow_verification":"verified"`, `"flow_data_trust":"untrusted"`, `"topology":{"complete":true`, `"provenance":"declared_dag"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("verified flow missing %s: %s", want, flow)
		}
	}
	if strings.Contains(text, `"flow_verification_reason":"`) && !strings.Contains(text, `"flow_verification_reason":""`) {
		t.Fatalf("verified flow reported a failure reason: %s", flow)
	}
}

func TestWorkflowFlowCanRenderExactHistoricalVersion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, j, _ := newTestServer(t, false)
	s.StateRoot = t.TempDir()
	mainFor := func(name string) []byte {
		return []byte(`package main

import (
	"context"
	reactor "github.com/bright-interaction/reactor/sdk"
)

func Run(ctx context.Context, flow reactor.Flow) error {
	_, err := reactor.Step(flow, ctx, "` + name + `", reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
	return err
}
`)
	}
	firstSource := mainFor("first")
	firstDAG := []byte(`{"steps":[{"name":"first","kind":"step"}]}`)
	firstArtifact := publishVerifiedTestArtifact(t, s, "versioned-flow", []byte("versioned-flow-v1"), firstSource, firstDAG)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_versioned_flow", "versioned-flow", sourceCodeHashForTest(firstSource), "0.1.0", firstArtifact.Digest, firstDAG, journal.DefaultTenant, sourceManifestPinForTest(t, firstArtifact)); err != nil {
		t.Fatal(err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_versioned_flow", false); err != nil {
		t.Fatal(err)
	}
	secondSource := mainFor("second")
	secondDAG := []byte(`{"steps":[{"name":"second","kind":"step"}]}`)
	secondArtifact := publishVerifiedTestArtifact(t, s, "versioned-flow", []byte("versioned-flow-v2"), secondSource, secondDAG)
	if _, err := j.RecordWorkflowVersionWithArtifactIfDisabled(ctx, "wf_versioned_flow", "0.1.0", sourceCodeHashForTest(secondSource), secondArtifact.Digest, secondDAG, sourceManifestPinForTest(t, secondArtifact)); err != nil {
		t.Fatal(err)
	}

	current := callOperationalTool(t, s, "reactor_get_workflow_flow", map[string]any{"slug": "versioned-flow"}, false)
	if !strings.Contains(string(current), `"version":2`) || !strings.Contains(string(current), `"id":"second"`) || strings.Contains(string(current), `"id":"first"`) {
		t.Fatalf("current flow did not use version 2: %s", current)
	}
	historical := callOperationalTool(t, s, "reactor_get_workflow_flow", map[string]any{"slug": "versioned-flow", "version": 1}, false)
	if !strings.Contains(string(historical), `"version":1`) || !strings.Contains(string(historical), `"id":"first"`) || strings.Contains(string(historical), `"id":"second"`) {
		t.Fatalf("historical flow did not use exact version 1: %s", historical)
	}
	resource, err := s.readResource(ctx, "reactor://workflows/versioned-flow/flow?version=1")
	if err != nil {
		t.Fatalf("historical flow resource failed: %v", err)
	}
	resourceText := resource["contents"].([]map[string]any)[0]["text"].(string)
	if !strings.Contains(resourceText, `"version":1`) || !strings.Contains(resourceText, `"id":"first"`) || strings.Contains(resourceText, `"id":"second"`) {
		t.Fatalf("historical flow resource did not use exact version 1: %s", resourceText)
	}
	for _, invalid := range []map[string]any{
		{"slug": "versioned-flow", "version": nil},
		{"slug": "versioned-flow", "version": 0},
		{"slug": "versioned-flow", "version": 99},
	} {
		callOperationalTool(t, s, "reactor_get_workflow_flow", invalid, true)
	}
	for _, uri := range []string{
		"reactor://workflows/versioned-flow/flow?version=0",
		"reactor://workflows/versioned-flow/flow?version=1&version=2",
		"reactor://workflows/versioned-flow/flow?unexpected=1",
		"reactor://workflows/versioned-flow/flow?version=1&unexpected=2",
	} {
		if _, err := s.readResource(ctx, uri); err == nil || !strings.Contains(err.Error(), "invalid params") {
			t.Fatalf("historical flow resource %q error = %v, want invalid params", uri, err)
		}
	}
}

func TestBoundOperationalFlowUsesRemainingBudgetAndDropsDanglingEdges(t *testing.T) {
	t.Parallel()

	nodes := []map[string]any{
		{"id": "workflow:wf"},
		{"id": "trigger:one"},
		{"id": "notification:one"},
	}
	edges := []map[string]any{
		{"from": "trigger:one", "to": "workflow:wf"},
		{"from": "workflow:wf", "to": "notification:one"},
		{"from": "workflow:wf", "to": "notification:missing"},
	}
	boundedNodes, boundedEdges, truncated := boundOperationalFlow(nodes, edges, 2, 1)
	if !truncated {
		t.Fatal("expected node, edge, and dangling-edge limits to mark the flow truncated")
	}
	if len(boundedNodes) != 2 || len(boundedEdges) != 1 {
		t.Fatalf("bounded flow = nodes %#v edges %#v; want 2 nodes and 1 edge", boundedNodes, boundedEdges)
	}
	if boundedEdges[0]["from"] != "trigger:one" || boundedEdges[0]["to"] != "workflow:wf" {
		t.Fatalf("bounded edge = %#v; want the complete first edge", boundedEdges[0])
	}
}

func TestBoundOperationalFlowHonorsZeroRemainingBudget(t *testing.T) {
	t.Parallel()

	nodes, edges, truncated := boundOperationalFlow(
		[]map[string]any{{"id": "trigger:one"}},
		[]map[string]any{{"from": "trigger:one", "to": "workflow:wf"}},
		0, 0,
	)
	if len(nodes) != 0 || len(edges) != 0 || !truncated {
		t.Fatalf("zero-budget flow = nodes %#v edges %#v truncated %v; want empty and truncated", nodes, edges, truncated)
	}
}

func oneStepProofFixture() (mainSource, dag []byte) {
	return []byte(`package main
import (
  "context"
  reactor "github.com/bright-interaction/reactor/sdk"
)
func Run(ctx context.Context, flow reactor.Flow) error {
  _, err := reactor.Step(flow, ctx, "shown", reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
  return err
}
`), []byte(`{"steps":[{"name":"shown","kind":"step"}]}`)
}

func TestValidateRetainedSourceDAGFailsClosedForHiddenDurableNodes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	reg := registry.New(filepath.Join(root, "workflows"))
	compiled := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(compiled, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("legacy-flow", compiled)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.ClaimTenant("legacy-flow", journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mainSource, dag := oneStepProofFixture()
	if err := os.WriteFile(filepath.Join(sourceDir, "main.go"), mainSource, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "dag.json"), dag, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := registry.BuildSourceManifest(map[string][]byte{"main.go": mainSource, "dag.json": dag}, []string{"main.go"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, registry.SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{StateRoot: root, TenantID: journal.DefaultTenant}
	verified := s.validateRetainedSourceDAGForTenant(context.Background(), "legacy-flow", artifact.Digest, sourceCodeHashForTest(mainSource), sourceManifestPinForTest(t, artifact), 2, dag)
	if verified.Status != "verified" || !sourceDAGVisualComplete(verified.Status) {
		t.Fatalf("plain retained source status = %+v; want verified visual flow", verified)
	}

	durable := []byte(`package main
import (
  "context"
  reactor "github.com/bright-interaction/reactor/sdk"
)
func Run(ctx context.Context, flow reactor.Flow) error {
	if _, err := reactor.Step(flow, ctx, "shown", reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil }); err != nil { return err }
	_, err := reactor.Step(flow, ctx, "hidden", reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
  return err
}
`)
	if err := os.WriteFile(filepath.Join(sourceDir, "main.go"), durable, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err = registry.BuildSourceManifest(map[string][]byte{"main.go": durable, "dag.json": dag}, []string{"main.go"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, registry.SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	mismatch := s.validateRetainedSourceDAGForTenant(context.Background(), "legacy-flow", artifact.Digest, sourceCodeHashForTest(durable), sourceManifestPinForTest(t, artifact), 2, dag)
	if mismatch.Status != "mismatch" || sourceDAGVisualComplete(mismatch.Status) || !strings.Contains(mismatch.Error, "integrity verification") || strings.Contains(mismatch.Error, "hidden") {
		t.Fatalf("durable source with hidden node status = %+v; want a closed, redacted mismatch", mismatch)
	}
}

func TestMCPPreflightAndEnableRejectHiddenDurableNodes(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, true)
	s.Scopes = &WriteScopes{Dispatch: true}
	s.StateRoot = t.TempDir()
	compiled := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(compiled, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	reg := registry.New(filepath.Join(s.StateRoot, "workflows"))
	artifact, err := reg.PublishArtifact("hidden-flow", compiled)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.ClaimTenant("hidden-flow", journal.DefaultTenant); err != nil {
		t.Fatalf("claim hidden-flow artifact namespace: %v", err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mainSource := []byte(`package main
import (
  "context"
  reactor "github.com/bright-interaction/reactor/sdk"
)
func Run(ctx context.Context, flow reactor.Flow) error {
  _, err := reactor.Step(flow, ctx, "hidden", reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
  return err
}
`)
	dag := []byte(`{}`)
	if err := os.WriteFile(filepath.Join(sourceDir, "main.go"), mainSource, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "dag.json"), dag, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := registry.BuildSourceManifest(map[string][]byte{"main.go": mainSource, "dag.json": dag})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, registry.SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_hidden_flow", "hidden-flow", sourceCodeHashForTest(mainSource), "0.1.0", artifact.Digest, dag, journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_hidden_flow", false); err != nil {
		t.Fatal(err)
	}
	preflight := callOperationalTool(t, s, "reactor_preflight_dispatch_workflow", map[string]any{"slug": "hidden-flow"}, false)
	for _, want := range []string{`"source_dag_status":"mismatch"`, `"visual_complete":false`, `"flow_valid":false`, `"dispatchable_now":false`} {
		if !strings.Contains(string(preflight), want) {
			t.Fatalf("preflight missing %s: %s", want, preflight)
		}
	}
	callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{"slug": "hidden-flow", "state": "enabled", "expected_version": 1}, true)
	enabled, err := j.IsWorkflowEnabled(ctx, "wf_hidden_flow")
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("workflow with hidden durable node was enabled")
	}
}

func TestMCPSourceProofBindsAuthenticatedTenant(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, true)
	s.TenantID = "globex"
	s.Scopes = &WriteScopes{Dispatch: true}
	s.StateRoot = t.TempDir()
	reg := registry.New(filepath.Join(s.StateRoot, "workflows"))
	compiled := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(compiled, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("shared-proof", compiled)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.ClaimTenant("shared-proof", "acme"); err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mainSource, dag := oneStepProofFixture()
	if err := os.WriteFile(filepath.Join(sourceDir, "main.go"), mainSource, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "dag.json"), dag, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := registry.BuildSourceManifest(map[string][]byte{"main.go": mainSource, "dag.json": dag})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, registry.SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_shared_proof", "shared-proof", sourceCodeHashForTest(mainSource), "0.1.0", artifact.Digest, dag, "globex", sourceManifestPinForTest(t, artifact)); err != nil {
		t.Fatal(err)
	}
	preflight := callOperationalTool(t, s, "reactor_preflight_dispatch_workflow", map[string]any{"slug": "shared-proof"}, false)
	text := string(preflight)
	for _, want := range []string{`"artifact_status":"unavailable"`, `"source_dag_status":"unavailable"`, `"visual_complete":false`, `"dispatchable_now":false`} {
		if !strings.Contains(text, want) {
			t.Fatalf("foreign tenant proof missing %s: %s", want, text)
		}
	}
	if strings.Contains(text, `"source_dag_status":"verified"`) || strings.Contains(text, `"visual_complete":true`) {
		t.Fatalf("foreign tenant artifact was reported as reviewable: %s", text)
	}
}

func TestMCPPreflightAndEnableRejectUnverifiedRetainedSource(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		status string
		mutate func(t *testing.T, artifact registry.Artifact)
	}{
		{
			name:   "unavailable",
			status: "unavailable",
			mutate: func(t *testing.T, artifact registry.Artifact) {
				t.Helper()
				if err := os.RemoveAll(filepath.Join(filepath.Dir(artifact.Path), "source")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:   "manifest_drift",
			status: "mismatch",
			mutate: func(t *testing.T, artifact registry.Artifact) {
				t.Helper()
				manifestPath := filepath.Join(filepath.Dir(artifact.Path), "source", registry.SourceManifestFilename)
				manifest, err := os.ReadFile(manifestPath)
				if err != nil {
					t.Fatal(err)
				}
				// Keep the manifest parseable and consistent with its listed files,
				// but change its exact bytes after the version pin was recorded.
				if err := os.WriteFile(manifestPath, append(manifest, '\n'), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, j, _ := newTestServer(t, true)
			s.Scopes = &WriteScopes{Dispatch: true}
			mainSource, dag := oneStepProofFixture()
			artifact := publishVerifiedTestArtifact(t, s, "unverified-"+tc.name, []byte("artifact-"+tc.name), mainSource, dag)
			manifestPin := sourceManifestPinForTest(t, artifact)
			tc.mutate(t, artifact)
			ctx := context.Background()
			if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_unverified_"+tc.name, "unverified-"+tc.name, sourceCodeHashForTest(mainSource), "0.1.0", artifact.Digest, dag, journal.DefaultTenant, manifestPin); err != nil {
				t.Fatal(err)
			}
			preflight := callOperationalTool(t, s, "reactor_preflight_dispatch_workflow", map[string]any{"slug": "unverified-" + tc.name}, false)
			for _, want := range []string{
				`"artifact_status":"verified"`,
				`"source_dag_status":"` + tc.status + `"`,
				`"visual_complete":false`,
				`"flow_valid":false`,
				`"durable_ready":false`,
				`"dispatchable_now":false`,
			} {
				if !strings.Contains(string(preflight), want) {
					t.Fatalf("preflight missing %s: %s", want, preflight)
				}
			}
			if err := j.SetWorkflowEnabled(ctx, "wf_unverified_"+tc.name, false); err != nil {
				t.Fatal(err)
			}
			callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{"slug": "unverified-" + tc.name, "state": "enabled", "expected_version": 1}, true)
			enabled, err := j.IsWorkflowEnabled(ctx, "wf_unverified_"+tc.name)
			if err != nil {
				t.Fatal(err)
			}
			if enabled {
				t.Fatalf("%s retained-source proof was enabled", tc.status)
			}
		})
	}
}

func TestWorkflowFlowCapsCombinedInternalAndOperationalTopology(t *testing.T) {
	s, j, _ := newTestServer(t, false)
	s.TenantID = "acme"

	graphNodes := make([]map[string]any, maxMCPFlowNodes)
	for i := range graphNodes {
		graphNodes[i] = map[string]any{"id": "step-" + string(rune('a'+i%26)) + "-" + string(rune('0'+i/26)), "kind": "step"}
	}
	dag, err := json.Marshal(map[string]any{"nodes": graphNodes, "edges": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_flow_budget", "flow-budget", "hash", "0.1.0", dag, "acme"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxMCPReviewItems; i++ {
		if _, err := j.CreateCronTrigger(ctx, "wf_flow_budget", json.RawMessage(`{"spec":"0 * * * *"}`)); err != nil {
			t.Fatal(err)
		}
	}

	raw := callOperationalTool(t, s, "reactor_get_workflow_flow", map[string]any{"slug": "flow-budget"}, false)
	var view struct {
		Nodes             []map[string]any `json:"nodes"`
		Edges             []map[string]any `json:"edges"`
		ExternalNodes     []map[string]any `json:"external_nodes"`
		ExternalEdges     []map[string]any `json:"external_edges"`
		ExternalTruncated bool             `json:"external_truncated"`
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Nodes) > maxMCPFlowNodes || len(view.Edges) > maxMCPFlowEdges {
		t.Fatalf("primary flow exceeded caps: nodes=%d edges=%d", len(view.Nodes), len(view.Edges))
	}
	if len(view.Nodes)+len(view.ExternalNodes) > maxMCPFlowNodes || len(view.Edges)+len(view.ExternalEdges) > maxMCPFlowEdges {
		t.Fatalf("combined flow exceeded caps: nodes=%d edges=%d", len(view.Nodes)+len(view.ExternalNodes), len(view.Edges)+len(view.ExternalEdges))
	}
	if !view.ExternalTruncated || len(view.ExternalNodes) != 0 {
		t.Fatalf("external flow = nodes=%d edges=%d truncated=%v; want omitted after primary node budget", len(view.ExternalNodes), len(view.ExternalEdges), view.ExternalTruncated)
	}
}

func TestWorkflowFlowIncludesSameTenantChainSource(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, false)
	s.TenantID = "acme"
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_chain_source", "chain-source", "hash", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_chain_downstream", "chain-downstream", "hash", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	triggerID, err := j.CreateChainTrigger(ctx, "wf_chain_downstream", "wf_chain_source", "succeeded")
	if err != nil {
		t.Fatal(err)
	}

	raw := callOperationalTool(t, s, "reactor_get_workflow_flow", map[string]any{"slug": "chain-downstream"}, false)
	var view struct {
		ExternalNodes []map[string]any `json:"external_nodes"`
		ExternalEdges []map[string]any `json:"external_edges"`
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	sourceNodeID := "workflow:wf_chain_source"
	triggerNodeID := "trigger:" + triggerID
	var sourceNode, triggerNode bool
	for _, node := range view.ExternalNodes {
		if node["id"] == sourceNodeID && node["kind"] == "workflow_source" && node["label"] == "chain-source" {
			sourceNode = true
		}
		if node["id"] == triggerNodeID && node["source_workflow_id"] == "wf_chain_source" && node["source_slug"] == "chain-source" {
			triggerNode = true
		}
	}
	if !sourceNode || !triggerNode {
		t.Fatalf("chain source topology missing: nodes=%#v", view.ExternalNodes)
	}
	var sourceEdge, targetEdge bool
	for _, edge := range view.ExternalEdges {
		if edge["from"] == sourceNodeID && edge["to"] == triggerNodeID && edge["kind"] == "chain" && edge["on_statuses"] == "succeeded" {
			sourceEdge = true
		}
		if edge["from"] == triggerNodeID && edge["to"] == "workflow:wf_chain_downstream" && edge["kind"] == "trigger" {
			targetEdge = true
		}
	}
	if !sourceEdge || !targetEdge {
		t.Fatalf("chain source edges missing: edges=%#v", view.ExternalEdges)
	}
}
