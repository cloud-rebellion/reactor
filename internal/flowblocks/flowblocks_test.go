package flowblocks

import (
	"encoding/json"
	"strings"
	"testing"
)

const routedDAG = `{"nodes":[{"id":"process","kind":"step","visual_flow":{
  "blocks":[
    {"id":"route","kind":"split","label":"Ready?"},
    {"id":"each","kind":"iterate","label":"Each item"},
    {"id":"sum","kind":"aggregate"},
    {"id":"join","kind":"merge"}
  ],
  "edges":[
    {"from":"route","to":"each","route":"ready"},
    {"from":"route","to":"join","route":"skipped"},
    {"from":"each","to":"sum"},
    {"from":"sum","to":"join"}
  ]
}}]}`

func TestFromDAGProjectsDeclaredRoutedBlocksWithoutExecutionClaim(t *testing.T) {
	t.Parallel()
	projection := FromDAG([]byte(routedDAG), 1<<20)
	if projection.Provenance != "author_declared_annotation" || !projection.Complete || projection.BehaviorVerified {
		t.Fatalf("projection trust = %#v", projection)
	}
	if projection.BlockCount != 4 || projection.EdgeCount != 4 || len(projection.Steps) != 1 {
		t.Fatalf("projection shape = %#v", projection)
	}
	if projection.Steps[0].Step != "process" || projection.Steps[0].Edges[1].Route != "skipped" {
		t.Fatalf("routed edge was lost: %#v", projection.Steps)
	}
	if !strings.Contains(projection.Note, "not independently executable") || !strings.Contains(projection.Note, "Durable steps have host-recorded outcomes") || !strings.Contains(projection.Note, "SDK-reported receipts") {
		t.Fatalf("projection omitted execution boundary: %q", projection.Note)
	}
}

func TestFromDAGRejectsPartialOrOversizedAnnotation(t *testing.T) {
	t.Parallel()
	for _, src := range []string{
		`{"steps":[{"name":"work","kind":"step","visual_flow":{"blocks":[{"id":"one","kind":"split"},{"id":"two","kind":"merge"}],"edges":[{"from":"one","to":"two"},{"from":"two","to":"one"}]}}]}`,
		`{"steps":[{"name":"work","kind":"step","visual_flow":{"blocks":[{"id":"one","kind":"split"}],"edges":[{"from":"one","to":"missing"}]}}]}`,
		`{"steps":[{"name":"work","kind":"sleep","visual_flow":{"blocks":[{"id":"one","kind":"iterate"}]}}]}`,
		`{"steps":[{"name":"work","kind":"step","visual_flow":{"blocks":[{"id":"one","kind":"split"}],"blocks":[{"id":"two","kind":"merge"}]}}]}`,
	} {
		p := FromDAG([]byte(src), 1<<20)
		if p.Provenance != "invalid_annotation" || p.Complete || p.BlockCount != 0 || len(p.Steps) != 0 {
			t.Fatalf("malformed annotation was partially projected: %#v", p)
		}
	}
	oversized := FromDAG([]byte(routedDAG), 8)
	if oversized.Complete || len(oversized.Steps) != 0 {
		t.Fatalf("oversized DAG was projected: %#v", oversized)
	}
}

func TestExtractRejectsUnknownFieldsAndGlobalBlockBudget(t *testing.T) {
	t.Parallel()
	var raw map[string]any
	if err := json.Unmarshal([]byte(`{"steps":[{"name":"work","kind":"step","visual_flow":{"blocks":[{"id":"one","kind":"split","credential":"opaque"}],"edges":[]}}]}`), &raw); err != nil {
		t.Fatal(err)
	}
	_, issues := Extract(raw)
	if len(issues) == 0 || issues[0].Path != "/steps/0/visual_flow/blocks/0" {
		t.Fatalf("unknown field was silently accepted: %#v", issues)
	}

	steps := make([]any, 9)
	for i := range steps {
		blocks := make([]any, MaxBlocksPerStep)
		for j := range blocks {
			blocks[j] = map[string]any{"id": "block" + decimal(j), "kind": "map"}
		}
		steps[i] = map[string]any{"name": "step" + decimal(i), "kind": "step", "visual_flow": map[string]any{"blocks": blocks}}
	}
	_, issues = Extract(map[string]any{"steps": steps})
	found := false
	for _, issue := range issues {
		if strings.Contains(issue.Message, "at most 256 visual blocks") {
			found = true
		}
	}
	if !found {
		t.Fatalf("global block budget was not enforced: %#v", issues)
	}
}

func TestMergeAnnotationPreservesExplicitModeAndBound(t *testing.T) {
	const dag = `{"steps":[{"name":"work","kind":"step","visual_flow":{"blocks":[{"id":"join","kind":"merge","label":"Join customers","mode":"full_join","key":"customer.id","max_rows":500}]}}]}`
	p := FromDAG([]byte(dag), 1<<20)
	if !p.Complete || p.Provenance != "author_declared_annotation" || p.BehaviorVerified || len(p.Steps) != 1 || len(p.Steps[0].Blocks) != 1 {
		t.Fatalf("merge projection = %+v", p)
	}
	block := p.Steps[0].Blocks[0]
	if block.Mode != "full_join" || block.Key != "customer.id" || block.MaxRows != 500 {
		t.Fatalf("merge settings lost: %+v", block)
	}
	for _, block := range []string{
		`{"id":"join","kind":"merge","mode":"full_join"}`,
		`{"id":"join","kind":"merge","mode":"full_join","max_rows":100001}`,
		`{"id":"join","kind":"merge","mode":"full_join","max_rows":1.5}`,
		`{"id":"join","kind":"merge","mode":"full_join","max_rows":null}`,
		`{"id":"join","kind":"merge","mode":"append","max_rows":10}`,
		`{"id":"join","kind":"merge","mode":"position_keep_all","key":"customer.id","max_rows":10}`,
		`{"id":"join","kind":"merge","mode":"unknown"}`,
		`{"id":"join","kind":"split","mode":"append"}`,
	} {
		src := `{"steps":[{"name":"work","kind":"step","visual_flow":{"blocks":[` + block + `]}}]}`
		if got := FromDAG([]byte(src), 1<<20); got.Complete || got.Provenance != "invalid_annotation" {
			t.Fatalf("invalid merge settings accepted: %s => %+v", block, got)
		}
	}
}

func TestSupportsSDKObservationForBoundedKeyJoinsAndSplits(t *testing.T) {
	for _, tc := range []struct {
		block Block
		want  bool
	}{
		{Block{Kind: "merge", Mode: "inner_join", MaxRows: 10}, true},
		{Block{Kind: "merge", Mode: "left_join", MaxRows: 10}, true},
		{Block{Kind: "merge", Mode: "right_join", MaxRows: 10}, true},
		{Block{Kind: "merge", Mode: "full_join", MaxRows: 10}, true},
		{Block{Kind: "merge", Mode: "full_join"}, false},
		{Block{Kind: "merge", Mode: "append"}, false},
		{Block{Kind: "split"}, true},
		{Block{Kind: "iterate"}, true},
		{Block{Kind: "aggregate"}, true},
	} {
		if got := SupportsSDKObservation(tc.block); got != tc.want {
			t.Errorf("SupportsSDKObservation(%+v) = %t, want %t", tc.block, got, tc.want)
		}
	}
}
