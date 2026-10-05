package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGetRunComparesObservedOrderWithPinnedDAG(t *testing.T) {
	s, j, _ := newTestServer(t, false)
	s.TenantID = "acme"
	ctx := context.Background()
	artifact := strings.Repeat("a", 64)
	dag := json.RawMessage(`{"steps":[{"name":"approve","kind":"step"},{"name":"send","kind":"step","depends_on":["approve"]}]}`)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_topology", "topology", "h", "0.1.0", artifact, dag, "acme"); err != nil {
		t.Fatal(err)
	}
	createRun := func(runID string, names ...string) {
		t.Helper()
		if err := j.CreateRunPinned(ctx, runID, "wf_topology", "manual", json.RawMessage(`{"private":"never-return"}`), 1, artifact); err != nil {
			t.Fatal(err)
		}
		for index, name := range names {
			seq := int64(index + 1)
			if _, err := j.RecordStepStartSeq(ctx, runID, name, seq, 1, "", "hash"); err != nil {
				t.Fatal(err)
			}
			if err := j.RecordStepEndSeq(ctx, runID, name, seq, 1, json.RawMessage(`null`), ""); err != nil {
				t.Fatal(err)
			}
			// SQLite persists millisecond timestamps; make the ordering
			// distinguishable from an equal-timestamp uncertainty.
			time.Sleep(2 * time.Millisecond)
		}
		if err := j.SetRunStatus(ctx, runID, "succeeded"); err != nil {
			t.Fatal(err)
		}
	}
	read := func(runID string, limit int) map[string]any {
		t.Helper()
		raw := callOperationalTool(t, s, "reactor_get_run", map[string]any{"run_id": runID, "limit": limit}, false)
		if strings.Contains(string(raw), "never-return") {
			t.Fatalf("run receipt exposed input: %s", raw)
		}
		var result struct {
			Topology map[string]any `json:"topology_execution"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		return result.Topology
	}

	createRun("run_topology_consistent", "approve", "send")
	consistent := read("run_topology_consistent", 10)
	if consistent["status"] != "no_observed_inversion" || consistent["compared_edge_count"] != float64(1) ||
		consistent["checked_start_count"] != float64(1) || consistent["behavior_verified"] != false ||
		consistent["branch_coverage_verified"] != false {
		t.Fatalf("consistent receipt = %#v", consistent)
	}

	createRun("run_topology_inverted", "send", "approve")
	inverted := read("run_topology_inverted", 1)
	if inverted["status"] != "mismatch" || inverted["mismatch_count"] != float64(1) ||
		inverted["timeline_complete"] != false {
		t.Fatalf("inverted first page receipt = %#v", inverted)
	}
	mismatches, ok := inverted["mismatches"].([]any)
	if !ok || len(mismatches) != 1 {
		t.Fatalf("missing inversion detail: %#v", inverted)
	}
	item := mismatches[0].(map[string]any)
	if item["from"] != "approve" || item["to"] != "send" || item["to_seq"] != float64(1) {
		t.Fatalf("inversion detail = %#v", item)
	}

	if err := j.CreateRunPinned(ctx, "run_topology_overlapped", "wf_topology", "manual", json.RawMessage(`{}`), 1, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordStepStartSeq(ctx, "run_topology_overlapped", "approve", 1, 1, "", "hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordStepStartSeq(ctx, "run_topology_overlapped", "send", 2, 1, "", "hash"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	for _, step := range []struct {
		name string
		seq  int64
	}{{"approve", 1}, {"send", 2}} {
		if err := j.RecordStepEndSeq(ctx, "run_topology_overlapped", step.name, step.seq, 1, json.RawMessage(`null`), ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.SetRunStatus(ctx, "run_topology_overlapped", "succeeded"); err != nil {
		t.Fatal(err)
	}
	overlapped := read("run_topology_overlapped", 10)
	if overlapped["status"] != "mismatch" || overlapped["mismatch_count"] != float64(1) {
		t.Fatalf("dependent started before predecessor finished: %#v", overlapped)
	}

	partial := read("run_topology_consistent", 1)
	if partial["status"] != "incomplete" || partial["timeline_complete"] != false {
		t.Fatalf("partial first page receipt = %#v", partial)
	}
	var laterPage struct {
		Topology map[string]any `json:"topology_execution"`
	}
	if err := json.Unmarshal(callOperationalTool(t, s, "reactor_get_run", map[string]any{
		"run_id": "run_topology_consistent", "limit": 1, "offset": 1,
	}, false), &laterPage); err != nil || laterPage.Topology["status"] != "unavailable" {
		t.Fatalf("non-prefix page must not claim a comparison: %+v, %v", laterPage, err)
	}

	s.TenantID = "other"
	callOperationalTool(t, s, "reactor_get_run", map[string]any{"run_id": "run_topology_inverted"}, true)
}
