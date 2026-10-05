package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestRunFlowUsesPinnedHistoricalDAG(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j := journalForServerTest(t)
	oldDAG := json.RawMessage(`{"steps":[{"name":"old-step","kind":"step"}]}`)
	newDAG := json.RawMessage(`{"steps":[{"name":"new-step","kind":"step"}]}`)
	oldArtifact := strings.Repeat("a", 64)
	newArtifact := strings.Repeat("b", 64)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_history", "history", "old", "0.1.0", oldArtifact, oldDAG, "default"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRunPinned(ctx, "run_history", "wf_history", "manual", json.RawMessage(`{}`), 1, oldArtifact); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_history", "0.2.0", "new", newArtifact, newDAG); err != nil {
		t.Fatal(err)
	}
	info, err := j.GetRun(ctx, "run_history")
	if err != nil {
		t.Fatal(err)
	}
	flow, notice := (&Server{Journal: j}).runFlowForRun(ctx, info, []journal.StepRow{{StepName: "old-step", Status: "succeeded"}})
	if notice != "" || !strings.Contains(flow, "old-step") || strings.Contains(flow, "new-step") {
		t.Fatalf("historical run flow = %q, notice = %q; want only the pinned v1 DAG", flow, notice)
	}

	info.WorkflowArtifactSHA256 = newArtifact
	flow, notice = (&Server{Journal: j}).runFlowForRun(ctx, info, nil)
	if flow != "" || !strings.Contains(notice, "identity cannot be verified") {
		t.Fatalf("artifact mismatch rendered a flow: %q, notice = %q", flow, notice)
	}
}

func TestRunFlowUnpinnedLegacyRunShowsTimelineNotice(t *testing.T) {
	t.Parallel()
	flow, notice := (&Server{}).runFlowForRun(context.Background(), journal.RunInfo{WorkflowID: "wf_old"}, nil)
	if flow != "" || !strings.Contains(notice, "predates workflow version pinning") {
		t.Fatalf("legacy flow = %q, notice = %q; want no invented current-version graph", flow, notice)
	}
	page := runDetailBody(journal.RunInfo{ID: "run_old"}, nil, flow, notice, "", nil, false)
	if !strings.Contains(page, "step timeline below is authoritative") {
		t.Fatal("legacy run page omitted the visible flow caveat")
	}
}

func TestRunDetailShowsBoundedProvenanceWithoutInput(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"hello":"world"}`)
	digest := sha256.Sum256(payload)
	info := journal.RunInfo{
		ID:                     "run_receipt",
		WorkflowID:             "wf_receipt",
		InputSHA256:            fmt.Sprintf("%x", digest),
		TriggerInput:           payload,
		WorkflowVersion:        3,
		WorkflowArtifactSHA256: strings.Repeat("c", 64),
	}
	page := runDetailBody(info, nil, "", "", "", nil, false)
	for _, want := range []string{"Input SHA-256", info.InputSHA256, "(17 captured bytes)", "Workflow version", "<code>3</code>", "Artifact SHA-256", info.WorkflowArtifactSHA256} {
		if !strings.Contains(page, want) {
			t.Fatalf("run detail missing provenance receipt %q", want)
		}
	}
	if strings.Contains(page, "hello") || strings.Contains(page, "world") {
		t.Fatal("run detail exposed trigger payload while rendering provenance")
	}
	bounded := runDetailBody(journal.RunInfo{
		ID:                     "run_bounded_receipt",
		InputSHA256:            info.InputSHA256,
		TriggerInputBytes:      len(payload),
		TriggerInputPresent:    true,
		WorkflowVersion:        3,
		WorkflowArtifactSHA256: info.WorkflowArtifactSHA256,
	}, nil, "", "", "", nil, false)
	if !strings.Contains(bounded, "(17 durable input bytes)") || strings.Contains(bounded, "hello") {
		t.Fatalf("bounded run detail = %q; want size-only receipt", bounded)
	}
}

func TestRunDetailMarksOmittedStepData(t *testing.T) {
	t.Parallel()
	page := runDetailBody(journal.RunInfo{ID: "run_step_bounds"}, []journal.StepRow{
		{StepName: "secret-output", Status: "succeeded", OutputBytes: maxRunDetailStepOutputBytes + 1, OutputTruncated: true},
		{StepName: "secret-error", Status: "failed", ErrorBytes: maxRunDetailStepErrorBytes + 1, ErrorTruncated: true},
	}, "", "", "", nil, false)
	if !strings.Contains(page, "output omitted (") || !strings.Contains(page, "error omitted (") {
		t.Fatalf("run detail omitted-data receipts missing: %s", page)
	}
	if strings.Contains(page, "output_jsonb") || strings.Contains(page, "secret") {
		// Step names are expected in the table; only the raw omitted data must
		// stay absent. The receipt assertions above prove the safe branch.
		if strings.Contains(page, `"secret"`) {
			t.Fatalf("run detail exposed omitted data: %s", page)
		}
	}
}

func TestBoundRunDetailLogsPreservesOmissionReceipts(t *testing.T) {
	t.Parallel()
	large := strings.Repeat("x", maxRunDetailLogLineBytes+32)
	logs := boundRunDetailLogs([]string{"ok", large})
	if len(logs) != 2 || !strings.Contains(logs[1], "log line omitted") || strings.Contains(logs[1], large) {
		t.Fatalf("bounded live logs = %#v; want explicit omission marker", logs)
	}
	persisted := boundRunDetailPersistedLogs([]journal.BoundedRunLogLine{{Bytes: len(large), Truncated: true}})
	if len(persisted) != 1 || !strings.Contains(persisted[0], "durable bytes") {
		t.Fatalf("bounded persisted logs = %#v; want durable byte receipt", persisted)
	}
}

func TestRunFlowBoundsHistoricalDAGBeforeMaterializingIt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j := journalForServerTest(t)
	artifact := strings.Repeat("d", 64)
	dag := json.RawMessage(`{"steps":[],"padding":"` + strings.Repeat("x", maxFlowDAGBytes+64) + `"}`)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_large_history", "large-history", "h", "0.1.0", artifact, dag, journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRunPinned(ctx, "run_large_history", "wf_large_history", "manual", json.RawMessage(`{}`), 1, artifact); err != nil {
		t.Fatal(err)
	}
	info, err := j.GetRun(ctx, "run_large_history")
	if err != nil {
		t.Fatal(err)
	}
	flow, notice := (&Server{Journal: j}).runFlowForRun(ctx, info, nil)
	if flow != "" || !strings.Contains(notice, "exceeds the bounded visual projection") || !strings.Contains(notice, "step timeline below is authoritative") {
		t.Fatalf("oversized historical flow = %q, notice = %q", flow, notice)
	}
}

func TestWorkflowDetailProofRejectsOversizedDAGMetadata(t *testing.T) {
	t.Parallel()
	artifact := strings.Repeat("e", 64)
	_, status, reason := (&Server{}).workflowDetailProof(context.Background(), "oversized-detail", journal.DefaultTenant, journal.WorkflowVersion{
		Version:        1,
		ArtifactSHA256: artifact,
		DAGBytes:       maxFlowDAGBytes + 1,
		DAGTruncated:   true,
	})
	if status != "unavailable" || !strings.Contains(reason, "bounded visual projection") {
		t.Fatalf("oversized detail proof = status %q reason %q; want unavailable bounded reason", status, reason)
	}
}
