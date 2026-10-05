package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkflowAuthoringAdmissionIsTenantScopedAndVersionFenced(t *testing.T) {
	s, j, _ := newTestServer(t, true)
	s.TenantID = "acme"
	ctx := context.Background()
	assertAdmission := func(expected int, present bool, status string, ready, existing bool) {
		t.Helper()
		view, err := s.workflowAuthoringAdmission(ctx, "shared", expected, present)
		if err != nil {
			t.Fatal(err)
		}
		if view["status"] != status || view["ready_to_submit"] != ready || view["existing"] != existing || view["point_in_time"] != true {
			t.Fatalf("admission = %#v; want status=%s ready=%t existing=%t", view, status, ready, existing)
		}
	}

	// A foreign tenant's slug must not make this tenant's first creation look
	// like a revision or disclose the foreign version/state.
	if err := j.CreateWorkflowInTenantDisabled(ctx, "wf_other_shared", "shared", "hash", "0.1.0", json.RawMessage(`{}`), "other"); err != nil {
		t.Fatal(err)
	}
	assertAdmission(0, false, "new_workflow", true, false)
	assertAdmission(1, true, "unexpected_version", false, false)

	if err := j.CreateWorkflowInTenantDisabled(ctx, "wf_acme_shared", "shared", "hash", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	assertAdmission(0, false, "review_required", false, true)
	assertAdmission(2, true, "stale_version", false, true)
	assertAdmission(1, true, "revision_ready", true, true)
	if err := j.SetWorkflowEnabled(ctx, "wf_acme_shared", true); err != nil {
		t.Fatal(err)
	}
	assertAdmission(1, true, "active_workflow", false, true)
}

func TestValidateWorkflowReturnsAuthoringAdmissionWithoutMutation(t *testing.T) {
	reactorRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("REACTOR_SDK_REPLACE", reactorRoot)
	s, j, _ := newTestServer(t, true)
	s.StateRoot = t.TempDir()
	s.TenantID = "acme"
	ctx := context.Background()
	source, dag := visualStepFixture("admission", "work")
	if err := j.CreateWorkflowInTenantDisabled(ctx, "wf_admission", "admission", "old", "0.1.0", dag, "acme"); err != nil {
		t.Fatal(err)
	}
	// A stale revision is a definite create failure. Invalid Go would fail
	// compilation, but the read-only admission result must arrive first and
	// honestly say the source was not validated.
	blockedRaw := callOperationalTool(t, s, "reactor_validate_workflow", map[string]any{
		"slug": "admission", "main_go": "package main\nnot Go source", "dag": dag, "expected_version": 2,
	}, false)
	var blocked struct {
		Valid            bool   `json:"valid"`
		SourceValidated  bool   `json:"source_validated"`
		ValidationStatus string `json:"validation_status"`
		Admission        struct {
			Status        string `json:"status"`
			ReadyToSubmit bool   `json:"ready_to_submit"`
		} `json:"authoring_admission"`
	}
	if err := json.Unmarshal(blockedRaw, &blocked); err != nil {
		t.Fatal(err)
	}
	if blocked.Valid || blocked.SourceValidated || blocked.ValidationStatus != "not_run_authoring_blocked" || blocked.Admission.Status != "stale_version" || blocked.Admission.ReadyToSubmit {
		t.Fatalf("blocked validation receipt = %s", blockedRaw)
	}
	raw := callOperationalTool(t, s, "reactor_validate_workflow", map[string]any{
		"slug": "admission", "main_go": string(source), "dag": dag, "expected_version": 1,
	}, false)
	var view struct {
		Valid              bool `json:"valid"`
		Persisted          bool `json:"persisted"`
		AuthoringAdmission struct {
			Status        string `json:"status"`
			ReadyToSubmit bool   `json:"ready_to_submit"`
			PointInTime   bool   `json:"point_in_time"`
			Current       int    `json:"current_version"`
		} `json:"authoring_admission"`
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	if !view.Valid || view.Persisted || view.AuthoringAdmission.Status != "revision_ready" || !view.AuthoringAdmission.ReadyToSubmit || !view.AuthoringAdmission.PointInTime || view.AuthoringAdmission.Current != 1 {
		t.Fatalf("validation receipt = %s", raw)
	}
	workflow, err := j.GetWorkflow(ctx, "wf_admission")
	if err != nil || workflow.CurrentVersion != 1 || workflow.Enabled {
		t.Fatalf("validation mutated workflow: %#v err=%v", workflow, err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_admission", true); err != nil {
		t.Fatal(err)
	}
	activeRaw := callOperationalTool(t, s, "reactor_validate_workflow", map[string]any{
		"slug": "admission", "main_go": string(source), "dag": dag, "expected_version": 1,
	}, false)
	var active struct {
		Valid           bool `json:"valid"`
		SourceValidated bool `json:"source_validated"`
		Admission       struct {
			Status        string `json:"status"`
			ReadyToSubmit bool   `json:"ready_to_submit"`
			NextAction    string `json:"next_action"`
		} `json:"authoring_admission"`
	}
	if err := json.Unmarshal(activeRaw, &active); err != nil {
		t.Fatal(err)
	}
	if !active.Valid || !active.SourceValidated || active.Admission.Status != "active_workflow" || active.Admission.ReadyToSubmit || !strings.Contains(active.Admission.NextAction, "disable") {
		t.Fatalf("active workflow admission = %s", activeRaw)
	}
	for _, fence := range []any{0, nil, -1} {
		rejected := callOperationalTool(t, s, "reactor_validate_workflow", map[string]any{
			"slug": "admission", "main_go": string(source), "dag": dag, "expected_version": fence,
		}, true)
		if !strings.Contains(string(rejected), "expected_version") {
			t.Fatalf("invalid expected_version=%v was not identified: %s", fence, rejected)
		}
	}
}
