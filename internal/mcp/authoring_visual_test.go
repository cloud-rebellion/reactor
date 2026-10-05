package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func visualStepFixture(slug, step string) ([]byte, json.RawMessage) {
	source := []byte(fmt.Sprintf(`package main
import (
    "context"
    reactor "github.com/bright-interaction/reactor/sdk"
    runtime "github.com/bright-interaction/reactor/sdk/runtime"
)
func run(ctx context.Context, flow reactor.Flow, _ struct{}) error {
    _, err := reactor.Step(flow, ctx, %q, reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
    return err
}
func main() { runtime.Serve(reactor.Workflow{Slug: %q, Version: "0.1.0"}, reactor.EventTrigger{}, run) }
`, step, slug))
	dag, _ := json.Marshal(map[string]any{"steps": []any{map[string]any{"name": step, "kind": "step"}}})
	return source, dag
}

func TestMCPAuthoringRejectsUnrenderableWorkflowBeforeBuild(t *testing.T) {
	s, j, _ := newTestServer(t, true)
	s.StateRoot = t.TempDir()
	mainSource := "package main\nfunc main() {}\n"
	for _, tc := range []struct {
		name string
		dag  any
	}{
		{"omitted", nil},
		{"explicit null", json.RawMessage(`null`)},
		{"empty object", map[string]any{}},
		{"empty steps", map[string]any{"steps": []any{}}},
		{"empty nodes", map[string]any{"nodes": []any{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]any{"slug": "no-flow", "main_go": mainSource}
			if tc.dag != nil {
				args["dag"] = tc.dag
			}
			for _, tool := range []string{"reactor_validate_workflow", "reactor_create_workflow"} {
				callOperationalTool(t, s, tool, args, true)
			}
		})
	}
	// A fabricated visual node must also fail the existing source/DAG check.
	for _, tool := range []string{"reactor_validate_workflow", "reactor_create_workflow"} {
		callOperationalTool(t, s, tool, map[string]any{
			"slug": "no-flow", "main_go": mainSource,
			"dag": map[string]any{"steps": []any{map[string]any{"name": "fake", "kind": "step"}}},
		}, true)
	}
	if _, err := j.WorkflowIDBySlug(context.Background(), "no-flow"); err == nil {
		t.Fatal("rejected MCP authoring request registered a workflow")
	}
}

func TestMCPAuthoringRejectsUndecodableVisualFieldsBeforeBuild(t *testing.T) {
	s, j, _ := newTestServer(t, true)
	s.StateRoot = t.TempDir()
	source, _ := visualStepFixture("malformed-visual", "send")
	dag := json.RawMessage(`{"steps":[{"name":"send","kind":"step","uses":"credential"}]}`)
	for _, tool := range []string{"reactor_validate_workflow", "reactor_create_workflow"} {
		result := callOperationalTool(t, s, tool, map[string]any{
			"slug": "malformed-visual", "main_go": string(source), "dag": dag,
		}, true)
		if !strings.Contains(string(result), "/steps/0/uses") {
			t.Fatalf("%s did not explain the invalid visual field: %s", tool, result)
		}
	}
	if _, err := j.WorkflowIDBySlug(context.Background(), "malformed-visual"); err == nil {
		t.Fatal("undecodable DAG registered a workflow")
	}
}

func TestMCPAuthoringRejectsFlowBeyondActivationProjection(t *testing.T) {
	s, j, _ := newTestServer(t, true)
	s.StateRoot = t.TempDir()
	steps := make([]map[string]any, 0, 33)
	for i := 0; i < 33; i++ {
		deps := make([]string, 0, i)
		for previous := 0; previous < i; previous++ {
			deps = append(deps, fmt.Sprintf("step%d", previous))
		}
		steps = append(steps, map[string]any{
			"name": fmt.Sprintf("step%d", i), "kind": "step", "depends_on": deps,
		})
	}
	dag, err := json.Marshal(map[string]any{"steps": steps})
	if err != nil {
		t.Fatal(err)
	}
	// The dependency graph is schema-valid but has 528 distinct edges. A
	// compiled artifact from it cannot pass the 512-edge review/enable gate.
	// Both authoring tools must reject it before Go build or registration.
	for _, tool := range []string{"reactor_validate_workflow", "reactor_create_workflow"} {
		result := callOperationalTool(t, s, tool, map[string]any{
			"slug": "unreviewable-flow", "main_go": "package main\nfunc main() {}\n", "dag": json.RawMessage(dag),
		}, true)
		if !strings.Contains(string(result), "bounded MCP flow projection") {
			t.Fatalf("%s did not explain the review limit: %s", tool, result)
		}
	}
	if _, err := j.WorkflowIDBySlug(context.Background(), "unreviewable-flow"); err == nil {
		t.Fatal("unreviewable flow registered a workflow")
	}
}

func TestMCPEmptyLegacyFlowStaysInspectableButCannotActivate(t *testing.T) {
	s, j, _ := newTestServer(t, true)
	s.StateRoot = t.TempDir()
	ctx := context.Background()
	mainSource := []byte("package main\nfunc main() {}\n")
	artifact := publishVerifiedTestArtifact(t, s, "legacy-empty-flow", []byte("binary"), mainSource, []byte(`{}`))
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_legacy_empty_flow", "legacy-empty-flow", sourceCodeHashForTest(mainSource), "0.1.0", artifact.Digest, json.RawMessage(`{}`), journal.DefaultTenant, sourceManifestPinForTest(t, artifact)); err != nil {
		t.Fatal(err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_legacy_empty_flow", false); err != nil {
		t.Fatal(err)
	}
	view := callOperationalTool(t, s, "reactor_review_workflow", map[string]any{"slug": "legacy-empty-flow"}, false)
	for _, want := range []string{`"source_dag_status":"mismatch"`, `"review_status":"invalid_flow"`, `"flow_valid":false`, `"visual_complete":false`, `"flow_verification":"unverified"`, "no executable nodes"} {
		if !strings.Contains(string(view), want) {
			t.Fatalf("legacy review missing %s: %s", want, view)
		}
	}
	flow := callOperationalTool(t, s, "reactor_get_workflow_flow", map[string]any{"slug": "legacy-empty-flow"}, false)
	for _, want := range []string{`"validated":true`, `"flow_valid":false`, `"visual_complete":false`, `"flow_verification":"unverified"`, missingVisualNodesReason} {
		if !strings.Contains(string(flow), want) {
			t.Fatalf("legacy flow missing %s: %s", want, flow)
		}
	}
	resource, err := s.readResource(ctx, "reactor://workflows/legacy-empty-flow/flow")
	if err != nil {
		t.Fatal(err)
	}
	resourceJSON, err := json.Marshal(resource)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`\"flow_valid\":false`, `\"visual_complete\":false`, `\"flow_verification\":\"unverified\"`, missingVisualNodesReason} {
		if !strings.Contains(string(resourceJSON), want) {
			t.Fatalf("legacy flow resource missing %s: %s", want, resourceJSON)
		}
	}
	preflight := callOperationalTool(t, s, "reactor_preflight_dispatch_workflow", map[string]any{"slug": "legacy-empty-flow"}, false)
	for _, want := range []string{`"durable_ready":false`, `"dispatchable_now":false`, `"flow_valid":false`, missingVisualNodesReason} {
		if !strings.Contains(string(preflight), want) {
			t.Fatalf("legacy preflight missing %s: %s", want, preflight)
		}
	}
	callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{
		"slug": "legacy-empty-flow", "state": "enabled", "expected_version": 1,
	}, true)
	if enabled, err := j.IsWorkflowEnabled(ctx, "wf_legacy_empty_flow"); err != nil || enabled {
		t.Fatalf("legacy empty flow activated: enabled=%t err=%v", enabled, err)
	}
}
