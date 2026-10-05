package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestMCPEnableRequiresExactDistributedWorkerArtifact(t *testing.T) {
	ctx := context.Background()
	s, j, _ := newTestServer(t, true)
	s.StateRoot = t.TempDir()
	s.WorkerArtifactRoot = t.TempDir()
	const slug = "worker-activation"
	source, dag := visualStepFixture(slug, "execute")
	artifact := publishVerifiedTestArtifact(t, s, slug, []byte("binary"), source, dag)
	if err := j.CreateWorkflowInTenantWithArtifactDisabled(ctx, "wf_worker_activation", slug, sourceCodeHashForTest(source), "0.1.0", artifact.Digest, dag, journal.DefaultTenant, sourceManifestPinForTest(t, artifact)); err != nil {
		t.Fatal(err)
	}

	args := map[string]any{"slug": slug, "state": "enabled", "expected_state": "disabled", "expected_version": 1}
	missingReview := callOperationalTool(t, s, "reactor_review_workflow", map[string]any{"slug": slug}, false)
	for _, want := range []string{`"review_status":"worker_artifact_not_ready"`, `"worker_artifact_ready":false`, `"worker_artifact_status":"unavailable"`} {
		if !strings.Contains(string(missingReview), want) {
			t.Fatalf("review omitted worker publication gate %s: %s", want, missingReview)
		}
	}
	missingEnable := callOperationalTool(t, s, "reactor_set_workflow_state", args, true)
	if !strings.Contains(string(missingEnable), "not verified on distributed worker storage") {
		t.Fatalf("enable did not explain the missing worker artifact: %s", missingEnable)
	}
	if enabled, err := j.IsWorkflowEnabled(ctx, "wf_worker_activation"); err != nil || enabled {
		t.Fatalf("missing worker artifact activated workflow: enabled=%t err=%v", enabled, err)
	}

	workerView := &Server{StateRoot: s.WorkerArtifactRoot}
	copied := publishVerifiedTestArtifact(t, workerView, slug, []byte("binary"), source, dag)
	if copied.Digest != artifact.Digest {
		t.Fatalf("worker digest = %q, want %q", copied.Digest, artifact.Digest)
	}
	readyReview := callOperationalTool(t, s, "reactor_review_workflow", map[string]any{"slug": slug}, false)
	for _, want := range []string{`"review_status":"ready_for_review"`, `"worker_artifact_ready":true`, `"worker_artifact_status":"verified"`} {
		if !strings.Contains(string(readyReview), want) {
			t.Fatalf("review did not recognize exact worker artifact %s: %s", want, readyReview)
		}
	}
	enabledReceipt := callOperationalTool(t, s, "reactor_set_workflow_state", args, false)
	var enabledView map[string]any
	if err := json.Unmarshal(enabledReceipt, &enabledView); err != nil {
		t.Fatal(err)
	}
	if enabledView["enabled"] != true || enabledView["worker_artifact_ready"] != true || enabledView["worker_artifact_status"] != "verified" {
		t.Fatalf("enabled receipt omitted worker proof: %s", enabledReceipt)
	}

	callOperationalTool(t, s, "reactor_set_workflow_state", map[string]any{"slug": slug, "state": "disabled", "expected_state": "enabled", "expected_version": 1}, false)
	if err := os.Remove(filepath.Join(filepath.Dir(copied.Path), "source", registry.SourceManifestFilename)); err != nil {
		t.Fatal(err)
	}
	badReview := callOperationalTool(t, s, "reactor_review_workflow", map[string]any{"slug": slug}, false)
	if !strings.Contains(string(badReview), `"worker_artifact_ready":false`) || !strings.Contains(string(badReview), `"review_status":"worker_artifact_not_ready"`) {
		t.Fatalf("review accepted worker source drift: %s", badReview)
	}
	callOperationalTool(t, s, "reactor_set_workflow_state", args, true)
	if enabled, err := j.IsWorkflowEnabled(ctx, "wf_worker_activation"); err != nil || enabled {
		t.Fatalf("drifted worker artifact activated workflow: enabled=%t err=%v", enabled, err)
	}
}
