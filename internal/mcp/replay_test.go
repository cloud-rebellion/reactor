package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestHTTPMCPReplayRunUsesExactInputAndFreshKey(t *testing.T) {
	s, j, _ := newTestServer(t, true)
	s.Scopes = &WriteScopes{Dispatch: true}
	ctx := context.Background()
	mainSource, dag := visualStepFixture("replayable", "execute")
	artifact := publishVerifiedTestArtifact(t, s, "replayable", []byte("replayable-artifact"), mainSource, dag)
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_replayable", "replayable", sourceCodeHashForTest(mainSource), "0.1.0", artifact.Digest, dag, sourceManifestPinForTest(t, artifact)); err != nil {
		t.Fatal(err)
	}
	payload := []byte(" {\"customer\":\"alice@example.test\",\"attempt\":2} ")
	if err := j.CreateRun(ctx, "run_replay_source", "wf_replayable", "manual", payload); err != nil {
		t.Fatal(err)
	}
	if err := j.SetRunStatus(ctx, "run_replay_source", "failed"); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(payload)
	digest := hex.EncodeToString(hash[:])
	var seenSlug, seenKey string
	var seenPayload []byte
	s.DispatchIdempotent = func(ctx context.Context, slug string, got json.RawMessage, key string) (string, error) {
		seenSlug, seenKey, seenPayload = slug, key, append([]byte(nil), got...)
		id, _, err := j.CreateRunPinnedIdempotent(ctx, "run_replayed", "wf_replayable", "manual", got, 1, artifact.Digest, key, digest)
		return id, err
	}

	result := callOperationalTool(t, s, "reactor_replay_run", map[string]any{
		"run_id": "run_replay_source", "input_sha256": digest, "idempotency_key": "replay-request-1",
	}, false)
	if seenSlug != "replayable" || seenKey != "replay-request-1" || string(seenPayload) != string(payload) {
		t.Fatalf("replay dispatcher received slug=%q key=%q payload=%q", seenSlug, seenKey, seenPayload)
	}
	for _, want := range []string{`"run_id":"run_replayed"`, `"replayed_from_run_id":"run_replay_source"`, `"input_sha256":"` + digest + `"`, `"input_source":"trigger_input"`} {
		if !strings.Contains(string(result), want) {
			t.Fatalf("replay result missing %s: %s", want, result)
		}
	}

	// The caller must confirm the exact recorded fingerprint; a mismatched
	// digest must not reach the dispatcher.
	callOperationalTool(t, s, "reactor_replay_run", map[string]any{
		"run_id": "run_replay_source", "input_sha256": strings.Repeat("0", 64), "idempotency_key": "replay-request-2",
	}, true)
	// A key used by the first replay is rejected before dispatch, so a retry
	// cannot silently turn this explicit replay into another operation.
	callOperationalTool(t, s, "reactor_replay_run", map[string]any{
		"run_id": "run_replay_source", "input_sha256": digest, "idempotency_key": "replay-request-1",
	}, true)
	if seenKey != "replay-request-1" || string(seenPayload) != string(payload) {
		t.Fatalf("duplicate replay reached dispatcher: key=%q payload=%q", seenKey, seenPayload)
	}
}

func TestHTTPMCPReplayRunRefusesForeignAndActiveRuns(t *testing.T) {
	s, j, _ := newTestServer(t, true)
	s.Scopes = &WriteScopes{Dispatch: true}
	s.TenantID = "acme"
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_foreign_replay", "foreign-replay", "h", "0.1.0", json.RawMessage(`{}`), journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	foreignPayload := []byte(`{"foreign":true}`)
	if err := j.CreateRun(ctx, "run_foreign_replay", "wf_foreign_replay", "manual", foreignPayload); err != nil {
		t.Fatal(err)
	}
	foreignHash := sha256.Sum256(foreignPayload)
	foreignDigest := hex.EncodeToString(foreignHash[:])
	called := false
	s.DispatchIdempotent = func(context.Context, string, json.RawMessage, string) (string, error) {
		called = true
		return "unexpected", nil
	}
	callOperationalTool(t, s, "reactor_replay_run", map[string]any{
		"run_id": "run_foreign_replay", "input_sha256": foreignDigest, "idempotency_key": "foreign-replay-key",
	}, true)
	if called {
		t.Fatal("foreign run reached replay dispatcher")
	}

	if err := j.CreateWorkflowInTenant(ctx, "wf_active_replay", "active-replay", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	activePayload := []byte(`{"active":true}`)
	if err := j.CreateRun(ctx, "run_active_replay", "wf_active_replay", "manual", activePayload); err != nil {
		t.Fatal(err)
	}
	activeHash := sha256.Sum256(activePayload)
	activeDigest := hex.EncodeToString(activeHash[:])
	callOperationalTool(t, s, "reactor_replay_run", map[string]any{
		"run_id": "run_active_replay", "input_sha256": activeDigest, "idempotency_key": "active-replay-key",
	}, true)
	if called {
		t.Fatal("active run reached replay dispatcher")
	}
}

func TestHTTPMCPReplayRunRejectsInvalidRetainedPayload(t *testing.T) {
	s, j, _ := newTestServer(t, true)
	s.Scopes = &WriteScopes{Dispatch: true}
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_invalid_replay", "invalid-replay", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`["not-an-object"]`)
	if err := j.CreateRun(ctx, "run_invalid_replay", "wf_invalid_replay", "manual", payload); err != nil {
		t.Fatal(err)
	}
	if err := j.SetRunStatus(ctx, "run_invalid_replay", "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(payload)
	digest := hex.EncodeToString(hash[:])
	called := false
	s.DispatchIdempotent = func(context.Context, string, json.RawMessage, string) (string, error) {
		called = true
		return "unexpected", nil
	}
	callOperationalTool(t, s, "reactor_replay_run", map[string]any{
		"run_id": "run_invalid_replay", "input_sha256": digest, "idempotency_key": "invalid-replay-key",
	}, true)
	if called {
		t.Fatal("invalid retained payload reached replay dispatcher")
	}
}
