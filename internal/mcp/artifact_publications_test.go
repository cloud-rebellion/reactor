package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestArtifactPublicationMCPExactVersionAndTenantFence(t *testing.T) {
	s, j, _ := newTestServer(t, false)
	s.StateRoot = t.TempDir()
	s.Scopes = &WriteScopes{ArtifactPublication: true}
	s.ArtifactPublicationAuthorized = func(context.Context) bool { return true }
	const slug = "publish-reviewed"
	source := []byte(`package main
import (
  "context"
  reactor "github.com/bright-interaction/reactor/sdk"
)
func Run(ctx context.Context, flow reactor.Flow) error {
  _, err := reactor.Step(flow, ctx, "execute", reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
  return err
}
func main() {}
`)
	dag := json.RawMessage(`{"steps":[{"name":"execute","kind":"step"}]}`)
	artifact := publishVerifiedTestArtifact(t, s, slug, []byte("verified workflow binary"), source, dag)
	if err := j.CreateWorkflowInTenantWithArtifactDisabled(context.Background(), "wf_publication_mcp", slug, sourceCodeHashForTest(source), "0.1.0", artifact.Digest, dag, journal.DefaultTenant, sourceManifestPinForTest(t, artifact)); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"slug": slug, "version": 1, "expected_artifact_sha256": artifact.Digest}
	first := callOperationalTool(t, s, "reactor_publish_workflow_artifact", args, false)
	var receipt map[string]any
	if err := json.Unmarshal(first, &receipt); err != nil {
		t.Fatal(err)
	}
	publicationID, _ := receipt["publication_id"].(string)
	if publicationID == "" || receipt["status"] != journal.ArtifactPublicationPending || receipt["enabled_unchanged"] != true || receipt["dispatch_started"] != false {
		t.Fatalf("unexpected publication receipt: %s", first)
	}
	if _, exposed := receipt["tenant_id"]; exposed {
		t.Fatalf("publication receipt exposed tenant identity: %s", first)
	}
	second := callOperationalTool(t, s, "reactor_publish_workflow_artifact", args, false)
	var retry map[string]any
	if err := json.Unmarshal(second, &retry); err != nil {
		t.Fatal(err)
	}
	if retry["publication_id"] != publicationID {
		t.Fatalf("exact retry created another request: first=%s second=%s", first, second)
	}
	status := callOperationalTool(t, s, "reactor_get_artifact_publication", map[string]any{"publication_id": publicationID}, false)
	if !strings.Contains(string(status), `"status":"pending"`) {
		t.Fatalf("status did not report pending publication: %s", status)
	}
	callOperationalTool(t, s, "reactor_publish_workflow_artifact", map[string]any{"slug": slug, "version": 1, "expected_artifact_sha256": strings.Repeat("0", 64)}, true)
	callOperationalTool(t, s, "reactor_publish_workflow_artifact", map[string]any{"slug": slug, "version": 2, "expected_artifact_sha256": artifact.Digest}, true)
	callOperationalTool(t, s, "reactor_publish_workflow_artifact", map[string]any{"slug": slug, "version": 1, "expected_artifact_sha256": artifact.Digest, "destination_root": "/tmp/other"}, true)
	callOperationalTool(t, s, "reactor_requeue_artifact_publication", map[string]any{"publication_id": publicationID, "confirm_publication_id": "wrong", "expected_artifact_sha256": artifact.Digest}, true)
	callOperationalTool(t, s, "reactor_requeue_artifact_publication", map[string]any{"publication_id": publicationID, "confirm_publication_id": publicationID, "expected_artifact_sha256": artifact.Digest}, true) // pending is not terminal failed

	// The HTTP tool resolves tenant from its authenticated server context. A
	// second tenant cannot poll or enqueue this publication by guessing the id.
	s.TenantID = "other-tenant"
	callOperationalTool(t, s, "reactor_get_artifact_publication", map[string]any{"publication_id": publicationID}, true)
	callOperationalTool(t, s, "reactor_publish_workflow_artifact", args, true)
	callOperationalTool(t, s, "reactor_requeue_artifact_publication", map[string]any{"publication_id": publicationID, "confirm_publication_id": publicationID, "expected_artifact_sha256": artifact.Digest}, true)
	if _, err := j.GetArtifactPublicationForTenant(context.Background(), publicationID, "other-tenant"); !errors.Is(err, journal.ErrNotFound) {
		t.Fatalf("foreign tenant publication lookup = %v, want not found", err)
	}
}

func TestArtifactPublicationMCPRequiresSeparateScope(t *testing.T) {
	for _, scopes := range []*WriteScopes{nil, {}, {Authoring: true}, {Dispatch: true}} {
		s, _, _ := newTestServer(t, false)
		s.StateRoot = t.TempDir()
		s.Scopes = scopes
		s.registerTools()
		if _, found := s.tools["reactor_publish_workflow_artifact"]; found {
			t.Fatalf("publication write tool exposed under scopes %+v", scopes)
		}
		if _, found := s.tools["reactor_get_artifact_publication"]; found {
			t.Fatalf("publication status tool exposed under scopes %+v", scopes)
		}
	}
	if !mcpToolMutates("reactor_publish_workflow_artifact") || !mcpToolMutates("reactor_requeue_artifact_publication") || mcpToolMutates("reactor_get_artifact_publication") {
		t.Fatal("publication tools have incorrect MCP audit classification")
	}
	s, _, _ := newTestServer(t, false)
	s.StateRoot = t.TempDir()
	s.Scopes = &WriteScopes{ArtifactPublication: true}
	s.registerTools()
	if _, err := s.tools["reactor_publish_workflow_artifact"].handler(context.Background(), json.RawMessage(`{}`)); err == nil || !strings.Contains(err.Error(), "authenticated administrator required") {
		t.Fatalf("unauthenticated publication request = %v", err)
	}
	if _, err := s.tools["reactor_get_artifact_publication"].handler(context.Background(), json.RawMessage(`{}`)); err == nil || !strings.Contains(err.Error(), "authenticated administrator required") {
		t.Fatalf("unauthenticated publication lookup = %v", err)
	}
	if _, err := s.tools["reactor_requeue_artifact_publication"].handler(context.Background(), json.RawMessage(`{}`)); err == nil || !strings.Contains(err.Error(), "authenticated administrator required") {
		t.Fatalf("unauthenticated publication requeue = %v", err)
	}
}

func TestArtifactPublicationMCPRequeuesOnlyTerminalTenantReceipt(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "publications.db")
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), "sqlite://"+dbPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	j := journal.New(db, journal.EngineSQLite)
	digest := strings.Repeat("a", 64)
	if err := j.CreateWorkflowInTenantWithArtifactDisabled(ctx, "wf_requeue_mcp", "requeue-workflow", "codehash", "0.1.0", digest, json.RawMessage(`{}`), journal.DefaultTenant, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	p, err := j.EnqueueArtifactPublication(ctx, journal.DefaultTenant, "wf_requeue_mcp", 1, digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE artifact_publications SET status = 'failed', attempts = 10, last_failure_code = 'copy_failed' WHERE id = ?`, p.ID); err != nil {
		t.Fatal(err)
	}
	s := &Server{Journal: j, StateRoot: t.TempDir(), Scopes: &WriteScopes{ArtifactPublication: true}, ArtifactPublicationAuthorized: func(context.Context) bool { return true }}
	args := map[string]any{"publication_id": p.ID, "confirm_publication_id": p.ID, "expected_artifact_sha256": digest}
	s.TenantID = "other-tenant"
	callOperationalTool(t, s, "reactor_requeue_artifact_publication", args, true)
	s.TenantID = journal.DefaultTenant
	out := callOperationalTool(t, s, "reactor_requeue_artifact_publication", args, false)
	var receipt map[string]any
	if err := json.Unmarshal(out, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt["publication_id"] != p.ID || receipt["status"] != journal.ArtifactPublicationPending || receipt["attempts"] != float64(0) || receipt["requeued"] != true {
		t.Fatalf("requeue response = %s", out)
	}
	callOperationalTool(t, s, "reactor_requeue_artifact_publication", args, true)
}
