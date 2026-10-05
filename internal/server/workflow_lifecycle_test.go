package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestDashboardEnableRejectsUnverifiedRetainedSource(t *testing.T) {
	ctx := context.Background()
	j := journalForServerTest(t)
	stateRoot := t.TempDir()
	if err := j.CreateWorkflowInTenantWithArtifactDisabled(ctx, "wf_legacy_enable", "legacy-enable", "", "0.1.0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", json.RawMessage(`{}`), journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	srv := &Server{Journal: j, Registry: registry.New(filepath.Join(stateRoot, "workflows")), State: stateRoot}
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/workflows/legacy-enable/enable", nil), "slug", "legacy-enable")
	rr := httptest.NewRecorder()
	srv.setWorkflowEnabled(rr, req, true)
	if rr.Code != http.StatusConflict {
		t.Fatalf("enable status = %d, want 409: %s", rr.Code, rr.Body.String())
	}
	enabled, err := j.IsWorkflowEnabled(ctx, "wf_legacy_enable")
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("unverified dashboard workflow was enabled")
	}
}

func TestDashboardEnableRequiresExactDistributedWorkerArtifact(t *testing.T) {
	ctx := context.Background()
	j := journalForServerTest(t)
	stateRoot, workerRoot := t.TempDir(), t.TempDir()
	const slug, workflowID = "dashboard-worker-proof", "wf_dashboard_worker_proof"
	const source = `package main
import (
  "context"
  reactor "github.com/bright-interaction/reactor/sdk"
)
func Run(ctx context.Context, flow reactor.Flow) error {
  _, err := reactor.Step(flow, ctx, "execute", reactor.StepOpts{}, func(context.Context) (int, error) { return 1, nil })
  return err
}`
	dag := json.RawMessage(`{"steps":[{"name":"execute","kind":"step"}]}`)
	reg := registry.New(filepath.Join(stateRoot, "workflows"))
	artifact, codeHash, manifestHash := publishVisualAcceptanceArtifact(t, reg, slug, source, dag, "v1")
	if err := j.CreateWorkflowInTenantWithArtifactDisabled(ctx, workflowID, slug, codeHash, "0.1.0", artifact, dag, journal.DefaultTenant, manifestHash); err != nil {
		t.Fatal(err)
	}
	srv := &Server{Journal: j, Registry: reg, State: stateRoot, WorkerArtifactRoot: workerRoot}
	request := func(action string) (*httptest.ResponseRecorder, *http.Request) {
		req := withChiParam(httptest.NewRequest(http.MethodPost, "/workflows/"+slug+"/"+action, nil), "slug", slug)
		return httptest.NewRecorder(), req
	}
	rr, req := request("enable")
	srv.setWorkflowEnabled(rr, req, true)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "distributed worker storage") {
		t.Fatalf("missing worker artifact enable = %d %q", rr.Code, rr.Body.String())
	}
	if enabled, err := j.IsWorkflowEnabled(ctx, workflowID); err != nil || enabled {
		t.Fatalf("missing worker artifact activated workflow: enabled=%t err=%v", enabled, err)
	}

	workerReg := registry.New(filepath.Join(workerRoot, "workflows"))
	workerArtifact, _, _ := publishVisualAcceptanceArtifact(t, workerReg, slug, source, dag, "v1")
	if workerArtifact != artifact {
		t.Fatalf("worker digest %q differs from reviewed artifact %q", workerArtifact, artifact)
	}
	rr, req = request("enable")
	srv.setWorkflowEnabled(rr, req, true)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("published worker artifact enable = %d %q", rr.Code, rr.Body.String())
	}
	if enabled, err := j.IsWorkflowEnabled(ctx, workflowID); err != nil || !enabled {
		t.Fatalf("published worker artifact not activated: enabled=%t err=%v", enabled, err)
	}

	rr, req = request("disable")
	srv.setWorkflowEnabled(rr, req, false)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("disable = %d %q", rr.Code, rr.Body.String())
	}
	workerBinary, err := workerReg.ArtifactPathForTenant(slug, artifact, journal.DefaultTenant)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(filepath.Dir(workerBinary), "source", registry.SourceManifestFilename)); err != nil {
		t.Fatal(err)
	}
	rr, req = request("enable")
	srv.setWorkflowEnabled(rr, req, true)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "distributed worker storage") {
		t.Fatalf("tampered worker artifact enable = %d %q", rr.Code, rr.Body.String())
	}
	if enabled, err := j.IsWorkflowEnabled(ctx, workflowID); err != nil || enabled {
		t.Fatalf("tampered worker artifact activated workflow: enabled=%t err=%v", enabled, err)
	}
}

func TestDashboardProofAndEnableErrorHideRetainedSourceRoot(t *testing.T) {
	ctx := context.Background()
	j := journalForServerTest(t)
	stateRoot := t.TempDir()
	reg := registry.New(filepath.Join(stateRoot, "workflows"))
	const slug = "malformed-dashboard-proof"
	binary := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(binary, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact(slug, binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.ClaimTenant(slug, journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	malformedSource := []byte("package main\nfunc broken( {\n")
	dag := []byte(`{"steps":[{"name":"execute","kind":"step"}]}`)
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"main.go": malformedSource, "dag.json": dag}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(sourceDir, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := registry.BuildSourceManifest(files, []string{"main.go"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, registry.SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	codeSum, manifestSum := sha256.Sum256(malformedSource), sha256.Sum256(manifest)
	const workflowID = "wf_malformed_dashboard_proof"
	if err := j.CreateWorkflowInTenantWithArtifactDisabled(ctx, workflowID, slug, hex.EncodeToString(codeSum[:])[:16], "0.1.0", artifact.Digest, json.RawMessage(dag), journal.DefaultTenant, hex.EncodeToString(manifestSum[:])); err != nil {
		t.Fatal(err)
	}
	version, err := j.CurrentWorkflowVersionRecord(ctx, workflowID)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{Journal: j, Registry: reg, State: stateRoot}
	_, status, reason := srv.workflowDetailProof(ctx, slug, journal.DefaultTenant, version)
	if status != "mismatch" || reason == "" || strings.Contains(reason, stateRoot) {
		t.Fatalf("dashboard source proof = %q %q", status, reason)
	}
	html := workflowDetailBody(workflowDetailData{Slug: slug, FlowProofStatus: status, FlowProofReason: reason})
	if strings.Contains(html, stateRoot) {
		t.Fatalf("dashboard rendered private source root: %s", html)
	}
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/workflows/"+slug+"/enable", nil), "slug", slug)
	rr := httptest.NewRecorder()
	srv.setWorkflowEnabled(rr, req, true)
	if rr.Code != http.StatusConflict || strings.Contains(rr.Body.String(), stateRoot) {
		t.Fatalf("enable refusal exposed source root: status=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestDashboardEnableRejectsVerifiedArtifactWithoutVisualNodes(t *testing.T) {
	ctx := context.Background()
	j := journalForServerTest(t)
	stateRoot := t.TempDir()
	reg := registry.New(filepath.Join(stateRoot, "workflows"))
	binary := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(binary, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("empty-dashboard-flow", binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.ClaimTenant("empty-dashboard-flow", journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mainGo := []byte("package main\nfunc main() {}\n")
	dag := []byte(`{}`)
	for name, contents := range map[string][]byte{"main.go": mainGo, "dag.json": dag} {
		if err := os.WriteFile(filepath.Join(sourceDir, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := registry.BuildSourceManifest(map[string][]byte{"main.go": mainGo, "dag.json": dag})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, registry.SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mainGo)
	codeHash := hex.EncodeToString(sum[:])[:16]
	manifestSum := sha256.Sum256(manifest)
	if err := j.CreateWorkflowInTenantWithArtifactDisabled(ctx, "wf_empty_dashboard_flow", "empty-dashboard-flow", codeHash, "0.1.0", artifact.Digest, json.RawMessage(dag), journal.DefaultTenant, hex.EncodeToString(manifestSum[:])); err != nil {
		t.Fatal(err)
	}
	srv := &Server{Journal: j, Registry: reg, State: stateRoot}
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/workflows/empty-dashboard-flow/enable", nil), "slug", "empty-dashboard-flow")
	rr := httptest.NewRecorder()
	srv.setWorkflowEnabled(rr, req, true)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "no executable nodes") || !strings.Contains(rr.Body.String(), "rebuild") {
		t.Fatalf("empty visual flow enable status=%d body=%q", rr.Code, rr.Body.String())
	}
	if enabled, err := j.IsWorkflowEnabled(ctx, "wf_empty_dashboard_flow"); err != nil || enabled {
		t.Fatalf("empty visual flow activated: enabled=%t err=%v", enabled, err)
	}
}

func TestDashboardEnableRejectsForeignTenantArtifactProof(t *testing.T) {
	ctx := context.Background()
	j := journalForServerTest(t)
	stateRoot := t.TempDir()
	reg := registry.New(filepath.Join(stateRoot, "workflows"))
	compiled := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(compiled, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("shared-enable", compiled)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.ClaimTenant("shared-enable", "acme"); err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mainGo := []byte("package main\nfunc main() {}\n")
	if err := os.WriteFile(filepath.Join(sourceDir, "main.go"), mainGo, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := registry.BuildSourceManifest(map[string][]byte{"main.go": mainGo})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, registry.SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mainGo)
	codeHash := hex.EncodeToString(sum[:])[:16]
	if err := j.CreateWorkflowInTenantWithArtifactDisabled(ctx, "wf_shared_enable", "shared-enable", codeHash, "0.1.0", artifact.Digest, json.RawMessage(`{}`), "globex"); err != nil {
		t.Fatal(err)
	}
	srv := &Server{Journal: j, Registry: reg, State: stateRoot}
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/workflows/shared-enable/enable?tenant=globex", nil), "slug", "shared-enable")
	rr := httptest.NewRecorder()
	srv.setWorkflowEnabled(rr, req, true)
	if rr.Code != http.StatusConflict {
		t.Fatalf("foreign artifact enable status = %d, want 409: %s", rr.Code, rr.Body.String())
	}
	enabled, err := j.IsWorkflowEnabled(ctx, "wf_shared_enable")
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("foreign tenant artifact proof enabled workflow")
	}
}
