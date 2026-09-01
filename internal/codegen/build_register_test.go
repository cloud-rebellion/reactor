package codegen

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeJournal stubs JournalForBuildRegister.
type fakeJournal struct {
	existingSlug     string
	existingID       string
	existingTenant   string
	createdID        string
	createdSlug      string
	createdHash      string
	createdSDK       string
	createdDAG       json.RawMessage
	createdTenant    string
	createdArtifact  string
	recordedID       string
	recordedArtifact string
	recordedVersion  int
	currentVersion   int
	currentArtifact  string
	createErr        error
}

func (f *fakeJournal) WorkflowIDBySlug(_ context.Context, slug string) (string, error) {
	if slug == f.existingSlug {
		return f.existingID, nil
	}
	return "", errors.New("not found")
}

// WorkflowIDBySlugInTenant models per-tenant slug uniqueness: the same slug in a
// DIFFERENT tenant must not resolve, which is what makes SkipIfExists correct.
func (f *fakeJournal) WorkflowIDBySlugInTenant(_ context.Context, slug, tenantID string) (string, error) {
	if slug == f.existingSlug && tenantID == f.existingTenant {
		return f.existingID, nil
	}
	return "", errors.New("not found")
}

func (f *fakeJournal) CreateWorkflow(ctx context.Context, id, slug, codeHash, sdkVersion string, dag json.RawMessage) error {
	return f.CreateWorkflowInTenant(ctx, id, slug, codeHash, sdkVersion, dag, "")
}

func (f *fakeJournal) CreateWorkflowInTenant(_ context.Context, id, slug, codeHash, sdkVersion string, dag json.RawMessage, tenantID string) error {
	return f.CreateWorkflowInTenantWithArtifact(context.Background(), id, slug, codeHash, sdkVersion, "", dag, tenantID)
}

func (f *fakeJournal) CreateWorkflowInTenantWithArtifact(_ context.Context, id, slug, codeHash, sdkVersion, artifactSHA256 string, dag json.RawMessage, tenantID string) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.createdID = id
	f.createdSlug = slug
	f.createdHash = codeHash
	f.createdSDK = sdkVersion
	f.createdDAG = dag
	f.createdTenant = tenantID
	f.createdArtifact = artifactSHA256
	f.currentVersion = 1
	f.currentArtifact = artifactSHA256
	return nil
}

func (f *fakeJournal) RecordWorkflowVersionWithArtifact(_ context.Context, workflowID, _ string, _ string, artifactSHA256 string, _ json.RawMessage) (int, error) {
	if f.createErr != nil {
		return 0, f.createErr
	}
	f.recordedID = workflowID
	f.recordedArtifact = artifactSHA256
	f.recordedVersion++
	f.currentVersion = f.recordedVersion + 1
	f.currentArtifact = artifactSHA256
	return f.currentVersion, nil
}

func (f *fakeJournal) ActivateWorkflowArtifactIfCurrent(_ context.Context, _ string, version int, artifactSHA256 string, activate func() error) (bool, error) {
	if version != f.currentVersion || artifactSHA256 != f.currentArtifact {
		return false, nil
	}
	if err := activate(); err != nil {
		return false, err
	}
	return true, nil
}

// writeMiniWorkflow produces a tiny compilable workflow source dir +
// optional dag.json so BuildAndRegister can run the real `go build`.
func writeMiniWorkflow(t *testing.T, withDAG bool) string {
	t.Helper()
	dir := t.TempDir()
	main := []byte("package main\n\nfunc main() {}\n")
	if err := os.WriteFile(filepath.Join(dir, "main.go"), main, 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	gomod := []byte("module tinywf\n\ngo 1.22\n")
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), gomod, 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if withDAG {
		dag := []byte(`{"slug":"x","version":"0.1.0","steps":[]}`)
		if err := os.WriteFile(filepath.Join(dir, "dag.json"), dag, 0o644); err != nil {
			t.Fatalf("write dag.json: %v", err)
		}
	}
	return dir
}

func TestBuildAndRegisterHappyPath(t *testing.T) {
	t.Parallel()
	src := writeMiniWorkflow(t, true)
	root := t.TempDir()
	j := &fakeJournal{}
	res, err := BuildAndRegister(context.Background(), j, BuildAndRegisterRequest{
		Slug:      "demo",
		SrcDir:    src,
		StateRoot: root,
	})
	if err != nil {
		t.Fatalf("BuildAndRegister: %v", err)
	}
	if res.WorkflowID == "" || res.BinaryPath == "" {
		t.Fatalf("incomplete result: %+v", res)
	}
	if _, err := os.Stat(res.BinaryPath); err != nil {
		t.Fatalf("binary not on disk: %v", err)
	}
	if j.createdSlug != "demo" || j.createdSDK != "0.1.0" {
		t.Fatalf("journal not called correctly: %+v", j)
	}
	if string(j.createdDAG) != `{"slug":"x","version":"0.1.0","steps":[]}` {
		t.Fatalf("dag not propagated: %s", j.createdDAG)
	}
	if len(j.createdHash) != 16 {
		t.Fatalf("code hash should be 16 hex chars; got %q", j.createdHash)
	}
	if len(j.createdArtifact) != 64 {
		t.Fatalf("artifact sha256 should be 64 lowercase hex chars; got %q", j.createdArtifact)
	}
}

func TestBuildAndRegisterRejectsBadSlug(t *testing.T) {
	t.Parallel()
	j := &fakeJournal{}
	for _, bad := range []string{"", "../escape", "UPPER", "1leading", "with space"} {
		_, err := BuildAndRegister(context.Background(), j, BuildAndRegisterRequest{
			Slug:      bad,
			SrcDir:    "/tmp/whatever",
			StateRoot: "/tmp/state",
		})
		if err == nil {
			t.Fatalf("slug %q should have been rejected", bad)
		}
	}
}

func TestBuildAndRegisterReusesExistingIDAndAppendsVersion(t *testing.T) {
	t.Parallel()
	src := writeMiniWorkflow(t, false)
	root := t.TempDir()
	j := &fakeJournal{
		existingSlug: "demo",
		existingID:   "wf_existing",
	}
	res, err := BuildAndRegister(context.Background(), j, BuildAndRegisterRequest{
		Slug:         "demo",
		SrcDir:       src,
		StateRoot:    root,
		SkipIfExists: true,
	})
	if err != nil {
		t.Fatalf("BuildAndRegister: %v", err)
	}
	if res.WorkflowID != "wf_existing" {
		t.Fatalf("WorkflowID = %s, want wf_existing", res.WorkflowID)
	}
	if j.createdID != "" {
		t.Fatalf("CreateWorkflow should not have been called; got %s", j.createdID)
	}
	if j.recordedID != "wf_existing" || len(j.recordedArtifact) != 64 {
		t.Fatalf("existing workflow version was not artifact-bound: %+v", j)
	}
}

func TestBuildAndRegisterSource(t *testing.T) {
	// Force the no-SDK-replace path so a stdlib-only workflow builds
	// deterministically regardless of the dev's shell env.
	t.Setenv("REACTOR_SDK_REPLACE", "")
	root := t.TempDir()
	j := &fakeJournal{}
	res, err := BuildAndRegisterSource(context.Background(), j, BuildSourceRequest{
		Slug:      "src-demo",
		MainGo:    "package main\n\nfunc main() {}\n",
		DAGJSON:   `{"steps":[]}`,
		StateRoot: root,
	})
	if err != nil {
		t.Fatalf("BuildAndRegisterSource: %v", err)
	}
	if res.WorkflowID == "" || res.BinaryPath == "" {
		t.Fatalf("incomplete result: %+v", res)
	}
	if _, err := os.Stat(res.BinaryPath); err != nil {
		t.Fatalf("compiled binary not on disk: %v", err)
	}
	if j.createdSlug != "src-demo" {
		t.Fatalf("journal slug = %q, want src-demo", j.createdSlug)
	}
	if string(j.createdDAG) != `{"steps":[]}` {
		t.Fatalf("dag not propagated: %s", j.createdDAG)
	}
	// The temp build dir must not leak into the workflows tree.
	if _, err := os.Stat(filepath.Join(root, "workflows", "src-demo", "main.go")); err == nil {
		t.Fatal("source main.go leaked into the workflows dir; expected build from a temp dir")
	}
}

func TestBuildAndRegisterSourceRejectsEmptyMain(t *testing.T) {
	t.Setenv("REACTOR_SDK_REPLACE", "")
	if _, err := BuildAndRegisterSource(context.Background(), &fakeJournal{}, BuildSourceRequest{
		Slug: "x", MainGo: "   ", StateRoot: t.TempDir(),
	}); err == nil {
		t.Fatal("empty main_go should be rejected")
	}
}

func TestBuildAndRegisterSourceRejectsBadSlug(t *testing.T) {
	t.Setenv("REACTOR_SDK_REPLACE", "")
	if _, err := BuildAndRegisterSource(context.Background(), &fakeJournal{}, BuildSourceRequest{
		Slug: "Bad Slug", MainGo: "package main\nfunc main(){}\n", StateRoot: t.TempDir(),
	}); err == nil {
		t.Fatal("invalid slug should be rejected")
	}
}

// TestBuildAndRegisterSkipsOnlyWithinTheSameTenant pins a bug found by uploading
// through a running dashboard, not by reading code. SkipIfExists checked the
// UNSCOPED resolver, so registering a slug into tenant B found tenant A's row,
// returned A's workflow id and wrote nothing: the upload reported success (303)
// while the workflow never existed in B. Slugs are unique PER TENANT, so "does
// some tenant own this slug" is the wrong question.
func TestBuildAndRegisterSkipsOnlyWithinTheSameTenant(t *testing.T) {
	t.Parallel()

	// Same tenant: the existing row is reused and nothing is rebuilt.
	sameTenant := &fakeJournal{existingSlug: "flow", existingID: "wf_existing", existingTenant: "acme"}
	res, err := BuildAndRegister(context.Background(), sameTenant, BuildAndRegisterRequest{
		Slug: "flow", SrcDir: writeMiniWorkflow(t, false), StateRoot: t.TempDir(),
		SkipIfExists: true, TenantID: "acme",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.WorkflowID != "wf_existing" {
		t.Fatalf("same-tenant re-register should reuse the row, got %q", res.WorkflowID)
	}
	if sameTenant.createdID != "" {
		t.Fatal("same-tenant re-register should not have created a second row")
	}

	// Different tenant: it must CREATE, not silently hand back the other
	// tenant's workflow.
	otherTenant := &fakeJournal{existingSlug: "flow", existingID: "wf_existing", existingTenant: "acme"}
	res, err = BuildAndRegister(context.Background(), otherTenant, BuildAndRegisterRequest{
		Slug: "flow", SrcDir: writeMiniWorkflow(t, false), StateRoot: t.TempDir(),
		SkipIfExists: true, TenantID: "globex",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.WorkflowID == "wf_existing" {
		t.Fatal("registering into a different tenant returned the OTHER tenant's workflow id")
	}
	if otherTenant.createdID == "" {
		t.Fatal("registering into a different tenant wrote no row, so the upload succeeded with nothing created")
	}
	if otherTenant.createdTenant != "globex" {
		t.Fatalf("row created in tenant %q, want globex", otherTenant.createdTenant)
	}
}

// TestCheckAllowedImportsSkipsAppleDoubleSidecars pins a defect that made the
// dashboard upload path unusable for every macOS operator. A plain `tar czf` on
// a Mac emits an AppleDouble `._main.go` sidecar next to each file; the walker
// matched it on the .go suffix and failed the whole upload with "illegal
// character NUL", surfacing only as an opaque 500. Go itself never compiles a
// file starting with "." or "_", so skipping matches the compiler's own rule.
func TestCheckAllowedImportsSkipsAppleDoubleSidecars(t *testing.T) {
	t.Parallel()
	dir := writeMiniWorkflow(t, false)
	// Byte-for-byte the shape that broke it: a NUL-prefixed binary blob.
	if err := os.WriteFile(filepath.Join(dir, "._main.go"), []byte{0x00, 0x05, 0x16, 0x07, 0x00}, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "_ignored.go"), []byte("this is not valid go either"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckAllowedImports(dir); err != nil {
		t.Fatalf("sidecar files the Go build ignores must not fail the scan: %v", err)
	}
}

// TestBuildAndRegisterRejectsVendorAndGoWork closes the other half of the
// supplied-module-graph hole. Regenerating go.mod is not enough on its own:
// Go auto-activates vendor mode from vendor/modules.txt, and a go.work
// overrides the module graph outright, so either one puts attacker code back
// into the build. The import-allowlist walker also deliberately skips vendor
// trees, so nothing would have scanned them.
func TestBuildAndRegisterRejectsVendorAndGoWork(t *testing.T) {
	t.Parallel()
	for _, banned := range []string{"vendor", "go.work", "go.work.sum"} {
		banned := banned
		t.Run(banned, func(t *testing.T) {
			t.Parallel()
			src := writeMiniWorkflow(t, false)
			path := filepath.Join(src, banned)
			if banned == "vendor" {
				if err := os.MkdirAll(path, 0o755); err != nil {
					t.Fatalf("mkdir vendor: %v", err)
				}
			} else if err := os.WriteFile(path, []byte("go 1.25\n"), 0o644); err != nil {
				t.Fatalf("write %s: %v", banned, err)
			}
			_, err := BuildAndRegister(context.Background(), &fakeJournal{}, BuildAndRegisterRequest{
				Slug: "demo", SrcDir: src, StateRoot: t.TempDir(),
			})
			if err == nil {
				t.Fatalf("%s in the source tree should be rejected", banned)
			}
			if !strings.Contains(err.Error(), banned) {
				t.Fatalf("error should name %q, got %v", banned, err)
			}
		})
	}
}

// TestBuildAndRegisterRegeneratesSuppliedGoMod pins the fix for the host-RCE
// path: the tarball-upload route used the caller's go.mod verbatim, so a
// `replace github.com/bright-interaction/reactor => ./evil` substituted
// attacker code for the SDK and ran it at build time as the daemon uid.
// initModule now runs on EVERY compile path, not just the MCP one.
func TestBuildAndRegisterRegeneratesSuppliedGoMod(t *testing.T) {
	t.Parallel()
	src := writeMiniWorkflow(t, false)
	hostile := "module tinywf\n\ngo 1.22\n\nreplace github.com/bright-interaction/reactor => ./evil\n"
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte(hostile), 0o644); err != nil {
		t.Fatalf("write hostile go.mod: %v", err)
	}
	if _, err := BuildAndRegister(context.Background(), &fakeJournal{}, BuildAndRegisterRequest{
		Slug: "hostile", SrcDir: src, StateRoot: t.TempDir(),
	}); err != nil {
		t.Fatalf("BuildAndRegister: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(src, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	if strings.Contains(string(got), "replace") {
		t.Fatalf("supplied replace directive survived:\n%s", got)
	}
	if !strings.Contains(string(got), "module reactor-workflow/hostile") {
		t.Fatalf("go.mod should be daemon-owned, got:\n%s", got)
	}
}
