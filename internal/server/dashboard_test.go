package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runlogs"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// stubValidator satisfies CodeValidator with a programmable result.
type stubValidator struct {
	calls int
	fail  error
}

func (s *stubValidator) Validate(_ context.Context, _, _, _, _ string) error {
	s.calls++
	return s.fail
}

// stubRegistrar satisfies WorkflowRegistrar and records rebuilds. Validation
// compiles in a throwaway temp dir, so a save that does not ALSO rebuild leaves
// the old binary serving every trigger; these counters are what pin that.
type stubRegistrar struct {
	calls           int
	expectedCalls   int
	expectedVersion int
	beforeExpected  func()
	slug            string
	dir             string
	tenantID        string
	fail            error
}

func (s *stubRegistrar) RegisterFromDir(_ context.Context, slug, dir, tenantID string) (string, error) {
	s.calls++
	s.slug, s.dir, s.tenantID = slug, dir, tenantID
	if s.fail != nil {
		return "", s.fail
	}
	return "wf_stub", nil
}

func (s *stubRegistrar) RegisterFromDirExpected(ctx context.Context, slug, dir, tenantID string, expectedVersion int) (string, error) {
	s.expectedCalls++
	s.expectedVersion = expectedVersion
	if s.beforeExpected != nil {
		s.beforeExpected()
	}
	return s.RegisterFromDir(ctx, slug, dir, tenantID)
}

type stubCommitter struct{ calls int }

func (s *stubCommitter) Commit(_ context.Context, _, _, _ string) error {
	s.calls++
	return nil
}

func TestRunTailReplaysClosedBufferAndReturns(t *testing.T) {
	t.Parallel()
	b := runlogs.New(10, time.Minute)
	b.Append("run-tail", "terminal line")
	b.Close("run-tail")
	srv := &Server{LogBuffer: b}
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/runs/run-tail/tail", nil), "id", "run-tail")
	rec := httptest.NewRecorder()
	srv.runTail(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got, want := rec.Body.String(), "data: terminal line\n\n"; got != want {
		t.Fatalf("SSE body = %q, want %q", got, want)
	}
}

func TestSaveCodeRejectsWhenValidatorFails(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "demo"), 0o700); err != nil {
		t.Fatal(err)
	}
	val := &stubValidator{fail: errors.New("go vet: undefined: foo")}
	srv := &Server{
		WorkflowsRoot: root,
		CodeValidator: val,
	}
	r := chi.NewRouter()
	r.Post("/workflows/{slug}/code", srv.workflowSaveCode)
	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, err := http.PostForm(ts.URL+"/workflows/demo/code", url.Values{"body": {"package main\n"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
	if val.calls != 1 {
		t.Fatalf("validator called %d times, want 1", val.calls)
	}
	// File must NOT have landed.
	if _, err := os.Stat(filepath.Join(root, "demo", "main.go")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("main.go should not exist after a failed validate")
	}
}

func TestSaveCodeWritesAndCommitsOnSuccess(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	val := &stubValidator{}
	com := &stubCommitter{}
	reg := &stubRegistrar{}
	srv := &Server{
		WorkflowsRoot:    root,
		CodeValidator:    val,
		CodeCommitter:    com,
		WorkflowRegister: reg,
	}
	r := chi.NewRouter()
	r.Post("/workflows/{slug}/code", srv.workflowSaveCode)
	ts := httptest.NewServer(r)
	defer ts.Close()

	body := "package main\n\nfunc main() {}\n"
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.PostForm(ts.URL+"/workflows/demo/code", url.Values{"body": {body}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	got, err := os.ReadFile(filepath.Join(root, "demo", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if string(got) != body {
		t.Fatalf("body mismatch:\n--got--\n%s\n--want--\n%s", got, body)
	}
	if com.calls != 1 {
		t.Fatalf("committer called %d times, want 1", com.calls)
	}
	if reg.calls != 1 {
		t.Fatalf("registrar called %d times, want 1: a save that does not rebuild leaves the old binary running", reg.calls)
	}
	if reg.slug != "demo" || reg.dir != filepath.Join(root, "demo") {
		t.Fatalf("rebuild targeted slug=%q dir=%q, want demo / %s", reg.slug, reg.dir, filepath.Join(root, "demo"))
	}
}

// TestSaveCodeRefusesWhenItCannotRebuild pins the trust property: a save that
// cannot recompile must not report success, because the drawer button says
// "Apply + rebuild" and the runtime execs the already-built binary.
func TestSaveCodeRefusesWhenItCannotRebuild(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	srv := &Server{
		WorkflowsRoot: root,
		CodeValidator: &stubValidator{},
		CodeCommitter: &stubCommitter{},
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		// WorkflowRegister deliberately nil.
	}
	r := chi.NewRouter()
	r.Post("/workflows/{slug}/code", srv.workflowSaveCode)
	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, err := ts.Client().PostForm(ts.URL+"/workflows/demo/code", url.Values{"body": {"package main\nfunc main(){}\n"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusOK {
		t.Fatalf("status = %d: a save that cannot rebuild must not report success", resp.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(root, "demo", "main.go")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source without a previous version must be removed after rebuild refusal; stat err=%v", err)
	}
}

func TestSaveCodeRemovesNewSourceWhenRebuildFails(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	srv := &Server{
		WorkflowsRoot:    root,
		CodeValidator:    &stubValidator{},
		WorkflowRegister: &stubRegistrar{fail: errors.New("go build: boom")},
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	r := chi.NewRouter()
	r.Post("/workflows/{slug}/code", srv.workflowSaveCode)
	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, err := ts.Client().PostForm(ts.URL+"/workflows/demo/code", url.Values{"body": {"package main\nfunc main(){}\n"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther {
		t.Fatalf("status = %d, want a failure when the rebuild fails", resp.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(root, "demo", "main.go")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new source must be removed after failed rebuild; stat err=%v", err)
	}
}

// TestSaveCodeRestoresSourceWhenRebuildFails keeps the on-disk source in step
// with the binary that is actually running.
func TestSaveCodeRestoresSourceWhenRebuildFails(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "demo")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	original := "package main\n\n// ORIGINAL\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		WorkflowsRoot:    root,
		CodeValidator:    &stubValidator{},
		CodeCommitter:    &stubCommitter{},
		WorkflowRegister: &stubRegistrar{fail: errors.New("go build: boom")},
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	r := chi.NewRouter()
	r.Post("/workflows/{slug}/code", srv.workflowSaveCode)
	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, err := ts.Client().PostForm(ts.URL+"/workflows/demo/code", url.Values{"body": {"package main\n\n// REPLACEMENT\nfunc main() {}\n"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther {
		t.Fatalf("status = %d, want a failure when the rebuild fails", resp.StatusCode)
	}
	got, err := os.ReadFile(filepath.Join(dir, "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("source should be rolled back to the version that matches the running binary, got:\n%s", got)
	}
	// The staging file must not be left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "stage") || strings.HasSuffix(e.Name(), ".new") {
			t.Fatalf("staging file %q left behind", e.Name())
		}
	}
}

func TestSaveDAGRejectsBadSchema(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	srv := &Server{WorkflowsRoot: root}
	r := chi.NewRouter()
	r.Post("/workflows/{slug}/dag", srv.workflowSaveDAG)
	ts := httptest.NewServer(r)
	defer ts.Close()

	bad := `{"slug":"../escape","version":"0.1.0","steps":[]}`
	resp, err := http.Post(ts.URL+"/workflows/escape/dag", "application/json", strings.NewReader(bad))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
}

func TestSaveDAGAcceptsCanonicalShape(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	srv := &Server{WorkflowsRoot: root}
	r := chi.NewRouter()
	r.Post("/workflows/{slug}/dag", srv.workflowSaveDAG)
	ts := httptest.NewServer(r)
	defer ts.Close()

	good := `{"slug":"demo","version":"0.1.0","steps":[{"name":"a","kind":"step"}]}`
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Post(ts.URL+"/workflows/demo/dag", "application/json", strings.NewReader(good))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	got, err := os.ReadFile(filepath.Join(root, "demo", "dag.json"))
	if err != nil {
		t.Fatalf("read dag.json: %v", err)
	}
	if string(got) != good {
		t.Fatalf("body mismatch")
	}
}

func TestSaveDAGRebuildsRegisteredWorkflow(t *testing.T) {
	t.Parallel()
	j := journalForServerTest(t)
	ctx := context.Background()
	root := t.TempDir()
	fileReg := registry.New(root)
	compiled := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(compiled, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := fileReg.PublishArtifact("demo", compiled)
	if err != nil {
		t.Fatal(err)
	}
	if err := fileReg.ClaimTenant("demo", journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldDAG := `{"steps":[{"name":"old","kind":"step"}]}`
	if err := os.WriteFile(filepath.Join(sourceDir, "dag.json"), []byte(oldDAG), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := registry.BuildSourceManifest(map[string][]byte{
		"main.go":  []byte("package main\nfunc main() {}\n"),
		"dag.json": []byte(oldDAG),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, registry.SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_demo", "demo", "h", "0.1.0", artifact.Digest, json.RawMessage(oldDAG), "default"); err != nil {
		t.Fatal(err)
	}
	reg := &stubRegistrar{}
	srv := &Server{Journal: j, WorkflowsRoot: root, WorkflowRegister: reg}
	good := `{"steps":[{"name":"new","kind":"step"}]}`
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/workflows/demo/dag", strings.NewReader(good)), "slug", "demo")
	rr := httptest.NewRecorder()
	srv.workflowSaveDAG(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303: %s", rr.Code, rr.Body.String())
	}
	if reg.calls != 1 || reg.tenantID != "default" {
		t.Fatalf("rebuild = calls %d tenant %q, want one default-tenant rebuild", reg.calls, reg.tenantID)
	}
	if reg.expectedCalls != 1 || reg.expectedVersion != 1 {
		t.Fatalf("revision fence = calls %d version %d, want one call at version 1", reg.expectedCalls, reg.expectedVersion)
	}
	got, err := os.ReadFile(filepath.Join(root, ".editor", "wf_demo", "dag.json"))
	if err != nil || string(got) != good {
		t.Fatalf("saved DAG = %q, %v; want %q", got, err, good)
	}
}

func TestSaveDAGRestoresOnRebuildFailureAndUsesTenantSelector(t *testing.T) {
	t.Parallel()
	j := journalForServerTest(t)
	ctx := context.Background()
	root := t.TempDir()
	fileReg := registry.New(root)
	compiled := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(compiled, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := fileReg.PublishArtifact("shared", compiled)
	if err != nil {
		t.Fatal(err)
	}
	if err := fileReg.ClaimTenant("shared", "acme"); err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldDAG := `{"steps":[{"name":"old","kind":"step"}]}`
	if err := os.WriteFile(filepath.Join(sourceDir, "dag.json"), []byte(oldDAG), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_acme", "shared", "h", "0.1.0", artifact.Digest, json.RawMessage(oldDAG), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_globex", "shared", "h", "0.1.0", artifact.Digest, json.RawMessage(oldDAG), "globex"); err != nil {
		t.Fatal(err)
	}
	reg := &stubRegistrar{fail: errors.New("build failed")}
	srv := &Server{Journal: j, WorkflowsRoot: root, WorkflowRegister: reg}
	newDAG := `{"steps":[{"name":"new","kind":"step"}]}`
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/workflows/shared/dag?tenant=acme", strings.NewReader(newDAG)), "slug", "shared")
	rr := httptest.NewRecorder()
	srv.workflowSaveDAG(rr, req)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422: %s", rr.Code, rr.Body.String())
	}
	if reg.calls != 1 || reg.tenantID != "acme" {
		t.Fatalf("rebuild = calls %d tenant %q, want acme-scoped rebuild", reg.calls, reg.tenantID)
	}
	if reg.expectedCalls != 1 || reg.expectedVersion != 1 {
		t.Fatalf("revision fence = calls %d version %d, want one call at version 1", reg.expectedCalls, reg.expectedVersion)
	}
	got, err := os.ReadFile(filepath.Join(root, ".editor", "wf_acme", "dag.json"))
	if err != nil || string(got) != oldDAG {
		t.Fatalf("DAG after failed rebuild = %q, %v; want original %q", got, err, oldDAG)
	}
}

func TestSaveCodeRejectsConcurrentRevisionAfterBaseline(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j := journalForServerTest(t)
	root := t.TempDir()
	fileReg := registry.New(root)
	compiled := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(compiled, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := fileReg.PublishArtifact("demo", compiled)
	if err != nil {
		t.Fatal(err)
	}
	if err := fileReg.ClaimTenant("demo", journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	original := "package main\nfunc main() {}\n"
	oldDAG := `{"steps":[]}`
	if err := os.WriteFile(filepath.Join(sourceDir, "main.go"), []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "dag.json"), []byte(oldDAG), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := registry.BuildSourceManifest(map[string][]byte{
		"main.go":  []byte("package main\nfunc main() {}\n"),
		"dag.json": []byte(oldDAG),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, registry.SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_demo", "demo", "h1", "0.1.0", artifact.Digest, json.RawMessage(oldDAG), "default"); err != nil {
		t.Fatal(err)
	}
	reg := &stubRegistrar{}
	reg.beforeExpected = func() {
		if _, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_demo", "0.1.0", "h2", artifact.Digest, json.RawMessage(oldDAG)); err != nil {
			t.Fatalf("concurrent revision: %v", err)
		}
		reg.fail = fmt.Errorf("%w: concurrent revision", journal.ErrWorkflowVersionConflict)
	}
	srv := &Server{
		Journal:          j,
		WorkflowsRoot:    root,
		Registry:         fileReg,
		CodeValidator:    &stubValidator{},
		WorkflowRegister: reg,
	}
	replacement := "package main\nfunc main() { println(2) }\n"
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/workflows/demo/code", strings.NewReader(replacement)), "slug", "demo")
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	srv.workflowSaveCode(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rr.Code, rr.Body.String())
	}
	if reg.expectedCalls != 1 || reg.expectedVersion != 1 {
		t.Fatalf("revision fence = calls %d version %d, want one call at version 1", reg.expectedCalls, reg.expectedVersion)
	}
	got, err := os.ReadFile(filepath.Join(root, ".editor", "wf_demo", "main.go"))
	if err != nil || string(got) != original {
		t.Fatalf("source after rejected concurrent save = %q, %v; want original %q", got, err, original)
	}
	current, err := j.CurrentWorkflowVersionRecord(ctx, "wf_demo")
	if err != nil || current.Version != 2 {
		t.Fatalf("current version after rejected concurrent save = %+v, %v; want concurrent version 2", current, err)
	}
}

func TestWorkflowEditVersionHonorsSubmittedBaseline(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j := journalForServerTest(t)
	digest := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_editor_form", "editor-form", "h1", "0.1.0", digest, json.RawMessage(`{"steps":[]}`), "default"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_editor_form", "0.1.0", "h2", digest, json.RawMessage(`{"steps":[]}`)); err != nil {
		t.Fatal(err)
	}
	srv := &Server{Journal: j}
	stale := httptest.NewRequest(http.MethodPost, "/workflows/editor-form/code?expected_version=1", strings.NewReader("package main\n"))
	expected, err := srv.workflowEditVersion(ctx, stale, "editor-form", "default")
	if err != nil || expected != 1 {
		t.Fatalf("submitted baseline = %d, err=%v; want 1", expected, err)
	}
	invalid := httptest.NewRequest(http.MethodPost, "/workflows/editor-form/code?expected_version=0", nil)
	if _, err := srv.workflowEditVersion(ctx, invalid, "editor-form", "default"); !errors.Is(err, errWorkflowExpectedVersionInvalid) {
		t.Fatalf("invalid submitted baseline error = %v, want errWorkflowExpectedVersionInvalid", err)
	}
}

func TestWorkflowSourceDirMaterializesTenantSpecificArtifactSnapshot(t *testing.T) {
	t.Parallel()
	j := journalForServerTest(t)
	ctx := context.Background()
	root := t.TempDir()
	reg := registry.New(root)
	compiled := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(compiled, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("shared", compiled)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.ClaimTenant("shared", "acme"); err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	main := "package main\nfunc main() {}\n"
	helper := "package main\nfunc helper() {}\n"
	if err := os.WriteFile(filepath.Join(sourceDir, "main.go"), []byte(main), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "helper.go"), []byte(helper), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "dag.json"), []byte(`{"steps":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := registry.BuildSourceManifest(map[string][]byte{
		"main.go": []byte(main), "helper.go": []byte(helper), "dag.json": []byte(`{"steps":[]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, registry.SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_acme", "shared", "h", "0.1.0", artifact.Digest, json.RawMessage(`{"steps":[]}`), "acme"); err != nil {
		t.Fatal(err)
	}
	srv := &Server{Journal: j, WorkflowsRoot: root, Registry: reg}
	dir, err := srv.workflowSourceDir(ctx, "shared", "acme")
	if err != nil {
		t.Fatal(err)
	}
	wantDir := filepath.Join(root, ".editor", "wf_acme")
	if dir != wantDir {
		t.Fatalf("source dir = %q, want workflow-isolated %q", dir, wantDir)
	}
	got, err := os.ReadFile(filepath.Join(dir, "main.go"))
	if err != nil || string(got) != main {
		t.Fatalf("materialized source = %q, %v", got, err)
	}
	gotHelper, err := os.ReadFile(filepath.Join(dir, "helper.go"))
	if err != nil || string(gotHelper) != helper {
		t.Fatalf("materialized helper = %q, %v", gotHelper, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "helper.go"), []byte("package main\nfunc helper() { println(9) }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.workflowSourceDir(ctx, "shared", "acme"); err != nil {
		t.Fatalf("workspace helper tamper should be repaired from artifact: %v", err)
	}
	gotHelper, err = os.ReadFile(filepath.Join(dir, "helper.go"))
	if err != nil || string(gotHelper) != helper {
		t.Fatalf("workspace helper tamper survived refresh = %q, %v", gotHelper, err)
	}
	compiled2 := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(compiled2, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact2, err := reg.PublishArtifact("shared", compiled2)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.ClaimTenant("shared", "acme"); err != nil {
		t.Fatal(err)
	}
	sourceDir2 := filepath.Join(filepath.Dir(artifact2.Path), "source")
	if err := os.MkdirAll(sourceDir2, 0o700); err != nil {
		t.Fatal(err)
	}
	main2 := "package main\nfunc main() { println(2) }\n"
	if err := os.WriteFile(filepath.Join(sourceDir2, "main.go"), []byte(main2), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir2, "dag.json"), []byte(`{"steps":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_acme", "0.1.0", "h2", artifact2.Digest, json.RawMessage(`{"steps":[]}`)); err != nil {
		t.Fatal(err)
	}
	dir, err = srv.workflowSourceDir(ctx, "shared", "acme")
	if err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(filepath.Join(dir, "main.go"))
	if err != nil || string(got) != main2 {
		t.Fatalf("workspace did not refresh to current artifact = %q, %v", got, err)
	}
}

func TestWorkflowSourceDirRejectsLegacyOrUnverifiableSource(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	j := journalForServerTest(t)
	legacy := filepath.Join(root, "legacy")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "main.go"), []byte("package main\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflow(ctx, "wf_legacy", "legacy", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	srv := &Server{Journal: j, WorkflowsRoot: root}
	if _, err := srv.workflowSourceDir(ctx, "legacy", "default"); !errors.Is(err, errWorkflowSourceUnavailable) {
		t.Fatalf("legacy source error = %v, want source-unavailable fence", err)
	}

	missing := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_missing", "missing", "h", "0.1.0", missing, json.RawMessage(`{}`), "default"); err != nil {
		t.Fatal(err)
	}
	missingDir := filepath.Join(root, "missing")
	if err := os.MkdirAll(missingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(missingDir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.workflowSourceDir(ctx, "missing", "default"); !errors.Is(err, errWorkflowSourceUnavailable) {
		t.Fatalf("missing artifact error = %v, want source-unavailable fence", err)
	}
}

func TestWorkflowSourceDirRechecksArtifactBeforeUsingWorkspaceMarker(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	reg := registry.New(root)
	compiled := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(compiled, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("tamper", compiled)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.ClaimTenant("tamper", journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "dag.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	j := journalForServerTest(t)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_tamper", "tamper", "h", "0.1.0", artifact.Digest, json.RawMessage(`{}`), "default"); err != nil {
		t.Fatal(err)
	}
	srv := &Server{Journal: j, WorkflowsRoot: root, Registry: reg}
	if _, err := srv.workflowSourceDir(ctx, "tamper", "default"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(artifact.Path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact.Path, []byte("tampered"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.workflowSourceDir(ctx, "tamper", "default"); !errors.Is(err, errWorkflowSourceUnavailable) {
		t.Fatalf("tampered current artifact error = %v, want source-unavailable fence", err)
	}
}

func TestSaveCodeOversizeReturns413(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	srv := &Server{WorkflowsRoot: root, CodeValidator: &stubValidator{}}
	r := chi.NewRouter()
	r.Post("/workflows/{slug}/code", srv.workflowSaveCode)
	ts := httptest.NewServer(r)
	defer ts.Close()

	big := strings.Repeat("x", 2<<20) // 2 MiB > 1 MiB cap
	resp, err := http.Post(ts.URL+"/workflows/demo/code", "application/octet-stream", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

// _ keeps registry imported in case the test file later uses it directly.
var _ = registry.ValidateDAG
