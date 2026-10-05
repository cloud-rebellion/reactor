package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

const nodeEditSrc = `package main

import (
	"context"

	"reactor"
)

func Run(ctx context.Context, flow reactor.Flow, in struct{}) error {
	customer, err := reactor.Step(flow, ctx, "fetch-customer", reactor.StepOpts{
		TimeoutSeconds: 30,
	}, func(ctx context.Context) (string, error) {
		return "ada@example.com", nil
	})
	if err != nil {
		return err
	}
	_ = customer
	return nil
}
`

func seedWorkflow(t *testing.T, root, slug, src string) {
	t.Helper()
	dir := filepath.Join(root, slug)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
}

func nodeRouter(srv *Server) *chi.Mux {
	r := chi.NewRouter()
	r.Get("/workflows/{slug}/node/{step}/code", srv.workflowNodeCode)
	r.Post("/workflows/{slug}/node/{step}/code", srv.workflowSaveNodeCode)
	return r
}

func TestNodeCodeGetReturnsSnippet(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	seedWorkflow(t, root, "demo", nodeEditSrc)
	srv := &Server{WorkflowsRoot: root, CodeValidator: &stubValidator{}}
	ts := httptest.NewServer(nodeRouter(srv))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/workflows/demo/node/fetch-customer/code")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out struct {
		Step     string `json:"step"`
		Code     string `json:"code"`
		Editable bool   `json:"editable"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Code, `reactor.Step(flow, ctx, "fetch-customer"`) {
		t.Fatalf("snippet missing the step call:\n%s", out.Code)
	}
	if strings.Contains(out.Code, "func Run") {
		t.Fatalf("snippet leaked the whole function:\n%s", out.Code)
	}
	if !out.Editable {
		t.Fatal("editable should be true when a validator is wired")
	}
}

func TestNodeCodeGetUnknownStep404(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	seedWorkflow(t, root, "demo", nodeEditSrc)
	srv := &Server{WorkflowsRoot: root, CodeValidator: &stubValidator{}}
	ts := httptest.NewServer(nodeRouter(srv))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/workflows/demo/node/does-not-exist/code")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestNodeCodeGetRejectsOversizedSource(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	seedWorkflow(t, root, "oversized", strings.Repeat("x", maxFlowSourceBytes+1))
	srv := &Server{WorkflowsRoot: root, CodeValidator: &stubValidator{}}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/workflows/oversized/node/step/code", nil)
	nodeRouter(srv).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), strings.Repeat("x", 64)) {
		t.Fatalf("oversized source bytes leaked in response: %s", recorder.Body.String())
	}
}

func TestNodeCodeSaveSplicesAndWrites(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	seedWorkflow(t, root, "demo", nodeEditSrc)
	val := &stubValidator{}
	com := &stubCommitter{}
	srv := &Server{WorkflowsRoot: root, CodeValidator: val, CodeCommitter: com, WorkflowRegister: &stubRegistrar{}}
	ts := httptest.NewServer(nodeRouter(srv))
	defer ts.Close()

	edited := `customer, err := reactor.Step(flow, ctx, "fetch-customer", reactor.StepOpts{
		TimeoutSeconds: 90,
	}, func(ctx context.Context) (string, error) {
		return "grace@example.com", nil
	})`
	resp, err := http.PostForm(ts.URL+"/workflows/demo/node/fetch-customer/code", url.Values{"body": {edited}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if val.calls != 1 {
		t.Fatalf("validator called %d times, want 1", val.calls)
	}
	got, err := os.ReadFile(filepath.Join(root, "demo", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(got)
	if !strings.Contains(src, "TimeoutSeconds: 90") || !strings.Contains(src, "grace@example.com") {
		t.Fatalf("edit not written to disk:\n%s", src)
	}
	if strings.Contains(src, "ada@example.com") {
		t.Fatalf("old node code still present:\n%s", src)
	}
	// The rest of the file (imports, func Run, error handling) must survive.
	if !strings.Contains(src, "func Run(") || !strings.Contains(src, "_ = customer") {
		t.Fatalf("splice damaged the surrounding file:\n%s", src)
	}
	if com.calls != 1 {
		t.Fatalf("committer called %d times, want 1", com.calls)
	}
}

func TestNodeCodeSaveRejectsBadEdit(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	seedWorkflow(t, root, "demo", nodeEditSrc)
	val := &stubValidator{fail: errors.New("go build: syntax error")}
	srv := &Server{WorkflowsRoot: root, CodeValidator: val}
	ts := httptest.NewServer(nodeRouter(srv))
	defer ts.Close()

	resp, err := http.PostForm(ts.URL+"/workflows/demo/node/fetch-customer/code", url.Values{"body": {"customer, err := boom("}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
	// Original file must be untouched.
	got, _ := os.ReadFile(filepath.Join(root, "demo", "main.go"))
	if !strings.Contains(string(got), "ada@example.com") {
		t.Fatalf("a rejected edit must not change the file:\n%s", got)
	}
}
