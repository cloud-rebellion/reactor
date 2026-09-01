package mcp

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	_ "modernc.org/sqlite"
)

// newTestServer wires real journal + credentials repos against a fresh
// sqlite DB so every test exercises the production query paths.
func newTestServer(t *testing.T, withDispatch bool) (*Server, *journal.Journal, *credentials.Repo) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "m.db")
	url := "sqlite://" + dbPath
	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(context.Background(), silent, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	j := journal.New(db, journal.EngineSQLite)
	cred := credentials.New(db, credentials.EngineSQLite)

	s := &Server{
		Info:        ServerInfo{Name: "reactor-test", Version: "0.0.0"},
		Journal:     j,
		Credentials: cred,
		Log:         silent,
	}
	if withDispatch {
		s.Dispatch = func(_ context.Context, slug string, _ json.RawMessage) (string, error) {
			return "run_dispatched_for_" + slug, nil
		}
	}
	return s, j, cred
}

// roundtrip drives one Serve loop with a list of requests; collects
// the responses. Closes stdin when requests are exhausted so Serve
// returns normally.
func roundtrip(t *testing.T, srv *Server, requests []rpcRequest) []rpcResponse {
	return roundtripT(t, srv, requests, 2*time.Second)
}

// roundtripT is roundtrip with an explicit wait budget, for tools that run a
// real `go build` (the authoring tool) and need more than the 2s default.
func roundtripT(t *testing.T, srv *Server, requests []rpcRequest, wait time.Duration) []rpcResponse {
	t.Helper()
	var buf bytes.Buffer
	for _, req := range requests {
		req.JSONRPC = "2.0"
		raw, _ := json.Marshal(req)
		buf.Write(raw)
		buf.WriteByte('\n')
	}
	out := &syncBuffer{}
	ctx, cancel := context.WithTimeout(context.Background(), wait+3*time.Second)
	defer cancel()
	go func() {
		_ = srv.Serve(ctx, &buf, out)
	}()
	deadline := time.Now().Add(wait)
	wantCount := 0
	for _, r := range requests {
		if r.ID != nil {
			wantCount++
		}
	}
	for time.Now().Before(deadline) {
		if out.lines() >= wantCount {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	dec := json.NewDecoder(out.reader())
	var resps []rpcResponse
	for dec.More() {
		var r rpcResponse
		if err := dec.Decode(&r); err != nil {
			break
		}
		resps = append(resps, r)
	}
	return resps
}

func TestInitialize(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, false)
	resps := roundtrip(t, srv, []rpcRequest{
		{ID: json.RawMessage(`1`), Method: "initialize"},
	})
	if len(resps) != 1 {
		t.Fatalf("got %d responses, want 1", len(resps))
	}
	if resps[0].Error != nil {
		t.Fatalf("initialize errored: %+v", resps[0].Error)
	}
	body, _ := json.Marshal(resps[0].Result)
	if !strings.Contains(string(body), ProtocolVersion) {
		t.Fatalf("expected protocol version in response: %s", body)
	}
	if !strings.Contains(string(body), `"name":"reactor-test"`) {
		t.Fatalf("expected serverInfo.name: %s", body)
	}
}

func TestToolsListReadOnly(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, false)
	resps := roundtrip(t, srv, []rpcRequest{
		{ID: json.RawMessage(`1`), Method: "tools/list"},
	})
	body, _ := json.Marshal(resps[0].Result)
	for _, want := range []string{
		"reactor_list_workflows",
		"reactor_list_runs",
		"reactor_get_run",
		"reactor_list_credentials",
		"reactor_get_credential_audit",
	} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("read tool %q missing from tools/list: %s", want, body)
		}
	}
	if strings.Contains(string(body), "reactor_dispatch_workflow") {
		t.Fatal("dispatch_workflow must NOT be advertised when Dispatch is nil")
	}
}

func TestToolsListWithDispatch(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, true)
	resps := roundtrip(t, srv, []rpcRequest{
		{ID: json.RawMessage(`1`), Method: "tools/list"},
	})
	body, _ := json.Marshal(resps[0].Result)
	for _, want := range []string{
		"reactor_dispatch_workflow",
		"reactor_register_workflow",
		"reactor_grant_secret",
		"reactor_revoke_secret",
	} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("write tool %q missing when Dispatch is set: %s", want, body)
		}
	}
}

// TestRegisterAndGrantWorkflowRoundTrip exercises the new authoring
// tools end-to-end: register a workflow, grant a secret, revoke it.
func TestRegisterAndGrantWorkflowRoundTrip(t *testing.T) {
	t.Parallel()
	srv, j, cred := newTestServer(t, true)
	ctx := context.Background()

	if err := cred.Create(ctx, credentials.CreateParams{
		ID: "cred_demo", Name: "demo", Service: "x", Provider: "shared-secret",
	}); err != nil {
		t.Fatal(err)
	}

	regArgs, _ := json.Marshal(map[string]any{
		"name":      "reactor_register_workflow",
		"arguments": map[string]any{"slug": "demo-author", "sdk_version": "0.2.0"},
	})
	resps := roundtrip(t, srv, []rpcRequest{
		{ID: json.RawMessage(`1`), Method: "tools/call", Params: regArgs},
	})
	if resps[0].Error != nil {
		t.Fatalf("register: %+v", resps[0].Error)
	}
	body, _ := json.Marshal(resps[0].Result)
	if !strings.Contains(string(body), `\"created\":true`) {
		t.Fatalf("expected created=true: %s", body)
	}

	id, err := j.WorkflowIDBySlug(ctx, "demo-author")
	if err != nil {
		t.Fatalf("workflow not in db: %v", err)
	}

	// Re-registering the same slug must be idempotent (created=false).
	resps2 := roundtrip(t, srv, []rpcRequest{
		{ID: json.RawMessage(`2`), Method: "tools/call", Params: regArgs},
	})
	body2, _ := json.Marshal(resps2[0].Result)
	if !strings.Contains(string(body2), `\"created\":false`) {
		t.Fatalf("re-register expected created=false: %s", body2)
	}

	grantArgs, _ := json.Marshal(map[string]any{
		"name":      "reactor_grant_secret",
		"arguments": map[string]any{"workflow_id": id, "credential_id": "cred_demo"},
	})
	resps3 := roundtrip(t, srv, []rpcRequest{
		{ID: json.RawMessage(`3`), Method: "tools/call", Params: grantArgs},
	})
	if resps3[0].Error != nil {
		t.Fatalf("grant: %+v", resps3[0].Error)
	}
	if ok, _ := j.HasGrant(ctx, id, "cred_demo"); !ok {
		t.Fatal("HasGrant returned false after grant_secret")
	}

	revokeArgs, _ := json.Marshal(map[string]any{
		"name":      "reactor_revoke_secret",
		"arguments": map[string]any{"workflow_id": id, "credential_id": "cred_demo"},
	})
	resps4 := roundtrip(t, srv, []rpcRequest{
		{ID: json.RawMessage(`4`), Method: "tools/call", Params: revokeArgs},
	})
	if resps4[0].Error != nil {
		t.Fatalf("revoke: %+v", resps4[0].Error)
	}
	// HasGrant returns ErrACLEmpty once the table is empty; treat both
	// "no grant" + "table empty" as success here.
	ok, _ := j.HasGrant(ctx, id, "cred_demo")
	if ok {
		t.Fatal("grant still present after revoke")
	}
}

func TestToolsCallListWorkflows(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	if err := j.CreateWorkflow(context.Background(), "wf_demo", "demo", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}

	args, _ := json.Marshal(map[string]any{
		"name":      "reactor_list_workflows",
		"arguments": map[string]any{},
	})
	resps := roundtrip(t, srv, []rpcRequest{
		{ID: json.RawMessage(`1`), Method: "tools/call", Params: args},
	})
	if len(resps) != 1 || resps[0].Error != nil {
		t.Fatalf("tools/call errored: %+v", resps)
	}
	// MCP wraps tool results as {"content":[{"type":"text","text":"<json>"}]}
	// where <json> is the raw payload encoded as a string, so the inner
	// quotes are backslash-escaped in the outer marshalled body.
	body, _ := json.Marshal(resps[0].Result)
	if !strings.Contains(string(body), `\"slug\":\"demo\"`) {
		t.Fatalf("expected slug in response: %s", body)
	}
}

func TestToolsCallGetRun(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	ctx := context.Background()
	_ = j.CreateWorkflow(ctx, "wf_x", "x", "h", "0.1.0", json.RawMessage(`{}`))
	_ = j.CreateRun(ctx, "run_x", "wf_x", "manual", json.RawMessage(`{}`))
	_, _ = j.RecordStepStart(ctx, "run_x", "do-thing", 1, "k", "h")
	_ = j.RecordStepEnd(ctx, "run_x", "do-thing", 1, json.RawMessage(`"ok"`), "")

	args, _ := json.Marshal(map[string]any{
		"name":      "reactor_get_run",
		"arguments": map[string]any{"run_id": "run_x"},
	})
	resps := roundtrip(t, srv, []rpcRequest{
		{ID: json.RawMessage(`1`), Method: "tools/call", Params: args},
	})
	// Result is wrapped as {"content":[{"type":"text","text":"<json>"}]}.
	body, _ := json.Marshal(resps[0].Result)
	if !strings.Contains(string(body), `\"step_name\":\"do-thing\"`) {
		t.Fatalf("expected step in response: %s", body)
	}
}

func TestToolsCallMissingArgsErrors(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, false)
	args, _ := json.Marshal(map[string]any{
		"name":      "reactor_get_run",
		"arguments": map[string]any{}, // missing run_id
	})
	resps := roundtrip(t, srv, []rpcRequest{
		{ID: json.RawMessage(`1`), Method: "tools/call", Params: args},
	})
	body, _ := json.Marshal(resps[0].Result)
	// Per MCP spec: tool errors return isError=true in the result, NOT
	// at the JSON-RPC error level.
	if !strings.Contains(string(body), `"isError":true`) {
		t.Fatalf("expected isError=true: %s", body)
	}
	if !strings.Contains(string(body), "run_id required") {
		t.Fatalf("expected validation error message: %s", body)
	}
}

func TestUnknownToolErrors(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, false)
	args, _ := json.Marshal(map[string]any{
		"name":      "reactor_nope",
		"arguments": map[string]any{},
	})
	resps := roundtrip(t, srv, []rpcRequest{
		{ID: json.RawMessage(`1`), Method: "tools/call", Params: args},
	})
	if resps[0].Error == nil || resps[0].Error.Code != errMethodNotFound {
		t.Fatalf("expected method-not-found: %+v", resps[0].Error)
	}
}

func TestDispatchWorkflowGoesThroughClosure(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, true)
	args, _ := json.Marshal(map[string]any{
		"name": "reactor_dispatch_workflow",
		"arguments": map[string]any{
			"slug":    "demo",
			"payload": map[string]any{"hello": "world"},
		},
	})
	resps := roundtrip(t, srv, []rpcRequest{
		{ID: json.RawMessage(`1`), Method: "tools/call", Params: args},
	})
	body, _ := json.Marshal(resps[0].Result)
	if !strings.Contains(string(body), "run_dispatched_for_demo") {
		t.Fatalf("expected dispatched run id in response: %s", body)
	}
}

func TestUnknownMethodReturnsErrorCode(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, false)
	resps := roundtrip(t, srv, []rpcRequest{
		{ID: json.RawMessage(`1`), Method: "wat/idk"},
	})
	if resps[0].Error == nil || resps[0].Error.Code != errMethodNotFound {
		t.Fatalf("expected method-not-found: %+v", resps[0].Error)
	}
}

// syncBuffer is an io.Writer + line-counter used to wait for N
// responses without polling the JSON decoder.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) lines() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Count(b.buf.Bytes(), []byte{'\n'})
}

func (b *syncBuffer) reader() io.Reader {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.NewReader(append([]byte(nil), b.buf.Bytes()...))
}

// TestCreateWorkflowToolGatedOnStateRoot: the authoring tool only appears
// when the write surface (Dispatch) AND a state root are both wired.
func TestCreateWorkflowToolGatedOnStateRoot(t *testing.T) {
	srv, _, _ := newTestServer(t, true) // Dispatch set, no StateRoot
	resps := roundtrip(t, srv, []rpcRequest{{ID: json.RawMessage(`1`), Method: "tools/list"}})
	body, _ := json.Marshal(resps[0].Result)
	if strings.Contains(string(body), `"name":"reactor_create_workflow"`) {
		t.Fatalf("create_workflow must be absent without StateRoot: %s", body)
	}

	srv2, _, _ := newTestServer(t, true)
	srv2.StateRoot = t.TempDir()
	resps2 := roundtrip(t, srv2, []rpcRequest{{ID: json.RawMessage(`1`), Method: "tools/list"}})
	body2, _ := json.Marshal(resps2[0].Result)
	if !strings.Contains(string(body2), `"name":"reactor_create_workflow"`) {
		t.Fatalf("create_workflow must be present with StateRoot + Dispatch: %s", body2)
	}
}

// TestCreateWorkflowToolBuildsAndRegisters drives the MCP authoring path
// end-to-end: submit Go source, the daemon compiles + registers it (no
// external API key), and the binary lands on disk.
func TestCreateWorkflowToolBuildsAndRegisters(t *testing.T) {
	t.Setenv("REACTOR_SDK_REPLACE", "") // stdlib-only workflow builds without the SDK replace
	srv, j, _ := newTestServer(t, true)
	srv.StateRoot = t.TempDir()
	callArgs, _ := json.Marshal(map[string]any{
		"name": "reactor_create_workflow",
		"arguments": map[string]any{
			"slug":    "mcp-built",
			"main_go": "package main\n\nfunc main() {}\n",
			"dag":     map[string]any{"steps": []any{}},
		},
	})
	// A real `go build` runs inside the handler, so give it a generous budget.
	resps := roundtripT(t, srv, []rpcRequest{{ID: json.RawMessage(`1`), Method: "tools/call", Params: callArgs}}, 60*time.Second)
	if len(resps) == 0 {
		t.Fatal("no response from create_workflow (build did not finish in time)")
	}
	if resps[0].Error != nil {
		t.Fatalf("create_workflow errored: %+v", resps[0].Error)
	}
	body, _ := json.Marshal(resps[0].Result)
	if !strings.Contains(string(body), `\"built\":true`) {
		t.Fatalf("expected built=true: %s", body)
	}
	id, err := j.WorkflowIDBySlug(context.Background(), "mcp-built")
	if err != nil || id == "" {
		t.Fatalf("workflow not registered: id=%q err=%v", id, err)
	}
	if _, err := os.Stat(filepath.Join(srv.StateRoot, "workflows", "mcp-built", "workflow")); err != nil {
		t.Fatalf("compiled binary not on disk: %v", err)
	}
}
