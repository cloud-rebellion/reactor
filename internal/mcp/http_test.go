package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/oauth"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestServeHTTPNullAuthoringFieldsCannotCreateArtifacts(t *testing.T) {
	t.Parallel()
	srv, store, _ := newTestServer(t, false)
	srv.Scopes = &WriteScopes{Authoring: true}

	for _, tc := range []struct {
		name      string
		tool      string
		arguments string
		field     string
	}{
		{name: "workflow sdk version", tool: "reactor_register_workflow", arguments: `{"slug":"null-sdk-version","sdk_version":null}`, field: "sdk_version"},
		{name: "workflow code hash", tool: "reactor_register_workflow", arguments: `{"slug":"null-code-hash","code_hash":null}`, field: "code_hash"},
		{name: "command description", tool: "reactor_create_command_automation", arguments: `{"name":"null-description","description":null,"definition":{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0}]}}`, field: "description"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tc.tool + `","arguments":` + tc.arguments + `}}`
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			out := httptest.NewRecorder()
			srv.ServeHTTP(out, req)
			if out.Code != http.StatusOK || !strings.Contains(out.Body.String(), `"isError":true`) || !strings.Contains(out.Body.String(), tc.field+` must not be null`) {
				t.Fatalf("null %s response = HTTP %d %s", tc.field, out.Code, out.Body.String())
			}
		})
	}
	for _, slug := range []string{"null-sdk-version", "null-code-hash"} {
		if _, err := store.WorkflowIDBySlugInTenant(context.Background(), slug, journal.DefaultTenant); !errors.Is(err, journal.ErrNotFound) {
			t.Fatalf("null authoring field created workflow %q: %v", slug, err)
		}
	}
	if _, err := store.GetCommandAutomationByName(context.Background(), journal.DefaultTenant, "null-description"); !errors.Is(err, journal.ErrNotFound) {
		t.Fatalf("null description created command automation: %v", err)
	}
}

type mcpCallCounter struct{ calls atomic.Uint64 }

func (c *mcpCallCounter) IncMCPCall() { c.calls.Add(1) }

// newMCPHTTPTestServer deliberately binds IPv4. Some developer and CI
// sandboxes deny IPv6 loopback listeners even though the MCP HTTP contract is
// otherwise fully available over loopback.
func newMCPHTTPTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable in this test environment: %v", err)
	}
	ts := &httptest.Server{
		Listener: listener,
		Config:   &http.Server{Handler: handler},
	}
	ts.Start()
	return ts
}

func TestServeHTTPInitialize(t *testing.T) {
	t.Parallel()

	srv := &Server{Info: ServerInfo{Name: "reactor-test", Version: "0.0.0"}}
	body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	r := httptest.NewRequest(http.MethodPost, "/mcp", body)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store, max-age=0" {
		t.Fatalf("MCP response Cache-Control = %q, want no-store", got)
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("MCP response Pragma = %q, want no-cache", got)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
	var resp rpcResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.JSONRPC != "2.0" {
		t.Fatalf("jsonrpc = %q, want 2.0", resp.JSONRPC)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	resultMap, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result not a map: %T %v", resp.Result, resp.Result)
	}
	if resultMap["protocolVersion"] == nil {
		t.Fatalf("missing protocolVersion in result: %v", resultMap)
	}
	if got, want := resultMap["protocolVersion"], ProtocolVersion; got != want {
		t.Fatalf("protocolVersion = %v, want shared MCP version %s", got, want)
	}
	instructions, ok := resultMap["instructions"].(string)
	if !ok || !strings.Contains(instructions, "validate") || !strings.Contains(instructions, "idempotency key") {
		t.Fatalf("initialize instructions = %v, want the bounded authoring safety contract", resultMap["instructions"])
	}
	capabilities, ok := resultMap["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("initialize capabilities = %T %v, want object", resultMap["capabilities"], resultMap["capabilities"])
	}
	toolsCapability, ok := capabilities["tools"].(map[string]any)
	if !ok || toolsCapability["listChanged"] != false {
		t.Fatalf("initialize tools capability = %v, want listChanged=false", capabilities["tools"])
	}
}

func TestServeHTTPInitializeDefaultsServerIdentity(t *testing.T) {
	t.Parallel()

	// HTTP and stdio share one Server type. An embedded caller may leave the
	// optional metadata empty, but MCP initialize still needs a usable server
	// identity for clients such as `reactor mcp check`.
	srv := &Server{}
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp rpcResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("initialize result = %T %v, want object", resp.Result, resp.Result)
	}
	serverInfo, ok := result["serverInfo"].(map[string]any)
	if !ok {
		t.Fatalf("serverInfo = %T %v, want object", result["serverInfo"], result["serverInfo"])
	}
	if got, want := serverInfo["name"], "reactor"; got != want {
		t.Fatalf("serverInfo.name = %v, want %q", got, want)
	}
}

func TestServeHTTPInitializeNegotiatesUnsupportedBodyProtocolVersion(t *testing.T) {
	t.Parallel()

	srv := &Server{Info: ServerInfo{Name: "reactor-test", Version: "0.0.0"}}
	body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`)
	r := httptest.NewRequest(http.MethodPost, "/mcp", body)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 JSON-RPC result; body=%s", w.Code, w.Body.String())
	}
	var resp rpcResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected initialize error: %+v", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("initialize result = %T %v, want object", resp.Result, resp.Result)
	}
	if got, want := result["protocolVersion"], ProtocolVersion; got != want {
		t.Fatalf("negotiated protocolVersion = %v, want %s", got, want)
	}
}

func TestServeHTTPInitializeRejectsMalformedBodyProtocolVersion(t *testing.T) {
	t.Parallel()

	for _, params := range []string{`{"protocolVersion":null}`, `{"protocolVersion":7}`, `{"protocolVersion":""}`} {
		t.Run(params, func(t *testing.T) {
			srv := &Server{}
			body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":` + params + `}`)
			r := httptest.NewRequest(http.MethodPost, "/mcp", body)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)
			var resp rpcResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("parse response: %v; body=%s", err, w.Body.String())
			}
			if w.Code != http.StatusOK || resp.Error == nil || resp.Error.Code != errInvalidParams {
				t.Fatalf("status=%d error=%+v; want JSON-RPC invalid params", w.Code, resp.Error)
			}
		})
	}
}

func TestServeHTTPWaitForRunReturnsToolTimeoutReceipt(t *testing.T) {
	// The transport budget must cover the longest tool-level wait, otherwise an
	// HTTP caller asking for an allowed timeout can receive context.Deadline
	// exceeded instead of the documented timed_out result. Keep this invariant
	// explicit while using a one-second fake/polling run so the regression stays
	// fast.
	if maxMCPHTTPExecution <= time.Duration(maxMCPWaitSeconds)*time.Second {
		t.Fatalf("HTTP execution budget = %s, must exceed max tool wait %ds", maxMCPHTTPExecution, maxMCPWaitSeconds)
	}
	s, j, _ := newTestServer(t, false)
	s.TenantID = "acme"
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_http_wait", "http-wait", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_http_wait", "wf_http_wait", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}

	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":      "reactor_wait_for_run",
			"arguments": map[string]any{"run_id": "run_http_wait", "timeout_seconds": 1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var envelope struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
		Error *rpcError `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode JSON-RPC response: %v; body=%s", err, w.Body.String())
	}
	if envelope.Error != nil || envelope.Result.IsError || len(envelope.Result.Content) != 1 {
		t.Fatalf("unexpected JSON-RPC wait response: %+v; body=%s", envelope, w.Body.String())
	}
	var receipt struct {
		TimedOut bool `json:"timed_out"`
		Terminal bool `json:"terminal"`
	}
	if err := json.Unmarshal([]byte(envelope.Result.Content[0].Text), &receipt); err != nil {
		t.Fatalf("decode wait receipt: %v; text=%s", err, envelope.Result.Content[0].Text)
	}
	if !receipt.TimedOut || receipt.Terminal {
		t.Fatalf("wait receipt = %+v; want timed_out=true, terminal=false", receipt)
	}
}

func TestServeHTTPRejectsBodiesOverSharedMCPRequestCap(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	body := append([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"padding":"`), bytes.Repeat([]byte{'x'}, (1<<20)+128)...)
	body = append(body, []byte(`"}}`)...)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for body over 1 MiB", w.Code)
	}
}

func TestServeHTTPMethodNotAllowed(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
	if a := w.Header().Get("Allow"); a != "POST" {
		t.Fatalf("Allow = %q, want POST", a)
	}
}

func TestServeHTTPWrongContentType(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", w.Code)
	}
}

func TestServeHTTPRequiresContentType(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("missing content type status = %d, want 415", w.Code)
	}
}

func TestServeHTTPRejectsAcceptWithoutJSONResponse(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "text/plain")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusNotAcceptable {
		t.Fatalf("status = %d, want 406", w.Code)
	}
	if got := w.Header().Get("Accept"); got != "application/json, text/event-stream" {
		t.Fatalf("response Accept = %q, want negotiated MCP media types", got)
	}
}

func TestServeHTTPAcceptsMCPNegotiatedMediaTypes(t *testing.T) {
	t.Parallel()

	srv := &Server{Info: ServerInfo{Name: "reactor-test", Version: "0.0.0"}}
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
}

func TestServeHTTPRejectsZeroQualityJSON(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json;q=0, text/event-stream;q=1")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusNotAcceptable {
		t.Fatalf("status = %d, want 406", w.Code)
	}
}

func TestServeHTTPAcceptsCaseInsensitiveJSONMediaType(t *testing.T) {
	t.Parallel()

	srv := &Server{Info: ServerInfo{Name: "reactor-test", Version: "0.0.0"}}
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	r.Header.Set("Content-Type", "Application/JSON; charset=utf-8")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestServeHTTPToolsCallIncrementsOperationalCounterOnFailures(t *testing.T) {
	t.Parallel()

	counter := &mcpCallCounter{}
	srv := &Server{MCPCalls: counter}
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"missing","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":[]}`,
	} {
		r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("tools/call status = %d, want 200; body=%s", w.Code, w.Body.String())
		}
	}
	if got, want := counter.calls.Load(), uint64(2); got != want {
		t.Fatalf("MCP call counter = %d, want %d failed tools/call attempts counted", got, want)
	}
}

func TestServeHTTPNegotiatesProtocolHeader(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		header string
		status int
	}{
		{name: "matching", header: ProtocolVersion, status: http.StatusOK},
		{name: "unsupported", header: "2099-01-01", status: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := &Server{Info: ServerInfo{Name: "reactor-test", Version: "0.0.0"}}
			r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set(MCPProtocolVersionHeader, tc.header)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.status, w.Body.String())
			}
			if got := w.Header().Get(MCPProtocolVersionHeader); got != ProtocolVersion {
				t.Fatalf("response protocol header = %q, want %q", got, ProtocolVersion)
			}
			if tc.status == http.StatusBadRequest {
				var resp rpcResponse
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("decode protocol error: %v", err)
				}
				if resp.Error == nil || resp.Error.Code != errInvalidRequest {
					t.Fatalf("protocol error = %+v", resp.Error)
				}
				if string(resp.ID) != "null" {
					t.Fatalf("protocol error id = %q, want null", resp.ID)
				}
			}
		})
	}
}

func TestServeHTTPValidatesJSONRPCEnvelope(t *testing.T) {
	t.Parallel()

	for _, body := range []string{
		`null`,
		`{"jsonrpc":"2.0","id":true,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":1}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping","result":{}}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/list"}`,
	} {
		t.Run(body, func(t *testing.T) {
			srv := &Server{}
			r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
			}
			var resp rpcResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp.Error == nil || resp.Error.Code != errInvalidRequest {
				t.Fatalf("response = %+v, want invalid request", resp)
			}
		})
	}
}

func TestServeHTTPInvalidRequestUsesNullID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		body  string
		batch bool
	}{
		{name: "invalid id type", body: `{"jsonrpc":"2.0","id":true,"method":"ping"}`},
		{name: "malformed json", body: `{"jsonrpc":"2.0","id":1,"method":`, batch: false},
		{name: "malformed batch member", body: `[{"jsonrpc":"2.0","id":{"bad":1},"method":"ping"}]`, batch: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &Server{}
			r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)

			if tc.batch {
				var responses []rpcResponse
				if err := json.Unmarshal(w.Body.Bytes(), &responses); err != nil {
					t.Fatalf("decode batch response: %v; body=%s", err, w.Body.String())
				}
				if len(responses) != 1 || string(responses[0].ID) != "null" {
					t.Fatalf("batch response id = %q; body=%s, want null", responses[0].ID, w.Body.String())
				}
				return
			}
			var response rpcResponse
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode response: %v; body=%s", err, w.Body.String())
			}
			if string(response.ID) != "null" {
				t.Fatalf("response id = %q; body=%s, want null", response.ID, w.Body.String())
			}
		})
	}
}

func TestServeHTTPBoundsLargeResponse(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	srv.ensureRegistered()
	srv.tools["reactor_test_oversized"] = toolDef{
		tool: Tool{Name: "reactor_test_oversized", InputSchema: map[string]any{"type": "object"}},
		handler: func(context.Context, json.RawMessage) (any, error) {
			return map[string]any{"body": strings.Repeat("x", maxMCPHTTPResponseBytes+1024)}, nil
		},
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"reactor_test_oversized","arguments":{}}}`
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Body.Len() > maxMCPHTTPResponseBytes {
		t.Fatalf("status=%d body bytes=%d, want bounded response", w.Code, w.Body.Len())
	}
	var resp rpcResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode bounded response: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != errInternalError {
		t.Fatalf("bounded response error = %+v", resp.Error)
	}
}

func TestServeHTTPRejectsCrossOriginBrowserRequest(t *testing.T) {
	srv := &Server{Info: ServerInfo{Name: "reactor-test", Version: "0.0.0"}}
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:7777/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestServeHTTPAllowsSameOriginBrowserRequest(t *testing.T) {
	srv := &Server{Info: ServerInfo{Name: "reactor-test", Version: "0.0.0"}}
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:7777/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://127.0.0.1:7777")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s; want 200", w.Code, w.Body.String())
	}
}

func TestServeHTTPRejectsHostDerivedSameOriginOnNonLoopback(t *testing.T) {
	// A DNS-rebinding page can make Origin match an attacker-controlled Host
	// header while the connection still reaches a local daemon. Only loopback
	// Host-derived origins are safe without an explicit operator allowlist.
	srv := &Server{Info: ServerInfo{Name: "reactor-test", Version: "0.0.0"}}
	r := httptest.NewRequest(http.MethodPost, "http://reactor.example:7777/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://reactor.example:7777")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body=%s; want 403 without an explicit origin allowlist", w.Code, w.Body.String())
	}
}

func TestServeHTTPAllowsConfiguredHTTPSOriginBehindProxy(t *testing.T) {
	srv := &Server{
		Info:           ServerInfo{Name: "reactor-test", Version: "0.0.0"},
		AllowedOrigins: []string{"https://reactor.example"},
	}
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:7777/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://reactor.example")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s; want 200", w.Code, w.Body.String())
	}
}

func TestServeHTTPRejectsMalformedOrMultipleOrigins(t *testing.T) {
	for _, origin := range []string{"null", "https://evil.example/path", "https://a.example, https://b.example"} {
		t.Run(origin, func(t *testing.T) {
			srv := &Server{}
			r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:7777/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", origin)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("origin %q status = %d, want 403", origin, w.Code)
			}
		})
	}
}

func TestServeHTTPRejectsOversizedBatch(t *testing.T) {
	srv := &Server{}
	requests := make([]string, 129)
	for i := range requests {
		requests[i] = `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
	}
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("["+strings.Join(requests, ",")+"]"))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp rpcResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != errInvalidRequest {
		t.Fatalf("response = %s, want invalid request", w.Body.String())
	}
}

func TestServeHTTPRejectsEmptyBatch(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("[]"))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp rpcResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != errInvalidRequest {
		t.Fatalf("response = %s, want invalid request", w.Body.String())
	}
}

func TestServeHTTPBatch(t *testing.T) {
	t.Parallel()

	srv := &Server{Info: ServerInfo{Name: "a", Version: "0"}}
	body := strings.NewReader(`[
		{"jsonrpc":"2.0","id":1,"method":"initialize"},
		{"jsonrpc":"2.0","id":2,"method":"tools/list"}
	]`)
	r := httptest.NewRequest(http.MethodPost, "/mcp", body)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var responses []rpcResponse
	if err := json.Unmarshal(w.Body.Bytes(), &responses); err != nil {
		t.Fatalf("parse batch: %v (body=%s)", err, w.Body.String())
	}
	if len(responses) != 2 {
		t.Fatalf("response count = %d, want 2", len(responses))
	}
	for _, r := range responses {
		if r.JSONRPC != "2.0" {
			t.Errorf("response jsonrpc = %q", r.JSONRPC)
		}
		if r.Error != nil {
			t.Errorf("response error: %+v", r.Error)
		}
	}
}

func TestServeHTTPBoundsOversizedBatchMembersWithoutLosingIDs(t *testing.T) {
	t.Parallel()

	// A single member can exceed the aggregate HTTP response budget even when
	// the other members are small. The transport must keep a correlated error
	// for that member so an AI does not mistake a batch-level id:null failure for
	// a lost mutation receipt and retry it blindly.
	responses := []rpcResponse{
		{JSONRPC: "2.0", ID: json.RawMessage(`11`), Result: map[string]any{"body": strings.Repeat("x", maxMCPHTTPResponseBytes+1024)}},
		{JSONRPC: "2.0", ID: json.RawMessage(`12`), Result: map[string]any{"ok": true}},
	}
	w := httptest.NewRecorder()
	writeRPCResponsesHTTP(w, responses)
	if w.Body.Len() > maxMCPHTTPResponseBytes {
		t.Fatalf("bounded batch response = %d bytes, want <= %d", w.Body.Len(), maxMCPHTTPResponseBytes)
	}
	var got []rpcResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode bounded batch response: %v; body=%s", err, w.Body.String())
	}
	if len(got) != 2 {
		t.Fatalf("batch members = %d, want 2", len(got))
	}
	if string(got[0].ID) != "11" || got[0].Error == nil || got[0].Error.Code != errInternalError {
		t.Fatalf("oversized member = %+v, want correlated internal error for id 11", got[0])
	}
	if string(got[1].ID) != "12" || got[1].Error != nil {
		t.Fatalf("small member = %+v, want successful id 12 response", got[1])
	}
}

func TestServeHTTPResponseCapIncludesWireNewline(t *testing.T) {
	t.Parallel()

	// Build a response whose JSON is exactly one byte below the transport cap;
	// the newline written by the HTTP encoder must fit inside the same bound.
	limit := maxMCPHTTPResponseBytes - 1
	base := rpcResponse{JSONRPC: "2.0", ID: json.RawMessage(`1`), Result: ""}
	baseRaw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	response := rpcResponse{
		JSONRPC: "2.0", ID: json.RawMessage(`1`),
		Result: strings.Repeat("x", limit-len(baseRaw)),
	}
	raw, err := json.Marshal(response)
	if err != nil || len(raw) != limit {
		t.Fatalf("exact response-cap fixture length = %d, err=%v; want %d", len(raw), err, limit)
	}
	recorder := httptest.NewRecorder()
	writeRPCResponseHTTP(recorder, response)
	if recorder.Body.Len() > maxMCPHTTPResponseBytes {
		t.Fatalf("wire response = %d bytes, want <= %d", recorder.Body.Len(), maxMCPHTTPResponseBytes)
	}
	if !strings.HasSuffix(recorder.Body.String(), "\n") {
		t.Fatal("MCP response lost its terminating newline")
	}
}

func TestServeHTTPResponseOnlyMessageReturns202(t *testing.T) {
	t.Parallel()

	// Streamable HTTP permits a server response as POST input when a peer is
	// sharing a bidirectional transport. Reactor is stateless and has no
	// pending server request to consume here, so the message is accepted and
	// produces no synthetic JSON-RPC response.
	srv := &Server{Info: ServerInfo{Name: "a", Version: "0"}}
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":7,"result":{"ok":true}}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)

	if w.Code != http.StatusAccepted || w.Body.Len() != 0 {
		t.Fatalf("response-only POST = %d %q, want 202 with empty body", w.Code, w.Body.String())
	}
}

func TestServeHTTPBatchIgnoresResponsesAlongsideRequests(t *testing.T) {
	t.Parallel()

	srv := &Server{Info: ServerInfo{Name: "a", Version: "0"}}
	body := `[
		{"jsonrpc":"2.0","id":7,"result":{"ok":true}},
		{"jsonrpc":"2.0","id":8,"method":"ping"},
		{"jsonrpc":"2.0","method":"notifications/initialized"}
	]`
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)

	var responses []rpcResponse
	if err := json.Unmarshal(w.Body.Bytes(), &responses); err != nil {
		t.Fatalf("decode batch response: %v; body=%s", err, w.Body.String())
	}
	if w.Code != http.StatusOK || len(responses) != 1 || string(responses[0].ID) != "8" || responses[0].Error != nil {
		t.Fatalf("batch responses = %d %s, want only ping response", w.Code, w.Body.String())
	}
}

func TestServeHTTPRejectsAmbiguousJSONRPCResponse(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":7,"result":{},"error":{"code":-1,"message":"both"}}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)

	var response rpcResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode invalid response envelope: %v; body=%s", err, w.Body.String())
	}
	if w.Code != http.StatusOK || response.Error == nil || response.Error.Code != errInvalidRequest {
		t.Fatalf("response = %d %+v, want JSON-RPC invalid request", w.Code, response)
	}
}

func TestServeHTTPNotificationReturns202(t *testing.T) {
	t.Parallel()

	srv := &Server{Info: ServerInfo{Name: "a", Version: "0"}}
	body := strings.NewReader(`{"jsonrpc":"2.0","method":"initialize"}`)
	r := httptest.NewRequest(http.MethodPost, "/mcp", body)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Fatalf("body = %q, want empty", w.Body.String())
	}
}

func TestServeHTTPNotificationsCannotRunToolsWithoutReceipts(t *testing.T) {
	counter := &mcpCallCounter{}
	srv := &Server{MCPCalls: counter}
	srv.ensureRegistered()
	var mutations atomic.Uint64
	srv.tools["reactor_test_mutation"] = toolDef{
		tool: Tool{Name: "reactor_test_mutation", InputSchema: map[string]any{"type": "object"}},
		handler: func(context.Context, json.RawMessage) (any, error) {
			mutations.Add(1)
			return map[string]any{"created": true}, nil
		},
	}
	const call = `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"reactor_test_mutation","arguments":{}}}`
	for _, body := range []string{
		`{"jsonrpc":"2.0","method":"initialize"}`,
		call,
		`[` + call + `,{"jsonrpc":"2.0","method":"notifications/initialized"}]`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusAccepted || w.Body.Len() != 0 {
			t.Fatalf("id-less MCP message = %d %q, want empty 202", w.Code, w.Body.String())
		}
	}
	if mutations.Load() != 0 || counter.calls.Load() != 0 {
		t.Fatalf("id-less tools/call executed: mutations=%d calls=%d", mutations.Load(), counter.calls.Load())
	}

	// An id-bearing request still runs the tool and returns its correlated
	// result, so an AI client can distinguish success from a lost transport.
	request := strings.Replace(call, `"method":"tools/call"`, `"id":7,"method":"tools/call"`, 1)
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(request))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	var response rpcResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode id-bearing tool result: %v; body=%s", err, w.Body.String())
	}
	if w.Code != http.StatusOK || string(response.ID) != "7" || response.Error != nil || mutations.Load() != 1 || counter.calls.Load() != 1 {
		t.Fatalf("id-bearing tool result = %d %+v, mutations=%d calls=%d", w.Code, response, mutations.Load(), counter.calls.Load())
	}
}

func TestServeHTTPNotificationsNeverProduceRPCResponses(t *testing.T) {
	for _, body := range []string{
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"notifications/unknown"}`,
		`{"jsonrpc":"2.0","method":"tools/call","params":[]}`,
		`[{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","method":"notifications/unknown"}]`,
	} {
		t.Run(body, func(t *testing.T) {
			srv := &Server{}
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			srv.ServeHTTP(w, req)
			if w.Code != http.StatusAccepted || w.Body.Len() != 0 {
				t.Fatalf("notification response = %d %s, want empty 202", w.Code, w.Body.String())
			}
		})
	}
}

func TestServeHTTPMixedBatchOmitsNotificationErrors(t *testing.T) {
	srv := &Server{}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`[
		{"jsonrpc":"2.0","method":"notifications/initialized"},
		{"jsonrpc":"2.0","method":"notifications/unknown"},
		{"jsonrpc":"2.0","id":42,"method":"ping"},
		{"jsonrpc":"1.0","id":99,"method":"unknown"}
	]`))
	req.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(w, req)
	var responses []rpcResponse
	if err := json.Unmarshal(w.Body.Bytes(), &responses); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || len(responses) != 2 {
		t.Fatalf("response = %d %s, want two request replies", w.Code, w.Body.String())
	}
	if string(responses[0].ID) != "42" || responses[0].Error != nil ||
		string(responses[1].ID) != "99" || responses[1].Error == nil || responses[1].Error.Code != errInvalidRequest {
		t.Fatalf("request replies changed: %s", w.Body.String())
	}
}

func TestServeHTTPBadJSON(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{not json`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (JSON-RPC parse errors body-encode, not HTTP-encode)", w.Code)
	}
	var resp rpcResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != errParseError {
		t.Fatalf("expected parse error, got %+v", resp.Error)
	}
}

func TestServeHTTPEmptyBody(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestServeHTTPRoundTripViaRealServer(t *testing.T) {
	t.Parallel()

	mcp := &Server{Info: ServerInfo{Name: "reactor", Version: "test"}}
	ts := newMCPHTTPTestServer(t, mcp)
	defer ts.Close()

	resp, err := http.Post(ts.URL, "application/json",
		bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":42,"method":"tools/list"}`)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	var r rpcResponse
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.Error != nil {
		t.Fatalf("tools/list error: %+v", r.Error)
	}
	result, ok := r.Result.(map[string]any)
	if !ok || result["tools"] == nil {
		t.Fatalf("missing tools in result: %v", r.Result)
	}

	callBody := []byte(`{"jsonrpc":"2.0","id":43,"method":"tools/call","params":{"name":"reactor_list_service_catalog","arguments":{"query":"stripe"}}}`)
	callResp, err := http.Post(ts.URL, "application/json", bytes.NewReader(callBody))
	if err != nil {
		t.Fatalf("catalog post: %v", err)
	}
	defer callResp.Body.Close()
	callRaw, _ := io.ReadAll(callResp.Body)
	if callResp.StatusCode != http.StatusOK {
		t.Fatalf("catalog status = %d, body=%s", callResp.StatusCode, callRaw)
	}
	var callRPC rpcResponse
	if err := json.Unmarshal(callRaw, &callRPC); err != nil {
		t.Fatalf("catalog parse: %v", err)
	}
	if callRPC.Error != nil || !strings.Contains(string(callRaw), `stripe`) {
		t.Fatalf("catalog response = %s", callRaw)
	}
}

func TestServeHTTPOAuthInventoryViaRealServer(t *testing.T) {
	t.Parallel()
	mcp, _, _ := newTestServer(t, false)
	if err := mcp.OAuth.UpsertProvider(context.Background(), oauth.Provider{
		ProviderID: "google", Name: "Google", AuthURL: "https://accounts.example/authorize",
		TokenURL: "https://accounts.example/token", ClientID: "client", Enabled: true,
	}, "secret-value"); err != nil {
		t.Fatal(err)
	}
	mcp.TenantID = "acme"
	ts := newMCPHTTPTestServer(t, mcp)
	defer ts.Close()
	body := []byte(`{"jsonrpc":"2.0","id":44,"method":"tools/call","params":{"name":"reactor_list_oauth_connections","arguments":{"provider_id":"google"}}}`)
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "google") {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	if strings.Contains(string(raw), "secret-value") || strings.Contains(string(raw), "access_token") {
		t.Fatalf("OAuth HTTP response leaked secret material: %s", raw)
	}
}
