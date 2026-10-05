package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/codegen"
	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/mcp"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/go-chi/chi/v5"
)

const mcpAcceptanceDAG = `{"steps":[{"name":"record","kind":"step"}]}`

func mcpAcceptanceWorkflowSource(slug string) string {
	return fmt.Sprintf(`package main
import (
    "context"
    reactor "github.com/bright-interaction/reactor/sdk"
    "github.com/bright-interaction/reactor/sdk/runtime"
)
func run(ctx context.Context, flow reactor.Flow, _ struct{}) error {
    _, err := reactor.Step(flow, ctx, "record", reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
    return err
}
func main() { runtime.Serve(reactor.Workflow{Slug: %q, Version: "0.1.0"}, reactor.EventTrigger{}, run) }
`, slug)
}

// The HTTP lifecycle uses an actual SecretFetch from the compiled child.
// Neither the source nor the Step result contains the synthetic values.
func mcpAcceptanceVaultWorkflowSource(slug string) string {
	return fmt.Sprintf(`package main
import (
    "context"
    "errors"
    reactor "github.com/bright-interaction/reactor/sdk"
    "github.com/bright-interaction/reactor/sdk/runtime"
    "github.com/bright-interaction/reactor/sdk/vault"
)
func run(ctx context.Context, flow reactor.Flow, _ struct{}) error {
    _, err := reactor.Step(flow, ctx, "record", reactor.StepOpts{}, func(stepCtx context.Context) (string, error) {
        if secret, fetchErr := vault.Get(stepCtx, "cred_http_mcp_ungranted"); fetchErr == nil || secret != nil {
            return "", errors.New("ungranted credential was released")
        }
        secret, fetchErr := vault.Get(stepCtx, "cred_http_mcp")
        if fetchErr != nil || secret == nil || len(secret.Reveal()) == 0 {
            return "", errors.New("granted credential was unavailable")
        }
        return "ok", nil
    })
    return err
}
func main() { runtime.Serve(reactor.Workflow{Slug: %q, Version: "0.1.0"}, reactor.EventTrigger{}, run) }
`, slug)
}

func setMCPAcceptanceSDK(t *testing.T) {
	t.Helper()
	reactorRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve Reactor SDK root: %v", err)
	}
	t.Setenv("REACTOR_SDK_REPLACE", reactorRoot)
	t.Setenv("ARACHNE_SDK_REPLACE", "")
}

func TestServeMCPDispatchUsesDaemonDispatcherAndPinnedArtifact(t *testing.T) {
	setMCPAcceptanceSDK(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	dbURL := "sqlite://" + filepath.Join(root, "reactor.db")
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := &serveConfig{
		dbURL:       dbURL,
		root:        root,
		masterKey:   bytes.Repeat([]byte{0x42}, 32),
		mcpDispatch: true,
	}
	deps, err := openServeDeps(ctx, log, cfg)
	if err != nil {
		t.Fatalf("open serve dependencies: %v", err)
	}
	defer deps.db.Close()

	built, err := codegen.BuildAndRegisterSource(ctx, deps.journal, codegen.BuildSourceRequest{
		Slug: "mcp-e2e", MainGo: mcpAcceptanceWorkflowSource("mcp-e2e"),
		DAGJSON: mcpAcceptanceDAG, StateRoot: root, TenantID: journal.DefaultTenant,
	})
	if err != nil {
		t.Fatalf("build workflow through canonical authoring path: %v", err)
	}

	var listed struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	serveMCPRequest(t, deps.mcpSrv, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, &listed)
	if !hasMCPTool(listed.Result.Tools, "reactor_dispatch_workflow") {
		t.Fatalf("dispatch scope did not advertise reactor_dispatch_workflow: %+v", listed.Result.Tools)
	}
	if hasMCPTool(listed.Result.Tools, "reactor_create_workflow") {
		t.Fatal("dispatch-only daemon advertised authoring")
	}

	var dispatched struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	serveMCPRequest(t, deps.mcpSrv, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"reactor_dispatch_workflow","arguments":{"slug":"mcp-e2e","payload":{"source":"mcp"}}}}`, &dispatched)
	if len(dispatched.Result.Content) != 1 {
		t.Fatalf("dispatch response content = %+v", dispatched.Result.Content)
	}
	var dispatchResult struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal([]byte(dispatched.Result.Content[0].Text), &dispatchResult); err != nil {
		t.Fatalf("decode dispatch response %q: %v", dispatched.Result.Content[0].Text, err)
	}
	if dispatchResult.RunID == "" {
		t.Fatalf("dispatch response omitted run id: %q", dispatched.Result.Content[0].Text)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		run, getErr := deps.journal.GetRun(ctx, dispatchResult.RunID)
		if getErr != nil {
			t.Fatalf("get dispatched run: %v", getErr)
		}
		if run.Status == "succeeded" {
			if run.WorkflowArtifactSHA256 != built.ArtifactSHA256 {
				t.Fatalf("run artifact pin = %q, want %q", run.WorkflowArtifactSHA256, built.ArtifactSHA256)
			}
			break
		}
		if run.Status == "failed" || run.Status == "failed_dlq" || time.Now().After(deadline) {
			t.Fatalf("dispatched run did not succeed: status=%q run=%+v", run.Status, run)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := deps.dispatcher.Drain(time.Second); err != nil {
		t.Fatalf("drain daemon dispatcher: %v", err)
	}
}

func serveMCPRequest(t *testing.T, srv interface {
	Serve(context.Context, io.Reader, io.Writer) error
}, request string, response any) {
	t.Helper()
	var out bytes.Buffer
	if err := srv.Serve(context.Background(), bytes.NewBufferString(request+"\n"), &out); err != nil {
		t.Fatalf("serve MCP request: %v", err)
	}
	if err := json.Unmarshal(out.Bytes(), response); err != nil {
		t.Fatalf("decode MCP response %q: %v", out.String(), err)
	}
}

func hasMCPTool(tools []struct {
	Name string `json:"name"`
}, name string) bool {
	for _, tool := range tools {
		if tool.Name == name {
			return true
		}
	}
	return false
}

// TestServeMCPHTTPAuthoringLifecycle exercises the production HTTP route,
// including bearer identity resolution and the admin middleware group. The
// older daemon acceptance test above calls Server.Serve directly, which proves
// dispatch wiring but cannot catch a route/auth/middleware regression. Keep
// this path deliberately small: validate -> build/register -> review ->
// version-fenced enable -> preflight -> dispatch -> terminal run receipt. The
// compiled child must also fetch a granted credential, be denied a same-tenant
// ungranted credential, and leave only a value-free authorized access receipt.
func TestServeMCPHTTPAuthoringLifecycle(t *testing.T) {
	setMCPAcceptanceSDK(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &serveConfig{
		dbURL:        "sqlite://" + filepath.Join(root, "reactor.db"),
		root:         root,
		masterKey:    bytes.Repeat([]byte{0x43}, 32),
		mcpToken:     "http-mcp-test-token",
		mcpTenant:    "acme",
		mcpAuthoring: true,
		mcpDispatch:  true,
		mcpSecrets:   true,
		mode:         "local",
	}
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	deps, err := openServeDeps(ctx, log, cfg)
	if err != nil {
		t.Fatalf("open serve dependencies: %v", err)
	}
	defer deps.db.Close()
	defer func() {
		if err := deps.dispatcher.Drain(5 * time.Second); err != nil {
			t.Errorf("drain daemon dispatcher: %v", err)
		}
	}()

	router := chi.NewRouter()
	buildHTTPServer(log, cfg, deps).Mount(router)
	httpTestServer := startInMemoryHTTPServer(t, router)
	defer httpTestServer.Close()
	client := httpTestServer.Client()
	endpoint := httpTestServer.Endpoint() + "/mcp"

	initialized := httpMCPRequest(t, client, endpoint, cfg.mcpToken, []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+mcp.ProtocolVersion+`","capabilities":{},"clientInfo":{"name":"reactor-e2e","version":"test"}}}`))
	var initializeEnvelope struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
			ServerInfo      struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
		Error any `json:"error"`
	}
	if err := json.Unmarshal(initialized, &initializeEnvelope); err != nil {
		t.Fatalf("decode initialize response %q: %v", initialized, err)
	}
	if initializeEnvelope.Error != nil || initializeEnvelope.Result.ProtocolVersion != mcp.ProtocolVersion || initializeEnvelope.Result.ServerInfo.Name == "" {
		t.Fatalf("initialize response = %s", initialized)
	}
	listed := httpMCPRequest(t, client, endpoint, cfg.mcpToken, []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	var listEnvelope struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(listed, &listEnvelope); err != nil {
		t.Fatalf("decode tools/list response %q: %v", listed, err)
	}
	seenTools := make(map[string]bool, len(listEnvelope.Result.Tools))
	for _, tool := range listEnvelope.Result.Tools {
		seenTools[tool.Name] = true
	}
	for _, name := range []string{"reactor_validate_workflow", "reactor_create_workflow", "reactor_get_workflow_flow", "reactor_grant_secret", "reactor_preflight_dispatch_workflow", "reactor_dispatch_workflow", "reactor_list_runtime_secret_access_audit"} {
		if !seenTools[name] {
			t.Fatalf("tools/list omitted lifecycle tool %q", name)
		}
	}
	for _, name := range []string{"reactor_get_run_input", "reactor_get_run_step_output", "reactor_get_run_logs"} {
		if seenTools[name] {
			t.Fatalf("tools/list exposed exact execution data without the data-export scope: %q", name)
		}
	}

	mainGo := mcpAcceptanceVaultWorkflowSource("http-mcp-e2e")
	dag := map[string]any{"steps": []any{map[string]any{"name": "record", "kind": "step"}}}
	// Exercise the actual daemon auth gate before authoring. An unauthenticated
	// client must not be able to initialize, discover tools, or create an
	// otherwise valid workflow through the same HTTP route.
	unauthorizedCreate, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]any{
			"name": "reactor_create_workflow",
			"arguments": map[string]any{
				"slug": "http-mcp-unauthorized", "main_go": mcpAcceptanceVaultWorkflowSource("http-mcp-unauthorized"), "dag": dag,
			},
		},
	})
	if err != nil {
		t.Fatalf("encode unauthorized create request: %v", err)
	}
	for _, authorization := range []string{"", "Bearer wrong-http-mcp-token"} {
		for _, request := range [][]byte{
			[]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + mcp.ProtocolVersion + `","capabilities":{},"clientInfo":{"name":"reactor-e2e","version":"test"}}}`),
			[]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`),
			unauthorizedCreate,
		} {
			assertHTTPMCPBearerRejected(t, client, endpoint, authorization, request)
		}
	}
	if _, err := deps.journal.WorkflowIDBySlugInTenant(ctx, "http-mcp-unauthorized", "acme"); !errors.Is(err, journal.ErrNotFound) {
		t.Fatalf("unauthenticated HTTP MCP create lookup = %v, want no workflow", err)
	}
	// An AI can supply null for a helper asset. Decoding it into a Go string
	// would silently publish an empty file, so both authoring entry points must
	// reject it through the authenticated HTTP route before any build or write.
	for _, tc := range []struct {
		name  string
		files any
	}{
		{name: "null-object", files: nil},
		{name: "null-content", files: map[string]any{"policy.json": nil}},
	} {
		slug := "http-mcp-invalid-files-" + tc.name
		for _, tool := range []string{"reactor_validate_workflow", "reactor_create_workflow"} {
			response := httpMCPCall(t, client, endpoint, cfg.mcpToken, tool, map[string]any{
				"slug": slug, "main_go": mcpAcceptanceWorkflowSource(slug), "dag": dag, "files": tc.files,
			})
			if !response.IsError || !strings.Contains(response.Text, "files") {
				t.Fatalf("%s accepted %s: %+v", tool, tc.name, response)
			}
		}
		if _, err := deps.journal.WorkflowIDBySlugInTenant(ctx, slug, "acme"); !errors.Is(err, journal.ErrNotFound) {
			t.Fatalf("%s produced a workflow: %v", tc.name, err)
		}
	}

	validated := httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_validate_workflow", map[string]any{
		"slug": "http-mcp-e2e", "main_go": mainGo, "dag": dag,
	})
	if validated.IsError || !strings.Contains(validated.Text, `"valid":true`) || !strings.Contains(validated.Text, `"persisted":false`) {
		t.Fatalf("validate response = %+v", validated)
	}

	created := httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_create_workflow", map[string]any{
		"slug": "http-mcp-e2e", "main_go": mainGo, "dag": dag,
	})
	if created.IsError || !strings.Contains(created.Text, `"built":true`) || !strings.Contains(created.Text, `"enabled":false`) || !strings.Contains(created.Text, `"artifact_status":"verified"`) {
		t.Fatalf("create response = %+v", created)
	}
	var createdReceipt struct {
		WorkflowID     string `json:"id"`
		ArtifactSHA256 string `json:"artifact_sha256"`
	}
	if err := json.Unmarshal([]byte(created.Text), &createdReceipt); err != nil {
		t.Fatalf("decode create receipt %q: %v", created.Text, err)
	}
	if createdReceipt.WorkflowID == "" || createdReceipt.ArtifactSHA256 == "" {
		t.Fatalf("create receipt omitted durable identity: %+v", createdReceipt)
	}
	// A second tenant may own the same slug, but the dedicated MCP bearer is
	// bound to acme. Seed that row with the same immutable artifact so this
	// check exercises the actual daemon tenant resolver and dispatch closure,
	// rather than only the journal's unscoped slug behavior.
	mainCodeSum := sha256.Sum256([]byte(mainGo))
	mainCodeHash := hex.EncodeToString(mainCodeSum[:])[:16]
	if err := deps.journal.CreateWorkflowInTenantWithArtifact(ctx, "wf_http_mcp_globex", "http-mcp-e2e", mainCodeHash, "0.1.0", createdReceipt.ArtifactSHA256, json.RawMessage(`{}`), "globex"); err != nil {
		t.Fatalf("create cross-tenant workflow: %v", err)
	}
	if err := deps.journal.CreateWorkflowInTenantWithArtifact(ctx, "wf_http_mcp_globex_only", "http-mcp-globex-only", mainCodeHash, "0.1.0", createdReceipt.ArtifactSHA256, json.RawMessage(`{}`), "globex"); err != nil {
		t.Fatalf("create cross-tenant-only workflow: %v", err)
	}
	if otherTenant := httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_review_workflow", map[string]any{"slug": "http-mcp-globex-only"}); !otherTenant.IsError {
		t.Fatalf("HTTP MCP bearer reviewed another tenant's workflow: %+v", otherTenant)
	}

	reviewed := httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_review_workflow", map[string]any{"slug": "http-mcp-e2e"})
	if reviewed.IsError {
		t.Fatalf("review response = %+v", reviewed)
	}
	var review struct {
		Version         int    `json:"version"`
		ReviewStatus    string `json:"review_status"`
		ArtifactStatus  string `json:"artifact_status"`
		SourceIntegrity string `json:"source_integrity"`
		Enabled         bool   `json:"enabled"`
	}
	if err := json.Unmarshal([]byte(reviewed.Text), &review); err != nil {
		t.Fatalf("decode review %q: %v", reviewed.Text, err)
	}
	if review.Version != 1 || review.ReviewStatus != "ready_for_review" || review.ArtifactStatus != "verified" || review.SourceIntegrity != "verified" || review.Enabled {
		t.Fatalf("review receipt = %+v", review)
	}
	var tenantView struct {
		TenantID string `json:"tenant_id"`
		ID       string `json:"workflow_id"`
	}
	if err := json.Unmarshal([]byte(reviewed.Text), &tenantView); err != nil {
		t.Fatalf("decode tenant review %q: %v", reviewed.Text, err)
	}
	if tenantView.TenantID != "acme" || tenantView.ID != createdReceipt.WorkflowID {
		t.Fatalf("HTTP MCP bearer crossed tenant boundary: review=%+v created=%+v", tenantView, createdReceipt)
	}

	flow := httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_get_workflow_flow", map[string]any{"slug": "http-mcp-e2e"})
	if flow.IsError || !strings.Contains(flow.Text, `"validated":true`) || !strings.Contains(flow.Text, `"visual_complete":true`) || !strings.Contains(flow.Text, `"artifact_status":"verified"`) {
		t.Fatalf("flow response = %+v", flow)
	}
	if err := deps.credRepo.Create(ctx, credentials.CreateParams{
		ID: "cred_http_mcp", TenantID: "acme", Name: "HTTP MCP acceptance credential",
		Service: "acceptance", Provider: "shared-secret",
	}); err != nil {
		t.Fatalf("create acceptance credential: %v", err)
	}
	if err := deps.credRepo.Create(ctx, credentials.CreateParams{
		ID: "cred_http_mcp_ungranted", TenantID: "acme", Name: "HTTP MCP denied credential",
		Service: "acceptance", Provider: "shared-secret",
	}); err != nil {
		t.Fatalf("create ungranted acceptance credential: %v", err)
	}
	if err := deps.credRepo.Create(ctx, credentials.CreateParams{
		ID: "cred_http_mcp_globex", TenantID: "globex", Name: "Other tenant credential",
		Service: "acceptance", Provider: "shared-secret",
	}); err != nil {
		t.Fatalf("create cross-tenant acceptance credential: %v", err)
	}
	for _, attemptedGrant := range []struct{ workflowID, credentialID string }{
		{"wf_http_mcp_globex", "cred_http_mcp"},
		{createdReceipt.WorkflowID, "cred_http_mcp_globex"},
	} {
		result := httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_grant_secret", map[string]any{
			"workflow_id": attemptedGrant.workflowID, "credential_id": attemptedGrant.credentialID,
		})
		if !result.IsError {
			t.Fatalf("HTTP MCP bearer granted cross-tenant credential access: %+v", attemptedGrant)
		}
	}
	for _, workflowID := range []string{"wf_http_mcp_globex", createdReceipt.WorkflowID} {
		grants, _, err := deps.journal.ListGrantsForWorkflowPageMetadata(ctx, workflowID, 10, 0)
		if err != nil {
			t.Fatalf("inspect cross-tenant grant outcome for %q: %v", workflowID, err)
		}
		if len(grants) != 0 {
			t.Fatalf("cross-tenant grant changed workflow %q: %+v", workflowID, grants)
		}
	}
	const grantedValue = "synthetic-http-mcp-granted-value-9b7f0ca1"
	const ungrantedValue = "synthetic-http-mcp-ungranted-value-613de8a4"
	for _, credential := range []struct{ id, value string }{
		{"cred_http_mcp", grantedValue},
		{"cred_http_mcp_ungranted", ungrantedValue},
	} {
		if err := deps.vaultStore.Put(ctx, credential.id, []byte(credential.value)); err != nil {
			t.Fatalf("seal acceptance credential %q: %v", credential.id, err)
		}
		var stored []byte
		if err := deps.db.QueryRowContext(ctx, `SELECT blob FROM credentials WHERE id = ?`, credential.id).Scan(&stored); err != nil {
			t.Fatalf("read sealed credential %q: %v", credential.id, err)
		}
		if bytes.Equal(stored, []byte(credential.value)) || bytes.Contains(stored, []byte(credential.value)) {
			t.Fatalf("credential %q was persisted in plaintext", credential.id)
		}
	}
	granted := httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_grant_secret", map[string]any{
		"workflow_id": createdReceipt.WorkflowID, "credential_id": "cred_http_mcp",
	})
	if granted.IsError || !strings.Contains(granted.Text, `"ok":true`) {
		t.Fatalf("grant response = %+v", granted)
	}
	reviewed = httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_review_workflow", map[string]any{"slug": "http-mcp-e2e"})
	if reviewed.IsError || !strings.Contains(reviewed.Text, `"credential_id":"cred_http_mcp"`) || !strings.Contains(reviewed.Text, `"secret_grants"`) {
		t.Fatalf("review after grant = %+v", reviewed)
	}
	if strings.Contains(reviewed.Text, grantedValue) || strings.Contains(reviewed.Text, ungrantedValue) {
		t.Fatal("review exposed a credential value")
	}

	enabled := httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_set_workflow_state", map[string]any{
		"slug": "http-mcp-e2e", "state": "enabled", "expected_state": "disabled", "expected_version": review.Version,
	})
	if enabled.IsError || !strings.Contains(enabled.Text, `"enabled":true`) || !strings.Contains(enabled.Text, `"artifact_status":"verified"`) {
		t.Fatalf("enable response = %+v", enabled)
	}
	preflight := httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_preflight_dispatch_workflow", map[string]any{"slug": "http-mcp-e2e"})
	if preflight.IsError || !strings.Contains(preflight.Text, `"durable_ready":true`) || !strings.Contains(preflight.Text, `"dispatchable_now":true`) {
		t.Fatalf("preflight response = %+v", preflight)
	}

	const sensitiveInput = "synthetic-customer-input-never-default-export-94ef2d1a"
	dispatched := httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_dispatch_workflow", map[string]any{
		"slug": "http-mcp-e2e", "payload": map[string]any{"source": "http-mcp", "private": sensitiveInput}, "idempotency_key": "http-mcp-e2e-1",
	})
	if dispatched.IsError {
		t.Fatalf("dispatch response = %+v", dispatched)
	}
	var dispatchReceipt struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal([]byte(dispatched.Text), &dispatchReceipt); err != nil {
		t.Fatalf("decode dispatch %q: %v", dispatched.Text, err)
	}
	if dispatchReceipt.RunID == "" {
		t.Fatalf("dispatch omitted run_id: %q", dispatched.Text)
	}

	// A retry after a lost HTTP response must converge on the original durable
	// run. Reusing that key with a different payload must fail closed instead
	// of silently attaching new data to the old run.
	retried := httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_dispatch_workflow", map[string]any{
		"slug": "http-mcp-e2e", "payload": map[string]any{"source": "http-mcp", "private": sensitiveInput}, "idempotency_key": "http-mcp-e2e-1",
	})
	if retried.IsError {
		t.Fatalf("idempotent retry errored: %+v", retried)
	}
	var retryReceipt struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal([]byte(retried.Text), &retryReceipt); err != nil {
		t.Fatalf("decode idempotent retry %q: %v", retried.Text, err)
	}
	if retryReceipt.RunID != dispatchReceipt.RunID {
		t.Fatalf("idempotent retry run_id=%q, want original %q", retryReceipt.RunID, dispatchReceipt.RunID)
	}
	drifted := httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_dispatch_workflow", map[string]any{
		"slug": "http-mcp-e2e", "payload": map[string]any{"source": "tampered"}, "idempotency_key": "http-mcp-e2e-1",
	})
	if !drifted.IsError {
		t.Fatalf("idempotency payload drift was accepted: %+v", drifted)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		run, getErr := deps.journal.GetRun(ctx, dispatchReceipt.RunID)
		if getErr != nil {
			t.Fatalf("get dispatched run: %v", getErr)
		}
		if run.Status == "succeeded" {
			if run.TenantID != "acme" {
				t.Fatalf("dispatch crossed bearer tenant boundary: run tenant=%q", run.TenantID)
			}
			if run.WorkflowVersion != review.Version || run.WorkflowArtifactSHA256 == "" {
				t.Fatalf("run receipt pins = version %d digest %q", run.WorkflowVersion, run.WorkflowArtifactSHA256)
			}
			break
		}
		if run.Status == "failed" || run.Status == "failed_dlq" || time.Now().After(deadline) {
			t.Fatalf("dispatched run did not succeed: status=%q run=%+v", run.Status, run)
		}
		time.Sleep(20 * time.Millisecond)
	}
	runView := httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_get_run", map[string]any{"run_id": dispatchReceipt.RunID})
	if runView.IsError || strings.Contains(runView.Text, sensitiveInput) ||
		!strings.Contains(runView.Text, `"trigger_meta_redacted":true`) ||
		!strings.Contains(runView.Text, `"output_redacted":true`) {
		t.Fatalf("default run view did not keep execution data opaque: is_error=%t body=%s", runView.IsError, runView.Text)
	}
	// Tool visibility is not the authorization boundary: try the exact-data
	// method directly over HTTP with this same bearer and no data-export scope.
	exactReadRequest, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 30, "method": "tools/call",
		"params": map[string]any{
			"name":      "reactor_get_run_input",
			"arguments": map[string]any{"run_id": dispatchReceipt.RunID},
		},
	})
	if err != nil {
		t.Fatalf("encode unscoped exact-read request: %v", err)
	}
	exactRead := httpMCPRequest(t, client, endpoint, cfg.mcpToken, exactReadRequest)
	var exactReadEnvelope struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(exactRead, &exactReadEnvelope); err != nil {
		t.Fatalf("decode unscoped exact-read refusal: %v", err)
	}
	if exactReadEnvelope.Error == nil || exactReadEnvelope.Error.Code != -32601 || bytes.Contains(exactRead, []byte(sensitiveInput)) {
		t.Fatalf("unscoped exact-read call escaped the MCP tool boundary: %s", exactRead)
	}

	audited := httpMCPCall(t, client, endpoint, cfg.mcpToken, "reactor_list_runtime_secret_access_audit", map[string]any{"limit": 10})
	if audited.IsError || strings.Contains(audited.Text, grantedValue) || strings.Contains(audited.Text, ungrantedValue) {
		t.Fatalf("runtime secret audit was unavailable or exposed a value: is_error=%t", audited.IsError)
	}
	var auditReceipt struct {
		Entries []journal.RuntimeSecretAccess `json:"entries"`
	}
	if err := json.Unmarshal([]byte(audited.Text), &auditReceipt); err != nil {
		t.Fatalf("decode runtime secret audit: %v", err)
	}
	if len(auditReceipt.Entries) != 1 {
		t.Fatalf("runtime secret access receipt count = %d, want one granted fetch", len(auditReceipt.Entries))
	}
	access := auditReceipt.Entries[0]
	if access.TenantID != "acme" || access.WorkflowID != createdReceipt.WorkflowID ||
		access.RunID != dispatchReceipt.RunID || access.SecretRef != "cred_http_mcp" ||
		access.SecretKind != "vault" || access.At.IsZero() {
		t.Fatalf("runtime secret access receipt identity = %+v", access)
	}
}

// inMemoryHTTPServer keeps this acceptance test on the real net/http server
// and client path without requiring an OS listener. The execution sandbox
// disallows loopback binds, which makes httptest.NewServer fall back to IPv6
// and panic before the handler is exercised. net.Pipe still covers HTTP
// parsing, middleware, authentication, routing, and MCP transport behavior.
type inMemoryHTTPServer struct {
	listener *inMemoryHTTPListener
	server   *http.Server
	client   *http.Client
	endpoint string
}

func startInMemoryHTTPServer(t *testing.T, handler http.Handler) *inMemoryHTTPServer {
	t.Helper()
	listener := newInMemoryHTTPListener()
	server := &http.Server{Handler: handler}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext:       listener.dialContext,
	}
	h := &inMemoryHTTPServer{
		listener: listener,
		server:   server,
		client:   &http.Client{Transport: transport},
		endpoint: "http://reactor-in-memory",
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Errorf("shut down in-memory HTTP server: %v", err)
		}
		if err := listener.Close(); err != nil {
			t.Errorf("close in-memory HTTP listener: %v", err)
		}
		select {
		case err := <-serveDone:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("serve in-memory HTTP server: %v", err)
			}
		case <-ctx.Done():
			t.Errorf("in-memory HTTP server did not stop: %v", ctx.Err())
		}
	})
	return h
}

func (s *inMemoryHTTPServer) Client() *http.Client { return s.client }

func (s *inMemoryHTTPServer) Endpoint() string { return s.endpoint }

func (s *inMemoryHTTPServer) Close() { s.client.CloseIdleConnections() }

type inMemoryHTTPListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newInMemoryHTTPListener() *inMemoryHTTPListener {
	return &inMemoryHTTPListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *inMemoryHTTPListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		if conn == nil {
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *inMemoryHTTPListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *inMemoryHTTPListener) Addr() net.Addr { return inMemoryHTTPAddr{} }

func (l *inMemoryHTTPListener) dialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	serverConn, clientConn := net.Pipe()
	select {
	case l.conns <- serverConn:
		return clientConn, nil
	case <-ctx.Done():
		serverConn.Close()
		clientConn.Close()
		return nil, ctx.Err()
	case <-l.closed:
		serverConn.Close()
		clientConn.Close()
		return nil, net.ErrClosed
	}
}

type inMemoryHTTPAddr struct{}

func (inMemoryHTTPAddr) Network() string { return "pipe" }

func (inMemoryHTTPAddr) String() string { return "reactor-in-memory" }

type httpMCPToolResult struct {
	Text    string
	IsError bool
}

func httpMCPCall(t *testing.T, client *http.Client, endpoint, token, name string, arguments map[string]any) httpMCPToolResult {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  map[string]any{"name": name, "arguments": arguments},
	})
	if err != nil {
		t.Fatalf("marshal MCP request: %v", err)
	}
	raw := httpMCPRequest(t, client, endpoint, token, body)
	var envelope struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text    string `json:"text"`
				IsError bool   `json:"isError"`
			} `json:"content"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode MCP %s response %q: %v", name, raw, err)
	}
	if envelope.Error != nil {
		t.Fatalf("MCP %s JSON-RPC error: %+v", name, envelope.Error)
	}
	if len(envelope.Result.Content) != 1 {
		t.Fatalf("MCP %s content = %s", name, raw)
	}
	return httpMCPToolResult{Text: envelope.Result.Content[0].Text, IsError: envelope.Result.IsError || envelope.Result.Content[0].IsError}
}

// httpMCPRequest exercises the same authenticated Streamable HTTP contract as
// a real MCP client: bearer identity, JSON content negotiation, and the
// protocol-version marker are all sent on every request.
func httpMCPRequest(t *testing.T, client *http.Client, endpoint, token string, body []byte) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build MCP request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(mcp.MCPProtocolVersionHeader, mcp.ProtocolVersion)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("MCP request: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read MCP response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("MCP HTTP status=%d body=%s", resp.StatusCode, raw)
	}
	return raw
}

func assertHTTPMCPBearerRejected(t *testing.T, client *http.Client, endpoint, authorization string, body []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build unauthorized MCP request: %v", err)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(mcp.MCPProtocolVersionHeader, mcp.ProtocolVersion)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unauthorized MCP request: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		t.Fatalf("read unauthorized MCP response: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != `Bearer realm="reactor-mcp"` ||
		bytes.Contains(raw, []byte(`"serverInfo"`)) || bytes.Contains(raw, []byte(`"tools"`)) || bytes.Contains(raw, []byte(`"built"`)) {
		t.Fatalf("MCP %s rejection failed: status=%d challenge=%q body=%s", authorization, resp.StatusCode, resp.Header.Get("WWW-Authenticate"), raw)
	}
}
