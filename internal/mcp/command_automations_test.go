package mcp

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	_ "modernc.org/sqlite"
)

func TestHTTPMCPCommandAutomationLifecycleIsNonExecutableAndVersioned(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true}
	refreshes := 0
	srv.GraphRefresh = func(context.Context) error {
		refreshes++
		return nil
	}
	definition := map[string]any{"steps": []map[string]any{
		{"name": "check", "command": "true", "purpose": "Check host", "timeout_seconds": 30, "expected_exit_code": 0},
		{"name": "verify", "command": "true", "purpose": "Verify host", "timeout_seconds": 30, "expected_exit_code": 0},
	}}

	created := callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{
		"name": "nightly-check", "description": "Check the host", "target": "ops-host", "definition": definition,
	}, false)
	if !strings.Contains(string(created), `"executable":false`) || !strings.Contains(string(created), `"version":1`) {
		t.Fatalf("create receipt = %s", created)
	}
	if refreshes != 1 {
		t.Fatalf("graph refreshes after create = %d, want 1", refreshes)
	}

	got := callOperationalTool(t, srv, "reactor_get_command_automation", map[string]any{"name": "nightly-check"}, false)
	if !strings.Contains(string(got), `"executable":false`) || !strings.Contains(string(got), `"kind":"command"`) || !strings.Contains(string(got), `"from":"check"`) {
		t.Fatalf("get receipt = %s", got)
	}
	// The schema treats version as optional, but an explicitly supplied null or
	// zero must not silently fall back to the current version. That ambiguity
	// could make a review request inspect a different immutable definition than
	// the caller intended.
	callOperationalTool(t, srv, "reactor_get_command_automation", map[string]any{"name": "nightly-check", "version": nil}, true)
	callOperationalTool(t, srv, "reactor_get_command_automation", map[string]any{"name": "nightly-check", "version": 0}, true)
	if strings.Contains(string(got), "run_id") {
		t.Fatalf("command plan unexpectedly dispatched: %s", got)
	}

	callOperationalTool(t, srv, "reactor_revise_command_automation", map[string]any{"name": "nightly-check", "expected_version": 99, "definition": definition}, true)
	definition["steps"] = []map[string]any{{"name": "verify", "command": "true", "purpose": "Verify host", "timeout_seconds": 30, "expected_exit_code": 0}}
	revised := callOperationalTool(t, srv, "reactor_revise_command_automation", map[string]any{"name": "nightly-check", "expected_version": 1, "definition": definition}, false)
	if !strings.Contains(string(revised), `"version":2`) {
		t.Fatalf("revision receipt = %s", revised)
	}

	list := callOperationalTool(t, srv, "reactor_list_command_automations", map[string]any{}, false)
	if !strings.Contains(string(list), "nightly-check") {
		t.Fatalf("list = %s", list)
	}
	callOperationalTool(t, srv, "reactor_delete_command_automation", map[string]any{"name": "nightly-check", "confirm_name": "nightly-check", "expected_version": 1}, true)
	callOperationalTool(t, srv, "reactor_delete_command_automation", map[string]any{"name": "nightly-check", "confirm_name": "nightly-check", "expected_version": 2}, false)
	callOperationalTool(t, srv, "reactor_get_command_automation", map[string]any{"name": "nightly-check"}, true)
}

func TestDecodeCommandArgsRejectsNonObjectPayloads(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{`null`, `[]`, `"text"`, `true`, `0`} {
		var args struct{}
		if err := decodeCommandArgs(json.RawMessage(raw), &args); !errors.Is(err, errInvalidParamsErr) {
			t.Fatalf("decodeCommandArgs(%s) = %v, want invalid params", raw, err)
		}
	}
	var args struct{}
	if err := decodeCommandArgs(json.RawMessage(`{}`), &args); err != nil {
		t.Fatalf("decodeCommandArgs({}) = %v, want success", err)
	}
}

func TestHTTPMCPCommandAutomationCreateRetryReturnsExistingReceipt(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true}
	definition := map[string]any{"steps": []map[string]any{{
		"name": "check", "command": "true", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0,
	}}}
	args := map[string]any{"name": "retry-safe-create", "description": "same", "target": "ops", "definition": definition}
	first := callOperationalTool(t, srv, "reactor_create_command_automation", args, false)
	var firstView struct {
		Automation struct {
			ID string `json:"id"`
		} `json:"automation"`
	}
	if err := json.Unmarshal(first, &firstView); err != nil || firstView.Automation.ID == "" {
		t.Fatalf("first create receipt=%s err=%v", first, err)
	}
	second := callOperationalTool(t, srv, "reactor_create_command_automation", args, false)
	if !strings.Contains(string(second), `"idempotent":true`) {
		t.Fatalf("retry receipt=%s; want idempotent replay", second)
	}
	var secondView struct {
		Automation struct {
			ID string `json:"id"`
		} `json:"automation"`
	}
	if err := json.Unmarshal(second, &secondView); err != nil || secondView.Automation.ID != firstView.Automation.ID {
		t.Fatalf("retry automation id=%q first=%q err=%v", secondView.Automation.ID, firstView.Automation.ID, err)
	}
	rows, more, err := j.ListCommandAutomationsPage(context.Background(), "acme", 10, 0)
	if err != nil || more || len(rows) != 1 {
		t.Fatalf("stored plans=%d more=%v err=%v; retry created a duplicate", len(rows), more, err)
	}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{
		"name": "retry-safe-create", "description": "changed", "target": "ops", "definition": definition,
	}, true)
}

func TestHTTPMCPCommandAutomationCreateExplicitIdempotencyKey(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true}
	definition := map[string]any{"steps": []map[string]any{{
		"name": "check", "command": "true", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0,
	}}}
	args := map[string]any{"name": "explicit-create-idem", "description": "same", "target": "ops", "definition": definition, "idempotency_key": "create-key-1"}
	first := callOperationalTool(t, srv, "reactor_create_command_automation", args, false)
	second := callOperationalTool(t, srv, "reactor_create_command_automation", args, false)
	if !strings.Contains(string(second), `"idempotent":true`) {
		t.Fatalf("explicit-key retry receipt=%s", second)
	}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{
		"name": "explicit-create-idem", "description": "changed", "target": "ops", "definition": definition, "idempotency_key": "create-key-1",
	}, true)
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{
		"name": "another-plan", "description": "same", "target": "ops", "definition": definition, "idempotency_key": "create-key-1",
	}, true)
	if strings.Contains(string(first), `"idempotent":true`) {
		t.Fatalf("first explicit create was marked replay: %s", first)
	}
	rows, more, err := j.ListCommandAutomationsPage(context.Background(), "acme", 10, 0)
	if err != nil || more || len(rows) != 1 {
		t.Fatalf("explicit-key create rows=%d more=%v err=%v", len(rows), more, err)
	}
}

func TestMCPCommandAutomationViewBoundsLegacyMetadata(t *testing.T) {
	plan := journal.CommandAutomation{
		ID: strings.Repeat("i", maxMCPRunIdentityBytes+37), TenantID: strings.Repeat("t", maxMCPRunIdentityBytes+19),
		Name: strings.Repeat("n", maxMCPRunIdentityBytes+11), Description: strings.Repeat("z", 4<<10+23),
		Target: strings.Repeat("h", maxMCPCommandRunTargetBytes+17), CreatedBy: strings.Repeat("a", maxMCPCommandRunActorBytes+29),
	}
	view := mcpCommandAutomationView(plan)
	for _, field := range []struct {
		name string
		max  int
		want string
	}{
		{"id", maxMCPRunIdentityBytes, "id_truncated"},
		{"tenant_id", maxMCPRunIdentityBytes, "tenant_id_truncated"},
		{"name", maxMCPRunIdentityBytes, "name_truncated"},
		{"description", 4 << 10, "description_truncated"},
		{"target", maxMCPCommandRunTargetBytes, "target_truncated"},
		{"created_by", maxMCPCommandRunActorBytes, "created_by_truncated"},
	} {
		value, ok := view[field.name].(string)
		if !ok || len(value) > field.max {
			t.Fatalf("%s=%q, want bounded string <= %d", field.name, value, field.max)
		}
		if view[field.want] != true {
			t.Fatalf("%s missing truncation marker: %#v", field.name, view)
		}
	}
	secret := "Authorization: Bearer " + strings.Repeat("s", 32)
	redacted := mcpCommandAutomationView(journal.CommandAutomation{Description: secret, Target: "ops@example.com"})
	for _, field := range []string{"description", "target"} {
		value, _ := redacted[field].(string)
		if strings.Contains(value, "Bearer "+strings.Repeat("s", 32)) || strings.Contains(value, "ops@example.com") {
			t.Fatalf("legacy metadata leaked secret in %s: %q", field, value)
		}
	}
}

func TestBoundMCPTextNeverExceedsByteCapAcrossUTF8Boundaries(t *testing.T) {
	for _, raw := range []string{"é", string([]byte{0xff, 0xfe})} {
		bounded, truncated, sourceBytes := boundMCPText(raw, 1)
		if !truncated || len([]byte(bounded)) > 1 || sourceBytes != len([]byte(raw)) {
			t.Fatalf("boundMCPText(%q) = %q truncated=%v bytes=%d", raw, bounded, truncated, sourceBytes)
		}
	}
}

func TestHTTPMCPCommandAutomationPreflightIsClosedByDefault(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true}
	definition := map[string]any{"steps": []map[string]any{{"name": "check", "command": "true", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0}}}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{"name": "preflight-closed", "definition": definition}, false)
	receipt := callOperationalTool(t, srv, "reactor_preflight_command_automation", map[string]any{"name": "preflight-closed"}, false)
	text := string(receipt)
	for _, want := range []string{`"executable":false`, `"status":"blocked"`, `"execution_eligible":false`, `"feature_flag"`, `"single_tenant"`, `"step_up_authorization"`, `"fixed_sandbox_profile"`, `"durable_audit"`, `"gate_digest":"`, `"point_in_time":true`, `"receipt_id":"cmdpreflight_v1_`} {
		if !strings.Contains(text, want) {
			t.Fatalf("closed preflight missing %s: %s", want, text)
		}
	}
	var result struct {
		DefinitionSHA256 string `json:"definition_sha256"`
		GateDigest       string `json:"gate_digest"`
		ReceiptID        string `json:"receipt_id"`
	}
	if err := json.Unmarshal(receipt, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.DefinitionSHA256) != 64 || len(result.GateDigest) != 64 || len(result.ReceiptID) != len("cmdpreflight_v1_")+64 {
		t.Fatalf("preflight binding lengths = %+v", result)
	}
	if strings.Contains(text, "run_id") {
		t.Fatalf("preflight unexpectedly created a run: %s", text)
	}
}

func TestHTTPMCPCommandAutomationPreflightReportsAllGatesReadyWithoutExecution(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true}
	srv.CommandExecutionCapabilities = func(context.Context, commandautomations.Definition) commandautomations.ExecutionCapabilities {
		return commandautomations.ExecutionCapabilities{
			FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true,
			StepUpAuthorized: true, SandboxProfileReady: true, VaultBoundaryReady: true,
			CredentialsSupported: true, OutputLimitsReady: true, AuditReady: true,
		}
	}
	definition := map[string]any{"steps": []map[string]any{{"name": "check", "command": "true", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0}}}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{"name": "preflight-ready", "definition": definition}, false)
	plan, err := j.GetCommandAutomationByName(context.Background(), "acme", "preflight-ready")
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(context.Background(), "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	receipt := callOperationalTool(t, srv, "reactor_preflight_command_automation", map[string]any{"name": "preflight-ready"}, false)
	text := string(receipt)
	for _, want := range []string{`"status":"blocked"`, `"gates_ready":true`, `"execution_eligible":false`, `"executable":false`, `"gate_digest":"`, `"receipt_id":"cmdpreflight_v1_`} {
		if !strings.Contains(text, want) {
			t.Fatalf("ready preflight missing %s: %s", want, text)
		}
	}
	if strings.Contains(text, `"missing_gates"`) || strings.Contains(text, "run_id") || strings.Contains(text, `"command":"true"`) || strings.Contains(text, `"definition_json"`) {
		t.Fatalf("ready preflight was not a read-only receipt: %s", text)
	}
}

func TestHTTPMCPCommandAutomationPreflightClosesConfiguredTenantMismatch(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true}
	srv.CommandTenantAllowed = func(context.Context) bool { return false }
	srv.CommandExecutionCapabilities = func(context.Context, commandautomations.Definition) commandautomations.ExecutionCapabilities {
		return commandautomations.ExecutionCapabilities{
			FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true,
			StepUpAuthorized: true, AutomationEnabled: true, SandboxProfileReady: true,
			VaultBoundaryReady: true, CredentialsSupported: true, OutputLimitsReady: true,
			AuditReady: true, RunnerReady: true,
		}
	}
	definition := map[string]any{"steps": []map[string]any{{"name": "check", "command": "true", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0}}}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{"name": "tenant-closed", "definition": definition}, false)
	plan, err := j.GetCommandAutomationByName(context.Background(), "acme", "tenant-closed")
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(context.Background(), "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	receipt := callOperationalTool(t, srv, "reactor_preflight_command_automation", map[string]any{"name": "tenant-closed"}, false)
	text := string(receipt)
	if !strings.Contains(text, `"executable":false`) || !strings.Contains(text, `"single_tenant"`) {
		t.Fatalf("tenant-mismatched preflight was executable: %s", receipt)
	}
}

func TestHTTPMCPCommandAutomationEnableClosesConfiguredTenantMismatch(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true, CommandExecution: true}
	srv.CommandTenantAllowed = func(context.Context) bool { return false }
	srv.CommandExecutionCapabilities = func(context.Context, commandautomations.Definition) commandautomations.ExecutionCapabilities {
		return commandautomations.ExecutionCapabilities{AdminAuthorized: true, StepUpAuthorized: true}
	}
	definition := map[string]any{"steps": []map[string]any{{"name": "check", "command": "true", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0}}}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{"name": "tenant-enable-closed", "definition": definition}, false)
	callOperationalTool(t, srv, "reactor_set_command_automation_state", map[string]any{"name": "tenant-enable-closed", "state": "enabled", "expected_version": 1}, true)
	plan, err := j.GetCommandAutomationByName(context.Background(), "acme", "tenant-enable-closed")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Enabled {
		t.Fatal("tenant-mismatched command plan was enabled")
	}
}

func TestHTTPMCPCommandAutomationPreflightClosesCredentialGatesWithoutTenantGrantResolver(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true}
	srv.CommandTargetAllowed = func(context.Context, string) bool { return true }
	srv.CommandExecutionCapabilities = func(context.Context, commandautomations.Definition) commandautomations.ExecutionCapabilities {
		return commandautomations.ExecutionCapabilities{
			FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true,
			StepUpAuthorized: true, SandboxProfileReady: true, VaultBoundaryReady: true,
			CredentialsSupported: true, OutputLimitsReady: true, AuditReady: true,
			RunnerReady: true,
		}
	}
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0,"credential_ids":["cred_missing"]}]}`)
	plan, err := j.CreateCommandAutomation(context.Background(), "acme", "cmd_credential_gates", "credential-gates", "", "ops-host", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(context.Background(), "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	receipt := callOperationalTool(t, srv, "reactor_preflight_command_automation", map[string]any{"name": "credential-gates"}, false)
	text := string(receipt)
	for _, want := range []string{`"executable":false`, `"vault_grant_boundary"`, `"credential_support"`, `"missing_credentials":["cred_missing"]`} {
		if !strings.Contains(text, want) {
			t.Fatalf("credential preflight missing %s: %s", want, receipt)
		}
	}
}

func TestHTTPMCPCommandPreflightMarksBrokerOnlyCredentialUnavailable(t *testing.T) {
	t.Parallel()
	srv, j, repo := newTestServer(t, false)
	srv.TenantID = "acme"
	ctx := context.Background()
	if err := repo.Create(ctx, credentials.CreateParams{ID: "cred_broker_only", TenantID: "acme", Name: "broker-only", Service: "salesforce"}); err != nil {
		t.Fatal(err)
	}
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0,"credential_ids":["cred_broker_only"]}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_broker_only", "broker-only", "", "ops-host", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.GrantCommandSecret(ctx, "acme", plan.ID, "cred_broker_only", "alice", ""); err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	srv.CommandTargetAllowed = func(context.Context, string) bool { return true }
	srv.CommandCredentialResolverReady = func(context.Context, string) bool { return false }
	srv.CommandExecutionCapabilities = func(context.Context, commandautomations.Definition) commandautomations.ExecutionCapabilities {
		return commandautomations.ExecutionCapabilities{
			FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true,
			StepUpAuthorized: true, SandboxProfileReady: true, VaultBoundaryReady: true,
			CredentialsSupported: true, OutputLimitsReady: true, AuditReady: true,
			RunnerReady: true, TargetReady: true,
		}
	}
	receipt := callOperationalTool(t, srv, "reactor_preflight_command_automation", map[string]any{"name": "broker-only"}, false)
	for _, want := range []string{`"executable":false`, `"status":"resolver_unavailable"`, `"missing_credentials":["cred_broker_only"]`, `"credential_support"`} {
		if !strings.Contains(string(receipt), want) {
			t.Fatalf("broker-only preflight missing %s: %s", want, receipt)
		}
	}
}

func TestHTTPMCPCommandAutomationRunBindsStoredDefinitionAndScope(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true, CommandExecution: true}
	srv.CommandExecutionCapabilities = func(context.Context, commandautomations.Definition) commandautomations.ExecutionCapabilities {
		return commandautomations.ExecutionCapabilities{FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true, StepUpAuthorized: true, SandboxProfileReady: true, VaultBoundaryReady: true, CredentialsSupported: true, OutputLimitsReady: true, AuditReady: true, RunnerReady: true}
	}
	var handed CommandRunAutomationRequest
	srv.RunCommandAutomation = func(_ context.Context, request CommandRunAutomationRequest) (journal.CommandRun, error) {
		handed = request
		return journal.CommandRun{ID: "cmdrun_mcp", TenantID: "acme", AutomationID: request.AutomationID, AutomationVersion: request.Version, Status: journal.CommandRunSucceeded, Admission: request.Admission}, nil
	}
	definition := map[string]any{"steps": []map[string]any{{"name": "check", "command": "true", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0}}}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{"name": "run-plan", "definition": definition}, false)
	plan, err := j.GetCommandAutomationByName(context.Background(), "acme", "run-plan")
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(context.Background(), "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	preflight := callOperationalTool(t, srv, "reactor_preflight_command_automation", map[string]any{"name": "run-plan", "version": 1}, false)
	var receipt struct {
		ReceiptID  string `json:"receipt_id"`
		GateDigest string `json:"gate_digest"`
	}
	if err := json.Unmarshal(preflight, &receipt); err != nil || receipt.ReceiptID == "" || receipt.GateDigest == "" {
		t.Fatalf("preflight = %s err=%v", preflight, err)
	}
	run := callOperationalTool(t, srv, "reactor_run_command_automation", map[string]any{"name": "run-plan", "version": 1, "receipt_id": receipt.ReceiptID, "gate_digest": receipt.GateDigest}, false)
	if !strings.Contains(string(run), `"run_id":"cmdrun_mcp"`) || !strings.Contains(string(run), `"status":"succeeded"`) {
		t.Fatalf("run receipt = %s", run)
	}
	if handed.AutomationID == "" || handed.Version != 1 || handed.Admission.DefinitionSHA256 == "" || handed.Admission.ActorID != "mcp" {
		t.Fatalf("runner handoff = %+v", handed)
	}
}

func TestHTTPMCPCommandRunWaitIsBoundedAndTenantScoped(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0}]}`)
	plan, err := j.CreateCommandAutomation(context.Background(), "acme", "cmd_wait", "wait-plan", "", "ops-host", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(context.Background(), "acme", plan.ID, true, false, 1); err != nil {
		t.Fatal(err)
	}
	_, normalized, err := commandautomations.Normalize(definition)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(normalized)
	definitionSHA256 := hex.EncodeToString(digest[:])
	gate := sha256.Sum256([]byte("wait-gates"))
	gateDigest := hex.EncodeToString(gate[:])
	admission := journal.CommandRunAdmission{
		ReceiptID:  commandautomations.ReceiptIDForGateDigest("acme", plan.ID, 1, definitionSHA256, gateDigest),
		GateDigest: gateDigest, DefinitionSHA256: definitionSHA256, ActorID: "alice",
	}
	ctx := context.Background()
	if _, err := j.CreateCommandRun(ctx, "acme", "cmdwait_timeout", plan.ID, 1, admission); err != nil {
		t.Fatal(err)
	}
	timedOut := callOperationalTool(t, srv, "reactor_wait_for_command_run", map[string]any{
		"run_id": "cmdwait_timeout", "timeout_seconds": 1,
	}, false)
	if !strings.Contains(string(timedOut), `"timed_out":true`) || strings.Contains(string(timedOut), `"terminal":true`) {
		t.Fatalf("bounded command wait = %s", timedOut)
	}

	if _, err := j.CreateCommandRun(ctx, "acme", "cmdwait_done", plan.ID, 1, admission); err != nil {
		t.Fatal(err)
	}
	go func() {
		t.Helper()
		claimed, claimErr := j.ClaimCommandRun(context.Background(), "cmdwait_done", "wait-worker", time.Minute)
		if claimErr != nil {
			t.Errorf("claim command run: %v", claimErr)
			return
		}
		if err := j.FinishCommandRun(context.Background(), "cmdwait_done", "wait-worker", claimed.ClaimToken, journal.CommandRunFailed, "test failure"); err != nil {
			t.Errorf("finish command run: %v", err)
		}
	}()
	completed := callOperationalTool(t, srv, "reactor_wait_for_command_run", map[string]any{
		"run_id": "cmdwait_done", "timeout_seconds": 2,
	}, false)
	if !strings.Contains(string(completed), `"status":"failed"`) || !strings.Contains(string(completed), `"terminal":true`) || strings.Contains(string(completed), `"timed_out":true`) {
		t.Fatalf("completed command wait = %s", completed)
	}

	srv.TenantID = "other"
	callOperationalTool(t, srv, "reactor_wait_for_command_run", map[string]any{"run_id": "cmdwait_done", "timeout_seconds": 1}, true)
}

func TestHTTPMCPCommandAutomationRetryRequiresTerminalCurrentPlanAndFreshRun(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true, CommandExecution: true}
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0}]}`)
	plan, err := j.CreateCommandAutomation(context.Background(), "acme", "cmd_retry", "retry-plan", "", "ops-host", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(context.Background(), "acme", plan.ID, true, false, 1); err != nil {
		t.Fatal(err)
	}
	_, normalized, err := commandautomations.Normalize(definition)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(normalized)
	definitionSHA256 := hex.EncodeToString(digest[:])
	gate := sha256.Sum256([]byte("retry-gates"))
	gateDigest := hex.EncodeToString(gate[:])
	admission := journal.CommandRunAdmission{
		ReceiptID:  commandautomations.ReceiptIDForGateDigest("acme", plan.ID, 1, definitionSHA256, gateDigest),
		GateDigest: gateDigest, DefinitionSHA256: definitionSHA256, ActorID: "alice",
	}
	ctx := context.Background()
	source, err := j.CreateCommandRun(ctx, "acme", "cmdrun_retry_source", plan.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimCommandRun(ctx, source.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.FinishCommandRun(ctx, source.ID, "worker-a", claimed.ClaimToken, journal.CommandRunFailed, "step failed"); err != nil {
		t.Fatal(err)
	}

	var handed CommandRunAutomationRequest
	var calls int
	srv.RunCommandAutomation = func(runCtx context.Context, request CommandRunAutomationRequest) (journal.CommandRun, error) {
		calls++
		handed = request
		return j.CreateCommandRunWithRetryOf(runCtx, "acme", request.RunID, request.AutomationID, request.Version, request.Admission, request.RetryOf)
	}
	retryArgs := map[string]any{
		"run_id": "cmdrun_retry_source", "receipt_id": admission.ReceiptID, "gate_digest": admission.GateDigest, "new_run_id": "cmdrun_retry_new",
	}
	raw := callOperationalTool(t, srv, "reactor_retry_command_run", retryArgs, false)
	if strings.Count(string(raw), `"retry_of":"cmdrun_retry_source"`) < 2 || !strings.Contains(string(raw), `"run_id":"cmdrun_retry_new"`) {
		t.Fatalf("retry receipt = %s", raw)
	}
	if calls != 1 || handed.AutomationID != plan.ID || handed.Version != 1 || handed.RunID != "cmdrun_retry_new" || handed.RetryOf != source.ID || handed.Admission.DefinitionSHA256 != definitionSHA256 || handed.Admission.ReceiptID != admission.ReceiptID {
		t.Fatalf("retry handoff = %+v", handed)
	}
	// A lost HTTP response must converge on the existing durable retry rather
	// than enqueueing a second attempt. This remains safe after an emergency
	// disable because it only returns an already-admitted receipt.
	repeated := callOperationalTool(t, srv, "reactor_retry_command_run", retryArgs, false)
	if !strings.Contains(string(repeated), `"run_id":"cmdrun_retry_new"`) || !strings.Contains(string(repeated), "matched an existing durable retry receipt") || calls != 1 {
		t.Fatalf("idempotent retry repeated receipt=%s calls=%d", repeated, calls)
	}
	callOperationalTool(t, srv, "reactor_retry_command_run", map[string]any{"run_id": source.ID, "receipt_id": admission.ReceiptID, "gate_digest": admission.GateDigest, "new_run_id": source.ID}, true)
	collision, err := j.CreateCommandRun(ctx, "acme", "cmdrun_retry_collision", plan.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	callOperationalTool(t, srv, "reactor_retry_command_run", map[string]any{"run_id": source.ID, "receipt_id": admission.ReceiptID, "gate_digest": admission.GateDigest, "new_run_id": collision.ID}, true)

	// A queued run is not a retry source, and disabling the exact plan closes
	// the operation even when the source itself is terminal.
	queued, err := j.CreateCommandRun(ctx, "acme", "cmdrun_retry_queued", plan.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	callOperationalTool(t, srv, "reactor_retry_command_run", map[string]any{"run_id": queued.ID, "receipt_id": admission.ReceiptID, "gate_digest": admission.GateDigest}, true)
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, false, true, 1); err != nil {
		t.Fatal(err)
	}
	if disabledRepeat := callOperationalTool(t, srv, "reactor_retry_command_run", retryArgs, false); !strings.Contains(string(disabledRepeat), `"run_id":"cmdrun_retry_new"`) || !strings.Contains(string(disabledRepeat), "matched an existing durable retry receipt") || calls != 1 {
		t.Fatalf("disabled idempotent retry receipt=%s calls=%d", disabledRepeat, calls)
	}
	callOperationalTool(t, srv, "reactor_retry_command_run", map[string]any{"run_id": source.ID, "receipt_id": admission.ReceiptID, "gate_digest": admission.GateDigest}, true)
	srv.TenantID = "other"
	callOperationalTool(t, srv, "reactor_retry_command_run", map[string]any{"run_id": source.ID, "receipt_id": admission.ReceiptID, "gate_digest": admission.GateDigest}, true)
}

func TestHTTPMCPCommandRunCancellationIsScopedAndAudited(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{CommandExecution: true}
	var handed CommandRunCancelRequest
	srv.CancelCommandRun = func(_ context.Context, request CommandRunCancelRequest) (journal.CommandRun, string, error) {
		handed = request
		return journal.CommandRun{ID: request.RunID, TenantID: "acme", Status: journal.CommandRunCancelled}, journal.CommandCancelDone, nil
	}
	result := callOperationalTool(t, srv, "reactor_cancel_command_run", map[string]any{"run_id": "cmdrun_stop", "reason": "operator stop"}, false)
	if handed.RunID != "cmdrun_stop" || handed.Reason != "operator stop" {
		t.Fatalf("cancel handoff = %+v", handed)
	}
	text := string(result)
	if !strings.Contains(text, `"status":"cancelled"`) || !strings.Contains(text, `"outcome":"cancelled"`) || !strings.Contains(text, `"executable":false`) {
		t.Fatalf("cancel receipt = %s", text)
	}
	callOperationalTool(t, srv, "reactor_cancel_command_run", map[string]any{"run_id": "cmdrun_stop", "unknown": true}, true)
}

func TestHTTPMCPCommandAutomationEnableRequiresStepUpAndFencesRevision(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true, CommandExecution: true}
	stepUp := false
	srv.CommandExecutionCapabilities = func(context.Context, commandautomations.Definition) commandautomations.ExecutionCapabilities {
		return commandautomations.ExecutionCapabilities{AdminAuthorized: true, StepUpAuthorized: stepUp}
	}
	definition := map[string]any{"steps": []map[string]any{{"name": "check", "command": "true", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0}}}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{"name": "state-plan", "definition": definition}, false)
	callOperationalTool(t, srv, "reactor_set_command_automation_state", map[string]any{"name": "state-plan", "state": "enabled", "expected_version": 1}, true)
	stepUp = true
	enabled := callOperationalTool(t, srv, "reactor_set_command_automation_state", map[string]any{"name": "state-plan", "state": "enabled", "expected_state": "disabled", "expected_version": 1}, false)
	if !strings.Contains(string(enabled), `"enabled":true`) {
		t.Fatalf("enable receipt = %s", enabled)
	}
	plan, err := j.GetCommandAutomationByName(context.Background(), "acme", "state-plan")
	if err != nil || !plan.Enabled {
		t.Fatalf("enabled plan = %+v err=%v", plan, err)
	}
	callOperationalTool(t, srv, "reactor_revise_command_automation", map[string]any{"name": "state-plan", "expected_version": 1, "definition": definition}, true)
	callOperationalTool(t, srv, "reactor_set_command_automation_state", map[string]any{"name": "state-plan", "state": "disabled", "expected_state": "enabled", "expected_version": 1}, false)
}

func TestHTTPMCPCommandAutomationPreflightBindsExactVersionAndGateResult(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true}
	definition := map[string]any{"steps": []map[string]any{{"name": "check", "command": "true", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0}}}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{"name": "binding-version", "definition": definition}, false)
	type binding struct {
		AutomationID     string `json:"automation_id"`
		Version          int    `json:"version"`
		DefinitionSHA256 string `json:"definition_sha256"`
		GateDigest       string `json:"gate_digest"`
		ReceiptID        string `json:"receipt_id"`
		Executable       bool   `json:"executable"`
	}
	read := func(version any) binding {
		t.Helper()
		args := map[string]any{"name": "binding-version"}
		if version != nil {
			args["version"] = version
		}
		raw := callOperationalTool(t, srv, "reactor_preflight_command_automation", args, false)
		var got binding
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if got.ReceiptID == "" || got.GateDigest == "" || got.Executable {
			t.Fatalf("invalid preflight binding: %s", raw)
		}
		return got
	}
	first := read(nil)
	if first != read(1) {
		t.Fatal("explicit immutable version changed its preflight binding")
	}
	plan, err := j.GetCommandAutomationByName(context.Background(), "acme", "binding-version")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := j.GetCommandAutomationVersion(context.Background(), "acme", plan.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, normalized, err := commandautomations.Normalize(stored.DefinitionJSON)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(normalized)
	if first.DefinitionSHA256 != hex.EncodeToString(sum[:]) || first.AutomationID != plan.ID || first.Version != 1 {
		t.Fatalf("preflight did not bind stored version: %+v", first)
	}
	definition["steps"] = []map[string]any{{"name": "check", "command": "false", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0}}
	callOperationalTool(t, srv, "reactor_revise_command_automation", map[string]any{"name": "binding-version", "expected_version": 1, "definition": definition}, false)
	second := read(nil)
	if second.Version != 2 || second.DefinitionSHA256 == first.DefinitionSHA256 || second.ReceiptID == first.ReceiptID || second.GateDigest == first.GateDigest {
		t.Fatalf("revised definition reused preflight binding: first=%+v second=%+v", first, second)
	}
	if first != read(1) {
		t.Fatal("historical immutable version changed after revision")
	}
	srv.CommandExecutionCapabilities = func(context.Context, commandautomations.Definition) commandautomations.ExecutionCapabilities {
		return commandautomations.ExecutionCapabilities{FeatureEnabled: true}
	}
	changedGate := read(1)
	if changedGate.DefinitionSHA256 != first.DefinitionSHA256 || changedGate.GateDigest == first.GateDigest || changedGate.ReceiptID == first.ReceiptID {
		t.Fatalf("changed gates reused preflight binding: first=%+v changed=%+v", first, changedGate)
	}
}

func TestHTTPMCPCommandAutomationExecutionRejectsHistoricalEnabledVersion(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true, CommandExecution: true}
	srv.CommandTargetAllowed = func(context.Context, string) bool { return true }
	srv.CommandExecutionCapabilities = func(context.Context, commandautomations.Definition) commandautomations.ExecutionCapabilities {
		return commandautomations.ExecutionCapabilities{
			FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true,
			StepUpAuthorized: true, SandboxProfileReady: true, VaultBoundaryReady: true,
			CredentialsSupported: true, OutputLimitsReady: true, AuditReady: true,
			RunnerReady: true,
		}
	}
	called := false
	srv.RunCommandAutomation = func(context.Context, CommandRunAutomationRequest) (journal.CommandRun, error) {
		called = true
		return journal.CommandRun{ID: "unexpected", Status: journal.CommandRunSucceeded}, nil
	}
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0}]}`)
	created, err := j.CreateCommandAutomation(context.Background(), "acme", "cmd_historical", "historical-plan", "", "ops-host", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(context.Background(), "acme", created.ID, true, false, 1); err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(context.Background(), "acme", created.ID, false, true, 1); err != nil {
		t.Fatal(err)
	}
	revisedDefinition := json.RawMessage(`{"steps":[{"name":"check","command":"false","purpose":"Check","timeout_seconds":30,"expected_exit_code":1}]}`)
	if _, err := j.AppendCommandAutomationVersion(context.Background(), "acme", created.ID, "alice", 1, revisedDefinition); err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(context.Background(), "acme", created.ID, true, false, 2); err != nil {
		t.Fatal(err)
	}

	preflight := callOperationalTool(t, srv, "reactor_preflight_command_automation", map[string]any{"name": "historical-plan", "version": 1}, false)
	text := string(preflight)
	for _, want := range []string{`"version_current":false`, `"current_version":2`, `"executable":false`, `"automation_enabled"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("historical preflight missing %s: %s", want, text)
		}
	}
	callOperationalTool(t, srv, "reactor_run_command_automation", map[string]any{
		"name": "historical-plan", "version": 1, "receipt_id": "receipt", "gate_digest": "digest",
	}, true)
	if called {
		t.Fatal("historical version reached the command runner")
	}
}

func TestHTTPMCPCommandRunInspectionIsTenantScopedBoundedAndNonExecuting(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	ctx := context.Background()
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	automation, err := j.CreateCommandAutomation(ctx, "acme", "cmd_inspect", "inspect-plan", "", "ops-host", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", automation.ID, true, false, automation.CurrentVersion); err != nil {
		t.Fatalf("enable inspection command plan: %v", err)
	}
	_, normalized, err := commandautomations.Normalize(definition)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(normalized)
	definitionSHA256 := hex.EncodeToString(digest[:])
	gate := sha256.Sum256([]byte("inspection-gates"))
	gateDigest := hex.EncodeToString(gate[:])
	run, err := j.CreateCommandRun(ctx, "acme", "cmdrun_inspect", automation.ID, 1, journal.CommandRunAdmission{
		ReceiptID:  commandautomations.ReceiptIDForGateDigest("acme", automation.ID, 1, definitionSHA256, gateDigest),
		GateDigest: gateDigest, DefinitionSHA256: definitionSHA256, ActorID: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimCommandRun(ctx, run.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.ClaimCommandRunStep(ctx, run.ID, "worker-a", claimed.ClaimToken, 1); err != nil {
		t.Fatal(err)
	}
	large := []byte(strings.Repeat("x", maxMCPCommandRunOutputBytes+32))
	stepError := "opaque-customer-step-error"
	stderr := "opaque-customer-stderr-å界"
	parentError := "opaque-customer-parent-error"
	if err := j.RecordCommandRunStepResult(ctx, run.ID, "worker-a", claimed.ClaimToken, 1, 1, 1, large, []byte(stderr), stepError); err != nil {
		t.Fatal(err)
	}
	if err := j.FinishCommandRun(ctx, run.ID, "worker-a", claimed.ClaimToken, journal.CommandRunFailed, parentError); err != nil {
		t.Fatal(err)
	}
	listed := callOperationalTool(t, srv, "reactor_list_command_runs", map[string]any{"limit": 1}, false)
	var list struct {
		Runs       []map[string]any `json:"runs"`
		HasMore    bool             `json:"has_more"`
		Executable bool             `json:"executable"`
	}
	if err := json.Unmarshal(listed, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Runs) != 1 || list.Runs[0]["run_id"] != run.ID || list.Executable || list.Runs[0]["claim_token"] != nil || list.Runs[0]["error_redacted"] != true || strings.Contains(string(listed), parentError) {
		t.Fatalf("command run list = %s", listed)
	}
	if admission, ok := list.Runs[0]["admission"].(map[string]any); !ok || admission["gate_digest"] != gateDigest || admission["receipt_id"] == "" {
		t.Fatalf("command run admission binding missing: %s", listed)
	}
	got := callOperationalTool(t, srv, "reactor_get_command_run", map[string]any{"run_id": run.ID, "limit": 1}, false)
	var detail struct {
		Run        map[string]any   `json:"run"`
		Steps      []map[string]any `json:"steps"`
		Executable bool             `json:"executable"`
	}
	if err := json.Unmarshal(got, &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Executable || len(detail.Steps) != 1 || detail.Run["run_id"] != run.ID || detail.Run["claim_token"] != nil {
		t.Fatalf("command run detail = %s", got)
	}
	step := detail.Steps[0]
	if step["stdout_text"] != nil || step["stderr_text"] != nil || step["error_text"] != nil || step["stdout_redacted"] != true || step["stderr_redacted"] != true || step["error_redacted"] != true || step["stdout_truncated"] != false || step["stdout_bytes"] != float64(len(large)) || step["command"] != nil || strings.Contains(string(got), stepError) || strings.Contains(string(got), stderr) || strings.Contains(string(got), parentError) {
		t.Fatalf("command run output was not bounded or command text leaked: %s", got)
	}
	waited := callOperationalTool(t, srv, "reactor_wait_for_command_run", map[string]any{"run_id": run.ID}, false)
	if strings.Contains(string(waited), parentError) || !strings.Contains(string(waited), `"terminal":true`) {
		t.Fatalf("command run wait exposed parent error or lost status: %s", waited)
	}
	callOperationalTool(t, srv, "reactor_get_command_run_diagnostics", map[string]any{"run_id": run.ID, "source": "run_error"}, true)
	scoped := &Server{Journal: j, TenantID: "acme", Scopes: &WriteScopes{DataExport: true}}
	page := callOperationalTool(t, scoped, "reactor_get_command_run_diagnostics", map[string]any{"run_id": run.ID, "source": "stderr", "step_seq": 1, "attempt": 1, "limit_bytes": 2}, false)
	var diagnostic struct {
		ContentBase64   string `json:"content_base64"`
		NextOffsetBytes int    `json:"next_offset_bytes"`
		HasMore         bool   `json:"has_more"`
		TotalBytes      int    `json:"total_bytes"`
	}
	if err := json.Unmarshal(page, &diagnostic); err != nil {
		t.Fatal(err)
	}
	first, err := base64.StdEncoding.DecodeString(diagnostic.ContentBase64)
	if err != nil || string(first) != stderr[:2] || !diagnostic.HasMore || diagnostic.NextOffsetBytes != 2 || diagnostic.TotalBytes != len(stderr) {
		t.Fatalf("command diagnostic page = %s, err=%v", page, err)
	}
	for source, want := range map[string]string{"run_error": parentError, "step_error": stepError} {
		args := map[string]any{"run_id": run.ID, "source": source}
		if source == "step_error" {
			args["step_seq"], args["attempt"] = 1, 1
		}
		raw := callOperationalTool(t, scoped, "reactor_get_command_run_diagnostics", args, false)
		if !strings.Contains(string(raw), base64.StdEncoding.EncodeToString([]byte(want))) {
			t.Fatalf("%s did not return exact persisted text: %s", source, raw)
		}
	}
	callOperationalTool(t, scoped, "reactor_get_command_run_diagnostics", map[string]any{"run_id": run.ID, "source": "stdout", "step_seq": 1, "attempt": 2}, true)
	callOperationalTool(t, scoped, "reactor_get_command_run_diagnostics", map[string]any{"run_id": run.ID, "source": "run_error", "step_seq": 1}, true)
	callOperationalTool(t, scoped, "reactor_get_command_run_diagnostics", map[string]any{"run_id": run.ID, "source": "run_error", "limit_bytes": 0}, true)
	callOperationalTool(t, scoped, "reactor_get_command_run_diagnostics", map[string]any{"run_id": run.ID, "source": "run_error", "offset_bytes": nil}, true)
	srv.TenantID = "other"
	scoped.TenantID = "other"
	callOperationalTool(t, srv, "reactor_list_command_runs", map[string]any{}, false)
	callOperationalTool(t, srv, "reactor_get_command_run", map[string]any{"run_id": run.ID}, true)
	callOperationalTool(t, scoped, "reactor_get_command_run_diagnostics", map[string]any{"run_id": run.ID, "source": "run_error"}, true)
}

func TestMCPCommandRunStepViewReportsOmittedErrorMetadata(t *testing.T) {
	step := journal.CommandRunStep{
		RunID:          "cmdrun_error_bound",
		StepSeq:        1,
		StepName:       "check",
		Status:         journal.CommandRunStepFailed,
		ErrorBytes:     16384,
		ErrorTruncated: true,
	}
	view := mcpCommandRunStepView(step)
	if _, ok := view["error_text"]; ok {
		t.Fatalf("omitted command error was exposed: %#v", view["error_text"])
	}
	if view["error_redacted"] != true || view["error_bytes"] != step.ErrorBytes {
		t.Fatalf("command error omission metadata = %#v, want redacted bytes=%d", view, step.ErrorBytes)
	}
}

func TestMCPCommandRunStepViewNeverReturnsLegacyOutput(t *testing.T) {
	secret := "Authorization: Bearer " + strings.Repeat("s", 32)
	rawStdout := secret + strings.Repeat("å", maxMCPCommandRunOutputBytes)
	rawStderr := strings.Repeat("界", maxMCPCommandRunOutputBytes)
	view := mcpCommandRunStepView(journal.CommandRunStep{
		RunID:         "legacy-output",
		StepName:      "check",
		CommandSHA256: strings.Repeat("h", maxMCPRunIdentityBytes+32),
		StdoutText:    rawStdout,
		StdoutBytes:   1, // stale imported metadata must not under-report the value
		StderrText:    rawStderr,
		StderrBytes:   1,
	})
	if view["stdout_text"] != nil || view["stderr_text"] != nil || view["stdout_redacted"] != true || view["stderr_redacted"] != true || view["stdout_bytes"] != len([]byte(rawStdout)) || view["stderr_bytes"] != len([]byte(rawStderr)) {
		t.Fatalf("legacy output projection = %#v", view)
	}
	if len(view["command_sha256"].(string)) > maxMCPRunIdentityBytes || view["command_sha256_truncated"] != true {
		t.Fatalf("command digest projection = %#v", view)
	}
}

func TestMCPCommandRunViewReportsOmittedErrorMetadata(t *testing.T) {
	run := journal.CommandRun{
		ID:             "cmdrun_parent_error_bound",
		TenantID:       "acme",
		AutomationID:   "cmd_parent_error",
		Status:         journal.CommandRunFailed,
		ErrorBytes:     journal.MaxCommandErrorBytes + 37,
		ErrorTruncated: true,
	}
	view := mcpCommandRunView(run)
	if _, ok := view["error_text"]; ok {
		t.Fatalf("omitted parent command error was exposed: %#v", view["error_text"])
	}
	if view["error_redacted"] != true || view["error_truncated"] != true || view["error_bytes"] != run.ErrorBytes {
		t.Fatalf("parent command error omission metadata = %#v, want redacted/truncated bytes=%d", view, run.ErrorBytes)
	}
}

func TestMCPCommandRunViewNeverReturnsLegacyParentError(t *testing.T) {
	secret := "Authorization: Bearer " + strings.Repeat("s", 32)
	view := mcpCommandRunView(journal.CommandRun{
		ID: "cmdrun_parent_error_legacy", ErrorText: "sandbox failed: " + secret,
	})
	if view["error_text"] != nil || view["error_redacted"] != true || view["error_bytes"] != len("sandbox failed: "+secret) {
		t.Fatalf("legacy parent command error projection = %#v", view)
	}
}

func TestMCPCommandRunViewRedactsFreeformRunMetadata(t *testing.T) {
	view := mcpCommandRunView(journal.CommandRun{
		ID: "cmdrun_metadata", TenantID: "acme", AutomationID: "cmd_metadata",
		Target: "opaque-customer-target", ActorID: "customer@example.test",
		Admission: journal.CommandRunAdmission{
			TriggerID: "trigger_1", TriggerEventID: "opaque-customer-event",
			ActorID: "customer@example.test",
		},
	})
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"opaque-customer-target", "customer@example.test", "opaque-customer-event"} {
		if strings.Contains(string(raw), private) {
			t.Fatalf("freeform run metadata escaped default MCP view: %s", raw)
		}
	}
	admission := view["admission"].(map[string]any)
	if view["run_id"] != "cmdrun_metadata" || view["automation_id"] != "cmd_metadata" || view["target_redacted"] != true || view["actor_id_redacted"] != true || admission["trigger_id"] != "trigger_1" || admission["trigger_event_id_redacted"] != true || admission["actor_id_redacted"] != true {
		t.Fatalf("run correlation/redaction receipt = %#v", view)
	}
}

func TestMCPCommandRunViewsRedactLegacyFreeformIDs(t *testing.T) {
	private := "customer secret in legacy id"
	run := mcpCommandRunView(journal.CommandRun{ID: private, RetryOf: private, TenantID: "acme"})
	step := mcpCommandRunStepView(journal.CommandRunStep{RunID: private, StepName: "check"})
	for name, view := range map[string]map[string]any{"run": run, "step": step} {
		raw, err := json.Marshal(view)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), private) || view["run_id"] != "" || view["run_id_redacted"] != true || view["run_id_bytes"] != len(private) {
			t.Fatalf("%s exposed legacy run ID: %s", name, raw)
		}
	}
	if run["retry_of"] != "" || run["retry_of_redacted"] != true {
		t.Fatalf("legacy retry ID exposed: %#v", run)
	}
}

func TestMCPCommandDiagnosticExportAuditFailsClosed(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "command-audit.db")
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), "sqlite://"+dbPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	j := journal.New(db, journal.EngineSQLite)
	s := &Server{Journal: j, TenantID: "acme", Scopes: &WriteScopes{DataExport: true}}
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	automation, err := j.CreateCommandAutomation(ctx, "acme", "cmd_diag_audit", "diag-audit", "", "ops-host", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", automation.ID, true, false, automation.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	_, normalized, err := commandautomations.Normalize(definition)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(normalized)
	gate := sha256.Sum256([]byte("diag-audit-gates"))
	definitionSHA256, gateDigest := hex.EncodeToString(digest[:]), hex.EncodeToString(gate[:])
	run, err := j.CreateCommandRun(ctx, "acme", "cmdrun_diag_audit", automation.ID, 1, journal.CommandRunAdmission{
		ReceiptID:  commandautomations.ReceiptIDForGateDigest("acme", automation.ID, 1, definitionSHA256, gateDigest),
		GateDigest: gateDigest, DefinitionSHA256: definitionSHA256, ActorID: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimCommandRun(ctx, run.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.ClaimCommandRunStep(ctx, run.ID, "worker-a", claimed.ClaimToken, 1); err != nil {
		t.Fatal(err)
	}
	secret := "opaque-customer-diagnostic-value"
	if err := j.RecordCommandRunStepResult(ctx, run.ID, "worker-a", claimed.ClaimToken, 1, 1, 0, []byte(secret), nil, ""); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"run_id": run.ID, "source": "stdout", "step_seq": 1, "attempt": 1}
	raw := callOperationalTool(t, s, "reactor_get_command_run_diagnostics", args, false)
	if !strings.Contains(string(raw), base64.StdEncoding.EncodeToString([]byte(secret))) {
		t.Fatalf("scoped diagnostic did not return persisted bytes: %s", raw)
	}
	entries, err := j.ListMCPAuditForTenant(ctx, "acme", 10, 0)
	if err != nil || len(entries) != 1 || entries[0].ToolName != "reactor_get_command_run_diagnostics" || entries[0].Outcome != "succeeded" || strings.Contains(entries[0].Target, secret) || strings.Contains(string(entries[0].Detail), secret) {
		t.Fatalf("diagnostic audit = %+v, err=%v", entries, err)
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE mcp_audit"); err != nil {
		t.Fatal(err)
	}
	failed := callOperationalTool(t, s, "reactor_get_command_run_diagnostics", args, true)
	if !strings.Contains(string(failed), "data-export audit unavailable") || strings.Contains(string(failed), secret) || strings.Contains(string(failed), base64.StdEncoding.EncodeToString([]byte(secret))) {
		t.Fatalf("diagnostic escaped failed audit boundary: %s", failed)
	}
}

func TestHTTPMCPCommandAutomationRejectsSecretAndUnknownFields(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, false)
	srv.Scopes = &WriteScopes{Authoring: true}
	base := map[string]any{"steps": []map[string]any{{"name": "check", "command": "true", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0}}}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{"name": "bad-fields", "definition": base, "unexpected": true}, true)
	base["steps"] = []map[string]any{{"name": "check", "command": "echo password=abcdefghijklmnop", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0}}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{"name": "inline-secret", "definition": base}, true)
}

func TestHTTPMCPCommandAutomationMetadataValidationMatchesSchema(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true}
	definition := map[string]any{"steps": []map[string]any{{"name": "check", "command": "true", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0}}}
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{name: "invalid name", args: map[string]any{"name": "Bad Name", "definition": definition}},
		{name: "description too long", args: map[string]any{"name": "too-long-description", "description": strings.Repeat("d", 4097), "definition": definition}},
		{name: "target too long", args: map[string]any{"name": "too-long-target", "target": strings.Repeat("t", 257), "definition": definition}},
	} {
		callOperationalTool(t, srv, "reactor_create_command_automation", tc.args, true)
	}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{
		"name": "metadata-validation", "definition": definition,
	}, false)
	for _, expectedVersion := range []int{0, -1} {
		callOperationalTool(t, srv, "reactor_revise_command_automation", map[string]any{
			"name": "metadata-validation", "expected_version": expectedVersion, "definition": definition,
		}, true)
	}
	callOperationalTool(t, srv, "reactor_revise_command_automation", map[string]any{
		"name": "Bad Name", "expected_version": 1, "definition": definition,
	}, true)
}

func TestCommandAutomationArgumentsRejectDuplicateFields(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, false)
	srv.Scopes = &WriteScopes{Authoring: true}
	srv.registerTools()
	handler := srv.tools["reactor_create_command_automation"].handler

	for _, raw := range []string{
		`{"name":"duplicate-name","definition":{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0}]},"name":"overwritten-name"}`,
		`{"name":"duplicate-step","definition":{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0,"command":"false"}]}}`,
	} {
		if _, err := handler(context.Background(), json.RawMessage(raw)); !errors.Is(err, errInvalidParamsErr) {
			t.Fatalf("duplicate command arguments %s error = %v, want invalid params", raw, err)
		}
	}
}

func TestHTTPMCPCommandAutomationFlowResourceIsTenantScopedAndNonExecutable(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true}
	definition := map[string]any{"steps": []map[string]any{
		{"name": "prepare", "command": "true", "purpose": "Prepare", "timeout_seconds": 30, "expected_exit_code": 0},
		{"name": "verify", "command": "true", "purpose": "Verify", "timeout_seconds": 30, "expected_exit_code": 0},
	}}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{"name": "resource-plan", "definition": definition}, false)
	resource, err := srv.readResource(context.Background(), "reactor://command-automations/resource-plan/flow")
	if err != nil {
		t.Fatal(err)
	}
	contents, ok := resource["contents"].([]map[string]any)
	if !ok || len(contents) != 1 {
		t.Fatalf("resource contents = %#v", resource["contents"])
	}
	text, ok := contents[0]["text"].(string)
	if !ok {
		t.Fatalf("resource text = %#v", contents[0]["text"])
	}
	if !strings.Contains(text, `"executable":false`) || !strings.Contains(text, `"from":"prepare"`) || !strings.Contains(text, `"command_trust":"untrusted"`) {
		t.Fatalf("command flow resource = %s", text)
	}
	srv.TenantID = "other"
	if _, err := srv.readResource(context.Background(), "reactor://command-automations/resource-plan/flow"); err == nil {
		t.Fatal("foreign tenant command flow resource was readable")
	}
}

func TestHTTPMCPCommandAutomationReviewReportsMissingCredentialWithoutExecution(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0,"credential_ids":["cred_missing"]}]}`)
	if _, err := j.CreateCommandAutomation(context.Background(), "acme", "cmd_review", "review-plan", "", "", "alice", definition); err != nil {
		t.Fatal(err)
	}
	review := callOperationalTool(t, srv, "reactor_review_command_automation", map[string]any{"name": "review-plan"}, false)
	text := string(review)
	if !strings.Contains(text, `"review_status":"missing_credentials"`) || !strings.Contains(text, `"credential_id":"cred_missing"`) || !strings.Contains(text, `"executable":false`) {
		t.Fatalf("review receipt = %s", review)
	}
	if strings.Contains(text, "run_id") || strings.Contains(text, "secret_value") {
		t.Fatalf("review receipt exposed execution or credential value: %s", review)
	}
}

func TestHTTPMCPCommandAutomationReviewSelectsImmutableVersion(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true}
	first := map[string]any{"steps": []map[string]any{{"name": "check", "command": "true", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0}}}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{"name": "versioned-review", "definition": first}, false)
	second := map[string]any{"steps": []map[string]any{{"name": "check", "command": "false", "purpose": "Check again", "timeout_seconds": 30, "expected_exit_code": 0}}}
	callOperationalTool(t, srv, "reactor_revise_command_automation", map[string]any{"name": "versioned-review", "expected_version": 1, "definition": second}, false)

	current := callOperationalTool(t, srv, "reactor_review_command_automation", map[string]any{"name": "versioned-review"}, false)
	if !strings.Contains(string(current), `"version":2`) || !strings.Contains(string(current), `"command":"false"`) {
		t.Fatalf("current review = %s", current)
	}
	historical := callOperationalTool(t, srv, "reactor_review_command_automation", map[string]any{"name": "versioned-review", "version": 1}, false)
	if !strings.Contains(string(historical), `"version":1`) || !strings.Contains(string(historical), `"command":"true"`) || strings.Contains(string(historical), `"command":"false"`) {
		t.Fatalf("historical review = %s", historical)
	}
	// An explicit null or zero must not silently fall back to the current
	// version. The caller must choose the immutable review target explicitly.
	callOperationalTool(t, srv, "reactor_review_command_automation", map[string]any{"name": "versioned-review", "version": nil}, true)
	callOperationalTool(t, srv, "reactor_review_command_automation", map[string]any{"name": "versioned-review", "version": 0}, true)
}

func TestStoredCommandDefinitionRejectsMalformedLegacyData(t *testing.T) {
	t.Parallel()
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"steps":[]}`),
		json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":0,"expected_exit_code":0}]}`),
		json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0,"unexpected":true}]}`),
	} {
		if _, err := decodeStoredCommandDefinition(raw); err == nil {
			t.Fatalf("malformed stored definition was accepted: %s", raw)
		}
	}
	valid := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0}]}`)
	if definition, err := decodeStoredCommandDefinition(valid); err != nil || len(definition.Steps) != 1 {
		t.Fatalf("valid stored definition rejected: definition=%+v err=%v", definition, err)
	}
}

func TestMCPCommandAutomationVersionViewPreservesMalformedDefinition(t *testing.T) {
	view := mcpCommandAutomationVersionView(journal.CommandAutomationVersion{
		AutomationID:   "cmd_legacy_definition",
		Version:        1,
		DefinitionJSON: []byte{'{', '"', 's', 't', 'e', 'p', 's', '"', ':', 0xff},
		CreatedBy:      "operator",
	})
	if _, ok := view["definition_json"].(string); !ok {
		t.Fatalf("malformed definition was not represented as text: %#v", view["definition_json"])
	}
	if _, err := json.Marshal(view); err != nil {
		t.Fatalf("malformed definition poisoned MCP view: %v", err)
	}
}

func TestHTTPMCPCommandAutomationDiffIsBoundedAndNonExecutable(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true}
	first := map[string]any{"tags": []string{"ops"}, "steps": []map[string]any{{"name": "check", "command": "true", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0}}}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{"name": "diff-plan", "definition": first}, false)
	second := map[string]any{"tags": []string{"daily"}, "steps": []map[string]any{{"name": "check", "command": "true", "purpose": "Changed", "timeout_seconds": 30, "expected_exit_code": 0}, {"name": "report", "command": "true", "purpose": "Report", "timeout_seconds": 30, "expected_exit_code": 0}}}
	callOperationalTool(t, srv, "reactor_revise_command_automation", map[string]any{"name": "diff-plan", "expected_version": 1, "definition": second}, false)
	diff := callOperationalTool(t, srv, "reactor_diff_command_automation", map[string]any{"name": "diff-plan", "from_version": 1, "to_version": 2}, false)
	text := string(diff)
	if !strings.Contains(text, `"no_changes":false`) || !strings.Contains(text, `"purpose"`) || !strings.Contains(text, `"steps_added":["report"]`) || !strings.Contains(text, `"executable":false`) {
		t.Fatalf("diff receipt = %s", diff)
	}
	if strings.Contains(text, "run_id") || strings.Contains(text, `"command":"true"`) {
		t.Fatalf("diff receipt exposed execution or command values: %s", diff)
	}
}

func TestHTTPMCPCommandAutomationVersionIndexOmitsCommandValues(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.Scopes = &WriteScopes{Authoring: true}
	first := map[string]any{"steps": []map[string]any{{"name": "check", "command": "true", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0}}}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{"name": "version-index", "definition": first}, false)
	second := map[string]any{"steps": []map[string]any{{"name": "check", "command": "false", "purpose": "Check again", "timeout_seconds": 30, "expected_exit_code": 0}}}
	callOperationalTool(t, srv, "reactor_revise_command_automation", map[string]any{"name": "version-index", "expected_version": 1, "definition": second}, false)
	index := callOperationalTool(t, srv, "reactor_list_command_automation_versions", map[string]any{"name": "version-index", "limit": 1}, false)
	text := string(index)
	if !strings.Contains(text, `"version":2`) || !strings.Contains(text, `"has_more":true`) || !strings.Contains(text, `"definition_sha256"`) || !strings.Contains(text, `"executable":false`) {
		t.Fatalf("version index = %s", index)
	}
	if strings.Contains(text, `"command":"false"`) || strings.Contains(text, "definition_json") {
		t.Fatalf("version index exposed command definition: %s", index)
	}
}

func TestHTTPMCPCommandAutomationValidationIsPreviewOnly(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	definition := map[string]any{"steps": []map[string]any{{"name": "check", "command": "true", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0, "credential_ids": []string{"cred_missing"}}}}
	validated := callOperationalTool(t, srv, "reactor_validate_command_automation", map[string]any{"definition": definition}, false)
	text := string(validated)
	if !strings.Contains(text, `"valid":true`) || !strings.Contains(text, `"persisted":false`) || !strings.Contains(text, `"credential_readiness":"missing_credentials"`) || !strings.Contains(text, `"executable":false`) || !strings.Contains(text, `"kind":"command"`) {
		t.Fatalf("validation receipt = %s", validated)
	}
	if _, err := j.GetCommandAutomationByName(context.Background(), "acme", "preview-only"); err == nil {
		t.Fatal("validation unexpectedly persisted a command plan")
	}
}

func TestHTTPMCPWorkflowAuthoringRejectsUnknownArguments(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, false)
	srv.Scopes = &WriteScopes{Authoring: true}
	callOperationalTool(t, srv, "reactor_register_workflow", map[string]any{
		"slug": "strict-authoring", "sdk_version": "0.1.0", "typo_dag": map[string]any{},
	}, true)
}
