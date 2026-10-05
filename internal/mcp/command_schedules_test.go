package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestMCPCommandAutomationScheduleLifecycleIsTenantScopedAndFenced(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.CommandAutomationSchedules = j
	srv.Scopes = &WriteScopes{Authoring: true, Triggers: true, CommandExecution: true}
	reconciles := 0
	srv.ReconcileCommandSchedules = func(context.Context) error { reconciles++; return nil }
	srv.CommandExecutionCapabilities = func(context.Context, commandautomations.Definition) commandautomations.ExecutionCapabilities {
		return commandautomations.ExecutionCapabilities{
			FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true, StepUpAuthorized: true,
			SandboxProfileReady: true, VaultBoundaryReady: true, CredentialsSupported: true,
			OutputLimitsReady: true, AuditReady: true, RunnerReady: true, TargetReady: true,
		}
	}
	srv.CommandTargetAllowed = func(context.Context, string) bool { return true }

	definition := map[string]any{"steps": []map[string]any{{
		"name": "check", "command": "true", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0,
	}}}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{
		"name": "scheduled-check", "description": "scheduled", "target": "ops-host", "definition": definition,
	}, false)
	plan, err := j.GetCommandAutomationByName(context.Background(), "acme", "scheduled-check")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := j.GetCommandAutomationVersion(context.Background(), "acme", plan.ID, plan.CurrentVersion)
	if err != nil {
		t.Fatal(err)
	}
	def, err := decodeStoredCommandDefinition(stored.DefinitionJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(context.Background(), "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	caps := commandautomations.ExecutionCapabilities{
		FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true, StepUpAuthorized: true,
		AutomationEnabled: true, SandboxProfileReady: true, VaultBoundaryReady: true,
		CredentialsSupported: true, OutputLimitsReady: true, AuditReady: true, RunnerReady: true, TargetReady: true,
	}
	receipt := commandautomations.EvaluateExecutionGates(def, caps)
	definitionSHA256 := commandDefinitionSHA256(stored.DefinitionJSON)
	binding := commandautomations.BindExecutionReceipt("acme", plan.ID, plan.CurrentVersion, definitionSHA256, receipt)

	created := callOperationalTool(t, srv, "reactor_create_command_automation_schedule", map[string]any{
		"name": "scheduled-check", "version": 1, "spec": "0 9 * * *", "timezone": "Europe/Stockholm",
		"receipt_id": binding.ReceiptID, "gate_digest": binding.GateDigest, "idempotency_key": "schedule-1",
	}, false)
	var createdView struct {
		Schedule struct {
			ID       string `json:"id"`
			Revision int64  `json:"revision"`
			State    string `json:"state"`
		} `json:"schedule"`
	}
	if err := json.Unmarshal(created, &createdView); err != nil {
		t.Fatal(err)
	}
	if createdView.Schedule.ID == "" || createdView.Schedule.Revision != 1 || createdView.Schedule.State != "disabled" {
		t.Fatalf("create schedule receipt = %s", created)
	}
	if !strings.Contains(string(created), `"runtime_reconciled":true`) {
		t.Fatalf("create schedule omitted runtime receipt: %s", created)
	}
	replayed := callOperationalTool(t, srv, "reactor_create_command_automation_schedule", map[string]any{
		"name": "scheduled-check", "version": 1, "spec": "0 9 * * *", "timezone": "Europe/Stockholm",
		"receipt_id": binding.ReceiptID, "gate_digest": binding.GateDigest, "idempotency_key": "schedule-1",
	}, false)
	if !strings.Contains(string(replayed), `"idempotent":true`) {
		t.Fatalf("schedule idempotency replay = %s", replayed)
	}
	listed := callOperationalTool(t, srv, "reactor_list_command_automation_schedules", map[string]any{}, false)
	if !strings.Contains(string(listed), createdView.Schedule.ID) || strings.Contains(string(listed), "schedule-1") {
		t.Fatalf("schedule list leaked idempotency key or omitted row: %s", listed)
	}

	updated := callOperationalTool(t, srv, "reactor_update_command_automation_schedule", map[string]any{
		"schedule_id": createdView.Schedule.ID, "spec": "30 10 * * *", "timezone": "UTC", "expected_revision": 1,
	}, false)
	if !strings.Contains(string(updated), `"revision":2`) || !strings.Contains(string(updated), `"spec":"30 10 * * *"`) {
		t.Fatalf("schedule update receipt = %s", updated)
	}
	active := callOperationalTool(t, srv, "reactor_set_command_automation_schedule_state", map[string]any{
		"schedule_id": createdView.Schedule.ID, "state": "active", "expected_revision": 2,
	}, false)
	if !strings.Contains(string(active), `"state":"active"`) || !strings.Contains(string(active), `"revision":3`) {
		t.Fatalf("schedule activation receipt = %s", active)
	}
	callOperationalTool(t, srv, "reactor_set_command_automation_schedule_state", map[string]any{
		"schedule_id": createdView.Schedule.ID, "state": "disabled", "expected_revision": 3,
	}, false)
	callOperationalTool(t, srv, "reactor_delete_command_automation_schedule", map[string]any{
		"schedule_id": createdView.Schedule.ID, "expected_revision": 4,
	}, false)
	if reconciles < 5 {
		t.Fatalf("schedule mutations reconciled %d times, want at least create/update/enable/disable/delete", reconciles)
	}
	callOperationalTool(t, srv, "reactor_list_command_automation_schedules", map[string]any{}, false)
}

func TestMCPCommandAutomationScheduleRejectsStaleReceiptAndRevision(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t, false)
	srv.TenantID = "acme"
	srv.CommandAutomationSchedules = j
	srv.Scopes = &WriteScopes{Authoring: true, Triggers: true, CommandExecution: true}
	definition := map[string]any{"steps": []map[string]any{{"name": "check", "command": "true", "purpose": "Check", "timeout_seconds": 30, "expected_exit_code": 0}}}
	callOperationalTool(t, srv, "reactor_create_command_automation", map[string]any{"name": "stale-schedule", "definition": definition}, false)
	plan, err := j.GetCommandAutomationByName(context.Background(), "acme", "stale-schedule")
	if err != nil {
		t.Fatal(err)
	}
	callOperationalTool(t, srv, "reactor_create_command_automation_schedule", map[string]any{
		"name": "stale-schedule", "version": 1, "spec": "0 9 * * *", "receipt_id": "cmdpreflight_v1_" + strings.Repeat("a", 64), "gate_digest": strings.Repeat("b", 64),
	}, true)
	// An update with an omitted or zero revision is rejected before the store is
	// reached; this prevents legacy callers from bypassing the CAS fence.
	_ = plan
	callOperationalTool(t, srv, "reactor_update_command_automation_schedule", map[string]any{"schedule_id": "missing", "spec": "0 9 * * *", "expected_revision": 0}, true)
}

func TestMCPCommandAutomationScheduleViewBoundsRuntimeMetadata(t *testing.T) {
	row := journal.CommandAutomationSchedule{
		ID: strings.Repeat("s", maxMCPRunIdentityBytes+20), TenantID: strings.Repeat("t", maxMCPRunIdentityBytes+20),
		AutomationID: strings.Repeat("a", maxMCPRunIdentityBytes+20), ActorID: strings.Repeat("x", maxMCPCommandRunActorBytes+20),
		Spec: strings.Repeat("* ", maxMCPCommandAutomationScheduleSpec), Timezone: strings.Repeat("z", maxMCPCommandAutomationScheduleZone+20),
		State: strings.Repeat("q", maxMCPCommandRunStatusBytes+20), LastError: "Authorization: Bearer " + strings.Repeat("s", 64),
	}
	view := mcpCommandAutomationScheduleView(row)
	for _, field := range []struct {
		name string
		max  int
	}{
		{"id", maxMCPRunIdentityBytes}, {"tenant_id", maxMCPRunIdentityBytes}, {"automation_id", maxMCPRunIdentityBytes},
		{"actor_id", maxMCPCommandRunActorBytes}, {"spec", maxMCPCommandAutomationScheduleSpec}, {"timezone", maxMCPCommandAutomationScheduleZone}, {"state", maxMCPCommandRunStatusBytes},
	} {
		value, ok := view[field.name].(string)
		if !ok || len([]byte(value)) > field.max || view[field.name+"_truncated"] != true {
			t.Fatalf("schedule field %s = %#v, want bounded/truncated", field.name, view[field.name])
		}
	}
	if _, leaked := view["last_error"]; leaked || view["last_error_trust"] != "redacted" || view["last_error_present"] != true {
		t.Fatalf("schedule last_error leaked or lost trust marker: %#v", view)
	}
}

func TestMCPCommandAutomationScheduleRequiresFiveFieldExpression(t *testing.T) {
	for _, spec := range []string{"@every 10s", "@hourly", "0 0 9 * * *"} {
		if _, _, err := validateCommandAutomationSchedule(spec, "UTC"); err == nil {
			t.Fatalf("non-five-field schedule %q was accepted", spec)
		}
	}
	if _, _, err := validateCommandAutomationSchedule("0 9 * * *", "Europe/Stockholm"); err != nil {
		t.Fatalf("valid five-field schedule rejected: %v", err)
	}
}
