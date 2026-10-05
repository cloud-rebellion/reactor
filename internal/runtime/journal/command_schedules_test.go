package journal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/bright-interaction/reactor/internal/commandautomations"
)

func commandScheduleInput(t *testing.T, tenant string, plan CommandAutomation, definition []byte, actor string) CommandAutomationScheduleInput {
	t.Helper()
	digest := commandDefinitionDigest(t, definition)
	gate := sha256.Sum256([]byte("schedule-gates-" + tenant))
	gateDigest := hex.EncodeToString(gate[:])
	return CommandAutomationScheduleInput{
		ID:                "cmdsched_" + tenant,
		AutomationID:      plan.ID,
		AutomationVersion: plan.CurrentVersion,
		DefinitionSHA256:  digest,
		ReceiptID:         commandautomations.ReceiptIDForGateDigest(tenant, plan.ID, plan.CurrentVersion, digest, gateDigest),
		GateDigest:        gateDigest,
		ActorID:           actor,
		Spec:              "0 9 * * *",
		Timezone:          "Europe/Stockholm",
	}
}

func TestCommandAutomationScheduleCRUDTenantFenceAndRevision(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_schedule_crud", "schedule-crud", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	input := commandScheduleInput(t, "acme", plan, definition, "alice")
	// Create is intentionally parked until the caller performs the explicit
	// schedule activation step-up. The plan itself may be disabled at this point.
	created, replay, err := j.CreateCommandAutomationScheduleWithIdempotency(ctx, "acme", input, "schedule-key")
	if err != nil || replay || created.State != CommandAutomationScheduleDisabled || created.Revision != 1 {
		t.Fatalf("create schedule = %+v replay=%v err=%v", created, replay, err)
	}
	replayed, replay, err := j.CreateCommandAutomationScheduleWithIdempotency(ctx, "acme", input, "schedule-key")
	if err != nil || !replay || replayed.ID != created.ID {
		t.Fatalf("replay schedule = %+v replay=%v err=%v", replayed, replay, err)
	}
	changed := input
	changed.Spec = "30 9 * * *"
	if _, _, err := j.CreateCommandAutomationScheduleWithIdempotency(ctx, "acme", changed, "schedule-key"); !errors.Is(err, ErrCommandAutomationScheduleConflict) {
		t.Fatalf("idempotency mismatch = %v, want schedule conflict", err)
	}

	got, err := j.GetCommandAutomationScheduleForTenant(ctx, "acme", created.ID)
	if err != nil || got.ID != created.ID || got.TenantID != "acme" || got.Revision != 1 {
		t.Fatalf("get schedule = %+v err=%v", got, err)
	}
	if _, err := j.GetCommandAutomationScheduleForTenant(ctx, "other", created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign get = %v, want ErrNotFound", err)
	}
	page, more, err := j.ListCommandAutomationSchedulesForTenantPage(ctx, CommandAutomationScheduleFilter{TenantID: "acme", Limit: 10})
	if err != nil || more || len(page) != 1 || page[0].ID != created.ID {
		t.Fatalf("schedule page = %+v more=%v err=%v", page, more, err)
	}
	foreignPage, more, err := j.ListCommandAutomationSchedulesForTenantPage(ctx, CommandAutomationScheduleFilter{TenantID: "other", Limit: 10})
	if err != nil || more || len(foreignPage) != 0 {
		t.Fatalf("foreign schedule page = %+v more=%v err=%v", foreignPage, more, err)
	}

	// Activation is blocked while the immutable plan is disabled. Enabling the
	// plan is a separate MCP step-up gate; this journal method only fences state.
	if err := j.SetCommandAutomationScheduleStateIfRevision(ctx, "acme", created.ID, CommandAutomationScheduleActive, created.Revision); !errors.Is(err, ErrCommandAutomationEnabled) {
		t.Fatalf("activate disabled plan = %v, want ErrCommandAutomationEnabled", err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationScheduleStateIfRevision(ctx, "acme", created.ID, CommandAutomationScheduleActive, created.Revision); err != nil {
		t.Fatalf("activate schedule: %v", err)
	}
	active, err := j.GetCommandAutomationScheduleForTenant(ctx, "acme", created.ID)
	if err != nil || active.State != CommandAutomationScheduleActive || active.Revision != 2 {
		t.Fatalf("active schedule = %+v err=%v", active, err)
	}
	if err := j.SetCommandAutomationScheduleStateIfRevision(ctx, "acme", created.ID, CommandAutomationScheduleDisabled, created.Revision); !errors.Is(err, ErrCommandAutomationScheduleRevisionConflict) {
		t.Fatalf("stale schedule state = %v, want revision conflict", err)
	}
	if err := j.SetCommandAutomationScheduleStateIfRevision(ctx, "acme", created.ID, CommandAutomationScheduleDisabled, active.Revision); err != nil {
		t.Fatalf("disable schedule: %v", err)
	}

	update := CommandAutomationScheduleUpdate{AutomationVersion: input.AutomationVersion, DefinitionSHA256: input.DefinitionSHA256, ReceiptID: input.ReceiptID, GateDigest: input.GateDigest, ActorID: "bob", Spec: "30 9 * * *", Timezone: "UTC"}
	if err := j.UpdateCommandAutomationScheduleIfRevision(ctx, "acme", created.ID, update, active.Revision); !errors.Is(err, ErrCommandAutomationScheduleRevisionConflict) {
		t.Fatalf("stale schedule update = %v, want revision conflict", err)
	}
	current, err := j.GetCommandAutomationScheduleForTenant(ctx, "acme", created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.UpdateCommandAutomationScheduleIfRevision(ctx, "acme", created.ID, update, current.Revision); err != nil {
		t.Fatalf("schedule update: %v", err)
	}
	updated, err := j.GetCommandAutomationScheduleForTenant(ctx, "acme", created.ID)
	if err != nil || updated.ActorID != "bob" || updated.Spec != "30 9 * * *" || updated.Revision != current.Revision+1 {
		t.Fatalf("updated schedule = %+v err=%v", updated, err)
	}
	if err := j.DeleteCommandAutomationScheduleIfRevision(ctx, "other", created.ID, updated.Revision); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign delete = %v, want ErrNotFound", err)
	}
	if err := j.DeleteCommandAutomationScheduleIfRevision(ctx, "acme", created.ID, updated.Revision); err != nil {
		t.Fatalf("delete schedule: %v", err)
	}
	if _, err := j.GetCommandAutomationScheduleForTenant(ctx, "acme", created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted schedule = %v, want ErrNotFound", err)
	}
}

func TestCommandAutomationScheduleBindingAndCurrentVersionFence(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_schedule_binding", "schedule-binding", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	valid := commandScheduleInput(t, "acme", plan, definition, "alice")
	badDigest := valid
	badDigest.DefinitionSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := j.CreateCommandAutomationSchedule(ctx, "acme", badDigest); !errors.Is(err, ErrCommandAutomationScheduleBindingMismatch) {
		t.Fatalf("bad definition digest = %v, want binding mismatch", err)
	}
	badReceipt := valid
	badReceipt.ReceiptID = "cmdpreflight_v1_bad"
	if _, err := j.CreateCommandAutomationSchedule(ctx, "acme", badReceipt); !errors.Is(err, ErrCommandAutomationScheduleBindingMismatch) {
		t.Fatalf("bad receipt = %v, want binding mismatch", err)
	}
	if _, err := j.CreateCommandAutomationSchedule(ctx, "other", valid); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign create = %v, want ErrNotFound", err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	created, err := j.CreateCommandAutomationSchedule(ctx, "acme", valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.AppendCommandAutomationVersion(ctx, "acme", plan.ID, "alice", plan.CurrentVersion, definition); !errors.Is(err, ErrCommandAutomationEnabled) {
		t.Fatalf("revision while plan enabled = %v, want ErrCommandAutomationEnabled", err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, false, true, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationScheduleStateIfRevision(ctx, "acme", created.ID, CommandAutomationScheduleActive, created.Revision); !errors.Is(err, ErrCommandAutomationEnabled) {
		t.Fatalf("activate schedule after plan disable = %v, want ErrCommandAutomationEnabled", err)
	}
}

func TestCommandAutomationScheduleRuntimeMarksAreTenantScopedAndRevisioned(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_schedule_marks", "schedule-marks", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	schedule, err := j.CreateCommandAutomationSchedule(ctx, "acme", commandScheduleInput(t, "acme", plan, definition, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.MarkCommandAutomationScheduleFired(ctx, "other", schedule.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign fired mark = %v, want ErrNotFound", err)
	}
	if err := j.MarkCommandAutomationScheduleError(ctx, "acme", schedule.ID, "temporary admission failure"); err != nil {
		t.Fatalf("error mark: %v", err)
	}
	marked, err := j.GetCommandAutomationScheduleForTenant(ctx, "acme", schedule.ID)
	if err != nil || marked.Revision != 2 || marked.LastError != "temporary admission failure" {
		t.Fatalf("error-marked schedule = %+v err=%v", marked, err)
	}
	if err := j.MarkCommandAutomationScheduleFired(ctx, "acme", schedule.ID); err != nil {
		t.Fatalf("fired mark: %v", err)
	}
	fired, err := j.GetCommandAutomationScheduleForTenant(ctx, "acme", schedule.ID)
	if err != nil || fired.Revision != 3 || fired.LastError != "" || fired.LastFiredAt == nil {
		t.Fatalf("fired schedule = %+v err=%v", fired, err)
	}
}
