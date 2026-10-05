package commandrunner

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	_ "modernc.org/sqlite"
)

func TestCommandScheduleDriverRejectsInvalidTimezoneBeforeStart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "command-schedule-driver.db")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(ctx, log, "sqlite://"+dbPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	j := journal.New(db, journal.EngineSQLite)

	raw := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":1}]}`)
	_, normalized, err := commandautomations.Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_schedule_driver", "schedule-driver", "", "local", "alice", normalized)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	digestBytes := sha256.Sum256(normalized)
	digest := hex.EncodeToString(digestBytes[:])
	gateBytes := sha256.Sum256([]byte("driver-gates"))
	gateDigest := hex.EncodeToString(gateBytes[:])
	schedule, err := j.CreateCommandAutomationSchedule(ctx, "acme", journal.CommandAutomationScheduleInput{
		ID: "cmdsched_driver_invalid_timezone", AutomationID: plan.ID, AutomationVersion: plan.CurrentVersion,
		DefinitionSHA256: digest,
		ReceiptID:        commandautomations.ReceiptIDForGateDigest("acme", plan.ID, plan.CurrentVersion, digest, gateDigest),
		GateDigest:       gateDigest, ActorID: "alice", Spec: "0 * * * *", Timezone: "Mars/Phobos",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationScheduleStateIfRevision(ctx, "acme", schedule.ID, journal.CommandAutomationScheduleActive, schedule.Revision); err != nil {
		t.Fatal(err)
	}
	active, err := j.GetCommandAutomationScheduleForTenant(ctx, "acme", schedule.ID)
	if err != nil {
		t.Fatal(err)
	}

	// The MCP authoring layer validates timezones, but the daemon must still
	// fail closed when an imported or legacy row reaches the runtime. Start
	// should reject the row before the cron clock becomes live and persist a
	// bounded operator-visible error for the next reconcile.
	driver := &CommandScheduleDriver{Journal: j, Runner: &Runner{}, Queue: &Queue{}, TenantID: "acme"}
	if err := driver.Start(ctx); err == nil || !strings.Contains(err.Error(), "invalid timezone") {
		t.Fatalf("driver start error = %v, want invalid timezone", err)
	}
	driver.Stop()
	marked, err := j.GetCommandAutomationScheduleForTenant(ctx, "acme", schedule.ID)
	if err != nil {
		t.Fatal(err)
	}
	if marked.State != journal.CommandAutomationScheduleActive {
		t.Fatalf("invalid schedule state = %q, want active for explicit operator repair", marked.State)
	}
	if !strings.Contains(marked.LastError, "schedule rejected") || !strings.Contains(marked.LastError, "invalid timezone") {
		t.Fatalf("invalid schedule error = %q, want bounded rejection reason", marked.LastError)
	}
	if marked.Revision != active.Revision+1 {
		t.Fatalf("invalid schedule revision = %d, want %d", marked.Revision, active.Revision+1)
	}
}

func TestCommandScheduleSpecRejectsSubMinuteDescriptors(t *testing.T) {
	if _, err := commandScheduleSpec(journal.CommandAutomationSchedule{Spec: "@every 10s"}); err == nil {
		t.Fatal("sub-minute @every schedule accepted despite minute-scoped event identity")
	}
}

func TestCommandScheduleDriverRereadsAfterFireRevisionAdvance(t *testing.T) {
	t.Parallel()
	driver, schedule := newCommandScheduleDriverFixture(t, "UTC")
	ctx := context.Background()
	if err := driver.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer driver.Stop()

	// Keep the original row as the cron callback would: MarkFired advances the
	// durable revision while the cron entry itself remains installed with its
	// captured snapshot.
	driver.fire(schedule)
	first, err := driver.Journal.GetCommandAutomationScheduleForTenant(ctx, schedule.TenantID, schedule.ID)
	if err != nil {
		t.Fatal(err)
	}
	if first.LastFiredAt == nil || first.LastError != "" {
		t.Fatalf("first schedule fire = %+v, want fired without error", first)
	}
	if first.Revision != schedule.Revision+1 {
		t.Fatalf("first schedule revision = %d, want %d", first.Revision, schedule.Revision+1)
	}

	// A second tick still invokes the callback captured during Start. The
	// driver must resolve the current row before admission or Runner will see
	// the old revision as stale and permanently mark a healthy schedule as
	// failed.
	driver.fire(schedule)
	second, err := driver.Journal.GetCommandAutomationScheduleForTenant(ctx, schedule.TenantID, schedule.ID)
	if err != nil {
		t.Fatal(err)
	}
	if second.LastError != "" {
		t.Fatalf("repeat schedule fire recorded stale-row error %q", second.LastError)
	}
	if second.Revision != first.Revision+1 {
		t.Fatalf("repeat schedule revision = %d, want %d", second.Revision, first.Revision+1)
	}
}

func TestCommandScheduleDriverReplacesChangedCronExpression(t *testing.T) {
	t.Parallel()
	driver, schedule := newCommandScheduleDriverFixture(t, "UTC")
	ctx := context.Background()
	if err := driver.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer driver.Stop()
	initial, ok := driver.entries[schedule.ID]
	if !ok {
		t.Fatalf("schedule %q was not installed", schedule.ID)
	}

	if err := driver.Journal.SetCommandAutomationScheduleStateIfRevision(ctx, "acme", schedule.ID, journal.CommandAutomationScheduleDisabled, schedule.Revision); err != nil {
		t.Fatal(err)
	}
	disabled, err := driver.Journal.GetCommandAutomationScheduleForTenant(ctx, "acme", schedule.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Journal.UpdateCommandAutomationScheduleIfRevision(ctx, "acme", schedule.ID, journal.CommandAutomationScheduleUpdate{
		AutomationVersion: disabled.AutomationVersion, DefinitionSHA256: disabled.DefinitionSHA256,
		ReceiptID: disabled.ReceiptID, GateDigest: disabled.GateDigest, ActorID: disabled.ActorID,
		Spec: "*/5 * * * *", Timezone: "UTC",
	}, disabled.Revision); err != nil {
		t.Fatal(err)
	}
	updated, err := driver.Journal.GetCommandAutomationScheduleForTenant(ctx, "acme", schedule.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Journal.SetCommandAutomationScheduleStateIfRevision(ctx, "acme", schedule.ID, journal.CommandAutomationScheduleActive, updated.Revision); err != nil {
		t.Fatal(err)
	}
	if err := driver.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	current, ok := driver.entries[schedule.ID]
	if !ok {
		t.Fatalf("updated schedule %q was not installed", schedule.ID)
	}
	if current.spec != "CRON_TZ=UTC */5 * * * *" {
		t.Fatalf("compiled schedule spec = %q, want updated timezone/spec", current.spec)
	}
	if current.id == initial.id {
		t.Fatalf("schedule entry id did not change after expression update: %d", current.id)
	}
}

func TestCommandScheduleDriverCapturesSlotBeforeSlowAdmission(t *testing.T) {
	t.Parallel()
	driver, schedule := newCommandScheduleDriverFixture(t, "UTC")
	ctx := context.Background()
	if err := driver.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer driver.Stop()

	// The callback begins just before the minute rolls over. The durable
	// admission/queue work can take long enough to cross that boundary, but
	// this cron tick must retain its original slot identity.
	callbackStart := time.Date(2026, time.January, 2, 12, 34, 59, 900*int(time.Millisecond), time.UTC)
	driver.Now = func() time.Time { return callbackStart }
	driver.fire(schedule)

	var run journal.CommandRun
	var err error
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		run, err = findCommandScheduleRun(ctx, driver.Journal, schedule.TenantID, schedule.AutomationID)
		if err == nil && run.Status == journal.CommandRunSucceeded {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	want := journal.CommandAutomationScheduleEventID(schedule.ID, callbackStart)
	if run.Admission.TriggerEventID != want {
		t.Fatalf("schedule event id = %q, want callback slot %q", run.Admission.TriggerEventID, want)
	}
}

func newCommandScheduleDriverFixture(t *testing.T, timezone string) (*CommandScheduleDriver, journal.CommandAutomationSchedule) {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "command-schedule-driver-repeat.db")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(ctx, log, "sqlite://"+dbPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	j := journal.New(db, journal.EngineSQLite)
	raw := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":1,"expected_exit_code":0}]}`)
	definition, normalized, err := commandautomations.Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_schedule_driver_repeat", "schedule-driver-repeat", "", "local", "alice", normalized)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	digestBytes := sha256.Sum256(normalized)
	digest := hex.EncodeToString(digestBytes[:])
	caps := commandautomations.ExecutionCapabilities{
		FeatureEnabled: true, SingleTenant: true, TriggerAuthorized: true, AutomationEnabled: true,
		SandboxProfileReady: true, VaultBoundaryReady: true, CredentialsSupported: true,
		OutputLimitsReady: true, AuditReady: true, RunnerReady: true, TargetReady: true,
	}
	binding := commandautomations.BindExecutionReceipt("acme", plan.ID, plan.CurrentVersion, digest, commandautomations.EvaluateExecutionGates(definition, caps))
	schedule, err := j.CreateCommandAutomationSchedule(ctx, "acme", journal.CommandAutomationScheduleInput{
		ID: "cmdsched_driver_repeat", AutomationID: plan.ID, AutomationVersion: plan.CurrentVersion,
		DefinitionSHA256: digest,
		ReceiptID:        binding.ReceiptID, GateDigest: binding.GateDigest, ActorID: "alice", Spec: "* * * * *", Timezone: timezone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationScheduleStateIfRevision(ctx, "acme", schedule.ID, journal.CommandAutomationScheduleActive, schedule.Revision); err != nil {
		t.Fatal(err)
	}
	schedule, err = j.GetCommandAutomationScheduleForTenant(ctx, "acme", schedule.ID)
	if err != nil {
		t.Fatal(err)
	}
	runner := &Runner{
		Journal: j, Sandbox: &fakeSandbox{}, Enabled: true, TargetPolicy: ExactTargetPolicy{"local": {}},
		ScheduledCapabilitiesProvider: func(context.Context, commandautomations.Definition) (commandautomations.ExecutionCapabilities, error) {
			return caps, nil
		},
	}
	queue, err := NewQueue(runner, j, QueueConfig{
		Workers: 1, Capacity: 1, PollInterval: 10 * time.Millisecond, TenantID: "acme", WorkerPrefix: "schedule-repeat",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = queue.Stop(stopCtx)
	})
	return &CommandScheduleDriver{Journal: j, Runner: runner, Queue: queue, TenantID: "acme"}, schedule
}

func findCommandScheduleRun(ctx context.Context, j *journal.Journal, tenantID, automationID string) (journal.CommandRun, error) {
	runs, err := j.ListCommandRunsForTenantPage(ctx, journal.CommandRunFilter{TenantID: tenantID, AutomationID: automationID, Limit: 10})
	if err != nil {
		return journal.CommandRun{}, err
	}
	if len(runs) == 0 {
		return journal.CommandRun{}, journal.ErrNotFound
	}
	return runs[0], nil
}
