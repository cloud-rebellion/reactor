package journal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/commandautomations"
)

func TestCommandAutomationVersionsAreTenantScopedAndDurable(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := json.RawMessage(`{"steps":[{"name":"backup","command":"restic snapshots","purpose":"Check backups","timeout_seconds":30}]}`)

	created, err := j.CreateCommandAutomation(ctx, "acme", "cmd_acme_1", "nightly-backup", "Back up the vault", "ops-host", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if created.CurrentVersion != 1 || created.TenantID != "acme" || created.Enabled {
		t.Fatalf("created = %+v", created)
	}
	if _, err := j.CreateCommandAutomation(ctx, "acme", "cmd_acme_2", "nightly-backup", "duplicate", "ops-host", "alice", definition); !errors.Is(err, ErrCommandAutomationNameTaken) {
		t.Fatalf("duplicate create error = %v, want ErrCommandAutomationNameTaken", err)
	}
	if _, err := j.GetCommandAutomationByName(ctx, "other", "nightly-backup"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant lookup = %v, want not found", err)
	}

	version, err := j.AppendCommandAutomationVersion(ctx, "acme", created.ID, "bob", 1, json.RawMessage(`{"steps":[{"name":"backup","command":"restic check","purpose":"Check backups","timeout_seconds":60}]}`))
	if err != nil || version != 2 {
		t.Fatalf("append version = %d, %v", version, err)
	}
	if _, err := j.AppendCommandAutomationVersion(ctx, "other", created.ID, "mallory", 2, definition); !errors.Is(err, ErrCommandAutomationTenant) {
		t.Fatalf("cross-tenant append = %v, want ErrCommandAutomationTenant", err)
	}

	got, err := j.GetCommandAutomation(ctx, "acme", created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CurrentVersion != 2 || got.Enabled {
		t.Fatalf("current version/enabled = %d/%v, want 2/false", got.CurrentVersion, got.Enabled)
	}
	v, err := j.GetCommandAutomationVersion(ctx, "acme", created.ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(v.DefinitionJSON), "restic check") {
		t.Fatalf("definition = %s", v.DefinitionJSON)
	}
}

func TestCommandAutomationEnabledFenceIsTenantScopedAndVersioned(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	created, err := j.CreateCommandAutomation(ctx, "acme", "cmd_enabled", "enabled-plan", "", "ops-host", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if created.Enabled {
		t.Fatal("new command automation must start disabled")
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", created.ID, true, false, 1); err != nil {
		t.Fatalf("enable reviewed command plan: %v", err)
	}
	got, err := j.GetCommandAutomation(ctx, "acme", created.ID)
	if err != nil || !got.Enabled {
		t.Fatalf("enabled command plan = %+v, err=%v", got, err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", created.ID, false, false, 1); !errors.Is(err, ErrCommandAutomationStateConflict) {
		t.Fatalf("stale enabled-state fence = %v, want ErrCommandAutomationStateConflict", err)
	}
	if _, err := j.AppendCommandAutomationVersion(ctx, "acme", created.ID, "bob", 1, definition); !errors.Is(err, ErrCommandAutomationEnabled) {
		t.Fatalf("revision while enabled = %v, want ErrCommandAutomationEnabled", err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", created.ID, false, true, 1); err != nil {
		t.Fatalf("disable current reviewed version: %v", err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "other", created.ID, true, false, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant enabled fence = %v, want ErrNotFound", err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", created.ID, true, false, 0); !errors.Is(err, ErrCommandAutomationConflict) {
		t.Fatalf("invalid version fence = %v, want ErrCommandAutomationConflict", err)
	}
	if version, err := j.AppendCommandAutomationVersion(ctx, "acme", created.ID, "bob", 1, definition); err != nil || version != 2 {
		t.Fatalf("revision after disable = version %d, err %v", version, err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", created.ID, true, false, 2); err != nil {
		t.Fatalf("re-enable latest reviewed version: %v", err)
	}
	if _, err := j.AppendCommandAutomationVersion(ctx, "acme", created.ID, "carol", 2, definition); !errors.Is(err, ErrCommandAutomationEnabled) {
		t.Fatalf("revision while enabled = %v, want ErrCommandAutomationEnabled", err)
	}
	if err := j.DeleteCommandAutomationIfVersion(ctx, "acme", created.ID, 2); !errors.Is(err, ErrCommandAutomationEnabled) {
		t.Fatalf("delete while enabled = %v, want ErrCommandAutomationEnabled", err)
	}
}

func TestCommandAutomationEnabledHelpersAreTenantScoped(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	created, err := j.CreateCommandAutomation(ctx, "acme", "cmd_enabled_helpers", "enabled-helpers", "", "ops-host", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if enabled, err := j.IsCommandAutomationEnabled(ctx, "acme", created.ID); err != nil || enabled {
		t.Fatalf("initial enabled=%v err=%v, want false", enabled, err)
	}
	if err := j.SetCommandAutomationEnabled(ctx, "acme", created.ID, true); err != nil {
		t.Fatalf("set enabled: %v", err)
	}
	if enabled, err := j.IsCommandAutomationEnabled(ctx, "acme", created.ID); err != nil || !enabled {
		t.Fatalf("updated enabled=%v err=%v, want true", enabled, err)
	}
	if err := j.SetCommandAutomationEnabled(ctx, "other", created.ID, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant set = %v, want ErrNotFound", err)
	}
	if _, err := j.IsCommandAutomationEnabled(ctx, "other", created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant read = %v, want ErrNotFound", err)
	}
	if err := j.SetCommandAutomationEnabledIfVersion(ctx, "acme", created.ID, false, 2); !errors.Is(err, ErrCommandAutomationConflict) {
		t.Fatalf("stale version helper = %v, want ErrCommandAutomationConflict", err)
	}
	if err := j.SetCommandAutomationEnabledIfVersion(ctx, "acme", created.ID, false, 1); err != nil {
		t.Fatalf("current version helper: %v", err)
	}
}

func TestCommandAutomationListAndDeleteAreTenantScoped(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check status","timeout_seconds":30}]}`)
	if _, err := j.CreateCommandAutomation(ctx, "a", "cmd_a", "a-job", "", "", "", definition); err != nil {
		t.Fatal(err)
	}
	if _, err := j.CreateCommandAutomation(ctx, "b", "cmd_b", "b-job", "", "", "", definition); err != nil {
		t.Fatal(err)
	}
	rows, more, err := j.ListCommandAutomationsPage(ctx, "a", 10, 0)
	if err != nil || more || len(rows) != 1 || rows[0].Name != "a-job" {
		t.Fatalf("list = %+v more=%v err=%v", rows, more, err)
	}
	if err := j.DeleteCommandAutomation(ctx, "b", "cmd_a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant delete = %v, want not found", err)
	}
	if err := j.DeleteCommandAutomation(ctx, "a", "cmd_a"); err != nil {
		t.Fatal(err)
	}
}

func TestCommandAutomationDeleteRefusesDurableReferences(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check status","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_delete_refs", "delete-refs", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.CreateCommandAutomationSchedule(ctx, "acme", commandScheduleInput(t, "acme", plan, definition, "alice")); err != nil {
		t.Fatal(err)
	}
	if err := j.DeleteCommandAutomationIfVersion(ctx, "acme", plan.ID, plan.CurrentVersion); !errors.Is(err, ErrCommandAutomationHasTriggers) {
		t.Fatalf("delete with schedule = %v, want ErrCommandAutomationHasTriggers", err)
	}
	if err := j.DeleteCommandAutomationScheduleIfRevision(ctx, "acme", "cmdsched_acme", 1); err != nil {
		t.Fatal(err)
	}
	if err := j.DeleteCommandAutomationIfVersion(ctx, "acme", plan.ID, plan.CurrentVersion); err != nil {
		t.Fatalf("delete after trigger removal = %v", err)
	}
}

func TestCommandAutomationVersionSummariesAreBoundedAndOmitDefinitions(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	first := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	second := json.RawMessage(`{"steps":[{"name":"check","command":"false","purpose":"Check again","timeout_seconds":30}]}`)
	created, err := j.CreateCommandAutomation(ctx, "acme", "cmd_versions", "versioned-plan", "", "", "alice", first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.AppendCommandAutomationVersion(ctx, "acme", created.ID, "bob", 1, second); err != nil {
		t.Fatal(err)
	}
	rows, more, err := j.ListCommandAutomationVersionSummariesPage(ctx, "acme", created.ID, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !more || len(rows) != 1 || rows[0].Version != 2 || rows[0].DefinitionBytes == 0 || len(rows[0].DefinitionSHA256) != 64 {
		t.Fatalf("summaries = %+v more=%v", rows, more)
	}
	if _, _, err := j.ListCommandAutomationVersionSummariesPage(ctx, "other", created.ID, 1, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant summaries = %v, want not found", err)
	}
}

func TestCommandAutomationVersionSummaryUsesNormalizedDigestWithLegacyFallback(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	canonical := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0}]}`)
	created, err := j.CreateCommandAutomation(ctx, "acme", "cmd_digest", "digest-plan", "", "", "alice", canonical)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a valid legacy/imported row whose JSON member order differs from
	// the normalized representation retained by current writes.
	legacyEquivalent := []byte(`{"steps":[{"purpose":"Check","expected_exit_code":0,"timeout_seconds":30,"command":"true","name":"check"}]}`)
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE command_automation_versions SET definition_json = $1 WHERE automation_id = $2 AND version = 1`), string(legacyEquivalent), created.ID); err != nil {
		t.Fatal(err)
	}
	_, normalized, err := commandautomations.Normalize(legacyEquivalent)
	if err != nil {
		t.Fatal(err)
	}
	wantSum := sha256.Sum256(normalized)
	want := hex.EncodeToString(wantSum[:])
	rawSum := sha256.Sum256(legacyEquivalent)
	if want == hex.EncodeToString(rawSum[:]) {
		t.Fatal("test fixture must differ from its normalized JSON digest")
	}
	rows, more, err := j.ListCommandAutomationVersionSummariesPage(ctx, "acme", created.ID, 10, 0)
	if err != nil || more || len(rows) != 1 {
		t.Fatalf("summary rows=%+v more=%v err=%v", rows, more, err)
	}
	if rows[0].DefinitionSHA256 != want {
		t.Fatalf("summary digest=%s, want normalized digest %s", rows[0].DefinitionSHA256, want)
	}
	if rows[0].DefinitionBytes != len(legacyEquivalent) {
		t.Fatalf("summary bytes=%d, want raw bytes=%d", rows[0].DefinitionBytes, len(legacyEquivalent))
	}

	// An invalid legacy row remains inspectable by its raw digest, but that
	// fallback does not make it executable: review/admission revalidation still
	// rejects the malformed definition.
	malformed := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"unknown":"field"}]}`)
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE command_automation_versions SET definition_json = $1 WHERE automation_id = $2 AND version = 1`), string(malformed), created.ID); err != nil {
		t.Fatal(err)
	}
	malformedSum := sha256.Sum256(malformed)
	rows, more, err = j.ListCommandAutomationVersionSummariesPage(ctx, "acme", created.ID, 10, 0)
	if err != nil || more || len(rows) != 1 {
		t.Fatalf("malformed summary rows=%+v more=%v err=%v", rows, more, err)
	}
	if rows[0].DefinitionSHA256 != hex.EncodeToString(malformedSum[:]) {
		t.Fatalf("malformed fallback digest=%s, want raw digest %s", rows[0].DefinitionSHA256, hex.EncodeToString(malformedSum[:]))
	}
}
