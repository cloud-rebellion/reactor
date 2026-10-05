package dispatcher

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	_ "modernc.org/sqlite"
)

// journalWithDB is the same isolated SQLite setup as newJournal, but retains
// the handle so these tests can make one admission dependency fail while the
// workflow and enabled-state reads remain available.
func journalWithDB(t *testing.T) (*journal.Journal, *sql.DB) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "admission.db")
	url := "sqlite://" + dbPath
	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(context.Background(), silent, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return journal.New(db, journal.EngineSQLite), db
}

func failClosedDispatcher(j *journal.Journal, artifact func(string, string) (string, error)) *Dispatcher {
	return &Dispatcher{
		Journal:      j,
		Resolver:     &SQLResolver{Journal: j},
		ArtifactPath: artifact,
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestDispatchFailsClosedWhenQuotaLookupFails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j, db := journalWithDB(t)
	createExecutableWorkflow(t, j, "wf_quota_error", "quota-error")
	// Keep workflow/enabled reads working, but remove the tenant policy table.
	// CheckWorkflowEnqueueAllowed must surface this dependency failure instead
	// of treating the tenant as unlimited.
	if _, err := db.ExecContext(ctx, `DROP TABLE tenants`); err != nil {
		t.Fatalf("drop tenants: %v", err)
	}
	artifactCalled := false
	d := failClosedDispatcher(j, func(string, string) (string, error) {
		artifactCalled = true
		return "/never-started", nil
	})

	_, err := d.DispatchManual(ctx, journal.Trigger{WorkflowID: "wf_quota_error", Kind: journal.TriggerManual}, []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "quota admission check failed") {
		t.Fatalf("quota lookup failure = %v, want fail-closed quota admission error", err)
	}
	if artifactCalled {
		t.Fatal("quota lookup failure reached immutable artifact resolution")
	}
}

func TestDispatchFailsClosedWhenEnabledStateLookupFails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j, db := journalWithDB(t)
	createExecutableWorkflow(t, j, "wf_enabled_error", "enabled-error")
	// The enabled flag is the workflow kill switch. Removing its backing table
	// must refuse dispatch before quota or artifact resolution can run.
	if _, err := db.ExecContext(ctx, `ALTER TABLE workflows RENAME TO workflows_enabled_error`); err != nil {
		t.Fatalf("rename workflows: %v", err)
	}
	artifactCalled := false
	d := failClosedDispatcher(j, func(string, string) (string, error) {
		artifactCalled = true
		return "/never-started", nil
	})

	_, err := d.DispatchManual(ctx, journal.Trigger{WorkflowID: "wf_enabled_error", Kind: journal.TriggerManual}, []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "enabled-state admission check failed") {
		t.Fatalf("enabled-state lookup failure = %v, want fail-closed admission error", err)
	}
	if artifactCalled {
		t.Fatal("enabled-state lookup failure reached immutable artifact resolution")
	}
}

func TestDispatchFailsClosedWhenRateLimitLookupFails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j, db := journalWithDB(t)
	createExecutableWorkflow(t, j, "wf_rate_error", "rate-error")
	if err := j.SetWorkflowRateLimit(ctx, "wf_rate_error", 1); err != nil {
		t.Fatalf("set rate limit: %v", err)
	}
	// The enabled and quota checks still work. Removing only the runs table
	// makes the configured rate-window count fail, proving dispatch does not
	// interpret an unavailable counter as an empty window.
	if _, err := db.ExecContext(ctx, `ALTER TABLE runs RENAME TO runs_rate_error`); err != nil {
		t.Fatalf("rename runs: %v", err)
	}
	d := failClosedDispatcher(j, func(string, string) (string, error) {
		return "/never-started", nil
	})

	_, err := d.DispatchManual(ctx, journal.Trigger{WorkflowID: "wf_rate_error", Kind: journal.TriggerManual}, []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "rate-limit admission check failed") {
		t.Fatalf("rate lookup failure = %v, want fail-closed rate-limit admission error", err)
	}
}

func TestRetryDeadLetterFailsClosedWhenQuotaLookupFails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j, db := journalWithDB(t)
	createExecutableWorkflow(t, j, "wf_dlq_quota_error", "dlq-quota-error")
	if err := j.CreateRunPinned(ctx, "run_dlq_quota_error", "wf_dlq_quota_error", "manual", json.RawMessage(`{}`), 1, testArtifactSHA256); err != nil {
		t.Fatalf("create run: %v", err)
	}
	if _, err := j.RecordStepStartSeq(ctx, "run_dlq_quota_error", "send", 1, 1, "send-key", "send-hash"); err != nil {
		t.Fatalf("step start: %v", err)
	}
	if dead, err := j.FinalizeStepAttemptSeq(ctx, "run_dlq_quota_error", "send", 1, 1, nil, "failed", false); err != nil || !dead {
		t.Fatalf("dead-letter step = %v, %v", dead, err)
	}
	if err := j.MarkRunFinished(ctx, "run_dlq_quota_error", "failed_dlq"); err != nil {
		t.Fatalf("mark failed_dlq: %v", err)
	}
	item, err := j.FindDeadLetterByRun(ctx, "run_dlq_quota_error")
	if err != nil {
		t.Fatalf("find dead letter: %v", err)
	}
	if _, err := db.ExecContext(ctx, `DROP TABLE tenants`); err != nil {
		t.Fatalf("drop tenants: %v", err)
	}
	d := failClosedDispatcher(j, func(string, string) (string, error) {
		return "/never-started", nil
	})

	status, err := d.RetryDeadLetter(ctx, item.ID)
	if status != "" || err == nil || !strings.Contains(err.Error(), "dlq retry quota admission check failed") {
		t.Fatalf("DLQ quota lookup failure = status %q err %v, want fail-closed admission error", status, err)
	}
	run, err := j.GetRun(ctx, "run_dlq_quota_error")
	if err != nil {
		t.Fatalf("read run after refused retry: %v", err)
	}
	if run.Status != "failed_dlq" {
		t.Fatalf("refused retry changed run status to %q", run.Status)
	}
}
