package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/bright-interaction/reactor/internal/migrate"
	_ "modernc.org/sqlite"
)

func newTestJournal(t *testing.T) (*Journal, func()) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "j.db")
	url := "sqlite://" + dbPath

	log := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if err := migrate.Up(context.Background(), log, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	j := New(db, EngineSQLite)

	// Seed a workflow + run so step rows have valid FKs.
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_1", "demo", "hash1", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("create workflow: %v", err)
	}
	if err := j.CreateRun(ctx, "run_1", "wf_1", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("create run: %v", err)
	}

	return j, func() { db.Close() }
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

func TestRecordStepStartInsertOnce(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	ins, err := j.RecordStepStart(ctx, "run_1", "fetch", 1, "k1", "h1")
	if err != nil {
		t.Fatal(err)
	}
	if !ins {
		t.Fatal("first start should insert")
	}
	// Second call with same PK should not insert.
	ins2, err := j.RecordStepStart(ctx, "run_1", "fetch", 1, "k1", "h1")
	if err != nil {
		t.Fatal(err)
	}
	if ins2 {
		t.Fatal("conflicting start should not insert")
	}
}

func TestRecordStepEndCachesOutput(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := j.RecordStepStart(ctx, "run_1", "fetch", 1, "cust-1", "h"); err != nil {
		t.Fatal(err)
	}
	out := json.RawMessage(`{"id":"cus_42"}`)
	if err := j.RecordStepEnd(ctx, "run_1", "fetch", 1, out, ""); err != nil {
		t.Fatal(err)
	}

	got, err := j.FindCachedOutput(ctx, "run_1", "fetch", "cust-1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(out) {
		t.Fatalf("got %s, want %s", got, out)
	}
}

func TestFindCachedOutputNotFound(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := j.FindCachedOutput(ctx, "run_1", "missing", "k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestFindCachedOutputIgnoresFailures(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	_, _ = j.RecordStepStart(ctx, "run_1", "fetch", 1, "k1", "h")
	if err := j.RecordStepEnd(ctx, "run_1", "fetch", 1, nil, "boom"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.FindCachedOutput(ctx, "run_1", "fetch", "k1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed step should not surface as cached output, got %v", err)
	}
}

func TestFindCachedOutputPicksLatestSuccess(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	// attempt 1 fails, attempt 2 succeeds with v1, attempt 3 succeeds with v2.
	_, _ = j.RecordStepStart(ctx, "run_1", "fetch", 1, "k", "h")
	_ = j.RecordStepEnd(ctx, "run_1", "fetch", 1, nil, "transient")

	_, _ = j.RecordStepStart(ctx, "run_1", "fetch", 2, "k", "h")
	_ = j.RecordStepEnd(ctx, "run_1", "fetch", 2, json.RawMessage(`"v1"`), "")

	_, _ = j.RecordStepStart(ctx, "run_1", "fetch", 3, "k", "h")
	_ = j.RecordStepEnd(ctx, "run_1", "fetch", 3, json.RawMessage(`"v2"`), "")

	got, err := j.FindCachedOutput(ctx, "run_1", "fetch", "k")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `"v2"` {
		t.Fatalf("got %s, want \"v2\"", got)
	}
}

func TestAttemptCount(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	for i := 1; i <= 4; i++ {
		_, _ = j.RecordStepStart(ctx, "run_1", "fetch", i, "", "h")
	}
	n, err := j.AttemptCount(ctx, "run_1", "fetch")
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("got %d, want 4", n)
	}
}

func TestRecordStepEndMissingRow(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	if err := j.RecordStepEnd(context.Background(), "run_1", "missing", 1, nil, ""); err == nil {
		t.Fatal("step_end without step_start should error")
	}
}

// TestListRunsFilters seeds runs across two workflows + statuses and
// asserts that RunFilter narrows correctly + paginates by limit/offset.
func TestListRunsFilters(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	// Already seeded: wf_1/run_1 (running). Add a second workflow + a few runs.
	if err := j.CreateWorkflow(ctx, "wf_2", "demo2", "h2", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"run_2a", "run_2b", "run_2c"} {
		if err := j.CreateRun(ctx, id, "wf_2", "webhook", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.MarkRunFinished(ctx, "run_2a", "succeeded"); err != nil {
		t.Fatal(err)
	}

	all, err := j.ListRuns(ctx, RunFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Fatalf("want 4 runs, got %d", len(all))
	}

	wf2, err := j.ListRuns(ctx, RunFilter{WorkflowID: "wf_2", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(wf2) != 3 {
		t.Fatalf("want 3 wf_2 runs, got %d", len(wf2))
	}
	for _, r := range wf2 {
		if r.WorkflowID != "wf_2" {
			t.Fatalf("filter leaked %q", r.WorkflowID)
		}
	}

	succ, err := j.ListRuns(ctx, RunFilter{Status: "succeeded", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(succ) != 1 || succ[0].ID != "run_2a" {
		t.Fatalf("status filter wrong: %+v", succ)
	}

	page1, err := j.ListRuns(ctx, RunFilter{Limit: 2, Offset: 0})
	if err != nil {
		t.Fatal(err)
	}
	page2, err := j.ListRuns(ctx, RunFilter{Limit: 2, Offset: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(page1) != 2 || len(page2) != 2 {
		t.Fatalf("pagination: page1=%d page2=%d", len(page1), len(page2))
	}
	if page1[0].ID == page2[0].ID {
		t.Fatal("pages overlap")
	}

	total, err := j.CountRuns(ctx, RunFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 {
		t.Fatalf("total = %d, want 4", total)
	}
	wf2Total, err := j.CountRuns(ctx, RunFilter{WorkflowID: "wf_2"})
	if err != nil {
		t.Fatal(err)
	}
	if wf2Total != 3 {
		t.Fatalf("wf_2 total = %d, want 3", wf2Total)
	}
}

func TestListRunsPaginationUsesStableTieBreaker(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_tie", "tie", "hash-tie", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	ids := []string{"run_tie_a", "run_tie_b", "run_tie_c"}
	for _, id := range ids {
		if err := j.CreateRun(ctx, id, "wf_tie", "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE runs SET started_at = $1 WHERE id = $2`), "2026-01-01T00:00:00.000000Z", id); err != nil {
			t.Fatalf("set tied timestamp for %s: %v", id, err)
		}
	}

	// Every row has the same started_at. The secondary id ordering should make
	// each offset page repeatable and cover each run exactly once.
	want := []string{"run_tie_c", "run_tie_b", "run_tie_a"}
	for offset, wantID := range want {
		page, err := j.ListRuns(ctx, RunFilter{WorkflowID: "wf_tie", Limit: 1, Offset: offset})
		if err != nil {
			t.Fatalf("page %d: %v", offset, err)
		}
		if len(page) != 1 || page[0].ID != wantID {
			t.Fatalf("page %d = %+v, want %s", offset, page, wantID)
		}
	}
	pageAgain, err := j.ListRuns(ctx, RunFilter{WorkflowID: "wf_tie", Limit: 1, Offset: 0})
	if err != nil {
		t.Fatal(err)
	}
	if len(pageAgain) != 1 || pageAgain[0].ID != want[0] {
		t.Fatalf("repeated first page = %+v, want %s", pageAgain, want[0])
	}
}
