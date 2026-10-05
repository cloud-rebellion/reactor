package journal

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// seedAnalyticsFixture creates a second workflow + a handful of runs
// spanning both workflows so analytics has interesting data to roll up.
// Returns the journal ready for AnalyticsSummary.
func seedAnalyticsFixture(t *testing.T, j *Journal) {
	t.Helper()
	ctx := context.Background()

	// Workflow 2 with a declared baseline of 5 minutes per run.
	if err := j.CreateWorkflow(ctx, "wf_2", "second", "h2", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("create wf_2: %v", err)
	}
	if err := j.SetEstimatedMinutesSavedPerRun(ctx, "wf_2", 5); err != nil {
		t.Fatalf("set minutes for wf_2: %v", err)
	}

	// run_1 (wf_1, succeeded, 1s duration).
	if err := j.MarkRunFinished(ctx, "run_1", "succeeded"); err != nil {
		t.Fatalf("finish run_1: %v", err)
	}

	// wf_2 runs: three succeeded, one failed_dlq.
	for i, status := range []string{"succeeded", "succeeded", "succeeded", "failed_dlq"} {
		runID := "run_wf2_" + itoa(i)
		if err := j.CreateRun(ctx, runID, "wf_2", "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatalf("create run wf_2 #%d: %v", i, err)
		}
		if err := j.MarkRunFinished(ctx, runID, status); err != nil {
			t.Fatalf("finish run wf_2 #%d: %v", i, err)
		}
	}
}

// itoa avoids the strconv import inside a tiny helper.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

func TestSetEstimatedMinutesSavedPerRunRejectsNegative(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	if err := j.SetEstimatedMinutesSavedPerRun(context.Background(), "wf_1", -5); err == nil {
		t.Fatal("negative minutes should have been rejected")
	}
}

func TestSetEstimatedMinutesSavedPerRunRoundTrip(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.SetEstimatedMinutesSavedPerRun(ctx, "wf_1", 42); err != nil {
		t.Fatalf("set: %v", err)
	}
	w, err := j.GetWorkflow(ctx, "wf_1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if w.EstimatedMinutesSavedPerRun != 42 {
		t.Fatalf("got %d, want 42", w.EstimatedMinutesSavedPerRun)
	}
}

func TestSetEstimatedMinutesSavedPerRunUnknownWorkflow(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	if err := j.SetEstimatedMinutesSavedPerRun(context.Background(), "wf_missing", 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestAnalyticsSummaryRollsUp(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	// Declare a 10-min baseline on wf_1 (fixture).
	if err := j.SetEstimatedMinutesSavedPerRun(ctx, "wf_1", 10); err != nil {
		t.Fatal(err)
	}
	seedAnalyticsFixture(t, j)

	got, err := j.AnalyticsSummary(ctx)
	if err != nil {
		t.Fatalf("AnalyticsSummary: %v", err)
	}

	// Total runs = 1 (wf_1) + 4 (wf_2) = 5
	if got.TotalRuns != 5 {
		t.Fatalf("TotalRuns = %d, want 5", got.TotalRuns)
	}
	if got.SucceededRuns != 4 {
		t.Fatalf("SucceededRuns = %d, want 4", got.SucceededRuns)
	}
	if got.RunsByStatus["succeeded"] != 4 {
		t.Fatalf("succeeded bucket = %d, want 4", got.RunsByStatus["succeeded"])
	}
	if got.RunsByStatus["failed_dlq"] != 1 {
		t.Fatalf("failed_dlq bucket = %d, want 1", got.RunsByStatus["failed_dlq"])
	}

	// Time saved: wf_1 (10 min/run * 1) + wf_2 (5 min/run * 3) = 25 min.
	if got.TotalMinutesSaved != 25 {
		t.Fatalf("TotalMinutesSaved = %d, want 25", got.TotalMinutesSaved)
	}

	// Per-workflow sort: wf_2 wins (15 min) > wf_1 (10 min) > zero-baseline.
	if len(got.PerWorkflow) < 2 {
		t.Fatalf("PerWorkflow rows = %d, want >= 2", len(got.PerWorkflow))
	}
	if got.PerWorkflow[0].Slug != "second" {
		t.Fatalf("top row slug = %s, want second", got.PerWorkflow[0].Slug)
	}
	if got.PerWorkflow[0].MinutesSavedTotal != 15 {
		t.Fatalf("top row total = %d, want 15", got.PerWorkflow[0].MinutesSavedTotal)
	}

	// DailyRuns has 7 buckets.
	if len(got.DailyRuns) != 7 {
		t.Fatalf("DailyRuns buckets = %d, want 7", len(got.DailyRuns))
	}
	// Today's bucket should hold every seeded run (they all just landed).
	today := got.DailyRuns[6]
	if today.Total < 4 {
		t.Fatalf("today's bucket = %d, want >= 4 (just-seeded runs)", today.Total)
	}
}

func TestAnalyticsSummaryEmptyState(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	// Move the seeded run into a terminal state but no baseline + no
	// second workflow. Headline tiles should render zeros without
	// erroring.
	ctx := context.Background()
	if err := j.MarkRunFinished(ctx, "run_1", "succeeded"); err != nil {
		t.Fatal(err)
	}
	got, err := j.AnalyticsSummary(ctx)
	if err != nil {
		t.Fatalf("AnalyticsSummary: %v", err)
	}
	if got.TotalMinutesSaved != 0 {
		t.Fatalf("TotalMinutesSaved = %d, want 0 (no baseline declared)", got.TotalMinutesSaved)
	}
	if got.TotalRuns != 1 {
		t.Fatalf("TotalRuns = %d, want 1", got.TotalRuns)
	}
}

func TestAnalyticsSummaryForTenantDoesNotAggregateOtherTenants(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_acme", "acme-flow", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_acme", "wf_acme", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, "run_acme", StatusSucceeded); err != nil {
		t.Fatal(err)
	}
	got, err := j.AnalyticsSummaryForTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("AnalyticsSummaryForTenant: %v", err)
	}
	if got.TotalRuns != 1 || got.SucceededRuns != 1 {
		t.Fatalf("tenant analytics = total %d succeeded %d, want 1/1", got.TotalRuns, got.SucceededRuns)
	}
	if len(got.PerWorkflow) != 1 || got.PerWorkflow[0].TenantID != "acme" {
		t.Fatalf("tenant analytics workflows = %+v, want only acme", got.PerWorkflow)
	}
}

func TestAnalyticsSummaryForTenantPageKeepsHeadlineCompleteAndRowsBounded(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	for _, row := range []struct {
		id, slug, tenant, run string
		minutes               int
	}{
		{"wf_page_a", "page-a", "acme", "run_page_a", 3},
		{"wf_page_b", "page-b", "acme", "run_page_b", 8},
		{"wf_page_foreign", "page-foreign", "other", "run_page_foreign", 99},
	} {
		if err := j.CreateWorkflowInTenant(ctx, row.id, row.slug, "h", "0.1.0", json.RawMessage(`{}`), row.tenant); err != nil {
			t.Fatal(err)
		}
		if err := j.SetEstimatedMinutesSavedPerRun(ctx, row.id, row.minutes); err != nil {
			t.Fatal(err)
		}
		if err := j.CreateRun(ctx, row.run, row.id, "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
		if err := j.MarkRunFinished(ctx, row.run, StatusSucceeded); err != nil {
			t.Fatal(err)
		}
	}

	first, hasMore, err := j.AnalyticsSummaryForTenantPage(ctx, "acme", 1, 0)
	if err != nil {
		t.Fatalf("first analytics page: %v", err)
	}
	if !hasMore || first.TotalRuns != 2 || first.SucceededRuns != 2 || first.TotalMinutesSaved != 11 || len(first.PerWorkflow) != 1 {
		t.Fatalf("first page = %+v, hasMore=%v", first, hasMore)
	}
	if first.PerWorkflow[0].WorkflowID != "wf_page_b" || first.PerWorkflow[0].TenantID != "acme" {
		t.Fatalf("first page row = %+v", first.PerWorkflow[0])
	}

	second, hasMore, err := j.AnalyticsSummaryForTenantPage(ctx, "acme", 1, 1)
	if err != nil {
		t.Fatalf("second analytics page: %v", err)
	}
	if hasMore || len(second.PerWorkflow) != 1 || second.PerWorkflow[0].WorkflowID != "wf_page_a" || second.PerWorkflow[0].TenantID != "acme" {
		t.Fatalf("second page = %+v, hasMore=%v", second, hasMore)
	}

	if _, _, err := j.AnalyticsSummaryForTenantPage(ctx, "", 1, 0); err == nil {
		t.Fatal("empty tenant should be rejected")
	}
	if _, _, err := j.AnalyticsSummaryForTenantPage(ctx, "acme", 0, 0); err == nil {
		t.Fatal("non-positive limit should be rejected")
	}
	if _, _, err := j.AnalyticsSummaryForTenantPage(ctx, "acme", maxAnalyticsWorkflowPage+1, 0); err == nil {
		t.Fatal("unbounded direct-call limit should be rejected")
	}
	if _, _, err := j.AnalyticsSummaryForTenantPage(ctx, "acme", 1, -1); err == nil {
		t.Fatal("negative offset should be rejected")
	}
	if _, _, err := j.AnalyticsSummaryForTenantPage(ctx, "acme", 1, maxAnalyticsWorkflowOffset+1); err == nil {
		t.Fatal("unbounded direct-call offset should be rejected")
	}
}

func TestAnalyticsExcludesRunsWithMismatchedWorkflowTenant(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_owner", "owner", "h", "0.1.0", json.RawMessage(`{}`), "owner"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_viewer", "viewer", "h", "0.1.0", json.RawMessage(`{}`), "viewer"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_owner", "wf_owner", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, "run_owner", StatusSucceeded); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE runs SET tenant_id = $1 WHERE id = $2`), "viewer", "run_owner"); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"owner", "viewer"} {
		for _, paged := range []bool{false, true} {
			var got Analytics
			var err error
			if paged {
				got, _, err = j.AnalyticsSummaryForTenantPage(ctx, tenant, 1, 0)
			} else {
				got, err = j.AnalyticsSummaryForTenant(ctx, tenant)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.TotalRuns != 0 || got.SucceededRuns != 0 || got.AvgDurationMs != 0 || got.TotalMinutesSaved != 0 {
				t.Fatalf("tenant=%s paged=%t leaked mismatched run: %+v", tenant, paged, got)
			}
			for _, day := range got.DailyRuns {
				if day.Total != 0 {
					t.Fatalf("tenant=%s paged=%t leaked daily run: %+v", tenant, paged, got.DailyRuns)
				}
			}
		}
	}
}

func TestPercentileEdgeCases(t *testing.T) {
	t.Parallel()
	// Empty slice should not panic.
	if got := percentileMs(nil, 0.95); got != 0 {
		t.Fatalf("empty p95 = %d, want 0", got)
	}
	// Single value: p95 is that value.
	if got := percentileMs([]int64{100}, 0.95); got != 100 {
		t.Fatalf("single p95 = %d, want 100", got)
	}
	// Sorted in calling code is not required.
	in := []int64{500, 100, 200, 400, 300}
	if got := percentileMs(in, 0.95); got != 500 {
		t.Fatalf("p95 = %d, want 500", got)
	}
	// Input unchanged after percentile (no in-place sort leak).
	if in[0] != 500 {
		t.Fatalf("input was mutated: %+v", in)
	}
}

func TestAnalyticsSucceededRunDurationsAverage(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	// Mark run_1 finished with a backdated started_at so duration > 0.
	if err := j.MarkRunFinished(ctx, "run_1", "succeeded"); err != nil {
		t.Fatal(err)
	}
	// Re-stamp started_at to a known value; finished_at was just set
	// by MarkRunFinished. Compute the expected duration.
	backStarted := time.Now().UTC().Add(-2 * time.Second)
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE runs SET started_at = $1 WHERE id = $2`),
		j.formatTime(backStarted), "run_1"); err != nil {
		t.Fatalf("backdate started_at: %v", err)
	}

	got, err := j.AnalyticsSummary(ctx)
	if err != nil {
		t.Fatalf("AnalyticsSummary: %v", err)
	}
	if got.AvgDurationMs <= 0 {
		t.Fatalf("AvgDurationMs = %d, want > 0 for a 2s seeded run", got.AvgDurationMs)
	}
}
