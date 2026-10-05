package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestHomePageRendersAnalyticsStrip seeds two workflows + multiple
// runs, declares a baseline on one of them, and verifies the home
// page surfaces the headline numbers (total runs, succeeded count,
// time saved) plus the per-workflow rollup table.
func TestHomePageRendersAnalyticsStrip(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t)
	ctx := context.Background()

	if err := j.CreateWorkflow(ctx, "wf_a", "alpha", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.SetEstimatedMinutesSavedPerRun(ctx, "wf_a", 7); err != nil {
		t.Fatal(err)
	}
	for i, status := range []string{"succeeded", "succeeded", "failed"} {
		runID := "run_" + itoa(i)
		if err := j.CreateRun(ctx, runID, "wf_a", "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
		if err := j.MarkRunFinished(ctx, runID, status); err != nil {
			t.Fatal(err)
		}
	}

	body := getBody(t, srv.URL+"/")
	s := string(body)
	for _, want := range []string{
		`class="tiles"`,
		`Total runs`,
		`Succeeded`,
		`Time saved`,
		`Last 7 days`,
		`Time saved by workflow`,
		`alpha`,
		`14 min`, // 7 min/run * 2 succeeded
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("home page missing %q\n--- body ---\n%s", want, s)
		}
	}
}

func TestCachedTenantAnalyticsDoesNotReuseEstateOrOtherTenantData(t *testing.T) {
	t.Parallel()
	j := journalForServerTest(t)
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_acme_metrics", "acme-metrics", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_globex_metrics", "globex-metrics", "h", "0.1.0", json.RawMessage(`{}`), "globex"); err != nil {
		t.Fatal(err)
	}
	for _, run := range []struct {
		id, workflow, status string
	}{
		{"run_acme_metrics", "wf_acme_metrics", "succeeded"},
		{"run_globex_metrics", "wf_globex_metrics", "succeeded"},
	} {
		if err := j.CreateRun(ctx, run.id, run.workflow, "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
		if err := j.MarkRunFinished(ctx, run.id, run.status); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{Journal: j}
	got, err := s.cachedTenantAnalytics(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if !got.available || got.stale || len(got.value.PerWorkflow) != 1 || got.value.PerWorkflow[0].TenantID != "acme" {
		t.Fatalf("tenant cache returned foreign or unavailable workflow rows: %+v", got)
	}
	if _, ok := s.analyticsTenantCache["globex"]; ok {
		t.Fatal("computing acme metrics populated another tenant's cache entry")
	}
}

func TestHomeAnalyticsCachesOnlyVisibleWorkflowRowsWithoutTruncatingHeadlines(t *testing.T) {
	t.Parallel()
	j := journalForServerTest(t)
	ctx := context.Background()
	for i := 1; i <= homeAnalyticsWorkflowLimit+2; i++ {
		id := "wf_bounded_home_" + itoa(i)
		if err := j.CreateWorkflowInTenant(ctx, id, "bounded-home-"+itoa(i), "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
			t.Fatal(err)
		}
		if err := j.SetEstimatedMinutesSavedPerRun(ctx, id, i); err != nil {
			t.Fatal(err)
		}
		runID := "run_bounded_home_" + itoa(i)
		if err := j.CreateRun(ctx, runID, id, "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
		if err := j.MarkRunFinished(ctx, runID, "succeeded"); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{Journal: j}
	for _, get := range []struct {
		name string
		fn   func(context.Context) (analyticsSnapshot, error)
	}{
		{"tenant", func(ctx context.Context) (analyticsSnapshot, error) { return s.cachedTenantAnalytics(ctx, "acme") }},
		{"fleet", s.cachedAnalytics},
	} {
		t.Run(get.name, func(t *testing.T) {
			got, err := get.fn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !got.available || got.value.TotalRuns != homeAnalyticsWorkflowLimit+2 || got.value.SucceededRuns != homeAnalyticsWorkflowLimit+2 || got.value.TotalMinutesSaved != 78 {
				t.Fatalf("truncated headline: %+v", got)
			}
			if len(got.value.PerWorkflow) != homeAnalyticsWorkflowLimit || !got.value.PerWorkflowHasMore || got.value.PerWorkflow[0].Slug != "bounded-home-12" {
				t.Fatalf("home workflow page: %+v", got.value.PerWorkflow)
			}
			html := renderAnalyticsStrip(got.value)
			if !strings.Contains(html, `Showing top 10 by impact`) {
				t.Fatalf("home table hides its pagination: %s", html)
			}
		})
	}
}

func TestHomeAnalyticsShowsFreshStaleAndUnavailableStates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j := journalForServerTest(t)
	if err := j.CreateWorkflowInTenant(ctx, "wf_analytics_state", "analytics-state", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_analytics_state", "wf_analytics_state", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, "run_analytics_state", "succeeded"); err != nil {
		t.Fatal(err)
	}

	s := &Server{Journal: j}
	fresh, err := s.cachedTenantAnalytics(ctx, "acme")
	if err != nil || !fresh.available || fresh.stale || fresh.value.TotalRuns != 1 || fresh.asOf.IsZero() {
		t.Fatalf("fresh analytics = %+v, err=%v", fresh, err)
	}
	freshHTML := homeBody(homeData{Analytics: fresh, WorkerCount: 2, WorkerCapacity: 4})
	if !strings.Contains(freshHTML, `Total runs`) || !strings.Contains(freshHTML, `<strong>0</strong> run(s) queued`) || strings.Contains(freshHTML, `Analytics refresh failed`) {
		t.Fatalf("fresh home analytics omitted or mislabeled: %s", freshHTML)
	}

	oldAsOf := time.Now().UTC().Add(-analyticsTTL - time.Second)
	s.analyticsTenantCache["acme"] = analyticsCacheEntry{value: fresh.value, at: oldAsOf}
	failedCtx, cancel := context.WithCancel(ctx)
	cancel()
	stale, err := s.cachedTenantAnalytics(failedCtx, "acme")
	if err == nil || !stale.available || !stale.stale || stale.value.TotalRuns != 1 || !stale.asOf.Equal(oldAsOf) {
		t.Fatalf("stale analytics = %+v, err=%v", stale, err)
	}
	staleHTML := homeBody(homeData{Analytics: stale, WorkerCount: 2, WorkerCapacity: 4})
	if !strings.Contains(staleHTML, `Analytics refresh failed`) || !strings.Contains(staleHTML, oldAsOf.Format(time.RFC3339)) || !strings.Contains(staleHTML, `Total runs`) {
		t.Fatalf("stale home did not mark last-good counts: %s", staleHTML)
	}

	cold := &Server{Journal: j}
	unavailable, err := cold.cachedTenantAnalytics(failedCtx, "acme")
	if err == nil || unavailable.available {
		t.Fatalf("cold failure presented as available: %+v, err=%v", unavailable, err)
	}
	unavailableHTML := homeBody(homeData{Analytics: unavailable, WorkerCount: 2, WorkerCapacity: 4})
	if !strings.Contains(unavailableHTML, `Analytics unavailable`) || strings.Contains(unavailableHTML, `class="tiles"`) || strings.Contains(unavailableHTML, `run(s) queued`) {
		t.Fatalf("cold failure displayed false run or queue numbers: %s", unavailableHTML)
	}
}

func TestEstateHomeAnalyticsMarksFailedRefreshStale(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j := journalForServerTest(t)
	if err := j.CreateWorkflow(ctx, "wf_estate_analytics", "estate-analytics", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	s := &Server{Journal: j}
	fresh, err := s.cachedAnalytics(ctx)
	if err != nil || !fresh.available || fresh.stale || fresh.asOf.IsZero() {
		t.Fatalf("fresh estate analytics = %+v, err=%v", fresh, err)
	}
	s.analyticsAt = time.Now().UTC().Add(-analyticsTTL - time.Second)
	failedCtx, cancel := context.WithCancel(ctx)
	cancel()
	stale, err := s.cachedAnalytics(failedCtx)
	if err == nil || !stale.available || !stale.stale || !stale.asOf.Equal(s.analyticsAt) {
		t.Fatalf("stale estate analytics = %+v, err=%v", stale, err)
	}
	cold, err := (&Server{Journal: j}).cachedAnalytics(failedCtx)
	if err == nil || cold.available {
		t.Fatalf("cold estate analytics = %+v, err=%v", cold, err)
	}
}

// TestWorkflowSetMinutesSavedRoundTrip POSTs to the new handler with
// a same-origin CSRF header, verifies a 303 redirect, and reads back
// the value via the workflow detail page render.
func TestWorkflowSetMinutesSavedRoundTrip(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t)
	ctx := context.Background()

	if err := j.CreateWorkflow(ctx, "wf_beta", "beta", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}

	form := url.Values{"minutes": []string{"42"}}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/workflows/beta/minutes-saved", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", srv.URL)
	noFollow := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}

	// Verify the journal stored it + the home page renders the rollup.
	wf, err := j.GetWorkflow(ctx, "wf_beta")
	if err != nil {
		t.Fatal(err)
	}
	if wf.EstimatedMinutesSavedPerRun != 42 {
		t.Fatalf("journal stored %d, want 42", wf.EstimatedMinutesSavedPerRun)
	}

	// Workflow detail page must pre-populate the input with the new
	// value so a re-load + re-edit shows the right baseline.
	body := getBody(t, srv.URL+"/workflows/beta")
	if !strings.Contains(string(body), `value="42"`) {
		t.Fatal("workflow detail page should pre-populate the minutes input with the stored value")
	}
}

func TestWorkflowSetMinutesSavedRejectsNegative(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t)
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_gamma", "gamma", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"minutes": []string{"-10"}}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/workflows/gamma/minutes-saved", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", srv.URL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for negative minutes", resp.StatusCode)
	}
}
