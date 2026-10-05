package journal

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
)

// The production analytics path uses PostgreSQL aggregates instead of
// materializing every run duration or daily event in the daemon. Exercise its
// SQL and exact nearest-rank/tenant semantics against an isolated database.
func TestPostgresAnalyticsAggregatesDurationsAndDailyCounts(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL to run PostgreSQL analytics integration")
	}
	// This opt-in test migrates and writes its target. Refuse a non-Postgres
	// URL or a database name that does not clearly identify a test database
	// before connecting or running any migration.
	engine, err := migrate.EngineFromURL(rawURL)
	if err != nil || engine != migrate.EnginePostgres {
		t.Fatalf("REACTOR_TEST_POSTGRES_URL must target Postgres: engine=%q err=%v", engine, err)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(strings.ToLower(strings.Trim(parsed.Path, "/")), "test") {
		t.Fatalf("REACTOR_TEST_POSTGRES_URL database name must contain 'test'")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), rawURL); err != nil {
		t.Fatal(err)
	}
	db, engine, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if engine != migrate.EnginePostgres {
		t.Fatalf("test URL selected %s, want postgres", engine)
	}
	j := New(db, EnginePostgres)
	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantID, foreignID := "analytics-"+suffix, "analytics-foreign-"+suffix
	workflowID, foreignWorkflowID, emptyWorkflowID := "wf_analytics_"+suffix, "wf_analytics_foreign_"+suffix, "wf_analytics_empty_"+suffix
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM runs WHERE workflow_id IN ($1,$2,$3)`, workflowID, foreignWorkflowID, emptyWorkflowID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM workflows WHERE id IN ($1,$2,$3)`, workflowID, foreignWorkflowID, emptyWorkflowID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE tenant_id IN ($1,$2)`, tenantID, foreignID)
	}()
	for _, tenant := range []string{tenantID, foreignID} {
		if err := j.UpsertTenant(ctx, Tenant{TenantID: tenant}); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct{ id, slug, tenant string }{
		{workflowID, "analytics", tenantID},
		{foreignWorkflowID, "analytics-foreign", foreignID},
	} {
		if err := j.CreateWorkflowInTenant(ctx, row.id, row.slug, "hash", "0.1.0", []byte(`{}`), row.tenant); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.SetEstimatedMinutesSavedPerRun(ctx, workflowID, 2); err != nil {
		t.Fatal(err)
	}
	started := time.Now().UTC().Add(-time.Second)
	if _, err := db.ExecContext(ctx, `INSERT INTO runs
		(id, workflow_id, tenant_id, trigger_kind, trigger_meta, status, started_at, finished_at, created_at)
		SELECT $1 || n::text, $2, $3, 'manual', '{}'::jsonb, 'succeeded',
			$4::timestamptz, $4::timestamptz + n * INTERVAL '1 millisecond', $4::timestamptz
		FROM generate_series(1,100) AS n`, "run_analytics_"+suffix+"_", workflowID, tenantID, started); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO runs
		(id, workflow_id, tenant_id, trigger_kind, trigger_meta, status, started_at, finished_at, created_at)
		VALUES ($1,$2,$3,'manual','{}'::jsonb,'succeeded',
			$4::timestamptz,$4::timestamptz + INTERVAL '1 second',$4::timestamptz)`,
		"run_analytics_foreign_"+suffix, foreignWorkflowID, foreignID, started); err != nil {
		t.Fatal(err)
	}
	// The FK only binds workflow_id, so a malformed imported row can carry a
	// different tenant_id. It must not contribute to either tenant's rollup.
	if _, err := db.ExecContext(ctx, `INSERT INTO runs
		(id, workflow_id, tenant_id, trigger_kind, trigger_meta, status, started_at, finished_at, created_at)
		VALUES ($1,$2,$3,'manual','{}'::jsonb,'succeeded',
			$4::timestamptz,$4::timestamptz + INTERVAL '2 seconds',$4::timestamptz)`,
		"run_analytics_mismatched_"+suffix, foreignWorkflowID, tenantID, started); err != nil {
		t.Fatal(err)
	}
	for _, get := range []struct {
		name string
		fn   func() (Analytics, error)
	}{
		{"dashboard", func() (Analytics, error) { return j.AnalyticsSummaryForTenant(ctx, tenantID) }},
		{"MCP page", func() (Analytics, error) {
			rollup, more, err := j.AnalyticsSummaryForTenantPage(ctx, tenantID, 10, 0)
			if more {
				return Analytics{}, fmt.Errorf("unexpected second workflow page")
			}
			return rollup, err
		}},
	} {
		t.Run(get.name, func(t *testing.T) {
			got, err := get.fn()
			if err != nil {
				t.Fatal(err)
			}
			if got.TotalRuns != 100 || got.SucceededRuns != 100 || got.AvgDurationMs != 50 || got.P95DurationMs != 95 || got.TotalMinutesSaved != 200 {
				t.Fatalf("tenant aggregate = %+v", got)
			}
			if len(got.PerWorkflow) != 1 || got.PerWorkflow[0].WorkflowID != workflowID || got.PerWorkflow[0].AvgDurationMs != 50 {
				t.Fatalf("per-workflow aggregate = %+v", got.PerWorkflow)
			}
			var dailyTotal int
			for _, bucket := range got.DailyRuns {
				dailyTotal += bucket.Total
			}
			if dailyTotal != 100 {
				t.Fatalf("daily buckets = %+v; want tenant total 100", got.DailyRuns)
			}
		})
	}
	fleet, more, err := j.AnalyticsSummaryPage(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !more || !fleet.PerWorkflowHasMore || fleet.TotalRuns != 101 || fleet.SucceededRuns != 101 || fleet.TotalMinutesSaved != 200 || fleet.AvgDurationMs != 59 || fleet.P95DurationMs != 96 {
		t.Fatalf("fleet headline or page = %+v, more=%t", fleet, more)
	}
	if len(fleet.PerWorkflow) != 1 || fleet.PerWorkflow[0].WorkflowID != workflowID {
		t.Fatalf("fleet first page = %+v", fleet.PerWorkflow)
	}
	fleetNext, more, err := j.AnalyticsSummaryPage(ctx, 1, 1)
	if err != nil || more || len(fleetNext.PerWorkflow) != 1 || fleetNext.PerWorkflow[0].WorkflowID != foreignWorkflowID {
		t.Fatalf("fleet second page = %+v, more=%t, err=%v", fleetNext.PerWorkflow, more, err)
	}
	if err := j.CreateWorkflowInTenant(ctx, emptyWorkflowID, "analytics-empty", "hash", "0.1.0", []byte(`{}`), tenantID); err != nil {
		t.Fatal(err)
	}
	first, more, err := j.AnalyticsSummaryForTenantPage(ctx, tenantID, 1, 0)
	if err != nil || !more || len(first.PerWorkflow) != 1 || first.PerWorkflow[0].WorkflowID != workflowID {
		t.Fatalf("first Postgres workflow page = %+v, more=%t, err=%v", first.PerWorkflow, more, err)
	}
	second, more, err := j.AnalyticsSummaryForTenantPage(ctx, tenantID, 1, 1)
	if err != nil || more || len(second.PerWorkflow) != 1 || second.PerWorkflow[0].WorkflowID != emptyWorkflowID || second.PerWorkflow[0].AvgDurationMs != 0 {
		t.Fatalf("second Postgres workflow page = %+v, more=%t, err=%v", second.PerWorkflow, more, err)
	}
}
