package journal

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"sort"
	"time"
)

// Analytics is the home-dashboard rollup the operator sees on first
// load. Counts by terminal status, duration percentiles over succeeded
// runs (so failed-DLQ outliers do not skew the perf number), and
// total minutes saved (sum of estimated_minutes_saved_per_run per
// workflow times that workflow's succeeded count).
type Analytics struct {
	// TotalRuns includes every status (running, succeeded, failed,
	// failed_dlq, suspended). RunsByStatus breaks down the counts.
	TotalRuns     int
	RunsByStatus  map[string]int
	SucceededRuns int

	// AvgDurationMs and P95DurationMs are computed over succeeded runs
	// only. Failed / dead-lettered runs are excluded so a hostile or
	// buggy workflow's failure pattern doesn't poison the perf headline.
	AvgDurationMs int64
	P95DurationMs int64

	// TotalMinutesSaved is the headline operator number: sum across
	// workflows of (estimated_minutes_saved_per_run * succeeded_runs).
	// Workflows with a zero baseline contribute nothing.
	TotalMinutesSaved int64

	// PerWorkflow is the per-workflow breakdown sorted by minutes saved
	// descending so the highest-impact automations land at the top of
	// the dashboard table.
	PerWorkflow []WorkflowAnalytics
	// PerWorkflowHasMore is set by paged summaries. Headline values still
	// cover the complete scope when this is true.
	PerWorkflowHasMore bool

	// DailyRuns is a 7-element slice covering the last 7 days
	// (DailyRuns[0] is six days ago, DailyRuns[6] is today). Drives the
	// sparkline-style activity strip on the home page.
	DailyRuns []DailyRunCount
}

// WorkflowAnalytics is the per-workflow rollup row.
type WorkflowAnalytics struct {
	WorkflowID string
	Slug       string
	// TenantID disambiguates the dashboard link: slugs are unique only per
	// tenant, so two rows can share a slug and a bare href would send both to
	// whichever workflow is newest.
	TenantID                    string
	SucceededRuns               int
	FailedRuns                  int
	AvgDurationMs               int64
	EstimatedMinutesSavedPerRun int
	MinutesSavedTotal           int64
}

// DailyRunCount is one bucket in the 7-day strip.
type DailyRunCount struct {
	Day   time.Time // 00:00 UTC of the bucket
	Total int
}

// PostgreSQL's timestamp subtraction is exact enough to floor to the same
// whole-millisecond value as Go's time.Duration.Milliseconds for valid runs.
// Keep this expression shared by the global and per-workflow projections.
const postgresRunDurationMs = `FLOOR(EXTRACT(EPOCH FROM (r.finished_at - r.started_at)) * 1000)::bigint`

const (
	maxAnalyticsWorkflowPage   = 1000
	maxAnalyticsWorkflowOffset = 1000000
)

// AnalyticsSummary returns the home-dashboard rollup. PostgreSQL keeps run
// duration and daily activity aggregation in the database so the daemon's
// memory does not grow with a high-volume tenant's retained run history.
func (j *Journal) AnalyticsSummary(ctx context.Context) (Analytics, error) {
	return j.analyticsSummary(ctx, "")
}

// AnalyticsSummaryForTenant returns the same rollup restricted to one
// tenant. Keeping the predicate in every aggregate prevents an MCP client
// from learning fleet-wide activity through a seemingly read-only tool.
func (j *Journal) AnalyticsSummaryForTenant(ctx context.Context, tenantID string) (Analytics, error) {
	if tenantID == "" {
		return Analytics{}, fmt.Errorf("analytics: tenant required")
	}
	return j.analyticsSummary(ctx, tenantID)
}

// AnalyticsSummaryPage returns fleet-wide headline values and a bounded page
// of workflow rows for the operator dashboard. It avoids retaining every
// workflow's rollup in each cached home-page snapshot.
func (j *Journal) AnalyticsSummaryPage(ctx context.Context, limit, offset int) (Analytics, bool, error) {
	if err := validateAnalyticsPage(limit, offset); err != nil {
		return Analytics{}, false, err
	}
	return j.analyticsSummaryPage(ctx, "", limit, offset)
}

// AnalyticsSummaryForTenantPage returns a tenant-scoped analytics rollup with
// only one page of per-workflow rows. Headline totals still cover the complete
// tenant, while status counts are aggregated in one query and per-workflow
// duration work is limited to the workflows in the requested page. The global
// p95 and ranking still read retained tenant history, so this is a memory and
// result-size bound rather than a constant-time dashboard query.
func (j *Journal) AnalyticsSummaryForTenantPage(ctx context.Context, tenantID string, limit, offset int) (Analytics, bool, error) {
	if tenantID == "" {
		return Analytics{}, false, fmt.Errorf("analytics: tenant required")
	}
	if err := validateAnalyticsPage(limit, offset); err != nil {
		return Analytics{}, false, err
	}
	return j.analyticsSummaryPage(ctx, tenantID, limit, offset)
}

func validateAnalyticsPage(limit, offset int) error {
	if limit <= 0 {
		return fmt.Errorf("analytics: limit must be positive")
	}
	if limit > maxAnalyticsWorkflowPage {
		return fmt.Errorf("analytics: limit exceeds %d", maxAnalyticsWorkflowPage)
	}
	if offset < 0 {
		return fmt.Errorf("analytics: offset must not be negative")
	}
	if offset > maxAnalyticsWorkflowOffset {
		return fmt.Errorf("analytics: offset exceeds %d", maxAnalyticsWorkflowOffset)
	}
	return nil
}

func (j *Journal) analyticsSummary(ctx context.Context, tenantID string) (Analytics, error) {
	statusCounts, err := j.countRunsByStatus(ctx, tenantID)
	if err != nil {
		return Analytics{}, err
	}

	out := Analytics{
		RunsByStatus: statusCounts,
		DailyRuns:    make([]DailyRunCount, 7),
	}
	for _, n := range statusCounts {
		out.TotalRuns += n
	}
	out.SucceededRuns = statusCounts[StatusSucceeded]

	if j.engine == EnginePostgres {
		out.PerWorkflow, err = j.postgresWorkflowAnalytics(ctx, tenantID)
		if err != nil {
			return Analytics{}, err
		}
	} else {
		var wfs []Workflow
		if tenantID == "" {
			wfs, err = j.ListWorkflows(ctx)
		} else {
			wfs, err = j.ListWorkflowsByTenant(ctx, tenantID)
		}
		if err != nil {
			return Analytics{}, fmt.Errorf("analytics: list workflows: %w", err)
		}
		out.PerWorkflow = make([]WorkflowAnalytics, 0, len(wfs))
		for _, w := range wfs {
			row, perr := j.workflowAnalytics(ctx, w, tenantID)
			if perr != nil {
				return Analytics{}, perr
			}
			out.PerWorkflow = append(out.PerWorkflow, row)
		}
	}
	for _, row := range out.PerWorkflow {
		out.TotalMinutesSaved += row.MinutesSavedTotal
	}

	// Global avg + p95 over succeeded runs. The Postgres path returns two
	// scalar values rather than materializing every run in the daemon.
	out.AvgDurationMs, out.P95DurationMs, err = j.successfulDurationSummaryMs(ctx, tenantID)
	if err != nil {
		return Analytics{}, err
	}

	sort.Slice(out.PerWorkflow, func(i, j int) bool {
		if out.PerWorkflow[i].MinutesSavedTotal != out.PerWorkflow[j].MinutesSavedTotal {
			return out.PerWorkflow[i].MinutesSavedTotal > out.PerWorkflow[j].MinutesSavedTotal
		}
		// Tiebreak by succeeded count so workflows with no declared
		// baseline still surface in a stable order.
		return out.PerWorkflow[i].SucceededRuns > out.PerWorkflow[j].SucceededRuns
	})

	// Last-7-day activity strip. Anchor to UTC midnight so the bucket
	// boundaries are deterministic across daemon timezones.
	daily, err := j.recentDailyRunCounts(ctx, 7, tenantID)
	if err != nil {
		return Analytics{}, err
	}
	out.DailyRuns = daily

	return out, nil
}

func (j *Journal) analyticsSummaryPage(ctx context.Context, tenantID string, limit, offset int) (Analytics, bool, error) {
	statusCounts, err := j.countRunsByStatus(ctx, tenantID)
	if err != nil {
		return Analytics{}, false, err
	}
	out := Analytics{
		RunsByStatus: statusCounts,
		DailyRuns:    make([]DailyRunCount, 7),
	}
	for _, n := range statusCounts {
		out.TotalRuns += n
	}
	out.SucceededRuns = statusCounts[StatusSucceeded]

	rows, hasMore, err := j.workflowAnalyticsPage(ctx, tenantID, limit, offset)
	if err != nil {
		return Analytics{}, false, err
	}
	out.TotalMinutesSaved, err = j.totalMinutesSavedForTenant(ctx, tenantID)
	if err != nil {
		return Analytics{}, false, err
	}
	if j.engine != EnginePostgres {
		for i := range rows {
			durations, derr := j.successfulRunDurationsForWorkflowMs(ctx, rows[i].WorkflowID, tenantID)
			if derr != nil {
				return Analytics{}, false, derr
			}
			rows[i].AvgDurationMs = averageMs(durations)
		}
	}
	out.PerWorkflow = rows
	out.PerWorkflowHasMore = hasMore

	// Headline duration and activity metrics retain the complete tenant scope.
	out.AvgDurationMs, out.P95DurationMs, err = j.successfulDurationSummaryMs(ctx, tenantID)
	if err != nil {
		return Analytics{}, false, err
	}
	daily, err := j.recentDailyRunCounts(ctx, 7, tenantID)
	if err != nil {
		return Analytics{}, false, err
	}
	out.DailyRuns = daily
	return out, hasMore, nil
}

// countRunsByStatus runs one GROUP BY query for the whole runs table.
func (j *Journal) countRunsByStatus(ctx context.Context, tenantID string) (map[string]int, error) {
	// The denormalized run tenant is used for hot-path admission, but legacy
	// and imported rows can disagree with their workflow owner. Do not include
	// such rows in a tenant's customer-facing analytics.
	q := `SELECT r.status, COUNT(*) FROM runs r
		JOIN workflows w ON w.id = r.workflow_id AND w.tenant_id = r.tenant_id`
	args := []any{}
	if tenantID != "" {
		q += ` WHERE r.tenant_id = $1`
		args = append(args, tenantID)
	}
	q += ` GROUP BY r.status`
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, fmt.Errorf("analytics: status counts: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, fmt.Errorf("analytics: scan status: %w", err)
		}
		out[status] = n
	}
	return out, rows.Err()
}

// postgresWorkflowAnalytics groups all workflow rows in one database query.
// The local SQLite dashboard keeps its portable v1 path; distributed mode
// avoids one round-trip and duration result set per workflow.
func (j *Journal) postgresWorkflowAnalytics(ctx context.Context, tenantID string) ([]WorkflowAnalytics, error) {
	q := `SELECT w.id, w.slug, w.tenant_id, w.estimated_minutes_saved_per_run,
		COUNT(r.id) FILTER (WHERE r.status = $1),
		COUNT(r.id) FILTER (WHERE r.status IN ($2, $3)),
		COALESCE(FLOOR(AVG(` + postgresRunDurationMs + `) FILTER (
			WHERE r.status = $1 AND r.started_at IS NOT NULL AND r.finished_at IS NOT NULL
			AND r.finished_at >= r.started_at))::bigint, 0)
		FROM workflows w
		LEFT JOIN runs r ON r.workflow_id = w.id AND r.tenant_id = w.tenant_id`
	args := []any{StatusSucceeded, StatusFailed, "failed_dlq"}
	if tenantID != "" {
		q += ` WHERE w.tenant_id = $4`
		args = append(args, tenantID)
	}
	q += ` GROUP BY w.id, w.slug, w.tenant_id, w.estimated_minutes_saved_per_run`
	rows, err := j.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("analytics: workflow aggregate: %w", err)
	}
	defer rows.Close()
	var out []WorkflowAnalytics
	for rows.Next() {
		var row WorkflowAnalytics
		if err := rows.Scan(&row.WorkflowID, &row.Slug, &row.TenantID,
			&row.EstimatedMinutesSavedPerRun, &row.SucceededRuns, &row.FailedRuns, &row.AvgDurationMs); err != nil {
			return nil, fmt.Errorf("analytics: scan workflow aggregate: %w", err)
		}
		row.MinutesSavedTotal = int64(row.EstimatedMinutesSavedPerRun) * int64(row.SucceededRuns)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("analytics: workflow aggregate rows: %w", err)
	}
	return out, nil
}

func (j *Journal) workflowAnalyticsPage(ctx context.Context, tenantID string, limit, offset int) ([]WorkflowAnalytics, bool, error) {
	// Rank using counts first, then calculate duration only for the bounded
	// page. A duration AVG inside the grouped query would scan every tenant
	// workflow's timestamps even though only one page is returned.
	avgProjection := `0 AS avg_duration_ms`
	if j.engine == EnginePostgres {
		avgProjection = `COALESCE((SELECT FLOOR(AVG(` + postgresRunDurationMs + `))::bigint
			FROM runs r WHERE r.workflow_id = page.workflow_id AND r.tenant_id = page.tenant_id
			AND r.status = $1 AND r.started_at IS NOT NULL AND r.finished_at IS NOT NULL
			AND r.finished_at >= r.started_at), 0) AS avg_duration_ms`
	}
	q := `SELECT page.workflow_id, page.slug, page.tenant_id,
			page.estimated_minutes_saved_per_run, page.succeeded_runs, page.failed_runs, ` + avgProjection + `
		FROM (
			SELECT ranked.* FROM (
				SELECT w.id AS workflow_id, w.slug, w.tenant_id, w.estimated_minutes_saved_per_run,
					COALESCE(SUM(CASE WHEN r.status = $1 THEN 1 ELSE 0 END), 0) AS succeeded_runs,
					COALESCE(SUM(CASE WHEN r.status IN ($2, $3) THEN 1 ELSE 0 END), 0) AS failed_runs
				FROM workflows w
				LEFT JOIN runs r ON r.workflow_id = w.id AND r.tenant_id = w.tenant_id`
	args := []any{StatusSucceeded, StatusFailed, "failed_dlq"}
	if tenantID != "" {
		q += ` WHERE w.tenant_id = $4`
		args = append(args, tenantID)
	}
	q += `
				GROUP BY w.id, w.slug, w.tenant_id, w.estimated_minutes_saved_per_run
			) ranked
			ORDER BY (ranked.estimated_minutes_saved_per_run * ranked.succeeded_runs) DESC,
				ranked.succeeded_runs DESC, ranked.slug ASC, ranked.workflow_id ASC`
	fetchLimit := limit + 1 // public API rejects values above maxAnalyticsWorkflowPage
	q += fmt.Sprintf(" LIMIT %d OFFSET %d", fetchLimit, offset)
	q += `
		) page
		ORDER BY (page.estimated_minutes_saved_per_run * page.succeeded_runs) DESC,
			page.succeeded_runs DESC, page.slug ASC, page.workflow_id ASC`
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, false, fmt.Errorf("analytics: workflow page: %w", err)
	}
	defer rows.Close()
	out := make([]WorkflowAnalytics, 0, limit)
	for rows.Next() {
		var row WorkflowAnalytics
		if err := rows.Scan(&row.WorkflowID, &row.Slug, &row.TenantID, &row.EstimatedMinutesSavedPerRun, &row.SucceededRuns, &row.FailedRuns, &row.AvgDurationMs); err != nil {
			return nil, false, fmt.Errorf("analytics: scan workflow page: %w", err)
		}
		row.MinutesSavedTotal = int64(row.EstimatedMinutesSavedPerRun) * int64(row.SucceededRuns)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("analytics: workflow page rows: %w", err)
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

func (j *Journal) totalMinutesSavedForTenant(ctx context.Context, tenantID string) (int64, error) {
	q := `SELECT COALESCE(SUM(rollup.estimated_minutes_saved_per_run * rollup.succeeded_runs), 0)
		FROM (
			SELECT w.id, w.estimated_minutes_saved_per_run,
				COALESCE(SUM(CASE WHEN r.status = $1 THEN 1 ELSE 0 END), 0) AS succeeded_runs
			FROM workflows w
			LEFT JOIN runs r ON r.workflow_id = w.id AND r.tenant_id = w.tenant_id`
	args := []any{StatusSucceeded}
	if tenantID != "" {
		q += ` WHERE w.tenant_id = $2`
		args = append(args, tenantID)
	}
	q += `
			GROUP BY w.id, w.estimated_minutes_saved_per_run
		) rollup`
	var total int64
	if err := j.db.QueryRowContext(ctx, j.bind(q), args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("analytics: total minutes saved: %w", err)
	}
	return total, nil
}

// workflowAnalytics fetches succeeded + failed counts and an average
// duration in one round-trip per workflow.
func (j *Journal) workflowAnalytics(ctx context.Context, w Workflow, tenantID string) (WorkflowAnalytics, error) {
	row := WorkflowAnalytics{
		WorkflowID:                  w.ID,
		Slug:                        w.Slug,
		TenantID:                    w.TenantID,
		EstimatedMinutesSavedPerRun: w.EstimatedMinutesSavedPerRun,
	}
	// Count succeeded vs failed-class. failed_dlq counts as failed for
	// the operator's headline rollup.
	countQ := `SELECT r.status, COUNT(*) FROM runs r
		JOIN workflows owner ON owner.id = r.workflow_id AND owner.tenant_id = r.tenant_id
		WHERE r.workflow_id = $1`
	countArgs := []any{w.ID}
	if tenantID != "" {
		countQ += ` AND r.tenant_id = $2`
		countArgs = append(countArgs, tenantID)
	}
	countQ += ` GROUP BY r.status`
	rows, err := j.db.QueryContext(ctx, j.bind(countQ), countArgs...)
	if err != nil {
		return WorkflowAnalytics{}, fmt.Errorf("analytics: workflow %s counts: %w", w.Slug, err)
	}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			rows.Close()
			return WorkflowAnalytics{}, err
		}
		switch status {
		case StatusSucceeded:
			row.SucceededRuns = n
		case "failed", "failed_dlq":
			row.FailedRuns += n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return WorkflowAnalytics{}, err
	}

	// Avg duration via the journal (covers both sqlite + postgres time
	// formats so we compute in Go after fetching).
	durations, derr := j.successfulRunDurationsForWorkflowMs(ctx, w.ID, tenantID)
	if derr != nil {
		return WorkflowAnalytics{}, derr
	}
	row.AvgDurationMs = averageMs(durations)
	row.MinutesSavedTotal = int64(row.EstimatedMinutesSavedPerRun) * int64(row.SucceededRuns)
	return row, nil
}

// successfulDurationSummaryMs keeps the high-cardinality duration set in
// Postgres. percentile_disc uses nearest-rank semantics, matching percentileMs
// for the nonnegative whole-millisecond values emitted by the subquery.
func (j *Journal) successfulDurationSummaryMs(ctx context.Context, tenantID string) (avg, p95 int64, err error) {
	if j.engine != EnginePostgres {
		durations, err := j.successfulRunDurationsMs(ctx, tenantID)
		if err != nil {
			return 0, 0, err
		}
		return averageMs(durations), percentileMs(durations, 0.95), nil
	}
	q := `SELECT COALESCE(FLOOR(AVG(ms))::bigint, 0),
		COALESCE(PERCENTILE_DISC(0.95) WITHIN GROUP (ORDER BY ms), 0)
		FROM (SELECT ` + postgresRunDurationMs + ` AS ms FROM runs r
			JOIN workflows w ON w.id = r.workflow_id AND w.tenant_id = r.tenant_id
			WHERE r.status = $1 AND r.started_at IS NOT NULL AND r.finished_at IS NOT NULL
			AND r.finished_at >= r.started_at`
	args := []any{StatusSucceeded}
	if tenantID != "" {
		q += ` AND r.tenant_id = $2`
		args = append(args, tenantID)
	}
	q += `) durations`
	if err := j.db.QueryRowContext(ctx, q, args...).Scan(&avg, &p95); err != nil {
		return 0, 0, fmt.Errorf("analytics: duration aggregate: %w", err)
	}
	return avg, p95, nil
}

// successfulRunDurationsMs is the SQLite-local fallback. Distributed mode
// uses Postgres aggregates and never materializes this history in the daemon.
func (j *Journal) successfulRunDurationsMs(ctx context.Context, tenantID string) ([]int64, error) {
	q := `SELECT r.started_at, r.finished_at FROM runs r
		JOIN workflows w ON w.id = r.workflow_id AND w.tenant_id = r.tenant_id
		WHERE r.status = $1 AND r.started_at IS NOT NULL AND r.finished_at IS NOT NULL`
	args := []any{StatusSucceeded}
	if tenantID != "" {
		q += ` AND r.tenant_id = $2`
		args = append(args, tenantID)
	}
	return j.scanDurations(ctx, q, args...)
}

func (j *Journal) successfulRunDurationsForWorkflowMs(ctx context.Context, workflowID, tenantID string) ([]int64, error) {
	q := `SELECT r.started_at, r.finished_at FROM runs r
		JOIN workflows w ON w.id = r.workflow_id AND w.tenant_id = r.tenant_id
		WHERE r.status = $1 AND r.workflow_id = $2 AND r.started_at IS NOT NULL AND r.finished_at IS NOT NULL`
	args := []any{StatusSucceeded, workflowID}
	if tenantID != "" {
		q += ` AND r.tenant_id = $3`
		args = append(args, tenantID)
	}
	return j.scanDurations(ctx, q, args...)
}

func (j *Journal) scanDurations(ctx context.Context, q string, args ...any) ([]int64, error) {
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, fmt.Errorf("analytics: durations: %w", err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var startedRaw, finishedRaw sql.NullString
		if err := rows.Scan(&startedRaw, &finishedRaw); err != nil {
			return nil, err
		}
		if !startedRaw.Valid || !finishedRaw.Valid {
			continue
		}
		started, err := j.parseTime(startedRaw.String)
		if err != nil {
			continue
		}
		finished, err := j.parseTime(finishedRaw.String)
		if err != nil {
			continue
		}
		ms := finished.Sub(started).Milliseconds()
		if ms < 0 {
			continue
		}
		out = append(out, ms)
	}
	return out, rows.Err()
}

// recentDailyRunCounts returns the last n days of run counts anchored to UTC
// midnight. Postgres groups in SQL so a busy fleet returns at most n rows to
// the daemon; SQLite's local-mode fallback keeps its portable timestamp scan.
func (j *Journal) recentDailyRunCounts(ctx context.Context, n int, tenantID string) ([]DailyRunCount, error) {
	if n <= 0 {
		return nil, nil
	}
	nowT := time.Now().UTC()
	today := time.Date(nowT.Year(), nowT.Month(), nowT.Day(), 0, 0, 0, 0, time.UTC)
	cutoff := today.AddDate(0, 0, -(n - 1))
	upper := today.AddDate(0, 0, 1)
	buckets := make([]DailyRunCount, n)
	for i := range buckets {
		buckets[i] = DailyRunCount{Day: cutoff.AddDate(0, 0, i)}
	}
	if j.engine == EnginePostgres {
		q := `SELECT TO_CHAR(r.started_at AT TIME ZONE 'UTC', 'YYYY-MM-DD'), COUNT(*)
			FROM runs r JOIN workflows w ON w.id = r.workflow_id AND w.tenant_id = r.tenant_id
			WHERE r.started_at >= $1 AND r.started_at < $2`
		args := []any{j.formatTime(cutoff), j.formatTime(upper)}
		if tenantID != "" {
			q += ` AND r.tenant_id = $3`
			args = append(args, tenantID)
		}
		q += ` GROUP BY 1`
		rows, err := j.db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, fmt.Errorf("analytics: daily counts: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var dayText string
			var count int
			if err := rows.Scan(&dayText, &count); err != nil {
				return nil, fmt.Errorf("analytics: scan daily count: %w", err)
			}
			day, err := time.Parse("2006-01-02", dayText)
			if err != nil {
				return nil, fmt.Errorf("analytics: parse daily bucket: %w", err)
			}
			idx := int(day.Sub(cutoff).Hours() / 24)
			if idx >= 0 && idx < n {
				buckets[idx].Total = count
			}
		}
		return buckets, rows.Err()
	}

	q := `SELECT r.started_at FROM runs r
		JOIN workflows w ON w.id = r.workflow_id AND w.tenant_id = r.tenant_id
		WHERE r.started_at IS NOT NULL AND r.started_at >= $1 AND r.started_at < $2`
	args := []any{j.formatTime(cutoff), j.formatTime(upper)}
	if tenantID != "" {
		q += ` AND r.tenant_id = $3`
		args = append(args, tenantID)
	}
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, fmt.Errorf("analytics: daily counts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var startedRaw sql.NullString
		if err := rows.Scan(&startedRaw); err != nil {
			return nil, err
		}
		if !startedRaw.Valid {
			continue
		}
		started, err := j.parseTime(startedRaw.String)
		if err != nil {
			continue
		}
		dayStart := time.Date(started.Year(), started.Month(), started.Day(), 0, 0, 0, 0, time.UTC)
		idx := int(dayStart.Sub(cutoff).Hours()/24 + 0.5)
		if idx < 0 || idx >= n {
			continue
		}
		buckets[idx].Total++
	}
	return buckets, rows.Err()
}

func averageMs(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	var sum int64
	for _, v := range values {
		sum += v
	}
	return sum / int64(len(values))
}

// percentileMs returns the rank-p value (e.g. p=0.95 -> p95). Uses the
// nearest-rank method which is simple, deterministic, and adequate for
// the dashboard summary (a real APM would interpolate).
func percentileMs(values []int64, p float64) int64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]int64, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	// Nearest-rank: rank = ceil(p*N), 1-based, so the 0-based index is
	// ceil(p*N)-1. The old int(p*N) floored and indexed 0-based, which
	// overshot by one (p95 of 1..100 returned 96 instead of 95).
	rank := int(math.Ceil(p*float64(len(sorted)))) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}
