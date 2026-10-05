package server

import (
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// renderAnalyticsStrip is the headline rollup at the top of the home
// page. Five tile-cards (runs total, succeeded, failed, time saved,
// avg/p95 duration), a 7-day daily-run mini-bar-chart, and a per-
// workflow time-saved table sorted by impact descending. Each
// number is server-rendered; no JS, no AJAX, no client-side templating.
//
// Zero values are rendered with a muted styling so an operator on
// first boot sees "0 runs" rather than blanks.
func renderAnalyticsStrip(a journal.Analytics) string {
	var b strings.Builder
	b.WriteString(`<section class="analytics">`)
	b.WriteString(renderTiles(a))
	b.WriteString(renderDailyChart(a.DailyRuns))
	b.WriteString(renderPerWorkflowTable(a.PerWorkflow, a.PerWorkflowHasMore))
	b.WriteString(`</section>`)
	b.WriteString(analyticsCSS)
	return b.String()
}

// renderTiles emits the five KPI cards.
func renderTiles(a journal.Analytics) string {
	succeeded := a.RunsByStatus[journal.StatusSucceeded]
	failed := a.RunsByStatus["failed"] + a.RunsByStatus["failed_dlq"]
	successRate := 0.0
	completed := succeeded + failed
	if completed > 0 {
		successRate = float64(succeeded) / float64(completed) * 100
	}
	var b strings.Builder
	b.WriteString(`<div class="tiles">`)
	tile(&b, "Total runs", fmt.Sprintf("%d", a.TotalRuns), "")
	tile(&b, "Succeeded", fmt.Sprintf("%d", succeeded), fmt.Sprintf("%.1f%% of completed runs", successRate))
	tile(&b, "Failed", fmt.Sprintf("%d", failed), "includes DLQ")
	tile(&b, "Avg duration", formatDuration(a.AvgDurationMs), fmt.Sprintf("p95 %s", formatDuration(a.P95DurationMs)))
	tile(&b, "Time saved", formatMinutesSaved(a.TotalMinutesSaved), "set per workflow")
	b.WriteString(`</div>`)
	return b.String()
}

// tile emits one KPI card. value is the headline number; sub is the
// muted subtitle (e.g. "p95 480ms" under "Avg duration").
func tile(b *strings.Builder, label, value, sub string) {
	muted := ""
	if value == "0" || value == "0ms" || value == "0 min" {
		muted = " tile-muted"
	}
	fmt.Fprintf(b, `<div class="tile%s">
  <div class="tile-label">%s</div>
  <div class="tile-value">%s</div>`, muted,
		template.HTMLEscapeString(label),
		template.HTMLEscapeString(value),
	)
	if sub != "" {
		fmt.Fprintf(b, `<div class="tile-sub">%s</div>`, template.HTMLEscapeString(sub))
	}
	b.WriteString(`</div>`)
}

// renderDailyChart draws a 7-bar SVG of the last-7-day run count. CSS
// height percentages would have been simpler but SVG keeps the line up
// crisp on retina displays without burning a JS chart library.
func renderDailyChart(daily []journal.DailyRunCount) string {
	if len(daily) == 0 {
		return ""
	}
	maxN := 1
	for _, d := range daily {
		if d.Total > maxN {
			maxN = d.Total
		}
	}
	const (
		w        = 420
		h        = 80
		gutter   = 8
		topPad   = 8
		labelH   = 16
		chartH   = h - labelH - topPad
		nBars    = 7
		barWidth = (w - gutter*(nBars+1)) / nBars
	)
	var b strings.Builder
	b.WriteString(`<div class="daily-chart"><div class="daily-chart-title">Last 7 days</div>`)
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" preserveAspectRatio="none" class="daily-chart-svg" role="img" aria-label="Run count by day, last 7 days">`, w, h)
	for i, d := range daily {
		x := gutter + i*(barWidth+gutter)
		barH := 0
		if maxN > 0 {
			barH = chartH * d.Total / maxN
		}
		y := topPad + chartH - barH
		fill := "#0a5"
		if d.Total == 0 {
			fill = "#ddd"
		}
		fmt.Fprintf(&b,
			`<rect x="%d" y="%d" width="%d" height="%d" fill="%s" rx="2" ry="2"></rect>`,
			x, y, barWidth, barH, fill,
		)
		fmt.Fprintf(&b,
			`<text x="%d" y="%d" text-anchor="middle" font-size="10" fill="#666">%s</text>`,
			x+barWidth/2, h-2, dayLabel(d.Day),
		)
		fmt.Fprintf(&b,
			`<text x="%d" y="%d" text-anchor="middle" font-size="11" font-weight="600" fill="#111">%d</text>`,
			x+barWidth/2, y-4, d.Total,
		)
	}
	b.WriteString(`</svg></div>`)
	return b.String()
}

// renderPerWorkflowTable lists every workflow with its succeeded
// count, average duration, declared minutes-saved-per-run, and
// computed minutes-saved-total. Sorted by total impact descending
// (see journal.AnalyticsSummary). Caps at 10 rows; the workflow
// detail page is the drill-down for the rest.
func renderPerWorkflowTable(rows []journal.WorkflowAnalytics, hasMore bool) string {
	if len(rows) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<details class="analytics-detail" open><summary>Time saved by workflow</summary>`)
	b.WriteString(`<p class="muted">Headline number is the operator-declared "manual baseline" (minutes a person would have spent doing this run by hand) multiplied by succeeded runs. Edit the per-workflow baseline on the workflow detail page.</p>`)
	b.WriteString(`<table><thead><tr><th>Workflow</th><th>Succeeded</th><th>Failed</th><th>Avg duration</th><th>Baseline</th><th>Total saved</th></tr></thead><tbody>`)
	limit := 10
	if len(rows) < limit {
		limit = len(rows)
	}
	for _, row := range rows[:limit] {
		baseline := "<span class=\"muted\">not set</span>"
		if row.EstimatedMinutesSavedPerRun > 0 {
			baseline = fmt.Sprintf("%d min/run", row.EstimatedMinutesSavedPerRun)
		}
		// Always carry ?tenant=. Slugs are unique only per tenant, so two rows can
		// share a slug and a bare href would send both to whichever workflow is
		// newest. The parameter is honoured only for a viewer with no scope of
		// their own (an admin); a member's own scope always wins in
		// workflowIDForViewer, so this cannot be used to cross a boundary.
		href := "/workflows/" + template.URLQueryEscaper(row.Slug)
		if row.TenantID != "" {
			href += "?tenant=" + template.URLQueryEscaper(row.TenantID)
		}
		fmt.Fprintf(&b,
			`<tr><td><a href="%s"><code>%s</code></a></td><td>%d</td><td>%d</td><td class="muted">%s</td><td>%s</td><td><strong>%s</strong></td></tr>`,
			href,
			template.HTMLEscapeString(row.Slug),
			row.SucceededRuns,
			row.FailedRuns,
			formatDuration(row.AvgDurationMs),
			baseline,
			formatMinutesSaved(row.MinutesSavedTotal),
		)
	}
	b.WriteString(`</tbody></table>`)
	if hasMore || len(rows) > limit {
		fmt.Fprintf(&b, `<p class="muted">Showing top %d by impact. Workflow detail pages have full per-workflow numbers.</p>`, limit)
	}
	b.WriteString(`</details>`)
	return b.String()
}

// formatDuration renders an int64 ms duration as a human-readable
// string. Stays compact: "850ms", "1.2s", "3m 12s".
func formatDuration(ms int64) string {
	if ms <= 0 {
		return "0ms"
	}
	d := time.Duration(ms) * time.Millisecond
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", ms)
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	default:
		m := int(d.Minutes())
		s := int(d.Seconds()) - m*60
		return fmt.Sprintf("%dm %ds", m, s)
	}
}

// formatMinutesSaved renders the total as the largest natural unit so
// "1240 min" becomes "20 h 40 m" and "1500 h" becomes "62 days".
// Keeps the headline number readable when an operator has weeks of
// automation history piled up.
func formatMinutesSaved(minutes int64) string {
	if minutes <= 0 {
		return "0 min"
	}
	if minutes < 60 {
		return fmt.Sprintf("%d min", minutes)
	}
	hours := minutes / 60
	rem := minutes % 60
	if hours < 24 {
		if rem == 0 {
			return fmt.Sprintf("%d h", hours)
		}
		return fmt.Sprintf("%d h %d m", hours, rem)
	}
	days := hours / 24
	remH := hours % 24
	if remH == 0 {
		return fmt.Sprintf("%d days", days)
	}
	return fmt.Sprintf("%d days %d h", days, remH)
}

// dayLabel returns "Mon", "Tue", etc. unless the day is today, in
// which case it returns "Today" so the rightmost bar is unambiguous.
func dayLabel(day time.Time) string {
	today := time.Now().UTC()
	todayStart := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	if day.Equal(todayStart) {
		return "Today"
	}
	return day.Format("Mon")
}

const analyticsCSS = `<style>
.analytics { margin: 0 0 24px; }
.tiles { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 0 0 16px; }
.tile { background:var(--surface); border:1px solid var(--border); box-shadow:var(--shadow); padding:18px 20px; border-radius:var(--radius); }
.tile-muted { opacity: 0.55; }
.tile-label { color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; font-size: 11px; margin-bottom: 6px; }
.tile-value { font-size: 25px; font-weight: 650; color: var(--fg); line-height: 1.1; letter-spacing: -0.02em; }
.tile-sub { color: var(--muted); font-size: 12px; margin-top: 4px; }
.daily-chart { background:var(--surface); border:1px solid var(--border); box-shadow:var(--shadow); padding:18px 20px; border-radius:var(--radius); margin: 0 0 16px; }
.daily-chart-title { color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; font-size: 11px; margin-bottom: 8px; }
.daily-chart-svg { width: 100%; height: 96px; display: block; }
.analytics-detail { background:var(--surface); border:1px solid var(--border); box-shadow:var(--shadow); padding:14px 18px; border-radius:var(--radius); margin: 0 0 16px; }
.analytics-detail > summary { color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; font-size: 11px; cursor: pointer; padding: 2px 0; font-weight: 600; }
.analytics-detail[open] > summary { margin-bottom: 8px; }
@media (max-width: 900px) { .tiles { grid-template-columns: repeat(2, 1fr); } }
</style>`
