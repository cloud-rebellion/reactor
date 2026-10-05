package server

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

type dlqRow struct {
	Item         journal.DeadLetterItem
	WorkflowSlug string
	TenantID     string
	RunStatus    string
}

// dlq renders the operator's dead-letter queue. The run-detail page still
// owns the full timeline; this page gives an operator one bounded queue view
// for triage and retry after a worker or provider outage.
func (s *Server) dlq(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := parseIntDefault(q.Get("limit"), 50)
	if limit < 1 {
		limit = 1
	}
	if limit > 200 {
		limit = 200
	}
	offset := parseIntDefault(q.Get("offset"), 0)
	if offset < 0 {
		offset = 0
	}
	items, err := s.Journal.ListDeadLetterItems(r.Context(), limit+1, offset)
	if err != nil {
		s.errorPage(w, "list dead letters", err)
		return
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	rows := make([]dlqRow, 0, len(items))
	for _, item := range items {
		row := dlqRow{Item: item, WorkflowSlug: item.RunID}
		if run, runErr := s.Journal.GetRunForTenantMetadata(r.Context(), item.RunID, viewerScope(r), 0); runErr == nil {
			row.RunStatus = run.Status
			row.TenantID = run.TenantID
			if slug, slugErr := s.Journal.WorkflowSlugByID(r.Context(), run.WorkflowID); slugErr == nil && slug != "" {
				row.WorkflowSlug = slug
			}
		}
		rows = append(rows, row)
	}
	s.renderPage(w, r, page{
		Title:   "Dead letters",
		Heading: "Dead letters",
		// A global viewer (the admin route today, and a future no-auth
		// bootstrap route) may see duplicate slugs across tenants. Keep the
		// tenant selector on workflow links so triage opens the exact workflow
		// that produced the dead letter. A tenant-scoped viewer must not be
		// handed a cross-tenant selector, even if this page is mounted for
		// members later.
		Body: template.HTML(dlqBody(rows, offset, limit, hasMore, viewerScope(r) == "")),
	})
}

func dlqBody(rows []dlqRow, offset, limit int, hasMore, globalViewer bool) string {
	var b strings.Builder
	b.WriteString(`<p class="muted">Failed workflow attempts waiting for inspection or retry. Retry uses the same admission, quota, rate, artifact, and lease gates as a normal dispatch.</p>`)
	if len(rows) == 0 {
		b.WriteString(`<p class="muted">The dead-letter queue is empty.</p>`)
		return b.String()
	}
	b.WriteString(`<table><thead><tr><th>Workflow</th><th>Step</th><th>Error</th><th>Moved</th><th></th></tr></thead><tbody>`)
	for _, row := range rows {
		item := row.Item
		workflow := template.HTMLEscapeString(row.WorkflowSlug)
		runID := template.HTMLEscapeString(item.RunID)
		workflowHref := "/workflows/" + url.PathEscape(row.WorkflowSlug)
		if globalViewer && row.TenantID != "" {
			workflowHref += "?tenant=" + url.QueryEscape(row.TenantID)
		}
		action := fmt.Sprintf(`<a href="/runs/%s">view run</a>`, url.PathEscape(item.RunID))
		if row.RunStatus == "failed_dlq" {
			action += fmt.Sprintf(` <form method="POST" action="/dlq/%s/retry" class="form-inline" data-confirm="Retry this dead-lettered run?"> <button type="submit" class="btn-link">retry</button></form>`, url.PathEscape(item.ID))
		}
		b.WriteString(`<tr><td><a href="` + template.HTMLEscapeString(workflowHref) + `">` + workflow + `</a><br><span class="muted"><code>` + runID + `</code></span></td>`)
		b.WriteString(`<td><code>` + template.HTMLEscapeString(item.StepName) + `</code></td>`)
		b.WriteString(`<td><span class="flow-err">` + template.HTMLEscapeString(truncate(item.ErrorText, 500)) + `</span></td>`)
		b.WriteString(`<td class="muted">` + template.HTMLEscapeString(formatTime(item.MovedAt)) + `</td><td>` + action + `</td></tr>`)
	}
	b.WriteString(`</tbody></table>`)
	var nav strings.Builder
	if offset > 0 {
		prev := offset - limit
		if prev < 0 {
			prev = 0
		}
		nav.WriteString(fmt.Sprintf(`<a href="/dlq?limit=%d&offset=%d">newer</a>`, limit, prev))
	}
	if hasMore {
		if nav.Len() > 0 {
			nav.WriteString(` &middot; `)
		}
		nav.WriteString(fmt.Sprintf(`<a href="/dlq?limit=%d&offset=%d">older</a>`, limit, offset+limit))
	}
	if nav.Len() > 0 {
		b.WriteString(`<p class="muted">` + nav.String() + `</p>`)
	}
	return b.String()
}
