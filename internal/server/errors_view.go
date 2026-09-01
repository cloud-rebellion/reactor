package server

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// errorsPage is the error log: every failed execution with the failing step's
// error text and a link to the run. Tenant-scoped for members (their own
// failures), global for admins. The data is auto-collected -- every failed run
// already records its step error in the journal -- so this is a live view, not
// a separate log to maintain.
func (s *Server) errorsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	scope := viewerScope(r)
	failed, err := s.Journal.ListFailedRuns(ctx, scope, 100)
	if err != nil {
		s.errorPage(w, "list failed runs", err)
		return
	}
	recurring, _ := s.Journal.TopFailingWorkflows(ctx, scope, 5)
	slugs := map[string]string{}
	resolve := func(wfID string) {
		if _, ok := slugs[wfID]; ok {
			return
		}
		if sl, e := s.Journal.WorkflowSlugByID(ctx, wfID); e == nil {
			slugs[wfID] = sl
		} else {
			slugs[wfID] = wfID
		}
	}
	for _, f := range failed {
		resolve(f.WorkflowID)
	}
	for _, rc := range recurring {
		resolve(rc.WorkflowID)
	}
	s.renderPage(w, r, page{
		Title:   "Errors",
		Heading: "Error log",
		Body:    template.HTML(errorsBody(failed, recurring, slugs)),
	})
}

func errorsBody(failed []journal.FailedRun, recurring []journal.WorkflowFailureCount, slugs map[string]string) string {
	var b strings.Builder
	if len(failed) == 0 {
		b.WriteString(`<p class="muted">No failed executions. Every failed run is collected here automatically with its error, so this is your debugging starting point.</p>`)
		return b.String()
	}
	fmt.Fprintf(&b, `<p class="muted">%d most recent failed executions. Every failure is logged automatically with the failing step + error. Click a run to see the full timeline; when explicitly enabled, permanent failures can produce an AI post-mortem on the <a href="/postmortems">Post-mortems</a> page.</p>`, len(failed))

	// Recurring-failure summary: the workflows worth fixing first.
	if len(recurring) > 1 || (len(recurring) == 1 && recurring[0].Count > 1) {
		b.WriteString(`<h2>Recurring failures</h2><p class="muted">Workflows ranked by failure count -- fix these first.</p><table><thead><tr><th>Workflow</th><th>Failures</th></tr></thead><tbody>`)
		for _, rc := range recurring {
			slug := slugs[rc.WorkflowID]
			fmt.Fprintf(&b, `<tr><td><a href="/workflows/%s"><code>%s</code></a></td><td>%d</td></tr>`,
				template.URLQueryEscaper(slug), template.HTMLEscapeString(slug), rc.Count)
		}
		b.WriteString(`</tbody></table><h2>All failures</h2>`)
	}
	b.WriteString(`<table><thead><tr><th>When</th><th>Workflow</th><th>Failed step</th><th>Error</th><th>Status</th><th></th></tr></thead><tbody>`)
	for _, f := range failed {
		when := `<span class="muted">-</span>`
		if !f.FinishedAt.IsZero() {
			when = f.FinishedAt.UTC().Format("2006-01-02 15:04Z")
		}
		slug := slugs[f.WorkflowID]
		step := `<span class="muted">-</span>`
		if f.StepName != "" {
			step = `<code>` + template.HTMLEscapeString(f.StepName) + `</code>`
		}
		errText := `<span class="muted">(no step error recorded)</span>`
		if f.Error != "" {
			errText = `<span style="color:var(--err);">` + template.HTMLEscapeString(truncate(f.Error, 160)) + `</span>`
		}
		fmt.Fprintf(&b, `<tr><td class="muted">%s</td><td><a href="/workflows/%s"><code>%s</code></a></td><td>%s</td><td>%s</td><td><span class="tag tag-off">%s</span></td><td><a href="/runs/%s" class="btn-link">view run</a></td></tr>`,
			when,
			template.URLQueryEscaper(slug), template.HTMLEscapeString(slug),
			step, errText, template.HTMLEscapeString(f.Status),
			template.URLQueryEscaper(f.RunID),
		)
	}
	b.WriteString(`</tbody></table>`)
	return b.String()
}
