package server

import (
	"fmt"
	"html/template"
	"strings"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// renderDownstreamChainSection draws the "Workflows that fire when
// this workflow terminates" block on the workflow detail page. The
// upstream side (workflows that THIS workflow depends on) appears in
// the standard Triggers table as kind=workflow_complete rows.
func renderDownstreamChainSection(rows []journal.ChainTriggerView) string {
	var b strings.Builder
	b.WriteString(`<h2>Downstream workflows</h2>`)
	if len(rows) == 0 {
		b.WriteString(`<p class="muted">No workflows fire from this one. To chain another workflow after this, open the downstream workflow's detail page and use the "Run after another workflow" form.</p>`)
		return b.String()
	}
	b.WriteString(`<p class="muted">These workflows dispatch automatically whenever this workflow terminates with one of the listed statuses. The downstream workflow receives a payload carrying <code>source_run_id</code>, <code>source_status</code>, <code>source_workflow_slug</code>, and (for failures) <code>source_error_text</code>.</p>`)
	b.WriteString(`<table><thead><tr><th>Downstream workflow</th><th>Fires on</th></tr></thead><tbody>`)
	for _, r := range rows {
		// Slugs are tenant-scoped. Carry the owner tenant in the link so a
		// global admin opening a chain cannot land on a same-slug workflow
		// belonging to another tenant. Members ignore the query selector because
		// their authenticated tenant scope always wins in workflowIDForViewer.
		href := "/workflows/" + template.URLQueryEscaper(r.DownstreamSlug)
		if r.DownstreamTenantID != "" {
			href += "?tenant=" + template.URLQueryEscaper(r.DownstreamTenantID)
		}
		fmt.Fprintf(&b, `<tr><td><a href="%s"><code>%s</code></a></td><td><code>%s</code></td></tr>`,
			href,
			template.HTMLEscapeString(r.DownstreamSlug),
			template.HTMLEscapeString(r.OnStatuses),
		)
	}
	b.WriteString(`</tbody></table>`)
	return b.String()
}
