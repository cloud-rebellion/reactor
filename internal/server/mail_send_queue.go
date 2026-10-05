package server

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

const mailSendQueuePageSize = 50

// mailSendQueue is the human operator's value-free reconciliation inventory.
// Mount gates it to admins; the journal also fences every row to the selected
// tenant so this view never depends on a presentation-layer filter.
func (s *Server) mailSendQueue(w http.ResponseWriter, r *http.Request) {
	tenant := editTenantScope(r)
	if len(tenant) > 256 {
		http.Error(w, "invalid tenant", http.StatusBadRequest)
		return
	}
	cursor := r.URL.Query().Get("cursor")
	if len(cursor) > 1024 {
		http.Error(w, "invalid mail send cursor", http.StatusBadRequest)
		return
	}
	items, more, next, err := s.Journal.ListAdmittedMailSendIntentsForTenant(r.Context(), tenant, mailSendQueuePageSize, cursor)
	if errors.Is(err, journal.ErrInvalidMailSendCursor) {
		http.Error(w, "invalid mail send cursor", http.StatusBadRequest)
		return
	}
	if err != nil {
		s.errorPage(w, "list uncertain mail sends", err)
		return
	}
	s.renderPage(w, r, page{
		Title: "Mail send reconciliation", Heading: "Mail send reconciliation",
		Body: template.HTML(mailSendQueueBody(tenant, items, more, next, viewerScope(r) == "")),
	})
}

func mailSendQueueBody(tenant string, items []journal.MailSendIntentReceipt, more bool, next string, globalViewer bool) string {
	var b strings.Builder
	b.WriteString(`<p class="muted">Each row is a durable send intent whose provider acceptance is unknown. Inspect the named connection in the provider before any manual redrive. Reactor does not automatically resend these messages. After checking the provider, an admin MCP client with the mail-reconciliation scope can record a finding using the exact intent, run, ordinal, and target shown here. A finding does not send mail or prove delivery.</p>`)
	if globalViewer {
		fmt.Fprintf(&b, `<form method="GET" action="/mail-sends"><label for="mail-tenant">Tenant</label> <input id="mail-tenant" name="tenant" value="%s" maxlength="256"> <button type="submit">Show</button></form>`, template.HTMLEscapeString(tenant))
	}
	if len(items) == 0 {
		b.WriteString(`<p class="muted">No unresolved connected-mail sends for this tenant.</p>`)
		return b.String()
	}
	b.WriteString(`<table><thead><tr><th>Admitted</th><th>Intent</th><th>Run</th><th>Step</th><th>Ordinal</th><th>Provider</th><th>Connection</th></tr></thead><tbody>`)
	for _, item := range items {
		provider := item.ProviderID
		if provider != "google" && provider != "microsoft" {
			provider = "Unknown"
		}
		connection := "Unavailable (legacy intent)"
		if item.TargetRecorded {
			connection = item.ConnectionID
		}
		fmt.Fprintf(&b, `<tr><td>%s</td><td><code>%s</code></td><td><a href="/runs/%s"><code>%s</code></a></td><td><code>%s</code></td><td>%d</td><td>%s</td><td><code>%s</code></td></tr>`,
			template.HTMLEscapeString(item.CreatedAt.UTC().Format("2006-01-02 15:04:05Z")),
			template.HTMLEscapeString(item.ID),
			url.PathEscape(item.RunID), template.HTMLEscapeString(item.RunID),
			template.HTMLEscapeString(item.StepName), item.Seq,
			template.HTMLEscapeString(provider), template.HTMLEscapeString(connection))
	}
	b.WriteString(`</tbody></table>`)
	if more {
		query := url.Values{"cursor": {next}}
		if globalViewer {
			query.Set("tenant", tenant)
		}
		fmt.Fprintf(&b, `<p><a href="/mail-sends?%s">Older unresolved sends</a></p>`, template.HTMLEscapeString(query.Encode()))
	}
	return b.String()
}
