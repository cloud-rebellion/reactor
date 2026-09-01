package server

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/bright-interaction/reactor/internal/knowledge"
)

// postmortems renders the AI post-mortem corpus (admin-only). When explicitly
// enabled, a permanent (DLQ) failure asks Claude for a structured root-cause +
// recommendation and stores it as a knowledge entry under topic "post-mortems".
// Those same entries are searchable over MCP, so the next agent that builds or
// repairs a workflow reads the accumulated lessons: the platform gets better at
// the APIs it integrates over time. This page is the human window onto that
// loop.
func (s *Server) postmortems(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	if s.Knowledge == nil {
		s.renderPage(w, r, page{Title: "Post-mortems", Heading: "Post-mortems",
			Body: template.HTML(`<p class="muted">The knowledge corpus is not wired on this deployment.</p>`)})
		return
	}
	entries, err := s.Knowledge.List(r.Context(), "post-mortems")
	if err != nil {
		s.errorPage(w, "list post-mortems", err)
		return
	}
	s.renderPage(w, r, page{
		Title:   "Post-mortems",
		Heading: "Post-mortems",
		Body:    template.HTML(postmortemsBody(entries)),
	})
}

func postmortemsBody(entries []knowledge.Entry) string {
	var b strings.Builder
	b.WriteString(`<p class="muted">When AI post-mortems are explicitly enabled, Claude analyses redacted run metadata and fixed error summaries and writes a root cause, lesson, and recommendation here. Raw Step errors, trigger bodies, and Step outputs are not sent. These entries are searchable over MCP, so future workflow repairs can use the accumulated lessons.</p>`)
	if len(entries) == 0 {
		b.WriteString(`<p class="muted">No post-mortems yet. Automatic generation requires both the explicit AI post-mortem opt-in and an Anthropic API key.</p>`)
		return b.String()
	}
	for _, e := range entries {
		fm := e.Frontmatter
		when := ""
		if !fm.CreatedAt.IsZero() {
			when = fm.CreatedAt.UTC().Format("2006-01-02 15:04Z")
		}
		b.WriteString(`<details class="analytics-detail"><summary>` +
			template.HTMLEscapeString(fm.Title) + `</summary>`)
		// Source run link + meta.
		if runID := sourceRun(fm.Sources); runID != "" {
			fmt.Fprintf(&b, `<p class="muted">%s &middot; <a href="/runs/%s">source run</a></p>`,
				template.HTMLEscapeString(when), template.URLQueryEscaper(runID))
		} else if when != "" {
			fmt.Fprintf(&b, `<p class="muted">%s</p>`, template.HTMLEscapeString(when))
		}
		// Body is markdown; present it readably (escaped, newlines preserved).
		fmt.Fprintf(&b, `<div style="white-space:pre-wrap;font-size:13px;line-height:1.5;">%s</div>`,
			template.HTMLEscapeString(e.Body))
		b.WriteString(`</details>`)
	}
	return b.String()
}

// sourceRun extracts a run id from a knowledge entry's sources (the post-mortem
// generator records "run:<id>").
func sourceRun(sources []string) string {
	for _, s := range sources {
		if strings.HasPrefix(s, "run:") {
			return strings.TrimPrefix(s, "run:")
		}
	}
	return ""
}
