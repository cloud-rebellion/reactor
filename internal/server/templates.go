package server

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/bright-interaction/reactor/internal/templates"
)

// templates renders the starter-template gallery. Browsable by anyone; the
// "Use template" action runs the AI generator (admin-gated like /generate).
func (s *Server) templates(w http.ResponseWriter, r *http.Request) {
	render := func(body string) {
		s.renderPage(w, r, page{Title: "Templates", Heading: "Templates", Body: template.HTML(body)})
	}
	render(templatesBody(s.Generator != nil))
}

func templatesBody(generatorEnabled bool) string {
	var b strings.Builder
	b.WriteString(`<p class="muted">Start from a proven automation instead of a blank page. "Use template" feeds the brief to the AI builder, which generates + registers a working workflow you can then edit.</p>`)
	if !generatorEnabled {
		b.WriteString(`<div class="callout">The AI builder is not configured on this deployment (no Anthropic API key), so one-click build is off. You can still copy a brief below and build via the CLI or paste it into the New workflow form.</div>`)
	}
	b.WriteString(`<div class="tpl-grid">`)
	for _, t := range templates.All() {
		b.WriteString(`<div class="tpl-card">`)
		fmt.Fprintf(&b, `<div class="tpl-cat">%s</div>`, template.HTMLEscapeString(t.Category))
		fmt.Fprintf(&b, `<h3 class="tpl-name">%s</h3>`, template.HTMLEscapeString(t.Name))
		fmt.Fprintf(&b, `<p class="tpl-desc">%s</p>`, template.HTMLEscapeString(t.Description))
		if generatorEnabled {
			fmt.Fprintf(&b, `<form method="POST" action="/generate" class="tpl-use"><input type="hidden" name="brief" value="%s"><button type="submit" class="btn-primary">Use template</button></form>`,
				template.HTMLEscapeString(t.Brief))
		}
		fmt.Fprintf(&b, `<details class="tpl-brief"><summary>view brief</summary><p class="muted">%s</p></details>`, template.HTMLEscapeString(t.Brief))
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}
