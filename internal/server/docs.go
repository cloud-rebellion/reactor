package server

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"

	docsfs "github.com/bright-interaction/reactor/docs"
)

// docsOrder controls the left-rail order on the docs index. Pages
// listed here render in this sequence; pages on disk but not listed
// appear after, alphabetised. Update when adding a new doc.
var docsOrder = []string{
	"README",
	"dashboard",
	"api",
	"mcp",
	"notifications",
	"connections",
	"chaining",
	"hash-esign-bridge",
	"teams",
	"architecture",
	"scaling",
	"sdk",
	"codegen",
	"rotation",
	"operations",
	"internal-readiness",
	"security",
}

// docTitles overrides the default humanised filename per page. Drives
// the sidebar link text + the <title> tag.
var docTitles = map[string]string{
	"README":             "Overview",
	"dashboard":          "Dashboard pages + endpoints",
	"api":                "REST API reference",
	"mcp":                "MCP server + tool reference",
	"notifications":      "Notifications (Slack + webhook + email)",
	"connections":        "OAuth connections",
	"chaining":           "Workflow chaining",
	"hash-esign-bridge":  "Hash e-signature bridge",
	"teams":              "Teams, users, sessions, API tokens",
	"architecture":       "Architecture",
	"scaling":            "Scaling (distributed mode + workers)",
	"sdk":                "SDK reference",
	"codegen":            "Codegen pipeline",
	"rotation":           "Credential rotation",
	"operations":         "Operations runbook",
	"internal-readiness": "Internal readiness runbook",
	"security":           "Security threat model",
}

// docsIndex serves the index page listing every embedded doc.
func (s *Server) docsIndex(w http.ResponseWriter, r *http.Request) {
	pages := listDocPages()
	var b strings.Builder
	b.WriteString(`<p class="muted">Documentation ships with the binary; every page is one focused chunk so an operator lands directly on what they need.</p>`)
	b.WriteString(`<ul class="docs-index">`)
	for _, slug := range pages {
		fmt.Fprintf(&b, `<li><a href="/docs/%s">%s</a></li>`,
			template.URLQueryEscaper(slug),
			template.HTMLEscapeString(docTitleFor(slug)),
		)
	}
	b.WriteString(`</ul>`)
	s.renderPage(w, r, page{
		Title:   "Documentation",
		Heading: "Documentation",
		Body:    template.HTML(b.String() + docsCSS),
	})
}

// docPage renders one embedded doc as HTML. Unknown slugs return 404.
func (s *Server) docPage(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "page")
	if !isValidDocSlug(slug) {
		http.Error(w, "doc not found", http.StatusNotFound)
		return
	}
	raw, err := fs.ReadFile(docsfs.FS, slug+".md")
	if err != nil {
		http.Error(w, "doc not found", http.StatusNotFound)
		return
	}
	body, err := renderMarkdown(raw)
	if err != nil {
		s.errorPage(w, "render doc", err)
		return
	}
	pages := listDocPages()
	var nav strings.Builder
	nav.WriteString(`<aside class="docs-nav"><ul>`)
	for _, p := range pages {
		active := ""
		if p == slug {
			active = ` class="active"`
		}
		fmt.Fprintf(&nav, `<li%s><a href="/docs/%s">%s</a></li>`,
			active,
			template.URLQueryEscaper(p),
			template.HTMLEscapeString(docTitleFor(p)),
		)
	}
	nav.WriteString(`</ul></aside>`)
	composed := `<div class="docs-shell">` + nav.String() + `<article class="docs-body">` + body + `</article></div>` + docsCSS
	s.renderPage(w, r, page{
		Title:   "Docs: " + docTitleFor(slug),
		Heading: docTitleFor(slug),
		Body:    template.HTML(composed),
	})
}

// listDocPages reads *.md from the embedded FS, returns slugs in
// docsOrder first, then alphabetised remainders.
func listDocPages() []string {
	entries, err := fs.ReadDir(docsfs.FS, ".")
	if err != nil {
		return nil
	}
	present := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".md") {
			continue
		}
		present[strings.TrimSuffix(name, ".md")] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, slug := range docsOrder {
		if present[slug] {
			out = append(out, slug)
			seen[slug] = true
		}
	}
	var extras []string
	for slug := range present {
		if !seen[slug] {
			extras = append(extras, slug)
		}
	}
	sort.Strings(extras)
	return append(out, extras...)
}

func docTitleFor(slug string) string {
	if t, ok := docTitles[slug]; ok {
		return t
	}
	return strings.Title(strings.ReplaceAll(slug, "-", " "))
}

func isValidDocSlug(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// renderMarkdown converts raw markdown bytes into HTML via goldmark
// with GFM (tables, strikethrough, auto-linking, task lists).
func renderMarkdown(raw []byte) (string, error) {
	md := goldmark.New(
		goldmark.WithExtensions(extension.GFM),
		goldmark.WithParserOptions(parser.WithAutoHeadingID()),
		goldmark.WithRendererOptions(html.WithHardWraps(), html.WithXHTML()),
	)
	var buf bytes.Buffer
	if err := md.Convert(raw, &buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

const docsCSS = `<style>
.docs-shell { display: grid; grid-template-columns: 220px 1fr; gap: 32px; align-items: start; }
.docs-nav { background: #fff; border: 1px solid var(--border); border-radius: 4px; padding: 8px 0; position: sticky; top: 16px; }
.docs-nav ul { list-style: none; padding: 0; margin: 0; }
.docs-nav li { padding: 0; }
.docs-nav li a { display: block; padding: 8px 16px; color: var(--fg); text-decoration: none; border-left: 3px solid transparent; }
.docs-nav li a:hover { background: #f6f6f6; }
.docs-nav li.active a { border-left-color: var(--accent); font-weight: 600; background: #f0f7f3; }
.docs-body { background: #fff; border: 1px solid var(--border); border-radius: 4px; padding: 28px 40px; max-width: 900px; line-height: 1.65; }
.docs-body h1, .docs-body h2, .docs-body h3, .docs-body h4 { margin-top: 28px; margin-bottom: 12px; line-height: 1.25; color: var(--fg); }
.docs-body h1 { font-size: 28px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
.docs-body h2 { font-size: 20px; color: var(--muted); text-transform: none; letter-spacing: normal; }
.docs-body h3 { font-size: 16px; }
.docs-body p { margin: 12px 0; }
.docs-body code { background: #f1f1f1; padding: 1px 5px; border-radius: 3px; font-size: 13px; }
.docs-body pre { background: #1e1e1e; color: #f5f5f5; padding: 14px 18px; overflow-x: auto; border-radius: 4px; line-height: 1.5; }
.docs-body pre code { background: transparent; color: inherit; padding: 0; font-size: 13px; }
.docs-body table { border-collapse: collapse; margin: 16px 0; width: 100%; }
.docs-body th, .docs-body td { border: 1px solid var(--border); padding: 6px 12px; text-align: left; vertical-align: top; }
.docs-body th { background: #f5f5f5; }
.docs-body ul, .docs-body ol { padding-left: 24px; }
.docs-body li { margin: 4px 0; }
.docs-body blockquote { border-left: 4px solid var(--border); padding: 4px 16px; color: var(--muted); margin: 12px 0; background: #fafafa; }
.docs-body a { color: var(--accent); }
.docs-index { list-style: none; padding: 0; }
.docs-index li { padding: 10px 0; border-bottom: 1px solid var(--border); }
.docs-index li:last-child { border-bottom: none; }
.docs-index a { font-size: 15px; }
@media (max-width: 900px) { .docs-shell { grid-template-columns: 1fr; } .docs-nav { position: static; } }
</style>`
