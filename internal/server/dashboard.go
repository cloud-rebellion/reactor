package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/knowledge"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// workflowDetail renders the three-pane view for one workflow:
// DAG (from dag.json), code (workflow.go or main.go), JSON (dag.json).
// Read-only in Ship 4; Ship 5 adds save-with-validate POST routes.
func (s *Server) workflowDetail(w http.ResponseWriter, r *http.Request) {
	slug, ok := slugFromRequest(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	wfID, err := s.workflowIDForViewer(r, slug)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			http.Error(w, "workflow not registered", http.StatusNotFound)
			return
		}
		s.errorPage(w, "lookup workflow", err)
		return
	}
	// Tenant isolation: a member may only open their own tenant's workflows.
	if scope := viewerScope(r); scope != "" {
		if owner, oErr := s.Journal.WorkflowTenant(ctx, wfID); oErr == nil && owner != scope {
			http.Error(w, "workflow not registered", http.StatusNotFound)
			return
		}
	}

	root := s.WorkflowsRoot
	if root == "" && s.Registry != nil {
		root = s.Registry.Root
	}
	dir := filepath.Join(root, slug)

	codeBytes, codePath := readFirstAvailable(dir, "main.go", "workflow.go")
	dagBytes, dagPath := readFirstAvailable(dir, "dag.json")

	availableSet := map[string]bool{}
	if list, err := s.Registry.List(); err == nil {
		for _, sl := range list {
			availableSet[sl] = true
		}
	}

	triggers, _ := s.Journal.ListTriggersForWorkflow(ctx, wfID)
	triggerWritesEnabled := s.Vault != nil

	wf, wfErr := s.Journal.GetWorkflow(ctx, wfID)
	if wfErr != nil {
		// The slug already resolved so this is a race (workflow deleted
		// between the two reads). Render with a zero baseline so the
		// form still works rather than erroring the whole page.
		s.Log.Warn("workflowDetail: GetWorkflow failed", "wfID", wfID, "err", wfErr)
	}

	// Pull a freshly-minted webhook secret out of the single-use
	// server-side flash store; clears the cookie regardless of whether
	// a payload was present so a second load shows no secret.
	flash := s.flash.take(w, r)

	routes, _ := s.Journal.ListNotificationRoutesForWorkflow(ctx, wfID)
	// Scope the attach-channel picker to the WORKFLOW's tenant. This page is
	// member-facing while /notifications is admin-gated, so an unscoped list
	// here handed any member the id, name and kind of every alert channel in
	// the install (and post-tenancy, every other tenant's).
	channelScope, err := s.Journal.WorkflowTenant(ctx, wfID)
	if err != nil {
		s.errorPage(w, "resolve workflow tenant", err)
		return
	}
	triggerActionQuery := ""
	if viewerScope(r) == "" && channelScope != "" {
		triggerActionQuery = "?tenant=" + url.QueryEscape(channelScope)
	}
	allChannels, _ := s.Journal.ListNotificationChannelsByTenant(ctx, channelScope)
	downstream, _ := s.Journal.ChainTriggersDownstreamOf(ctx, wfID)
	rateLimit, _ := s.Journal.WorkflowRateLimit(ctx, wfID)

	s.renderPage(w, r, page{
		Title:   "Workflow " + slug,
		Heading: "Workflow " + slug,
		Body: template.HTML(workflowDetailBody(workflowDetailData{
			Slug:                        slug,
			ID:                          wfID,
			Deployed:                    availableSet[slug],
			CodePath:                    codePath,
			Code:                        string(codeBytes),
			DAGPath:                     dagPath,
			DAG:                         string(dagBytes),
			EditEnabled:                 s.CodeValidator != nil,
			Triggers:                    triggers,
			TriggerWritesEnabled:        triggerWritesEnabled,
			TriggerActionQuery:          triggerActionQuery,
			NewWebhookToken:             flash["new_webhook_token"],
			NewWebhookSecret:            flash["new_webhook_secret"],
			NewWebhookProvider:          flash["new_webhook_provider"],
			NewWebhookCredentialID:      flash["new_webhook_credential_id"],
			EstimatedMinutesSavedPerRun: wf.EstimatedMinutesSavedPerRun,
			RateLimitPerMin:             rateLimit,
			NotificationRoutes:          routes,
			AllNotificationChannels:     allChannels,
			DownstreamChains:            downstream,
		})),
	})
}

type workflowDetailData struct {
	Slug, ID                    string
	Deployed                    bool
	CodePath, Code              string
	DAGPath, DAG                string
	EditEnabled                 bool
	Triggers                    []journal.Trigger
	TriggerWritesEnabled        bool
	TriggerActionQuery          string
	NewWebhookToken             string
	NewWebhookSecret            string
	NewWebhookProvider          string
	NewWebhookCredentialID      string
	EstimatedMinutesSavedPerRun int
	RateLimitPerMin             int
	NotificationRoutes          []journal.NotificationRouteWithChannel
	AllNotificationChannels     []journal.NotificationChannel
	DownstreamChains            []journal.ChainTriggerView
}

func workflowDetailBody(d workflowDetailData) string {
	var b strings.Builder

	// Top metadata strip.
	deploy := `<span class="tag tag-off">missing</span>`
	if d.Deployed {
		deploy = `<span class="tag tag-on">deployed</span>`
	}
	fmt.Fprintf(&b, `<table>
<tr><th>Slug</th><td><code>%s</code></td></tr>
<tr><th>ID</th><td><code>%s</code></td></tr>
<tr><th>Binary</th><td>%s</td></tr>
</table>`,
		template.HTMLEscapeString(d.Slug), template.HTMLEscapeString(d.ID), deploy)

	// Lifecycle actions: manual run + enable/disable + delete.
	b.WriteString(`<h2>Run now</h2>`)
	fmt.Fprintf(&b, `<form method="POST" action="/workflows/%s/run" class="form">
  <label>Payload (JSON, optional)
    <textarea name="payload" rows="4" placeholder='{"hello":"world"}'></textarea>
  </label>
  <label class="form-inline"><input type="checkbox" name="dry_run"> Test run (dry run): execute with this input but suppress notifications + downstream chains. Workflow code can read REACTOR_MODE=dry_run to mock its own external calls.</label>
  <button type="submit" class="btn-primary">Dispatch</button>
  <span class="muted">Fires the workflow as a manual trigger. The run shows up at <code>/runs</code> within a second.</span>
</form>`, template.URLQueryEscaper(d.Slug))

	b.WriteString(`<h2>Lifecycle</h2>`)
	fmt.Fprintf(&b, `<form method="POST" action="/workflows/%s/disable" class="form-inline">
  <button type="submit">Disable</button>
  <span class="muted">Stops dispatcher from accepting new runs. Existing runs continue.</span>
</form>
<form method="POST" action="/workflows/%s/enable" class="form-inline">
  <button type="submit">Enable</button>
</form>
<form method="POST" action="/workflows/%s/delete" class="form-inline" data-confirm="Delete workflow + all run history? This cannot be undone.">
  <button type="submit" class="btn-link">Delete (irreversible)</button>
</form>`,
		template.URLQueryEscaper(d.Slug),
		template.URLQueryEscaper(d.Slug),
		template.URLQueryEscaper(d.Slug),
	)

	// Time-saved baseline: drives the home dashboard headline number.
	b.WriteString(`<h2>Time saved</h2>`)
	fmt.Fprintf(&b, `<form method="POST" action="/workflows/%s/minutes-saved" class="form-inline">
  <label>Manual baseline <input type="number" name="minutes" min="0" max="100000" value="%d" required> minutes per successful run</label>
  <button type="submit">Save</button>
  <span class="muted">How long a person would have spent doing this run by hand. The home dashboard's "Time saved" tile is the sum across all workflows of (this number x succeeded runs).</span>
</form>`,
		template.URLQueryEscaper(d.Slug),
		d.EstimatedMinutesSavedPerRun,
	)

	// Rate limit: cap how fast this workflow may start runs.
	b.WriteString(`<h2>Rate limit</h2>`)
	fmt.Fprintf(&b, `<form method="POST" action="/workflows/%s/rate-limit" class="form-inline">
  <label>Max runs <input type="number" name="per_min" min="0" max="100000" value="%d" required> per minute (0 = unlimited)</label>
  <button type="submit">Save</button>
  <span class="muted">Runs past this in any 60s window are refused (the trigger source backs off). Counted across instances.</span>
</form>`,
		template.URLQueryEscaper(d.Slug),
		d.RateLimitPerMin,
	)

	// Triggers section: surface every inbound source + let the operator
	// add/remove without dropping into SQL.
	b.WriteString(renderTriggersSection(d))

	// Notifications routing section: which channels fire on which
	// terminal statuses for this workflow.
	b.WriteString(renderNotificationRoutesSection(d.Slug, d.NotificationRoutes, d.AllNotificationChannels))

	// Downstream chain section: workflows that fire when THIS workflow
	// terminates. The upstream side (workflows that THIS depends on)
	// lives in the trigger table below as a 'chain' trigger row.
	b.WriteString(renderDownstreamChainSection(d.DownstreamChains))

	// Unified workflow editor: a Visual <-> Code toggle. The Visual view is the
	// cytoscape DAG with clickable nodes; tapping a node slides in a drawer
	// (workflow-editor.js) that fetches and edits just that node's source. The
	// Code view keeps the whole-file editors for devs. CSP stays script-src
	// 'self': every bit of logic lives in /assets, no inline JS.
	b.WriteString(`<h2>Editor</h2>`)
	fmt.Fprintf(&b, `<div id="wf-editor" data-slug="%s" data-editable="%t">`,
		template.HTMLEscapeString(d.Slug), d.EditEnabled)
	b.WriteString(`<div class="wf-toolbar" role="tablist">` +
		`<button type="button" class="wf-tab is-active" data-view="visual">Visual</button>` +
		`<button type="button" class="wf-tab" data-view="code">Code</button>` +
		`<span class="wf-toolbar-hint">Click a node to edit it</span></div>`)

	// Visual view: the data-flow map.
	b.WriteString(`<section class="wf-view" data-view="visual">`)
	if d.DAG == "" {
		b.WriteString(`<p class="empty">No dag.json found at <code>` + template.HTMLEscapeString(d.DAGPath+"/dag.json") + `</code>. Hand-built workflows can run without one; codegen-generated workflows always include it.</p>`)
	} else {
		// Cytoscape canvas. Data lives in a non-executing JSON island the
		// dag-render.js script reads; CSP stays script-src 'self'.
		b.WriteString(`<div id="dag-canvas" class="wf-canvas"></div>`)
		fmt.Fprintf(&b, `<script type="application/json" id="dag-data">%s</script>`, template.JSEscapeString(d.DAG))
		b.WriteString(`<script src="/assets/cytoscape.min.js"></script>`)
		b.WriteString(`<script src="/assets/dag-render.js"></script>`)
		// Step summary table stays as accessible fallback (also useful with
		// JS off, or to read idempotency keys / timeouts beside the graph).
		b.WriteString(`<details class="wf-steptable"><summary>Step table + dag.json source</summary>`)
		b.WriteString(renderDAGSummary(d.DAG))
		b.WriteString(`<pre>`)
		b.WriteString(template.HTMLEscapeString(prettyJSON(d.DAG)))
		b.WriteString(`</pre></details>`)
	}
	b.WriteString(`</section>`)

	// Code view: whole-file editors for devs.
	b.WriteString(`<section class="wf-view" data-view="code" hidden>`)
	if d.Code == "" {
		b.WriteString(`<p class="empty">Source not bundled at <code>` + template.HTMLEscapeString(d.CodePath) + `</code>. Operators can copy main.go into the workflow directory to surface it here.</p>`)
	} else {
		fmt.Fprintf(&b, `<p class="muted">From <code>%s</code></p>`, template.HTMLEscapeString(d.CodePath))
		if d.EditEnabled {
			fmt.Fprintf(&b, `<form method="post" action="/workflows/%s/code">`, template.URLQueryEscaper(d.Slug))
			fmt.Fprintf(&b, `<textarea name="body" rows="20" class="wf-codearea">%s</textarea>`, template.HTMLEscapeString(d.Code))
			b.WriteString(`<p><button type="submit" class="btn-primary">Save (runs go vet + reactor lint + go build)</button> <span class="muted">Failed validation returns 422 with the issue list.</span></p></form>`)
		} else {
			b.WriteString(`<pre>`)
			b.WriteString(template.HTMLEscapeString(d.Code))
			b.WriteString(`</pre>`)
		}
	}
	if d.EditEnabled && d.DAG != "" {
		fmt.Fprintf(&b, `<h3>dag.json</h3><form method="post" action="/workflows/%s/dag">`, template.URLQueryEscaper(d.Slug))
		fmt.Fprintf(&b, `<textarea name="body" rows="14" class="wf-codearea">%s</textarea>`, template.HTMLEscapeString(prettyJSON(d.DAG)))
		b.WriteString(`<p><button type="submit" class="btn-primary">Save (runs JSON Schema validate)</button></p></form>`)
	}
	b.WriteString(`</section></div>`)

	// Slide-in editing drawer, populated by workflow-editor.js when a node is
	// tapped. Lives outside #wf-editor so it can fix to the viewport edge.
	b.WriteString(`<div id="wf-drawer-backdrop" class="wf-drawer-backdrop" hidden></div>` +
		`<aside id="wf-drawer" class="wf-drawer" aria-hidden="true" aria-label="Node editor">` +
		`<header class="wf-drawer-head"><div><span class="wf-drawer-kicker">Edit node</span>` +
		`<h3 id="wf-drawer-title">node</h3></div>` +
		`<button type="button" id="wf-drawer-close" class="wf-drawer-x" aria-label="Close">&times;</button></header>` +
		`<div class="wf-drawer-body"><p id="wf-drawer-meta" class="muted"></p>` +
		`<div id="wf-drawer-dataflow" class="wf-dataflow"></div>` +
		`<div class="wf-drawer-codewrap"><div class="wf-drawer-sechdr">Code <span class="muted">edit this node, Apply re-runs the validator</span></div>` +
		`<textarea id="wf-drawer-code" class="wf-codearea" rows="16" spellcheck="false"></textarea></div>` +
		`<div id="wf-drawer-status" class="wf-drawer-status"></div></div>` +
		`<footer class="wf-drawer-foot"><button type="button" id="wf-drawer-apply" class="btn-primary" disabled>Apply + rebuild</button> ` +
		`<button type="button" id="wf-drawer-cancel" class="btn-link">Cancel</button></footer></aside>`)
	b.WriteString(`<script src="/assets/workflow-editor.js"></script>`)

	return b.String()
}

// renderDAGSummary parses dag.json and renders a small step list that
// gives operators an at-a-glance shape without needing a heavyweight
// graph library. Cytoscape lands in Ship 5 alongside the editor.
func renderDAGSummary(src string) string {
	var dag struct {
		Steps []struct {
			Name           string   `json:"name"`
			Kind           string   `json:"kind"`
			DependsOn      []string `json:"depends_on,omitempty"`
			IdempotencyKey string   `json:"idempotency_key,omitempty"`
			TimeoutSeconds float64  `json:"timeout_seconds,omitempty"`
		} `json:"steps"`
		Nodes []struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
		} `json:"nodes"`
		Triggers []struct {
			Kind string `json:"kind"`
		} `json:"triggers"`
	}
	if err := json.Unmarshal([]byte(src), &dag); err != nil {
		return `<p class="warn">dag.json is not parseable: ` + template.HTMLEscapeString(err.Error()) + `</p>`
	}

	type step struct {
		Name, Kind     string
		DependsOn      []string
		Idem           string
		TimeoutSeconds float64
	}
	steps := make([]step, 0, len(dag.Steps)+len(dag.Nodes))
	for _, s := range dag.Steps {
		steps = append(steps, step{Name: s.Name, Kind: s.Kind, DependsOn: s.DependsOn, Idem: s.IdempotencyKey, TimeoutSeconds: s.TimeoutSeconds})
	}
	for _, n := range dag.Nodes {
		steps = append(steps, step{Name: n.Name, Kind: n.Kind})
	}

	var b strings.Builder
	if len(dag.Triggers) > 0 {
		var ts []string
		for _, t := range dag.Triggers {
			ts = append(ts, template.HTMLEscapeString(t.Kind))
		}
		b.WriteString(`<p>Triggers: `)
		b.WriteString(strings.Join(ts, ", "))
		b.WriteString(`</p>`)
	}
	if len(steps) == 0 {
		b.WriteString(`<p class="empty">No steps declared.</p>`)
		return b.String()
	}
	b.WriteString(`<table><thead><tr><th>Step</th><th>Kind</th><th>Depends on</th><th>Idempotency</th><th>Timeout</th></tr></thead><tbody>`)
	for _, st := range steps {
		dep := strings.Join(st.DependsOn, ", ")
		if dep == "" {
			dep = `<span class="muted">-</span>`
		} else {
			dep = template.HTMLEscapeString(dep)
		}
		idem := st.Idem
		if idem == "" {
			idem = `<span class="muted">-</span>`
		} else {
			idem = `<code>` + template.HTMLEscapeString(idem) + `</code>`
		}
		timeout := `<span class="muted">-</span>`
		if st.TimeoutSeconds > 0 {
			timeout = fmt.Sprintf("%.0fs", st.TimeoutSeconds)
		}
		fmt.Fprintf(&b, `<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			template.HTMLEscapeString(st.Name), template.HTMLEscapeString(st.Kind), dep, idem, timeout)
	}
	b.WriteString(`</tbody></table>`)
	return b.String()
}

// knowledge renders the topic-faceted list of corpus entries.
func (s *Server) knowledge(w http.ResponseWriter, r *http.Request) {
	// Tenant-scoped, not admin-gated: viewerScope is "" for an admin (sees
	// everything) and the member's tenant otherwise. Untenanted entries are
	// shared material and stay visible to all.
	entries, err := s.Knowledge.ListForTenant(r.Context(), "", viewerScope(r))
	if err != nil {
		s.errorPage(w, "list knowledge", err)
		return
	}
	s.renderPage(w, r, page{
		Title:   "Knowledge",
		Heading: "Knowledge corpus",
		Body:    template.HTML(knowledgeListBody(entries)),
	})
}

func knowledgeListBody(entries []knowledge.Entry) string {
	if len(entries) == 0 {
		return `<p class="empty">No knowledge entries. The corpus is pre-seeded on init; if you see this on a fresh install, check that ~/.reactor/knowledge/ exists.</p><p><a href="/knowledge/new" class="btn-primary">Add entry</a></p>`
	}
	// Group by topic for the topic-faceted view.
	byTopic := map[string][]knowledge.Entry{}
	var topics []string
	for _, e := range entries {
		t := e.Frontmatter.Topic
		if _, ok := byTopic[t]; !ok {
			topics = append(topics, t)
		}
		byTopic[t] = append(byTopic[t], e)
	}
	sort.Strings(topics)

	var b strings.Builder
	b.WriteString(`<p><a href="/knowledge/new" class="btn-primary">Add entry</a></p>`)
	fmt.Fprintf(&b, `<p class="muted">%d entries across %d topics. Each entry is a markdown file in <code>~/.reactor/knowledge/&lt;topic&gt;/</code>; the codegen prompt assembler reads these on every <code>reactor generate</code> call.</p>`, len(entries), len(topics))
	for _, t := range topics {
		fmt.Fprintf(&b, `<h2>%s</h2><table><thead><tr><th>Title</th><th>ID</th><th>Gold</th><th>Citations</th><th>Created by</th></tr></thead><tbody>`,
			template.HTMLEscapeString(t))
		for _, e := range byTopic[t] {
			gold := ""
			if e.Frontmatter.Gold {
				gold = `<span class="tag tag-on">gold</span>`
			}
			fmt.Fprintf(&b, `<tr><td><a href="/knowledge/%s">%s</a></td><td><code>%s</code></td><td>%s</td><td>%d</td><td>%s</td></tr>`,
				template.URLQueryEscaper(e.Frontmatter.ID),
				template.HTMLEscapeString(e.Frontmatter.Title), template.HTMLEscapeString(e.Frontmatter.ID),
				gold, e.Frontmatter.CitationCount, template.HTMLEscapeString(e.Frontmatter.CreatedBy))
		}
		b.WriteString(`</tbody></table>`)
	}
	return b.String()
}

// knowledgeDetail renders a single entry with its frontmatter +
// markdown body + (TODO Ship 5) which generations cited it.
func (s *Server) knowledgeDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	// Scoped fetch: another tenant's entry returns ErrNotFound, never a
	// permission error, so guessing an id cannot confirm it exists.
	entry, err := s.Knowledge.GetForTenant(r.Context(), id, viewerScope(r))
	if err != nil {
		if errors.Is(err, knowledge.ErrNotFound) {
			http.Error(w, "knowledge entry not found", http.StatusNotFound)
			return
		}
		s.errorPage(w, "get knowledge", err)
		return
	}
	s.renderPage(w, r, page{
		Title:   entry.Frontmatter.Title,
		Heading: entry.Frontmatter.Title,
		Body:    template.HTML(knowledgeDetailBody(entry)),
	})
}

func knowledgeDetailBody(e knowledge.Entry) string {
	var b strings.Builder
	gold := "no"
	if e.Frontmatter.Gold {
		gold = `<span class="tag tag-on">gold</span>`
	}
	fmt.Fprintf(&b, `<table>
<tr><th>ID</th><td><code>%s</code></td></tr>
<tr><th>Topic</th><td><code>%s</code></td></tr>
<tr><th>Created by</th><td>%s</td></tr>
<tr><th>Gold</th><td>%s</td></tr>
<tr><th>Citations</th><td>%d</td></tr>
<tr><th>Sources</th><td>%s</td></tr>
<tr><th>Tags</th><td>%s</td></tr>
</table>`,
		template.HTMLEscapeString(e.Frontmatter.ID),
		template.HTMLEscapeString(e.Frontmatter.Topic),
		template.HTMLEscapeString(e.Frontmatter.CreatedBy),
		gold, e.Frontmatter.CitationCount,
		formatList(e.Frontmatter.Sources), formatList(e.Frontmatter.Tags),
	)
	b.WriteString(`<h2>Body</h2><pre>`)
	b.WriteString(template.HTMLEscapeString(e.Body))
	b.WriteString(`</pre>`)

	// Lifecycle actions: promote to gold, mark stale, supersede.
	// Rendered always; the routes are mounted only when KnowledgeWrite
	// is wired, so a read-only deployment 404s on the POST and the
	// operator sees an explainable error.
	fmt.Fprintf(&b, `<h2>Actions</h2>
<form method="POST" action="/knowledge/%s/promote" class="form-inline">
  <button type="submit">Promote to gold</button>
  <span class="muted">marks the entry as authoritative; lens search prefers gold entries.</span>
</form>
<form method="POST" action="/knowledge/%s/stale" class="form-inline">
  <button type="submit" class="btn-link">Mark stale</button>
  <span class="muted">drops the entry from default lens results without deleting it.</span>
</form>
<form method="POST" action="/knowledge/%s/supersede" class="form-inline">
  <label>Replace with entry id <input type="text" name="superseded_by" placeholder="e.g. patterns-2026-05-30-abc" required></label>
  <button type="submit">Supersede</button>
</form>`,
		template.URLQueryEscaper(e.Frontmatter.ID),
		template.URLQueryEscaper(e.Frontmatter.ID),
		template.URLQueryEscaper(e.Frontmatter.ID),
	)
	return b.String()
}

func formatList(items []string) string {
	if len(items) == 0 {
		return `<span class="muted">-</span>`
	}
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = `<code>` + template.HTMLEscapeString(it) + `</code>`
	}
	return strings.Join(parts, " ")
}

// graphJSON serialises the runtime graph for external consumers.
// Same shape as the MCP query_graph response so any tool that
// understands one understands the other.
func (s *Server) graphJSON(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := s.Graph.Serialize(w); err != nil {
		s.Log.Error("graph serialize", "err", err)
	}
}

// readFirstAvailable returns the first existing file under dir from
// the candidate names, or empty bytes + the (last attempted) path.
// Used by /workflows/{slug} so we can render gracefully whether the
// source landed as workflow.go (codegen) or main.go (hand-built).
func readFirstAvailable(dir string, names ...string) ([]byte, string) {
	for _, n := range names {
		p := filepath.Join(dir, n)
		data, err := os.ReadFile(p)
		if err == nil {
			return data, p
		}
	}
	return nil, filepath.Join(dir, names[len(names)-1])
}

// prettyJSON re-indents src for display. Returns src unchanged if it
// doesn't parse.
func prettyJSON(src string) string {
	var any interface{}
	if err := json.Unmarshal([]byte(src), &any); err != nil {
		return src
	}
	out, err := json.MarshalIndent(any, "", "  ")
	if err != nil {
		return src
	}
	return string(out)
}

// onboarding renders the 5-step welcome walkthrough. Auto-redirected to
// from /home when no workflows are registered. Each step also has a
// live status indicator so an operator who completes a step in another
// tab sees the green tick on refresh.
func (s *Server) onboarding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wfs, _ := s.Journal.ListWorkflows(ctx)
	creds, _ := s.Credentials.List(ctx)
	runs, _ := s.Journal.ListRecentRuns(ctx, 1)

	s.renderPage(w, r, page{
		Title:   "Welcome to Reactor",
		Heading: "Welcome to Reactor",
		Body:    template.HTML(onboardingBody(len(wfs) > 0, len(creds) > 0, len(runs) > 0)),
	})
}

func onboardingBody(hasWorkflow, hasCred, hasRun bool) string {
	step := func(num int, done bool, title, body string) string {
		mark := `<span class="tag tag-off">todo</span>`
		if done {
			mark = `<span class="tag tag-on">done</span>`
		}
		return fmt.Sprintf(`<h2>Step %d: %s %s</h2>%s`, num, template.HTMLEscapeString(title), mark, body)
	}

	var b strings.Builder
	b.WriteString(`<p class="muted">A 5-step walk from a fresh install to a working AI-built workflow. The status pill on each step updates when the daemon sees you complete it.</p>`)

	b.WriteString(step(1, true, "Daemon up", `<p>If you're reading this page the daemon's HTTP listener is alive. Healthz lives at <a href="/healthz"><code>/healthz</code></a>.</p>`))

	b.WriteString(step(2, false, "Connect your AI coding client", `
<p>Reactor's builder is <strong>your</strong> AI coding CLI (Claude Code or Codex), not a server-side API key: the client reads your live environment over MCP and writes the workflow Go. Install the reactor MCP server; each command prints the config snippet to paste in:</p>
<pre>reactor mcp install --client claude-code   # Claude Code (.claude/settings.json)
reactor mcp install --client codex         # Codex CLI (~/.codex/config.toml)
reactor mcp install --client claude-desktop
reactor mcp install --client cursor
reactor mcp install --client continue
reactor mcp install --client cline</pre>
<p>Add <code>--allow-write</code> to register the authoring tools (<code>reactor_create_workflow</code>, <code>reactor_grant_secret</code>, <code>reactor_dispatch_workflow</code>). Restart the client; <code>tools/list</code> should now show the reactor tools.</p>
<p class="muted">The in-dashboard prompt bar (a convenience that builds server-side) is optional and only appears when <code>ANTHROPIC_API_KEY</code> is set. You do not need it: the CLI-over-MCP path above is the primary one.</p>`))

	b.WriteString(step(3, hasCred, "Add your first credential", `
<p>Workflows that hit external APIs need a vault credential. Add one from the CLI:</p>
<pre>reactor vault add --name resend-api-key --service resend --provider shared-secret --value &lt;your-key&gt;</pre>
<p>Then grant a workflow access:</p>
<pre>reactor vault grant &lt;workflow-slug&gt; resend-api-key</pre>`))

	b.WriteString(step(4, hasWorkflow, "Generate (or scaffold) your first workflow", `
<p>Two paths. Either ask your AI client through the MCP:</p>
<blockquote>"Build me a Reactor workflow that sends a welcome email when a webhook fires"</blockquote>
<p>or scaffold one directly:</p>
<pre>reactor new cron-echo my-first-workflow
cd my-first-workflow
reactor workflow build --src . --slug my-first-workflow
reactor workflow register --db sqlite://./reactor.db --slug my-first-workflow --src main.go</pre>`))

	b.WriteString(step(5, hasRun, "Trigger it", `
<p>Insert a webhook trigger row + post to it. The dispatcher resolves the trigger, spawns the supervisor, and the run lands at <a href="/runs">/runs</a> within a second.</p>
<p>For the cron-echo template the trigger curl looks like:</p>
<pre>curl -X POST http://127.0.0.1:7777/webhook/&lt;token&gt; \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Signature: sha256=&lt;hmac&gt;" \
  -H "X-Webhook-Delivery: $(uuidgen)" \
  -d '{"hello":"world"}'</pre>`))

	b.WriteString(`<h2>Once you're done</h2><p>The home page at <a href="/">/</a> stops auto-redirecting here as soon as a workflow exists. Knowledge corpus + graph live at <a href="/knowledge">/knowledge</a> and <a href="/graph.json">/graph.json</a>.</p>`)
	return b.String()
}

// runTail streams slog lines for a run via Server-Sent Events. Reads
// from the in-process LogBuffer subscribed by the dispatcher; on EOF
// (run finished + buffer drained) the stream closes naturally.
func (s *Server) runTail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	if !s.runInScope(r, id) {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	if s.LogBuffer == nil {
		http.Error(w, "live logs not wired (LogBuffer nil)", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Replay any buffered lines first so a late subscriber sees the
	// run from the beginning.
	for _, line := range s.LogBuffer.Snapshot(id) {
		writeSSE(w, line)
	}
	flusher.Flush()

	sub := s.LogBuffer.Subscribe(id)
	defer s.LogBuffer.Unsubscribe(id, sub)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-sub:
			if !ok {
				// Buffer closed (run finished + cleanup ran).
				return
			}
			writeSSE(w, line)
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, line string) {
	// SSE wire shape: data: <line>\n\n. Newlines inside line need
	// each split out as their own data: prefix.
	for _, part := range strings.Split(line, "\n") {
		fmt.Fprintf(w, "data: %s\n", part)
	}
	fmt.Fprint(w, "\n")
}

// maxEditBody caps the size of a code or dag save. 1 MiB is plenty for
// a workflow.go (the lint already forbids the heavy stdlib that would
// bloat output) + dag.json should be a few KB. A bigger payload almost
// certainly indicates a misuse of the endpoint.
const maxEditBody = 1 << 20

// workflowSaveCode replaces <root>/workflows/<slug>/main.go (preferred)
// or workflow.go after running the same validator the codegen
// orchestrator uses. On success the file is atomically renamed into
// place + a git commit lands. On validation failure: 422 with the
// validator's error message in the response body.
func (s *Server) workflowSaveCode(w http.ResponseWriter, r *http.Request) {
	slug, ok := slugFromRequest(w, r)
	if !ok {
		return
	}
	if s.CodeValidator == nil {
		http.Error(w, "code validator not wired", http.StatusServiceUnavailable)
		return
	}

	body, status, err := readEditBody(w, r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	dir := filepath.Join(s.WorkflowsRoot, slug)
	// Read the sibling dag.json so the validator gets a complete
	// EmitInput shape; the chain checks dag.json validity too.
	dagBytes, _ := os.ReadFile(filepath.Join(dir, "dag.json"))

	if status, err := s.writeValidatedCode(r.Context(), slug, dir, viewerScope(r), body, dagBytes); err != nil {
		// 422 is a build/lint failure: the workflow author needs the compiler
		// output to fix their own code, so surface it. Everything else
		// (including 500) is an internal error that must not leak SQL/paths/vault
		// detail to the client; route it through the generic error page.
		if status == http.StatusUnprocessableEntity {
			http.Error(w, err.Error(), status)
		} else {
			s.errorPage(w, "save code", err)
		}
		return
	}

	http.Redirect(w, r, "/workflows/"+slug, http.StatusSeeOther)
}

// writeValidatedCode validates body (a full main.go) through the code
// validator, then atomically writes it to <dir>/main.go and commits. It stages
// in a tmp dir so a failed validate never leaves a half-written file. Returns
// (0, nil) on success; on failure an HTTP status (422 for a validation error,
// 500 for IO) plus the error to surface.
func (s *Server) writeValidatedCode(ctx context.Context, slug, dir, viewerTenant string, body, dagBytes []byte) (int, error) {
	tmpDir, err := os.MkdirTemp("", "reactor-edit-")
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("tmp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), body, 0o600); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("stage main.go: %w", err)
	}
	if len(dagBytes) > 0 {
		_ = os.WriteFile(filepath.Join(tmpDir, "dag.json"), dagBytes, 0o600)
	}
	if err := s.CodeValidator.Validate(ctx, tmpDir, slug, string(body), string(dagBytes)); err != nil {
		return http.StatusUnprocessableEntity, fmt.Errorf("validation failed:\n%w", err)
	}

	// Atomic rename: the destination already exists, so write to a sibling
	// temp + rename over it.
	dest := filepath.Join(dir, "main.go")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("mkdir dest: %w", err)
	}
	// Keep the current source so a failed rebuild can be rolled back rather
	// than leaving the tree describing code that is not what runs.
	var prev []byte
	hadPrev := false
	if b, rerr := os.ReadFile(dest); rerr == nil {
		prev, hadPrev = b, true
	}
	restore := func() {
		if hadPrev {
			_ = os.WriteFile(dest, prev, 0o600)
		}
	}

	stagePath, err := stageFile(dir, body)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := os.Rename(stagePath, dest); err != nil {
		_ = os.Remove(stagePath)
		return http.StatusInternalServerError, fmt.Errorf("rename: %w", err)
	}

	// REBUILD. Validation above compiled the source in a throwaway temp dir,
	// which proves it builds but changes nothing the runtime executes: the
	// supervisor execs an artifact published by the rebuild pipeline, and no
	// route, watcher or dispatch path recompiles source on demand. So the
	// drawer's "Apply + rebuild" button previously validated,
	// wrote, git-committed and returned ok:true while the OLD binary kept
	// serving every trigger. An admin patching a vulnerable step got a green
	// save and no fix. RegisterFromDir rebuilds even for an existing slug
	// (SkipIfExists reuses the workflow id and appends an artifact-bound version).
	if s.WorkflowRegister == nil {
		restore()
		return http.StatusServiceUnavailable, errors.New("this build cannot recompile workflows, so the save would not change what runs; use the reactor CLI on a host with the Go toolchain")
	}
	// A rebuild must not move the workflow between tenants, so pass its CURRENT
	// owner rather than the editor's scope.
	owner := ""
	if s.Journal != nil {
		if wfID, lerr := s.Journal.WorkflowIDBySlugInTenant(ctx, slug, viewerTenant); lerr == nil {
			owner, _ = s.Journal.WorkflowTenant(ctx, wfID)
		}
	}
	if _, err := s.WorkflowRegister.RegisterFromDir(ctx, slug, dir, owner); err != nil {
		restore()
		return http.StatusUnprocessableEntity, fmt.Errorf("rebuild failed, previous source restored:\n%w", err)
	}
	// Commit only once the rebuild succeeded, so git records what is actually
	// running rather than a source revision that never compiled into place.
	s.commitOptional(ctx, dir, slug, "edit "+slug+" main.go via dashboard")
	return 0, nil
}

// stageFile writes body to a unique sibling temp file in dir, returning its
// path for an atomic rename over the destination. A fixed "<dest>.new" name
// (as this used to use, with O_TRUNC) let two concurrent saves for one slug
// interleave: A writes its stage, B truncates and is mid-write, A renames, and
// B's half-written buffer is published as main.go, bytes no validator ever saw.
func stageFile(dir string, body []byte) (string, error) {
	f, err := os.CreateTemp(dir, "main.go.stage-")
	if err != nil {
		return "", fmt.Errorf("write stage: %w", err)
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("stage chmod: %w", err)
	}
	if _, err := f.Write(body); err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("write stage: %w", err)
	}
	return f.Name(), nil
}

// workflowSaveDAG replaces dag.json after schema validation.
func (s *Server) workflowSaveDAG(w http.ResponseWriter, r *http.Request) {
	slug, ok := slugFromRequest(w, r)
	if !ok {
		return
	}

	body, status, err := readEditBody(w, r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	if err := registry.ValidateDAG(body); err != nil {
		http.Error(w, "validation failed:\n"+err.Error(), http.StatusUnprocessableEntity)
		return
	}

	dir := filepath.Join(s.WorkflowsRoot, slug)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.errorPage(w, "mkdir dest", err)
		return
	}
	stagePath := filepath.Join(dir, "dag.json.new")
	if err := os.WriteFile(stagePath, body, 0o600); err != nil {
		s.errorPage(w, "write stage", err)
		return
	}
	if err := os.Rename(stagePath, filepath.Join(dir, "dag.json")); err != nil {
		s.errorPage(w, "rename", err)
		return
	}
	s.commitOptional(r.Context(), dir, slug, "edit "+slug+" dag.json via dashboard")
	http.Redirect(w, r, "/workflows/"+slug, http.StatusSeeOther)
}

// readEditBody handles both raw POST bodies and form-encoded posts
// (the textarea form sends application/x-www-form-urlencoded with the
// content under the "body" field). Returns (bytes, status, err).
func readEditBody(w http.ResponseWriter, r *http.Request) ([]byte, int, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxEditBody)
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				return nil, http.StatusRequestEntityTooLarge, errors.New("payload too large")
			}
			return nil, http.StatusBadRequest, err
		}
		return []byte(r.FormValue("body")), 0, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, http.StatusRequestEntityTooLarge, errors.New("payload too large")
		}
		return nil, http.StatusBadRequest, err
	}
	if len(body) == 0 {
		return nil, http.StatusBadRequest, errors.New("empty body")
	}
	return body, 0, nil
}

func (s *Server) commitOptional(ctx context.Context, dir, slug, msg string) {
	if s.CodeCommitter == nil {
		return
	}
	if err := s.CodeCommitter.Commit(ctx, dir, slug, msg); err != nil {
		s.Log.Warn("editor: git commit failed", "slug", slug, "err", err)
	}
}
