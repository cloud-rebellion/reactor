package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/flowblocks"
	"github.com/bright-interaction/reactor/internal/knowledge"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/workflowproof"
)

const workflowArtifactMarker = ".artifact_sha256"

// errWorkflowSourceUnavailable means the dashboard cannot prove that the
// source being edited corresponds to the workflow's current immutable
// artifact. A mutable legacy directory is never an acceptable fallback for a
// journal-backed workflow because it may be shared by tenants with the same
// slug.
var errWorkflowSourceUnavailable = errors.New("workflow source snapshot unavailable")

// errWorkflowRevisionFenceUnavailable means a journal-backed editor save was
// wired to a registrar that cannot atomically compare the reviewed version.
// Refusing the save is safer than silently appending over a concurrent MCP or
// CLI revision.
var errWorkflowRevisionFenceUnavailable = errors.New("workflow revision fence unavailable")

var errWorkflowExpectedVersionInvalid = errors.New("invalid expected workflow version")

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

	dir, sourceErr := s.workflowSourceDir(ctx, slug, editTenantScope(r))
	if sourceErr != nil {
		if errors.Is(sourceErr, errWorkflowSourceUnavailable) {
			http.Error(w, "workflow source snapshot unavailable; rebuild and re-register this workflow before editing", http.StatusConflict)
			return
		}
		s.errorPage(w, "resolve workflow source", sourceErr)
		return
	}

	codeBytes, codePath, codeTruncated := readFirstAvailableBounded(dir, maxFlowSourceBytes, "main.go", "workflow.go", "source/main.go")
	dagBytes, dagPath, dagTruncated := readFirstAvailableBounded(dir, maxFlowDAGBytes, "dag.json", "source/dag.json")

	availableSet := map[string]bool{}
	var available []string
	if scope := editTenantScope(r); scope != "" {
		available, _ = s.Registry.ListForTenant(scope)
	} else {
		available, _ = s.Registry.List()
	}
	for _, sl := range available {
		availableSet[sl] = true
	}

	triggers, _ := s.Journal.ListTriggersForWorkflow(ctx, wfID)
	readOnly := false
	if user, ok := UserFromContext(r.Context()); ok {
		readOnly = !user.IsAdmin()
	}
	triggerWritesEnabled := s.Vault != nil && !readOnly

	wf, wfErr := s.Journal.GetWorkflow(ctx, wfID)
	if wfErr != nil {
		// The slug already resolved so this is a race (workflow deleted
		// between the two reads). Render with a zero baseline so the
		// form still works rather than erroring the whole page.
		s.Log.Warn("workflowDetail: GetWorkflow failed", "wfID", wfID, "err", wfErr)
	}
	currentVersion := 0
	var currentVersionRecord journal.WorkflowVersion
	if version, versionErr := s.Journal.CurrentWorkflowVersionRecordBounded(ctx, wfID, maxFlowDAGBytes); versionErr == nil {
		currentVersionRecord = version
		currentVersion = version.Version
		var snapshotErr error
		if dagBytes, dagTruncated, snapshotErr = workflowDetailSnapshot(version, codeBytes, codeTruncated, dagBytes, dagTruncated); snapshotErr != nil {
			http.Error(w, "workflow source snapshot changed during page load; reload to review the current version", http.StatusConflict)
			return
		}
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
	// Slugs are unique per tenant, not globally. Every form on this page must
	// carry the selected tenant when a global admin opened a duplicate slug;
	// otherwise the POST resolves whichever tenant's row the bare-slug lookup
	// happens to return (and can mutate the wrong workflow).
	workflowActionQuery := ""
	if viewerScope(r) == "" && channelScope != "" {
		workflowActionQuery = "?tenant=" + url.QueryEscape(channelScope)
	}
	artifactSHA256, flowProofStatus, flowProofReason := s.workflowDetailProof(ctx, slug, channelScope, currentVersionRecord)
	channelPage := notificationPageIndex(r, "channel_page")
	allChannels, channelHasMore, err := s.Journal.ListNotificationChannelMetadataByTenantPage(ctx, channelScope, notificationPageSize, channelPage*notificationPageSize)
	if err != nil {
		s.errorPage(w, "list notification channels", err)
		return
	}
	downstream, _ := s.Journal.ChainTriggersDownstreamOf(ctx, wfID)
	rateLimit, _ := s.Journal.WorkflowRateLimit(ctx, wfID)

	s.renderPage(w, r, page{
		Title:   "Workflow " + slug,
		Heading: "Workflow " + slug,
		Body: template.HTML(workflowDetailBody(workflowDetailData{
			Slug:                        slug,
			ID:                          wfID,
			CurrentVersion:              currentVersion,
			ArtifactSHA256:              artifactSHA256,
			FlowProofStatus:             flowProofStatus,
			FlowProofReason:             flowProofReason,
			ReadOnly:                    readOnly,
			Deployed:                    availableSet[slug],
			CodePath:                    codePath,
			Code:                        string(codeBytes),
			DAGPath:                     dagPath,
			DAG:                         string(dagBytes),
			DAGTruncated:                dagTruncated,
			CodeTruncated:               codeTruncated,
			EditEnabled:                 s.CodeValidator != nil && !readOnly && !codeTruncated,
			Triggers:                    triggers,
			TriggerWritesEnabled:        triggerWritesEnabled,
			WorkflowActionQuery:         workflowActionQuery,
			TriggerActionQuery:          workflowActionQuery,
			NewWebhookToken:             flash["new_webhook_token"],
			NewWebhookSecret:            flash["new_webhook_secret"],
			NewWebhookProvider:          flash["new_webhook_provider"],
			NewWebhookCredentialID:      flash["new_webhook_credential_id"],
			EstimatedMinutesSavedPerRun: wf.EstimatedMinutesSavedPerRun,
			RateLimitPerMin:             rateLimit,
			NotificationRoutes:          routes,
			AllNotificationChannels:     allChannels,
			NotificationChannelPage:     channelPage,
			NotificationChannelHasMore:  channelHasMore,
			DownstreamChains:            downstream,
		})),
	})
}

// The editor workspace is mutable. A rebuild or local change between its
// verification and page rendering must not pair stale source with a newly
// verified version. The canvas and DAG editor always use the bounded journal
// DAG from the same immutable version shown in the header. Oversized source
// is omitted by workflowDetailBody, while a legacy version without a usable
// code hash remains visibly unverified under workflowDetailProof.
func workflowDetailSnapshot(version journal.WorkflowVersion, code []byte, codeTruncated bool, workspaceDAG []byte, workspaceDAGTruncated bool) ([]byte, bool, error) {
	if version.Version < 1 || version.ArtifactSHA256 == "" {
		return workspaceDAG, workspaceDAGTruncated, nil
	}
	if !codeTruncated && len(version.CodeHash) == 16 {
		sum := sha256.Sum256(code)
		if hex.EncodeToString(sum[:])[:16] != version.CodeHash {
			return nil, false, errWorkflowSourceUnavailable
		}
	}
	return version.DAG, version.DAGTruncated, nil
}

// workflowDetailProof returns the same immutable source/DAG proof used by the
// dispatcher and MCP readiness receipts. The dashboard is an inspection
// surface, so an unverifiable version still renders its metadata with a
// warning; it must never be presented as an executable or trusted flow.
func (s *Server) workflowDetailProof(_ context.Context, slug, tenant string, version journal.WorkflowVersion) (artifactSHA256, status, reason string) {
	artifactSHA256 = strings.TrimSpace(version.ArtifactSHA256)
	if version.Version <= 0 || artifactSHA256 == "" {
		return artifactSHA256, "missing", "no immutable artifact is pinned"
	}
	if version.DAGTruncated {
		return artifactSHA256, "unavailable", fmt.Sprintf("workflow DAG is %d bytes and exceeds the bounded visual projection", version.DAGBytes)
	}
	stateRoot := strings.TrimSpace(s.State)
	if stateRoot == "" {
		root := strings.TrimSpace(s.WorkflowsRoot)
		if root == "" && s.Registry != nil {
			root = strings.TrimSpace(s.Registry.Root)
		}
		if filepath.Base(filepath.Clean(root)) == "workflows" {
			stateRoot = filepath.Dir(root)
		} else {
			stateRoot = root
		}
	}
	if stateRoot == "" {
		return artifactSHA256, "unavailable", "workflow state root is not configured"
	}
	proof := workflowproof.CheckVersionForTenant(stateRoot, slug, tenant, version)
	return artifactSHA256, proof.Status, proof.Reason
}

type workflowDetailData struct {
	Slug, ID        string
	CurrentVersion  int
	ArtifactSHA256  string
	FlowProofStatus string
	FlowProofReason string
	// ReadOnly is true for an authenticated member. Members can inspect a
	// workflow and run/cancel runs in their tenant, but all authoring,
	// lifecycle, trigger, notification, and editor mutations are admin-only.
	ReadOnly             bool
	Deployed             bool
	CodePath, Code       string
	CodeTruncated        bool
	DAGPath, DAG         string
	DAGTruncated         bool
	EditEnabled          bool
	Triggers             []journal.Trigger
	TriggerWritesEnabled bool
	// WorkflowActionQuery disambiguates admin mutations when duplicate slugs
	// exist across tenants. Members are pinned by session scope and leave it
	// empty; TriggerActionQuery is retained as a separate field for trigger
	// rendering tests and compatibility.
	WorkflowActionQuery         string
	TriggerActionQuery          string
	NewWebhookToken             string
	NewWebhookSecret            string
	NewWebhookProvider          string
	NewWebhookCredentialID      string
	EstimatedMinutesSavedPerRun int
	RateLimitPerMin             int
	NotificationRoutes          []journal.NotificationRouteWithChannel
	AllNotificationChannels     []journal.NotificationChannelMetadata
	NotificationChannelPage     int
	NotificationChannelHasMore  bool
	DownstreamChains            []journal.ChainTriggerView
}

func workflowDetailBody(d workflowDetailData) string {
	var b strings.Builder
	workflowActionQuery := d.WorkflowActionQuery

	// Top metadata strip.
	deploy := `<span class="tag tag-off">missing</span>`
	if d.Deployed {
		deploy = `<span class="tag tag-on">deployed</span>`
	}
	artifactDigest := strings.TrimSpace(d.ArtifactSHA256)
	if artifactDigest == "" {
		artifactDigest = "-"
	}
	artifactStatus := workflowProofTag(d.FlowProofStatus)
	fmt.Fprintf(&b, `<table>
<tr><th>Slug</th><td><code>%s</code></td></tr>
<tr><th>ID</th><td><code>%s</code></td></tr>
<tr><th>Immutable version</th><td>%s</td></tr>
<tr><th>Artifact SHA-256</th><td><code>%s</code></td></tr>
<tr><th>Flow proof</th><td>%s%s</td></tr>
<tr><th>Binary</th><td>%s</td></tr>
</table>`,
		template.HTMLEscapeString(d.Slug), template.HTMLEscapeString(d.ID),
		workflowVersionLabel(d.CurrentVersion), template.HTMLEscapeString(boundWorkflowArtifactDigest(artifactDigest)),
		artifactStatus, workflowProofReasonHTML(d.FlowProofReason), deploy)

	// Lifecycle actions: manual run + enable/disable + delete.
	b.WriteString(`<h2>Run now</h2>`)
	fmt.Fprintf(&b, `<form method="POST" action="/workflows/%s/run%s" class="form">
  <label>Payload (JSON, optional)
    <textarea name="payload" rows="4" placeholder='{"hello":"world"}'></textarea>
  </label>
  <label class="form-inline"><input type="checkbox" name="dry_run"> Test run (dry run): execute with this input but suppress notifications + downstream chains. Workflow code can read REACTOR_MODE=dry_run to mock its own external calls.</label>
  <button type="submit" class="btn-primary">Dispatch</button>
  <span class="muted">Fires the workflow as a manual trigger. The run shows up at <code>/runs</code> within a second.</span>
</form>`, template.URLQueryEscaper(d.Slug), workflowActionQuery)

	if !d.ReadOnly {
		b.WriteString(`<h2>Lifecycle</h2>`)
		fmt.Fprintf(&b, `<form method="POST" action="/workflows/%s/disable%s" class="form-inline">
  <button type="submit">Disable</button>
  <span class="muted">Stops dispatcher from accepting new runs. Existing runs continue.</span>
</form>
<form method="POST" action="/workflows/%s/enable%s" class="form-inline">
  <button type="submit">Enable</button>
</form>
<form method="POST" action="/workflows/%s/delete%s" class="form-inline" data-confirm="Delete workflow + all run history? This cannot be undone.">
  <button type="submit" class="btn-link">Delete (irreversible)</button>
</form>`,
			template.URLQueryEscaper(d.Slug),
			workflowActionQuery,
			template.URLQueryEscaper(d.Slug),
			workflowActionQuery,
			template.URLQueryEscaper(d.Slug),
			workflowActionQuery,
		)

		// Time-saved baseline: drives the home dashboard headline number.
		b.WriteString(`<h2>Time saved</h2>`)
		fmt.Fprintf(&b, `<form method="POST" action="/workflows/%s/minutes-saved%s" class="form-inline">
  <label>Manual baseline <input type="number" name="minutes" min="0" max="100000" value="%d" required> minutes per successful run</label>
  <button type="submit">Save</button>
  <span class="muted">How long a person would have spent doing this run by hand. The home dashboard's "Time saved" tile is the sum across all workflows of (this number x succeeded runs).</span>
</form>`,
			template.URLQueryEscaper(d.Slug),
			workflowActionQuery,
			d.EstimatedMinutesSavedPerRun,
		)

		// Rate limit: cap how fast this workflow may start runs.
		b.WriteString(`<h2>Rate limit</h2>`)
		fmt.Fprintf(&b, `<form method="POST" action="/workflows/%s/rate-limit%s" class="form-inline">
  <label>Max runs <input type="number" name="per_min" min="0" max="100000" value="%d" required> per minute (0 = unlimited)</label>
  <button type="submit">Save</button>
  <span class="muted">Runs past this in any 60s window are refused (the trigger source backs off). Counted across instances.</span>
</form>`,
			template.URLQueryEscaper(d.Slug),
			workflowActionQuery,
			d.RateLimitPerMin,
		)
	} else {
		b.WriteString(`<p class="muted">Workflow configuration is read-only for members. Ask an administrator to change lifecycle, limits, triggers, notifications, or source.</p>`)
	}

	// Triggers section: surface every inbound source + let the operator
	// add/remove without dropping into SQL.
	b.WriteString(renderTriggersSection(d))

	// Notifications routing section: which channels fire on which
	// terminal statuses for this workflow.
	b.WriteString(renderNotificationRoutesSectionForTenantPage(d.Slug, d.NotificationRoutes, d.AllNotificationChannels, d.ReadOnly, workflowActionQuery, d.NotificationChannelPage, d.NotificationChannelHasMore))

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
	editable := d.EditEnabled && !d.CodeTruncated
	fmt.Fprintf(&b, `<div id="wf-editor" data-slug="%s" data-editable="%t" data-action-query="%s" data-expected-version="%d">`,
		template.HTMLEscapeString(d.Slug), editable, template.HTMLEscapeString(workflowActionQuery), d.CurrentVersion)
	b.WriteString(`<div class="wf-toolbar" role="tablist">` +
		`<button type="button" class="wf-tab is-active" data-view="visual">Visual</button>` +
		`<button type="button" class="wf-tab" data-view="code">Code</button>` +
		`<span class="wf-toolbar-hint">Click a node to edit it</span></div>`)

	// Visual view: the data-flow map.
	b.WriteString(`<section class="wf-view" data-view="visual">`)
	if d.FlowProofStatus == "visual_unverified" || d.FlowProofStatus == "legacy_manifest_unpinned" {
		fmt.Fprintf(&b, `<p class="callout">This legacy artifact passed the available executable integrity checks, but its retained source manifest was not pinned when published. An already enabled version can keep running under its original proof policy. The displayed inner-step block annotations are unverified; rebuild and review a corrected flow before enabling this version again.%s</p>`, workflowProofReasonHTML(d.FlowProofReason))
	} else if d.FlowProofStatus != "verified" {
		fmt.Fprintf(&b, `<p class="callout">This visual flow is inspection data only. Immutable source/DAG proof is <strong>%s</strong>; Reactor will keep enablement and dispatch closed until the retained artifact and flow verify together.%s</p>`,
			template.HTMLEscapeString(displayWorkflowProofStatus(d.FlowProofStatus)), workflowProofReasonHTML(d.FlowProofReason))
	} else {
		b.WriteString(`<p class="muted">Durable flow proof verified against the immutable artifact and retained source. Review the durable nodes and edges before enabling; inner-step visual blocks are author-declared annotations.</p>`)
	}
	b.WriteString(`<p class="flow-note">This canvas shows the author-declared dependency graph; runtime step receipts show the actual path. Optional visual blocks inside a step are author-declared annotations, not inferred or independently executed. Undeclared branch predicates, error paths, loops, aggregation, and data transforms inside Go nodes remain unavailable.</p>`)
	if d.DAGTruncated {
		b.WriteString(`<p class="warn">dag.json exceeds the dashboard flow projection limit and was not embedded. Inspect the bounded MCP flow resource or replace the oversized artifact before treating this view as complete.</p>`)
	} else if d.DAG == "" {
		b.WriteString(`<p class="empty">No dag.json found at <code>` + template.HTMLEscapeString(d.DAGPath+"/dag.json") + `</code>. Hand-built workflows can run without one; codegen-generated workflows always include it.</p>`)
	} else {
		// Cytoscape canvas. Data lives in a non-executing JSON island the
		// dag-render.js script reads; CSP stays script-src 'self'.
		stepFlows := flowblocks.FromDAG([]byte(d.DAG), maxFlowDAGBytes)
		b.WriteString(`<div id="dag-canvas" class="wf-canvas"></div>`)
		fmt.Fprintf(&b, `<script type="application/json" id="dag-data">%s</script>`, scriptJSON([]byte(d.DAG)))
		if stepFlows.Complete && len(stepFlows.Steps) > 0 {
			if raw, err := json.Marshal(stepFlows); err == nil {
				fmt.Fprintf(&b, `<script type="application/json" id="step-flows-data">%s</script>`, scriptJSON(raw))
			}
		}
		b.WriteString(`<script src="/assets/cytoscape.min.js"></script>`)
		b.WriteString(`<script src="/assets/dag-render.js"></script>`)
		if len(stepFlows.Steps) > 0 || !stepFlows.Complete {
			b.WriteString(`<details class="wf-steptable"><summary>Declared visual blocks inside steps</summary>`)
			b.WriteString(renderAllDeclaredStepFlows(stepFlows))
			b.WriteString(`</details>`)
		}
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
	if d.CodeTruncated {
		fmt.Fprintf(&b, `<p class="warn">Source at <code>%s</code> exceeds the dashboard projection limit and was not embedded. Use the bounded MCP source resource or rebuild the workflow before editing it here.</p>`, template.HTMLEscapeString(d.CodePath))
	} else if d.Code == "" {
		b.WriteString(`<p class="empty">Source not bundled at <code>` + template.HTMLEscapeString(d.CodePath) + `</code>. Operators can copy main.go into the workflow directory to surface it here.</p>`)
	} else {
		fmt.Fprintf(&b, `<p class="muted">From <code>%s</code></p>`, template.HTMLEscapeString(d.CodePath))
		if d.EditEnabled {
			fmt.Fprintf(&b, `<form method="post" action="/workflows/%s/code%s">`, template.URLQueryEscaper(d.Slug), workflowActionQuery)
			if d.CurrentVersion > 0 {
				fmt.Fprintf(&b, `<input type="hidden" name="expected_version" value="%d">`, d.CurrentVersion)
			}
			fmt.Fprintf(&b, `<textarea name="body" rows="20" class="wf-codearea">%s</textarea>`, template.HTMLEscapeString(d.Code))
			b.WriteString(`<p><button type="submit" class="btn-primary">Save (runs go vet + reactor lint + go build)</button> <span class="muted">Failed validation returns 422 with the issue list.</span></p></form>`)
		} else {
			b.WriteString(`<pre>`)
			b.WriteString(template.HTMLEscapeString(d.Code))
			b.WriteString(`</pre>`)
		}
	}
	if d.EditEnabled && d.DAG != "" && !d.DAGTruncated {
		fmt.Fprintf(&b, `<h3>dag.json</h3><form method="post" action="/workflows/%s/dag%s">`, template.URLQueryEscaper(d.Slug), workflowActionQuery)
		if d.CurrentVersion > 0 {
			fmt.Fprintf(&b, `<input type="hidden" name="expected_version" value="%d">`, d.CurrentVersion)
		}
		fmt.Fprintf(&b, `<textarea name="body" rows="14" class="wf-codearea">%s</textarea>`, template.HTMLEscapeString(prettyJSON(d.DAG)))
		b.WriteString(`<p><button type="submit" class="btn-primary">Save (runs JSON Schema validate)</button></p></form>`)
	} else if d.EditEnabled && d.DAGTruncated {
		b.WriteString(`<p class="warn">The dag.json editor is disabled because the retained file exceeds the dashboard projection limit. Use the MCP flow inspection and replace it through a bounded authoring revision.</p>`)
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
		`<section id="wf-drawer-blockflow" class="wf-drawer-blockflow" hidden><div class="wf-drawer-sechdr">Declared block flow <span class="muted">inside this durable step</span></div>` +
		`<p class="flow-note">Author-declared review metadata. Only the enclosing durable step has an execution receipt; inspect the Go source to confirm these operations.</p>` +
		`<div id="wf-blockflow-canvas" class="wf-blockflow-canvas" role="img" aria-label="Declared block data flow"></div>` +
		`<div id="wf-blockflow-list" class="wf-blockflow-list"></div></section>` +
		`<div id="wf-drawer-dataflow" class="wf-dataflow"></div>` +
		`<div class="wf-drawer-codewrap"><div class="wf-drawer-sechdr">Code <span class="muted">edit this node, Apply re-runs the validator</span></div>` +
		`<textarea id="wf-drawer-code" class="wf-codearea" rows="16" spellcheck="false"></textarea></div>` +
		`<div id="wf-drawer-status" class="wf-drawer-status"></div></div>` +
		`<footer class="wf-drawer-foot"><button type="button" id="wf-drawer-apply" class="btn-primary" disabled>Apply + rebuild</button> ` +
		`<button type="button" id="wf-drawer-cancel" class="btn-link">Cancel</button></footer></aside>`)
	b.WriteString(`<script src="/assets/workflow-editor.js"></script>`)

	return b.String()
}

func workflowVersionLabel(version int) string {
	if version < 1 {
		return `<span class="tag tag-off">none</span>`
	}
	return fmt.Sprintf(`<code>v%d</code>`, version)
}

func boundWorkflowArtifactDigest(digest string) string {
	if len(digest) <= 128 {
		return digest
	}
	return digest[:128] + "..."
}

func displayWorkflowProofStatus(status string) string {
	switch status {
	case "verified", "visual_unverified", "legacy_manifest_unpinned", "unavailable", "legacy_unverified", "mismatch", "missing":
		return status
	default:
		return "unknown"
	}
}

func workflowProofTag(status string) string {
	status = displayWorkflowProofStatus(status)
	class := "tag-warn"
	if status == "verified" {
		class = "tag-on"
	} else if status == "missing" {
		class = "tag-off"
	}
	return fmt.Sprintf(`<span class="tag %s">%s</span>`, class, template.HTMLEscapeString(status))
}

func workflowProofReasonHTML(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return ""
	}
	if len(reason) > 512 {
		reason = reason[:512] + "..."
	}
	return ` <span class="muted">` + template.HTMLEscapeString(reason) + `</span>`
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
			ID   string `json:"id"`
			Name string `json:"name"`
			Kind string `json:"kind"`
		} `json:"nodes"`
		Edges []struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"edges"`
		Triggers []struct {
			Kind string `json:"kind"`
		} `json:"triggers"`
	}
	if len(src) > maxFlowDAGBytes {
		return `<p class="warn">dag.json is too large to render safely.</p>`
	}
	if err := json.Unmarshal([]byte(src), &dag); err != nil {
		return `<p class="warn">dag.json is not parseable: ` + template.HTMLEscapeString(err.Error()) + `</p>`
	}
	if (len(dag.Steps) > 0 && len(dag.Steps) > maxFlowNodes) ||
		(len(dag.Steps) == 0 && (len(dag.Nodes) > maxFlowNodes || len(dag.Edges) > maxFlowEdges)) || len(dag.Triggers) > maxFlowNodes {
		return `<p class="warn">dag.json exceeds the visual summary limits.</p>`
	}

	type step struct {
		Name, Kind     string
		DependsOn      []string
		Idem           string
		TimeoutSeconds float64
	}
	// Keep this table in lockstep with dag-render.js and the MCP flow
	// normalizer: a non-empty steps[] is the executable representation, so a
	// stale visual nodes[] companion must not add rows that cannot run. An
	// empty steps[] is the legacy visual-editor form and uses nodes[].
	steps := make([]step, 0, len(dag.Steps)+len(dag.Nodes))
	byName := make(map[string]int, len(dag.Steps)+len(dag.Nodes))
	for _, s := range dag.Steps {
		if s.Name == "" {
			continue
		}
		if len(s.Name) > maxFlowIdentifier || len(s.DependsOn) > maxFlowEdges {
			return `<p class="warn">dag.json contains an oversized step definition.</p>`
		}
		if _, exists := byName[s.Name]; exists {
			continue
		}
		byName[s.Name] = len(steps)
		steps = append(steps, step{Name: s.Name, Kind: boundFlowDisplay(s.Kind), DependsOn: append([]string(nil), s.DependsOn...), Idem: boundFlowDisplay(s.IdempotencyKey), TimeoutSeconds: s.TimeoutSeconds})
	}
	if len(dag.Steps) == 0 {
		for _, n := range dag.Nodes {
			name := n.ID
			if name == "" {
				name = n.Name
			}
			if name == "" {
				continue
			}
			if len(name) > maxFlowIdentifier {
				return `<p class="warn">dag.json contains an oversized node identifier.</p>`
			}
			if _, exists := byName[name]; exists {
				continue
			}
			byName[name] = len(steps)
			steps = append(steps, step{Name: name, Kind: boundFlowDisplay(n.Kind)})
		}
	}
	// Normalize legacy depends_on values before considering visual edges. The flow
	// renderer drops dangling and self references, so this summary must do the
	// same or the table can claim lineage that the canvas and runtime ignore.
	usedEdges := 0
	for i := range steps {
		filtered := steps[i].DependsOn[:0]
		for _, dep := range steps[i].DependsOn {
			if dep == "" || dep == steps[i].Name || len(dep) > maxFlowIdentifier {
				continue
			}
			if _, ok := byName[dep]; !ok {
				continue
			}
			updated := appendUnique(filtered, dep)
			if len(updated) == len(filtered) {
				continue
			}
			filtered = updated
			usedEdges++
			if usedEdges > maxFlowEdges {
				return `<p class="warn">dag.json exceeds the visual edge limits.</p>`
			}
		}
		steps[i].DependsOn = filtered
	}
	// Top-level edges[] belongs to the nodes[] encoding. The canvas and run
	// flow ignore it when executable steps[] exists; the accessible table must
	// not present a stale edge between two real steps as a dependency.
	if len(dag.Steps) == 0 {
		for _, edge := range dag.Edges {
			if edge.From == "" || edge.To == "" || edge.From == edge.To {
				continue
			}
			target, targetOK := byName[edge.To]
			if _, sourceOK := byName[edge.From]; !sourceOK || !targetOK {
				continue
			}
			updated := appendUnique(steps[target].DependsOn, edge.From)
			if len(updated) == len(steps[target].DependsOn) {
				continue
			}
			steps[target].DependsOn = updated
			usedEdges++
			if usedEdges > maxFlowEdges {
				return `<p class="warn">dag.json exceeds the visual edge limits.</p>`
			}
		}
	}

	var b strings.Builder
	if len(dag.Triggers) > 0 {
		var ts []string
		for _, t := range dag.Triggers {
			ts = append(ts, template.HTMLEscapeString(boundFlowDisplay(t.Kind)))
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

// readFirstAvailableBounded is the dashboard counterpart to the MCP flow
// projection boundary. It reads at most max+1 bytes so an imported or damaged
// dag.json cannot be fully materialized into the HTML page before the browser
// applies its own graph limits. The caller receives a clear truncation bit and
// can render a warning instead of a misleading partial graph.
func readFirstAvailableBounded(dir string, max int, names ...string) ([]byte, string, bool) {
	if max <= 0 {
		return nil, filepath.Join(dir, names[len(names)-1]), false
	}
	for _, n := range names {
		p := filepath.Join(dir, n)
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(f, int64(max)+1))
		_ = f.Close()
		if readErr != nil {
			continue
		}
		if len(data) > max {
			return data[:max], p, true
		}
		return data, p, false
	}
	return nil, filepath.Join(dir, names[len(names)-1]), false
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
	<p>Reactor's builder is <strong>your</strong> AI coding CLI (Claude Code or Codex), not a server-side API key: the client reads your live environment over MCP and writes the workflow Go. The daemon serves MCP over authenticated HTTP at <code>/mcp</code>. MCP clients do not reuse the browser's dashboard session. After <code>reactor setup</code>, sign in and mint a user API token at <a href="/tokens"><code>/tokens</code></a> (it is shown once), then keep it in the client environment before generating a registration:</p>
<pre>export REACTOR_MCP_TOKEN='rtr_...'
reactor mcp install --client claude-code --token-env REACTOR_MCP_TOKEN
reactor mcp check --url http://127.0.0.1:7777/mcp</pre>
<p>The installer prints equivalent HTTP snippets for Codex, Claude Desktop, Cursor, Continue, and Cline. Loopback development may use an explicitly configured no-auth daemon; remote endpoints must use HTTPS and an authenticated bearer, and the installer refuses to print an unauthenticated remote registration.</p>
<p>These commands default to <code>http://127.0.0.1:7777/mcp</code>; pass <code>--url</code> for another host or TLS endpoint. Remote endpoints must use HTTPS and an authenticated bearer. A dedicated <code>REACTOR_MCP_TOKEN</code> configured on the daemon is an alternative to a user API token; set its matching <code>REACTOR_MCP_TENANT</code> explicitly. Start the daemon with <code>reactor serve</code> and enable only the required <code>--mcp-allow-*</code> capabilities.</p>
<p>For a narrowly scoped client, enable only the daemon capabilities it needs: <code>--mcp-allow-authoring</code> for <code>reactor_create_workflow</code>, <code>--mcp-allow-secrets</code> for vault grants, and <code>--mcp-allow-dispatch</code> for <code>reactor_dispatch_workflow</code>. Restart the client; <code>tools/list</code> should show the selected tools.</p>
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

	// Replay the buffered tail and subscribe under one per-run lock. Taking a
	// snapshot and subscribing in separate calls leaves a gap where a line can
	// be appended to neither the replay nor the live stream.
	snapshot, sub := s.LogBuffer.SubscribeWithSnapshot(id)
	snapshot = boundRunDetailLogs(snapshot)
	// After a daemon restart the in-memory buffer is empty, while the durable
	// run is already terminal and its log tail lives in the journal. Do not
	// leave a client hanging on a brand-new open subscription in that case.
	if len(snapshot) == 0 {
		if info, err := s.Journal.GetRunForTenantMetadata(r.Context(), id, viewerScope(r), 0); err == nil && isTerminalStatus(info.Status) {
			if persisted, logErr := s.Journal.GetRunLogsPageForTenantBounded(r.Context(), id, info.TenantID, maxRunDetailLogLines, 0, maxRunDetailLogLineBytes); logErr == nil {
				snapshot = boundRunDetailPersistedLogs(persisted)
			}
			for _, line := range snapshot {
				writeSSE(w, line)
			}
			flusher.Flush()
			s.LogBuffer.Unsubscribe(id, sub)
			return
		}
	}
	for _, line := range snapshot {
		writeSSE(w, line)
	}
	flusher.Flush()
	defer s.LogBuffer.Unsubscribe(id, sub)

	ctx := r.Context()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			// Keep an otherwise-quiet SSE connection visible to reverse
			// proxies and browsers. A comment is valid SSE and carries no
			// workflow data.
			fmt.Fprint(w, ": keep-alive\n\n")
			flusher.Flush()
		case line, ok := <-sub:
			if !ok {
				// Buffer closed (run finished + cleanup ran).
				return
			}
			writeSSE(w, boundRunDetailLogLine(line))
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

// Retained source snapshots normally carry a registry manifest with these
// bounds. Legacy artifacts may not, so materialisation enforces the same
// per-file and aggregate limits before copying bytes into the editor
// workspace.
const (
	maxWorkflowMaterializedFileBytes  = 16 << 20
	maxWorkflowMaterializedTotalBytes = 64 << 20
)

// maxEditBody caps the size of a code or dag save. 1 MiB is plenty for
// a workflow.go (the lint already forbids the heavy stdlib that would
// bloat output) + dag.json should be a few KB. A bigger payload almost
// certainly indicates a misuse of the endpoint.
const maxEditBody = 1 << 20

// workflowSaveCode replaces the workflow-ID editor workspace source after
// running the same validator the codegen orchestrator uses. On success the
// file is atomically renamed into place, rebuilt into an immutable artifact,
// and committed. On validation failure: 422 with the validator's error.
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

	expectedVersion, err := s.workflowEditVersion(r.Context(), r, slug, editTenantScope(r))
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			http.Error(w, "workflow not registered", http.StatusNotFound)
		} else if errors.Is(err, errWorkflowExpectedVersionInvalid) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			s.errorPage(w, "resolve workflow version", err)
		}
		return
	}
	dir, err := s.workflowSourceDir(r.Context(), slug, editTenantScope(r))
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			http.Error(w, "workflow not registered", http.StatusNotFound)
		} else if errors.Is(err, errWorkflowSourceUnavailable) {
			http.Error(w, "workflow source snapshot unavailable; rebuild and re-register this workflow before editing", http.StatusConflict)
		} else {
			s.errorPage(w, "resolve workflow source", err)
		}
		return
	}
	// Read the sibling dag.json so the validator gets a complete EmitInput
	// shape; the chain checks dag.json validity too. A retained oversized DAG
	// is not safe to splice into an edit workspace, so refuse the edit rather
	// than silently validating against a truncated projection.
	dagBytes, _, dagTruncated := readFirstAvailableBounded(dir, maxFlowDAGBytes, "dag.json", "source/dag.json")
	if dagTruncated {
		http.Error(w, "workflow DAG exceeds the dashboard projection limit; rebuild before editing source", http.StatusConflict)
		return
	}

	if status, err := s.writeValidatedCode(r.Context(), slug, dir, editTenantScope(r), expectedVersion, body, dagBytes); err != nil {
		// 422 is a build/lint failure: the workflow author needs the compiler
		// output to fix their own code, so surface it. Everything else
		// (including 500) is an internal error that must not leak SQL/paths/vault
		// detail to the client; route it through the generic error page.
		if status == http.StatusUnprocessableEntity || status == http.StatusConflict || status == http.StatusServiceUnavailable {
			http.Error(w, err.Error(), status)
		} else {
			s.errorPage(w, "save code", err)
		}
		return
	}

	http.Redirect(w, r, workflowEditRedirect(r, slug), http.StatusSeeOther)
}

// writeValidatedCode validates body (a full main.go) through the code
// validator, then atomically writes it to <dir>/main.go and commits. It stages
// in a tmp dir so a failed validate never leaves a half-written file. Returns
// (0, nil) on success; on failure an HTTP status (422 for a validation error,
// 500 for IO) plus the error to surface.
func (s *Server) writeValidatedCode(ctx context.Context, slug, dir, viewerTenant string, expectedVersion int, body, dagBytes []byte) (int, error) {
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
	owner, status, err := s.workflowOwnerForEdit(ctx, slug, viewerTenant)
	if err != nil {
		return status, err
	}

	// Atomic rename: the destination already exists, so write to a sibling
	// temp + rename over it.
	dest := filepath.Join(dir, "main.go")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("mkdir dest: %w", err)
	}
	// Keep the current source so a failed rebuild can be rolled back rather
	// than leaving the tree describing code that is not what runs.
	prev, _, prevTruncated := readFirstAvailableBounded(dir, maxFlowSourceBytes, "main.go")
	if prevTruncated {
		return http.StatusConflict, errors.New("existing workflow source exceeds the dashboard projection limit; rebuild before editing")
	}
	_, prevErr := os.Stat(dest)
	hadPrev := prevErr == nil
	restore := func() error {
		if hadPrev {
			stagePath, err := stageFile(dir, prev)
			if err != nil {
				return fmt.Errorf("stage previous source: %w", err)
			}
			if err := os.Rename(stagePath, dest); err != nil {
				_ = os.Remove(stagePath)
				return fmt.Errorf("restore previous source: %w", err)
			}
			return nil
		}
		if err := os.Remove(dest); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove uncommitted source: %w", err)
		}
		return nil
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
		if restoreErr := restore(); restoreErr != nil {
			if s.Log != nil {
				s.Log.Error("editor: rollback after missing rebuild capability failed", "slug", slug, "err", restoreErr)
			}
			return http.StatusInternalServerError, fmt.Errorf("rebuild unavailable and source rollback failed: %w", restoreErr)
		}
		return http.StatusServiceUnavailable, errors.New("this build cannot recompile workflows, so the save would not change what runs; use the reactor CLI on a host with the Go toolchain")
	}
	if _, err := s.registerWorkflowEdit(ctx, slug, dir, owner, expectedVersion); err != nil {
		if restoreErr := restore(); restoreErr != nil {
			return http.StatusInternalServerError, fmt.Errorf("rebuild failed and source rollback failed: %v; original rebuild error: %w", restoreErr, err)
		}
		status := http.StatusUnprocessableEntity
		if errors.Is(err, journal.ErrWorkflowVersionConflict) {
			status = http.StatusConflict
		} else if errors.Is(err, errWorkflowRevisionFenceUnavailable) {
			status = http.StatusServiceUnavailable
		}
		return status, fmt.Errorf("rebuild failed, previous source restored:\n%w", err)
	}
	if err := s.markWorkflowWorkspaceCurrent(ctx, slug, viewerTenant, dir); err != nil && s.Log != nil {
		s.Log.Warn("editor: workflow workspace marker refresh failed", "slug", slug, "err", err)
	}
	// Commit only once the rebuild succeeded, so git records what is actually
	// running rather than a source revision that never compiled into place.
	s.commitOptional(ctx, dir, slug, "edit "+slug+" main.go via dashboard")
	return 0, nil
}

// editTenantScope resolves the tenant selector used by admin dashboard links.
// Members are always pinned to their session tenant; admins may select a
// tenant with ?tenant= when two tenants share a slug.
func editTenantScope(r *http.Request) string {
	if scope := viewerScope(r); scope != "" {
		return scope
	}
	if tenant := strings.TrimSpace(r.URL.Query().Get("tenant")); tenant != "" {
		return tenant
	}
	// Dashboard requests without an authenticated member scope or explicit
	// tenant selector are the single-tenant/default-tenant path. Resolve that
	// owner explicitly before tenant-aware artifact checks; an empty selector
	// would otherwise be rejected as an invalid tenant and make valid legacy
	// dashboard links unusable.
	return journal.DefaultTenant
}

func workflowEditRedirect(r *http.Request, slug string) string {
	path := "/workflows/" + url.PathEscape(slug)
	if viewerScope(r) == "" {
		if tenant := strings.TrimSpace(r.URL.Query().Get("tenant")); tenant != "" {
			path += "?tenant=" + url.QueryEscape(tenant)
		}
	}
	return path
}

// workflowSourceDir returns an editor workspace isolated by workflow id. The
// immutable artifact is the source of truth for newly registered workflows;
// materialising its retained snapshot avoids sharing the legacy
// workflows/<slug> directory when two tenants reuse a slug. Journal-backed
// workflows with only a mutable legacy source, a missing artifact, or a
// missing retained snapshot fail closed. A metadata-only row with no source
// at all may still use a new private workspace so an operator can author its
// first executable version safely.
func (s *Server) workflowSourceDir(ctx context.Context, slug, tenant string) (string, error) {
	root := s.WorkflowsRoot
	if root == "" && s.Registry != nil {
		root = s.Registry.Root
	}
	legacy := filepath.Join(root, slug)
	if s.Journal == nil {
		return legacy, nil
	}
	wfID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, slug, tenant)
	if err != nil {
		return "", err
	}
	workspace := filepath.Join(root, ".editor", wfID)
	version, err := s.Journal.CurrentWorkflowVersionRecordBounded(ctx, wfID, maxFlowDAGBytes)
	if err != nil && !errors.Is(err, journal.ErrNotFound) {
		return "", fmt.Errorf("resolve workflow version: %w", err)
	}
	if err == nil && version.ArtifactSHA256 != "" {
		if version.DAGTruncated {
			return "", fmt.Errorf("%w: workflow DAG is %d bytes and exceeds the bounded dashboard projection", errWorkflowSourceUnavailable, version.DAGBytes)
		}
		registryRoot := root
		if s.Registry != nil {
			registryRoot = s.Registry.Root
		}
		artifact, artifactErr := registry.New(registryRoot).ArtifactPathForTenant(slug, version.ArtifactSHA256, tenant)
		if artifactErr != nil {
			return "", fmt.Errorf("%w: immutable artifact cannot be verified: %v", errWorkflowSourceUnavailable, artifactErr)
		}
		source := filepath.Join(filepath.Dir(artifact), "source")
		sourceHasManifest, sourceManifestErr := registry.VerifySourceManifestIfPresent(source)
		if sourceManifestErr != nil {
			return "", fmt.Errorf("%w: retained source manifest could not be verified", errWorkflowSourceUnavailable)
		}
		if !workflowSourcePresent(source) {
			return "", fmt.Errorf("%w: artifact %s has no retained main.go", errWorkflowSourceUnavailable, version.ArtifactSHA256)
		}
		// Verify the retained source before trusting an already-materialized
		// workspace marker. The artifact may be deleted or tampered with after
		// the previous editor load; the marker alone is not source proof.
		workspaceHasManifest, workspaceManifestErr := registry.VerifySourceManifestIfPresent(workspace)
		workspaceManifestMatches := !sourceHasManifest || (workspaceHasManifest && workspaceManifestErr == nil)
		if workflowWorkspaceMatches(workspace, version.ArtifactSHA256) &&
			workspaceManifestMatches &&
			registry.VerifySourceCodeHash(filepath.Join(workspace, "main.go"), version.CodeHash) == nil &&
			verifyWorkflowDAGSnapshot(workspace, version.DAG) == nil {
			return workspace, nil
		}
		if err := registry.VerifySourceCodeHash(filepath.Join(source, "main.go"), version.CodeHash); err != nil {
			return "", fmt.Errorf("%w: retained source does not match recorded code hash", errWorkflowSourceUnavailable)
		}
		if err := verifyWorkflowDAGSnapshot(source, version.DAG); err != nil {
			return "", fmt.Errorf("%w: retained DAG does not match recorded workflow version", errWorkflowSourceUnavailable)
		}
		if materializeErr := materializeWorkflowSource(source, workspace, version.ArtifactSHA256); materializeErr != nil {
			return "", fmt.Errorf("materialize workflow source: %w", materializeErr)
		}
		return workspace, nil
	}
	// Never reuse an existing mutable directory once a workflow is journal
	// backed. It predates artifact retention and may belong to another tenant
	// with the same slug. An empty metadata row is still editable, but only in
	// the private workflow-id workspace created above.
	if workflowSourcePresent(workspace) || workflowSourcePresent(legacy) {
		return "", fmt.Errorf("%w: workflow %q has no retained immutable source; rebuild and re-register it", errWorkflowSourceUnavailable, slug)
	}
	return workspace, nil
}

func workflowSourcePresent(dir string) bool {
	info, err := os.Lstat(filepath.Join(dir, "main.go"))
	return err == nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular()
}

func verifyWorkflowDAGSnapshot(dir string, expected []byte) error {
	path := filepath.Join(dir, "dag.json")
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("workflow DAG is not a regular file")
	}
	got, _, truncated := readFirstAvailableBounded(dir, maxFlowDAGBytes, "dag.json")
	if truncated {
		return errors.New("workflow DAG exceeds the bounded projection")
	}
	if len(got) == 0 {
		return errors.New("workflow DAG is empty")
	}
	return registry.VerifyDAGSnapshot(got, expected)
}

func workflowWorkspaceMatches(workspace, digest string) bool {
	if !workflowSourcePresent(workspace) {
		return false
	}
	marker := filepath.Join(workspace, workflowArtifactMarker)
	info, err := os.Lstat(marker)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false
	}
	raw, err := os.ReadFile(marker)
	return err == nil && strings.TrimSpace(string(raw)) == digest
}

func materializeWorkflowSource(source, workspace, digest string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("retained source is not a directory")
	}
	parent := filepath.Dir(workspace)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".editor-source-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	var totalBytes int64
	err = filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("retained source contains symlink %q", rel)
		}
		dest := filepath.Join(stage, rel)
		if entry.IsDir() {
			return os.MkdirAll(dest, 0o700)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("retained source contains special file %q", rel)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() < 0 || info.Size() > maxWorkflowMaterializedFileBytes {
			return fmt.Errorf("retained source file %q exceeds %d-byte limit", rel, maxWorkflowMaterializedFileBytes)
		}
		if totalBytes > maxWorkflowMaterializedTotalBytes-info.Size() {
			return fmt.Errorf("retained source exceeds %d-byte total limit", maxWorkflowMaterializedTotalBytes)
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxWorkflowMaterializedFileBytes+1))
		_ = file.Close()
		if readErr != nil {
			return readErr
		}
		if int64(len(data)) > maxWorkflowMaterializedFileBytes {
			return fmt.Errorf("retained source file %q exceeds %d-byte limit", rel, maxWorkflowMaterializedFileBytes)
		}
		totalBytes += int64(len(data))
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			return err
		}
		return os.WriteFile(dest, data, 0o600)
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stage, workflowArtifactMarker), []byte(digest+"\n"), 0o600); err != nil {
		return err
	}
	existing, statErr := os.Lstat(workspace)
	if statErr == nil {
		if existing.Mode()&os.ModeSymlink != 0 || !existing.IsDir() {
			return errors.New("editor workspace is not a directory")
		}
		backup, err := os.MkdirTemp(parent, ".editor-source-old-")
		if err != nil {
			return err
		}
		_ = os.RemoveAll(backup)
		if err := os.Rename(workspace, backup); err != nil {
			return err
		}
		if err := os.Rename(stage, workspace); err != nil {
			_ = os.Rename(backup, workspace)
			return err
		}
		return os.RemoveAll(backup)
	}
	if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	return os.Rename(stage, workspace)
}

func (s *Server) markWorkflowWorkspaceCurrent(ctx context.Context, slug, tenant, workspace string) error {
	if s.Journal == nil {
		return nil
	}
	wfID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, slug, tenant)
	if err != nil {
		return err
	}
	version, err := s.Journal.CurrentWorkflowVersionRecordBounded(ctx, wfID, 0)
	if err != nil {
		return err
	}
	if version.ArtifactSHA256 == "" {
		return nil
	}
	return os.WriteFile(filepath.Join(workspace, workflowArtifactMarker), []byte(version.ArtifactSHA256+"\n"), 0o600)
}

// workflowOwnerForEdit resolves the existing workflow before any source or
// DAG mutation. A missing/ambiguous tenant resolution must fail closed rather
// than letting RegisterFromDir create or update a workflow in the default
// tenant. Nil Journal is retained for isolated dashboard handler tests.
func (s *Server) workflowOwnerForEdit(ctx context.Context, slug, tenant string) (string, int, error) {
	if s.Journal == nil {
		return "", 0, nil
	}
	wfID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, slug, tenant)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			return "", http.StatusNotFound, errors.New("workflow not registered")
		}
		return "", http.StatusInternalServerError, fmt.Errorf("resolve workflow: %w", err)
	}
	owner, err := s.Journal.WorkflowTenant(ctx, wfID)
	if err != nil {
		return "", http.StatusInternalServerError, fmt.Errorf("resolve workflow tenant: %w", err)
	}
	return owner, 0, nil
}

// workflowEditVersion captures the immutable baseline before the editor
// materialises its source workspace. Reading this first means any concurrent
// MCP/CLI revision that lands before workflowSourceDir is observed by the
// expected-version CAS instead of being silently overwritten from stale bytes.
func (s *Server) workflowEditVersion(ctx context.Context, r *http.Request, slug, tenant string) (int, error) {
	if s.Journal == nil {
		return 0, nil
	}
	wfID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, slug, tenant)
	if err != nil {
		return 0, err
	}
	version, err := s.Journal.CurrentWorkflowVersionRecordBounded(ctx, wfID, 0)
	if err != nil {
		return 0, fmt.Errorf("resolve workflow version: %w", err)
	}
	if version.Version < 1 {
		return 0, fmt.Errorf("resolve workflow version: invalid current version %d", version.Version)
	}
	if raw := strings.TrimSpace(r.FormValue("expected_version")); raw != "" {
		expected, parseErr := strconv.Atoi(raw)
		if parseErr != nil || expected < 1 {
			return 0, fmt.Errorf("%w: expected_version must be a positive integer", errWorkflowExpectedVersionInvalid)
		}
		return expected, nil
	}
	return version.Version, nil
}

// registerWorkflowEdit routes journal-backed dashboard revisions through the
// optional expected-version surface. An adapter that only implements the
// legacy registrar is rejected for an existing journal row so editor saves
// cannot append over a newer MCP or CLI revision.
func (s *Server) registerWorkflowEdit(ctx context.Context, slug, dir, tenant string, expectedVersion int) (string, error) {
	if expectedVersion > 0 {
		fenced, ok := s.WorkflowRegister.(WorkflowRegistrarWithExpectedVersion)
		if !ok {
			return "", errWorkflowRevisionFenceUnavailable
		}
		return fenced.RegisterFromDirExpected(ctx, slug, dir, tenant, expectedVersion)
	}
	return s.WorkflowRegister.RegisterFromDir(ctx, slug, dir, tenant)
}

// stageFile writes body to a unique sibling temp file in dir, returning its
// path for an atomic rename over the destination. A fixed destination name
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

// workflowSaveDAG replaces dag.json after schema validation and rebuilds the
// immutable executable so the visual flow and the artifact remain aligned.
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

	expectedVersion, err := s.workflowEditVersion(r.Context(), r, slug, editTenantScope(r))
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			http.Error(w, "workflow not registered", http.StatusNotFound)
		} else if errors.Is(err, errWorkflowExpectedVersionInvalid) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			s.errorPage(w, "resolve workflow version", err)
		}
		return
	}
	dir, dirErr := s.workflowSourceDir(r.Context(), slug, editTenantScope(r))
	if dirErr != nil {
		if errors.Is(dirErr, journal.ErrNotFound) {
			http.Error(w, "workflow not registered", http.StatusNotFound)
		} else if errors.Is(dirErr, errWorkflowSourceUnavailable) {
			http.Error(w, "workflow source snapshot unavailable; rebuild and re-register this workflow before editing", http.StatusConflict)
		} else {
			s.errorPage(w, "resolve workflow source", dirErr)
		}
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.errorPage(w, "mkdir dest", err)
		return
	}
	owner, ownerStatus, ownerErr := s.workflowOwnerForEdit(r.Context(), slug, editTenantScope(r))
	if ownerErr != nil {
		if ownerStatus == http.StatusNotFound {
			http.Error(w, ownerErr.Error(), ownerStatus)
		} else {
			s.errorPage(w, "resolve workflow", ownerErr)
		}
		return
	}
	// A registered workflow must be rebuilt against its new DAG. Without this
	// gate the dashboard could display a flow that the immutable executable
	// never implements. Nil Journal is the draft-only handler-test path.
	codeBytes, _, codeTruncated := readFirstAvailableBounded(dir, maxFlowSourceBytes, "main.go", "workflow.go", "source/main.go")
	if s.Journal != nil && codeTruncated {
		http.Error(w, "workflow source exceeds the dashboard projection limit; rebuild before editing this DAG", http.StatusConflict)
		return
	}
	if s.Journal != nil && len(codeBytes) == 0 {
		http.Error(w, "workflow source not bundled; rebuild cannot verify this DAG", http.StatusConflict)
		return
	}
	if s.Journal != nil && s.WorkflowRegister == nil {
		http.Error(w, "this build cannot recompile workflows, so the DAG was not changed", http.StatusServiceUnavailable)
		return
	}
	dest := filepath.Join(dir, "dag.json")
	previous, _, previousTruncated := readFirstAvailableBounded(dir, maxFlowDAGBytes, "dag.json")
	if previousTruncated {
		http.Error(w, "existing workflow DAG exceeds the dashboard projection limit; replace it through a bounded authoring revision", http.StatusConflict)
		return
	}
	_, readErr := os.Stat(dest)
	hadPrevious := readErr == nil
	stagePath, err := stageFile(dir, body)
	if err != nil {
		s.errorPage(w, "write stage", err)
		return
	}
	if err := os.Rename(stagePath, dest); err != nil {
		_ = os.Remove(stagePath)
		s.errorPage(w, "rename", err)
		return
	}
	restore := func() {
		if hadPrevious {
			_ = os.WriteFile(dest, previous, 0o600)
		} else {
			_ = os.Remove(dest)
		}
	}
	if s.Journal != nil {
		if _, err := s.registerWorkflowEdit(r.Context(), slug, dir, owner, expectedVersion); err != nil {
			restore()
			status := http.StatusUnprocessableEntity
			if errors.Is(err, journal.ErrWorkflowVersionConflict) {
				status = http.StatusConflict
			} else if errors.Is(err, errWorkflowRevisionFenceUnavailable) {
				status = http.StatusServiceUnavailable
			}
			http.Error(w, "rebuild failed, previous DAG restored:\n"+err.Error(), status)
			return
		}
		if err := s.markWorkflowWorkspaceCurrent(r.Context(), slug, editTenantScope(r), dir); err != nil && s.Log != nil {
			s.Log.Warn("editor: workflow workspace marker refresh failed", "slug", slug, "err", err)
		}
	}
	s.commitOptional(r.Context(), dir, slug, "edit "+slug+" dag.json via dashboard")
	http.Redirect(w, r, workflowEditRedirect(r, slug), http.StatusSeeOther)
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
		if s.Log != nil {
			s.Log.Warn("editor: git commit failed", "slug", slug, "err", err)
		}
	}
}
