package server

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/dispatcher"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// dlqRetry handles POST /dlq/{id}/retry. Drives the dispatcher's
// retry pipeline + redirects back to the run detail page so the
// operator sees the new terminal status.
func (s *Server) dlqRetry(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	status, err := s.DLQRetry.RetryDeadLetter(r.Context(), id)
	if err != nil {
		// A refused retry is not a server fault. Funnelling these into
		// errorPage rendered "Something went wrong" with a 500 and put the real
		// reason in the daemon log only, so an operator could not tell "enable
		// the workflow" from "the daemon is broken". Map each expected refusal
		// to its own status and say what to do about it.
		//
		// Importing dispatcher for the sentinels is the same thing
		// internal/runtime/webhook already does for ErrRateLimited/ErrCapacity;
		// dispatcher does not import server (that is why Counters is declared
		// as a local interface there), so there is no cycle.
		if msg, code, ok := dlqRefusal(err); ok {
			http.Error(w, msg, code)
			return
		}
		s.errorPage(w, "dlq retry ("+id+", status="+status+")", err)
		return
	}
	// Bounce back to the run detail page; the operator can read the
	// new status + timeline at a glance.
	item, gerr := s.Journal.GetDeadLetterItem(r.Context(), id)
	if gerr != nil {
		// On success the dlq row is deleted; the redirect would 404. Land
		// on /runs instead so the operator at least sees the run list.
		http.Redirect(w, r, "/runs", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/runs/"+item.RunID, http.StatusSeeOther)
}

// knowledgeNewForm renders the form for adding a new corpus entry.
func (s *Server) knowledgeNewForm(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, r, page{
		Title:   "New knowledge entry",
		Heading: "New knowledge entry",
		Body:    template.HTML(knowledgeNewBody("")),
	})
}

// knowledgeCreate handles POST /knowledge.
func (s *Server) knowledgeCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	topic := strings.TrimSpace(r.PostFormValue("topic"))
	title := strings.TrimSpace(r.PostFormValue("title"))
	body := r.PostFormValue("body")
	tags := splitTags(r.PostFormValue("tags"))

	if topic == "" || title == "" || body == "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderPage(w, r, page{
			Title:   "New knowledge entry",
			Heading: "New knowledge entry",
			Body:    template.HTML(knowledgeNewBody("topic, title, and body are required")),
		})
		return
	}

	id, err := s.KnowledgeWrite.AddEntry(r.Context(), topic, title, body, "operator", tags)
	if err != nil {
		s.errorPage(w, "knowledge add", err)
		return
	}
	http.Redirect(w, r, "/knowledge/"+id, http.StatusSeeOther)
}

func (s *Server) knowledgePromote(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.KnowledgeWrite.PromoteEntry(r.Context(), id); err != nil {
		s.errorPage(w, "knowledge promote", err)
		return
	}
	http.Redirect(w, r, "/knowledge/"+id, http.StatusSeeOther)
}

func (s *Server) knowledgeStale(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.KnowledgeWrite.StaleEntry(r.Context(), id); err != nil {
		s.errorPage(w, "knowledge stale", err)
		return
	}
	http.Redirect(w, r, "/knowledge/"+id, http.StatusSeeOther)
}

func (s *Server) knowledgeSupersede(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	newID := strings.TrimSpace(r.PostFormValue("superseded_by"))
	if newID == "" {
		http.Error(w, "superseded_by required", http.StatusBadRequest)
		return
	}
	if err := s.KnowledgeWrite.SupersedeEntry(r.Context(), id, newID); err != nil {
		s.errorPage(w, "knowledge supersede", err)
		return
	}
	http.Redirect(w, r, "/knowledge/"+id, http.StatusSeeOther)
}

// workflowNewForm renders the upload-workflow form. Accepts a .tar.gz
// of a single directory containing main.go and, when it uses durable Reactor
// nodes, a matching visual dag.json.
func (s *Server) workflowNewForm(w http.ResponseWriter, r *http.Request) {
	tenants, current := s.availableTenants(r)
	s.renderPage(w, r, page{
		Title:   "Register workflow",
		Heading: "Register workflow",
		Body:    template.HTML(workflowNewBody("", tenants, current)),
	})
}

// workflowCreate handles POST /workflows. Multipart body with a "slug"
// text field + a "tarball" file. Extracts to a tempdir, runs the same
// validator chain the editor save uses, hands off to the registrar.
func (s *Server) workflowCreate(w http.ResponseWriter, r *http.Request) {
	const maxUpload = 8 << 20 // 8 MiB; a workflow + deps should comfortably fit
	if err := r.ParseMultipartForm(maxUpload); err != nil {
		http.Error(w, "invalid multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}
	slug := strings.TrimSpace(r.PostFormValue("slug"))
	if !slugRe.MatchString(slug) {
		s.workflowNewError(w, r, "slug must match ^[a-z][a-z0-9-]*$")
		return
	}

	file, _, err := r.FormFile("tarball")
	if err != nil {
		s.workflowNewError(w, r, "tarball file required ("+err.Error()+")")
		return
	}
	defer file.Close()

	tmp, err := os.MkdirTemp("", "reactor-upload-")
	if err != nil {
		s.errorPage(w, "tmp dir", err)
		return
	}
	defer os.RemoveAll(tmp)

	if err := extractTarGz(file, tmp); err != nil {
		s.workflowNewError(w, r, "extract: "+err.Error())
		return
	}

	src, err := findWorkflowDir(tmp)
	if err != nil {
		s.workflowNewError(w, r, err.Error())
		return
	}

	// A SCOPED viewer (a member) is forced into their own tenant whatever the
	// form submits, so a crafted POST cannot plant a workflow in someone else's
	// tenant; only a global admin may choose.
	tenantID := strings.TrimSpace(r.PostFormValue("tenant_id"))
	if scope := viewerScope(r); scope != "" {
		tenantID = scope
	}
	id, err := s.WorkflowRegister.RegisterFromDir(r.Context(), slug, src, tenantID)
	if err != nil {
		s.errorPage(w, "register from dir ("+slug+", id="+id+")", err)
		return
	}
	http.Redirect(w, r, "/workflows/"+slug, http.StatusSeeOther)
}

func (s *Server) workflowNewError(w http.ResponseWriter, r *http.Request, msg string) {
	tenants, current := s.availableTenants(r)
	w.WriteHeader(http.StatusUnprocessableEntity)
	render(w, layout, page{
		Title:   "Register workflow",
		Heading: "Register workflow",
		Body:    template.HTML(workflowNewBody(msg, tenants, current)),
	})
}

// globalAudit handles GET /audit and renders an aggregated view of
// credential_audit entries across every credential, newest first.
func (s *Server) globalAudit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creds, err := s.Credentials.List(ctx)
	if err != nil {
		s.errorPage(w, "list credentials", err)
		return
	}
	type row struct {
		CredentialID string
		Name         string
		Entry        credentials.AuditEntry
	}
	var rows []row
	for _, c := range creds {
		entries, err := s.Credentials.ListAudit(ctx, c.ID, 50)
		if err != nil {
			continue
		}
		for _, e := range entries {
			rows = append(rows, row{CredentialID: c.ID, Name: c.Name, Entry: e})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Entry.At.After(rows[j].Entry.At)
	})
	if len(rows) > 500 {
		rows = rows[:500]
	}

	var b strings.Builder
	b.WriteString(`<p class="muted">Aggregated credential audit log across every credential, newest first. Capped at 500 rows.</p>`)
	if len(rows) == 0 {
		b.WriteString(`<p class="empty">No audit entries yet.</p>`)
	} else {
		b.WriteString(`<table><thead><tr><th>At</th><th>Credential</th><th>Action</th><th>Actor</th><th>Workflow</th><th>Detail</th></tr></thead><tbody>`)
		for _, r := range rows {
			actor := r.Entry.ActorKind
			if r.Entry.ActorID != "" {
				actor += ":" + r.Entry.ActorID
			}
			fmt.Fprintf(&b, `<tr><td class="muted">%s</td><td><a href="/credentials/%s">%s</a></td><td><code>%s</code></td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>`,
				formatTime(r.Entry.At),
				template.URLQueryEscaper(r.CredentialID),
				template.HTMLEscapeString(r.Name),
				template.HTMLEscapeString(r.Entry.Action),
				template.HTMLEscapeString(actor),
				template.HTMLEscapeString(r.Entry.WorkflowID),
				template.HTMLEscapeString(truncate(string(r.Entry.Detail), 120)),
			)
		}
		b.WriteString(`</tbody></table>`)
	}
	s.renderPage(w, r, page{
		Title:   "Audit log",
		Heading: "Audit log",
		Body:    template.HTML(b.String()),
	})
}

// knowledgeNewBody renders the add-knowledge-entry form. errMsg is
// shown above the fields when non-empty.
func knowledgeNewBody(errMsg string) string {
	var b strings.Builder
	if errMsg != "" {
		b.WriteString(`<div class="err">` + template.HTMLEscapeString(errMsg) + `</div>`)
	}
	b.WriteString(`<form method="POST" action="/knowledge" class="form">
  <p class="muted">Adds a new entry to the knowledge corpus. Frontmatter is auto-generated; you only fill in the body. The codegen lens will surface this entry in future workflow generations whenever it matches a brief by full-text search.</p>
  <label>Topic <input type="text" name="topic" required placeholder="e.g. patterns, post-mortems, sdk-tips" autocomplete="off"></label>
  <label>Title <input type="text" name="title" required placeholder="e.g. Idempotency keys must hash the payload" autocomplete="off"></label>
  <label>Tags (comma-separated) <input type="text" name="tags" placeholder="optional, e.g. retry, supervisor" autocomplete="off"></label>
  <label>Body
    <textarea name="body" rows="14" required placeholder="Markdown body. Anything sensitive (api keys, emails, passwords) is rejected on submit by the redactor."></textarea>
  </label>
  <button type="submit" class="btn-primary">Create</button>
  <a href="/knowledge" class="btn-secondary">Cancel</a>
</form>`)
	return b.String()
}

// workflowNewBody renders the workflow-upload form.
func workflowNewBody(errMsg string, tenants []journal.Tenant, currentTenant string) string {
	var b strings.Builder
	if errMsg != "" {
		b.WriteString(`<div class="err">` + template.HTMLEscapeString(errMsg) + `</div>`)
	}
	b.WriteString(`<form method="POST" action="/workflows" enctype="multipart/form-data" class="form">
  <p class="muted">Upload a tar.gz containing a single directory with main.go (required) and a matching visual dag.json whenever the source uses durable Reactor nodes. The server extracts, runs go vet + reactor lint + go build, then registers the workflow + builds the binary. Use this when you have Go source on disk and don't want the AI codegen path; for non-devs, the home page Generate form is faster.</p>
  <label>Slug <input type="text" name="slug" required pattern="[a-z][a-z0-9-]*" title="lowercase letters/digits/hyphen, must start with a letter" autocomplete="off"></label>
  <label>Tarball <input type="file" name="tarball" required accept=".tgz,.tar.gz,application/gzip,application/x-gzip,application/x-tar"></label>` +
		tenantSelect(tenants, currentTenant) + `
  <button type="submit" class="btn-primary">Register</button>
  <a href="/" class="btn-secondary">Cancel</a>
</form>`)
	return b.String()
}

// maxExtractedBytes caps the total bytes extractTarGz will write to
// disk regardless of how compressible the input is. A few KB of
// gzip-of-zeros can expand to gigabytes otherwise (zip-bomb shape);
// pin it at 64 MiB so a legitimate workflow + deps fits but the
// daemon's tmp dir cannot be exhausted from one upload.
const maxExtractedBytes int64 = 64 << 20

// extractTarGz reads a gzipped tar from src and writes its contents
// into dest. Defends against path traversal (each entry is resolved
// against dest via filepath.Rel and rejected if it escapes), symlink
// shenanigans (only regular files + dirs), and decompression bombs
// (a per-extract total cap via io.LimitReader).
func extractTarGz(src io.Reader, dest string) error {
	gz, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	limited := &io.LimitedReader{R: gz, N: maxExtractedBytes + 1}
	tr := tar.NewReader(limited)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		// Resolve the entry under dest. filepath.Rel after a Clean+Join
		// catches `..` segments, absolute paths, percent-encoded
		// variants, and Windows-style drive prefixes.
		target := filepath.Join(dest, filepath.Clean(hdr.Name))
		rel, err := filepath.Rel(dest, target)
		if err != nil || strings.HasPrefix(rel, "..") || rel == ".." {
			return fmt.Errorf("tar: path traversal blocked: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			// O_EXCL + O_NOFOLLOW: refuse to write over a pre-existing
			// entry (rules out a same-archive symlink-then-overwrite
			// trick) and refuse to traverse symlinks even if one
			// somehow landed in the destination.
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		default:
			// Skip symlinks, hardlinks, devices, fifos. Workflow
			// uploads are pure source so anything weird is suspect.
			continue
		}
		if limited.N <= 0 {
			return fmt.Errorf("tar: extracted bytes exceed cap (%d MiB)", maxExtractedBytes>>20)
		}
	}
}

// findWorkflowDir picks the directory under root that contains main.go.
// Returns the deepest match so wrappers like "myworkflow/main.go" or
// "myworkflow/cmd/main.go" both work.
func findWorkflowDir(root string) (string, error) {
	var match string
	err := filepath.WalkDir(root, func(path string, _d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if filepath.Base(path) == "main.go" {
			if match != "" {
				return errors.New("multiple main.go files; tarball must contain exactly one workflow")
			}
			match = filepath.Dir(path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if match == "" {
		return "", errors.New("no main.go found in tarball; the workflow source must live at the top level of an embedded directory")
	}
	return match, nil
}

// splitTags parses a comma-separated tag list into a slice, trimming
// whitespace and dropping empties.
func splitTags(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// dlqRefusal maps an EXPECTED dead-letter retry refusal to an operator-facing
// message and status. Returns ok=false for anything else, which stays a 500 so
// a genuine fault is never dressed up as a policy decision.
func dlqRefusal(err error) (msg string, code int, ok bool) {
	var qe *journal.QuotaError
	switch {
	case errors.Is(err, dispatcher.ErrWorkflowDisabled):
		return "this workflow is disabled, so the retry was refused; enable it on the workflow page and retry again", http.StatusConflict, true
	case errors.Is(err, dispatcher.ErrRetryInFlight):
		return "this run is already executing (another retry claimed it) or was cancelled; reload the run page to see its current state", http.StatusConflict, true
	case errors.Is(err, dispatcher.ErrCapacity):
		return "the daemon is at capacity, so no new run was started; retry when in-flight runs have drained", http.StatusTooManyRequests, true
	case errors.Is(err, dispatcher.ErrRateLimited):
		return "this workflow is over its per-minute rate limit; retry shortly, or raise the limit on the workflow page", http.StatusTooManyRequests, true
	case errors.As(err, &qe):
		return "tenant quota reached, so the retry was refused: " + qe.Reason, http.StatusTooManyRequests, true
	}
	return "", 0, false
}
