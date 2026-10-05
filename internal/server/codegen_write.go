package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/bright-interaction/reactor/internal/codegen"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// generateWorkflow handles POST /generate. Body has a "brief" form
// field; the handler runs the codegen orchestrator, builds the
// resulting binary, registers it in the journal so the dispatcher can
// find it, and redirects to /workflows/{slug}. Synchronous; takes
// 10-60s depending on the model + retry count.
func (s *Server) generateWorkflow(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	brief := strings.TrimSpace(r.PostFormValue("brief"))
	if brief == "" {
		http.Error(w, "brief is required", http.StatusBadRequest)
		return
	}
	tenantID, err := s.generateTenant(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	slug, path, version, err := s.Generator.GenerateFromBrief(ctx, brief)
	if err != nil {
		// Exhausting the bounded model validation loop is an authoring
		// failure: the operator can use the compiler/lint feedback to fix
		// the brief or generated source and retry. Returning 500 here made
		// the prompt bar look like a daemon outage and discarded the only
		// actionable feedback.
		var validationErr *codegen.ValidationError
		if errors.As(err, &validationErr) {
			http.Error(w, validationErr.Error(), http.StatusUnprocessableEntity)
			return
		}
		s.errorPage(w, "generate", err)
		return
	}

	if err := s.autoBuildAndRegister(ctx, slug, path, version, tenantID); err != nil {
		// Workflow code landed on disk + was committed, but the build
		// or register step failed. Surface that on the error page so
		// the operator knows the codegen output is preserved and only
		// the post-step needs follow-up.
		s.errorPage(w, "generate post-step ("+slug+" at "+path+")", err)
		return
	}

	// Admins may own the same slug in several tenants. Preserve the selected
	// tenant on the redirect so the detail page resolves the row we just
	// staged instead of whichever tenant happens to be newest.
	redirect := "/workflows/" + url.PathEscape(slug)
	if tenantID != "" && viewerScope(r) == "" {
		redirect += "?tenant=" + url.QueryEscape(tenantID)
	}
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

// generateTenant resolves and validates the tenant selected by the dashboard
// codegen form. Members are always pinned to their session tenant even if a
// crafted form submits another id. Global admins may choose only a tenant
// visible from the journal; an unknown id fails closed instead of silently
// landing in the default tenant.
func (s *Server) generateTenant(r *http.Request) (string, error) {
	if scope := viewerScope(r); scope != "" {
		return scope, nil
	}
	tenantID := strings.TrimSpace(r.PostFormValue("tenant_id"))
	if tenantID == "" {
		tenantID = journal.DefaultTenant
	}
	if s.Journal == nil {
		return tenantID, nil
	}
	// Resolve the selected id directly for mutation. availableTenants is a
	// rendering helper that intentionally falls back to the default tenant when
	// a list query fails; reusing that fallback here would let an unknown or
	// temporarily unavailable target silently become "default".
	if _, err := s.Journal.GetTenant(r.Context(), tenantID); err != nil {
		if errors.Is(err, journal.ErrTenantNotFound) {
			return "", fmt.Errorf("unknown tenant_id %q", tenantID)
		}
		return "", fmt.Errorf("tenant_id %q is unavailable", tenantID)
	}
	return tenantID, nil
}

// autoBuildAndRegister mirrors `reactor workflow build` + `register`
// without going through the CLI. Run after a successful Generate so
// the operator's redirect lands on a usable detail page. Thin wrapper
// over codegen.BuildAndRegister which carries the canonical pipeline.
func (s *Server) autoBuildAndRegister(ctx context.Context, slug, src, version, tenantID string) error {
	root := s.State
	if root == "" && s.Registry != nil {
		root = s.Registry.Root
	}
	if root == "" {
		return fmt.Errorf("no state dir wired (set Server.State); generated workflow at %s needs a manual `reactor workflow build`", src)
	}
	request := dashboardBuildRequest(root, slug, src, version, tenantID)
	// Revisions are fenced against the version the dashboard observed. The
	// disabled authoring journal path will then reject an active workflow (and
	// any concurrent change) explicitly instead of failing later with a generic
	// missing expected_version error.
	if s.Journal != nil {
		if workflowID, lookupErr := s.Journal.WorkflowIDBySlugInTenant(ctx, slug, tenantID); lookupErr == nil {
			request.ExpectedVersion, lookupErr = s.Journal.CurrentWorkflowVersion(ctx, workflowID)
			if lookupErr != nil {
				return fmt.Errorf("read current workflow version for %s: %w", slug, lookupErr)
			}
		} else if !errors.Is(lookupErr, journal.ErrNotFound) {
			return fmt.Errorf("look up existing workflow %s: %w", slug, lookupErr)
		}
	}
	_, err := codegen.BuildAndRegister(ctx, s.Journal, request)
	return err
}

func dashboardBuildRequest(root, slug, src, version, tenantID string) codegen.BuildAndRegisterRequest {
	return codegen.BuildAndRegisterRequest{
		Slug:         slug,
		SrcDir:       src,
		StateRoot:    root,
		SDKVersion:   version,
		SkipIfExists: true,
		TenantID:     tenantID,
		// Generated source is untrusted authoring input. Keep it disabled until
		// an operator reviews the immutable artifact and explicitly enables it
		// from the workflow detail page.
		StartDisabled: true,
		RetainSource:  true,
	}
}
