package mcp

import (
	"context"
	"errors"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// workflowAuthoringAdmission describes the current journal state relevant to
// reactor_create_workflow. It is deliberately advisory: validation cannot
// reserve a slug or version, and the build path enforces its own transactional
// disabled/version fences when the author submits the request.
func (s *Server) workflowAuthoringAdmission(ctx context.Context, slug string, expectedVersion int, expectedPresent bool) (map[string]any, error) {
	view := map[string]any{
		"point_in_time":   true,
		"existing":        false,
		"ready_to_submit": false,
		"note":            "Validation does not reserve this slug or version. reactor_create_workflow rechecks the disabled state and expected_version at registration; review the current workflow before revising it.",
	}
	id, err := s.Journal.WorkflowIDBySlugInTenant(ctx, slug, s.tenantID(ctx))
	if errors.Is(err, journal.ErrNotFound) {
		if expectedPresent {
			view["status"] = "unexpected_version"
			view["next_action"] = "omit expected_version for a first creation"
			return view, nil
		}
		view["status"] = "new_workflow"
		view["ready_to_submit"] = true
		view["next_action"] = "reactor_create_workflow"
		return view, nil
	}
	if err != nil {
		return nil, err
	}
	wf, err := s.Journal.GetWorkflow(ctx, id)
	if err != nil {
		return nil, err
	}
	view["existing"] = true
	view["enabled"] = wf.Enabled
	view["current_version"] = wf.CurrentVersion
	if wf.Enabled {
		view["status"] = "active_workflow"
		view["next_action"] = "review and disable the workflow before revising it"
	} else if wf.CurrentVersion < 1 {
		view["status"] = "missing_version"
		view["next_action"] = "repair or remove the metadata-only workflow before authoring"
	} else if !expectedPresent {
		// The build path may accept an exact unfenced retry after a transport
		// timeout. This read cannot prove source identity, so never recommend
		// an unfenced revision as if it had been reviewed.
		view["status"] = "review_required"
		view["next_action"] = "reactor_review_workflow, then pass its version as expected_version"
		view["exact_retry_may_succeed"] = true
	} else if expectedVersion != wf.CurrentVersion {
		view["status"] = "stale_version"
		view["next_action"] = "reactor_review_workflow, then validate the proposed revision against its current version"
	} else {
		view["status"] = "revision_ready"
		view["ready_to_submit"] = true
		view["next_action"] = "reactor_create_workflow with the same expected_version"
	}
	return view, nil
}
