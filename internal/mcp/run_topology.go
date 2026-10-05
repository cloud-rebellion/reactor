package mcp

import (
	"context"
	"errors"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

const maxRunTopologyMismatches = 16

// runTopologyExecutionView compares the visible chronological prefix of one
// run with the exact DAG version pinned when it was dispatched. This is a
// separate observation from flow_verification, which proves retained source
// identity and lexical calls, not the path taken by a run.
func (s *Server) runTopologyExecutionView(ctx context.Context, info journal.RunInfo, steps []journal.StepRow, hasMore bool, offset int) map[string]any {
	view := map[string]any{
		"status":                   "unavailable",
		"behavior_verified":        false,
		"branch_coverage_verified": false,
		"note":                     "Step dependency comparison uses journaled starts and successful completions. A clean observed path does not prove branch coverage, data dependencies, or behavior inside steps.",
	}
	if offset != 0 {
		view["reason"] = "request the first chronological step page to compare a run"
		return view
	}
	if info.WorkflowVersion <= 0 || info.WorkflowArtifactSHA256 == "" {
		view["reason"] = "run has no pinned workflow version and artifact"
		return view
	}
	version, err := s.Journal.WorkflowVersionAtBounded(ctx, info.WorkflowID, info.WorkflowVersion, maxMCPWorkflowDAGBytes)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			view["reason"] = "pinned workflow version is unavailable"
		} else {
			view["reason"] = "pinned workflow version could not be read"
		}
		return view
	}
	if version.ArtifactSHA256 != info.WorkflowArtifactSHA256 {
		view["reason"] = "pinned workflow artifact identity differs from the run"
		return view
	}
	if version.DAGTruncated || registry.ValidateDAG(version.DAG) != nil || !workflowDAGHasNodes(version.DAG) {
		view["reason"] = "pinned workflow DAG is too large or invalid"
		return view
	}
	nodes, edges, truncated := flowElementsBounded(version.DAG, maxMCPFlowNodes, maxMCPFlowInputEdges)
	if truncated {
		view["reason"] = "pinned workflow topology exceeds the bounded comparison"
		return view
	}
	view["pinned_version"] = info.WorkflowVersion
	view["timeline_complete"] = !hasMore && terminalRunStatus(info.Status)
	view["status"] = "no_observed_inversion"

	kinds := make(map[string]string, len(nodes))
	for _, node := range nodes {
		id, _ := node["id"].(string)
		kind, _ := node["kind"].(string)
		kinds[id] = kind
	}
	dependencies := make(map[string][]string)
	compared, skipped := 0, 0
	for _, edge := range edges {
		from, _ := edge["from"].(string)
		to, _ := edge["to"].(string)
		if !journaledStepKind(kinds[from]) || !journaledStepKind(kinds[to]) {
			skipped++
			continue
		}
		dependencies[to] = append(dependencies[to], from)
		compared++
	}
	view["compared_edge_count"] = compared
	view["skipped_edge_count"] = skipped
	if compared == 0 {
		view["status"] = "not_applicable"
		view["reason"] = "pinned DAG has no edge between journaled Step or SideEffect nodes"
		return view
	}

	byName := make(map[string][]journal.StepRow, len(steps))
	for _, step := range steps {
		byName[step.StepName] = append(byName[step.StepName], step)
	}
	mismatches := make([]map[string]any, 0)
	mismatchCount, checkedStarts := 0, 0
	incompleteEvidence := hasMore || !terminalRunStatus(info.Status)
	for _, step := range steps {
		predecessors := dependencies[step.StepName]
		if len(predecessors) == 0 {
			continue
		}
		if step.Seq <= 0 || step.StartedAt.IsZero() {
			incompleteEvidence = true // legacy rows cannot establish call order
			continue
		}
		checkedStarts++
		for _, predecessor := range predecessors {
			priorSuccess, uncertain := completedBeforeStart(byName[predecessor], step)
			if priorSuccess {
				continue
			}
			if uncertain {
				incompleteEvidence = true
				continue
			}
			mismatchCount++
			if len(mismatches) < maxRunTopologyMismatches {
				mismatches = append(mismatches, map[string]any{
					"from": predecessor, "to": step.StepName, "to_seq": step.Seq,
					"reason": "dependent step started before a successful predecessor completion",
				})
			}
		}
	}
	view["checked_start_count"] = checkedStarts
	view["mismatch_count"] = mismatchCount
	view["mismatches"] = mismatches
	if mismatchCount > 0 {
		view["status"] = "mismatch"
	} else if incompleteEvidence {
		view["status"] = "incomplete"
		view["reason"] = "run or first timeline page is incomplete, or legacy ordinals/timestamps prevent comparison"
	} else if checkedStarts == 0 {
		view["status"] = "not_observed"
		view["reason"] = "no destination step for a comparable dependency started in this run"
	}
	return view
}

func journaledStepKind(kind string) bool {
	return kind == "step" || kind == "side_effect"
}

func terminalRunStatus(status string) bool {
	switch status {
	case "succeeded", "failed", "failed_dlq", "canceled", "cancelled":
		return true
	default:
		return false
	}
}

func completedBeforeStart(rows []journal.StepRow, dependent journal.StepRow) (success, uncertain bool) {
	for _, row := range rows {
		if row.Seq <= 0 {
			uncertain = true
			continue
		}
		if row.Seq >= dependent.Seq || row.Status != journal.StatusSucceeded {
			continue
		}
		if row.FinishedAt.IsZero() {
			uncertain = true
			continue
		}
		if row.FinishedAt.Before(dependent.StartedAt) {
			return true, false
		}
		if row.FinishedAt.Equal(dependent.StartedAt) {
			// SQLite records millisecond timestamps. Equal values cannot
			// establish which event happened first.
			uncertain = true
		}
	}
	return false, uncertain
}
