package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/workflowproof"
)

// workflowDispatchPreflight is a point-in-time admission receipt. It reports
// the same durable gates that the dispatcher checks without creating a run.
// Capacity, shutdown, and races after this read remain deliberately marked as
// dynamic: a true receipt is useful guidance, never an execution guarantee.
func (s *Server) workflowDispatchPreflight(ctx context.Context, slug string) (map[string]any, error) {
	slug = strings.TrimSpace(slug)
	id, err := s.Journal.WorkflowIDBySlugInTenant(ctx, slug, s.tenantID(ctx))
	if err != nil {
		return nil, err
	}
	wf, err := s.Journal.GetWorkflow(ctx, id)
	if err != nil {
		return nil, err
	}
	enabled, err := s.Journal.IsWorkflowEnabled(ctx, id)
	if err != nil {
		return nil, err
	}
	dag, dagBytes, dagTruncated, version, artifactSHA256, codeHash, sourceManifestSHA256, sourceProofVersion, artifactStatus, versionSource, err := s.workflowFlowSnapshot(ctx, id, slug)
	if err != nil {
		return nil, err
	}
	sourceDAG := s.validateRetainedSourceDAGForTenant(ctx, slug, artifactSHA256, codeHash, sourceManifestSHA256, sourceProofVersion, dag)
	// Metadata-only workflows have no executable source to prove this graph
	// against. The flow view reports them unverified; preflight must not give
	// an AI client a conflicting flow_valid=true signal.
	flowValid := artifactSHA256 != ""
	executionFlowValid := true
	flowError := ""
	visualComplete := sourceDAGVisualComplete(sourceDAG.Status)
	flowTruncated := false
	trimmedDAG := strings.TrimSpace(string(dag))
	if trimmedDAG != "" && trimmedDAG != "{}" {
		if validateErr := registry.ValidateDAG(dag); validateErr != nil {
			flowValid = false
			executionFlowValid = false
			flowError = validateErr.Error()
		} else if visualDAGTruncated(dag) {
			flowValid = false
			executionFlowValid = false
			visualComplete = false
			flowTruncated = true
			flowError = "visual DAG exceeds the bounded MCP flow projection; split the workflow before enabling"
		}
	}
	if !workflowDAGHasNodes(dag) {
		flowValid = false
		executionFlowValid = false
		visualComplete = false
		flowError = missingVisualNodesReason
	}
	// Executable source integrity is distinct from inner-step visual fidelity.
	// A published legacy artifact with only an unverified visual annotation may
	// keep running, but no review surface may claim its block graph is proven.
	// Missing manifests, source, or a durable-node mismatch still fail closed.
	if artifactSHA256 != "" && !sourceDAGVisualComplete(sourceDAG.Status) {
		flowValid = false
		visualComplete = false
		if sourceDAG.Status != "visual_unverified" && sourceDAG.Status != "legacy_manifest_unpinned" {
			executionFlowValid = false
		}
		flowError = sourceDAG.Error
		if flowError == "" {
			flowError = "retained workflow source and visual DAG are not verified"
		}
	}
	if dagTruncated {
		flowValid = false
		executionFlowValid = false
		visualComplete = false
		flowTruncated = true
		flowError = fmt.Sprintf("workflow DAG exceeds the bounded MCP projection (%d bytes); rebuild or split the workflow before enabling", dagBytes)
	}
	// The Kubernetes daemon can have an intact authoring artifact while the
	// read-only tree mounted by its workers still lacks this exact version.
	// Check the same tenant/version/source proof on that tree before an MCP
	// client is told that a new run can be dispatched.
	pinned := journal.WorkflowVersion{
		WorkflowID: wf.ID, Version: version, ArtifactSHA256: artifactSHA256,
		CodeHash: codeHash, DAG: dag, SourceManifestSHA256: sourceManifestSHA256,
		SourceProofVersion: sourceProofVersion,
	}
	workerArtifactReady, workerArtifactStatus, workerArtifactReason := s.workerArtifactProof(slug, wf.TenantID, pinned)
	dependencies := s.workflowDependencyReadiness(ctx, slug, wf.ID, artifactSHA256, sourceManifestSHA256, sourceDAG.Status)

	quotaStatus := "allowed"
	quotaReason := ""
	if quotaErr := s.Journal.CheckWorkflowEnqueueAllowed(ctx, id); quotaErr != nil {
		var rejected *journal.QuotaError
		if errors.As(quotaErr, &rejected) {
			quotaStatus = "blocked"
			quotaReason = rejected.Reason
		} else {
			quotaStatus = "unknown"
			quotaReason = "quota check unavailable"
		}
	}
	rateStatus := "allowed"
	rateLimit := 0
	allowed, limit, rateErr := s.Journal.CheckWorkflowRateLimit(ctx, id)
	rateLimit = limit
	if rateErr != nil {
		rateStatus = "unknown"
	} else {
		if !allowed {
			rateStatus = "blocked"
		}
	}

	dispatcherConfigured := s.Dispatch != nil && s.writeEnabled(s.Scopes == nil || s.Scopes.Dispatch)
	sourceProofExecutable := sourceDAG.Status == "verified" || sourceDAG.Status == "visual_unverified" || sourceDAG.Status == "legacy_manifest_unpinned"
	durableReady := enabled && version > 0 && artifactStatus == "verified" && executionFlowValid && sourceProofExecutable && workerArtifactReady && dispatcherConfigured
	admissionStatus := "allowed"
	if dependencies.blocked() || quotaStatus == "blocked" || rateStatus == "blocked" {
		admissionStatus = "blocked"
	} else if dependencies.checkFailed || quotaStatus == "unknown" || rateStatus == "unknown" {
		admissionStatus = "unknown"
	}
	dispatchableNow := durableReady && admissionStatus == "allowed"
	reason := "ready for a point-in-time dispatch attempt"
	switch {
	case !dispatcherConfigured:
		reason = "dispatch surface is not configured or the dispatch scope is disabled"
	case !enabled:
		reason = "workflow is disabled"
	case version == 0 || artifactSHA256 == "":
		reason = "workflow has no immutable executable artifact"
	case artifactStatus != "verified":
		reason = "immutable artifact is not verified on this daemon"
	case !workerArtifactReady:
		reason = "immutable artifact and retained source are not verified on the Kubernetes worker artifact mount"
	case !executionFlowValid || !sourceProofExecutable:
		reason = flowError
	case dependencies.blocked():
		reason = "required workflow credential grant or connection is missing"
	case dependencies.checkFailed:
		reason = "workflow credential or connection readiness could not be checked"
	case admissionStatus == "blocked":
		reason = "tenant quota or workflow rate limit blocks admission"
	case admissionStatus == "unknown":
		reason = "quota or rate-limit admission could not be checked"
	}

	result := map[string]any{
		"slug": slug, "workflow_id": wf.ID, "tenant_id": wf.TenantID,
		"enabled": enabled, "version": version, "artifact_sha256": artifactSHA256,
		"artifact_status": artifactStatus, "version_source": versionSource,
		"dispatcher_configured": dispatcherConfigured,
		"flow_valid":            flowValid, "quota_status": quotaStatus,
		"execution_integrity_valid": executionFlowValid && sourceProofExecutable,
		"rate_limit_status":         rateStatus, "rate_limit_per_min": rateLimit,
		"source_dag_status": sourceDAG.Status, "visual_complete": visualComplete, "flow_truncated": flowTruncated,
		"legacy_visual_compat": sourceDAG.Status == "visual_unverified" || sourceDAG.Status == "legacy_manifest_unpinned",
		"admission_status":     admissionStatus, "durable_ready": durableReady,
		"dispatchable_now": dispatchableNow, "reason": reason,
		"dynamic_gates": []string{"capacity", "shutdown", "concurrent changes"},
		"point_in_time": true,
		"dependencies":  dependencies.view(),
	}
	result["dag_bytes"] = dagBytes
	result["dag_truncated"] = dagTruncated
	if quotaReason != "" {
		result["quota_reason"] = quotaReason
	}
	if flowError != "" {
		result["flow_error"] = flowError
	}
	if sourceDAG.Error != "" {
		result["source_dag_error"] = sourceDAG.Error
	}
	if s.WorkerArtifactRoot != "" {
		result["worker_artifact_ready"] = workerArtifactReady
		result["worker_artifact_status"] = workerArtifactStatus
		if !workerArtifactReady {
			result["worker_artifact_reason"] = workerArtifactReason
		}
	}
	// Keep executable-flow verification distinct from the data trust label used
	// by visual/review projections. The DAG and retained source remain
	// untrusted content for an AI to inspect, while this receipt records that the
	// daemon verified their relationship before admitting a live run.
	flowVerification := "unverified"
	flowVerificationReason := flowError
	if flowValid && visualComplete && sourceDAG.Status == "verified" {
		flowVerification = "verified"
	} else if flowVerificationReason == "" {
		if sourceDAG.Error != "" {
			flowVerificationReason = sourceDAG.Error
		} else {
			flowVerificationReason = "retained source and visual DAG proof is not verified"
		}
	}
	result["flow_verification"] = flowVerification
	result["flow_verification_reason"] = flowVerificationReason
	result["flow_data_trust"] = "untrusted"
	flowNodes, flowEdges, flowProjectionTruncated := flowElementsBounded(dag, maxMCPFlowNodes, maxMCPFlowEdges)
	addFlowTopology(result, flowNodes, flowEdges, flowTruncated || dagTruncated || flowProjectionTruncated, dag)
	return result, nil
}

// workerArtifactProof is the shared exact-version check for review, activation,
// and preflight. A local/single-node daemon has no separate worker tree; when
// one is configured, an unavailable or mismatched copy must close activation
// before triggers can begin sending work to workers.
func (s *Server) workerArtifactProof(slug, tenantID string, version journal.WorkflowVersion) (ready bool, status, reason string) {
	if s.WorkerArtifactRoot == "" {
		return true, "", ""
	}
	proof := workflowproof.CheckVersionForTenant(s.WorkerArtifactRoot, slug, tenantID, version)
	// Legacy-compatible proof may still describe a previously admitted run,
	// but a new review-to-enable decision requires the fully pinned artifact,
	// source, and visual DAG proof used by the dashboard activation path.
	return proof.Status == "verified", proof.Status, safeSourceProofReason(proof)
}
