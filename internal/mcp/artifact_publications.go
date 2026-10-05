package mcp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bright-interaction/reactor/internal/codegen"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/workflowproof"
)

// registerArtifactPublicationTools exposes a durable request, not filesystem
// access. A separately deployed publisher is the only process that needs a
// writable worker artifact volume. This scope is intentionally independent of
// authoring and dispatch, including for embedded MCP servers.
func (s *Server) registerArtifactPublicationTools() {
	if s.Journal == nil || s.Scopes == nil || !s.Scopes.ArtifactPublication {
		return
	}
	s.tools["reactor_get_artifact_publication"] = toolDef{
		tool: Tool{
			Name:        "reactor_get_artifact_publication",
			Description: "Read the durable status of one exact-version artifact publication request in the active MCP tenant. A published receipt means the publisher verified the worker artifact tree; it does not enable or dispatch the workflow.",
			InputSchema: map[string]any{
				"type": "object", "additionalProperties": false,
				"required":   []string{"publication_id"},
				"properties": map[string]any{"publication_id": map[string]any{"type": "string", "pattern": "^apub_[0-9a-f]{32}$"}},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			if s.ArtifactPublicationAuthorized == nil || !s.ArtifactPublicationAuthorized(ctx) {
				return nil, fmt.Errorf("%w: authenticated administrator required", errInvalidParamsErr)
			}
			var a struct {
				ID string `json:"publication_id"`
			}
			if err := decodeMCPArgs(args, &a); err != nil {
				return nil, err
			}
			if !validMCPPublicationID(a.ID) {
				return nil, fmt.Errorf("%w: valid publication_id is required", errInvalidParamsErr)
			}
			publication, err := s.Journal.GetArtifactPublicationForTenant(ctx, a.ID, s.tenantID(ctx))
			if err != nil {
				return nil, err
			}
			return artifactPublicationMCPView(publication), nil
		},
	}
	if strings.TrimSpace(s.StateRoot) == "" {
		return
	}
	s.tools["reactor_publish_workflow_artifact"] = toolDef{
		tool: Tool{
			Name:        "reactor_publish_workflow_artifact",
			Description: "Request publication of the reviewed current workflow version to distributed worker storage. Requires the exact artifact SHA-256 from review and the separate artifact-publication MCP scope. The queue is durable and tenant-scoped; poll reactor_get_artifact_publication until published, then enable, preflight, and dispatch separately. This does not run the workflow.",
			InputSchema: map[string]any{
				"type": "object", "additionalProperties": false,
				"required": []string{"slug", "version", "expected_artifact_sha256"},
				"properties": map[string]any{
					"slug":                     map[string]any{"type": "string"},
					"version":                  map[string]any{"type": "integer", "minimum": 1},
					"expected_artifact_sha256": map[string]any{"type": "string", "minLength": 64, "maxLength": 64},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			if s.ArtifactPublicationAuthorized == nil || !s.ArtifactPublicationAuthorized(ctx) {
				return nil, fmt.Errorf("%w: authenticated administrator required", errInvalidParamsErr)
			}
			var a struct {
				Slug                   string `json:"slug"`
				Version                int    `json:"version"`
				ExpectedArtifactSHA256 string `json:"expected_artifact_sha256"`
			}
			if err := decodeMCPArgs(args, &a); err != nil {
				return nil, err
			}
			version, present, err := optionalMCPPositiveInt(args, "version")
			if err != nil {
				return nil, err
			}
			if !present || version > int64(^uint(0)>>1) || !codegen.IsValidSlug(a.Slug) || !validMCPArtifactDigest(a.ExpectedArtifactSHA256) {
				return nil, fmt.Errorf("%w: valid slug, positive version, and lowercase expected_artifact_sha256 are required", errInvalidParamsErr)
			}
			a.Version = int(version)
			tenantID := s.tenantID(ctx)
			workflowID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, a.Slug, tenantID)
			if err != nil {
				return nil, err
			}
			workflow, err := s.Journal.GetWorkflow(ctx, workflowID)
			if err != nil {
				return nil, err
			}
			if workflow.CurrentVersion != a.Version {
				return nil, fmt.Errorf("%w: workflow version changed; review the current version again", errInvalidParamsErr)
			}
			pinned, err := s.Journal.WorkflowVersionAtBounded(ctx, workflowID, a.Version, maxMCPWorkflowDAGBytes)
			if err != nil {
				return nil, err
			}
			if pinned.DAGTruncated || pinned.WorkflowID != workflowID || pinned.Version != a.Version || pinned.ArtifactSHA256 != a.ExpectedArtifactSHA256 {
				return nil, fmt.Errorf("%w: exact reviewed artifact does not match the current workflow version", errInvalidParamsErr)
			}
			if pinned.SourceProofVersion != 2 || workflowproof.CheckVersionForTenant(s.StateRoot, a.Slug, tenantID, pinned).Status != "verified" {
				return nil, fmt.Errorf("%w: exact version does not have verified source, artifact, and visual DAG proof", errInvalidParamsErr)
			}
			publication, err := s.Journal.EnqueueArtifactPublication(ctx, tenantID, workflowID, a.Version, a.ExpectedArtifactSHA256)
			if err != nil {
				return nil, err
			}
			return artifactPublicationMCPView(publication), nil
		},
	}
	s.tools["reactor_requeue_artifact_publication"] = toolDef{
		tool: Tool{
			Name:        "reactor_requeue_artifact_publication",
			Description: "After an operator fixes the cause of a terminal failed publication, reopen that exact tenant-owned current-version request. Repeat the publication ID exactly and supply its pinned artifact SHA-256. Requires authenticated admin and the artifact-publication scope; it does not copy, enable, or dispatch by itself.",
			InputSchema: map[string]any{
				"type": "object", "additionalProperties": false,
				"required": []string{"publication_id", "confirm_publication_id", "expected_artifact_sha256"},
				"properties": map[string]any{
					"publication_id":           map[string]any{"type": "string", "pattern": "^apub_[0-9a-f]{32}$"},
					"confirm_publication_id":   map[string]any{"type": "string", "pattern": "^apub_[0-9a-f]{32}$"},
					"expected_artifact_sha256": map[string]any{"type": "string", "minLength": 64, "maxLength": 64},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			if s.ArtifactPublicationAuthorized == nil || !s.ArtifactPublicationAuthorized(ctx) {
				return nil, fmt.Errorf("%w: authenticated administrator required", errInvalidParamsErr)
			}
			var a struct {
				ID                     string `json:"publication_id"`
				ConfirmID              string `json:"confirm_publication_id"`
				ExpectedArtifactSHA256 string `json:"expected_artifact_sha256"`
			}
			if err := decodeMCPArgs(args, &a); err != nil {
				return nil, err
			}
			if !validMCPPublicationID(a.ID) || a.ID != a.ConfirmID || !validMCPArtifactDigest(a.ExpectedArtifactSHA256) {
				return nil, fmt.Errorf("%w: exact confirm_publication_id and lowercase expected_artifact_sha256 are required", errInvalidParamsErr)
			}
			publication, err := s.Journal.RequeueFailedArtifactPublication(ctx, s.tenantID(ctx), a.ID, a.ExpectedArtifactSHA256)
			if err != nil {
				return nil, err
			}
			view := artifactPublicationMCPView(publication)
			view["requeued"] = true
			return view, nil
		},
	}
}

func validMCPArtifactDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validMCPPublicationID(value string) bool {
	if !strings.HasPrefix(value, "apub_") || len(value) != len("apub_")+32 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "apub_"))
	return err == nil && strings.ToLower(value) == value
}

func artifactPublicationMCPView(p journal.ArtifactPublication) map[string]any {
	view := map[string]any{
		"publication_id":    p.ID,
		"workflow_id":       p.WorkflowID,
		"slug":              p.Slug,
		"version":           p.Version,
		"artifact_sha256":   p.ArtifactSHA256,
		"status":            p.Status,
		"attempts":          p.Attempts,
		"requested_at":      p.RequestedAt,
		"enabled_unchanged": true,
		"dispatch_started":  false,
	}
	if p.PublishedAt != nil {
		view["published_at"] = *p.PublishedAt
	}
	if !p.NextAttemptAt.IsZero() && p.Status == journal.ArtifactPublicationPending {
		view["next_attempt_at"] = p.NextAttemptAt
	}
	if p.LastFailureCode != "" {
		view["last_failure_code"] = p.LastFailureCode
	}
	return view
}
