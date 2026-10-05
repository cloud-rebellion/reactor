package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bright-interaction/reactor/internal/flowblocks"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// registerRunBlockReceiptTools exposes only metadata reported by an observed
// SDK merge, split, iterate, or aggregate. No customer value or error text is stored or read.
func (s *Server) registerRunBlockReceiptTools() {
	if s.Journal == nil {
		return
	}
	s.tools["reactor_list_run_block_receipts"] = toolDef{
		tool: Tool{
			Name:        "reactor_list_run_block_receipts",
			Description: "List bounded, value-free SDK-reported key-join, split, iterate, and aggregate observations for one tenant-owned run. Declared blocks distinguish matching reports, shape mismatches, ID-only presence outside this page, no observation, and kinds without an SDK observer. This does not prove arbitrary Go behavior: workflow code controls its wire messages. The immutable pinned visual declaration is returned only when its artifact identity and bounded DAG are available.",
			InputSchema: map[string]any{
				"type": "object", "required": []string{"run_id"},
				"properties": map[string]any{
					"run_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 512},
					"limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 50},
					"offset": map[string]any{"type": "integer", "minimum": 0, "maximum": 10000, "default": 0},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				RunID  string `json:"run_id"`
				Limit  int    `json:"limit"`
				Offset int    `json:"offset"`
			}
			if err := decodeMCPArgs(args, &a); err != nil {
				return nil, fmt.Errorf("%w: %v", errInvalidParamsErr, err)
			}
			if a.RunID == "" || len(a.RunID) > 512 {
				return nil, fmt.Errorf("%w: run_id must be 1..512 bytes", errInvalidParamsErr)
			}
			if a.Limit == 0 {
				a.Limit = 50
			}
			if a.Limit < 1 || a.Limit > 100 || a.Offset < 0 || a.Offset > 10000 {
				return nil, fmt.Errorf("%w: invalid block receipt page", errInvalidParamsErr)
			}
			tenant := s.tenantID(ctx)
			info, err := s.Journal.GetRunForTenantMetadata(ctx, a.RunID, tenant, 0)
			if err != nil {
				return nil, err
			}
			receipts, more, err := s.Journal.ListBlockReceiptsForTenant(ctx, a.RunID, tenant, a.Limit, a.Offset)
			if err != nil {
				return nil, err
			}
			observed, err := s.Journal.ObservedBlockIdentitiesForTenant(ctx, a.RunID, tenant)
			if err != nil {
				return nil, err
			}
			seen := make(map[[2]string]bool, len(observed))
			for _, item := range observed {
				seen[[2]string{item.StepName, item.BlockID}] = true
			}
			// The presence query is complete but only carries the block ID.
			// Compare the newest receipt in this bounded page before claiming it
			// matches a pinned declaration's kind and, for merges, mode/bound.
			shown := make(map[[2]string]journal.BlockReceipt, len(receipts))
			for _, receipt := range receipts {
				key := [2]string{receipt.StepName, receipt.BlockID}
				if _, exists := shown[key]; !exists {
					shown[key] = receipt
				}
			}
			declaredStatus := "unavailable"
			declared := make([]map[string]any, 0)
			if info.WorkflowVersion > 0 && info.WorkflowArtifactSHA256 != "" {
				version, vErr := s.Journal.WorkflowVersionAtBounded(ctx, info.WorkflowID, info.WorkflowVersion, maxMCPWorkflowDAGBytes)
				if vErr == nil && !version.DAGTruncated && version.ArtifactSHA256 == info.WorkflowArtifactSHA256 {
					projection := flowblocks.FromDAG(version.DAG, maxMCPWorkflowDAGBytes)
					if projection.Complete {
						declaredStatus = "pinned_declaration"
						for _, step := range projection.Steps {
							for _, block := range step.Blocks {
								status := "observation_unsupported"
								if flowblocks.SupportsSDKObservation(block) {
									status = "no_sdk_observation"
									key := [2]string{step.Step, block.ID}
									if seen[key] {
										status = "sdk_reported_identity_only"
										if receipt, ok := shown[key]; ok {
											if (block.Kind == "merge" && receipt.Kind == "merge" && receipt.Mode == block.Mode && receipt.MaxRows == block.MaxRows) ||
												(block.Kind == "split" && receipt.Kind == "split" && receipt.InputRows != nil && receipt.YesRows != nil && receipt.NoRows != nil) ||
												((block.Kind == "iterate" || block.Kind == "aggregate") && receipt.Kind == block.Kind && journal.ValidBlockReceiptShape(receipt)) {
												status = "sdk_reported_observation"
											} else {
												status = "sdk_reported_shape_mismatch"
											}
										}
									}
								}
								declared = append(declared, map[string]any{"step_name": step.Step, "block_id": block.ID, "kind": block.Kind, "observation_status": status})
							}
						}
					}
				} else if vErr != nil && !errors.Is(vErr, journal.ErrNotFound) {
					// A transient DB failure must not look like a normal unobserved
					// block. Legacy/missing version rows remain labelled unavailable.
					return nil, vErr
				}
			}
			publicReceipts := make([]map[string]any, 0, len(receipts))
			for _, receipt := range receipts {
				publicReceipts = append(publicReceipts, projectBlockReceipt(receipt))
			}
			out := map[string]any{
				"run_id": a.RunID, "receipts": publicReceipts, "limit": a.Limit,
				"offset": a.Offset, "has_more": more,
				"declared_blocks": declared, "declaration_status": declaredStatus,
				"receipt_provenance": "sdk_reported", "behavior_verified": false,
				"note": "Bounded key-join merges, splits, iterations, and aggregations have optional SDK observers. sdk_reported_observation means the newest report for that block in this page matches its declared kind and typed shape; for merges the mode and bound must also match. sdk_reported_shape_mismatch means it differs. sdk_reported_identity_only means a report exists elsewhere in the run but its shape is not in this page. Receipts cannot verify a declared key, split predicate, route, mapping, or fold. observation_unsupported means no SDK receipt mechanism exists; no_sdk_observation does not prove a supported block was skipped. Authored Go can bypass the helper or forge a wire frame. No customer values are returned.",
			}
			if more {
				out["next_offset"] = a.Offset + len(receipts)
			}
			return out, nil
		},
	}
}

// Each operation exposes only its meaningful metadata. A split with zero
// inputs must not appear to have zero join sides or a zero join bound.
func projectBlockReceipt(r journal.BlockReceipt) map[string]any {
	out := map[string]any{
		"run_id": r.RunID, "step_name": r.StepName, "seq": r.Seq,
		"attempt": r.Attempt, "call_ordinal": r.CallOrdinal,
		"block_id": r.BlockID, "kind": r.Kind, "outcome": r.Outcome,
	}
	if r.Kind == "split" {
		out["input_rows"], out["yes_rows"], out["no_rows"] = r.InputRows, r.YesRows, r.NoRows
	} else if r.Kind == "iterate" || r.Kind == "aggregate" {
		out["input_rows"], out["output_rows"] = r.InputRows, r.OutputRows
	} else {
		out["mode"], out["left_rows"], out["right_rows"] = r.Mode, r.LeftRows, r.RightRows
		out["output_rows"], out["max_rows"] = r.OutputRows, r.MaxRows
	}
	return out
}
