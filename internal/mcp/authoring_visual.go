package mcp

import (
	"encoding/json"
	"fmt"

	"github.com/bright-interaction/reactor/internal/registry"
)

const missingVisualNodesReason = "workflow visual DAG has no executable nodes"

// workflowDAGHasNodes checks only presence, not schema validity. Every
// authoring and activation caller also runs the canonical DAG validator.
// Legacy empty graphs remain readable, but cannot prove a visual workflow.
func workflowDAGHasNodes(dag []byte) bool {
	var shape struct {
		Steps []json.RawMessage `json:"steps"`
		Nodes []json.RawMessage `json:"nodes"`
	}
	return json.Unmarshal(dag, &shape) == nil && (len(shape.Steps) > 0 || len(shape.Nodes) > 0)
}

// requireMCPAuthoringVisualDAG prevents a newly AI-authored binary with no
// durable Reactor nodes from being published as a reviewable automation. The
// source/DAG validator later checks that every declared node has a matching
// literal SDK call; this early check avoids a needless Go build for a blank
// graph and keeps the MCP contract stricter than legacy CLI imports.
func requireMCPAuthoringVisualDAG(dag json.RawMessage) error {
	if len(dag) > maxMCPWorkflowDAGBytes {
		return fmt.Errorf("%w: visual DAG exceeds the bounded MCP authoring projection (%d bytes); split the workflow before building", errInvalidParamsErr, maxMCPWorkflowDAGBytes)
	}
	if err := registry.ValidateDAG(dag); err != nil {
		return fmt.Errorf("%w: visual DAG is required and must be valid: %v", errInvalidParamsErr, err)
	}
	if !workflowDAGHasNodes(dag) {
		return fmt.Errorf("%w: %s; declare at least one matching Step, SideEffect, Sleep, or AwaitSignal call", errInvalidParamsErr, missingVisualNodesReason)
	}
	if visualDAGTruncated(dag) {
		return fmt.Errorf("%w: visual DAG exceeds the bounded MCP flow projection; reduce declared edges or uses before building", errInvalidParamsErr)
	}
	return nil
}
