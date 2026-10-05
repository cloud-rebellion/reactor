package mcp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/bright-interaction/reactor/internal/flowblocks"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/workflowproof"
)

const (
	maxMCPFlowIdentifierBytes = 128
	maxMCPFlowDisplayBytes    = 256
	maxMCPFlowUsesPerNode     = 32
	maxMCPFlowInputEdges      = 4096
	// Legacy trigger rows are bounded at the MCP projection boundary before
	// parsing chain metadata; new trigger mutations are much smaller, but old
	// installations may contain arbitrary JSON configuration.
	maxMCPTriggerConfigBytes  = 16 << 10
	maxMCPSourceDAGErrorBytes = 4 << 10
)

// flowTopologyNote is deliberately explicit about what a visual DAG proves.
// Reactor workflows are Go programs: predicates, error handling, iteration,
// aggregation, and data transforms can happen inside a Step closure and are
// not recoverable from a static dependency graph. Keeping that distinction in
// every flow receipt prevents an AI or operator from mistaking the declared
// graph for the path a particular run actually took.
const flowTopologyNote = "This is the author-declared workflow dependency graph. It does not infer branch predicates, error paths, loops or iteration, aggregation, or data transformations executed inside Go nodes; runtime step receipts are the authoritative actual path."

// addFlowTopology annotates a flow/review/preflight payload with a bounded
// topology summary. The node and edge slices must be the executable workflow
// graph, not the separately projected trigger/notification metadata.
func addFlowTopology(payload map[string]any, nodes, edges []map[string]any, truncated bool, dag []byte) {
	payload["topology"] = flowTopologyView(nodes, edges, truncated)
	blocks := flowblocks.FromDAG(dag, maxMCPWorkflowDAGBytes)
	if dagTruncated, _ := payload["dag_truncated"].(bool); dagTruncated {
		blocks.Complete = false
		blocks.Note = "The retained DAG exceeds the bounded visual-block projection."
	}
	payload["step_flows"] = blocks
}

func flowTopologyView(nodes, edges []map[string]any, truncated bool) map[string]any {
	declared := len(nodes) > 0 || len(edges) > 0
	provenance := "declared_dag"
	note := flowTopologyNote
	if !declared {
		provenance = "unavailable"
		note = "No executable visual DAG was retained. The workflow source may still contain control flow or durable work; inspect the retained source and run receipts before treating this as a complete flow."
	}

	inDegree := make(map[string]int, len(nodes))
	outDegree := make(map[string]int, len(nodes))
	for _, node := range nodes {
		if id, ok := node["id"].(string); ok && id != "" {
			inDegree[id] = 0
			outDegree[id] = 0
		}
	}
	seenEdges := make(map[[2]string]struct{}, len(edges))
	for _, edge := range edges {
		from, fromOK := edge["from"].(string)
		to, toOK := edge["to"].(string)
		if !fromOK || !toOK || from == "" || to == "" || from == to {
			continue
		}
		if _, ok := inDegree[from]; !ok {
			continue
		}
		if _, ok := inDegree[to]; !ok {
			continue
		}
		key := [2]string{from, to}
		if _, seen := seenEdges[key]; seen {
			continue
		}
		seenEdges[key] = struct{}{}
		outDegree[from]++
		inDegree[to]++
	}

	var roots, leaves, split, merge, disconnected int
	for id, in := range inDegree {
		out := outDegree[id]
		if in == 0 {
			roots++
		}
		if out == 0 {
			leaves++
		}
		if out > 1 {
			split++
		}
		if in > 1 {
			merge++
		}
		if in == 0 && out == 0 {
			disconnected++
		}
	}
	return map[string]any{
		"provenance":         provenance,
		"complete":           !truncated,
		"truncated":          truncated,
		"node_count":         len(inDegree),
		"edge_count":         len(seenEdges),
		"root_count":         roots,
		"leaf_count":         leaves,
		"split_count":        split,
		"merge_count":        merge,
		"disconnected_count": disconnected,
		"has_split":          split > 0,
		"has_merge":          merge > 0,
		"has_disconnected":   disconnected > 0,
		"note":               note,
	}
}

// workflowFlowSnapshot resolves the visual graph from the same immutable
// version record used by dispatch. Versionless rows are retained as a
// deliberately labelled metadata fallback for old installations.
func (s *Server) workflowFlowSnapshot(ctx context.Context, workflowID, slug string) (dag json.RawMessage, dagBytes int, dagTruncated bool, version int, artifactSHA256, codeHash, sourceManifestSHA256 string, sourceProofVersion int, artifactStatus, versionSource string, err error) {
	return s.workflowFlowSnapshotAt(ctx, workflowID, slug, 0)
}

// workflowFlowSnapshotAt resolves either the current immutable version or one
// exact historical version. A requested version is never silently replaced by
// the current pointer: review clients use this to render the same immutable
// topology they inspected before a rollback or another authoring revision.
func (s *Server) workflowFlowSnapshotAt(ctx context.Context, workflowID, slug string, requestedVersion int) (dag json.RawMessage, dagBytes int, dagTruncated bool, version int, artifactSHA256, codeHash, sourceManifestSHA256 string, sourceProofVersion int, artifactStatus, versionSource string, err error) {
	versionSource = "legacy_metadata"
	artifactStatus = "missing"
	var current journal.WorkflowVersion
	var versionErr error
	if requestedVersion > 0 {
		current, versionErr = s.Journal.WorkflowVersionAtBounded(ctx, workflowID, requestedVersion, maxMCPWorkflowDAGBytes)
	} else {
		current, versionErr = s.Journal.CurrentWorkflowVersionRecordBounded(ctx, workflowID, maxMCPWorkflowDAGBytes)
	}
	if versionErr == nil {
		version = current.Version
		artifactSHA256 = current.ArtifactSHA256
		codeHash = current.CodeHash
		sourceManifestSHA256 = current.SourceManifestSHA256
		sourceProofVersion = current.SourceProofVersion
		versionSource = "immutable_version"
		dag = current.DAG
		dagBytes = current.DAGBytes
		dagTruncated = current.DAGTruncated
	} else if requestedVersion > 0 {
		// An exact historical request must remain exact. Falling back to a
		// legacy/current metadata row would render a different executable graph
		// under the caller's requested version and undermine review/rollback
		// fencing.
		return nil, 0, false, 0, "", "", "", 0, "", "", versionErr
	} else if errors.Is(versionErr, journal.ErrNotFound) {
		dag, dagBytes, dagTruncated, err = s.Journal.WorkflowDAGBounded(ctx, workflowID, maxMCPWorkflowDAGBytes)
		if err != nil {
			return nil, 0, false, 0, "", "", "", 0, "", "", err
		}
	} else {
		return nil, 0, false, 0, "", "", "", 0, "", "", versionErr
	}
	if artifactSHA256 != "" {
		artifactStatus = "pinned_unverified"
		if strings.TrimSpace(s.StateRoot) != "" {
			if _, artifactErr := s.artifactPathForTenant(ctx, slug, artifactSHA256); artifactErr == nil {
				artifactStatus = "verified"
			} else {
				artifactStatus = "unavailable"
			}
		}
	}
	return dag, dagBytes, dagTruncated, version, artifactSHA256, codeHash, sourceManifestSHA256, sourceProofVersion, artifactStatus, versionSource, nil
}

type sourceDAGValidation struct {
	Status string
	Error  string
}

func sourceCodeHashVerifiable(codeHash string) bool {
	if len(codeHash) != 16 {
		return false
	}
	_, err := hex.DecodeString(codeHash)
	return err == nil
}

// validateRetainedSourceDAG checks the source/DAG relationship at read time as
// well as during authoring. A legacy or externally-imported workflow can carry
// a valid-looking empty DAG even though its executable source contains durable
// calls; callers must therefore distinguish a schema-valid graph from a flow
// whose executable topology was actually verified.
func (s *Server) validateRetainedSourceDAG(slug, artifactSHA256, codeHash string, dag []byte) sourceDAGValidation {
	if strings.TrimSpace(artifactSHA256) == "" {
		return sourceDAGValidation{Status: "not_checked"}
	}
	// Keep the legacy helper for low-level tests and embedded callers that do
	// not carry an authenticated request context. Production MCP handlers use
	// the context-aware variant below, which binds proof to the active tenant.
	result := workflowproof.Check(s.StateRoot, slug, artifactSHA256, codeHash, dag)
	return sourceDAGResult(result)
}

func (s *Server) validateRetainedSourceDAGForTenant(ctx context.Context, slug, artifactSHA256, codeHash, sourceManifestSHA256 string, sourceProofVersion int, dag []byte) sourceDAGValidation {
	if strings.TrimSpace(artifactSHA256) == "" {
		return sourceDAGValidation{Status: "not_checked"}
	}
	result := workflowproof.CheckVersionForTenant(s.StateRoot, slug, s.tenantID(ctx), journal.WorkflowVersion{
		ArtifactSHA256: artifactSHA256, CodeHash: codeHash, SourceManifestSHA256: sourceManifestSHA256,
		SourceProofVersion: sourceProofVersion, DAG: dag,
	})
	return sourceDAGResult(result)
}

func sourceDAGResult(result workflowproof.Result) sourceDAGValidation {
	message := safeSourceProofReason(result)
	if message != "" {
		message, _, _ = boundMCPText(message, maxMCPSourceDAGErrorBytes)
	}
	return sourceDAGValidation{Status: result.Status, Error: message}
}

// Proof failures can contain an absolute on-disk source filename from the Go
// parser or a filesystem error. MCP receipts expose a stable category while
// leaving the detailed diagnostic on the operator's local build surface.
func safeSourceProofReason(result workflowproof.Result) string {
	if result.Reason == "" {
		return ""
	}
	if strings.HasPrefix(result.Reason, missingVisualNodesReason) {
		return missingVisualNodesReason
	}
	switch result.Status {
	case "unavailable":
		return "immutable artifact or retained workflow source is unavailable"
	case "mismatch":
		return "retained workflow source, artifact, or visual DAG failed integrity verification"
	case "visual_unverified":
		return "legacy visual annotations are not proven against retained workflow source"
	case "legacy_manifest_unpinned":
		return "legacy source manifest is not pinned to the workflow version"
	case "compiled_files_unverified":
		return "source manifest does not prove the compiled workflow Go files"
	case "legacy_unverified":
		return "legacy workflow source proof is unavailable"
	default:
		return "retained workflow source proof did not pass execution policy"
	}
}

func sourceDAGVisualComplete(status string) bool {
	return status == "verified"
}

// workflowFlowVerification turns the source/DAG proof and the bounded visual
// projection into the explicit trust gate exposed by both flow read surfaces.
// A schema-valid graph can still be unsafe to treat as the executable flow
// when its retained source proof is absent or when the MCP projection omitted
// nodes or edges. Keep that distinction separate from `validated`, which is
// the schema-level result used by renderers.
func workflowFlowVerification(sourceStatus string, dagTruncated, flowTruncated bool, dag []byte, sourceError string) (status, reason string) {
	if dagTruncated {
		return "unverified", "workflow DAG exceeds the bounded MCP flow projection"
	}
	if flowTruncated {
		return "unverified", "visual flow exceeds the bounded MCP projection"
	}
	if !workflowDAGHasNodes(dag) {
		return "unverified", missingVisualNodesReason
	}
	if sourceDAGVisualComplete(sourceStatus) {
		return "verified", ""
	}
	if trimmed := strings.TrimSpace(sourceError); trimmed != "" {
		return "unverified", trimmed
	}
	switch sourceStatus {
	case "not_checked":
		return "unverified", "retained source and visual DAG proof was not checked"
	case "":
		return "unverified", "retained source and visual DAG proof is unavailable"
	default:
		return "unverified", "retained source and visual DAG proof is " + sourceStatus
	}
}

// visualDAGTruncated reports whether the bounded MCP projection omits any
// part of an otherwise valid DAG. A flow that cannot be rendered completely
// is useful for inspection, but it is not sufficient proof for activation or
// dispatch because the client could miss an executable node or edge.
func visualDAGTruncated(src []byte) bool {
	trimmed := strings.TrimSpace(string(src))
	if trimmed == "" || trimmed == "{}" {
		return false
	}
	_, _, truncated := flowElementsBounded(src, maxMCPFlowNodes, maxMCPFlowEdges)
	return truncated
}

// flowElements converts both DAG encodings accepted by Reactor into the small
// node/edge shape used by visual clients. It intentionally returns metadata
// only; source and run payloads stay behind their separate tools.
func flowElements(src []byte) ([]map[string]any, []map[string]any) {
	nodes, edges, _ := flowElementsBounded(src, 0, 0)
	return nodes, edges
}

func flowElementsBounded(src []byte, maxNodes, maxEdges int) ([]map[string]any, []map[string]any, bool) {
	if maxNodes < 0 {
		maxNodes = 0
	}
	if maxEdges < 0 {
		maxEdges = 0
	}
	if len(src) == 0 || len(src) > maxMCPWorkflowDAGBytes {
		return nil, nil, len(src) > maxMCPWorkflowDAGBytes
	}
	var dag struct {
		Steps []struct {
			Name      string   `json:"name"`
			Kind      string   `json:"kind"`
			DependsOn []string `json:"depends_on"`
			Uses      []string `json:"uses"`
		} `json:"steps"`
		Nodes []struct {
			ID    string   `json:"id"`
			Name  string   `json:"name"`
			Kind  string   `json:"kind"`
			Label string   `json:"label"`
			Uses  []string `json:"uses"`
		} `json:"nodes"`
		Edges []struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"edges"`
	}
	if json.Unmarshal(src, &dag) != nil {
		// A retained legacy DAG can be syntactically valid yet contain a field
		// the visual projection cannot decode. Never report an empty graph as
		// complete in that case: review and activation must fail closed.
		return nil, nil, true
	}
	nodes := make([]map[string]any, 0, len(dag.Steps)+len(dag.Nodes))
	seen := map[string]bool{}
	truncated := false
	for _, step := range dag.Steps {
		if step.Name == "" || seen[step.Name] {
			continue
		}
		if len(step.Name) > maxMCPFlowIdentifierBytes {
			truncated = true
			continue
		}
		if maxNodes > 0 && len(nodes) >= maxNodes {
			truncated = true
			break
		}
		seen[step.Name] = true
		node := map[string]any{"id": step.Name, "label": step.Name, "kind": boundMCPFlowDisplay(step.Kind)}
		if uses, usesTruncated := boundMCPFlowValues(step.Uses); len(uses) > 0 {
			node["uses"] = uses
			truncated = truncated || usesTruncated
		}
		nodes = append(nodes, node)
	}
	edges := make([]map[string]any, 0)
	// Dependencies and visual edges represent graph relationships, not a
	// multigraph. A repeated dependency is legal JSON and has no runtime
	// meaning, but emitting it twice makes renderers show duplicate arrows and
	// needlessly consumes the bounded edge budget. Keep the first occurrence in
	// source order so the normalized flow is deterministic.
	seenEdges := map[[2]string]bool{}
	appendEdge := func(from, to string) bool {
		key := [2]string{from, to}
		if seenEdges[key] {
			return false
		}
		seenEdges[key] = true
		edges = append(edges, map[string]any{"from": from, "to": to})
		return true
	}
	inputEdges := 0
	for _, step := range dag.Steps {
		for _, dep := range step.DependsOn {
			inputEdges++
			if inputEdges > maxMCPFlowInputEdges {
				truncated = true
				break
			}
			// A bounded graph must remain renderable when the node cap is
			// reached. Do not emit an edge whose endpoint was omitted (or is
			// malformed in a legacy row); the truncated flag tells the client
			// to fetch a narrower view instead of rendering a dangling edge.
			if !seen[dep] || !seen[step.Name] {
				truncated = true
				continue
			}
			if seenEdges[[2]string{dep, step.Name}] {
				continue
			}
			if maxEdges > 0 && len(edges) >= maxEdges {
				truncated = true
				break
			}
			appendEdge(dep, step.Name)
		}
		if inputEdges > maxMCPFlowInputEdges {
			break
		}
	}
	// When a stale row contains both encodings, match the browser renderer and
	// prefer a non-empty executable steps[] representation. New authoring is
	// rejected by registry.ValidateDAG before this projection is exposed.
	if len(dag.Steps) == 0 {
		for _, node := range dag.Nodes {
			id := node.ID
			if id == "" {
				id = node.Name
			}
			if id == "" || seen[id] {
				continue
			}
			if len(id) > maxMCPFlowIdentifierBytes {
				truncated = true
				continue
			}
			if maxNodes > 0 && len(nodes) >= maxNodes {
				truncated = true
				break
			}
			seen[id] = true
			label := node.Label
			if label == "" {
				label = id
			}
			entry := map[string]any{"id": id, "label": boundMCPFlowDisplay(label), "kind": boundMCPFlowDisplay(node.Kind)}
			if uses, usesTruncated := boundMCPFlowValues(node.Uses); len(uses) > 0 {
				entry["uses"] = uses
				truncated = truncated || usesTruncated
			}
			nodes = append(nodes, entry)
		}
	}
	// edges[] belongs to the nodes[] encoding. In a stale mixed row it can
	// name two executable steps yet declare a relationship that the steps[]
	// graph never had. Omit those links and flag the projection incomplete.
	if len(dag.Steps) > 0 && (len(dag.Nodes) > 0 || len(dag.Edges) > 0) {
		truncated = true
	}
	if len(dag.Steps) == 0 {
		for i, edge := range dag.Edges {
			if i >= maxMCPFlowInputEdges {
				truncated = true
				break
			}
			if edge.From != "" && edge.To != "" {
				if !seen[edge.From] || !seen[edge.To] {
					truncated = true
					continue
				}
				if seenEdges[[2]string{edge.From, edge.To}] {
					continue
				}
				if maxEdges > 0 && len(edges) >= maxEdges {
					truncated = true
					break
				}
				appendEdge(edge.From, edge.To)
			}
		}
	}
	return nodes, edges, truncated
}

func boundMCPFlowDisplay(value string) string {
	if len(value) <= maxMCPFlowDisplayBytes {
		return value
	}
	// Keep the rendered value within the advertised byte budget and never cut
	// through a UTF-8 rune. Flow labels come from authored or imported data, so
	// a legacy multibyte value must remain valid JSON and deterministic across
	// clients just like the other MCP text projections.
	const suffix = "..."
	prefix, _, _ := boundMCPText(value, maxMCPFlowDisplayBytes-len(suffix))
	return prefix + suffix
}

func boundMCPFlowValues(values []string) ([]string, bool) {
	truncated := len(values) > maxMCPFlowUsesPerNode
	if len(values) > maxMCPFlowUsesPerNode {
		values = values[:maxMCPFlowUsesPerNode]
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if len(value) > maxMCPFlowIdentifierBytes {
			truncated = true
			value = boundMCPFlowDisplay(value)
		}
		out = append(out, value)
	}
	return out, truncated
}

// boundOperationalFlow applies the remaining response budget to the
// trigger/notification topology that surrounds a workflow DAG. The primary
// flow and operational flow are serialized as separate arrays, so bounding
// them independently would let their combined response exceed the advertised
// node/edge limits. Edges whose endpoint is omitted are dropped so a client
// never receives a dangling operational edge; truncated tells it to request a
// narrower view or continue through the inventory tools.
func boundOperationalFlow(nodes, edges []map[string]any, maxNodes, maxEdges int) ([]map[string]any, []map[string]any, bool) {
	if maxNodes < 0 {
		maxNodes = 0
	}
	if maxEdges < 0 {
		maxEdges = 0
	}
	truncated := len(nodes) > maxNodes
	if len(nodes) > maxNodes {
		nodes = nodes[:maxNodes]
	}
	seenNodes := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		if id, ok := node["id"].(string); ok && id != "" {
			seenNodes[id] = struct{}{}
		}
	}
	boundedEdges := make([]map[string]any, 0, len(edges))
	for _, edge := range edges {
		from, fromOK := edge["from"].(string)
		to, toOK := edge["to"].(string)
		if !fromOK || !toOK || from == "" || to == "" {
			truncated = true
			continue
		}
		if _, ok := seenNodes[from]; !ok {
			truncated = true
			continue
		}
		if _, ok := seenNodes[to]; !ok {
			truncated = true
			continue
		}
		if len(boundedEdges) >= maxEdges {
			truncated = true
			break
		}
		boundedEdges = append(boundedEdges, edge)
	}
	if len(boundedEdges) < len(edges) {
		truncated = true
	}
	return nodes, boundedEdges, truncated
}

// workflowOperationalFlow adds the bounded event and alert topology around a
// workflow's executable DAG. The internal step graph remains sourced from the
// immutable workflow version; these external nodes are tenant-scoped journal
// metadata and deliberately omit webhook tokens and channel configuration.
func (s *Server) workflowOperationalFlow(ctx context.Context, workflowID, slug string) (nodes, edges []map[string]any, truncated bool, err error) {
	workflowNodeID := "workflow:" + workflowID
	nodes = append(nodes, map[string]any{"id": workflowNodeID, "label": boundMCPFlowDisplay(slug), "kind": "workflow"})
	seenNodes := map[string]bool{workflowNodeID: true}
	triggers, triggerMore, err := s.Journal.ListTriggersForWorkflowPageBounded(ctx, workflowID, maxMCPReviewItems, 0, maxMCPTriggerConfigBytes)
	if err != nil {
		return nil, nil, false, err
	}
	for _, trigger := range triggers {
		nodeID := "trigger:" + trigger.ID
		node := map[string]any{
			"id": nodeID, "label": string(trigger.Kind), "kind": "trigger",
			"trigger_id": trigger.ID, "state": trigger.State,
			"revision": trigger.Revision, "token_available": trigger.TokenID != "",
		}
		// A workflow-complete trigger is an edge from another workflow, not an
		// anonymous event source. Include the same-tenant source node and edge
		// in the visual topology so a renderer cannot imply that the downstream
		// workflow runs without its upstream dependency. Legacy rows may contain
		// malformed or oversized config; leave those as an inspectable trigger
		// node rather than trusting arbitrary JSON or leaking another tenant's
		// workflow identity.
		if trigger.Kind == journal.TriggerWorkflowComplete && !trigger.ConfigTruncated && len(trigger.Config) <= maxMCPTriggerConfigBytes {
			var chain struct {
				SourceWorkflowID string `json:"source_workflow_id"`
				OnStatuses       string `json:"on_statuses"`
			}
			if json.Unmarshal(trigger.Config, &chain) == nil {
				sourceID := strings.TrimSpace(chain.SourceWorkflowID)
				if sourceID != "" {
					if sourceTenant, tenantErr := s.Journal.WorkflowTenant(ctx, sourceID); tenantErr == nil && sourceTenant == s.tenantID(ctx) {
						if sourceSlug, slugErr := s.Journal.WorkflowSlugByID(ctx, sourceID); slugErr == nil && strings.TrimSpace(sourceSlug) != "" {
							node["source_workflow_id"] = sourceID
							node["source_slug"] = boundMCPFlowDisplay(sourceSlug)
							sourceNodeID := "workflow:" + sourceID
							if sourceNodeID != workflowNodeID {
								if !seenNodes[sourceNodeID] {
									seenNodes[sourceNodeID] = true
									nodes = append(nodes, map[string]any{
										"id": sourceNodeID, "label": boundMCPFlowDisplay(sourceSlug), "kind": "workflow_source",
										"workflow_id": sourceID,
									})
								}
								edge := map[string]any{"from": sourceNodeID, "to": nodeID, "kind": "chain"}
								if status := strings.TrimSpace(chain.OnStatuses); status != "" {
									edge["on_statuses"] = boundMCPFlowDisplay(status)
								}
								edges = append(edges, edge)
							}
						}
					}
				}
			}
		}
		nodes = append(nodes, node)
		edges = append(edges, map[string]any{"from": nodeID, "to": workflowNodeID, "kind": "trigger"})
	}
	if triggerMore {
		truncated = true
	}
	routes, err := s.Journal.ListNotificationRoutesForWorkflowPageBounded(ctx, workflowID, maxMCPReviewItems+1, 0, maxMCPNotificationNameBytes, maxMCPNotificationStatusBytes)
	if err != nil {
		return nil, nil, false, err
	}
	if len(routes) > maxMCPReviewItems {
		truncated = true
		routes = routes[:maxMCPReviewItems]
	}
	seenChannels := map[string]bool{}
	for _, route := range routes {
		if route.ChannelNameTruncated || route.OnStatusesTruncated {
			truncated = true
		}
		nodeID := "notification:" + route.ChannelID
		if !seenChannels[route.ChannelID] {
			node := map[string]any{
				"id": nodeID, "label": route.ChannelName, "kind": "notification",
				"channel_id": route.ChannelID, "channel_kind": route.ChannelKind,
			}
			if route.ChannelNameTruncated {
				node["label_truncated"] = true
				node["label_bytes"] = route.ChannelNameBytes
			}
			nodes = append(nodes, node)
			seenChannels[route.ChannelID] = true
		}
		edge := map[string]any{
			"from": workflowNodeID, "to": nodeID, "kind": "notification",
			"on_statuses": route.OnStatuses,
		}
		if route.OnStatusesTruncated {
			edge["on_statuses_truncated"] = true
			edge["on_statuses_bytes"] = route.OnStatusesBytes
		}
		edges = append(edges, edge)
	}
	return nodes, edges, truncated, nil
}
