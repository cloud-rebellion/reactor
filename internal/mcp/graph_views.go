package mcp

import (
	"encoding/json"
	"math"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/bright-interaction/reactor/internal/graph"
	"github.com/bright-interaction/reactor/internal/knowledge"
)

const (
	maxMCPGraphDiagnosticBytes = 4 << 10
	maxMCPGraphAttrs           = 32
	maxMCPGraphNestedItems     = 16
	maxMCPGraphNestedDepth     = 3
	maxMCPGraphNestedBytes     = 8 << 10
	maxMCPGraphNodeAttrBytes   = 16 << 10
	maxMCPGraphEdgeAttrBytes   = 4 << 10
)

const (
	mcpGraphRedacted  = "redacted"
	mcpGraphUntrusted = "[untrusted]"
	mcpGraphTruncated = "[truncated]"
)

// mcpGraphSubgraphView keeps the graph useful as an AI environment lens while
// preventing server-side credential diagnostics from crossing the MCP
// boundary. The graph itself retains raw values for local search and the
// admin-only graph export; only the tenant-scoped MCP projection is changed.
func mcpGraphSubgraphView(sub graph.Subgraph) graph.Subgraph {
	redactor := knowledge.NewRedactor()
	view := graph.Subgraph{
		Nodes: make([]graph.Node, 0, len(sub.Nodes)),
		Edges: make([]graph.Edge, 0, len(sub.Edges)),
	}
	for _, node := range sub.Nodes {
		node.ID = boundMCPGraphString(redactor.Scrub(node.ID))
		node.Kind = boundMCPGraphString(redactor.Scrub(node.Kind))
		node.Label = boundMCPGraphString(redactor.Scrub(node.Label))
		node.Attrs = projectMCPGraphAttrs(node.Attrs, redactor, maxMCPGraphNodeAttrBytes)
		view.Nodes = append(view.Nodes, node)
	}
	for _, edge := range sub.Edges {
		edge.From = boundMCPGraphString(redactor.Scrub(edge.From))
		edge.To = boundMCPGraphString(redactor.Scrub(edge.To))
		edge.Kind = boundMCPGraphString(redactor.Scrub(edge.Kind))
		edge.Attrs = projectMCPGraphAttrs(edge.Attrs, redactor, maxMCPGraphEdgeAttrBytes)
		view.Edges = append(view.Edges, edge)
	}
	return view
}

// projectMCPGraphAttrs creates a bounded, deterministic representation of an
// attribute map. Graph attributes are mostly scalar values today, but imported
// or legacy snapshots may contain nested JSON. Treat every value as untrusted:
// sensitive keys are redacted, strings are scrubbed and bounded, containers
// have depth/item limits, and the encoded map has a byte budget.
func projectMCPGraphAttrs(attrs map[string]any, redactor *knowledge.Redactor, byteBudget int) map[string]any {
	if len(attrs) == 0 {
		return nil
	}
	if len(attrs) > maxMCPGraphAttrs {
		// Do not sort or copy an untrusted attribute map just to discard most
		// of it. Keep the two diagnostic receipts that have explicit handling;
		// ordinary fields are omitted with a clear truncation marker.
		diagnostics := make(map[string]any, 2)
		if value, ok := attrs["last_error"]; ok {
			diagnostics["last_error"] = value
		}
		if value, ok := attrs["error_text"]; ok {
			diagnostics["error_text"] = value
		}
		out := projectMCPGraphAttrs(diagnostics, redactor, byteBudget)
		if out == nil {
			out = make(map[string]any, 1)
		}
		out["attrs_truncated"] = true
		return out
	}
	keys := make([]string, 0, len(attrs))
	for key := range attrs {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make(map[string]any, minInt(len(attrs), maxMCPGraphAttrs))
	used := 0
	truncated := false
	add := func(key string, value any) {
		if len(out) >= maxMCPGraphAttrs {
			truncated = true
			return
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			truncated = true
			return
		}
		// Account for the key and JSON punctuation as well as the value. This
		// is an upper bound for the object contribution and keeps a single
		// attribute map from consuming the response envelope.
		contribution := len(key) + len(encoded) + 4
		if used+contribution > byteBudget {
			truncated = true
			return
		}
		out[key] = value
		used += contribution
	}

	// Preserve the safe diagnostic receipts before ordinary fields can consume
	// the per-node budget.
	for _, key := range keys {
		switch key {
		case "last_error":
			value := attrs[key]
			if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
				add("last_error_present", true)
			}
			add("last_error_status", mcpGraphRedacted)
		case "error_text":
			projectMCPGraphError(add, attrs[key], redactor)
		}
	}

	for _, key := range keys {
		if key == "last_error" || key == "error_text" {
			continue
		}
		add(key, projectMCPGraphValue(key, attrs[key], redactor, 0))
	}
	if truncated {
		// The marker is intentionally small. It may take the map one entry over
		// the ordinary attribute cap, but never carries untrusted content.
		out["attrs_truncated"] = true
	}
	return out
}

func projectMCPGraphError(add func(string, any), value any, redactor *knowledge.Redactor) {
	text, ok := value.(string)
	if !ok {
		add("error_present", true)
		add("error_trust", "untrusted")
		return
	}
	text = redactor.Scrub(text)
	add("error_trust", "untrusted")
	if len(text) <= maxMCPGraphDiagnosticBytes {
		add("error_text", text)
		return
	}
	bounded := boundMCPGraphString(text)
	add("error_text", bounded)
	add("error_truncated", true)
	add("error_bytes", len(text))
}

func projectMCPGraphValue(key string, value any, redactor *knowledge.Redactor, depth int) any {
	if graphAttrKeySensitive(key) {
		return mcpGraphRedacted
	}
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case string:
		return boundMCPGraphString(redactor.Scrub(v))
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return v
	case float32:
		if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
			return mcpGraphUntrusted
		}
		return v
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return mcpGraphUntrusted
		}
		return v
	case json.Number:
		return boundMCPGraphString(redactor.Scrub(v.String()))
	case map[string]any:
		if depth >= maxMCPGraphNestedDepth {
			return mcpGraphTruncated
		}
		return projectMCPGraphMap(v, redactor, depth+1)
	case map[string]string:
		if depth >= maxMCPGraphNestedDepth {
			return mcpGraphTruncated
		}
		if len(v) > maxMCPGraphNestedItems {
			return map[string]any{"_truncated": true}
		}
		converted := make(map[string]any, len(v))
		for itemKey, item := range v {
			converted[itemKey] = item
		}
		return projectMCPGraphMap(converted, redactor, depth+1)
	case []any:
		return projectMCPGraphSlice(v, redactor, depth)
	case []string:
		return projectMCPGraphStringSlice(v, redactor, depth)
	default:
		// Do not call fmt.Sprint or json.Marshal on an unknown value: custom
		// implementations may allocate or expose data outside the graph's
		// JSON-like contract.
		return mcpGraphUntrusted
	}
}

func projectMCPGraphMap(value map[string]any, redactor *knowledge.Redactor, depth int) map[string]any {
	if len(value) > maxMCPGraphNestedItems {
		return map[string]any{"_truncated": true}
	}
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make(map[string]any, minInt(len(keys), maxMCPGraphNestedItems))
	used := 0
	for i, key := range keys {
		if i >= maxMCPGraphNestedItems {
			out["_truncated"] = true
			break
		}
		projected := projectMCPGraphValue(key, value[key], redactor, depth)
		encoded, err := json.Marshal(projected)
		if err != nil || used+len(key)+len(encoded)+4 > maxMCPGraphNestedBytes {
			out["_truncated"] = true
			break
		}
		out[key] = projected
		used += len(key) + len(encoded) + 4
	}
	return out
}

func projectMCPGraphSlice(value []any, redactor *knowledge.Redactor, depth int) []any {
	if depth >= maxMCPGraphNestedDepth {
		return []any{mcpGraphTruncated}
	}
	limit := len(value)
	if limit > maxMCPGraphNestedItems {
		limit = maxMCPGraphNestedItems
	}
	out := make([]any, 0, limit+1)
	used := 0
	for i := 0; i < limit; i++ {
		projected := projectMCPGraphValue("value", value[i], redactor, depth+1)
		encoded, err := json.Marshal(projected)
		if err != nil || used+len(encoded) > maxMCPGraphNestedBytes {
			out = append(out, mcpGraphTruncated)
			return out
		}
		out = append(out, projected)
		used += len(encoded)
	}
	if len(value) > limit {
		out = append(out, mcpGraphTruncated)
	}
	return out
}

func projectMCPGraphStringSlice(value []string, redactor *knowledge.Redactor, depth int) []any {
	if depth >= maxMCPGraphNestedDepth {
		return []any{mcpGraphTruncated}
	}
	limit := len(value)
	if limit > maxMCPGraphNestedItems {
		limit = maxMCPGraphNestedItems
	}
	out := make([]any, 0, limit+1)
	used := 0
	for i := 0; i < limit; i++ {
		projected := projectMCPGraphValue("value", value[i], redactor, depth+1)
		encoded, err := json.Marshal(projected)
		if err != nil || used+len(encoded) > maxMCPGraphNestedBytes {
			out = append(out, mcpGraphTruncated)
			return out
		}
		out = append(out, projected)
		used += len(encoded)
	}
	if len(value) > limit {
		out = append(out, mcpGraphTruncated)
	}
	return out
}

func graphAttrKeySensitive(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(key))
	for _, fragment := range []string{
		"error", "secret", "token", "password", "credential", "authorization", "apikey",
		"payload", "url", "providermeta", "diagnostic",
	} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func boundMCPGraphString(text string) string {
	if len(text) <= maxMCPGraphDiagnosticBytes {
		return text
	}
	bounded := strings.ToValidUTF8(text[:maxMCPGraphDiagnosticBytes], "�")
	for len(bounded) > maxMCPGraphDiagnosticBytes {
		_, size := utf8.DecodeLastRuneInString(bounded)
		if size <= 0 || size > len(bounded) {
			break
		}
		bounded = bounded[:len(bounded)-size]
	}
	return bounded
}
