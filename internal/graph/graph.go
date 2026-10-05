// Package graph maintains an in-memory graph over Reactor's runtime state
// (workflows, declarative command automations, credentials, triggers, recent
// runs, dlq items) and the knowledge corpus. The graph is the AI Environment Lens: a single MCP
// query returns the subgraph relevant to a brief, replacing the 5+
// roundtrips an AI would otherwise need to walk the database manually.
//
// The graph is rebuilt incrementally on writes (workflow CRUD, credential
// CRUD, knowledge add) and serialised to ~/.reactor/graph.json so external
// tools can consume it. JSON shape is self-describing; no graphify
// dependency.
package graph

import (
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/reactor/internal/knowledge"
)

// Common node kinds. Defined as constants so MCP / dashboard / tests
// share the same vocabulary.
const (
	KindWorkflow          = "workflow"
	KindCommandAutomation = "command-automation"
	KindCommandSchedule   = "command-schedule"
	KindCommandWebhook    = "command-webhook"
	KindCommandChain      = "command-chain"
	KindCredential        = "credential"
	KindTrigger           = "trigger"
	KindRun               = "run"
	KindDLQItem           = "dlq-item"
	KindKnowledge         = "knowledge"
	KindPostMortem        = "post-mortem"
)

// Common edge kinds.
const (
	EdgeUses        = "USES"         // workflow USES credential
	EdgeFires       = "FIRES"        // trigger FIRES workflow
	EdgeOnTerminal  = "ON_TERMINAL"  // command chain runs when source workflow reaches a terminal status
	EdgeBelongsTo   = "BELONGS_TO"   // run BELONGS_TO workflow
	EdgeFrom        = "FROM"         // dlq-item FROM run
	EdgeDerivedFrom = "DERIVED_FROM" // post-mortem DERIVED_FROM run
	EdgeCitedBy     = "CITED_BY"     // knowledge CITED_BY workflow / run
	EdgeSupersedes  = "SUPERSEDES"   // knowledge SUPERSEDES knowledge
)

// Node is a single graph vertex. ID has the shape "<kind>:<local-id>"
// so subgraphs can be flattened without losing kind context. Attrs is a
// loose map so callers can stash domain-specific fields without
// forcing a schema migration.
type Node struct {
	ID    string         `json:"id"`
	Kind  string         `json:"kind"`
	Label string         `json:"label"`
	Attrs map[string]any `json:"attrs,omitempty"`
}

// Edge is a directed link between two nodes. Kind identifies the
// relationship; Attrs carries optional metadata (e.g. created_at on a
// grant).
type Edge struct {
	From  string         `json:"from"`
	To    string         `json:"to"`
	Kind  string         `json:"kind"`
	Attrs map[string]any `json:"attrs,omitempty"`
}

// Graph is the in-memory store. Safe for concurrent reads; write paths
// take the mu write side.
type Graph struct {
	mu    sync.RWMutex
	nodes map[string]Node
	out   map[string][]Edge // outbound edges by from-id
	in    map[string][]Edge // inbound  edges by to-id
}

// New returns an empty Graph.
func New() *Graph {
	return &Graph{
		nodes: map[string]Node{},
		out:   map[string][]Edge{},
		in:    map[string][]Edge{},
	}
}

// ReplaceFrom atomically replaces this graph with a rebuilt snapshot. Readers
// either see the old complete graph or the new complete graph; they never see
// a partially rebuilt set of nodes and edges. The source is copied so callers
// may reuse or discard it after the call returns.
func (g *Graph) ReplaceFrom(source *Graph) {
	if g == nil || source == nil || g == source {
		return
	}
	source.mu.RLock()
	nodes := make(map[string]Node, len(source.nodes))
	for id, node := range source.nodes {
		nodes[id] = cloneNode(node)
	}
	out := cloneEdges(source.out)
	in := cloneEdges(source.in)
	source.mu.RUnlock()

	g.mu.Lock()
	g.nodes, g.out, g.in = nodes, out, in
	g.mu.Unlock()
}

func cloneMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for key, value := range src {
		dst[key] = cloneValue(value)
	}
	return dst
}

// cloneValue copies JSON-like values accepted in graph attributes. Graph
// snapshots are shared by concurrent readers and are also exposed through
// query results, so retaining a nested map or slice from a caller would let
// it mutate the graph without taking the graph lock. Reflection is limited to
// maps, slices, and interface wrappers; opaque structs and pointers remain
// values owned by the caller and are outside the graph's JSON contract.
func cloneValue(value any) any {
	if value == nil {
		return nil
	}
	return cloneReflectValue(reflect.ValueOf(value)).Interface()
}

func cloneReflectValue(value reflect.Value) reflect.Value {
	if !value.IsValid() {
		return value
	}
	if value.Kind() == reflect.Interface {
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		inner := cloneReflectValue(value.Elem())
		wrapped := reflect.New(value.Type()).Elem()
		wrapped.Set(inner)
		return wrapped
	}
	switch value.Kind() {
	case reflect.Map:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		out := reflect.MakeMapWithSize(value.Type(), value.Len())
		iter := value.MapRange()
		for iter.Next() {
			out.SetMapIndex(iter.Key(), cloneReflectValue(iter.Value()))
		}
		return out
	case reflect.Slice:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		out := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		for i := 0; i < value.Len(); i++ {
			out.Index(i).Set(cloneReflectValue(value.Index(i)))
		}
		return out
	case reflect.Array:
		out := reflect.New(value.Type()).Elem()
		for i := 0; i < value.Len(); i++ {
			out.Index(i).Set(cloneReflectValue(value.Index(i)))
		}
		return out
	default:
		return value
	}
}

func cloneNode(node Node) Node {
	node.Attrs = cloneMap(node.Attrs)
	return node
}

func cloneEdge(edge Edge) Edge {
	edge.Attrs = cloneMap(edge.Attrs)
	return edge
}

func cloneEdges(src map[string][]Edge) map[string][]Edge {
	dst := make(map[string][]Edge, len(src))
	for key, edges := range src {
		copied := make([]Edge, len(edges))
		copy(copied, edges)
		for i := range copied {
			copied[i] = cloneEdge(copied[i])
		}
		dst[key] = copied
	}
	return dst
}

// Subgraph is a self-contained slice of nodes + edges. Returned by
// Query and Neighbors. Suitable to JSON-marshal for an MCP tool reply.
type Subgraph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// AddNode inserts or replaces a node. Replacing keeps existing edges.
func (g *Graph) AddNode(n Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[n.ID] = cloneNode(n)
}

// AddEdge inserts e. Caller is responsible for not duplicating; we
// don't dedupe because some edges legitimately repeat with different
// attrs (e.g. multiple CITED_BY edges from one knowledge node).
func (g *Graph) AddEdge(e Edge) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e = cloneEdge(e)
	g.out[e.From] = append(g.out[e.From], e)
	g.in[e.To] = append(g.in[e.To], e)
}

// RemoveNode drops the node and every edge touching it. Used by the
// builder when a workflow / credential / knowledge entry is deleted.
func (g *Graph) RemoveNode(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.nodes, id)
	for _, e := range g.out[id] {
		g.in[e.To] = removeEdge(g.in[e.To], e)
	}
	delete(g.out, id)
	for _, e := range g.in[id] {
		g.out[e.From] = removeEdge(g.out[e.From], e)
	}
	delete(g.in, id)
}

func removeEdge(edges []Edge, target Edge) []Edge {
	out := edges[:0]
	for _, e := range edges {
		if e.From == target.From && e.To == target.To && e.Kind == target.Kind {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Get returns a node by id and whether it was found.
func (g *Graph) Get(id string) (Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	if !ok {
		return Node{}, false
	}
	return cloneNode(n), true
}

// Outbound returns edges whose From == id, optionally filtered by
// edgeKinds (empty = all).
func (g *Graph) Outbound(id string, edgeKinds ...string) []Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return filterEdges(g.out[id], edgeKinds)
}

// Inbound returns edges whose To == id, optionally filtered.
func (g *Graph) Inbound(id string, edgeKinds ...string) []Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return filterEdges(g.in[id], edgeKinds)
}

func filterEdges(in []Edge, kinds []string) []Edge {
	if len(kinds) == 0 {
		out := make([]Edge, len(in))
		for i, edge := range in {
			out[i] = cloneEdge(edge)
		}
		return out
	}
	want := map[string]bool{}
	for _, k := range kinds {
		want[k] = true
	}
	out := make([]Edge, 0, len(in))
	for _, e := range in {
		if want[e.Kind] {
			out = append(out, cloneEdge(e))
		}
	}
	return out
}

// Neighbors returns the subgraph reachable from startID within depth
// steps, treating edges as undirected for the walk. edgeKinds (if any)
// constrain which edges count for the walk.
func (g *Graph) Neighbors(startID string, depth int, edgeKinds ...string) Subgraph {
	return g.neighbors(startID, depth, "", edgeKinds...)
}

// NeighborsForTenant walks only nodes visible to tenantID. Global nodes (with
// no tenant_id attribute) remain usable as shared context; tenant-owned nodes
// and all edges touching them are filtered out.
func (g *Graph) NeighborsForTenant(startID, tenantID string, depth int, edgeKinds ...string) Subgraph {
	return g.neighbors(startID, depth, tenantID, edgeKinds...)
}

// NeighborsForTenantBounded is the MCP-safe variant of NeighborsForTenant.
// It caps both vertices and edges while walking a high-fanout graph and
// reports whether the result was truncated. The unbounded method remains for
// local/dashboard callers that own their response boundary.
func (g *Graph) NeighborsForTenantBounded(startID, tenantID string, depth, maxNodes, maxEdges int, edgeKinds ...string) (Subgraph, bool) {
	return g.neighborsBounded(startID, depth, tenantID, maxNodes, maxEdges, edgeKinds...)
}

func (g *Graph) neighbors(startID string, depth int, tenantID string, edgeKinds ...string) Subgraph {
	sub, _ := g.neighborsBounded(startID, depth, tenantID, 0, 0, edgeKinds...)
	return sub
}

func (g *Graph) neighborsBounded(startID string, depth int, tenantID string, maxNodes, maxEdges int, edgeKinds ...string) (Subgraph, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if depth < 1 {
		depth = 1
	}
	visited := map[string]bool{startID: true}
	frontier := []string{startID}
	var sub Subgraph
	if root, ok := g.nodes[startID]; ok && visibleNodeForTenant(root, tenantID) {
		sub.Nodes = append(sub.Nodes, cloneNode(root))
	} else {
		return sub, false
	}
	truncated := false
	for d := 0; d < depth && len(frontier) > 0; d++ {
		var next []string
		for _, cur := range frontier {
			for _, e := range filterEdges(g.out[cur], edgeKinds) {
				if !visibleEdgeForTenant(g.nodes, e, tenantID) {
					continue
				}
				if maxEdges > 0 && len(sub.Edges) >= maxEdges {
					truncated = true
					break
				}
				if !visited[e.To] && maxNodes > 0 && len(sub.Nodes) >= maxNodes {
					truncated = true
					continue
				}
				sub.Edges = append(sub.Edges, e)
				if !visited[e.To] {
					visited[e.To] = true
					if n, ok := g.nodes[e.To]; ok && visibleNodeForTenant(n, tenantID) {
						sub.Nodes = append(sub.Nodes, cloneNode(n))
					}
					next = append(next, e.To)
				}
			}
			for _, e := range filterEdges(g.in[cur], edgeKinds) {
				if !visibleEdgeForTenant(g.nodes, e, tenantID) {
					continue
				}
				if maxEdges > 0 && len(sub.Edges) >= maxEdges {
					truncated = true
					break
				}
				if !visited[e.From] && maxNodes > 0 && len(sub.Nodes) >= maxNodes {
					truncated = true
					continue
				}
				sub.Edges = append(sub.Edges, e)
				if !visited[e.From] {
					visited[e.From] = true
					if n, ok := g.nodes[e.From]; ok && visibleNodeForTenant(n, tenantID) {
						sub.Nodes = append(sub.Nodes, cloneNode(n))
					}
					next = append(next, e.From)
				}
			}
		}
		frontier = next
	}
	return sub, truncated
}

// Query scores every node by BM25 over its label + attr-string-values
// against the query, returns the top-N as a Subgraph along with their
// 1-hop neighborhood. Uses the same tokeniser as the knowledge package
// so search ergonomics match.
func (g *Graph) Query(query string, limit int) Subgraph {
	return g.query(query, limit, "")
}

// QueryForTenant is the tenant-scoped graph lens used by MCP. It filters both
// search candidates and their one-hop neighborhood, so a relevant global node
// cannot pull a hidden tenant-owned node into the response through an edge.
func (g *Graph) QueryForTenant(query, tenantID string, limit int) Subgraph {
	return g.query(query, limit, tenantID)
}

// QueryForTenantBounded is the MCP-safe query variant. It limits both the
// number of matched roots and the fan-out attached to them, reporting whether
// any visible nodes or edges were omitted.
func (g *Graph) QueryForTenantBounded(query, tenantID string, limit, maxNodes, maxEdges int) (Subgraph, bool) {
	return g.queryBounded(query, limit, tenantID, maxNodes, maxEdges)
}

func (g *Graph) query(query string, limit int, tenantID string) Subgraph {
	sub, _ := g.queryBounded(query, limit, tenantID, 0, 0)
	return sub
}

func (g *Graph) queryBounded(query string, limit int, tenantID string, maxNodes, maxEdges int) (Subgraph, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if limit <= 0 {
		limit = 10
	}
	visible := make(map[string]Node, len(g.nodes))
	for id, n := range g.nodes {
		if visibleNodeForTenant(n, tenantID) {
			visible[id] = n
		}
	}
	allHits := scoreNodes(visible, query)
	hits := allHits
	if len(hits) > limit {
		hits = hits[:limit]
	}
	visited := map[string]bool{}
	var sub Subgraph
	truncated := false
	for _, h := range hits {
		if maxNodes > 0 && len(sub.Nodes) >= maxNodes {
			truncated = true
			break
		}
		if !visited[h.ID] {
			visited[h.ID] = true
			sub.Nodes = append(sub.Nodes, cloneNode(h))
		}
		for _, e := range g.out[h.ID] {
			if !visibleEdgeForTenant(visible, e, tenantID) {
				continue
			}
			if maxEdges > 0 && len(sub.Edges) >= maxEdges {
				truncated = true
				break
			}
			if !visited[e.To] && maxNodes > 0 && len(sub.Nodes) >= maxNodes {
				truncated = true
				continue
			}
			sub.Edges = append(sub.Edges, cloneEdge(e))
			if !visited[e.To] {
				visited[e.To] = true
				if n, ok := visible[e.To]; ok {
					sub.Nodes = append(sub.Nodes, cloneNode(n))
				}
			}
		}
	}
	if len(allHits) > len(hits) {
		truncated = true
	}
	return sub, truncated
}

func visibleNodeForTenant(n Node, tenantID string) bool {
	if tenantID == "" {
		return true
	}
	raw, exists := n.Attrs["tenant_id"]
	if !exists {
		return true
	}
	tenant, ok := raw.(string)
	// A tenant marker is an ownership claim. If imported or legacy graph data
	// carries a malformed marker, hide it from tenant-scoped views instead of
	// treating the malformed value as global and risking a cross-tenant leak.
	return ok && (tenant == "" || tenant == tenantID)
}

func visibleEdgeForTenant(nodes map[string]Node, e Edge, tenantID string) bool {
	if tenantID == "" {
		return true
	}
	from, fromOK := nodes[e.From]
	to, toOK := nodes[e.To]
	return fromOK && toOK && visibleNodeForTenant(from, tenantID) && visibleNodeForTenant(to, tenantID)
}

// Serialize writes the full graph as JSON to w. Format is the same
// {"nodes": [...], "edges": [...]} shape that Subgraph uses, so the
// dump and a query response are interchangeable for downstream tools.
func (g *Graph) Serialize(w io.Writer) error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	all := Subgraph{
		Nodes: make([]Node, 0, len(g.nodes)),
	}
	for _, n := range g.nodes {
		all.Nodes = append(all.Nodes, n)
	}
	sort.SliceStable(all.Nodes, func(i, j int) bool {
		return all.Nodes[i].ID < all.Nodes[j].ID
	})
	for _, edges := range g.out {
		all.Edges = append(all.Edges, edges...)
	}
	sort.SliceStable(all.Edges, func(i, j int) bool {
		if all.Edges[i].From != all.Edges[j].From {
			return all.Edges[i].From < all.Edges[j].From
		}
		if all.Edges[i].To != all.Edges[j].To {
			return all.Edges[i].To < all.Edges[j].To
		}
		return all.Edges[i].Kind < all.Edges[j].Kind
	})
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(all)
}

// Stats returns counts per kind. Useful for the dashboard summary +
// MCP introspection.
func (g *Graph) Stats() map[string]int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := map[string]int{
		"nodes_total": len(g.nodes),
	}
	for _, n := range g.nodes {
		out["nodes_"+n.Kind]++
	}
	edgeCount := 0
	for _, edges := range g.out {
		edgeCount += len(edges)
	}
	out["edges_total"] = edgeCount
	return out
}

// FormatSubgraph renders a Subgraph in the Claude-friendly shape
// described in the plan:
//
//	NODE workflow:welcome-customer [status=succeeded ...]
//	EDGE workflow:foo USES credential:bar
//
// Lighter than JSON for inline prompt injection and easier to skim.
// promptSafe renders an untrusted string as a single-line, quoted Go literal
// so it cannot break out of the prompt region it is embedded in.
//
// Every value this function guards is writable by someone who is not the
// operator running codegen: node labels come from workflow slugs and CREDENTIAL
// NAMES, and attr values include dead-letter error_text, which is arbitrary
// free text chosen by whoever authored the failing workflow. Those strings were
// interpolated raw into the codegen prompt, whose output is compiled and
// executed on the host with no human approval step, and node selection is BM25
// over label+attrs against the brief, so stuffing likely brief terms into a
// long error_text reliably buys inclusion. A newline plus a fenced-block
// terminator was enough to append attacker instructions to the prompt.
//
// strconv.Quote handles the quote, backslash, backtick and newline cases in one
// pass; the length cap keeps one hostile node from crowding out the real slice.
func promptSafe(v string) string {
	const max = 300
	if len(v) > max {
		v = v[:max] + "...(truncated)"
	}
	// The graph is built from runtime rows and workflow-authored metadata. Apply
	// the same credential/PII scrub used by knowledge egress before quoting so a
	// harmless-looking label or status field cannot carry a token to codegen.
	v = graphPromptRedactor.Scrub(v)
	return strconv.Quote(v)
}

// promptSafeIdentifier preserves the compact graph shape for the identifiers
// Reactor itself creates, while quoting a malformed or caller-controlled value
// before it can create a new prompt line or close a framing token. Workflow
// slugs and generated IDs normally take the fast path; command names, future
// node kinds, and imported graph snapshots do not get that assumption.
func promptSafeIdentifier(v string) string {
	v = graphPromptRedactor.Scrub(v)
	if v != "" && len(v) <= 256 {
		valid := true
		for _, r := range v {
			if unicode.IsControl(r) || unicode.IsSpace(r) || r == '`' || r == '[' || r == ']' {
				valid = false
				break
			}
		}
		if valid {
			return v
		}
	}
	return promptSafe(v)
}

// promptAttr is deliberately stricter than the graph's internal projection.
// Rotation/provider diagnostics and dead-letter text are untrusted and can
// contain credentials, customer data, or model instructions. The codegen lens
// may send this rendering to an external model, so it receives only presence
// markers for those fields; the dashboard/admin graph keeps the raw values.
func promptAttr(key string, value any) string {
	normalized := strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(key))
	for _, fragment := range []string{"error", "secret", "token", "password", "credential", "authorization", "apikey", "payload", "url"} {
		if strings.Contains(normalized, fragment) {
			if promptValueEmpty(value) {
				return `"absent"`
			}
			return `"redacted"`
		}
	}
	if text, ok := scalarSearchText(value); ok {
		return promptSafe(text)
	}
	if value == nil {
		return `"null"`
	}
	// Opaque maps, slices, and custom values are not part of the graph's
	// authoring contract. Avoid marshaling them here: a legacy/imported value
	// could otherwise allocate a large temporary before appendPromptBounded
	// gets a chance to enforce the prompt budget.
	return `"untrusted"`
}

func promptValueEmpty(value any) bool {
	if value == nil {
		return true
	}
	text, ok := value.(string)
	return ok && strings.TrimSpace(text) == ""
}

const maxPromptSubgraphBytes = 32 << 10

const promptSubgraphTruncationMarker = "\n...[untrusted graph data truncated]"

var graphPromptRedactor = knowledge.NewRedactor()

// appendPromptBounded appends a complete UTF-8-safe fragment until the prompt
// slice reaches its hard cap. Keeping the cap here means a future graph node
// with a large attribute map cannot exhaust the model request even if each
// individual value remains below promptSafe's per-field limit.
func appendPromptBounded(b *strings.Builder, fragment string) bool {
	if b.Len() >= maxPromptSubgraphBytes {
		return false
	}
	remaining := maxPromptSubgraphBytes - b.Len()
	if len(fragment) <= remaining {
		b.WriteString(fragment)
		return true
	}
	cut := fragment[:remaining]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	b.WriteString(cut)
	return false
}

func FormatSubgraph(s Subgraph) string {
	var b strings.Builder
	truncated := false
	write := func(fragment string) {
		if !truncated {
			truncated = !appendPromptBounded(&b, fragment)
		}
	}
	for _, n := range s.Nodes {
		write("NODE ")
		write(promptSafeIdentifier(n.ID))
		if n.Label != "" && n.Label != n.ID {
			write(" ")
			write(promptSafe(n.Label))
		}
		if len(n.Attrs) > 0 {
			write(" [")
			keys := make([]string, 0, len(n.Attrs))
			for k := range n.Attrs {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for i, k := range keys {
				if i > 0 {
					write(" ")
				}
				write(promptSafeIdentifier(k))
				write("=")
				write(promptAttr(k, n.Attrs[k]))
			}
			write("]")
		}
		write("\n")
	}
	for _, e := range s.Edges {
		write("EDGE ")
		write(promptSafeIdentifier(e.From))
		write(" ")
		write(promptSafeIdentifier(e.Kind))
		write(" ")
		write(promptSafeIdentifier(e.To))
		write("\n")
	}
	if truncated {
		// Reserve space after the fact when the bounded writer filled the cap
		// exactly. A model must be told that the graph is incomplete; otherwise
		// the final partial NODE/EDGE line can look like a complete topology.
		raw := b.String()
		if len(raw)+len(promptSubgraphTruncationMarker) <= maxPromptSubgraphBytes {
			return raw + promptSubgraphTruncationMarker
		}
		keep := maxPromptSubgraphBytes - len(promptSubgraphTruncationMarker)
		for keep > 0 && !utf8.ValidString(raw[:keep]) {
			keep--
		}
		return raw[:keep] + promptSubgraphTruncationMarker
	}
	return b.String()
}
