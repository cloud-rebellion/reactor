package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/bright-interaction/reactor/internal/flowblocks"
)

const (
	// Keep validation bounded independently of the transport. MCP and the
	// source-build path apply their own (smaller) request limits, but registry
	// callers also read legacy rows and files directly. Without a registry
	// limit a malformed stored DAG could make every review/readiness request do
	// work proportional to an arbitrarily large dependency list.
	maxDAGBytes  = 1 << 20
	maxDAGSteps  = 256
	maxDAGEdges  = 4096
	maxDAGName   = 128
	maxDAGIssues = 512
)

var stepNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,127}$`)

// DAGSchemaError is the structured error returned by ValidateDAG. The
// dashboard's POST handler surfaces these as a 422 with a machine-
// readable issue list so the editor UI can highlight problems inline.
type DAGSchemaError struct {
	Issues []DAGIssue
}

// DAGIssue pinpoints one validation failure. Path uses JSON-Pointer-ish
// shape ("/steps/3/kind") so a future inline-error UI can map it to a
// position in the textarea.
type DAGIssue struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

func (e *DAGSchemaError) Error() string {
	if len(e.Issues) == 0 {
		return "dag.json: validation failed"
	}
	parts := make([]string, len(e.Issues))
	for i, is := range e.Issues {
		parts[i] = fmt.Sprintf("%s: %s", is.Path, is.Message)
	}
	return "dag.json: " + strings.Join(parts, "; ")
}

// allowedKinds mirrors the JSON Schema's enum. Kept package-local so a
// new kind requires a deliberate edit here + in the SDK + in the lint.
var allowedKinds = map[string]bool{
	"step":         true,
	"sleep":        true,
	"await_signal": true,
	"side_effect":  true,
}

var slugRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// ValidateDAG checks src against the dag.json shape:
//   - Top-level object with optional slug/version metadata and one graph shape
//   - slug matches ^[a-z][a-z0-9-]*$
//   - steps is a (possibly empty) array of {name, kind, depends_on?, idempotency_key?, timeout_seconds?}
//   - top-level edges belong to nodes; steps express edges with depends_on
//   - nodes express edges at the top level, not through depends_on
//   - kind is one of step / sleep / await_signal / side_effect
//   - a step may include bounded visual_flow blocks/edges as author-declared
//     review metadata; these annotations do not create executable nodes
//
// Returns *DAGSchemaError on validation failure with a non-empty Issues
// slice; returns a plain error on JSON parse failure.
func ValidateDAG(src []byte) error {
	if len(src) == 0 {
		return errors.New("dag.json: empty body")
	}
	if len(src) > maxDAGBytes {
		return fmt.Errorf("dag.json: body exceeds %d-byte limit", maxDAGBytes)
	}
	// encoding/json applies last-wins semantics to duplicate object keys. The
	// MCP envelope rejects them, but CLI and programmatic build callers reach
	// this canonical validator directly. Rejecting them here keeps the source,
	// visual review, and persisted version from disagreeing about which value
	// was authored.
	if _, found, err := duplicateJSONKey(src); err != nil {
		return fmt.Errorf("dag.json: parse: %w", err)
	} else if found {
		// Do not reflect an attacker-controlled key into the operator/MCP error
		// body. The key is retained in the local walk only to identify the
		// duplicate; the stable error is enough for the author to retry.
		return errors.New("dag.json: duplicate object key")
	}
	var raw map[string]any
	if err := json.Unmarshal(src, &raw); err != nil {
		return fmt.Errorf("dag.json: parse: %w", err)
	}

	var issues []DAGIssue
	issuesTruncated := false
	add := func(path, msg string) {
		if issuesTruncated {
			return
		}
		if len(issues) >= maxDAGIssues-1 {
			issues = append(issues, DAGIssue{Path: "/", Message: fmt.Sprintf("validation stopped after %d issues", maxDAGIssues)})
			issuesTruncated = true
			return
		}
		issues = append(issues, DAGIssue{Path: path, Message: msg})
	}

	slug, hasSlug := raw["slug"].(string)
	if hasSlug && slug != "" && !slugRe.MatchString(slug) {
		add("/slug", `must match ^[a-z][a-z0-9-]*$ (becomes a filesystem path)`)
	}
	// slug/version are metadata and remain optional for legacy hand-authored
	// DAGs. If present, they are validated; the build pipeline separately
	// checks a non-empty slug matches the workflow being built.

	stepsAny, hasSteps := raw["steps"]
	nodesAny, hasNodes := raw["nodes"]
	// Reactor has accepted both the authoring shape (steps + depends_on) and
	// the visual-editor shape (nodes + edges). Validate whichever shape is
	// present, but never accept an object with no graph at all.
	if !hasSteps && !hasNodes {
		add("/steps", "required array (or nodes array)")
	}
	stepsList, stepsArray := stepsAny.([]any)
	nodesList, nodesArray := nodesAny.([]any)
	if stepsArray && nodesArray && len(stepsList) > 0 && len(nodesList) > 0 {
		// The two encodings have different edge semantics. Treating both as a
		// single graph lets duplicate names silently hide one representation in
		// the flow renderer and can make source/DAG checks disagree with runtime.
		// An empty legacy array is deliberately allowed beside a populated visual
		// array so old editors can migrate without losing their graph.
		add("/", "use either steps or nodes, not both")
	}
	if rawEdges, hasEdges := raw["edges"]; hasEdges {
		// Every flow projection gives populated steps[] precedence over
		// top-level edges[]. An empty steps[] without a populated nodes[]
		// graph has no owner for those edges either. Reject relationships that
		// would disappear from review, including malformed edges values.
		// Empty legacy arrays carry no relationship and remain readable.
		edges, ok := rawEdges.([]any)
		if !ok || len(edges) > 0 {
			if stepsArray && len(stepsList) > 0 {
				add("/edges", "top-level edges require nodes; use steps[].depends_on for steps")
			} else if !nodesArray || len(nodesList) == 0 {
				add("/edges", "top-level edges require a populated nodes graph")
			}
		}
	}

	// Dependency lists are bounded as one graph-wide budget. A single node
	// with tens of thousands of repeated dependencies is otherwise enough to
	// make cycle/dangling-reference validation dominate an authoring request.
	edgesUsed := 0
	edgeLimitReported := false
	recordEdge := func(path string, from, to string, deps map[string][]string) {
		if edgesUsed >= maxDAGEdges {
			if !edgeLimitReported {
				add(path, fmt.Sprintf("graph must contain at most %d dependencies/edges", maxDAGEdges))
				edgeLimitReported = true
			}
			return
		}
		edgesUsed++
		deps[to] = append(deps[to], from)
	}
	boundedName := func(name string) string {
		if len(name) <= maxDAGName {
			return name
		}
		return name[:maxDAGName] + "..."
	}
	// The MCP flow projection decodes uses as []string. A malformed optional
	// field must fail validation rather than make the entire visual graph
	// disappear while the retained DAG still appears valid.
	validateUses := func(path string, object map[string]any) {
		value, present := object["uses"]
		if !present {
			return
		}
		uses, ok := value.([]any)
		if !ok {
			add(path+"/uses", "must be an array of strings")
			return
		}
		for i, use := range uses {
			if _, ok := use.(string); !ok {
				add(fmt.Sprintf("%s/uses/%d", path, i), "must be a string")
			}
			if issuesTruncated {
				return
			}
		}
	}
	if hasSteps {
		steps, ok := stepsAny.([]any)
		if !ok {
			add("/steps", "must be an array")
		} else {
			if len(steps) > maxDAGSteps {
				add("/steps", fmt.Sprintf("must contain at most %d steps", maxDAGSteps))
				steps = steps[:maxDAGSteps]
			}
			seen := map[string]bool{}
			deps := map[string][]string{}
			for i, raw := range steps {
				path := fmt.Sprintf("/steps/%d", i)
				step, ok := raw.(map[string]any)
				if !ok {
					add(path, "must be an object")
					continue
				}
				name, _ := step["name"].(string)
				if name == "" {
					add(path+"/name", "required string")
				} else if !stepNameRe.MatchString(name) {
					add(path+"/name", "must start with a letter and contain only letters, digits, '.', '_' or '-' (max 128 chars)")
				} else if seen[name] {
					add(path+"/name", fmt.Sprintf("duplicate step name %q", name))
				} else {
					seen[name] = true
				}
				validateUses(path, step)
				kind, _ := step["kind"].(string)
				if kind == "" {
					add(path+"/kind", "required string")
				} else if !allowedKinds[kind] {
					add(path+"/kind", fmt.Sprintf("must be one of step / sleep / await_signal / side_effect, got %q", boundedName(kind)))
				}
				if dep, ok := step["depends_on"]; ok {
					arr, ok := dep.([]any)
					if !ok {
						add(path+"/depends_on", "must be an array of strings")
					} else {
						if len(arr) > maxDAGEdges {
							add(path+"/depends_on", fmt.Sprintf("must contain at most %d dependencies", maxDAGEdges))
							arr = arr[:maxDAGEdges]
						}
						for di, d := range arr {
							depName, isString := d.(string)
							if !isString {
								add(fmt.Sprintf("%s/depends_on/%d", path, di), "must be a string")
							} else {
								recordEdge(path+"/depends_on", boundedName(depName), name, deps)
							}
						}
					}
				}
				if idem, ok := step["idempotency_key"]; ok {
					if idemString, ok := idem.(string); !ok {
						add(path+"/idempotency_key", "must be a string")
					} else if len(idemString) > maxDAGName {
						add(path+"/idempotency_key", fmt.Sprintf("must be at most %d bytes", maxDAGName))
					}
				}
				if to, ok := step["timeout_seconds"]; ok {
					if n, ok := to.(float64); !ok || n < 0 {
						add(path+"/timeout_seconds", "must be a non-negative number")
					}
				}
			}
			for name, names := range deps {
				for _, dep := range names {
					if dep == name {
						add("/steps", fmt.Sprintf("step %q cannot depend on itself", boundedName(name)))
					} else if !seen[dep] {
						add("/steps", fmt.Sprintf("step %q depends on unknown step %q", boundedName(name), boundedName(dep)))
					}
				}
			}
			if cycle := dependencyCycle(deps, seen); cycle != "" {
				add("/steps", "dependency cycle: "+cycle)
			}
		}
	}
	if hasNodes {
		nodes, ok := nodesAny.([]any)
		if !ok {
			add("/nodes", "must be an array")
		} else {
			if len(nodes) > maxDAGSteps {
				add("/nodes", fmt.Sprintf("must contain at most %d nodes", maxDAGSteps))
				nodes = nodes[:maxDAGSteps]
			}
			seen := map[string]bool{}
			for i, rawNode := range nodes {
				path := fmt.Sprintf("/nodes/%d", i)
				node, ok := rawNode.(map[string]any)
				if !ok {
					add(path, "must be an object")
					continue
				}
				kind, kindPresent := node["kind"]
				kindString, kindIsString := kind.(string)
				if !kindPresent || !kindIsString || kindString == "" {
					add(path+"/kind", "required string")
				} else if !allowedKinds[kindString] {
					add(path+"/kind", fmt.Sprintf("must be one of step / sleep / await_signal / side_effect, got %q", boundedName(kindString)))
				}
				for _, field := range []string{"id", "name", "label"} {
					if value, present := node[field]; present {
						if _, ok := value.(string); !ok {
							add(path+"/"+field, "must be a string")
						}
					}
				}
				if rawDepends, hasDepends := node["depends_on"]; hasDepends {
					// The nodes[] projection reads only top-level edges[]. A
					// depends_on on an individual node looks executable to an author
					// but would disappear from review and the editor canvas.
					depends, ok := rawDepends.([]any)
					if !ok || len(depends) > 0 {
						add(path+"/depends_on", "node dependencies require top-level edges; use edges[] for nodes")
					}
				}
				validateUses(path, node)
				name, _ := node["id"].(string)
				if name == "" {
					name, _ = node["name"].(string)
				}
				if name == "" {
					add(path, "requires non-empty id or name")
				} else if !stepNameRe.MatchString(name) {
					add(path, "id/name must start with a letter and contain only letters, digits, '.', '_' or '-' (max 128 chars)")
				} else if seen[name] {
					add(path, fmt.Sprintf("duplicate node %q", name))
				} else {
					seen[name] = true
				}
			}
			var edges []any
			if rawEdges, exists := raw["edges"]; exists {
				var edgeOK bool
				edges, edgeOK = rawEdges.([]any)
				if !edgeOK {
					add("/edges", "must be an array")
				}
			}
			if len(edges) > maxDAGEdges {
				add("/edges", fmt.Sprintf("must contain at most %d edges", maxDAGEdges))
				edges = edges[:maxDAGEdges]
			}
			deps := map[string][]string{}
			for i, rawEdge := range edges {
				path := fmt.Sprintf("/edges/%d", i)
				edge, ok := rawEdge.(map[string]any)
				if !ok {
					add(path, "must be an object")
					continue
				}
				from, _ := edge["from"].(string)
				to, _ := edge["to"].(string)
				if from == "" || to == "" {
					add(path, "requires string from and to")
					continue
				}
				if !seen[from] {
					add(path+"/from", fmt.Sprintf("unknown node %q", boundedName(from)))
				}
				if !seen[to] {
					add(path+"/to", fmt.Sprintf("unknown node %q", boundedName(to)))
				}
				recordEdge("/edges", boundedName(from), to, deps)
			}
			if cycle := dependencyCycle(deps, seen); cycle != "" {
				add("/edges", "dependency cycle: "+cycle)
			}
		}
	}
	// The optional block graph lives inside a durable step. Keep its schema
	// validation in one package shared by the MCP and dashboard projections,
	// so neither renderer can silently accept a malformed annotation that the
	// authoring gate would reject.
	_, blockIssues := flowblocks.Extract(raw)
	for _, issue := range blockIssues {
		add(issue.Path, issue.Message)
	}

	if len(issues) > 0 {
		return &DAGSchemaError{Issues: issues}
	}
	return nil
}

// duplicateJSONKey returns the first duplicate object key at any nesting
// depth. The JSON syntax itself is validated by json.Unmarshal in
// ValidateDAG; this walk exists solely to remove encoding/json's ambiguous
// last-wins behavior before schema checks inspect the decoded map.
func duplicateJSONKey(src []byte) (string, bool, error) {
	dec := json.NewDecoder(bytes.NewReader(src))
	key, duplicate, err := walkJSONValue(dec)
	if err != nil {
		return "", false, err
	}
	if duplicate {
		return key, true, nil
	}
	// A valid JSON value followed by another value is rejected by the
	// json.Unmarshal call in ValidateDAG. Consume the tail here only to keep
	// malformed input from being reported as a duplicate-key result.
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return "", false, errors.New("multiple JSON values")
		}
		return "", false, err
	}
	return "", false, nil
}

func walkJSONValue(dec *json.Decoder) (string, bool, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", false, err
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return "", false, nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return "", false, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return "", false, fmt.Errorf("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return key, true, nil
			}
			seen[key] = struct{}{}
			if duplicate, found, err := walkJSONValue(dec); err != nil || found {
				return duplicate, found, err
			}
		}
		if _, err := dec.Token(); err != nil {
			return "", false, err
		}
	case '[':
		for dec.More() {
			if key, found, err := walkJSONValue(dec); err != nil || found {
				return key, found, err
			}
		}
		if _, err := dec.Token(); err != nil {
			return "", false, err
		}
	}
	return "", false, nil
}

// dependencyCycle returns a stable, human-readable cycle when deps contains
// one. The graph and edge lists are bounded above, so this DFS is cheap and
// cannot be used as an unbounded work input by an MCP caller.
func dependencyCycle(deps map[string][]string, known map[string]bool) string {
	state := map[string]uint8{}
	stack := []string{}
	var visit func(string) string
	visit = func(name string) string {
		if state[name] == 1 {
			for i, item := range stack {
				if item == name {
					return strings.Join(append(stack[i:], name), " -> ")
				}
			}
			return name
		}
		if state[name] == 2 {
			return ""
		}
		state[name] = 1
		stack = append(stack, name)
		// A malformed legacy row may repeat an edge many times. Validation caps
		// the total, but sorting a small copy also makes the reported cycle
		// deterministic despite Go's randomized map iteration.
		neighbors := append([]string(nil), deps[name]...)
		sort.Strings(neighbors)
		for _, dep := range neighbors {
			if known[dep] {
				if cycle := visit(dep); cycle != "" {
					return cycle
				}
			}
		}
		stack = stack[:len(stack)-1]
		state[name] = 2
		return ""
	}
	names := make([]string, 0, len(known))
	for name := range known {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if cycle := visit(name); cycle != "" {
			return cycle
		}
	}
	return ""
}
