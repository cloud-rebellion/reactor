// Package flowblocks validates and projects author-declared data/control
// blocks inside a durable workflow step. These annotations are review data:
// they do not create executable nodes, affect replay, or prove that arbitrary
// Go source actually calls the named SDK helpers.
package flowblocks

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"unicode"

	sdkblocks "github.com/bright-interaction/reactor/sdk/blocks"
)

const (
	MaxBlocksPerStep = 32
	MaxEdgesPerStep  = 64
	MaxBlocksTotal   = 256
	MaxEdgesTotal    = 512
	MaxLabelBytes    = 128
	MaxRouteBytes    = 64
	maxIssues        = 64
)

var blockID = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,127}$`)

// The kind describes an author's intended pure operation, not a new durable
// execution primitive. A custom kind makes arbitrary Go logic visible without
// pretending that it matches a built-in helper.
var kinds = map[string]bool{
	"if": true, "switch": true, "split": true, "iterate": true,
	"aggregate": true, "merge": true, "map": true, "filter": true,
	"reduce": true, "group_by": true, "sort": true, "limit": true,
	"chunk": true, "flatten": true, "zip": true, "join": true,
	"unique": true, "coalesce": true, "custom": true,
}

type Issue struct {
	Path    string
	Message string
}

type Block struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Label   string `json:"label,omitempty"`
	Mode    string `json:"mode,omitempty"`
	Key     string `json:"key,omitempty"`
	MaxRows int    `json:"max_rows,omitempty"`
}

// SupportsSDKObservation reports whether an optional value-free runtime
// observer exists for this declared shape. It does not say the authored Go
// uses that observer or that a reported call proves arbitrary child behavior.
func SupportsSDKObservation(block Block) bool {
	if block.Kind == "split" || block.Kind == "iterate" || block.Kind == "aggregate" {
		return block.Mode == "" && block.MaxRows == 0
	}
	if block.Kind != "merge" || block.MaxRows < 1 || block.MaxRows > sdkblocks.MaxJoinRows {
		return false
	}
	switch block.Mode {
	case "inner_join", "left_join", "right_join", "full_join":
		return true
	default:
		return false
	}
}

// Merge settings are retained review data, not an assertion that the helper
// executed. A source check separately confirms a direct merge helper call.
var mergeModes = map[string]struct{ bounded, keyed bool }{
	"append":                 {},
	"inner_join":             {bounded: true, keyed: true},
	"left_join":              {bounded: true, keyed: true},
	"right_join":             {bounded: true, keyed: true},
	"full_join":              {bounded: true, keyed: true},
	"position_keep_all":      {bounded: true},
	"position_truncate":      {},
	"all_pairs":              {bounded: true},
	"left_enrich_last_right": {keyed: true},
	"map_override":           {},
}

type Edge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Route string `json:"route,omitempty"`
}

type StepFlow struct {
	Step   string  `json:"step"`
	Blocks []Block `json:"blocks"`
	Edges  []Edge  `json:"edges"`
}

type Projection struct {
	Provenance       string     `json:"provenance"`
	Complete         bool       `json:"complete"`
	BehaviorVerified bool       `json:"behavior_verified"`
	BlockCount       int        `json:"block_count"`
	EdgeCount        int        `json:"edge_count"`
	Steps            []StepFlow `json:"steps"`
	Note             string     `json:"note"`
}

const declaredNote = "Author-declared visual blocks inside durable steps. They are retained review annotations, not independently executable nodes or verified Go call traces. Durable steps have host-recorded outcomes; observed joins, splits, iterations, and aggregations may also have value-free SDK-reported receipts. Inspect source to confirm block behavior."
const unavailableNote = "No per-step visual blocks were declared. Pure Go control flow and data operations inside durable steps cannot be inferred from the dependency graph."

// FromDAG returns a bounded, all-or-nothing projection for MCP and dashboard
// readers. Legacy malformed annotations are never rendered as a partial flow.
func FromDAG(src []byte, maxBytes int) Projection {
	out := Projection{Provenance: "unavailable", Complete: true, Steps: []StepFlow{}, Note: unavailableNote}
	if maxBytes <= 0 || len(src) > maxBytes {
		out.Complete = false
		out.Note = "The retained DAG exceeds the bounded visual-block projection."
		return out
	}
	if len(src) == 0 {
		return out
	}
	var raw map[string]any
	if json.Unmarshal(src, &raw) != nil {
		out.Complete = false
		out.Note = "The retained DAG is not valid JSON; visual blocks are unavailable."
		return out
	}
	// A legacy row may predate registry's duplicate-key gate. Last-wins JSON
	// decoding would let an attacker make the displayed block graph disagree
	// with another parser's interpretation of the same retained bytes.
	if duplicateKey(src) {
		out.Provenance = "invalid_annotation"
		out.Complete = false
		out.Note = "The retained DAG has duplicate JSON keys; visual blocks are unavailable."
		return out
	}
	flows, issues := Extract(raw)
	if len(issues) > 0 {
		out.Provenance = "invalid_annotation"
		out.Complete = false
		out.Note = "The retained visual-block annotation is invalid; no partial block graph is shown."
		return out
	}
	if len(flows) == 0 {
		return out
	}
	out.Provenance = "author_declared_annotation"
	out.Steps = flows
	out.Note = declaredNote
	for _, flow := range flows {
		out.BlockCount += len(flow.Blocks)
		out.EdgeCount += len(flow.Edges)
	}
	return out
}

// Extract validates the optional visual_flow member of steps[] or nodes[].
// The caller must separately validate the executable DAG and reject duplicate
// JSON keys. It deliberately follows the same encoding precedence as the
// executable flow normalizers: non-empty steps[] wins over nodes[].
func Extract(raw map[string]any) ([]StepFlow, []Issue) {
	steps, _ := raw["steps"].([]any)
	nodes, _ := raw["nodes"].([]any)
	items := steps
	pathPrefix := "/steps"
	visual := false
	if len(steps) == 0 {
		items = nodes
		pathPrefix = "/nodes"
		visual = true
	}
	flows := make([]StepFlow, 0)
	issues := make([]Issue, 0)
	add := func(path, message string) {
		if len(issues) < maxIssues {
			issues = append(issues, Issue{Path: path, Message: message})
		}
	}
	blocksTotal, edgesTotal := 0, 0
	for i, item := range items {
		if i >= MaxBlocksTotal {
			// The executable graph itself is capped at 256 nodes. Avoid work on
			// malformed legacy arrays before its validator reports the overrun.
			break
		}
		node, ok := item.(map[string]any)
		if !ok {
			continue
		}
		value, hasFlow := node["visual_flow"]
		if !hasFlow {
			continue
		}
		path := pathPrefix + "/" + decimal(i) + "/visual_flow"
		step := str(node["name"])
		if visual {
			step = str(node["id"])
			if step == "" {
				step = str(node["name"])
			}
		}
		if !blockID.MatchString(step) {
			add(path, "visual flow requires a valid durable step id")
			continue
		}
		if str(node["kind"]) != "step" {
			add(path, "visual flow is supported only inside a durable step")
			continue
		}
		annotation, ok := value.(map[string]any)
		if !ok {
			add(path, "must be an object with blocks and optional edges")
			continue
		}
		for key := range annotation {
			if key != "blocks" && key != "edges" {
				add(path, "unknown visual flow field")
			}
		}
		blocks, ok := annotation["blocks"].([]any)
		if !ok || len(blocks) == 0 {
			add(path+"/blocks", "must be a non-empty array")
			continue
		}
		if len(blocks) > MaxBlocksPerStep {
			add(path+"/blocks", "must contain at most 32 blocks")
			blocks = blocks[:MaxBlocksPerStep]
		}
		if blocksTotal+len(blocks) > MaxBlocksTotal {
			add(path+"/blocks", "workflow must contain at most 256 visual blocks")
			break
		}
		blocksTotal += len(blocks)
		flow := StepFlow{Step: step, Blocks: make([]Block, 0, len(blocks)), Edges: []Edge{}}
		ids := make(map[string]bool, len(blocks))
		for bi, value := range blocks {
			bp := path + "/blocks/" + decimal(bi)
			block, ok := value.(map[string]any)
			if !ok {
				add(bp, "must be an object")
				continue
			}
			for key := range block {
				if key != "id" && key != "kind" && key != "label" && key != "mode" && key != "key" && key != "max_rows" {
					add(bp, "unknown visual block field")
				}
			}
			id := str(block["id"])
			kind := str(block["kind"])
			label := str(block["label"])
			if !blockID.MatchString(id) {
				add(bp+"/id", "must start with a letter and contain only letters, digits, '.', '_' or '-' (max 128 chars)")
				continue
			}
			if ids[id] {
				add(bp+"/id", "duplicate block id")
				continue
			}
			ids[id] = true
			if !kinds[kind] {
				add(bp+"/kind", "unknown visual block kind")
				continue
			}
			if _, exists := block["label"]; exists && !displayString(label, MaxLabelBytes) {
				add(bp+"/label", "must be a printable string of at most 128 bytes")
				continue
			}
			mode := str(block["mode"])
			_, hasMode := block["mode"]
			key := str(block["key"])
			_, hasKey := block["key"]
			maxRowsRaw, hasMaxRows := block["max_rows"]
			if hasMode || hasKey || hasMaxRows {
				if kind != "merge" || !hasMode {
					add(bp, "mode, key, and max_rows require a merge block with an explicit mode")
					continue
				}
				rules, valid := mergeModes[mode]
				if !valid {
					add(bp+"/mode", "unknown merge mode")
					continue
				}
				if hasKey && (!rules.keyed || !blockID.MatchString(key)) {
					add(bp+"/key", "key must be a non-sensitive identifier for a key-join mode")
					continue
				}
				if hasMaxRows != rules.bounded {
					add(bp+"/max_rows", "max_rows is required exactly for bounded merge modes")
					continue
				}
			}
			maxRows := 0
			if hasMaxRows {
				n, ok := maxRowsRaw.(float64)
				if !ok || n < 1 || n > sdkblocks.MaxJoinRows || n != float64(int(n)) {
					add(bp+"/max_rows", "must be a whole number within the SDK join bound")
					continue
				}
				maxRows = int(n)
			}
			flow.Blocks = append(flow.Blocks, Block{ID: id, Kind: kind, Label: label, Mode: mode, Key: key, MaxRows: maxRows})
		}
		if rawEdges, exists := annotation["edges"]; exists {
			edges, ok := rawEdges.([]any)
			if !ok {
				add(path+"/edges", "must be an array")
				continue
			}
			if len(edges) > MaxEdgesPerStep {
				add(path+"/edges", "must contain at most 64 edges")
				edges = edges[:MaxEdgesPerStep]
			}
			if edgesTotal+len(edges) > MaxEdgesTotal {
				add(path+"/edges", "workflow must contain at most 512 visual edges")
				break
			}
			edgesTotal += len(edges)
			seenEdges := make(map[[3]string]bool, len(edges))
			for ei, value := range edges {
				ep := path + "/edges/" + decimal(ei)
				edge, ok := value.(map[string]any)
				if !ok {
					add(ep, "must be an object")
					continue
				}
				for key := range edge {
					if key != "from" && key != "to" && key != "route" {
						add(ep, "unknown visual edge field")
					}
				}
				from, to, route := str(edge["from"]), str(edge["to"]), str(edge["route"])
				if !ids[from] || !ids[to] || from == to {
					add(ep, "from and to must name distinct blocks in the same step")
					continue
				}
				if _, exists := edge["route"]; exists && !displayString(route, MaxRouteBytes) {
					add(ep+"/route", "must be a printable string of at most 64 bytes")
					continue
				}
				key := [3]string{from, to, route}
				if seenEdges[key] {
					add(ep, "duplicate visual edge")
					continue
				}
				seenEdges[key] = true
				flow.Edges = append(flow.Edges, Edge{From: from, To: to, Route: route})
			}
		}
		if hasCycle(flow) {
			add(path+"/edges", "visual block graph must be acyclic")
		}
		flows = append(flows, flow)
	}
	return flows, issues
}

func hasCycle(flow StepFlow) bool {
	degree := make(map[string]int, len(flow.Blocks))
	children := make(map[string][]string, len(flow.Blocks))
	for _, block := range flow.Blocks {
		degree[block.ID] = 0
	}
	seen := make(map[[2]string]bool, len(flow.Edges))
	for _, edge := range flow.Edges {
		key := [2]string{edge.From, edge.To}
		if seen[key] {
			continue
		}
		seen[key] = true
		degree[edge.To]++
		children[edge.From] = append(children[edge.From], edge.To)
	}
	queue := make([]string, 0, len(degree))
	for id, n := range degree {
		if n == 0 {
			queue = append(queue, id)
		}
	}
	visited := 0
	for len(queue) > 0 {
		id := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		visited++
		for _, child := range children[id] {
			degree[child]--
			if degree[child] == 0 {
				queue = append(queue, child)
			}
		}
	}
	return visited != len(degree)
}

func str(value any) string {
	s, _ := value.(string)
	return s
}

func displayString(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes || strings.TrimSpace(value) == "" {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func decimal(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[n:])
}

func duplicateKey(src []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(src))
	found, err := valueHasDuplicateKey(decoder)
	return found || err != nil
}

func valueHasDuplicateKey(decoder *json.Decoder) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return false, nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return false, err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return true, nil
			}
			seen[key] = true
			if found, err := valueHasDuplicateKey(decoder); found || err != nil {
				return found, err
			}
		}
	case '[':
		for decoder.More() {
			if found, err := valueHasDuplicateKey(decoder); found || err != nil {
				return found, err
			}
		}
	default:
		return true, nil
	}
	_, err = decoder.Token()
	return false, err
}
