package server

import (
	"encoding/json"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/bright-interaction/reactor/internal/flowblocks"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

const (
	// A run detail page is a user-facing read path, so it must remain bounded
	// even when it is asked to render an old or hand-edited DAG that predates
	// registry validation. Keep these limits aligned with the authoring and MCP
	// flow budgets; exceeding them falls back to the ordinary step timeline.
	maxFlowDAGBytes = 1 << 20
	// Source shown in the dashboard and node editor is untrusted authoring
	// input. Keep its read projection at the same one MiB boundary as the
	// editor request cap so a retained source file cannot turn a page load or
	// node drawer response into an unbounded allocation. A truncated source is
	// never used for an edit or splice.
	maxFlowSourceBytes = 1 << 20
	maxFlowNodes       = 256
	maxFlowEdges       = 512
	// Validation permits repeated dependency declarations up to this raw
	// input bound. Count distinct rendered links against maxFlowEdges instead:
	// a duplicate-heavy DAG can still contain a late, meaningful branch.
	maxFlowInputEdges   = 4096
	maxFlowIdentifier   = 128
	maxFlowUsesPerNode  = 32
	maxFlowDisplayBytes = 256
	maxFlowRuntimeNodes = 256
	// A flow card stays compact even when one Step is called in a long loop.
	// The full bounded window remains visible in the step table below it.
	maxFlowAttemptPreview = 5
	// Run detail uses the same bounded control-plane read as the node drawer;
	// omitted values retain their durable byte count for an honest UI receipt.
	maxRunDetailStepRows         = 1000
	maxRunDetailBlockReceiptRows = 100
	maxRunDetailStepOutputBytes  = 64 << 10
	maxRunDetailStepErrorBytes   = 8 << 10
	maxFlowOutputDisplayBytes    = 4000
	maxRunDetailLogLines         = 1000
	maxRunDetailLogLineBytes     = 16 << 10
	maxRunDetailLogBytes         = 256 << 10
)

// This file renders a run's execution as a flow diagram: the workflow's step
// graph (from dag.json) laid out top-to-bottom in topological order, each node
// coloured by the run's actual per-step status, with the duration and an
// expandable peek of the data that step produced (output_jsonb). It is
// dependency-free (server-rendered HTML + the dashboard's own CSS) and shows
// "how it ran, where the data ended up, and how it flowed".

// flowNode is one step in the diagram, after overlaying run data on the DAG.
type flowNode struct {
	Name                      string
	Kind                      string
	Uses                      []string
	DependsOn                 []string
	DeclaredBlocks            *flowblocks.StepFlow
	BlockObservations         map[string]bool
	BlockReceipts             []journal.BlockReceipt
	BlockReceiptWindowOmitted bool
	Status                    string // succeeded | failed | running | suspended | cancelled | pending
	Output                    json.RawMessage
	OutputBytes               int
	OutputTruncated           bool
	Error                     string
	ErrorBytes                int
	ErrorTruncated            bool
	DurMS                     int64
	ObservedDurMS             int64
	ReceiptCount              int
	RecentReceipts            []flowAttemptReceipt
	level                     int
}

type flowAttemptReceipt struct {
	Seq     int64
	Attempt int
	Status  string
}

// runFlowDiagram builds the flow HTML for a run. Returns "" when the DAG can't
// be parsed or has no steps, so the caller can fall back to the plain timeline.
func runFlowDiagram(dagJSON []byte, steps []journal.StepRow) string {
	return runFlowDiagramWithHistory(dagJSON, steps, false)
}

// The diagram uses only the displayed step window. When older attempts were
// omitted, a node without a receipt is unobserved, not proven unexecuted.
func runFlowDiagramWithHistory(dagJSON []byte, steps []journal.StepRow, historyOmitted bool) string {
	return runFlowDiagramWithObservations(dagJSON, steps, historyOmitted, nil, nil, false)
}

func runFlowDiagramWithObservations(dagJSON []byte, steps []journal.StepRow, historyOmitted bool, receipts []journal.BlockReceipt, observed []journal.ObservedBlockIdentity, blockHistoryOmitted bool) string {
	nodes := parseDAGNodes(dagJSON)
	if len(nodes) == 0 {
		return ""
	}
	if observed != nil {
		for _, node := range nodes {
			node.BlockObservations = make(map[string]bool)
			node.BlockReceiptWindowOmitted = blockHistoryOmitted
		}
		for _, item := range observed {
			if node := nodes[item.StepName]; node != nil {
				node.BlockObservations[item.BlockID] = true
			}
		}
		for _, receipt := range receipts {
			if node := nodes[receipt.StepName]; node != nil {
				node.BlockReceipts = append(node.BlockReceipts, receipt)
			}
		}
	}
	runtimeTruncated := overlayRunStatus(nodes, steps)
	assignLevels(nodes)

	// Group by level, stable order within a level.
	maxLevel := 0
	for _, n := range nodes {
		if n.level > maxLevel {
			maxLevel = n.level
		}
	}
	levels := make([][]*flowNode, maxLevel+1)
	order := make([]*flowNode, 0, len(nodes))
	for _, n := range nodes {
		order = append(order, n)
	}
	sort.SliceStable(order, func(i, j int) bool { return order[i].Name < order[j].Name })
	for _, n := range order {
		levels[n.level] = append(levels[n.level], n)
	}

	var b strings.Builder
	b.WriteString(`<h2>Flow</h2>`)
	b.WriteString(flowSummary(order, historyOmitted))
	if runtimeTruncated {
		b.WriteString(`<p class="warn">Some recorded runtime-only steps were omitted from this bounded flow; the step timeline below remains authoritative.</p>`)
	}
	b.WriteString(`<div class="flow">`)
	for _, row := range levels {
		if len(row) == 0 {
			continue
		}
		b.WriteString(renderFlowIncomingEdges(row))
		b.WriteString(`<div class="flow-row">`)
		for _, n := range row {
			b.WriteString(renderFlowNode(n, historyOmitted))
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// A row can have several unrelated steps, and an edge may skip a topological
// level. An anonymous arrow between whole rows would invent connections. Show
// each declared source and target instead; runtime-only steps have no declared
// dependency edges and therefore cannot acquire one through the layout.
func renderFlowIncomingEdges(row []*flowNode) string {
	var b strings.Builder
	for _, node := range row {
		for _, dep := range node.DependsOn {
			if b.Len() == 0 {
				b.WriteString(`<div class="flow-edges" role="list" aria-label="Declared dependency edges">`)
			}
			fmt.Fprintf(&b, `<span class="flow-edge" role="listitem"><code>%s</code> &rarr; <code>%s</code></span>`,
				template.HTMLEscapeString(boundFlowDisplay(dep)), template.HTMLEscapeString(boundFlowDisplay(node.Name)))
		}
	}
	if b.Len() > 0 {
		b.WriteString(`</div>`)
	}
	return b.String()
}

func flowSummary(nodes []*flowNode, historyOmitted bool) string {
	var ran, ok, failed int
	var totalMS int64
	for _, n := range nodes {
		if n.ReceiptCount > 0 {
			ran++
		}
		switch n.Status {
		case "succeeded":
			ok++
		case "failed", "failed_dlq":
			failed++
		}
		totalMS += n.ObservedDurMS
	}
	unseenLabel := "not run"
	if historyOmitted {
		unseenLabel = "not observed in displayed window"
	}
	return fmt.Sprintf(`<p class="muted">%d steps &middot; %d succeeded &middot; %d failed &middot; %d %s &middot; %s compute across shown attempts</p><p class="flow-note">Card status is the latest displayed attempt. Named arrows show declared dependencies; row position is topological, not a runtime trace. Runtime step receipts show the actual path. Inner-step blocks are author-declared; observed merges and splits can additionally have value-free, SDK-reported receipts. Branch predicates, error paths, loops/iteration, aggregation, and data transforms inside Go nodes are not inferred.</p>`,
		len(nodes), ok, failed, len(nodes)-ran, unseenLabel, fmtDurMS(totalMS))
}

func renderFlowNode(n *flowNode, historyOmitted bool) string {
	status := n.Status
	if status == "" {
		status = "pending"
	}
	status = boundFlowDisplay(status)
	statusLabel := status
	if historyOmitted && n.ReceiptCount == 0 {
		statusLabel = "not observed"
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<div class="flow-node flow-%s">`, template.HTMLEscapeString(status))
	b.WriteString(`<div class="flow-node-body">`)

	dur := ""
	if n.DurMS > 0 {
		dur = `<span class="flow-dur">` + fmtDurMS(n.DurMS) + `</span>`
	}
	fmt.Fprintf(&b, `<div class="flow-node-head"><span class="flow-name">%s</span><span class="flow-status">%s%s</span></div>`,
		template.HTMLEscapeString(boundFlowDisplay(n.Name)), dur, template.HTMLEscapeString(statusLabel))

	// Meta: kind, what it touches, and where its inputs come from (lineage).
	var meta []string
	if n.Kind != "" {
		meta = append(meta, template.HTMLEscapeString(boundFlowDisplay(n.Kind)))
	}
	if len(n.Uses) > 0 {
		meta = append(meta, "uses "+template.HTMLEscapeString(joinBoundFlowValues(n.Uses)))
	}
	if len(n.DependsOn) > 0 {
		meta = append(meta, "from "+template.HTMLEscapeString(joinBoundFlowValues(n.DependsOn)))
	}
	if len(meta) > 0 {
		b.WriteString(`<div class="flow-meta">` + strings.Join(meta, " &middot; ") + `</div>`)
	}
	if n.ReceiptCount > 0 {
		latest := n.RecentReceipts[len(n.RecentReceipts)-1]
		receiptLabel := "attempt receipts"
		if n.ReceiptCount == 1 {
			receiptLabel = "attempt receipt"
		}
		fmt.Fprintf(&b, `<div class="flow-meta">%d %s shown &middot; latest %s, attempt %d</div>`,
			n.ReceiptCount, receiptLabel, flowCallLabel(latest.Seq), latest.Attempt)
		if n.ReceiptCount > 1 {
			fmt.Fprintf(&b, `<details class="flow-data"><summary>Last %d attempt receipts</summary>`, len(n.RecentReceipts))
			if n.ReceiptCount > len(n.RecentReceipts) {
				fmt.Fprintf(&b, `<p class="flow-meta">Showing the last %d of %d attempts on this card; see the Steps table for the displayed window.</p>`, len(n.RecentReceipts), n.ReceiptCount)
			}
			b.WriteString(`<ol>`)
			for _, receipt := range n.RecentReceipts {
				fmt.Fprintf(&b, `<li>%s, attempt %d &middot; %s</li>`, flowCallLabel(receipt.Seq), receipt.Attempt,
					template.HTMLEscapeString(boundFlowDisplay(receipt.Status)))
			}
			b.WriteString(`</ol></details>`)
		}
	}
	if n.DeclaredBlocks != nil {
		fmt.Fprintf(&b, `<details class="flow-data wf-block-step"><summary>%d author-declared visual blocks`, len(n.DeclaredBlocks.Blocks))
		if n.BlockObservations != nil {
			observedCount := 0
			for _, block := range n.DeclaredBlocks.Blocks {
				if n.BlockObservations[block.ID] {
					observedCount++
				}
			}
			fmt.Fprintf(&b, ` &middot; %d SDK-reported block IDs in this run`, observedCount)
		}
		b.WriteString(`</summary>`)
		if n.BlockObservations != nil {
			b.WriteString(renderDeclaredStepFlowSummaryWithObservations(*n.DeclaredBlocks, n.BlockObservations, n.BlockReceipts, n.BlockReceiptWindowOmitted))
		} else {
			b.WriteString(renderDeclaredStepFlowSummary(*n.DeclaredBlocks))
		}
		b.WriteString(`</details>`)
	}

	// Data peek: where the data ends up. Failed steps show the error instead.
	switch {
	case n.ErrorTruncated:
		b.WriteString(`<details class="flow-data"><summary>error</summary><pre class="flow-err">` +
			template.HTMLEscapeString(flowOmittedValue("error", n.ErrorBytes)) + `</pre></details>`)
	case n.Error != "":
		b.WriteString(`<details class="flow-data"><summary>error</summary><pre class="flow-err">` +
			template.HTMLEscapeString(truncate(n.Error, 1200)) + `</pre></details>`)
	case n.OutputTruncated:
		b.WriteString(`<details class="flow-data"><summary>output</summary><pre>` +
			template.HTMLEscapeString(flowOmittedValue("output", n.OutputBytes)) + `</pre></details>`)
	case len(n.Output) > maxRunDetailStepOutputBytes:
		b.WriteString(`<details class="flow-data"><summary>output</summary><pre>` +
			template.HTMLEscapeString(flowOmittedValue("output", len(n.Output))) + `</pre></details>`)
	case len(n.Output) > 0 && string(n.Output) != "null":
		b.WriteString(`<details class="flow-data"><summary>output</summary><pre>` +
			template.HTMLEscapeString(truncate(prettyJSON(string(n.Output)), maxFlowOutputDisplayBytes)) + `</pre></details>`)
	case status == "pending":
		if historyOmitted {
			b.WriteString(`<div class="flow-meta muted">no attempt in displayed window</div>`)
		} else {
			b.WriteString(`<div class="flow-meta muted">not run</div>`)
		}
	default:
		b.WriteString(`<div class="flow-meta muted">no output</div>`)
	}

	b.WriteString(`</div></div>`)
	return b.String()
}

func flowCallLabel(seq int64) string {
	if seq < 1 {
		return "legacy call (ordinal unavailable)"
	}
	return fmt.Sprintf("call #%d", seq)
}

func flowOmittedValue(kind string, bytes int) string {
	if bytes <= 0 {
		return kind + " omitted (durable value exceeds the dashboard read bound)"
	}
	return fmt.Sprintf("%s omitted (%d durable bytes exceed the dashboard read bound)", kind, bytes)
}

func boundFlowDisplay(value string) string {
	// Workflow names and labels can come from imported legacy rows. Normalize
	// the complete string before applying the byte budget so an arbitrary
	// truncation boundary cannot leave malformed UTF-8 in the rendered HTML.
	// The dashboard is also consumed by browser automation, where malformed
	// text can make the flow and its accessible labels disagree.
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= maxFlowDisplayBytes {
		return value
	}
	const suffix = "..."
	limit := maxFlowDisplayBytes - len(suffix)
	if limit <= 0 {
		return suffix
	}
	prefix := value[:limit]
	for len(prefix) > 0 && !utf8.ValidString(prefix) {
		prefix = prefix[:len(prefix)-1]
	}
	return prefix + suffix
}

func joinBoundFlowValues(values []string) string {
	omitted := 0
	if len(values) > maxFlowUsesPerNode {
		omitted = len(values) - maxFlowUsesPerNode
		values = values[:maxFlowUsesPerNode]
	}
	bounded := make([]string, 0, len(values))
	for _, value := range values {
		bounded = append(bounded, boundFlowDisplay(value))
	}
	joined := strings.Join(bounded, ", ")
	if omitted > 0 {
		joined += fmt.Sprintf(" (+%d more; see named arrows)", omitted)
	}
	return joined
}

// parseDAGNodes reads the dag.json into flow nodes, tolerating both the
// steps[]+depends_on shape and the nodes[]/edges[] shape.
func parseDAGNodes(src []byte) map[string]*flowNode {
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
	if len(src) == 0 || len(src) > maxFlowDAGBytes || json.Unmarshal(src, &dag) != nil {
		return nil
	}
	if (len(dag.Steps) > 0 && len(dag.Steps) > maxFlowNodes) ||
		(len(dag.Steps) == 0 && (len(dag.Nodes) > maxFlowNodes || len(dag.Edges) > maxFlowInputEdges)) {
		return nil
	}
	nodes := map[string]*flowNode{}
	inputEdges := 0
	for _, s := range dag.Steps {
		inputEdges += len(s.DependsOn)
		if inputEdges > maxFlowInputEdges {
			return nil
		}
		if s.Name == "" {
			continue
		}
		if len(s.Name) > maxFlowIdentifier {
			return nil
		}
		if len(nodes) >= maxFlowNodes {
			return nil
		}
		if _, exists := nodes[s.Name]; exists {
			continue
		}
		// Dependency links are graph structure, not display metadata. Limiting
		// them to maxFlowUsesPerNode (32) silently hid valid merge fan-in in
		// the run view; keep the full bounded list until the graph-wide edge
		// budget below is checked.
		nodes[s.Name] = &flowNode{Name: s.Name, Kind: s.Kind, Uses: boundedFlowValues(s.Uses), DependsOn: s.DependsOn}
	}
	// Match the browser renderer's precedence for stale mixed-encoding rows:
	// a non-empty steps[] is the executable representation, so visual nodes
	// are ignored rather than merged (which could surface a second node with
	// the same id but a different kind).
	if len(dag.Steps) == 0 {
		for _, n := range dag.Nodes {
			name := n.ID
			if name == "" {
				name = n.Name
			}
			if name == "" {
				continue
			}
			if len(name) > maxFlowIdentifier {
				return nil
			}
			if _, ok := nodes[name]; !ok {
				if len(nodes) >= maxFlowNodes {
					return nil
				}
				kind := n.Kind
				if n.Label != "" && kind == "" {
					kind = n.Label
				}
				nodes[name] = &flowNode{Name: name, Kind: kind, Uses: boundedFlowValues(n.Uses)}
			}
		}
	}
	// Normalize dependencies from the steps encoding before adding visual
	// edges. This both drops dangling lineage and lets one graph-wide edge
	// budget cover the two representations.
	usedEdges := 0
	for _, node := range nodes {
		filtered := node.DependsOn[:0]
		for _, dep := range node.DependsOn {
			if dep != node.Name && nodes[dep] != nil {
				filtered = appendUnique(filtered, dep)
			}
		}
		node.DependsOn = filtered
		usedEdges += len(filtered)
		if usedEdges > maxFlowEdges {
			return nil
		}
	}
	// edges[] belong to the nodes[] encoding. A stale mixed row must not
	// add visual-only edges to the executable steps[] graph.
	if len(dag.Steps) == 0 {
		for _, e := range dag.Edges {
			if e.To == "" || e.From == "" || e.To == e.From {
				continue
			}
			// A malformed edge must not invent a node that was absent from the
			// validated graph. Such an invented node is especially misleading on a
			// run page because it looks executable but has no source definition.
			if nodes[e.To] == nil || nodes[e.From] == nil {
				continue
			}
			before := len(nodes[e.To].DependsOn)
			updated := appendUnique(nodes[e.To].DependsOn, e.From)
			if len(updated) == before {
				continue
			}
			if usedEdges >= maxFlowEdges {
				return nil
			}
			nodes[e.To].DependsOn = updated
			usedEdges++
		}
	}
	// The block annotation is retained review metadata, not a second set of
	// executable or status-bearing nodes. Attach it only when the entire
	// bounded annotation validates; otherwise the durable step timeline is
	// still rendered without a misleading partial inner graph.
	projection := flowblocks.FromDAG(src, maxFlowDAGBytes)
	if projection.Complete {
		for i := range projection.Steps {
			flow := &projection.Steps[i]
			if node := nodes[flow.Step]; node != nil {
				node.DeclaredBlocks = flow
			}
		}
	}
	return nodes
}

func boundedFlowValues(values []string) []string {
	if len(values) > maxFlowUsesPerNode {
		values = values[:maxFlowUsesPerNode]
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

// overlayRunStatus stamps each node with the latest displayed attempt and a
// bounded preview of repeated calls/retries. Nodes without receipts stay pending.
func overlayRunStatus(nodes map[string]*flowNode, steps []journal.StepRow) bool {
	truncated := false
	for i := range steps {
		s := steps[i]
		n := nodes[s.StepName]
		if n == nil {
			// A step the DAG didn't declare is useful runtime evidence, but it is
			// not part of the reviewed executable graph. Keep it visible for
			// diagnosis while labelling it explicitly so the run page cannot be
			// mistaken for an executable-flow projection.
			if len(nodes) >= maxFlowRuntimeNodes || s.StepName == "" || len(s.StepName) > maxFlowIdentifier {
				truncated = true
				continue
			}
			n = &flowNode{Name: s.StepName, Kind: "runtime-only"}
			nodes[s.StepName] = n
		}
		n.Status = s.Status
		n.ReceiptCount++
		n.RecentReceipts = append(n.RecentReceipts, flowAttemptReceipt{Seq: s.Seq, Attempt: s.Attempt, Status: s.Status})
		if len(n.RecentReceipts) > maxFlowAttemptPreview {
			n.RecentReceipts = n.RecentReceipts[1:]
		}
		n.Output = s.OutputJSONB
		n.OutputBytes = s.OutputBytes
		n.OutputTruncated = s.OutputTruncated
		n.Error = s.ErrorText
		n.ErrorBytes = s.ErrorBytes
		n.ErrorTruncated = s.ErrorTruncated
		n.DurMS = 0
		if !s.StartedAt.IsZero() && !s.FinishedAt.IsZero() && !s.FinishedAt.Before(s.StartedAt) {
			n.DurMS = s.FinishedAt.Sub(s.StartedAt).Milliseconds()
			n.ObservedDurMS += n.DurMS
		}
	}
	for _, n := range nodes {
		if n.Status == "" {
			n.Status = "pending"
		}
	}
	return truncated
}

// assignLevels computes each node's topological depth (longest path from a
// root) for the row layout. Kahn's algorithm is deliberately iterative: old
// rows can contain cycles and must never turn a dashboard request into a
// recursive walk. Any cycle members are left at level zero so the diagram
// remains finite and the ordinary timeline still gives the authoritative
// execution view.
func assignLevels(nodes map[string]*flowNode) {
	indegree := make(map[string]int, len(nodes))
	out := make(map[string][]string, len(nodes))
	for name := range nodes {
		indegree[name] = 0
	}
	for name, n := range nodes {
		seenDeps := map[string]bool{}
		for _, dep := range n.DependsOn {
			if dep == name || seenDeps[dep] || nodes[dep] == nil {
				continue
			}
			seenDeps[dep] = true
			indegree[name]++
			out[dep] = append(out[dep], name)
		}
	}
	queue := make([]string, 0, len(nodes))
	for name, degree := range indegree {
		if degree == 0 {
			queue = append(queue, name)
		}
	}
	sort.Strings(queue)
	processed := 0
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		processed++
		for _, child := range out[name] {
			if nodes[child].level < nodes[name].level+1 {
				nodes[child].level = nodes[name].level + 1
			}
			indegree[child]--
			if indegree[child] == 0 {
				queue = append(queue, child)
			}
		}
		if len(queue) > 1 {
			sort.Strings(queue)
		}
	}
	if processed != len(nodes) {
		for name, degree := range indegree {
			if degree > 0 {
				nodes[name].level = 0
			}
		}
	}
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func fmtDurMS(ms int64) string {
	switch {
	case ms <= 0:
		return "0ms"
	case ms < 1000:
		return fmt.Sprintf("%dms", ms)
	case ms < 60000:
		return fmt.Sprintf("%.1fs", float64(ms)/1000)
	default:
		return fmt.Sprintf("%.1fm", float64(ms)/60000)
	}
}
