package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestRunFlowDiagram(t *testing.T) {
	t.Parallel()
	dag := []byte(`{"steps":[
		{"name":"fetch","kind":"step","uses":["http"]},
		{"name":"transform","kind":"step","depends_on":["fetch"]},
		{"name":"save","kind":"step","depends_on":["transform"]}
	]}`)
	start := time.Now().UTC()
	steps := []journal.StepRow{
		{StepName: "fetch", Attempt: 1, Status: "succeeded", OutputJSONB: json.RawMessage(`{"rows":3}`),
			StartedAt: start, FinishedAt: start.Add(120 * time.Millisecond)},
		{StepName: "transform", Attempt: 1, Status: "failed", ErrorText: "boom: bad row",
			StartedAt: start.Add(120 * time.Millisecond), FinishedAt: start.Add(130 * time.Millisecond)},
		// 'save' never ran -> pending.
	}

	html := runFlowDiagram(dag, steps)
	if html == "" {
		t.Fatal("expected flow HTML, got empty")
	}

	// Status overlay: succeeded / failed / pending classes present.
	for _, want := range []string{"flow-succeeded", "flow-failed", "flow-pending"} {
		if !strings.Contains(html, want) {
			t.Errorf("flow missing status class %s", want)
		}
	}
	// Data peek: the output data + the error are rendered (JSON is HTML-escaped
	// inside the <pre>, so match the key + value, not the raw quotes).
	if !strings.Contains(html, "rows") || !strings.Contains(html, "<pre>") {
		t.Error("flow should show fetch's output data (where data ends up)")
	}
	if !strings.Contains(html, "boom: bad row") {
		t.Error("flow should show the failed step's error")
	}
	// Lineage: transform shows it depends on fetch.
	if !strings.Contains(html, "from fetch") {
		t.Error("flow should show data lineage (from fetch)")
	}
	if !strings.Contains(html, "Named arrows show declared dependencies") || !strings.Contains(html, "Runtime step receipts show the actual path") || !strings.Contains(strings.ToLower(html), "branch predicates") {
		t.Error("flow should distinguish the declared graph from the runtime path")
	}
	// Topological order: fetch before transform before save.
	// Scope the order assertion to node labels; the explanatory flow note may
	// mention terms such as "transforms" before the rendered cards.
	fi, ti, si := strings.Index(html, `<span class="flow-name">fetch`), strings.Index(html, `<span class="flow-name">transform`), strings.Index(html, `<span class="flow-name">save`)
	if !(fi < ti && ti < si) {
		t.Fatalf("steps not in topological order: fetch=%d transform=%d save=%d", fi, ti, si)
	}
}

func TestRunFlowDiagramDistinguishesRepeatedCallsAndRetries(t *testing.T) {
	t.Parallel()
	dag := []byte(`{"steps":[{"name":"iterate","kind":"step"},{"name":"sink","kind":"step","depends_on":["iterate"]}]}`)
	start := time.Now().UTC()
	steps := []journal.StepRow{
		{StepName: "iterate", Seq: 1, Attempt: 1, Status: "succeeded", OutputJSONB: json.RawMessage(`"first"`), StartedAt: start, FinishedAt: start.Add(10 * time.Millisecond)},
		{StepName: "iterate", Seq: 2, Attempt: 1, Status: "failed", ErrorText: "retryable", StartedAt: start.Add(20 * time.Millisecond), FinishedAt: start.Add(40 * time.Millisecond)},
		{StepName: "iterate", Seq: 2, Attempt: 2, Status: "succeeded", OutputJSONB: json.RawMessage(`"second"`), StartedAt: start.Add(50 * time.Millisecond), FinishedAt: start.Add(80 * time.Millisecond)},
	}
	html := runFlowDiagram(dag, steps)
	for _, want := range []string{
		"3 attempt receipts shown", "latest call #2, attempt 2", "call #1, attempt 1", "call #2, attempt 1", "call #2, attempt 2",
		"60ms compute across shown attempts", "second", "flow-succeeded",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("repeated call flow missing %q: %s", want, html)
		}
	}
	if strings.Contains(html, "first</pre>") || strings.Contains(html, "retryable</pre>") {
		t.Fatalf("flow card displayed stale attempt output or error as latest: %s", html)
	}
	if strings.Count(html, `class="flow-edge"`) != 1 || strings.Contains(html, `<code>iterate</code> &rarr; <code>iterate</code>`) {
		t.Fatalf("repeated calls invented graph edges: %s", html)
	}
}

func TestRunFlowDiagramMarksUnseenNodesWhenHistoryOmitted(t *testing.T) {
	t.Parallel()
	dag := []byte(`{"steps":[{"name":"early","kind":"step"},{"name":"late","kind":"step"}]}`)
	html := runFlowDiagramWithHistory(dag, []journal.StepRow{{StepName: "late", Seq: 1001, Attempt: 1, Status: "succeeded"}}, true)
	if !strings.Contains(html, "1 not observed in displayed window") || !strings.Contains(html, "no attempt in displayed window") || strings.Contains(html, "not run") {
		t.Fatalf("bounded history falsely marked an unseen node unexecuted: %s", html)
	}
}

func TestRunFlowDiagramBoundsRepeatPreview(t *testing.T) {
	t.Parallel()
	dag := []byte(`{"steps":[{"name":"repeat","kind":"step"}]}`)
	steps := make([]journal.StepRow, maxFlowAttemptPreview+2)
	for i := range steps {
		steps[i] = journal.StepRow{StepName: "repeat", Seq: int64(i + 1), Attempt: 1, Status: "succeeded"}
	}
	html := runFlowDiagram(dag, steps)
	if !strings.Contains(html, "7 attempt receipts shown") || !strings.Contains(html, "Showing the last 5 of 7 attempts") || strings.Contains(html, "<li>call #1,") || !strings.Contains(html, "<li>call #7,") {
		t.Fatalf("repeated receipt preview not bounded or not explained: %s", html)
	}
}

func TestRunFlowDiagramDoesNotCarryOldDurationIntoRunningAttempt(t *testing.T) {
	t.Parallel()
	start := time.Now().UTC()
	dag := []byte(`{"steps":[{"name":"repeat","kind":"step"}]}`)
	html := runFlowDiagram(dag, []journal.StepRow{
		{StepName: "repeat", Seq: 1, Attempt: 1, Status: "succeeded", StartedAt: start, FinishedAt: start.Add(50 * time.Millisecond)},
		{StepName: "repeat", Seq: 2, Attempt: 1, Status: "running", StartedAt: start.Add(time.Second)},
	})
	if !strings.Contains(html, `class="flow-node flow-running"`) || !strings.Contains(html, "50ms compute across shown attempts") || strings.Contains(html, `class="flow-dur"`) {
		t.Fatalf("latest in-flight attempt inherited an earlier duration: %s", html)
	}
}

func TestRunFlowDiagramShowsOnlyDeclaredSplitAndMergeEdges(t *testing.T) {
	t.Parallel()
	dag := []byte(`{"nodes":[{"id":"left","kind":"step"},{"id":"right","kind":"step"},{"id":"split-child","kind":"step"},{"id":"merge-child","kind":"step"}],"edges":[{"from":"left","to":"split-child"},{"from":"left","to":"merge-child"},{"from":"right","to":"merge-child"}]}`)
	html := runFlowDiagram(dag, nil)
	for _, edge := range []string{
		`<code>left</code> &rarr; <code>split-child</code>`,
		`<code>left</code> &rarr; <code>merge-child</code>`,
		`<code>right</code> &rarr; <code>merge-child</code>`,
	} {
		if !strings.Contains(html, edge) {
			t.Fatalf("declared edge %q absent from run flow: %s", edge, html)
		}
	}
	if strings.Count(html, `class="flow-edge"`) != 3 || strings.Contains(html, `<code>right</code> &rarr; <code>split-child</code>`) || strings.Contains(html, `class="flow-conn"`) {
		t.Fatalf("run flow invented an undeclared row connection: %s", html)
	}
}

func TestRunFlowDiagramPreservesMergeFanInBeyondDisplayCap(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString(`{"steps":[`)
	for i := 0; i <= maxFlowUsesPerNode; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"name":"input-%d","kind":"step"}`, i)
	}
	b.WriteString(`,{"name":"join","kind":"step","depends_on":[`)
	for i := 0; i <= maxFlowUsesPerNode; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"input-%d"`, i)
	}
	b.WriteString(`]}]}`)
	dag := []byte(b.String())
	nodes := parseDAGNodes(dag)
	if nodes["join"] == nil || len(nodes["join"].DependsOn) != maxFlowUsesPerNode+1 {
		t.Fatalf("merge fan-in lost declared dependencies: %#v", nodes["join"])
	}
	html := runFlowDiagram(dag, nil)
	if !strings.Contains(html, `<code>input-32</code> &rarr; <code>join</code>`) ||
		!strings.Contains(html, `(+1 more; see named arrows)`) ||
		strings.Count(html, `class="flow-edge"`) != maxFlowUsesPerNode+1 {
		t.Fatalf("run flow hid a valid merge input: %s", html)
	}
}

func TestRunFlowDiagramRetainsLateBranchAfterRepeatedInputEdges(t *testing.T) {
	t.Parallel()
	edges := make([]map[string]string, 0, 513)
	for i := 0; i < 512; i++ {
		edges = append(edges, map[string]string{"from": "source", "to": "first"})
	}
	// Put the distinct route after the repeated prefix that used to make the
	// run renderer reject the entire otherwise reviewable graph.
	edges = append(edges, map[string]string{"from": "source", "to": "late"})
	visual := map[string]any{
		"nodes": []map[string]string{{"id": "source", "kind": "step"}, {"id": "first", "kind": "step"}, {"id": "late", "kind": "step"}},
		"edges": edges,
	}
	visualDAG, err := json.Marshal(visual)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.ValidateDAG(visualDAG); err != nil {
		t.Fatalf("visual DAG should be schema-valid: %v", err)
	}
	visualHTML := runFlowDiagram(visualDAG, nil)
	if strings.Count(visualHTML, `class="flow-edge"`) != 2 ||
		!strings.Contains(visualHTML, `<code>source</code> &rarr; <code>late</code>`) {
		t.Fatalf("run flow omitted a late distinct visual route: %s", visualHTML)
	}

	deps := make([]string, 512)
	for i := range deps {
		deps[i] = "source"
	}
	stepsDAG, err := json.Marshal(map[string]any{"steps": []map[string]any{
		{"name": "source", "kind": "step"},
		{"name": "first", "kind": "step", "depends_on": deps},
		{"name": "late", "kind": "step", "depends_on": []string{"source"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.ValidateDAG(stepsDAG); err != nil {
		t.Fatalf("steps DAG should be schema-valid: %v", err)
	}
	stepsHTML := runFlowDiagram(stepsDAG, nil)
	if strings.Count(stepsHTML, `class="flow-edge"`) != 2 ||
		!strings.Contains(stepsHTML, `<code>source</code> &rarr; <code>late</code>`) {
		t.Fatalf("run flow omitted a late distinct dependency: %s", stepsHTML)
	}
}

func TestRunFlowDiagramRejectsMoreThan512DistinctEdges(t *testing.T) {
	t.Parallel()
	nodes := make([]map[string]string, 33)
	edges := make([]map[string]string, 0, 528)
	for i := range nodes {
		nodes[i] = map[string]string{"id": fmt.Sprintf("step-%d", i), "kind": "step"}
		for j := 0; j < i; j++ {
			edges = append(edges, map[string]string{"from": fmt.Sprintf("step-%d", j), "to": nodes[i]["id"]})
		}
	}
	dag, err := json.Marshal(map[string]any{"nodes": nodes, "edges": edges})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.ValidateDAG(dag); err != nil {
		t.Fatalf("dense graph should be schema-valid before projection bound: %v", err)
	}
	if got := runFlowDiagram(dag, nil); got != "" {
		t.Fatalf("run flow showed a partial %d-edge graph: %s", len(edges), got)
	}
}

func TestRunFlowDiagramEscapesLegacyDependencyNames(t *testing.T) {
	t.Parallel()
	dag := []byte(`{"steps":[{"name":"<script>","kind":"step"},{"name":"sink","kind":"step","depends_on":["<script>"]}]}`)
	html := runFlowDiagram(dag, nil)
	if strings.Contains(html, `<script>`) || !strings.Contains(html, `<code>&lt;script&gt;</code> &rarr; <code>sink</code>`) {
		t.Fatalf("legacy dependency name was not safely rendered: %s", html)
	}
}

func TestRunFlowDiagramEmptyDAG(t *testing.T) {
	t.Parallel()
	if got := runFlowDiagram(nil, nil); got != "" {
		t.Fatalf("nil DAG should yield no diagram, got %q", got)
	}
	if got := runFlowDiagram([]byte(`{"steps":[]}`), nil); got != "" {
		t.Fatalf("empty DAG should yield no diagram, got %q", got)
	}
}

func TestRunFlowDiagramLabelsUndeclaredRuntimeStepsAsRuntimeOnly(t *testing.T) {
	t.Parallel()
	dag := []byte(`{"steps":[{"name":"declared","kind":"step"}]}`)
	steps := []journal.StepRow{{StepName: "undeclared", Status: "succeeded"}}
	html := runFlowDiagram(dag, steps)
	if !strings.Contains(html, "runtime-only") {
		t.Fatalf("undeclared runtime step lacked runtime-only label: %s", html)
	}
}

func TestRunFlowDiagramLabelsOmittedStepData(t *testing.T) {
	t.Parallel()
	dag := []byte(`{"steps":[{"name":"fetch","kind":"step"}]}`)
	steps := []journal.StepRow{{
		StepName: "fetch", Status: "succeeded",
		OutputBytes: maxRunDetailStepOutputBytes + 1, OutputTruncated: true,
	}}
	html := runFlowDiagram(dag, steps)
	if !strings.Contains(html, "output omitted (") || strings.Contains(html, "no output") {
		t.Fatalf("flow omitted-output receipt missing or misleading: %s", html)
	}
}

func TestRunFlowDiagramReportsOmittedRuntimeOnlySteps(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString(`{"steps":[`)
	for i := 0; i < maxFlowRuntimeNodes; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"name":"step-%d","kind":"step"}`, i)
	}
	b.WriteString(`]}`)
	html := runFlowDiagram([]byte(b.String()), []journal.StepRow{{StepName: "runtime-extra", Status: "succeeded"}})
	if !strings.Contains(html, "runtime-only steps were omitted") {
		t.Fatalf("flow omitted runtime-only step without bounded warning: %s", html)
	}
}

func TestBoundFlowDisplayPreservesUTF8AtByteBoundary(t *testing.T) {
	t.Parallel()

	// Three-byte runes force the 256-byte display budget to cut through a
	// rune if the renderer slices the source string directly.
	got := boundFlowDisplay(strings.Repeat("界", maxFlowDisplayBytes))
	if !utf8.ValidString(got) {
		t.Fatalf("bound flow display is invalid UTF-8: %q", got)
	}
	if len([]byte(got)) > maxFlowDisplayBytes {
		t.Fatalf("bound flow display bytes = %d, want <= %d", len([]byte(got)), maxFlowDisplayBytes)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("bound flow display = %q, want truncation suffix", got)
	}
}

func TestParseDAGNodesDropsDanglingEdgesAndDependencies(t *testing.T) {
	t.Parallel()
	dag := []byte(`{"steps":[
		{"name":"known","kind":"step","depends_on":["missing"]},
		{"name":"next","kind":"step","depends_on":["known"]}
	],"edges":[{"from":"known","to":"missing"},{"from":"known","to":"next"}]}`)
	nodes := parseDAGNodes(dag)
	if len(nodes) != 2 {
		t.Fatalf("nodes = %#v, want only declared nodes", nodes)
	}
	if _, ok := nodes["missing"]; ok {
		t.Fatal("dangling edge invented a node")
	}
	if len(nodes["known"].DependsOn) != 0 {
		t.Fatalf("known dependencies = %#v, want dangling dependency removed", nodes["known"].DependsOn)
	}
	if len(nodes["next"].DependsOn) != 1 || nodes["next"].DependsOn[0] != "known" {
		t.Fatalf("next dependencies = %#v, want known", nodes["next"].DependsOn)
	}
}

func TestParseDAGNodesUsesExecutableStepsWhenMixed(t *testing.T) {
	t.Parallel()
	dag := []byte(`{"steps":[{"name":"send","kind":"step"}],"nodes":[
		{"id":"send","kind":"side_effect"},
		{"id":"visual-only","kind":"step"}
	]}`)
	nodes := parseDAGNodes(dag)
	if len(nodes) != 1 {
		t.Fatalf("mixed nodes = %#v, want steps representation only", nodes)
	}
	if nodes["send"] == nil || nodes["send"].Kind != "step" {
		t.Fatalf("mixed duplicate = %#v, want executable step kind", nodes["send"])
	}
}

func TestParseDAGNodesIgnoresVisualEdgesWhenStepsAreExecutable(t *testing.T) {
	t.Parallel()
	dag := []byte(`{"steps":[{"name":"first","kind":"step"},{"name":"second","kind":"step"}],"edges":[{"from":"first","to":"second"}]}`)
	nodes := parseDAGNodes(dag)
	if nodes["second"] == nil || len(nodes["second"].DependsOn) != 0 {
		t.Fatalf("visual-only edge changed executable steps graph: %#v", nodes)
	}
	if strings.Contains(runFlowDiagram(dag, nil), `class="flow-edge"`) {
		t.Fatal("run flow displayed an edge outside the executable steps encoding")
	}
}

func TestParseDAGNodesRejectsPathologicalGraphBounds(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString(`{"nodes":[`)
	for i := 0; i < maxFlowNodes+1; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":"node-%d","kind":"step"}`, i)
	}
	b.WriteString(`]}`)
	if nodes := parseDAGNodes([]byte(b.String())); nodes != nil {
		t.Fatalf("pathological graph returned %d nodes, want fallback", len(nodes))
	}

	oversized := []byte(`{"steps":[]}` + strings.Repeat(" ", maxFlowDAGBytes))
	if nodes := parseDAGNodes(oversized); nodes != nil {
		t.Fatal("oversized DAG should not be parsed")
	}
}

func TestAssignLevelsTerminatesOnCycle(t *testing.T) {
	t.Parallel()
	nodes := map[string]*flowNode{
		"a": {Name: "a", DependsOn: []string{"b"}},
		"b": {Name: "b", DependsOn: []string{"a"}},
	}
	assignLevels(nodes)
	if nodes["a"].level != 0 || nodes["b"].level != 0 {
		t.Fatalf("cycle levels = %d, %d; want bounded fallback level zero", nodes["a"].level, nodes["b"].level)
	}
}
