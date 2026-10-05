// dag-render.js: reads the dag.json shape from a <script type="application/json"
// id="dag-data"> island and renders it into the #dag-canvas div via cytoscape.
// Layout: top-down breadthfirst so workflow steps read like a vertical pipeline.
//
// Step kinds get distinct colours so the DAG conveys at-a-glance shape:
//   step          -> green
//   sleep         -> grey
//   await_signal  -> amber
//   side_effect   -> blue
//
// Clicking a node dispatches an "reactor:node-tap" event (detail.id = the step
// name) that workflow-editor.js listens for to open the code-editing drawer. We
// keep the two scripts decoupled via the event rather than sharing globals.
(function () {
    // The dashboard can be opened against old or hand-edited rows. Keep the
    // browser-side normalizer bounded even when the registry has not seen the
    // payload, and never use an ordinary object as an untrusted id set.
    var MAX_DAG_BYTES = 1 << 20;
    var MAX_NODES = 256;
    var MAX_EDGES = 512;
    // The validated DAG permits up to 4096 declared dependencies. Count
    // unique rendered edges separately so repeated declarations cannot hide
    // a later branch that MCP review and activation both retain.
    var MAX_INPUT_EDGES = 4096;
    var MAX_ID_LENGTH = 128;
    var MAX_LABEL_LENGTH = 256;

    var data = document.getElementById("dag-data");
    var canvas = document.getElementById("dag-canvas");
    if (!data || !canvas || typeof cytoscape !== "function") return;

    var sourceText = data.textContent || "";
    if (sourceText.length > MAX_DAG_BYTES) { incompleteGraph(); return; }
    var dag;
    try { dag = JSON.parse(sourceText || "{}"); } catch (e) { invalidGraph(); return; }
    if (!dag || typeof dag !== "object" || Array.isArray(dag)) { invalidGraph(); return; }
    // The server validates and bounds this separate projection before
    // embedding it. Keep it separate from the executable DAG: these blocks
    // are author-declared inner-step annotations, not inferred Go calls or
    // independent runtime nodes.
    var visualByStep = Object.create(null);
    var visualData = document.getElementById("step-flows-data");
    if (visualData && (visualData.textContent || "").length <= MAX_DAG_BYTES) {
        try {
            var projection = JSON.parse(visualData.textContent || "{}");
            if (projection.provenance === "author_declared_annotation" &&
                projection.complete === true && Array.isArray(projection.steps)) {
                projection.steps.slice(0, MAX_NODES).forEach(function (flow) {
                    if (flow && typeof flow.step === "string" && validVisualBlocks(flow.blocks)) {
                        visualByStep[flow.step] = flow;
                    }
                });
            }
        } catch (e) { /* The durable DAG remains renderable on its own. */ }
    }

    function validVisualBlocks(blocks) {
        return Array.isArray(blocks) && blocks.length > 0 && blocks.length <= 32;
    }
    // Authoring accepts both the legacy steps[] shape and the visual
    // nodes[]/edges[] shape.  Prefer a non-empty steps array when both are
    // present, but do not let an empty legacy array hide a populated visual
    // graph.
    var usesExecutableSteps = Array.isArray(dag.steps) && dag.steps.length > 0;
    var steps = usesExecutableSteps ? dag.steps :
        (Array.isArray(dag.nodes) ? dag.nodes : []);
    if (!steps.length) return;
    function incompleteGraph() {
        // A partial drawing can appear to prove a dependency or fan-out that
        // the review projection did not actually include. Keep the saved DAG
        // inspectable in the step table, but do not display a partial canvas.
        canvas.textContent = "Visual graph omitted: node or dependency limit exceeded. Inspect dag.json and the bounded MCP flow before reviewing this version.";
    }
    function invalidGraph() {
        // A legacy or hand-edited DAG can reach this read path even though
        // authoring would reject it. Omitting bad nodes/edges and drawing the
        // remainder would make an incomplete flow look ready for review.
        canvas.textContent = "Visual graph omitted: invalid or inconsistent nodes or dependencies. Inspect and repair dag.json before reviewing this version.";
    }
    if (steps.length > MAX_NODES ||
        (!usesExecutableSteps && Array.isArray(dag.edges) && dag.edges.length > MAX_INPUT_EDGES)) {
        incompleteGraph();
        return;
    }

    function own(obj, key) {
        return Object.prototype.hasOwnProperty.call(obj, key);
    }

    function validID(value) {
        if (typeof value !== "string" || value.length === 0 || value.length > MAX_ID_LENGTH || !value.trim()) return false;
        for (var i = 0; i < value.length; i++) {
            var code = value.charCodeAt(i);
            if (code < 0x20 || code === 0x7f) return false;
        }
        return true;
    }

    function nodeId(s) {
        if (!s || typeof s !== "object" || Array.isArray(s)) return "";
        // Match the server/MCP normalizers: steps use name, while visual
        // nodes use id and only fall back to the legacy name field.
        if (usesExecutableSteps) {
            return validID(s.name) ? s.name : "";
        }
        // An empty/null id is the accepted legacy form that falls back to
        // name. A non-string or non-empty invalid id is malformed and must
        // not silently become a different executable node.
        if (own(s, "id") && s.id !== "" && s.id !== null && typeof s.id !== "undefined") {
            return validID(s.id) ? s.id : "";
        }
        return validID(s.name) ? s.name : "";
    }

    function displayText(value, fallback) {
        var text = typeof value === "string" ? value : "";
        // Keep control characters from changing the apparent shape of a
        // label. IDs are rejected above; labels are merely made readable.
        text = text.replace(/[\u0000-\u001f\u007f]/g, " ").trim();
        if (!text) text = fallback;
        if (text.length > MAX_LABEL_LENGTH) text = text.slice(0, MAX_LABEL_LENGTH - 3) + "...";
        return text;
    }

    var edges = [];
    var nodes = [];
    var records = [];
    var seen = Object.create(null);
    var malformedGraph = false;
    // Keep each selected node bounded. An invalid or duplicate entry omits
    // the entire canvas; silently skipping it would change the reviewed flow.
    steps.slice(0, MAX_NODES).forEach(function (s) {
        var id = nodeId(s);
        if (!id || seen[id]) { malformedGraph = true; return; }
        seen[id] = true;
        var label = usesExecutableSteps ? id : (s && s.label);
        var kind = s && s.kind;
        var visual = visualByStep[id];
        var blockKinds = visual ? visual.blocks.slice(0, 3).map(function (b) {
            var kindText = displayText(b && b.kind, "custom");
            if (kindText === "merge" && b && b.mode) {
                kindText += ":" + displayText(String(b.mode).replace(/_/g, " "), "mode");
            }
            return kindText;
        }).join(" · ") : "";
        if (visual && visual.blocks.length > 3) blockKinds += " · +" + (visual.blocks.length - 3);
        nodes.push({
            data: {
                id: id,
                // Visual DAG nodes may carry a human-facing label separate
                // from their executable id. Use it in the canvas while the
                // node id remains stable for edge and editor lookups.
                label: displayText(label, id) + "\n" + displayText(kind, "step") +
                    (visual ? "\n" + blockKinds : ""),
                kind: displayText(kind, "step"),
                hasBlocks: !!visual
            }
        });
        records.push({ step: s, id: id });
    });
    if (malformedGraph) { invalidGraph(); return; }
    if (!nodes.length) return;

    var seenEdges = Object.create(null);
    var edgeLimitExceeded = false;
    function addEdge(from, to) {
        // Retained legacy rows may predate DAG validation. A missing source,
        // target, or self edge cannot be silently removed from the canvas:
        // that would display a different graph from the one under review.
        if (!validID(from) || !validID(to) || !seen[from] || !seen[to] || from === to) {
            malformedGraph = true;
            return;
        }
        var key = from + "\u0000" + to;
        if (seenEdges[key]) return;
        if (edges.length >= MAX_EDGES) {
            edgeLimitExceeded = true;
            return;
        }
        seenEdges[key] = true;
        edges.push({ data: { source: from, target: to } });
    }
    var inputEdges = 0;
    records.forEach(function (record) {
        if (!own(record.step, "depends_on")) return;
        if (!Array.isArray(record.step.depends_on) ||
            (!usesExecutableSteps && record.step.depends_on.length > 0)) {
            // nodes[] uses only top-level edges[]. A legacy depends_on here
            // must not create a route that MCP review and execution omit.
            malformedGraph = true;
            return;
        }
        if (usesExecutableSteps) inputEdges += record.step.depends_on.length;
    });
    if (malformedGraph) { invalidGraph(); return; }
    if (inputEdges > MAX_INPUT_EDGES) {
        incompleteGraph();
        return;
    }
    inputEdges = 0;
    for (var recordIndex = 0; usesExecutableSteps && recordIndex < records.length && inputEdges < MAX_INPUT_EDGES; recordIndex++) {
        var record = records[recordIndex];
        var dependencies = record.step && Array.isArray(record.step.depends_on) ? record.step.depends_on : [];
        for (var dependencyIndex = 0; dependencyIndex < dependencies.length && inputEdges < MAX_INPUT_EDGES; dependencyIndex++) {
            inputEdges++;
            addEdge(dependencies[dependencyIndex], record.id);
        }
    }
    // The visual-editor shape stores dependencies in a top-level edges array;
    // previously it was ignored and the fallback below drew a false linear
    // chain for every nodes[] graph.  That made the rendered flow disagree
    // with the validated graph and could mislead an operator about execution
    // order or fan-out.
    // edges[] belongs to the nodes[] encoding. A stale mixed row must not
    // append visual-only links to an executable steps[] dependency graph.
    if (!usesExecutableSteps && own(dag, "edges") && !Array.isArray(dag.edges)) {
        invalidGraph();
        return;
    }
    var declaredEdges = !usesExecutableSteps && Array.isArray(dag.edges) ? dag.edges.slice(0, MAX_INPUT_EDGES) : [];
    declaredEdges.forEach(function (e) {
        if (e && typeof e === "object" && !Array.isArray(e)) addEdge(e.from, e.to);
        else malformedGraph = true;
    });
    if (malformedGraph) { invalidGraph(); return; }
    if (edgeLimitExceeded) {
        incompleteGraph();
        return;
    }
    // Do not invent ordering when a workflow has no declared dependencies.
    // Independent steps and an intentionally disconnected visual graph must
    // remain visibly independent; a fabricated chain would tell an operator
    // that execution order or data flow exists where the stored DAG says it
    // does not. Cytoscape can lay out disconnected nodes without synthetic
    // edges.

    // Mark shortcut edges that skip one or more longest-path levels. Without
    // a bend, a direct split->merge edge can run through intermediate nodes
    // and disappear under another path in the customer canvas.
    var depth = Object.create(null), incoming = Object.create(null), outgoing = Object.create(null);
    nodes.forEach(function (node) {
        depth[node.data.id] = 0;
        incoming[node.data.id] = 0;
        outgoing[node.data.id] = [];
    });
    edges.forEach(function (edge) {
        incoming[edge.data.target]++;
        outgoing[edge.data.source].push(edge.data.target);
    });
    var ready = nodes.filter(function (node) { return incoming[node.data.id] === 0; }).map(function (node) { return node.data.id; });
    var visited = 0;
    while (ready.length) {
        var from = ready.shift();
        visited++;
        outgoing[from].forEach(function (to) {
            depth[to] = Math.max(depth[to], depth[from] + 1);
            if (--incoming[to] === 0) ready.push(to);
        });
    }
    if (visited !== nodes.length) { invalidGraph(); return; }
    edges.forEach(function (edge) {
        if (depth[edge.data.target] > depth[edge.data.source] + 1) edge.data.bypass = true;
    });

    var color = Object.create(null);
    color.step = "#15803D";
    color.sleep = "#A3A3A3";
    color.await_signal = "#D97706";
    color.side_effect = "#4F46E5";

    // Pull a couple of colours from the live theme so the graph matches light
    // and dark mode at render time.
    var css = getComputedStyle(document.documentElement);
    function v(name, fb) { return (css.getPropertyValue(name) || "").trim() || fb; }
    var accent = v("--accent", "#171717");
    var edgeColor = v("--border-strong", "#D4D4D4");

    var cy = cytoscape({
        container: canvas,
        elements: { nodes: nodes, edges: edges },
        // Put a fan-in node after its deepest declared predecessor. The
        // default shortest-path breadth-first level can place a merge next
        // to an early split when another branch has several durable steps.
        layout: { name: "breadthfirst", directed: true, maximal: true, padding: 16, spacingFactor: 1.4 },
        style: [
            {
                selector: "node",
                style: {
                    "background-color": function (ele) { return color[ele.data("kind")] || color.step; },
                    "label": "data(label)",
                    "text-wrap": "wrap",
                    "text-valign": "center",
                    "text-halign": "center",
                    "color": "#fff",
                    "font-size": 11,
                    "font-family": "ui-monospace, SFMono-Regular, monospace",
                    "text-max-width": 160,
                    "width": function (ele) { return ele.data("hasBlocks") ? 170 : 116; },
                    "height": function (ele) { return ele.data("hasBlocks") ? 92 : 52; },
                    "shape": "round-rectangle",
                    "border-width": 0
                }
            },
            {
                selector: "node.wf-selected",
                style: { "border-width": 3, "border-color": accent }
            },
            {
                selector: "edge",
                style: {
                    "width": 2,
                    "line-color": edgeColor,
                    "target-arrow-color": edgeColor,
                    "target-arrow-shape": "triangle",
                    "curve-style": "bezier"
                }
            },
            {
                selector: "edge[bypass]",
                style: { "curve-style": "unbundled-bezier", "control-point-distances": 140,
                    "control-point-weights": 0.5 }
            }
        ],
        wheelSensitivity: 0.2
    });

    window.__reactorCy = cy;

    // Hover affordance + click-to-edit.
    cy.on("mouseover", "node", function () { canvas.style.cursor = "pointer"; });
    cy.on("mouseout", "node", function () { canvas.style.cursor = "default"; });
    cy.on("tap", "node", function (evt) {
        cy.nodes().removeClass("wf-selected");
        evt.target.addClass("wf-selected");
        document.dispatchEvent(new CustomEvent("reactor:node-tap", {
            detail: { id: evt.target.id() }
        }));
    });

    // Let the drawer clear the selection highlight when it closes.
    document.addEventListener("reactor:drawer-close", function () {
        cy.nodes().removeClass("wf-selected");
    });
})();
