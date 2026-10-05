// workflow-editor.js: the n8n-style editor controller. Served from /assets so
// it satisfies CSP (script-src 'self'; no inline JS, no inline handlers).
//
// Two jobs:
//   1. Visual <-> Code view toggle on the workflow detail page.
//   2. Click a node in the visual DAG -> slide-in drawer on the right that
//      fetches just that node's Go source (GET .../node/{step}/code), lets the
//      operator edit it, and saves it back (POST same URL). The server splices
//      the snippet into the full file and runs the validator, so a bad edit is
//      rejected with the compiler's message shown inline in the drawer.
(function () {
    var editor = document.getElementById("wf-editor");
    if (!editor) return;

    var slug = editor.getAttribute("data-slug");
    var editable = editor.getAttribute("data-editable") === "true";
    var expectedVersion = editor.getAttribute("data-expected-version") || "";
    // Admin workflow pages carry ?tenant= when duplicate slugs exist. Keep
    // the node editor on that same tenant for both reads and writes.
    var actionQuery = editor.getAttribute("data-action-query") || "";
    // A page's canvas is tied to one immutable workflow version. A newer
    // version must make a stale node tap ask for a reload, not pair old
    // arrows with newly published source and sample data.
    var nodeReadQuery = actionQuery + (expectedVersion ?
        (actionQuery ? "&" : "?") + "expected_version=" + encodeURIComponent(expectedVersion) : "");

    // --- view toggle ---------------------------------------------------------
    var tabs = editor.querySelectorAll(".wf-tab");
    function showView(name) {
        editor.querySelectorAll(".wf-view").forEach(function (v) {
            v.hidden = v.getAttribute("data-view") !== name;
        });
        tabs.forEach(function (t) {
            t.classList.toggle("is-active", t.getAttribute("data-view") === name);
        });
    }
    tabs.forEach(function (t) {
        t.addEventListener("click", function () { showView(t.getAttribute("data-view")); });
    });

    // --- drawer --------------------------------------------------------------
    var drawer = document.getElementById("wf-drawer");
    var backdrop = document.getElementById("wf-drawer-backdrop");
    var title = document.getElementById("wf-drawer-title");
    var meta = document.getElementById("wf-drawer-meta");
    var dataflow = document.getElementById("wf-drawer-dataflow");
    var blockPanel = document.getElementById("wf-drawer-blockflow");
    var blockCanvas = document.getElementById("wf-blockflow-canvas");
    var blockList = document.getElementById("wf-blockflow-list");
    var codeBox = document.getElementById("wf-drawer-code");
    var status = document.getElementById("wf-drawer-status");
    var applyBtn = document.getElementById("wf-drawer-apply");
    var current = null;
    var blockCy = null;
    var declaredFlows = Object.create(null);
    var flowData = document.getElementById("step-flows-data");
    if (flowData && (flowData.textContent || "").length <= (1 << 20)) {
        try {
            var visualProjection = JSON.parse(flowData.textContent || "{}");
            if (visualProjection.complete === true && visualProjection.provenance === "author_declared_annotation" &&
                Array.isArray(visualProjection.steps)) {
                visualProjection.steps.slice(0, 256).forEach(function (flow) {
                    if (flow && typeof flow.step === "string" && Array.isArray(flow.blocks) &&
                        flow.blocks.length > 0 && flow.blocks.length <= 32 &&
                        Array.isArray(flow.edges) && flow.edges.length <= 64) {
                        declaredFlows[flow.step] = flow;
                    }
                });
            }
        } catch (e) { /* The durable node editor still works without annotations. */ }
    }

    function esc(s) {
        return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
            return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
        });
    }
    function pretty(raw) {
        if (raw == null) return "";
        try { return JSON.stringify(typeof raw === "string" ? JSON.parse(raw) : raw, null, 2); }
        catch (e) { return String(raw); }
    }
    // insertAtCursor drops text into the code box where the caret is, so a
    // non-dev can reference an upstream step without retyping its name.
    function insertAtCursor(text) {
        if (codeBox.disabled) return;
        var s = codeBox.selectionStart, e = codeBox.selectionEnd;
        codeBox.value = codeBox.value.slice(0, s) + text + codeBox.value.slice(e);
        codeBox.selectionStart = codeBox.selectionEnd = s + text.length;
        codeBox.focus();
    }

    // renderDataflow shows declared dependencies with recorded output samples.
    // The Go source decides which values are actually passed into this node.
    function renderDataflow(data) {
        var up = data.upstream || [], down = data.downstream || [];
        var h = "";
        h += '<div class="wf-df-sec"><div class="wf-df-hdr">Declared predecessors <span class="muted">' +
            (up.length ? up.length + " step" + (up.length > 1 ? "s" : "") : "") + "</span></div>";
        if (!up.length) {
            h += '<p class="wf-df-empty">No predecessors declared. Inspect the Go source for inputs, including the trigger payload.</p>';
        } else {
            h += '<p class="wf-df-empty">These are ordering dependencies. A sample output does not prove the node consumes that value.</p>';
            if (data.sample_run) h += '<p class="wf-df-empty">Samples are from current-version run <code>' + esc(data.sample_run) + '</code>.</p>';
            up.forEach(function (u) {
                var hasOut = u.output != null && u.output !== "null" && u.output !== "";
                h += '<div class="wf-df-node">';
                h += '<div class="wf-df-noderow"><button type="button" class="wf-df-chip" data-ref="' + esc(u.name) + '" title="Insert this step name at the cursor"><span class="wf-df-dot wf-k-' + esc(u.kind || "step") + '"></span>' + esc(u.name) + '</button>';
                if (u.status) h += '<span class="wf-df-status is-' + esc(u.status) + '">' + esc(u.status) + "</span>";
                h += "</div>";
                if (u.output_truncated) {
                    h += '<p class="wf-df-nodata muted">Sample output omitted (' + esc(u.output_bytes || "unknown") + ' bytes). Use the run history to inspect bounded output pages.</p>';
                } else if (hasOut) {
                    h += '<details class="wf-df-data"><summary>sample output</summary><pre>' + esc(pretty(u.output)) + "</pre></details>";
                } else {
                    h += '<p class="wf-df-nodata muted">No sample from the most recent run pinned to this version. Check run history or dispatch this version.</p>';
                }
                h += "</div>";
            });
        }
        h += "</div>";
        if (down.length) {
            h += '<div class="wf-df-sec"><div class="wf-df-hdr">Declared successors</div><div class="wf-df-chips">';
            down.forEach(function (d) {
                h += '<span class="wf-df-chip is-static"><span class="wf-df-dot wf-k-' + esc(d.kind || "step") + '"></span>' + esc(d.name) + "</span>";
            });
            h += "</div></div>";
        }
        dataflow.innerHTML = h;
        dataflow.querySelectorAll(".wf-df-chip[data-ref]").forEach(function (chip) {
            chip.addEventListener("click", function () { insertAtCursor(chip.getAttribute("data-ref")); });
        });
    }

    function renderBlockFlow(step) {
        if (!blockPanel || !blockCanvas || !blockList) return;
        if (blockCy) { blockCy.destroy(); blockCy = null; }
        blockCanvas.innerHTML = "";
        blockList.innerHTML = "";
        var flow = declaredFlows[step];
        if (!flow) { blockPanel.hidden = true; return; }
        blockPanel.hidden = false;
        blockCanvas.setAttribute("aria-label", "Author-declared data flow inside " + step);

        // Always provide a text equivalent, including route names, because
        // a canvas alone is neither accessible nor proof of runtime path.
        var list = '<ol class="wf-block-list">';
        flow.blocks.forEach(function (block) {
            var mode = block.kind === "merge" && block.mode ? String(block.mode).replace(/_/g, " ") : "";
            list += '<li><code>' + esc(block.id) + '</code> <span class="tag">' +
                esc(block.kind) + '</span> ' + esc(block.label || block.id);
            if (mode) {
                list += ' <span class="muted">mode: ' + esc(mode);
                if (block.key) list += '; key: <code>' + esc(block.key) + '</code>';
                if (block.max_rows) list += '; max rows: ' + esc(block.max_rows);
                list += '</span>';
            }
            list += '</li>';
        });
        list += '</ol>';
        if (flow.edges.length) {
            list += '<div class="wf-drawer-sechdr">Declared data edges</div><ul class="wf-block-edges">';
            flow.edges.forEach(function (edge) {
                list += '<li><code>' + esc(edge.from) + '</code> &rarr; <code>' +
                    esc(edge.to) + '</code>' + (edge.route ? ' <span class="muted">via ' + esc(edge.route) + '</span>' : '') + '</li>';
            });
            list += '</ul>';
        }
        blockList.innerHTML = list;
        if (typeof cytoscape !== "function") { blockCanvas.hidden = true; return; }
        blockCanvas.hidden = false;

        var nodeSeen = Object.create(null);
        var nodes = flow.blocks.map(function (block) {
            nodeSeen[block.id] = true;
            var kindLabel = block.kind + (block.kind === "merge" && block.mode ? " · " + String(block.mode).replace(/_/g, " ") : "");
            return { data: { id: block.id, label: (block.label || block.id) + "\n" + kindLabel, kind: block.kind } };
        });
        var edges = [];
        flow.edges.forEach(function (edge) {
            if (nodeSeen[edge.from] && nodeSeen[edge.to] && edge.from !== edge.to) {
                edges.push({ data: { source: edge.from, target: edge.to, route: edge.route || "" } });
            }
        });
        // The longest-path layout can put a direct split->merge edge across
        // several intermediate levels. Bend such bypasses away from the
        // middle nodes so the direct branch stays visible as its own route.
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
        if (visited === nodes.length) {
            edges.forEach(function (edge) {
                if (depth[edge.data.target] > depth[edge.data.source] + 1) edge.data.bypass = true;
            });
        }
        var css = getComputedStyle(document.documentElement);
        var edgeColor = (css.getPropertyValue("--border-strong") || "").trim() || "#D4D4D4";
        var labelColor = (css.getPropertyValue("--fg") || "").trim() || "#171717";
        var labelBackground = (css.getPropertyValue("--surface") || "").trim() || "#fff";
        var colors = { split: "#D97706", switch: "#D97706", "if": "#D97706",
            iterate: "#2563EB", chunk: "#2563EB", aggregate: "#0F766E",
            reduce: "#0F766E", merge: "#7C3AED", join: "#7C3AED", zip: "#7C3AED" };
        blockCy = cytoscape({
            container: blockCanvas,
            elements: { nodes: nodes, edges: edges },
            // A split may feed a merge both directly and through several
            // shaping blocks. Longest-path layering keeps the merge after
            // every declared predecessor instead of beside the first branch.
            layout: { name: "breadthfirst", directed: true, maximal: true, padding: 12, spacingFactor: 1.25 },
            style: [
                { selector: "node", style: { "background-color": function (ele) { return colors[ele.data("kind")] || "#15803D"; },
                    "label": "data(label)", "text-wrap": "wrap", "text-valign": "center", "text-halign": "center",
                    "color": "#fff", "font-size": 10, "font-family": "ui-monospace, SFMono-Regular, monospace",
                    "width": 104, "height": 52, "shape": "round-rectangle" } },
                { selector: "edge", style: { "width": 2, "line-color": edgeColor, "target-arrow-color": edgeColor,
                    "target-arrow-shape": "triangle", "curve-style": "bezier", "label": "data(route)",
                    "font-size": 9, "color": labelColor, "text-background-color": labelBackground,
                    "text-background-opacity": 0.9, "text-background-padding": 2 } },
                { selector: "edge[bypass]", style: { "curve-style": "unbundled-bezier",
                    "control-point-distances": 140, "control-point-weights": 0.5 } }
            ],
            wheelSensitivity: 0.2
        });
        var visibleCy = blockCy;
        setTimeout(function () { if (blockCy === visibleCy) { blockCy.resize(); blockCy.fit(undefined, 12); } }, 230);
    }

    function setStatus(msg, kind) {
        status.textContent = msg || "";
        status.className = "wf-drawer-status" + (kind ? " is-" + kind : "");
    }

    function openDrawer() {
        drawer.classList.add("is-open");
        drawer.setAttribute("aria-hidden", "false");
        if (backdrop) backdrop.hidden = false;
    }
    function closeDrawer() {
        drawer.classList.remove("is-open");
        drawer.setAttribute("aria-hidden", "true");
        if (backdrop) backdrop.hidden = true;
        current = null;
        if (blockCy) { blockCy.destroy(); blockCy = null; }
        document.dispatchEvent(new CustomEvent("reactor:drawer-close"));
    }

    function loadNode(step) {
        current = step;
        title.textContent = step;
        meta.textContent = "Loading this node...";
        codeBox.value = "";
        codeBox.disabled = true;
        applyBtn.disabled = true;
        if (dataflow) dataflow.innerHTML = "";
        setStatus("");
        openDrawer();
        renderBlockFlow(step);

        fetch("/workflows/" + encodeURIComponent(slug) + "/node/" + encodeURIComponent(step) + "/code" + nodeReadQuery, {
            headers: { "Accept": "application/json" }
        }).then(function (r) {
            if (r.status === 404) {
                meta.textContent = "This node has no editable Go source (it may be a structural or trigger node). Use the Code view to edit the whole file.";
                return null;
            }
            if (!r.ok) { return r.text().then(function (t) { throw new Error(t || ("HTTP " + r.status)); }); }
            return r.json();
        }).then(function (data) {
            if (!data) return;
            codeBox.value = data.code || "";
            if (dataflow) renderDataflow(data);
            meta.textContent = "From " + (data.source || "main.go") + ". Edits splice back into the full workflow and re-run go vet + lint + build.";
            if (editable && data.editable) {
                codeBox.disabled = false;
                applyBtn.disabled = false;
            } else {
                codeBox.disabled = true;
                applyBtn.disabled = true;
                meta.textContent = "Read-only: the code validator is not wired on this instance.";
            }
        }).catch(function (err) {
            meta.textContent = "Could not load this node.";
            setStatus(String(err.message || err), "err");
        });
    }

    function applyNode() {
        if (!current) return;
        applyBtn.disabled = true;
        setStatus("Validating + rebuilding...", "busy");
        var form = new URLSearchParams();
        form.set("body", codeBox.value);
        if (expectedVersion) form.set("expected_version", expectedVersion);
        fetch("/workflows/" + encodeURIComponent(slug) + "/node/" + encodeURIComponent(current) + "/code" + actionQuery, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: form.toString()
        }).then(function (r) {
            if (r.ok) {
                setStatus("Saved. Reloading...", "ok");
                window.location.reload();
                return;
            }
            return r.text().then(function (t) {
                applyBtn.disabled = false;
                setStatus(t || ("HTTP " + r.status), "err");
            });
        }).catch(function (err) {
            applyBtn.disabled = false;
            setStatus(String(err.message || err), "err");
        });
    }

    document.addEventListener("reactor:node-tap", function (e) {
        if (e.detail && e.detail.id) loadNode(e.detail.id);
    });

    var closeBtn = document.getElementById("wf-drawer-close");
    var cancelBtn = document.getElementById("wf-drawer-cancel");
    if (closeBtn) closeBtn.addEventListener("click", closeDrawer);
    if (cancelBtn) cancelBtn.addEventListener("click", closeDrawer);
    if (backdrop) backdrop.addEventListener("click", closeDrawer);
    if (applyBtn) applyBtn.addEventListener("click", applyNode);
    document.addEventListener("keydown", function (e) {
        if (e.key === "Escape" && drawer.classList.contains("is-open")) closeDrawer();
    });

    // Soft tab support in the code box so editing stays comfortable.
    if (codeBox) {
        codeBox.addEventListener("keydown", function (e) {
            if (e.key === "Tab") {
                e.preventDefault();
                var s = codeBox.selectionStart, en = codeBox.selectionEnd;
                codeBox.value = codeBox.value.slice(0, s) + "\t" + codeBox.value.slice(en);
                codeBox.selectionStart = codeBox.selectionEnd = s + 1;
            }
        });
    }
})();
