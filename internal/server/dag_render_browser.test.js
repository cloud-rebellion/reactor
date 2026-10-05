import { test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

const source = readFileSync(new URL("./assets/dag-render.js", import.meta.url), "utf8");

function renderDAG(dag, sourceText) {
    const canvas = { style: {} };
    const data = { textContent: sourceText ?? JSON.stringify(dag) };
    let options;
    const cy = { on() {}, nodes() { return { removeClass() {} }; } };
    const document = {
        documentElement: {},
        getElementById(id) {
            if (id === "dag-data") return data;
            if (id === "dag-canvas") return canvas;
            return null;
        },
        addEventListener() {}
    };
    runInNewContext(source, {
        document,
        window: {},
        getComputedStyle() { return { getPropertyValue() { return ""; } }; },
        cytoscape(value) { options = value; return cy; }
    }, { timeout: 1000 });
    return { options, canvas };
}

test("malformed or oversized retained JSON gives an explicit canvas reason", () => {
    for (const source of ["{broken", "null", " ".repeat((1 << 20) + 1)]) {
        const { options, canvas } = renderDAG({}, source);
        expect(options).toBeUndefined();
        expect(canvas.textContent).toContain("Visual graph omitted");
    }
});

function renderedEdges(dag) {
    const { options } = renderDAG(dag);
    if (!options) throw new Error("DAG renderer did not produce a customer canvas");
    return options.elements.edges.map((edge) => [edge.data.source, edge.data.target]);
}

test("visual graph retains a distinct branch after 512 repeated edges", () => {
    const repeated = Array.from({ length: 512 }, () => ({ from: "source", to: "first" }));
    const dag = {
        nodes: ["source", "first", "late"].map((id) => ({ id, kind: "step" })),
        edges: [...repeated, { from: "source", to: "late" }]
    };
    expect(renderedEdges(dag)).toEqual([["source", "first"], ["source", "late"]]);
});

test("steps graph retains a distinct dependency after 512 repetitions", () => {
    const dag = {
        steps: [
            { name: "source", kind: "step" },
            { name: "first", kind: "step", depends_on: Array(512).fill("source") },
            { name: "late", kind: "step", depends_on: ["source"] }
        ]
    };
    expect(renderedEdges(dag)).toEqual([["source", "first"], ["source", "late"]]);
});

test("a valid schema graph above the 512 distinct-edge canvas limit is explicit, not partial", () => {
    const nodes = Array.from({ length: 33 }, (_, i) => ({ id: `step${i}`, kind: "step" }));
    const edges = nodes.flatMap((node, i) => nodes.slice(i + 1).map((next) => ({ from: node.id, to: next.id })));
    expect(edges.length).toBe(528);
    const { options, canvas } = renderDAG({ nodes, edges });
    expect(options).toBeUndefined();
    expect(canvas.textContent).toContain("Visual graph omitted");
});

test("an oversized node list cannot silently present its first 256 nodes", () => {
    const nodes = Array.from({ length: 257 }, (_, i) => ({ id: `step${i}`, kind: "step" }));
    const { options, canvas } = renderDAG({ nodes, edges: [] });
    expect(options).toBeUndefined();
    expect(canvas.textContent).toContain("Visual graph omitted");
});

test("invalid retained graphs do not draw a plausible but incomplete customer flow", () => {
    const cases = [
        { nodes: [{ id: "first", kind: "step" }, { id: "first", kind: "step" }], edges: [] },
        { nodes: [{ id: "first", kind: "step" }, { id: "last", kind: "step" }], edges: [{ from: "first", to: "missing" }] },
        { nodes: [{ id: "first", kind: "step" }], edges: [{ from: "first", to: "first" }] },
        { nodes: [{ id: "first", kind: "step" }, { id: "last", kind: "step" }], edges: [{ from: "first", to: "last" }, { from: "last", to: "first" }] },
        { nodes: [{ id: "first", kind: "step" }, { id: "last", kind: "step", depends_on: ["first"] }], edges: [] },
        { steps: [{ name: "first", kind: "step" }, { name: "last", kind: "step", depends_on: ["missing"] }] },
        { steps: [{ name: "first", kind: "step" }, { name: "last", kind: "step", depends_on: "first" }] }
    ];
    for (const dag of cases) {
        const { options, canvas } = renderDAG(dag);
        expect(options).toBeUndefined();
        expect(canvas.textContent).toContain("Visual graph omitted: invalid");
    }
});

test("valid split and merge routes remain exact, including an empty legacy steps array", () => {
    const dag = {
        steps: [],
        nodes: ["split", "yes", "no", "merge"].map((id) => ({ id, kind: "step" })),
        edges: [
            { from: "split", to: "yes" }, { from: "split", to: "no" },
            { from: "yes", to: "merge" }, { from: "no", to: "merge" }
        ]
    };
    expect(renderedEdges(dag)).toEqual([
        ["split", "yes"], ["split", "no"], ["yes", "merge"], ["no", "merge"]
    ]);
});
