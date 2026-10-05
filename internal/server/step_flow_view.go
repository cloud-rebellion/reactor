package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"

	"github.com/bright-interaction/reactor/internal/flowblocks"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// scriptJSON keeps JSON parseable in a non-executing application/json island
// while escaping HTML-sensitive bytes so a label containing </script> cannot
// break out of the element. JSEscapeString is for quoted JavaScript strings:
// it escapes JSON quotation marks and made the existing DAG canvas fail to
// parse its own data.
func scriptJSON(src []byte) string {
	var b bytes.Buffer
	json.HTMLEscape(&b, src)
	return b.String()
}

// renderDeclaredStepFlowSummary is the accessible, server-rendered fallback
// for the editor's nested Cytoscape view. It is also used on run pages, where
// the parent durable step has a receipt but the declared inner blocks do not.
func renderDeclaredStepFlowSummary(flow flowblocks.StepFlow) string {
	return renderDeclaredStepFlowSummaryWithObservations(flow, nil, nil, false)
}

func renderDeclaredStepFlowSummaryWithObservations(flow flowblocks.StepFlow, observed map[string]bool, receipts []journal.BlockReceipt, windowOmitted bool) string {
	var b strings.Builder
	b.WriteString(`<div class="wf-block-flow-summary">`)
	if observed == nil {
		b.WriteString(`<p class="flow-note">Author-declared operations inside this durable step. The step receipt applies to the whole step; this declaration does not prove inner block execution. Bounded joins, splits, iterations, and aggregations may also have SDK-reported run observations. Inspect the Go source to confirm behavior.</p>`)
	} else {
		b.WriteString(`<p class="flow-note">These blocks are author-declared. Merge, split, iterate, and aggregate observations are reported by the workflow SDK, not independently verified behavior. A merge report matches only when its mode and row bound agree; split reports contain branch counts but cannot verify the predicate or declared routes. Iterate and aggregate reports contain counts but cannot verify a mapping or fold. A missing observation does not prove a block was skipped.</p>`)
	}
	b.WriteString(`<ol class="wf-block-list">`)
	for _, block := range flow.Blocks {
		label := block.Label
		if label == "" {
			label = block.ID
		}
		fmt.Fprintf(&b, `<li><code>%s</code> <span class="tag">%s</span> %s`,
			template.HTMLEscapeString(block.ID), template.HTMLEscapeString(block.Kind), template.HTMLEscapeString(label))
		if block.Kind == "merge" && block.Mode != "" {
			fmt.Fprintf(&b, ` <span class="muted">mode: %s`, template.HTMLEscapeString(strings.ReplaceAll(block.Mode, "_", " ")))
			if block.Key != "" {
				fmt.Fprintf(&b, `; key: <code>%s</code>`, template.HTMLEscapeString(block.Key))
			}
			if block.MaxRows > 0 {
				fmt.Fprintf(&b, `; max rows: %d`, block.MaxRows)
			}
			b.WriteString(`</span>`)
		}
		if observed != nil {
			if !flowblocks.SupportsSDKObservation(block) {
				b.WriteString(` <span class="tag">SDK observation unavailable for this block</span>`)
			} else if observed[block.ID] {
				var shown *journal.BlockReceipt
				for i := range receipts {
					if receipts[i].BlockID == block.ID {
						shown = &receipts[i]
						break
					}
				}
				switch {
				case shown == nil:
					if block.Kind == "split" {
						b.WriteString(` <span class="tag tag-warn">SDK-reported split ID; counts not shown</span>`)
					} else if block.Kind == "iterate" || block.Kind == "aggregate" {
						b.WriteString(` <span class="tag tag-warn">SDK-reported block ID; counts not shown</span>`)
					} else {
						b.WriteString(` <span class="tag tag-warn">SDK-reported block ID; mode and bound not shown</span>`)
					}
				case block.Kind == "split" && (shown.Kind != "split" || shown.InputRows == nil || shown.YesRows == nil || shown.NoRows == nil):
					b.WriteString(` <span class="tag tag-warn">SDK report differs from declared split</span>`)
				case block.Kind == "split":
					b.WriteString(` <span class="tag tag-on">SDK-reported observation</span>`)
					fmt.Fprintf(&b, ` <span class="muted">latest shown: call %d, attempt %d; input %d, yes %d, no %d rows</span>`,
						shown.CallOrdinal, shown.Attempt, *shown.InputRows, *shown.YesRows, *shown.NoRows)
				case (block.Kind == "iterate" || block.Kind == "aggregate") &&
					(shown.Kind != block.Kind || !journal.ValidBlockReceiptShape(*shown)):
					b.WriteString(` <span class="tag tag-warn">SDK report differs from declared collection operation</span>`)
				case block.Kind == "iterate" || block.Kind == "aggregate":
					b.WriteString(` <span class="tag tag-on">SDK-reported observation</span>`)
					fmt.Fprintf(&b, ` <span class="muted">latest shown: call %d, attempt %d; input %d, output %d</span>`,
						shown.CallOrdinal, shown.Attempt, *shown.InputRows, shown.OutputRows)
				case shown.Kind != "merge" || shown.Mode != block.Mode || shown.MaxRows != block.MaxRows:
					fmt.Fprintf(&b, ` <span class="tag tag-warn">SDK report differs from declared merge mode or bound</span> <span class="muted">latest shown: mode %s; max rows %d</span>`,
						template.HTMLEscapeString(shown.Mode), shown.MaxRows)
				default:
					b.WriteString(` <span class="tag tag-on">SDK-reported observation</span>`)
					fmt.Fprintf(&b, ` <span class="muted">latest shown: call %d, attempt %d, %s; left %d, right %d, output %d rows</span>`,
						shown.CallOrdinal, shown.Attempt, template.HTMLEscapeString(shown.Outcome),
						shown.LeftRows, shown.RightRows, shown.OutputRows)
				}
			} else {
				b.WriteString(` <span class="tag tag-warn">No SDK observation in this run</span>`)
			}
		}
		b.WriteString(`</li>`)
	}
	b.WriteString(`</ol>`)
	if windowOmitted {
		b.WriteString(`<p class="muted">Only the newest 100 block receipts are shown; an observed block may have its details outside this window.</p>`)
	}
	if len(flow.Edges) > 0 {
		b.WriteString(`<div class="wf-drawer-sechdr">Declared data edges</div><ul class="wf-block-edges">`)
		for _, edge := range flow.Edges {
			fmt.Fprintf(&b, `<li><code>%s</code> &rarr; <code>%s</code>`,
				template.HTMLEscapeString(edge.From), template.HTMLEscapeString(edge.To))
			if edge.Route != "" {
				fmt.Fprintf(&b, ` <span class="muted">via %s</span>`, template.HTMLEscapeString(edge.Route))
			}
			b.WriteString(`</li>`)
		}
		b.WriteString(`</ul>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

func renderAllDeclaredStepFlows(projection flowblocks.Projection) string {
	if !projection.Complete {
		return `<p class="warn">Visual block annotations are invalid or exceed the bounded projection. Inspect and repair dag.json before using this block view.</p>`
	}
	if len(projection.Steps) == 0 {
		return `<p class="muted">No per-step visual blocks declared.</p>`
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<p class="flow-note">%d author-declared visual blocks across %d durable steps. These are review annotations. Durable steps have host-recorded outcomes; observed joins, splits, iterations, and aggregations may also have value-free SDK-reported receipts.</p>`, projection.BlockCount, len(projection.Steps))
	for _, flow := range projection.Steps {
		fmt.Fprintf(&b, `<details class="wf-block-step"><summary><code>%s</code> &middot; %d declared blocks</summary>`,
			template.HTMLEscapeString(flow.Step), len(flow.Blocks))
		b.WriteString(renderDeclaredStepFlowSummary(flow))
		b.WriteString(`</details>`)
	}
	return b.String()
}
