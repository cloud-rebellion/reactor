package codegen

import (
	"context"

	"github.com/bright-interaction/reactor/internal/graph"
	"github.com/bright-interaction/reactor/internal/knowledge"
)

// NewLens wires a PromptLens against a live knowledge.Store + graph.Graph.
// Defined in the codegen package so callers (CLI, daemon, MCP) can pull
// one helper without re-wiring the closures themselves. The two
// dependencies are imported here only; the rest of codegen stays free
// of knowledge / graph types so the package's tests can use a fake Lens
// without touching either dep.
func NewLens(store *knowledge.Store, g *graph.Graph) *PromptLens {
	if store == nil && g == nil {
		return nil
	}
	lens := &PromptLens{KnowledgeLimit: 5}
	if store != nil {
		redactor := knowledge.NewRedactor()
		lens.Search = func(ctx context.Context, query string, limit int) ([]LensHit, error) {
			hits, err := store.Search(ctx, query, limit)
			if err != nil {
				return nil, err
			}
			out := make([]LensHit, 0, len(hits))
			for _, h := range hits {
				out = append(out, LensHit{
					ID:    redactor.Scrub(h.Entry.Frontmatter.ID),
					Topic: redactor.Scrub(h.Entry.Frontmatter.Topic),
					Title: redactor.Scrub(h.Entry.Frontmatter.Title),
					Body:  redactor.Scrub(h.Entry.Body),
					Score: h.Score,
					Gold:  h.Entry.Frontmatter.Gold,
				})
			}
			return out, nil
		}
		lens.IncrementCitation = store.IncrementCitation
	}
	if g != nil {
		lens.QueryGraph = func(query string) string {
			sub := g.Query(query, 8)
			if len(sub.Nodes) == 0 {
				return ""
			}
			return graph.FormatSubgraph(sub)
		}
	}
	return lens
}
