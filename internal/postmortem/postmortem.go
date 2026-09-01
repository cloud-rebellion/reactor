// Package postmortem turns a failed run's journal into a knowledge
// entry. Auto-fired by the dispatcher when a run terminates as
// failed_dlq; also reachable via the reactor_record_postmortem MCP tool
// so an operator-driven AI can backfill an old failure.
//
// The entry lands in the knowledge corpus under topic "post-mortems"
// with created_by="claude". It's then visible to every future codegen
// prompt assembly (Ship 2's lens) and shows up as a node in the graph
// (Ship 1's builder).
package postmortem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/bright-interaction/reactor/internal/codegen"
	"github.com/bright-interaction/reactor/internal/knowledge"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// Anthropic is the minimal surface we need from the codegen Anthropic
// client. Defined as an interface so tests can inject a fake.
type Anthropic interface {
	SendMessages(ctx context.Context, req codegen.MessagesRequest) (*codegen.MessagesResponse, error)
}

// Generator builds + persists post-mortems.
type Generator struct {
	Anthropic Anthropic        // optional; nil → Generate returns ErrAnthropicMissing
	Journal   *journal.Journal // required
	Knowledge *knowledge.Store // required
	Log       *slog.Logger     // optional; defaults to slog.Default
	Now       func() time.Time // optional; defaults to time.Now
	Model     string           // optional; defaults to codegen.DefaultModel
}

// ErrAnthropicMissing is returned when Anthropic is nil. The dispatcher
// checks for this and silently skips the post-mortem step (operators
// without an API key still get a working DLQ; they just don't get
// auto-generated lessons).
var ErrAnthropicMissing = errors.New("postmortem: anthropic client not configured")

// Generate analyses runID's journal + dlq item via Claude and writes a
// new knowledge entry under topic "post-mortems". Returns the entry id
// on success.
func (g *Generator) Generate(ctx context.Context, runID string) (string, error) {
	if g.Anthropic == nil {
		return "", ErrAnthropicMissing
	}
	if g.Journal == nil || g.Knowledge == nil {
		return "", errors.New("postmortem: journal + knowledge required")
	}
	if g.Log == nil {
		g.Log = slog.Default()
	}
	if g.Now == nil {
		g.Now = time.Now
	}

	run, err := g.Journal.GetRun(ctx, runID)
	if err != nil {
		return "", fmt.Errorf("postmortem: get run: %w", err)
	}
	steps, err := g.Journal.ListSteps(ctx, runID)
	if err != nil {
		return "", fmt.Errorf("postmortem: list steps: %w", err)
	}
	slug, err := g.Journal.WorkflowSlugByID(ctx, run.WorkflowID)
	if err != nil {
		// Slug lookup is best-effort; we still want a post-mortem even if
		// the workflow row got renamed mid-run.
		slug = run.WorkflowID
	}

	prompt := buildPrompt(run, steps, slug)
	model := g.Model
	if model == "" {
		model = codegen.DefaultModel
	}

	req := codegen.MessagesRequest{
		Model:     model,
		MaxTokens: 1024,
		Messages: []codegen.Message{{
			Role: "user",
			Content: []codegen.ContentBlock{{
				Type: "text",
				Text: prompt,
			}},
		}},
		Tools:      []codegen.Tool{postmortemTool},
		ToolChoice: &codegen.ToolChoice{Type: "tool", Name: postmortemToolName},
	}

	resp, err := g.Anthropic.SendMessages(ctx, req)
	if err != nil {
		return "", fmt.Errorf("postmortem: anthropic: %w", err)
	}

	pm, err := extractPostmortem(resp)
	if err != nil {
		return "", err
	}

	body := renderBody(pm, run, slug)
	entry, err := g.Knowledge.Add(ctx, knowledge.Entry{
		Frontmatter: knowledge.Frontmatter{
			Topic: "post-mortems",
			// Scope the entry to the run's tenant. The body names the workflow
			// slug and may describe its step metadata, so an
			// unstamped post-mortem is readable by every tenant on /knowledge.
			// Empty stays global, which is right for a single-tenant install.
			Tenant:    run.TenantID,
			Title:     pm.Title,
			CreatedBy: "claude",
			Sources:   []string{"run:" + runID, "workflow:" + slug},
			Tags:      append([]string{"post-mortem", slug}, pm.Tags...),
		},
		Body: body,
	})
	if err != nil {
		// PII redactor is the most likely culprit here; surface clearly.
		var red *knowledge.ErrRedacted
		if errors.As(err, &red) {
			g.Log.Warn("postmortem: blocked by redactor", "run_id", runID, "findings", len(red.Findings))
		}
		return "", fmt.Errorf("postmortem: persist: %w", err)
	}
	g.Log.Info("postmortem: written", "run_id", runID, "entry_id", entry.Frontmatter.ID, "workflow", slug)
	return entry.Frontmatter.ID, nil
}

// Postmortem is the structured shape Claude returns via tool-use.
type Postmortem struct {
	Title          string   `json:"title"`
	Summary        string   `json:"summary"`
	RootCause      string   `json:"root_cause"`
	Lesson         string   `json:"lesson"`
	Recommendation string   `json:"recommendation"`
	Tags           []string `json:"tags"`
}

const postmortemToolName = "emit_postmortem"

var postmortemTool = codegen.Tool{
	Name:        postmortemToolName,
	Description: "Emit a structured post-mortem for a failed Reactor workflow run.",
	InputSchema: json.RawMessage(`{
		"type": "object",
		"required": ["title", "summary", "root_cause", "lesson", "recommendation"],
		"properties": {
			"title":          {"type": "string", "maxLength": 100},
			"summary":        {"type": "string"},
			"root_cause":     {"type": "string"},
			"lesson":         {"type": "string"},
			"recommendation": {"type": "string"},
			"tags":           {"type": "array", "items": {"type": "string"}}
		}
	}`),
}

func extractPostmortem(resp *codegen.MessagesResponse) (Postmortem, error) {
	for _, c := range resp.Content {
		if c.Type == "tool_use" && c.Name == postmortemToolName {
			var pm Postmortem
			if err := json.Unmarshal(c.Input, &pm); err != nil {
				return Postmortem{}, fmt.Errorf("postmortem: parse tool_use: %w", err)
			}
			if pm.Title == "" || pm.Lesson == "" {
				return Postmortem{}, errors.New("postmortem: model returned empty title or lesson")
			}
			return pm, nil
		}
	}
	return Postmortem{}, errors.New("postmortem: no tool_use block in response")
}

// buildPrompt constructs the user message Claude sees. Includes the
// brief, the step timeline, and explicit instructions on what shape
// the lesson should take so future codegen prompts can pull it
// usefully via BM25.
func buildPrompt(run journal.RunInfo, steps []journal.StepRow, slug string) string {
	sanitizer := newPromptSanitizer(run, steps)
	var b strings.Builder
	b.WriteString("A workflow run failed terminally and landed in the dead-letter queue. ")
	b.WriteString("Your job: write a post-mortem in the structured shape so the lesson lands in the Reactor knowledge corpus and benefits every future generated workflow.\n\n")

	b.WriteString("## Run\n\n")
	fmt.Fprintf(&b, "- workflow: %s\n", sanitizer.scrub(slug))
	fmt.Fprintf(&b, "- run_id: %s\n", sanitizer.scrub(run.ID))
	fmt.Fprintf(&b, "- trigger_kind: %s\n", sanitizer.scrub(run.TriggerKind))
	fmt.Fprintf(&b, "- status: %s\n", sanitizer.scrub(run.Status))
	if !run.StartedAt.IsZero() {
		fmt.Fprintf(&b, "- started_at: %s\n", run.StartedAt.UTC().Format(time.RFC3339))
	}
	if !run.FinishedAt.IsZero() {
		fmt.Fprintf(&b, "- finished_at: %s\n", run.FinishedAt.UTC().Format(time.RFC3339))
	}
	b.WriteString("\n## Step timeline\n\n")
	if len(steps) == 0 {
		b.WriteString("(no steps recorded; the workflow likely failed before its first Step)\n")
	}
	for _, s := range steps {
		fmt.Fprintf(&b, "- step %s attempt=%d status=%s", sanitizer.scrub(s.StepName), s.Attempt, sanitizer.scrub(s.Status))
		if s.ErrorText != "" {
			// Never place raw or transformed error text on the external request.
			// Provider errors may contain arbitrary customer/document metadata
			// that no heuristic redactor can prove safe.
			fmt.Fprintf(&b, " %s", summarizeStepError(s.ErrorText))
		}
		b.WriteString("\n")
	}

	b.WriteString("\n## What we want from the post-mortem\n\n")
	b.WriteString("- title: <100 chars, action-oriented (\"don't X\" / \"always Y\"); will become the entry title in the corpus.\n")
	b.WriteString("- summary: 2-3 sentences of what happened.\n")
	b.WriteString("- root_cause: the actual underlying issue, not the symptom.\n")
	b.WriteString("- lesson: the durable insight, framed so a future generation sees it and applies it.\n")
	b.WriteString("- recommendation: concrete code-level guidance for the next workflow author (human or AI).\n")
	b.WriteString("- tags: 2-5 tags for retrieval (e.g. [retry, idempotency, http-clients]).\n\n")
	b.WriteString("Do NOT include customer PII, secrets, tokens, or any value that looks like a credential. The corpus is operator-shareable; treat it as such.\n")
	b.WriteString("Call emit_postmortem exactly once.\n")

	return b.String()
}

func renderBody(pm Postmortem, run journal.RunInfo, slug string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", pm.Title)
	fmt.Fprintf(&b, "_Auto-generated from run `%s` on workflow `%s`._\n\n", run.ID, slug)
	if pm.Summary != "" {
		b.WriteString("## Summary\n\n")
		b.WriteString(pm.Summary)
		b.WriteString("\n\n")
	}
	if pm.RootCause != "" {
		b.WriteString("## Root cause\n\n")
		b.WriteString(pm.RootCause)
		b.WriteString("\n\n")
	}
	if pm.Lesson != "" {
		b.WriteString("## Lesson\n\n")
		b.WriteString(pm.Lesson)
		b.WriteString("\n\n")
	}
	if pm.Recommendation != "" {
		b.WriteString("## Recommendation\n\n")
		b.WriteString(pm.Recommendation)
		b.WriteString("\n\n")
	}
	return b.String()
}
