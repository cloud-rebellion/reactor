package codegen

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

//go:embed prompts/system.md
var systemPrompt string

// EmitToolName is the forced tool the model must call. Anthropic's tool
// system gives us strict JSON output without prose to parse.
const EmitToolName = "emit_workflow_files"

// emitToolSchema is the JSON Schema for the tool input. The schema is
// inlined as a string so we can pass it to the API verbatim and so users
// can read what the model is being forced into.
const emitToolSchema = `{
	"type": "object",
	"required": ["slug", "version", "workflow_go", "dag_json", "workflow_test_go"],
	"properties": {
		"slug":            {"type": "string", "pattern": "^[a-z][a-z0-9-]*$"},
		"version":         {"type": "string"},
		"workflow_go":     {"type": "string"},
		"dag_json":        {"type": "string"},
		"workflow_test_go":{"type": "string"}
	}
}`

// EmitInput is the typed shape of the tool call. Mirrors emitToolSchema.
type EmitInput struct {
	Slug         string `json:"slug"`
	Version      string `json:"version"`
	WorkflowGo   string `json:"workflow_go"`
	DAGJson      string `json:"dag_json"`
	WorkflowTest string `json:"workflow_test_go"`
}

// Generator orchestrates the codegen pipeline: prompt assembly, model call,
// validation, retry, commit.
type Generator struct {
	Anthropic *AnthropicClient
	Log       *slog.Logger

	// WorkflowsDir is where generated workflows land. Default
	// "reactor-workflows/" relative to the project root.
	WorkflowsDir string

	// Validator runs the post-generation gates. Defaults to a real
	// `go vet` + `reactor lint` + `go build` chain; tests can inject
	// a fake.
	Validator Validator

	// Committer commits the generated files to git. Defaults to a real
	// git invocation; tests can inject a fake.
	Committer Committer

	// MaxRetries caps the validation feedback loop. Default 3.
	MaxRetries int

	// Now overrides the clock for tests.
	Now func() time.Time

	// Lens is the Environment Lens: knowledge corpus + runtime graph.
	// When non-nil, assembleUserMessage queries both for relevant
	// context to inject into the prompt before the brief reaches
	// Claude. Nil means generation falls back to brief-only behaviour
	// (the pre-Ship-2 path); useful for tests + minimal installs.
	Lens *PromptLens

	// EchoPrompt, when set, receives the assembled user message after
	// every successful prompt build. Wired by the CLI's --echo-prompt
	// flag so an operator can inspect what the model actually saw.
	EchoPrompt func(prompt string)
}

// PromptLens is what assembleUserMessage queries to enrich the user
// message with environment context. Decoupled into an interface-shaped
// struct so packages that don't want to import internal/knowledge or
// internal/graph (notably tests) can pass nil and skip the injection.
type PromptLens struct {
	// Search returns the top-N knowledge entries matching query.
	Search func(ctx context.Context, query string, limit int) ([]LensHit, error)

	// QueryGraph returns a textual rendering of the subgraph relevant
	// to the brief. Should already be Claude-friendly (NODE/EDGE
	// shape). Empty result means no runtime context to inject.
	QueryGraph func(query string) string

	// IncrementCitation is called for each knowledge entry actually
	// cited in the prompt. Optional; nil means citations are not
	// tracked.
	IncrementCitation func(ctx context.Context, id string) error

	// KnowledgeLimit caps how many entries the lens injects. Default 5.
	KnowledgeLimit int
}

// LensHit pairs an entry id + topic + title + body excerpt with a
// score. Mirrors knowledge.Hit but lives here so the codegen package
// avoids the import cycle a bidirectional dependency would create.
type LensHit struct {
	ID    string
	Topic string
	Title string
	Body  string
	Score float64
	Gold  bool
}

// Validator is what runs against the generated files in their landing dir.
type Validator interface {
	Validate(ctx context.Context, dir string, input EmitInput) error
}

// Committer commits a generated workflow to git.
type Committer interface {
	Commit(ctx context.Context, dir, slug, version string) error
}

// GenerateRequest is what the HTTP / MCP caller passes in.
type GenerateRequest struct {
	Brief       string `json:"brief"`
	Environment string `json:"environment_context,omitempty"` // services + cred IDs + schemas; week 9 wires this from the MCP Lens
}

// GenerateResult is what the caller gets back.
type GenerateResult struct {
	Slug        string
	Version     string
	Path        string
	Attempts    int
	UsageInput  int
	UsageOutput int
}

// Generate runs the full pipeline. Returns the workflow path on success.
func (g *Generator) Generate(ctx context.Context, req GenerateRequest) (*GenerateResult, error) {
	if g.applyDefaults() != nil {
		return nil, errors.New("codegen: missing config")
	}

	tool := Tool{
		Name:        EmitToolName,
		Description: "Emit a complete Reactor workflow as four files.",
		InputSchema: json.RawMessage(emitToolSchema),
	}
	choice := &ToolChoice{Type: "tool", Name: EmitToolName}

	userMessage := g.assembleUserMessage(ctx, req)
	if g.EchoPrompt != nil {
		g.EchoPrompt(userMessage)
	}
	messages := []Message{{
		Role: "user",
		Content: []ContentBlock{{
			Type: "text",
			Text: userMessage,
		}},
	}}

	var (
		input    EmitInput
		usageIn  int
		usageOut int
		lastErr  error
	)
	for attempt := 1; attempt <= g.MaxRetries; attempt++ {
		resp, err := g.Anthropic.SendMessages(ctx, MessagesRequest{
			System:     systemPrompt,
			Messages:   messages,
			Tools:      []Tool{tool},
			ToolChoice: choice,
		})
		if err != nil {
			return nil, err
		}
		usageIn += resp.Usage.InputTokens
		usageOut += resp.Usage.OutputTokens

		input, err = extractEmit(resp)
		if err != nil {
			return nil, fmt.Errorf("codegen: parse tool call: %w", err)
		}

		// Write to a tmp dir, validate, on success move into place.
		tmpDir, err := os.MkdirTemp("", "ff-codegen-")
		if err != nil {
			return nil, fmt.Errorf("codegen: tmp dir: %w", err)
		}
		if err := writeFiles(tmpDir, input); err != nil {
			os.RemoveAll(tmpDir)
			return nil, err
		}

		if err := g.Validator.Validate(ctx, tmpDir, input); err != nil {
			lastErr = err
			os.RemoveAll(tmpDir)
			g.Log.Warn("codegen validation failed", "attempt", attempt, "err", err)
			messages = append(messages,
				Message{Role: "assistant", Content: extractAssistantContent(resp)},
				Message{Role: "user", Content: []ContentBlock{{
					Type: "text",
					Text: "Validation failed:\n\n" + err.Error() +
						"\n\nFix only the listed problems. Re-emit the full file set via emit_workflow_files.",
				}}},
			)
			continue
		}

		// Move into the workflows dir + commit.
		dest := filepath.Join(g.WorkflowsDir, input.Slug)
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			os.RemoveAll(tmpDir)
			return nil, fmt.Errorf("codegen: mkdir workflows: %w", err)
		}
		if err := os.RemoveAll(dest); err != nil && !os.IsNotExist(err) {
			os.RemoveAll(tmpDir)
			return nil, fmt.Errorf("codegen: remove dest: %w", err)
		}
		if err := os.Rename(tmpDir, dest); err != nil {
			os.RemoveAll(tmpDir)
			return nil, fmt.Errorf("codegen: rename: %w", err)
		}
		if err := g.Committer.Commit(ctx, dest, input.Slug, input.Version); err != nil {
			return nil, fmt.Errorf("codegen: commit: %w", err)
		}
		return &GenerateResult{
			Slug:        input.Slug,
			Version:     input.Version,
			Path:        dest,
			Attempts:    attempt,
			UsageInput:  usageIn,
			UsageOutput: usageOut,
		}, nil
	}
	return nil, fmt.Errorf("codegen: validation failed after %d attempts: %w", g.MaxRetries, lastErr)
}

func (g *Generator) applyDefaults() error {
	if g.Anthropic == nil {
		return errors.New("anthropic client required")
	}
	if g.Log == nil {
		g.Log = slog.Default()
	}
	if g.WorkflowsDir == "" {
		g.WorkflowsDir = "reactor-workflows"
	}
	if g.MaxRetries == 0 {
		g.MaxRetries = 3
	}
	if g.Validator == nil {
		g.Validator = &GoBuildValidator{}
	}
	if g.Committer == nil {
		g.Committer = &GitCommitter{}
	}
	if g.Now == nil {
		g.Now = time.Now
	}
	return nil
}

// extractEmit pulls the tool_use block from the response and decodes the
// EmitInput. Returns an error if no tool call is present (which indicates
// a model misbehaviour we shouldn't paper over).
//
// Re-validates the slug against the same regex emitToolSchema declares.
// The Anthropic API treats JSON Schema patterns as a hint to the model,
// not a hard server-side check, so a misbehaving response could pass a
// slug like ".." or "/etc/passwd" that filepath.Join would happily walk
// outside WorkflowsDir. The check here closes that hole.
func extractEmit(resp *MessagesResponse) (EmitInput, error) {
	for _, c := range resp.Content {
		if c.Type == "tool_use" && c.Name == EmitToolName {
			var in EmitInput
			if err := json.Unmarshal(c.Input, &in); err != nil {
				return EmitInput{}, err
			}
			if !IsValidSlug(in.Slug) {
				return EmitInput{}, fmt.Errorf("codegen: slug %q must match %s", in.Slug, slugRe.String())
			}
			return in, nil
		}
	}
	return EmitInput{}, errors.New("no emit_workflow_files tool call in response")
}

// slugRe mirrors emitToolSchema's JSON-Schema pattern. Kept as a package
// var so Generator-internal validators (and future callers) share the
// exact same shape.
var slugRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// IsValidSlug reports whether s is a workflow slug that's safe to use
// as a filesystem path component (no traversal, no shell metacharacters,
// no spaces). Mirrors emitToolSchema's `^[a-z][a-z0-9-]*$` pattern.
//
// Callers (CLI workflow build/register, MCP register_workflow tool,
// codegen extractEmit) should reject anything that doesn't match before
// touching the filesystem or the workflows table.
func IsValidSlug(s string) bool { return slugRe.MatchString(s) }

// extractAssistantContent returns the assistant turn so we can echo it
// back to the model along with the validation feedback. Anthropic requires
// the assistant turn to be replayed before the next user turn when we
// want the model to maintain the tool-use context.
func extractAssistantContent(resp *MessagesResponse) []ContentBlock {
	out := make([]ContentBlock, 0, len(resp.Content))
	for _, c := range resp.Content {
		switch c.Type {
		case "text", "tool_use":
			out = append(out, c)
		}
	}
	return out
}

// writeFiles materialises the EmitInput on disk in dir.
func writeFiles(dir string, in EmitInput) error {
	files := map[string]string{
		"workflow.go":      in.WorkflowGo,
		"dag.json":         in.DAGJson,
		"workflow_test.go": in.WorkflowTest,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			return fmt.Errorf("codegen: write %s: %w", name, err)
		}
	}
	return nil
}

// assembleUserMessage builds the prose passed as the user turn:
//  1. Brief (operator-typed)
//  2. Optional --environment flag content (legacy hand-curated context)
//  3. Graph slice from g.Lens.QueryGraph (runtime state relevant to brief)
//  4. Top-K knowledge entries from g.Lens.Search (lessons + patterns)
//
// Steps 3 + 4 are the Environment Lens. They turn what was a blind
// generation into one Claude sees the live deployment + accumulated
// wisdom for free, on every call.
func (g *Generator) assembleUserMessage(ctx context.Context, req GenerateRequest) string {
	var b strings.Builder
	b.WriteString(req.Brief)
	if req.Environment != "" {
		b.WriteString("\n\n## Environment context\n\n")
		b.WriteString(req.Environment)
	}

	if g.Lens == nil {
		return b.String()
	}

	if g.Lens.QueryGraph != nil {
		if slice := g.Lens.QueryGraph(req.Brief); slice != "" {
			b.WriteString("\n\n## Runtime graph slice (for this brief)\n\n")
			b.WriteString("```\n")
			b.WriteString(slice)
			b.WriteString("```\n")
		}
	}

	if g.Lens.Search != nil {
		limit := g.Lens.KnowledgeLimit
		if limit == 0 {
			limit = 5
		}
		hits, err := g.Lens.Search(ctx, req.Brief, limit)
		if err == nil && len(hits) > 0 {
			b.WriteString("\n\n## Relevant knowledge (compounded from prior runs + seeded references)\n\n")
			for _, h := range hits {
				goldTag := ""
				if h.Gold {
					goldTag = " [GOLD]"
				}
				fmt.Fprintf(&b, "### %s%s (id=%s, topic=%s)\n\n", h.Title, goldTag, h.ID, h.Topic)
				b.WriteString(strings.TrimSpace(h.Body))
				b.WriteString("\n\n")
				if g.Lens.IncrementCitation != nil {
					if cerr := g.Lens.IncrementCitation(ctx, h.ID); cerr != nil && g.Log != nil {
						g.Log.Warn("codegen: citation bump failed", "id", h.ID, "err", cerr)
					}
				}
			}
		}
	}

	return b.String()
}

// GoBuildValidator runs `go vet` + `go build` + the Reactor lint pass
// against the temp dir. Used by Generator unless a fake is injected.
type GoBuildValidator struct {
	GoBin string // defaults to "go" on PATH
}

// Validate runs the gates. The temp dir is the workflow source root; we
// initialise a tiny Go module that imports the Reactor SDK so `go build`
// can resolve dependencies without a parent workspace go.mod.
func (v *GoBuildValidator) Validate(ctx context.Context, dir string, in EmitInput) error {
	gobin := v.GoBin
	if gobin == "" {
		gobin = "go"
	}

	if err := PrepareWorkflowModule(ctx, gobin, dir, in.Slug); err != nil {
		return fmt.Errorf("module preparation: %w", err)
	}

	// Reject disallowed imports before compiling anything: `go build` is
	// not sandboxed and a third-party module can run code at build time.
	if err := CheckAllowedImports(dir); err != nil {
		return err
	}

	if out, err := run(ctx, gobin, dir, "vet", "./..."); err != nil {
		return fmt.Errorf("go vet: %w\n%s", err, out)
	}
	if out, err := run(ctx, gobin, dir, "build", BuildVCSFlag, "./..."); err != nil {
		return fmt.Errorf("go build: %w\n%s", err, out)
	}

	if err := lintWorkflow(in.WorkflowGo); err != nil {
		return fmt.Errorf("reactor lint: %w", err)
	}

	if !json.Valid([]byte(in.DAGJson)) {
		return errors.New("dag.json is not valid JSON")
	}

	return nil
}

// PrepareWorkflowModule creates the trusted, workflow-local module graph used
// by every Reactor workflow compiler. It rejects the module escape hatches
// that regenerating go.mod cannot neutralise, removes any caller-supplied
// go.mod/go.sum, and optionally wires the operator-controlled local Reactor SDK
// path from REACTOR_SDK_REPLACE.
func PrepareWorkflowModule(ctx context.Context, gobin, dir, slug string) error {
	if gobin == "" {
		gobin = "go"
	}
	if dir == "" {
		return errors.New("workflow module: source directory is required")
	}
	if !IsValidSlug(slug) {
		return fmt.Errorf("workflow module: invalid slug %q", slug)
	}

	// A root vendor tree can replace the allowlisted SDK with attacker source
	// that CheckAllowedImports deliberately skips. A go.work can override the
	// freshly generated module graph. Reject both even though GOWORK=off is also
	// pinned in SecureBuildEnv, so every authoring surface has one fail-closed
	// policy and operators get a clear error.
	for _, banned := range []string{"vendor", "go.work", "go.work.sum"} {
		path := filepath.Join(dir, banned)
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("workflow module: %q is not allowed in a workflow source tree (Reactor owns module setup)", banned)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("workflow module: inspect %q: %w", banned, err)
		}
	}

	// Never trust a supplied go.mod. An uploaded tarball could ship a go.mod
	// carrying `replace github.com/bright-interaction/reactor => ./evil` (plus
	// attacker code in ./evil) that substitutes for the SDK and runs at build
	// time, and `go mod init` refuses when one exists. The daemon owns module
	// setup, so remove any supplied go.mod/go.sum and regenerate a clean one
	// wired only to the bundled SDK.
	for _, supplied := range []string{"go.mod", "go.sum"} {
		if err := os.Remove(filepath.Join(dir, supplied)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("workflow module: remove supplied %s: %w", supplied, err)
		}
	}
	if _, err := run(ctx, gobin, dir, "mod", "init", "reactor-workflow/"+slug); err != nil {
		return err
	}
	// The Reactor SDK module is not yet published to a public proxy, so a
	// bare `go build` of a generated workflow can't resolve its SDK import
	// outside the dev checkout. When the operator points REACTOR_SDK_REPLACE
	// at a local Reactor checkout, wire a require + replace so the workflow
	// builds against it. (When the module is published this require alone
	// will resolve; until then the replace is the supported self-host path.)
	if replace := envFirst("REACTOR_SDK_REPLACE", "ARACHNE_SDK_REPLACE"); replace != "" {
		const sdkModule = "github.com/bright-interaction/reactor"
		if _, err := run(ctx, gobin, dir, "mod", "edit",
			"-require="+sdkModule+"@v0.0.0",
			"-replace="+sdkModule+"="+replace); err != nil {
			return fmt.Errorf("wire SDK replace: %w", err)
		}
	}
	return nil
}

// envFirst returns the value of the primary env var, falling back to the
// legacy name when the primary is unset. The fallback is read via a variable
// (not a string literal) so the pre-commit legacy-prefix guard treats this as
// a proper migration read, matching the cmd/reactor envFirst contract.
func envFirst(primary, fallback string) string {
	if v := os.Getenv(primary); v != "" {
		return v
	}
	return os.Getenv(fallback)
}

// run executes `go <args...>` in dir and returns combined output + error.
func run(ctx context.Context, gobin, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, gobin, args...)
	cmd.Dir = dir
	cmd.Env = SecureBuildEnv()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// GitCommitter commits the generated workflow to git. The repo is
// detected by walking up from the workflows dir; if no .git is found,
// the commit silently no-ops (REACTOR_GIT_BACKED=false path).
type GitCommitter struct {
	GitBin string
}

// Commit stages the workflow dir and creates a feat commit. Callers
// that already have a fully-formatted commit message (notably
// knowledge.Store) should use CommitMessage to skip the slug-shaped
// format string.
func (c *GitCommitter) Commit(ctx context.Context, dir, slug, version string) error {
	// Detect knowledge-like callers (slug="knowledge", version="add:..."
	// or "supersede:...", etc) and format a clean conventional commit
	// instead of the workflow-shaped one. Keeps the Committer interface
	// stable while letting both consumers produce sensible messages.
	if slug == "knowledge" {
		return c.CommitMessage(ctx, dir, fmt.Sprintf("docs(knowledge): %s", version))
	}
	return c.CommitMessage(ctx, dir, fmt.Sprintf("feat(workflow): %s v%s", slug, version))
}

// CommitMessage stages dir + commits with the supplied message
// verbatim. No-ops gracefully when no .git repo is found above dir.
func (c *GitCommitter) CommitMessage(ctx context.Context, dir, msg string) error {
	gitbin := c.GitBin
	if gitbin == "" {
		gitbin = "git"
	}
	cur := dir
	for {
		if _, err := os.Stat(filepath.Join(cur, ".git")); err == nil {
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return nil // no repo, no-op
		}
		cur = parent
	}
	rel, err := filepath.Rel(cur, dir)
	if err != nil {
		return err
	}
	if _, err := runCmd(ctx, gitbin, cur, "add", rel); err != nil {
		return fmt.Errorf("git add: %w", err)
	}
	if _, err := runCmd(ctx, gitbin, cur, "commit", "-m", msg); err != nil {
		return fmt.Errorf("git commit: %w", err)
	}
	return nil
}

func runCmd(ctx context.Context, bin, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
