package main

import (
	"context"
	"log/slog"

	"github.com/bright-interaction/reactor/internal/catalog"
	"github.com/bright-interaction/reactor/internal/codegen"
	knowledgepkg "github.com/bright-interaction/reactor/internal/knowledge"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// editValidator adapts codegen.GoBuildValidator to the server's
// CodeValidator surface. Translates the (dir, slug, code, dag) call
// shape into the EmitInput the codegen path expects so the editor
// save runs through the exact same gates as a generate.
type editValidator struct{}

func (editValidator) Validate(ctx context.Context, dir, slug, workflowGo, dagJSON string) error {
	v := &codegen.GoBuildValidator{}
	return v.Validate(ctx, dir, codegen.EmitInput{
		Slug:       slug,
		WorkflowGo: workflowGo,
		DAGJson:    dagJSON,
	})
}

// generatorAdapter bridges the codegen.Generator's Generate(req) shape
// to the server.WorkflowGenerator interface (GenerateFromBrief). Keeps
// the server package free of the internal/codegen import so read-only
// deployments don't pull in the Anthropic HTTP client.
type generatorAdapter struct {
	gen *codegen.Generator
}

func (a generatorAdapter) GenerateFromBrief(ctx context.Context, brief string) (string, string, string, error) {
	// Inject the service catalog so the generator knows every CRM / PM / API
	// integration's base URL, auth, and operations instead of guessing.
	res, err := a.gen.Generate(ctx, codegen.GenerateRequest{Brief: brief, Environment: catalog.RenderForAI()})
	if err != nil {
		return "", "", "", err
	}
	return res.Slug, res.Path, res.Version, nil
}

// knowledgeAdapter bridges knowledge.Store onto server.KnowledgeWriter.
// Keeps the server package free of the knowledge import beyond the
// interface declaration.
type knowledgeAdapter struct {
	store *knowledgepkg.Store
	log   *slog.Logger
}

func (a knowledgeAdapter) AddEntry(ctx context.Context, topic, title, body, createdBy string, tags []string) (string, error) {
	if createdBy == "" {
		createdBy = "operator"
	}
	entry, err := a.store.Add(ctx, knowledgepkg.Entry{
		Frontmatter: knowledgepkg.Frontmatter{
			Topic:     topic,
			Title:     title,
			Tags:      tags,
			CreatedBy: createdBy,
		},
		Body: body,
	})
	if err != nil {
		return "", err
	}
	return entry.Frontmatter.ID, nil
}

func (a knowledgeAdapter) SupersedeEntry(ctx context.Context, oldID, newID string) error {
	// Operator path: link the existing entry as superseded by `newID`
	// without minting a new entry. The knowledge.Store.Supersede flow
	// expects a NEW entry; we adapt by creating a stub that references
	// the operator-supplied newID via the Supersedes chain.
	existing, err := a.store.Get(ctx, oldID)
	if err != nil {
		return err
	}
	stub := knowledgepkg.Entry{
		Frontmatter: knowledgepkg.Frontmatter{
			ID:        newID,
			Topic:     existing.Frontmatter.Topic,
			Title:     existing.Frontmatter.Title + " (replaced)",
			Tags:      existing.Frontmatter.Tags,
			CreatedBy: "operator",
		},
		Body: "Superseded by operator action via dashboard. See `" + newID + "` for the replacement entry.",
	}
	_, err = a.store.Supersede(ctx, oldID, stub, "dashboard")
	return err
}

func (a knowledgeAdapter) PromoteEntry(ctx context.Context, id string) error {
	_, err := a.store.PromoteGold(ctx, id, true)
	return err
}

func (a knowledgeAdapter) StaleEntry(ctx context.Context, id string) error {
	_, err := a.store.MarkStale(ctx, id)
	return err
}

// workflowRegistrarAdapter implements server.WorkflowRegistrar by
// running the canonical codegen.BuildAndRegister pipeline (the same
// helper the codegen prompt bar's auto-build step + the CLI register
// command go through).
type workflowRegistrarAdapter struct {
	registry  *registry.FileRegistry
	journal   *journal.Journal
	root      string
	committer *codegen.GitCommitter
	log       *slog.Logger
}

func (a workflowRegistrarAdapter) RegisterFromDir(ctx context.Context, slug, src, tenantID string) (string, error) {
	return a.registerFromDir(ctx, slug, src, tenantID, 0)
}

// RegisterFromDirExpected is the revision-fenced editor path. The legacy
// RegisterFromDir method remains for first registration and callers that do
// not have a reviewed baseline (for example knowledge uploads).
func (a workflowRegistrarAdapter) RegisterFromDirExpected(ctx context.Context, slug, src, tenantID string, expectedVersion int) (string, error) {
	return a.registerFromDir(ctx, slug, src, tenantID, expectedVersion)
}

func (a workflowRegistrarAdapter) registerFromDir(ctx context.Context, slug, src, tenantID string, expectedVersion int) (string, error) {
	res, err := codegen.BuildAndRegister(ctx, a.journal, codegen.BuildAndRegisterRequest{
		Slug:            slug,
		SrcDir:          src,
		StateRoot:       a.root,
		SDKVersion:      "0.1.0",
		SkipIfExists:    true,
		TenantID:        tenantID,
		ExpectedVersion: expectedVersion,
		RetainSource:    true,
	})
	if err != nil {
		return "", err
	}
	return res.WorkflowID, nil
}
