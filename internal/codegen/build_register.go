package codegen

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bright-interaction/reactor/internal/registry"
)

// BuildAndRegisterRequest is the input to BuildAndRegister. Every field
// except Journal is optional; sensible defaults are documented inline.
type BuildAndRegisterRequest struct {
	// Slug is the workflow's filesystem-safe identifier; required.
	// Validated against IsValidSlug; an invalid slug returns an error
	// without touching disk or the journal.
	Slug string

	// SrcDir is the directory containing the workflow's main.go +
	// optional dag.json. The go build command runs with cmd.Dir = SrcDir.
	SrcDir string

	// StateRoot is the daemon's state directory. The compiled binary is
	// published below <StateRoot>/workflows/<Slug>/artifacts/sha256/<digest>/
	// and selected by candidate.sha256; workflow is compatibility-only.
	StateRoot string

	// SDKVersion is recorded on the workflows row + the version-1
	// workflow_versions row. Defaults to "0.1.0" when empty.
	SDKVersion string

	// SkipIfExists, when true, reuses the existing workflow_id instead of
	// inserting a duplicate workflow row. A successful build still appends a
	// new immutable artifact-bound workflow version.
	SkipIfExists bool

	// TenantID owns the resulting workflow. Empty means the journal's default
	// tenant, which is what the CLI and MCP callers get since neither carries a
	// tenant context. The dashboard passes the operator's choice.
	TenantID string
}

// BuildAndRegisterResult is the output of BuildAndRegister.
type BuildAndRegisterResult struct {
	WorkflowID string
	BinaryPath string
	CodeHash   string
	DAGRaw     json.RawMessage
}

// JournalForBuildRegister is the subset of *journal.Journal that
// BuildAndRegister needs. Defined as an interface so tests can mock
// without spinning up a real database, and so the codegen package
// doesn't pull in the full journal API just to expose this helper.
type JournalForBuildRegister interface {
	WorkflowIDBySlug(ctx context.Context, slug string) (string, error)
	// WorkflowIDBySlugInTenant scopes the lookup. Slugs are unique PER TENANT,
	// so the unscoped form answers "does ANY tenant own this slug", which is the
	// wrong question for a re-registration check.
	WorkflowIDBySlugInTenant(ctx context.Context, slug, tenantID string) (string, error)
	CreateWorkflow(ctx context.Context, id, slug, codeHash, sdkVersion string, dag json.RawMessage) error
	// CreateWorkflowInTenant is the tenant-aware writer. CreateWorkflow
	// delegates to it with the default tenant, so both stay on this interface
	// while callers without a tenant context keep the shorter one.
	CreateWorkflowInTenant(ctx context.Context, id, slug, codeHash, sdkVersion string, dag json.RawMessage, tenantID string) error
	CreateWorkflowInTenantWithArtifact(ctx context.Context, id, slug, codeHash, sdkVersion, artifactSHA256 string, dag json.RawMessage, tenantID string) error
	RecordWorkflowVersionWithArtifact(ctx context.Context, workflowID, sdkVersion, codeHash, artifactSHA256 string, dag json.RawMessage) (int, error)
	ActivateWorkflowArtifactIfCurrent(ctx context.Context, workflowID string, version int, artifactSHA256 string, activate func() error) (bool, error)
}

// BuildAndRegister is the canonical "compile a workflow + insert the
// workflows row" pipeline. Replaces the three near-identical copies
// that lived under cmd/reactor/serve.go's workflowRegistrarAdapter,
// internal/server/codegen_write.go's autoBuildAndRegister, and
// cmd/reactor/workflow.go's cmdWorkflowBuild + cmdWorkflowRegister
// chain.
//
// Steps:
//  1. Validate slug.
//  2. mkdir -p <StateRoot>/workflows/<Slug> with mode 0700.
//  3. go build to a private stage (cwd = SrcDir).
//  4. Compute SHA-256 of <SrcDir>/main.go (16-char hex prefix).
//  5. Read <SrcDir>/dag.json (optional; defaults to "{}").
//  6. Publish the compiled bytes under their SHA-256 content address.
//  7. If SkipIfExists and the slug exists, append its next artifact-bound
//     version; otherwise mint a workflow_id + atomically insert version 1.
//  8. Record the immutable candidate selected by split build/test tooling.
//  9. Refresh the mutable compatibility binary under the workflow-version row
//     lock, but only if this registration is still current.
func BuildAndRegister(ctx context.Context, j JournalForBuildRegister, req BuildAndRegisterRequest) (BuildAndRegisterResult, error) {
	if req.Slug == "" || !IsValidSlug(req.Slug) {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: invalid slug %q (must match ^[a-z][a-z0-9-]*$)", req.Slug)
	}
	if req.SrcDir == "" {
		return BuildAndRegisterResult{}, errors.New("build_and_register: SrcDir is required")
	}
	if req.StateRoot == "" {
		return BuildAndRegisterResult{}, errors.New("build_and_register: StateRoot is required")
	}
	if req.SDKVersion == "" {
		req.SDKVersion = "0.1.0"
	}

	binDir := filepath.Join(req.StateRoot, "workflows", req.Slug)
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: mkdir %s: %w", binDir, err)
	}
	// The daemon owns module setup on every path into a compile. The shared
	// preparation gate rejects module-graph escape hatches, discards supplied
	// go.mod/go.sum files, and creates the workflow-local module used below.
	if err := PrepareWorkflowModule(ctx, "go", req.SrcDir, req.Slug); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: prepare module: %w", err)
	}
	// Static import allowlist BEFORE compiling: a hostile brief or saved
	// edit must not pull a third-party module that could run code at build
	// time. Workflows are sandboxed at runtime, but `go build` is not.
	if err := CheckAllowedImports(req.SrcDir); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: %w", err)
	}
	// Lint the workflow source so the auto-build path enforces the same
	// gate the codegen validator does (the dashboard upload + codegen
	// auto-build paths previously built with no lint at all).
	if src, err := os.ReadFile(filepath.Join(req.SrcDir, "main.go")); err == nil {
		if lerr := lintWorkflow(string(src)); lerr != nil {
			return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: reactor lint: %w", lerr)
		}
	}

	// Preflight: a workflow is compiled with `go build`, so the toolchain must
	// be on PATH. The distroless production image ships no compiler, so without
	// this check the dashboard codegen/upload paths fail with an opaque
	// "go: not found" behind a generic error page and the workflow is left in
	// "missing" status with no explanation. Surface the real cause instead.
	if _, err := exec.LookPath("go"); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: the Go toolchain is required to compile workflows but %q was not found on PATH (expected in the distroless production image); build workflows with the reactor CLI on a host that has Go, or deploy an image that bundles the toolchain: %w", "go", err)
	}

	stage, err := os.CreateTemp(binDir, ".workflow-build-")
	if err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: create binary stage: %w", err)
	}
	stagePath := stage.Name()
	if err := stage.Close(); err != nil {
		_ = os.Remove(stagePath)
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: close binary stage: %w", err)
	}
	_ = os.Remove(stagePath) // go build requires control of the output file.
	defer os.Remove(stagePath)
	cmd := exec.CommandContext(ctx, "go", "build", BuildVCSFlag, "-o", stagePath, ".")
	cmd.Dir = req.SrcDir
	cmd.Env = SecureBuildEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: go build: %w (output: %s)", err, string(out))
	}
	fileRegistry := registry.New(filepath.Join(req.StateRoot, "workflows"))
	artifact, err := fileRegistry.PublishArtifact(req.Slug, stagePath)
	if err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: publish immutable artifact: %w", err)
	}
	if err := fileRegistry.SetBuildArtifact(req.Slug, artifact.Digest); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: record candidate artifact: %w", err)
	}

	codeHash := ""
	if raw, err := os.ReadFile(filepath.Join(req.SrcDir, "main.go")); err == nil {
		sum := sha256.Sum256(raw)
		codeHash = hex.EncodeToString(sum[:])[:16]
	}
	dag := json.RawMessage(`{}`)
	if raw, err := os.ReadFile(filepath.Join(req.SrcDir, "dag.json")); err == nil && json.Valid(raw) {
		dag = raw
	}

	res := BuildAndRegisterResult{
		BinaryPath: artifact.Path,
		CodeHash:   codeHash,
		DAGRaw:     dag,
	}

	if req.SkipIfExists {
		// Scope the "already registered?" check to the TARGET tenant. Using the
		// unscoped lookup here meant registering a slug into tenant B silently
		// returned tenant A's workflow id and wrote no row at all, so the upload
		// reported success (303) while the workflow never existed in B. Slugs
		// are unique per tenant, so "some tenant owns this slug" is the wrong
		// question.
		if existing, err := j.WorkflowIDBySlugInTenant(ctx, req.Slug, req.TenantID); err == nil && existing != "" {
			version, err := j.RecordWorkflowVersionWithArtifact(ctx, existing, req.SDKVersion, codeHash, artifact.Digest, dag)
			if err != nil {
				return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: record workflow version: %w", err)
			}
			if _, err := j.ActivateWorkflowArtifactIfCurrent(ctx, existing, version, artifact.Digest, func() error {
				_, err := fileRegistry.ActivateArtifact(req.Slug, artifact.Digest)
				return err
			}); err != nil {
				return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: activate workflow artifact: %w", err)
			}
			res.WorkflowID = existing
			return res, nil
		}
	}

	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: id: %w", err)
	}
	wfID := "wf_" + hex.EncodeToString(idBytes)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, wfID, req.Slug, codeHash, req.SDKVersion, artifact.Digest, dag, req.TenantID); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: create workflow: %w", err)
	}
	if _, err := j.ActivateWorkflowArtifactIfCurrent(ctx, wfID, 1, artifact.Digest, func() error {
		_, err := fileRegistry.ActivateArtifact(req.Slug, artifact.Digest)
		return err
	}); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: activate workflow artifact: %w", err)
	}
	res.WorkflowID = wfID
	return res, nil
}

// BuildSourceRequest is the input to BuildAndRegisterSource.
type BuildSourceRequest struct {
	// Slug is the workflow's filesystem-safe identifier; required.
	Slug string
	// MainGo is the workflow's main.go source; required.
	MainGo string
	// DAGJSON is the optional dag.json body; defaults to "{}" when empty or
	// not valid JSON.
	DAGJSON string
	// StateRoot is the daemon's state directory; compiled bytes are published
	// under the slug's immutable SHA-256 artifact namespace.
	StateRoot string
	// SDKVersion is recorded on the workflows row; defaults to "0.1.0".
	SDKVersion string
	// SkipIfExists reuses the existing id and appends an immutable version when
	// the slug is already registered.
	SkipIfExists bool
}

// BuildAndRegisterSource compiles + registers a workflow from source the
// caller supplies directly (no go.mod needed: it inits a workflow-local
// module wired to the SDK). This is the MCP/programmatic authoring path -- an
// AI client writes the Go, Reactor builds it in-container with NO external
// LLM/API key and no shell access. The source is materialised + built in a
// temp dir (kept out of the workflows tree), and the compiled binary lands at
// an immutable content address via BuildAndRegister, which also runs
// the import allowlist + lint + go build gates.
func BuildAndRegisterSource(ctx context.Context, j JournalForBuildRegister, req BuildSourceRequest) (BuildAndRegisterResult, error) {
	if req.Slug == "" || !IsValidSlug(req.Slug) {
		return BuildAndRegisterResult{}, fmt.Errorf("build_source: invalid slug %q (must match ^[a-z][a-z0-9-]*$)", req.Slug)
	}
	if strings.TrimSpace(req.MainGo) == "" {
		return BuildAndRegisterResult{}, errors.New("build_source: main_go is required")
	}
	if req.StateRoot == "" {
		return BuildAndRegisterResult{}, errors.New("build_source: StateRoot is required")
	}
	if _, err := exec.LookPath("go"); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_source: the Go toolchain is required to compile workflows but %q was not found on PATH (expected in the distroless production image): %w", "go", err)
	}
	tmp, err := os.MkdirTemp("", "reactor-src-")
	if err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_source: tmp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	if err := os.WriteFile(filepath.Join(tmp, "main.go"), []byte(req.MainGo), 0o600); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_source: write main.go: %w", err)
	}
	dag := strings.TrimSpace(req.DAGJSON)
	if dag == "" || !json.Valid([]byte(dag)) {
		dag = "{}"
	}
	if err := os.WriteFile(filepath.Join(tmp, "dag.json"), []byte(dag), 0o600); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_source: write dag.json: %w", err)
	}
	// Module setup (and the vendor/go.work rejection) now lives in
	// BuildAndRegister so every compile path gets it, not just this one.
	return BuildAndRegister(ctx, j, BuildAndRegisterRequest{
		Slug:         req.Slug,
		SrcDir:       tmp,
		StateRoot:    req.StateRoot,
		SDKVersion:   req.SDKVersion,
		SkipIfExists: req.SkipIfExists,
	})
}
