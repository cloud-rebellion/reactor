package codegen

import (
	"bytes"
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
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// BuildAndRegisterRequest is the input to BuildAndRegister. Every field
// except Journal is optional; sensible defaults are documented inline.
type BuildAndRegisterRequest struct {
	// Slug is the workflow's filesystem-safe identifier; required.
	// Validated against IsValidSlug; an invalid slug returns an error
	// without touching disk or the journal.
	Slug string

	// SrcDir is the directory containing the workflow's main.go and, when the
	// source uses durable Reactor nodes, a matching visual dag.json. The source
	// is copied into a private build directory;
	// caller-owned files are never rewritten by module preparation or the
	// compiler.
	SrcDir string

	// StateRoot is the daemon's state directory. The compiled binary is
	// published below the legacy <StateRoot>/workflows/<Slug>/ namespace when
	// available, or the hashed tenant namespace for a same-slug collision. In
	// either layout the immutable executable lives under
	// artifacts/sha256/<digest>/ and candidate.sha256 selects the build;
	// workflow is compatibility-only.
	StateRoot string

	// SDKVersion is recorded on the workflows row + the version-1
	// workflow_versions row. Defaults to "0.1.0" when empty.
	SDKVersion string

	// SkipIfExists, when true, reuses the existing workflow_id instead of
	// inserting a duplicate workflow row. An exact retained-source retry also
	// reuses the current immutable version; changed source appends a new one.
	SkipIfExists bool

	// TenantID owns the resulting workflow. Empty means the journal's default
	// tenant, which is what the CLI and MCP callers get since neither carries a
	// tenant context. The dashboard passes the operator's choice.
	TenantID string

	// StartDisabled stages MCP-authored workflows for explicit review and
	// activation. CLI/build callers retain the historical enabled default.
	StartDisabled bool
	// ExpectedVersion is the immutable version reviewed before a revision. It is
	// required when StartDisabled reuses an existing workflow and is also used
	// by journal-backed dashboard edits to fence active workflows atomically.
	ExpectedVersion int

	// RetainSource stores the complete staged source tree (plus a content
	// manifest) beside the current workflow and inside the immutable artifact
	// directory. MCP authoring sets this because its input is otherwise
	// materialised in a disposable staging directory.
	RetainSource bool
}

// BuildAndRegisterResult is the output of BuildAndRegister.
type BuildAndRegisterResult struct {
	WorkflowID string
	// Version and ArtifactSHA256 identify the exact immutable executable
	// registered by this build. Callers should use these values for review and
	// receipts instead of re-reading a mutable workflow row after the build.
	Version        int
	ArtifactSHA256 string
	// Idempotent is true when the requested artifact already was the current
	// version and the build was safely treated as a retry.
	Idempotent bool
	BinaryPath string
	// SourcePath is populated when RetainSource is true and points to the
	// current workflow source snapshot. The immutable copy lives beside the
	// artifact at filepath.Join(filepath.Dir(BinaryPath), "source").
	SourcePath string
	CodeHash   string
	DAGRaw     json.RawMessage
}

// JournalForBuildRegister is the subset of *journal.Journal that
// BuildAndRegister needs. Defined as an interface so tests can mock
// without spinning up a real database, and so the codegen package
// doesn't pull in the full journal API just to expose this helper.
type JournalForBuildRegister interface {
	WorkflowIDBySlug(ctx context.Context, slug string) (string, error)
	// WorkflowTenantsBySlug enumerates every owner because the database allows
	// duplicate slugs per tenant. A cross-tenant collision selects the registry's
	// hashed tenant namespace rather than overwriting another tenant's mutable
	// compatibility files.
	WorkflowTenantsBySlug(ctx context.Context, slug string) ([]string, error)
	// WorkflowIDBySlugInTenant scopes the lookup. Slugs are unique PER TENANT,
	// so the unscoped form answers "does ANY tenant own this slug", which is the
	// wrong question for a re-registration check.
	WorkflowIDBySlugInTenant(ctx context.Context, slug, tenantID string) (string, error)
	CreateWorkflow(ctx context.Context, id, slug, codeHash, sdkVersion string, dag json.RawMessage) error
	// CreateWorkflowInTenant is the tenant-aware writer. CreateWorkflow
	// delegates to it with the default tenant, so both stay on this interface
	// while callers without a tenant context keep the shorter one.
	CreateWorkflowInTenant(ctx context.Context, id, slug, codeHash, sdkVersion string, dag json.RawMessage, tenantID string) error
	CreateWorkflowInTenantWithArtifact(ctx context.Context, id, slug, codeHash, sdkVersion, artifactSHA256 string, dag json.RawMessage, tenantID string, sourceManifestSHA256 ...string) error
	RecordWorkflowVersionWithArtifact(ctx context.Context, workflowID, sdkVersion, codeHash, artifactSHA256 string, dag json.RawMessage, sourceManifestSHA256 ...string) (int, error)
	ActivateWorkflowArtifactIfCurrent(ctx context.Context, workflowID string, version int, artifactSHA256 string, activate func() error) (bool, error)
}

// MCPAuthoringJournal is the optional journal surface used to stage authored
// workflows disabled and reject hot replacement of an active workflow.
type MCPAuthoringJournal interface {
	CreateWorkflowInTenantWithArtifactDisabled(ctx context.Context, id, slug, codeHash, sdkVersion, artifactSHA256 string, dag json.RawMessage, tenantID string, sourceManifestSHA256 ...string) error
	RecordWorkflowVersionWithArtifactIfDisabled(ctx context.Context, workflowID, sdkVersion, codeHash, artifactSHA256 string, dag json.RawMessage, sourceManifestSHA256 ...string) (int, error)
}

type mcpAuthoringCASJournal interface {
	RecordWorkflowVersionWithArtifactIfDisabledExpected(ctx context.Context, workflowID, sdkVersion, codeHash, artifactSHA256 string, dag json.RawMessage, expectedVersion int, sourceManifestSHA256 ...string) (int, error)
}

type workflowRevisionCASJournal interface {
	RecordWorkflowVersionWithArtifactExpected(ctx context.Context, workflowID, sdkVersion, codeHash, artifactSHA256 string, dag json.RawMessage, expectedVersion int, sourceManifestSHA256 ...string) (int, error)
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
//  2. Copy SrcDir into a private, validated build directory.
//  3. mkdir -p <StateRoot>/workflows/<Slug> with mode 0700.
//  4. Prepare the private module, scan imports/lint, run go vet, and go build there.
//  5. Compute SHA-256 of the staged main.go (16-char hex prefix) and read the
//     staged dag.json (defaults to "{}" only for source with no durable
//     Reactor nodes).
//  6. Publish the compiled bytes under their SHA-256 content address.
//  7. If SkipIfExists and the slug exists, reuse the current immutable version
//     for an exact retained-source retry; otherwise append its next
//     artifact-bound version or mint a workflow_id + insert version 1.
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
	fileRegistry := registry.New(filepath.Join(req.StateRoot, "workflows"))
	releaseSlug, err := fileRegistry.AcquireSlugLock(ctx, req.Slug)
	if err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: lock workflow filesystem namespace: %w", err)
	}
	defer releaseSlug()
	ctx, releaseCompiler, err := workflowCompilerAdmission.acquireContext(ctx)
	if err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: %w", err)
	}
	defer releaseCompiler()
	// The immutable artifact directories are digest-scoped. Existing installs
	// keep candidate.sha256, source, and the compatibility workflow under the
	// legacy slug directory; when another tenant already owns that slug, the
	// requested tenant receives an isolated hashed namespace instead. Journal
	// implementations are required to provide the full owner inventory so the
	// choice is made before staging/building and a query failure is fail-closed.
	owners, err := j.WorkflowTenantsBySlug(ctx, req.Slug)
	if err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: check workflow filesystem namespace: %w", err)
	}
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		tenantID = journal.DefaultTenant
	}
	// Keep the normalized owner on the request passed to every later journal
	// lookup/write. The filesystem claim above used the normalized value, but
	// leaving req.TenantID empty made the same build query the unscoped journal
	// path and could register or revise the wrong tenant.
	req.TenantID = tenantID
	// Bind the node-local executable namespace before compiling. Preserve a
	// matching legacy owner for backwards-compatible paths. A slug owned by a
	// different tenant is placed below the hashed tenant namespace, which lets
	// the journal's per-tenant slug uniqueness and the filesystem coexist.
	legacyOwner, legacyOwnerErr := fileRegistry.TenantOwner(req.Slug)
	if legacyOwnerErr != nil && !errors.Is(legacyOwnerErr, registry.ErrTenantOwnerMissing) {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: inspect workflow filesystem namespace: %w", legacyOwnerErr)
	}
	useScopedNamespace := legacyOwnerErr == nil && legacyOwner != tenantID
	if legacyOwnerErr != nil {
		for _, owner := range owners {
			if strings.TrimSpace(owner) != tenantID {
				useScopedNamespace = true
				break
			}
		}
	}
	var binDir string
	if useScopedNamespace {
		binDir, err = fileRegistry.EnsureScopedTenant(req.Slug, tenantID)
		if err != nil {
			return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: claim isolated workflow filesystem namespace: %w", err)
		}
	} else {
		// A pre-manifest legacy directory is accepted only when the journal
		// already proved that the requested tenant owns the slug (migration),
		// or when the directory is genuinely fresh.
		if err := fileRegistry.EnsureTenant(req.Slug, tenantID, len(owners) > 0); err != nil {
			return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: claim workflow filesystem namespace: %w", err)
		}
		binDir = filepath.Join(req.StateRoot, "workflows", req.Slug)
	}
	// All registration callers (including the dashboard and adapter paths)
	// must get the same non-destructive source boundary as the CLI. In
	// particular, PrepareWorkflowModule removes caller-supplied go.mod/go.sum
	// and writes a daemon-owned module; doing that in-place both surprises
	// authors and makes the build depend on a mutable tree.
	buildSrc, cleanup, err := StageWorkflowSource(req.SrcDir)
	if err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: %w", err)
	}
	defer cleanup()
	if _, err := readBoundedSourceFile(filepath.Join(buildSrc, "main.go"), maxWorkflowSourceBytes); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: read main.go: %w", err)
	}
	dag, err := readWorkflowDAG(buildSrc)
	if err != nil {
		return BuildAndRegisterResult{}, err
	}
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: mkdir %s: %w", binDir, err)
	}
	// The daemon owns module setup on every path into a compile. The shared
	// preparation gate rejects module-graph escape hatches, discards supplied
	// go.mod/go.sum files, and creates the workflow-local module used below.
	if err := PrepareWorkflowModule(ctx, "go", buildSrc, req.Slug); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: prepare module: %w", err)
	}
	// Static import allowlist BEFORE compiling: a hostile brief or saved
	// edit must not pull a third-party module that could run code at build
	// time. Workflows are sandboxed at runtime, but `go build` is not.
	if err := CheckAllowedImports(buildSrc); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: %w", err)
	}
	// Lint every compiled workflow source file so helper packages cannot
	// bypass the determinism and process-safety rules by putting a forbidden
	// call outside main.go. CheckAllowedImports already walks the tree; the
	// lint pass must cover the same tree.
	if issues, lerr := LintDir(buildSrc); lerr != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: reactor lint: %w", lerr)
	} else if len(issues) > 0 {
		parts := make([]string, 0, len(issues))
		for _, issue := range issues {
			parts = append(parts, issue.Format())
		}
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: reactor lint: %s", strings.Join(parts, "; "))
	}

	// Preflight: a workflow is compiled with `go build`, so the toolchain must
	// be on PATH. A native or custom image without Go would otherwise make
	// the dashboard codegen/upload paths fail with an opaque
	// "go: not found" behind a generic error page and the workflow is left in
	// "missing" status with no explanation. Surface the real cause instead.
	if _, err := exec.LookPath("go"); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: the Go toolchain is required to compile workflows but %q was not found on PATH; install Go for native authoring or use an image that bundles the toolchain: %w", "go", err)
	}
	selectedGoFiles, err := SelectedExecutableGoFiles(ctx, "go", buildSrc)
	if err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: %w", err)
	}
	if err := ValidateSourceDAGFiles(buildSrc, dag, selectedGoFiles); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: %w", err)
	}
	// Keep the persistence path identical to the non-persisting authoring
	// preflight. A caller can invoke reactor_create_workflow directly (or use a
	// legacy CLI/dashboard path), so relying on a prior validate call would let
	// code that builds but fails go vet become an immutable executable. Run vet
	// after the import/lint gates and before publishing or touching the journal.
	if out, vetErr := run(ctx, "go", buildSrc, "vet", "./..."); vetErr != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: go vet: %w\n%s", vetErr, out)
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
	// BuildAndRegisterSource stages every request in a fresh private directory.
	// Without -trimpath, otherwise identical source can embed that directory
	// in the binary and produce a new content address on an exact retry.
	cmd := exec.CommandContext(ctx, "go", "build", BuildVCSFlag, "-trimpath", "-o", stagePath, ".")
	cmd.Dir = buildSrc
	cmd.Env = SecureBuildEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: go build: %w (output: %s)", err, string(out))
	}
	var artifact registry.Artifact
	if useScopedNamespace {
		artifact, err = fileRegistry.PublishArtifactForTenant(req.Slug, stagePath, tenantID)
	} else {
		artifact, err = fileRegistry.PublishArtifact(req.Slug, stagePath)
	}
	if err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: publish immutable artifact: %w", err)
	}
	var sourceFiles map[string][]byte
	var sourcePinArgs []string
	var sourceManifestDigest string
	if req.RetainSource {
		sourceFiles, err = retainImmutableWorkflowSource(buildSrc, filepath.Dir(artifact.Path), selectedGoFiles)
		if err != nil {
			return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: retain source: %w", err)
		}
		manifest := sourceFiles[registry.SourceManifestFilename]
		if len(manifest) == 0 {
			return BuildAndRegisterResult{}, errors.New("build_and_register: retained source manifest is missing")
		}
		manifestSum := sha256.Sum256(manifest)
		sourceManifestDigest = hex.EncodeToString(manifestSum[:])
		sourcePinArgs = []string{sourceManifestDigest}
	}
	// Mutable review files and the compatibility pointer follow only an
	// accepted, still-current registration. Refused or superseded edits must
	// not replace the source an operator sees for the registered version.
	activateArtifact := func(digest string) error {
		if req.RetainSource {
			if err := writeCurrentSource(filepath.Join(binDir, "source"), sourceFiles); err != nil {
				return fmt.Errorf("write current source: %w", err)
			}
		}
		if useScopedNamespace {
			if err := fileRegistry.SetBuildArtifactForTenant(req.Slug, digest, tenantID); err != nil {
				return fmt.Errorf("record candidate artifact: %w", err)
			}
			_, err = fileRegistry.ActivateArtifactForTenant(req.Slug, digest, tenantID)
		} else {
			if err := fileRegistry.SetBuildArtifact(req.Slug, digest); err != nil {
				return fmt.Errorf("record candidate artifact: %w", err)
			}
			_, err = fileRegistry.ActivateArtifact(req.Slug, digest)
		}
		return err
	}
	activate := func() error { return activateArtifact(artifact.Digest) }

	codeHash := ""
	if raw, err := os.ReadFile(filepath.Join(buildSrc, "main.go")); err == nil {
		sum := sha256.Sum256(raw)
		codeHash = hex.EncodeToString(sum[:])[:16]
	}
	res := BuildAndRegisterResult{
		BinaryPath:     artifact.Path,
		ArtifactSHA256: artifact.Digest,
		CodeHash:       codeHash,
		DAGRaw:         dag,
	}
	if req.RetainSource {
		res.SourcePath = filepath.Join(binDir, "source")
	}

	if req.SkipIfExists {
		// Scope the "already registered?" check to the TARGET tenant. Using the
		// unscoped lookup here meant registering a slug into tenant B silently
		// returned tenant A's workflow id and wrote no row at all, so the upload
		// reported success (303) while the workflow never existed in B. Slugs
		// are unique per tenant, so "some tenant owns this slug" is the wrong
		// question.
		if existing, err := j.WorkflowIDBySlugInTenant(ctx, req.Slug, req.TenantID); err == nil && existing != "" {
			// MCP clients may retry after a transport timeout. If the exact
			// artifact and metadata are already current, return the existing
			// immutable receipt instead of appending a duplicate version. Keep
			// this optional so older build-test journals remain source compatible.
			if reader, ok := j.(interface {
				CurrentWorkflowVersionRecord(context.Context, string) (journal.WorkflowVersion, error)
			}); ok {
				if current, readErr := reader.CurrentWorkflowVersionRecord(ctx, existing); readErr == nil &&
					current.CodeHash == codeHash &&
					current.SDKVersion == req.SDKVersion && current.SourceManifestSHA256 == sourceManifestDigest && bytes.Equal(bytes.TrimSpace(current.DAG), bytes.TrimSpace(dag)) {
					// An idempotent retry is still a mutation request carrying an
					// optimistic-concurrency fence. Do not let an older review
					// silently succeed merely because it happens to submit the same
					// source as the current artifact; that would make a stale AI
					// authoring decision appear current. An omitted fence remains the
					// backwards-compatible retry form.
					if req.ExpectedVersion > 0 && req.ExpectedVersion != current.Version {
						return BuildAndRegisterResult{}, fmt.Errorf("%w: expected version %d, current version %d", journal.ErrWorkflowVersionConflict, req.ExpectedVersion, current.Version)
					}
					// The mutable source view may be stale or absent if the journal
					// committed but activation failed. A retained-source retry is
					// identified by the journal-pinned manifest, not that view. The
					// immutable source beside the registered artifact is verified
					// below before the retry can repair the mutable files.
					sourceMatches := req.RetainSource || current.ArtifactSHA256 == artifact.Digest
					if sourceMatches {
						// A previous attempt may have committed this exact version
						// and then failed while refreshing the filesystem compatibility
						// view (or while syncing it). Retrying an otherwise-idempotent
						// authoring request must replay that activation; returning here
						// would leave the durable row pointing at a valid artifact while
						// the dashboard/CLI view remained stale or absent forever.
						// Keep the already-registered immutable artifact as the retry
						// identity even if a toolchain or environment change produces a
						// different binary digest from the same retained source.
						retryDigest := current.ArtifactSHA256
						retryPath := artifact.Path
						if retryDigest == "" {
							return BuildAndRegisterResult{}, fmt.Errorf("%w: current workflow version has no immutable artifact", journal.ErrWorkflowArtifactFence)
						}
						if retryDigest != artifact.Digest {
							var pathErr error
							if useScopedNamespace {
								retryPath, pathErr = fileRegistry.ArtifactPathForTenant(req.Slug, retryDigest, tenantID)
							} else {
								retryPath, pathErr = fileRegistry.ArtifactPath(req.Slug, retryDigest)
							}
							if pathErr != nil {
								return BuildAndRegisterResult{}, fmt.Errorf("%w: current workflow artifact is unavailable: %v", journal.ErrWorkflowArtifactFence, pathErr)
							}
						}
						if req.RetainSource {
							present, digest, verifyErr := registry.VerifySourceManifestDigestIfPresent(filepath.Join(filepath.Dir(retryPath), "source"))
							if verifyErr != nil || !present || digest != current.SourceManifestSHA256 {
								return BuildAndRegisterResult{}, fmt.Errorf("%w: current workflow retained source proof is unavailable or mismatched", journal.ErrWorkflowArtifactFence)
							}
						}
						retryActivate := func() error { return activateArtifact(retryDigest) }
						var activated bool
						var activateErr error
						if req.StartDisabled {
							guarded, ok := j.(interface {
								ActivateWorkflowArtifactIfCurrentAndDisabled(context.Context, string, int, string, func() error) (bool, error)
							})
							if !ok {
								return BuildAndRegisterResult{}, errors.New("build_and_register: journal does not support disabled MCP retry fencing")
							}
							activated, activateErr = guarded.ActivateWorkflowArtifactIfCurrentAndDisabled(ctx, existing, current.Version, retryDigest, retryActivate)
						} else {
							activated, activateErr = j.ActivateWorkflowArtifactIfCurrent(ctx, existing, current.Version, retryDigest, retryActivate)
						}
						if activateErr != nil {
							return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: retry current artifact activation: %w", activateErr)
						}
						if !activated {
							return BuildAndRegisterResult{}, fmt.Errorf("%w: workflow changed while retrying artifact activation", journal.ErrWorkflowVersionConflict)
						}
						res.WorkflowID = existing
						res.Version = current.Version
						res.ArtifactSHA256 = retryDigest
						res.BinaryPath = retryPath
						res.Idempotent = true
						return res, nil
					}
				}
			}
			if req.StartDisabled && req.ExpectedVersion < 1 {
				return BuildAndRegisterResult{}, errors.New("build_and_register: expected_version is required when revising an existing MCP workflow")
			}
			var version int
			if req.StartDisabled {
				cas, ok := j.(mcpAuthoringCASJournal)
				if !ok {
					return BuildAndRegisterResult{}, errors.New("build_and_register: journal does not support MCP revision compare-and-swap")
				}
				version, err = cas.RecordWorkflowVersionWithArtifactIfDisabledExpected(ctx, existing, req.SDKVersion, codeHash, artifact.Digest, dag, req.ExpectedVersion, sourcePinArgs...)
			} else if req.ExpectedVersion > 0 {
				cas, ok := j.(workflowRevisionCASJournal)
				if !ok {
					return BuildAndRegisterResult{}, errors.New("build_and_register: journal does not support workflow revision compare-and-swap")
				}
				version, err = cas.RecordWorkflowVersionWithArtifactExpected(ctx, existing, req.SDKVersion, codeHash, artifact.Digest, dag, req.ExpectedVersion, sourcePinArgs...)
			} else {
				version, err = j.RecordWorkflowVersionWithArtifact(ctx, existing, req.SDKVersion, codeHash, artifact.Digest, dag, sourcePinArgs...)
			}
			if err != nil {
				return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: record workflow version: %w", err)
			}
			activated, err := j.ActivateWorkflowArtifactIfCurrent(ctx, existing, version, artifact.Digest, activate)
			if err != nil {
				return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: activate workflow artifact: %w", err)
			}
			if !activated {
				return BuildAndRegisterResult{}, fmt.Errorf("%w: workflow version %d was superseded before artifact activation", journal.ErrWorkflowVersionConflict, version)
			}
			res.WorkflowID = existing
			res.Version = version
			return res, nil
		}
	}
	if req.ExpectedVersion > 0 {
		return BuildAndRegisterResult{}, fmt.Errorf("%w: expected version %d, but workflow %q does not exist in tenant %q", journal.ErrWorkflowVersionConflict, req.ExpectedVersion, req.Slug, req.TenantID)
	}

	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: id: %w", err)
	}
	wfID := "wf_" + hex.EncodeToString(idBytes)
	var createErr error
	if req.StartDisabled {
		if mj, ok := j.(MCPAuthoringJournal); ok {
			createErr = mj.CreateWorkflowInTenantWithArtifactDisabled(ctx, wfID, req.Slug, codeHash, req.SDKVersion, artifact.Digest, dag, req.TenantID, sourcePinArgs...)
		} else {
			createErr = errors.New("build_and_register: journal does not support disabled MCP authoring")
		}
	} else {
		createErr = j.CreateWorkflowInTenantWithArtifact(ctx, wfID, req.Slug, codeHash, req.SDKVersion, artifact.Digest, dag, req.TenantID, sourcePinArgs...)
	}
	if createErr != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: create workflow: %w", createErr)
	}
	activated, err := j.ActivateWorkflowArtifactIfCurrent(ctx, wfID, 1, artifact.Digest, activate)
	if err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_and_register: activate workflow artifact: %w", err)
	}
	if !activated {
		return BuildAndRegisterResult{}, fmt.Errorf("%w: workflow version 1 was superseded before artifact activation", journal.ErrWorkflowVersionConflict)
	}
	res.WorkflowID = wfID
	res.Version = 1
	return res, nil
}

func readWorkflowDAG(srcDir string) (json.RawMessage, error) {
	raw, err := os.ReadFile(filepath.Join(srcDir, "dag.json"))
	if errors.Is(err, os.ErrNotExist) {
		return json.RawMessage(`{}`), nil
	}
	if err != nil {
		return nil, fmt.Errorf("build_and_register: read dag.json: %w", err)
	}
	if len(raw) > maxWorkflowDAGBytes {
		return nil, fmt.Errorf("build_and_register: dag.json exceeds %d-byte limit", maxWorkflowDAGBytes)
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "{}" {
		return json.RawMessage(`{}`), nil
	}
	if !json.Valid(raw) {
		return nil, errors.New("build_and_register: dag.json is not valid JSON")
	}
	if err := registry.ValidateDAG(raw); err != nil {
		return nil, fmt.Errorf("build_and_register: dag.json validation: %w", err)
	}
	return raw, nil
}

// BuildSourceRequest is the input to BuildAndRegisterSource.
type BuildSourceRequest struct {
	// Slug is the workflow's filesystem-safe identifier; required.
	Slug string
	// MainGo is the workflow's main.go source; required.
	MainGo string
	// Files contains optional additional text source/assets keyed by safe
	// relative path. main.go and dag.json are supplied by dedicated fields.
	Files map[string]string
	// DAGJSON is the dag.json body. It may be empty only when the source has no
	// durable Reactor nodes; empty input is normalized to "{}".
	DAGJSON string
	// StateRoot is the daemon's state directory; compiled bytes are published
	// under the slug's immutable SHA-256 artifact namespace.
	StateRoot string
	// SDKVersion is recorded on the workflows row; defaults to "0.1.0".
	SDKVersion string
	// SkipIfExists reuses the existing id and appends an immutable version when
	// the slug is already registered.
	SkipIfExists bool
	// TenantID owns the resulting workflow. Empty means the journal's default
	// tenant, matching the unqualified CLI behavior.
	TenantID string
	// StartDisabled stages MCP-authored workflows for explicit review and
	// activation. CLI/build callers retain the historical enabled default.
	StartDisabled bool
	// ExpectedVersion is the immutable version reviewed before a revision. It is
	// required when StartDisabled reuses an existing workflow and is also used
	// by journal-backed dashboard edits to fence active workflows atomically.
	ExpectedVersion int
}

const (
	maxWorkflowSourceBytes      = 4 << 20
	maxWorkflowDAGBytes         = 1 << 20
	maxWorkflowSourceFiles      = 256
	maxRetainedSourceFileBytes  = 16 << 20
	maxRetainedSourceTotalBytes = 64 << 20
)

// ValidateSourceRequest is the non-persisting authoring preflight. It uses
// the same import allowlist, lint, module setup, go vet and go build gates as
// BuildAndRegisterSource, but never publishes an artifact or touches the
// journal. MCP clients can call this before create_workflow to get deterministic
// feedback without creating a workflow row or executable.
type ValidateSourceRequest struct {
	Slug    string
	MainGo  string
	DAGJSON string
	Files   map[string]string
}

// ValidateWorkflowSource validates a proposed workflow without persisting it.
func ValidateWorkflowSource(ctx context.Context, req ValidateSourceRequest) error {
	if req.Slug == "" || !IsValidSlug(req.Slug) {
		return fmt.Errorf("validate_source: invalid slug %q", req.Slug)
	}
	if strings.TrimSpace(req.MainGo) == "" {
		return errors.New("validate_source: main_go is required")
	}
	if len(req.MainGo) > maxWorkflowSourceBytes {
		return fmt.Errorf("validate_source: main_go exceeds %d-byte limit", maxWorkflowSourceBytes)
	}
	dag := strings.TrimSpace(req.DAGJSON)
	if dag == "" {
		dag = "{}"
	} else if !json.Valid([]byte(dag)) {
		return errors.New("validate_source: dag_json is not valid JSON")
	} else if len(dag) > maxWorkflowDAGBytes {
		return fmt.Errorf("validate_source: dag.json exceeds %d-byte limit", maxWorkflowDAGBytes)
	} else if dag != "{}" {
		if err := registry.ValidateDAG([]byte(dag)); err != nil {
			return fmt.Errorf("validate_source: dag.json validation: %w", err)
		}
	}
	ctx, releaseCompiler, err := workflowCompilerAdmission.acquireContext(ctx)
	if err != nil {
		return fmt.Errorf("validate_source: %w", err)
	}
	defer releaseCompiler()
	tmp, err := os.MkdirTemp("", "reactor-validate-")
	if err != nil {
		return fmt.Errorf("validate_source: tmp dir: %w", err)
	}
	defer os.RemoveAll(tmp)
	if err := os.WriteFile(filepath.Join(tmp, "main.go"), []byte(req.MainGo), 0o600); err != nil {
		return fmt.Errorf("validate_source: write main.go: %w", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "dag.json"), []byte(dag), 0o600); err != nil {
		return fmt.Errorf("validate_source: write dag.json: %w", err)
	}
	if err := writeWorkflowAdditionalFiles(tmp, req.Files); err != nil {
		return fmt.Errorf("validate_source: %w", err)
	}
	if err := PrepareWorkflowModule(ctx, "go", tmp, req.Slug); err != nil {
		return fmt.Errorf("validate_source: prepare module: %w", err)
	}
	if err := (&GoBuildValidator{}).Validate(ctx, tmp, EmitInput{Slug: req.Slug, WorkflowGo: req.MainGo, DAGJson: dag}); err != nil {
		return fmt.Errorf("validate_source: %w", err)
	}
	return nil
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
	if len(req.MainGo) > maxWorkflowSourceBytes {
		return BuildAndRegisterResult{}, fmt.Errorf("build_source: main_go exceeds %d-byte limit", maxWorkflowSourceBytes)
	}
	if req.StateRoot == "" {
		return BuildAndRegisterResult{}, errors.New("build_source: StateRoot is required")
	}
	if _, err := exec.LookPath("go"); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_source: the Go toolchain is required to compile workflows but %q was not found on PATH; install Go for native authoring or use an image that bundles the toolchain: %w", "go", err)
	}
	ctx, releaseCompiler, err := workflowCompilerAdmission.acquireContext(ctx)
	if err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_source: %w", err)
	}
	defer releaseCompiler()
	tmp, err := os.MkdirTemp("", "reactor-src-")
	if err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_source: tmp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	if err := os.WriteFile(filepath.Join(tmp, "main.go"), []byte(req.MainGo), 0o600); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_source: write main.go: %w", err)
	}
	if err := writeWorkflowAdditionalFiles(tmp, req.Files); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_source: %w", err)
	}
	dag := strings.TrimSpace(req.DAGJSON)
	if dag == "" {
		dag = "{}"
	} else if !json.Valid([]byte(dag)) {
		return BuildAndRegisterResult{}, errors.New("build_source: dag_json is not valid JSON")
	}
	if len(dag) > maxWorkflowDAGBytes {
		return BuildAndRegisterResult{}, fmt.Errorf("build_source: dag_json exceeds %d-byte limit", maxWorkflowDAGBytes)
	}
	if dag != "{}" {
		if err := registry.ValidateDAG([]byte(dag)); err != nil {
			return BuildAndRegisterResult{}, fmt.Errorf("build_source: dag.json validation: %w", err)
		}
	}
	if err := os.WriteFile(filepath.Join(tmp, "dag.json"), []byte(dag), 0o600); err != nil {
		return BuildAndRegisterResult{}, fmt.Errorf("build_source: write dag.json: %w", err)
	}
	// Module setup (and the vendor/go.work rejection) now lives in
	// BuildAndRegister so every compile path gets it, not just this one.
	return BuildAndRegister(ctx, j, BuildAndRegisterRequest{
		Slug:            req.Slug,
		SrcDir:          tmp,
		StateRoot:       req.StateRoot,
		SDKVersion:      req.SDKVersion,
		SkipIfExists:    req.SkipIfExists,
		TenantID:        req.TenantID,
		StartDisabled:   req.StartDisabled,
		ExpectedVersion: req.ExpectedVersion,
		RetainSource:    true,
	})
}

func writeWorkflowAdditionalFiles(root string, files map[string]string) error {
	if len(files) > maxWorkflowSourceFiles {
		return fmt.Errorf("additional source file count exceeds %d", maxWorkflowSourceFiles)
	}
	var total int64
	for rawName, content := range files {
		name, err := validateWorkflowSourcePath(rawName)
		if err != nil {
			return err
		}
		if name == "main.go" || name == "dag.json" || name == "go.mod" || name == "go.sum" {
			return fmt.Errorf("additional source path %q is reserved", name)
		}
		for _, part := range strings.Split(name, "/") {
			if part == "vendor" || part == ".git" || part == "go.work" || part == "go.work.sum" {
				return fmt.Errorf("additional source path %q is not allowed", name)
			}
		}
		if int64(len(content)) > maxRetainedSourceFileBytes {
			return fmt.Errorf("additional source file %q exceeds %d-byte limit", name, maxRetainedSourceFileBytes)
		}
		total += int64(len(content))
		if total > maxRetainedSourceTotalBytes {
			return fmt.Errorf("additional source exceeds %d-byte total limit", maxRetainedSourceTotalBytes)
		}
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

func validateWorkflowSourcePath(raw string) (string, error) {
	if strings.TrimSpace(raw) != raw || raw == "" || strings.Contains(raw, "\\") || strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("invalid additional source path %q", raw)
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(raw)))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != raw {
		return "", fmt.Errorf("invalid additional source path %q", raw)
	}
	return clean, nil
}

// retainImmutableWorkflowSource preserves the artifact's source before its
// database registration and returns the files for later current-version activation.
func retainImmutableWorkflowSource(srcDir, artifactDir string, selectedGoFiles []string) (map[string][]byte, error) {
	files, err := collectRetainedWorkflowSource(srcDir)
	if err != nil {
		return nil, err
	}
	manifest, err := registry.BuildSourceManifest(files, selectedGoFiles)
	if err != nil {
		return nil, fmt.Errorf("build source manifest: %w", err)
	}
	files[registry.SourceManifestFilename] = manifest
	if err := writeImmutableSource(filepath.Join(artifactDir, "source"), files); err != nil {
		return nil, fmt.Errorf("write immutable snapshot: %w", err)
	}
	return files, nil
}

// collectRetainedWorkflowSource keeps every regular input that can affect the
// compiled workflow, not just main.go. Generated module metadata is excluded;
// it is recreated by PrepareWorkflowModule on the next private build.
func collectRetainedWorkflowSource(srcDir string) (map[string][]byte, error) {
	files := make(map[string][]byte)
	var total int64
	err := filepath.WalkDir(srcDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if entry.Name() == ".git" && entry.IsDir() {
			return filepath.SkipDir
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("retain source: symlink %q is not allowed", rel)
		}
		if entry.IsDir() {
			return nil
		}
		if rel == "go.mod" || rel == "go.sum" {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("retain source: special file %q is not allowed", rel)
		}
		data, err := readBoundedSourceFile(path, maxRetainedSourceFileBytes)
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		total += int64(len(data))
		if total > maxRetainedSourceTotalBytes {
			return fmt.Errorf("retained source exceeds %d-byte total limit", maxRetainedSourceTotalBytes)
		}
		name := filepath.ToSlash(rel)
		if name == registry.SourceManifestFilename {
			return fmt.Errorf("source file %q is reserved", name)
		}
		files[name] = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	if _, ok := files["main.go"]; !ok {
		return nil, errors.New("read main.go: file does not exist")
	}
	if _, ok := files["dag.json"]; !ok {
		dag, err := readWorkflowDAGBytes(srcDir)
		if err != nil {
			return nil, err
		}
		files["dag.json"] = dag
	}
	return files, nil
}

func readBoundedSourceFile(path string, max int) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > int64(max) {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, max)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func readWorkflowDAGBytes(srcDir string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(srcDir, "dag.json"))
	if errors.Is(err, os.ErrNotExist) {
		return []byte("{}\n"), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read dag.json: %w", err)
	}
	if len(raw) > maxWorkflowDAGBytes {
		return nil, fmt.Errorf("dag.json exceeds %d-byte limit", maxWorkflowDAGBytes)
	}
	return raw, nil
}

func writeCurrentSource(dir string, files map[string][]byte) error {
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(dir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%s is not a regular source directory", dir)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".source-current-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for name, data := range files {
		if err := ensureSourceParent(stage, name); err != nil {
			return err
		}
		if err := writeAtomicSourceFile(filepath.Join(stage, name), data); err != nil {
			return err
		}
	}
	if err := syncSourceDir(stage); err != nil {
		return err
	}
	existing, statErr := os.Lstat(dir)
	if statErr == nil {
		if existing.Mode()&os.ModeSymlink != 0 || !existing.IsDir() {
			return fmt.Errorf("%s is not a regular source directory", dir)
		}
		backup, err := os.MkdirTemp(parent, ".source-current-old-")
		if err != nil {
			return err
		}
		_ = os.RemoveAll(backup)
		if err := os.Rename(dir, backup); err != nil {
			return err
		}
		if err := os.Rename(stage, dir); err != nil {
			_ = os.Rename(backup, dir)
			return err
		}
		if err := os.RemoveAll(backup); err != nil {
			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	} else if err := os.Rename(stage, dir); err != nil {
		return err
	}
	return syncSourceDir(parent)
}

func writeImmutableSource(dir string, files map[string][]byte) error {
	if info, err := os.Lstat(dir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%s exists but is not a directory", dir)
		}
		for name, want := range files {
			got, readErr := os.ReadFile(filepath.Join(dir, name))
			if readErr != nil || string(got) != string(want) {
				return fmt.Errorf("existing immutable source %s does not match", name)
			}
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".source-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for name, data := range files {
		if err := ensureSourceParent(stage, name); err != nil {
			return err
		}
		if err := writeAtomicSourceFile(filepath.Join(stage, name), data); err != nil {
			return err
		}
	}
	if err := syncSourceDir(stage); err != nil {
		return err
	}
	if err := os.Rename(stage, dir); err != nil {
		if errors.Is(err, os.ErrExist) {
			return writeImmutableSource(dir, files)
		}
		return err
	}
	return syncSourceDir(parent)
}

func ensureSourceParent(root, name string) error {
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return fmt.Errorf("invalid retained source path %q", name)
	}
	parent := filepath.Join(root, filepath.Dir(clean))
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	return nil
}

func writeAtomicSourceFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".source-file-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func syncSourceDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
