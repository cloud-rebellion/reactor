package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"text/tabwriter"

	"github.com/bright-interaction/reactor/internal/codegen"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// cmdWorkflow dispatches the workflow subcommand group.
//
//	reactor workflow list   --db <url>
//	reactor workflow register --db <url> --slug <slug> [--artifact-sha256 <digest>]
//	reactor workflow build  --src <dir> --root <state-root> --slug <slug>
//
// The build subcommand wraps `go build` so users on a blank install
// don't need to know the registry convention; it publishes immutable bytes and
// atomically records candidate.sha256. register binds that exact candidate (or
// an explicitly supplied digest) to a workflow-version row.
func cmdWorkflow(ctx context.Context, log *slog.Logger, args []string) error {
	if len(args) == 0 {
		return errors.New("workflow: missing subcommand (list|register|build)")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return cmdWorkflowList(ctx, log, rest)
	case "register":
		return cmdWorkflowRegister(ctx, log, rest)
	case "build":
		return cmdWorkflowBuild(ctx, rest)
	default:
		return fmt.Errorf("workflow: unknown subcommand %q (want list|register|build)", sub)
	}
}

func cmdWorkflowList(ctx context.Context, _ *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("workflow list", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if *dbURL == "" {
		return errors.New("missing --db (or $REACTOR_DB_URL)")
	}

	j, closer, err := openJournalForCLI(*dbURL)
	if err != nil {
		return err
	}
	defer closer()

	wfs, err := j.ListWorkflows(ctx)
	if err != nil {
		return err
	}

	if *asJSON {
		if wfs == nil {
			wfs = []journal.Workflow{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(wfs)
	}
	if len(wfs) == 0 {
		fmt.Println("(no workflows)")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprintln(tw, "SLUG\tID\tSDK\tUPDATED")
	for _, w := range wfs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", w.Slug, w.ID, w.SDKVersion,
			w.UpdatedAt.UTC().Format("2006-01-02T15:04Z"))
	}
	return nil
}

func cmdWorkflowRegister(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("workflow register", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL")
	slug := fs.String("slug", "", "workflow slug (required)")
	sdkVersion := fs.String("sdk-version", "0.1.0", "SDK version this workflow was authored against")
	dagPath := fs.String("dag", "", "path to dag.json (optional)")
	srcPath := fs.String("src", "", "path to workflow.go (used to compute code hash, optional)")
	artifactSHA256 := fs.String("artifact-sha256", "", "exact immutable build digest (recommended when builds for one slug may overlap; defaults to the latest candidate.sha256)")
	root := fs.String("root", defaultRoot(), "Reactor state root containing the immutable artifact produced by workflow build")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if *dbURL == "" || *slug == "" || *root == "" {
		return errors.New("workflow register: --db, --slug, and --root required")
	}
	if !codegen.IsValidSlug(*slug) {
		return fmt.Errorf("workflow register: --slug %q must match ^[a-z][a-z0-9-]*$ (becomes a filesystem path; no traversal allowed)", *slug)
	}

	j, closer, err := openJournalForCLI(*dbURL)
	if err != nil {
		return err
	}
	defer closer()

	// Re-registration reuses an existing workflow id and appends the next
	// immutable artifact-bound version instead of inserting a duplicate row.
	//
	// Scoped to the tenant CreateWorkflow below actually writes to
	// (DefaultTenant). Slugs are unique per tenant, so the unscoped lookup
	// answered "does ANY tenant own this slug" and another tenant's row made this
	// print "already registered (id=...)" while creating nothing here.
	existing, err := j.WorkflowIDBySlugInTenant(ctx, *slug, journal.DefaultTenant)
	if err != nil && !errors.Is(err, journal.ErrNotFound) {
		return err
	}

	codeHash := ""
	if *srcPath != "" {
		h, err := hashFile(*srcPath)
		if err != nil {
			return err
		}
		codeHash = h
	}
	dag := json.RawMessage(`{}`)
	if *dagPath != "" {
		raw, err := os.ReadFile(*dagPath)
		if err != nil {
			return fmt.Errorf("read dag: %w", err)
		}
		if !json.Valid(raw) {
			return errors.New("dag: invalid json")
		}
		dag = raw
	}
	reg := registry.New(filepath.Join(*root, "workflows"))
	var artifact registry.Artifact
	if *artifactSHA256 != "" {
		path, err := reg.ArtifactPath(*slug, *artifactSHA256)
		if err != nil {
			return fmt.Errorf("workflow register: resolve --artifact-sha256: %w", err)
		}
		artifact = registry.Artifact{Path: path, Digest: *artifactSHA256}
	} else {
		artifact, err = reg.BuildArtifact(*slug)
		if err != nil {
			return fmt.Errorf("workflow register: resolve immutable build candidate: %w (run `reactor workflow build` first)", err)
		}
	}

	if existing != "" {
		version, err := j.RecordWorkflowVersionWithArtifact(ctx, existing, *sdkVersion, codeHash, artifact.Digest, dag)
		if err != nil {
			return fmt.Errorf("workflow register: append version: %w", err)
		}
		activated, err := j.ActivateWorkflowArtifactIfCurrent(ctx, existing, version, artifact.Digest, func() error {
			_, err := reg.ActivateArtifact(*slug, artifact.Digest)
			return err
		})
		if err != nil {
			return fmt.Errorf("workflow register: activate artifact: %w", err)
		}
		if !activated {
			log.Info("workflow register: compatibility activation skipped because a newer version is current",
				"slug", *slug, "id", existing, "version", version)
		}
		log.Info("workflow register: appended immutable workflow version",
			"slug", *slug, "id", existing, "version", version, "artifact_sha256", artifact.Digest)
		fmt.Printf("registered %s version %d (id=%s artifact=%s)\n", *slug, version, existing, artifact.Digest)
		return nil
	}

	id, err := newWorkflowID()
	if err != nil {
		return err
	}
	if err := j.CreateWorkflowWithArtifact(ctx, id, *slug, codeHash, *sdkVersion, artifact.Digest, dag); err != nil {
		return err
	}
	if _, err := j.ActivateWorkflowArtifactIfCurrent(ctx, id, 1, artifact.Digest, func() error {
		_, err := reg.ActivateArtifact(*slug, artifact.Digest)
		return err
	}); err != nil {
		return fmt.Errorf("workflow register: activate artifact: %w", err)
	}
	fmt.Printf("registered %s as %s (artifact=%s)\n", *slug, id, artifact.Digest)
	return nil
}

func cmdWorkflowBuild(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("workflow build", flag.ContinueOnError)
	src := fs.String("src", "", "path to workflow source directory (must contain main.go)")
	root := fs.String("root", defaultRoot(), "Reactor state root (immutable artifacts land below <root>/workflows/<slug>/artifacts/sha256/)")
	slug := fs.String("slug", "", "workflow slug (required; identifies the immutable artifact namespace)")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if *src == "" || *slug == "" {
		return errors.New("workflow build: --src and --slug required")
	}
	if !codegen.IsValidSlug(*slug) {
		return fmt.Errorf("workflow build: --slug %q must match ^[a-z][a-z0-9-]*$ (becomes a filesystem path; no traversal allowed)", *slug)
	}
	if *root == "" {
		return errors.New("workflow build: --root required (and HOME unset)")
	}

	binDir := filepath.Join(*root, "workflows", *slug)
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		return fmt.Errorf("workflow build: mkdir: %w", err)
	}
	stage, err := os.CreateTemp(binDir, ".workflow-build-")
	if err != nil {
		return fmt.Errorf("workflow build: create binary stage: %w", err)
	}
	stagePath := stage.Name()
	if err := stage.Close(); err != nil {
		_ = os.Remove(stagePath)
		return fmt.Errorf("workflow build: close binary stage: %w", err)
	}
	_ = os.Remove(stagePath)
	defer os.Remove(stagePath)
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("workflow build: the Go toolchain is required to compile a workflow but %q was not found on PATH: %w", "go", err)
	}
	// Compile from a private staging copy so Reactor can own the module graph
	// without deleting or rewriting operator source files. The staging gate
	// also rejects symlinks, special files, vendor, and workspace overrides.
	buildSrc, cleanup, err := codegen.StageWorkflowSource(*src)
	if err != nil {
		return fmt.Errorf("workflow build: %w", err)
	}
	defer cleanup()
	if err := codegen.PrepareWorkflowModule(ctx, "go", buildSrc, *slug); err != nil {
		return fmt.Errorf("workflow build: prepare module: %w", err)
	}
	// Parity with the daemon's codegen/upload build path: enforce the import
	// allowlist (the build-time RCE gate - blocks import "C"/os/exec/third-party
	// modules) and the lint pass BEFORE compiling. Without this, `reactor
	// workflow build` was the one authoring surface that skipped the gate.
	if err := codegen.CheckAllowedImports(buildSrc); err != nil {
		return fmt.Errorf("workflow build: %w", err)
	}
	if issues, lErr := codegen.LintDir(buildSrc); lErr != nil {
		return fmt.Errorf("workflow build: lint: %w", lErr)
	} else if len(issues) > 0 {
		for _, is := range issues {
			fmt.Fprintf(os.Stderr, "lint: %s:%d:%d [%s] %s\n", is.Path, is.Line, is.Col, is.Rule, is.Message)
		}
		return fmt.Errorf("workflow build: %d lint issue(s); fix them before building", len(issues))
	}
	cmd := exec.CommandContext(ctx, "go", "build", codegen.BuildVCSFlag, "-o", stagePath, ".")
	cmd.Dir = buildSrc
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	// Strip REACTOR_*/ARACHNE_*/ANTHROPIC_API_KEY from the build environment: a
	// `go build` has no business reading the vault master key or DB URL, and a
	// hostile module dependency could otherwise exfiltrate them. Matches the
	// daemon's codegen/upload build path (codegen.BuildAndRegister).
	cmd.Env = codegen.SecureBuildEnv()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("workflow build: go build: %w", err)
	}
	reg := registry.New(filepath.Join(*root, "workflows"))
	artifact, err := reg.PublishArtifact(*slug, stagePath)
	if err != nil {
		return fmt.Errorf("workflow build: publish immutable artifact: %w", err)
	}
	if err := reg.SetBuildArtifact(*slug, artifact.Digest); err != nil {
		return fmt.Errorf("workflow build: record immutable candidate: %w", err)
	}
	fmt.Printf("built %s -> %s (sha256=%s)\n", *src, artifact.Path, artifact.Digest)
	fmt.Printf("register this exact build with --artifact-sha256 %s (recommended if builds for %s may overlap)\n", artifact.Digest, *slug)
	return nil
}

func openJournalForCLI(dbURL string) (*journal.Journal, func(), error) {
	db, engine, err := migrate.Open(dbURL)
	if err != nil {
		return nil, nil, err
	}
	closer := func() { _ = db.Close() }
	jEngine := journal.EngineSQLite
	if engine == migrate.EnginePostgres {
		jEngine = journal.EnginePostgres
	}
	return journal.New(db, jEngine), closer, nil
}

func newWorkflowID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "wf_" + hex.EncodeToString(b), nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
