package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// TestHashESignScaffoldBuildsFromFreshDirectory guards the documented path:
// `reactor new` emits no module files, and `reactor workflow build` must create
// a trusted local module before compiling it. REACTOR_SDK_REPLACE models an
// installation whose SDK is supplied by the local Reactor checkout.
func TestHashESignScaffoldBuildsFromFreshDirectory(t *testing.T) {
	reactorRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve Reactor root: %v", err)
	}
	t.Setenv("REACTOR_SDK_REPLACE", reactorRoot)
	t.Setenv("ARACHNE_SDK_REPLACE", "")

	destination := t.TempDir()
	const slug = "partner-signing"
	if err := cmdNew(context.Background(), slog.Default(), []string{
		"hash-esign-bridge", slug, "--dest=" + destination,
	}); err != nil {
		t.Fatalf("render scaffold: %v", err)
	}
	source := filepath.Join(destination, slug)
	if _, err := os.Stat(filepath.Join(source, "go.mod")); !os.IsNotExist(err) {
		t.Fatalf("fresh scaffold unexpectedly contains go.mod: %v", err)
	}

	stateRoot := t.TempDir()
	if err := cmdWorkflowBuild(context.Background(), []string{
		"--src=" + source,
		"--slug=" + slug,
		"--root=" + stateRoot,
	}); err != nil {
		t.Fatalf("build fresh scaffold: %v", err)
	}
	if _, err := registry.New(filepath.Join(stateRoot, "workflows")).BuildArtifact(slug); err != nil {
		t.Fatalf("immutable build candidate missing: %v", err)
	}
	if owner, err := registry.New(filepath.Join(stateRoot, "workflows")).TenantOwner(slug); err != nil || owner != journal.DefaultTenant {
		t.Fatalf("CLI build owner = %q, err=%v; want %q", owner, err, journal.DefaultTenant)
	}
	if _, err := os.Stat(filepath.Join(source, "go.mod")); !os.IsNotExist(err) {
		t.Fatalf("build modified fresh scaffold source with go.mod: %v", err)
	}
}

func TestHashESignLifecycleScaffoldBuildsFromFreshDirectory(t *testing.T) {
	reactorRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve Reactor root: %v", err)
	}
	t.Setenv("REACTOR_SDK_REPLACE", reactorRoot)
	t.Setenv("ARACHNE_SDK_REPLACE", "")

	destination := t.TempDir()
	const slug = "partner-lifecycle"
	if err := cmdNew(context.Background(), slog.Default(), []string{
		"hash-esign-lifecycle", slug, "--dest=" + destination,
	}); err != nil {
		t.Fatalf("render scaffold: %v", err)
	}
	source := filepath.Join(destination, slug)
	if _, err := os.Stat(filepath.Join(source, "go.mod")); !os.IsNotExist(err) {
		t.Fatalf("fresh scaffold unexpectedly contains go.mod: %v", err)
	}

	stateRoot := t.TempDir()
	if err := cmdWorkflowBuild(context.Background(), []string{
		"--src=" + source,
		"--slug=" + slug,
		"--root=" + stateRoot,
	}); err != nil {
		t.Fatalf("build fresh lifecycle scaffold: %v", err)
	}
	if _, err := registry.New(filepath.Join(stateRoot, "workflows")).BuildArtifact(slug); err != nil {
		t.Fatalf("immutable lifecycle build candidate missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(source, "go.mod")); !os.IsNotExist(err) {
		t.Fatalf("build modified fresh scaffold source with go.mod: %v", err)
	}
}

func TestWorkflowBuildRejectsModuleEscapeHatches(t *testing.T) {
	for _, banned := range []string{"vendor", "go.work", "go.work.sum"} {
		t.Run(banned, func(t *testing.T) {
			source := t.TempDir()
			if err := os.WriteFile(filepath.Join(source, "main.go"), []byte("package main\nfunc main() {}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(source, banned)
			if banned == "vendor" {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("go 1.25\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			err := cmdWorkflowBuild(context.Background(), []string{
				"--src=" + source,
				"--slug=blocked-module",
				"--root=" + t.TempDir(),
			})
			if err == nil || !strings.Contains(err.Error(), banned) {
				t.Fatalf("got %v, want rejection naming %q", err, banned)
			}
		})
	}
}

func TestWorkflowBuildDiscardsSuppliedModuleGraph(t *testing.T) {
	t.Setenv("REACTOR_SDK_REPLACE", "")
	t.Setenv("ARACHNE_SDK_REPLACE", "")

	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "main.go"), []byte("package main\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const hostileModule = `module attacker-controlled

go 1.25

replace github.com/bright-interaction/reactor => ../attacker-sdk
`
	if err := os.WriteFile(filepath.Join(source, "go.mod"), []byte(hostileModule), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "go.sum"), []byte("attacker-controlled checksum\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := cmdWorkflowBuild(context.Background(), []string{
		"--src=" + source,
		"--slug=trusted-module",
		"--root=" + t.TempDir(),
	}); err != nil {
		t.Fatalf("build with supplied module graph: %v", err)
	}
	module, err := os.ReadFile(filepath.Join(source, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if string(module) != hostileModule {
		t.Fatalf("workflow build modified caller-owned go.mod:\n%s", module)
	}
	checksum, err := os.ReadFile(filepath.Join(source, "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	if string(checksum) != "attacker-controlled checksum\n" {
		t.Fatalf("workflow build modified caller-owned go.sum: %q", checksum)
	}
}

func TestWorkflowRegisterArtifactFlagPinsExactBuildAcrossCandidateChange(t *testing.T) {
	ctx := context.Background()
	dbURL, j := newSeededDB(t)
	stateRoot := t.TempDir()
	reg := registry.New(filepath.Join(stateRoot, "workflows"))
	if err := reg.ClaimTenant("exact-build", journal.DefaultTenant); err != nil {
		t.Fatalf("claim CLI artifact namespace: %v", err)
	}
	publish := func(body string) registry.Artifact {
		t.Helper()
		source := filepath.Join(t.TempDir(), "workflow")
		if err := os.WriteFile(source, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
		artifact, err := reg.PublishArtifact("exact-build", source)
		if err != nil {
			t.Fatal(err)
		}
		return artifact
	}
	requested := publish("requested-build")
	newerCandidate := publish("newer-overlapping-build")
	if err := reg.SetBuildArtifact("exact-build", newerCandidate.Digest); err != nil {
		t.Fatal(err)
	}

	if err := cmdWorkflowRegister(ctx, discardLogger(), []string{
		"--db=" + dbURL,
		"--root=" + stateRoot,
		"--slug=exact-build",
		"--artifact-sha256=" + requested.Digest,
	}); err != nil {
		t.Fatal(err)
	}
	wfID, err := j.WorkflowIDBySlugInTenant(ctx, "exact-build", journal.DefaultTenant)
	if err != nil {
		t.Fatal(err)
	}
	version, err := j.CurrentWorkflowVersionRecord(ctx, wfID)
	if err != nil {
		t.Fatal(err)
	}
	if version.ArtifactSHA256 != requested.Digest {
		t.Fatalf("registered digest = %s, want explicitly selected %s", version.ArtifactSHA256, requested.Digest)
	}
	current, err := reg.BinaryPath("exact-build")
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(current)
	if err != nil {
		t.Fatal(err)
	}
	if string(bytes) != "requested-build" {
		t.Fatalf("compatibility binary = %q, want requested build", bytes)
	}
	candidate, err := reg.BuildArtifact("exact-build")
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Digest != newerCandidate.Digest {
		t.Fatalf("registration mutated candidate pointer: got %s want %s", candidate.Digest, newerCandidate.Digest)
	}
}

func TestWorkflowRegisterRejectsCrossTenantArtifactNamespace(t *testing.T) {
	ctx := context.Background()
	dbURL, j := newSeededDB(t)
	if err := j.UpsertTenant(ctx, journal.Tenant{TenantID: "other"}); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_other_cli", "cli-shared", "h", "0.1.0", json.RawMessage(`{}`), "other"); err != nil {
		t.Fatal(err)
	}

	stateRoot := t.TempDir()
	reg := registry.New(filepath.Join(stateRoot, "workflows"))
	source := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(source, []byte("foreign tenant artifact"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("cli-shared", source)
	if err != nil {
		t.Fatal(err)
	}

	err = cmdWorkflowRegister(ctx, discardLogger(), []string{
		"--db=" + dbURL,
		"--root=" + stateRoot,
		"--slug=cli-shared",
		"--artifact-sha256=" + artifact.Digest,
	})
	if err == nil || !strings.Contains(err.Error(), "executable filesystem namespace is shared") {
		t.Fatalf("cross-tenant CLI registration error = %v, want namespace refusal", err)
	}
	if _, err := j.WorkflowIDBySlugInTenant(ctx, "cli-shared", journal.DefaultTenant); !errors.Is(err, journal.ErrNotFound) {
		t.Fatalf("cross-tenant CLI registration created default workflow: %v", err)
	}
	if _, err := reg.BinaryPath("cli-shared"); err == nil {
		t.Fatal("cross-tenant CLI registration activated compatibility binary")
	}
}
