package workflowproof

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

const proofStepSource = `package main
import (
  "context"
  reactor "github.com/bright-interaction/reactor/sdk"
)
func Run(ctx context.Context, flow reactor.Flow) error {
  _, err := reactor.Step(flow, ctx, "execute", reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
  return err
}
func main() {}
`

const proofStepDAG = `{"steps":[{"name":"execute","kind":"step"}]}`

func TestLegacyVisualMismatchDoesNotFenceExecutableArtifact(t *testing.T) {
	root := t.TempDir()
	reg := registry.New(filepath.Join(root, "workflows"))
	binary := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(binary, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("legacy-visual", binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.ClaimTenant("legacy-visual", "acme"); err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mainGo := []byte(proofStepSource)
	dag := []byte(`{"steps":[{"name":"execute","kind":"step","visual_flow":{"blocks":[{"id":"predicate","kind":"filter"}]}}]}`)
	manifestFiles := map[string][]byte{"main.go": mainGo, "dag.json": dag}
	for name, contents := range manifestFiles {
		if err := os.WriteFile(filepath.Join(sourceDir, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := registry.BuildSourceManifest(manifestFiles)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(sourceDir, registry.SourceManifestFilename)
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mainGo)
	codeHash := hex.EncodeToString(sum[:])[:16]
	version := journal.WorkflowVersion{WorkflowID: "wf_legacy_visual", Version: 1, ArtifactSHA256: artifact.Digest, CodeHash: codeHash, SourceProofVersion: 1, DAG: dag}
	result := CheckForTenant(root, "legacy-visual", "acme", artifact.Digest, codeHash, dag)
	if result.Status != "visual_unverified" || !strings.Contains(result.Reason, "declares 1 filter blocks") {
		t.Fatalf("legacy visual-only mismatch = %+v, want explicit unverified status", result)
	}
	if err := ValidateVersionForTenant(root, "legacy-visual", "acme", version); err != nil {
		t.Fatalf("legacy visual-only mismatch terminalized intact artifact: %v", err)
	}
	newWithoutPin := version
	newWithoutPin.SourceProofVersion = 2
	var fence *journal.WorkflowArtifactFenceError
	if err := ValidateVersionForTenant(root, "legacy-visual", "acme", newWithoutPin); !errors.As(err, &fence) || !strings.Contains(fence.Reason, "no pinned source manifest") {
		t.Fatalf("new unpinned version = %v, want hard artifact fence", err)
	}
	manifestSum := sha256.Sum256(manifest)
	manifestHash := hex.EncodeToString(manifestSum[:])
	version.SourceManifestSHA256 = manifestHash
	version.SourceProofVersion = 2
	result = CheckForTenant(root, "legacy-visual", "acme", artifact.Digest, codeHash, dag, manifestHash)
	if result.Status != "mismatch" {
		t.Fatalf("new-policy visual mismatch = %+v, want hard mismatch", result)
	}
	fence = nil
	if err := ValidateVersionForTenant(root, "legacy-visual", "acme", version); !errors.As(err, &fence) {
		t.Fatalf("new-policy visual mismatch = %v, want artifact fence", err)
	}
	// Even a valid re-signed local manifest cannot downgrade a pinned version.
	if err := os.WriteFile(manifestPath, append([]byte(" \n"), manifest...), 0o600); err != nil {
		t.Fatal(err)
	}
	result = CheckForTenant(root, "legacy-visual", "acme", artifact.Digest, codeHash, dag, manifestHash)
	if result.Status != "mismatch" || !strings.Contains(result.Reason, "immutable version pin") {
		t.Fatalf("changed self-signed manifest = %+v, want pinned mismatch", result)
	}
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	version.SourceManifestSHA256 = ""
	version.SourceProofVersion = 1
	badDAG := []byte(`{"steps":[{"name":"different","kind":"step","visual_flow":{"blocks":[{"id":"predicate","kind":"filter"}]}}]}`)
	version.DAG = badDAG
	result = CheckForTenant(root, "legacy-visual", "acme", artifact.Digest, codeHash, badDAG)
	if result.Status != "mismatch" {
		t.Fatalf("legacy retained DAG mismatch = %+v, want hard mismatch", result)
	}
}

func TestValidateVersionForTenantFencesEmptyVisualDAG(t *testing.T) {
	root := t.TempDir()
	reg := registry.New(filepath.Join(root, "workflows"))
	binary := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(binary, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("empty-flow", binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.ClaimTenant("empty-flow", "acme"); err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mainGo := []byte("package main\nfunc main() {}\n")
	dag := []byte(`{}`)
	for name, contents := range map[string][]byte{"main.go": mainGo, "dag.json": dag} {
		if err := os.WriteFile(filepath.Join(sourceDir, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := registry.BuildSourceManifest(map[string][]byte{"main.go": mainGo, "dag.json": dag})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, registry.SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mainGo)
	codeHash := hex.EncodeToString(sum[:])[:16]
	for _, candidate := range [][]byte{nil, []byte(`{}`), []byte(`{"steps":[]}`), []byte(`{"nodes":[]}`)} {
		result := CheckForTenant(root, "empty-flow", "acme", artifact.Digest, codeHash, candidate)
		if result.Status != "mismatch" || result.Reason != missingExecutableDAGReason {
			t.Fatalf("empty DAG %q proof = %+v, want stable mismatch", candidate, result)
		}
		version := journal.WorkflowVersion{WorkflowID: "wf_empty_flow", Version: 1, ArtifactSHA256: artifact.Digest, CodeHash: codeHash, SourceProofVersion: 1, DAG: candidate}
		var fence *journal.WorkflowArtifactFenceError
		if err := ValidateVersionForTenant(root, "empty-flow", "acme", version); !errors.As(err, &fence) || !errors.Is(err, journal.ErrWorkflowArtifactFence) || fence.Reason != missingExecutableDAGReason {
			t.Fatalf("empty DAG %q validation = %v, want typed artifact fence", candidate, err)
		}
	}
	for _, candidate := range []struct {
		name string
		dag  []byte
	}{
		{name: "invalid node kind", dag: []byte(`{"steps":[{"name":"send","kind":"unknown"}]}`)},
		{name: "oversized DAG", dag: []byte(strings.Repeat(" ", maxProofDAGBytes+1))},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			version := journal.WorkflowVersion{WorkflowID: "wf_empty_flow", Version: 1, ArtifactSHA256: artifact.Digest, CodeHash: codeHash, SourceProofVersion: 1, DAG: candidate.dag}
			var fence *journal.WorkflowArtifactFenceError
			if err := ValidateVersionForTenant(root, "empty-flow", "acme", version); !errors.As(err, &fence) || !errors.Is(err, journal.ErrWorkflowArtifactFence) || fence.Reason == "" {
				t.Fatalf("invalid DAG validation = %v, want typed artifact fence with reason", err)
			}
		})
	}
}

func TestCheckRequiresRetainedSourceProof(t *testing.T) {
	root := t.TempDir()
	reg := registry.New(filepath.Join(root, "workflows"))
	artifactSource := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(artifactSource, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("proof", artifactSource)
	if err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mainGo := []byte(proofStepSource)
	if err := os.WriteFile(filepath.Join(sourceDir, "main.go"), mainGo, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := registry.BuildSourceManifest(map[string][]byte{"main.go": mainGo}, []string{"main.go"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, registry.SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mainGo)
	hash := hex.EncodeToString(sum[:])[:16]

	manifestSum := sha256.Sum256(manifest)
	manifestHash := hex.EncodeToString(manifestSum[:])
	if got := Check(root, "proof", artifact.Digest, hash, []byte(proofStepDAG), manifestHash); got.Status != "verified" {
		t.Fatalf("proof status = %#v, want verified", got)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "main.go"), []byte("package main\nfunc main(){ println(1) }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Check(root, "proof", artifact.Digest, hash, []byte(proofStepDAG), manifestHash); got.Status != "mismatch" {
		t.Fatalf("drift status = %#v, want mismatch", got)
	}
}

func TestPinnedCompiledFilesRejectNestedVisualDecoy(t *testing.T) {
	root := t.TempDir()
	reg := registry.New(filepath.Join(root, "workflows"))
	binary := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(binary, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("compiled-proof", binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.ClaimTenant("compiled-proof", "acme"); err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(filepath.Join(sourceDir, "unused"), 0o700); err != nil {
		t.Fatal(err)
	}
	mainGo := []byte("package main\nfunc main() {}\n")
	decoy := []byte(`package unused
import (
    "context"
    reactor "github.com/bright-interaction/reactor/sdk"
)
func phantom(ctx context.Context, flow reactor.Flow) error {
    _, err := reactor.Step(flow, ctx, "phantom", reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
    return err
}
`)
	dag := []byte(`{"steps":[{"name":"phantom","kind":"step"}]}`)
	files := map[string][]byte{"main.go": mainGo, "unused/decoy.go": decoy, "dag.json": dag}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(sourceDir, filepath.FromSlash(name)), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := registry.BuildSourceManifest(files, []string{"main.go"})
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(sourceDir, registry.SourceManifestFilename)
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	mainSum := sha256.Sum256(mainGo)
	codeHash := hex.EncodeToString(mainSum[:])[:16]
	manifestSum := sha256.Sum256(manifest)
	manifestHash := hex.EncodeToString(manifestSum[:])
	if result := Check(root, "compiled-proof", artifact.Digest, codeHash, dag, manifestHash); result.Status != "mismatch" || !strings.Contains(result.Reason, "DAG nodes missing from source: phantom") {
		t.Fatalf("nested decoy proof = %+v, want executable/visual mismatch", result)
	}
	version := journal.WorkflowVersion{WorkflowID: "wf_compiled_proof", Version: 1, ArtifactSHA256: artifact.Digest, CodeHash: codeHash, DAG: dag, SourceProofVersion: 2, SourceManifestSHA256: manifestHash}
	var fence *journal.WorkflowArtifactFenceError
	if err := ValidateVersionForTenant(root, "compiled-proof", "acme", version); !errors.As(err, &fence) {
		t.Fatalf("nested decoy dispatch proof = %v, want artifact fence", err)
	}
	// A pre-selection manifest is still recognized as legacy, but never
	// presented to review clients as verified executable visual flow.
	legacyManifest, err := registry.BuildSourceManifest(files)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, legacyManifest, 0o600); err != nil {
		t.Fatal(err)
	}
	legacySum := sha256.Sum256(legacyManifest)
	version.SourceManifestSHA256 = hex.EncodeToString(legacySum[:])
	if result := CheckVersionForTenant(root, "compiled-proof", "acme", version); result.Status != "compiled_files_unverified" || !strings.Contains(result.Reason, "no compiled workflow Go file selection") {
		t.Fatalf("pinned pre-selection proof = %+v, want unverified", result)
	}
	if err := ValidateVersionForTenant(root, "compiled-proof", "acme", version); err == nil || !strings.Contains(err.Error(), "compiled_files_unverified") {
		t.Fatalf("pinned pre-selection artifact admitted for dispatch: %v", err)
	}
	// The version-1 compatibility policy remains explicit: an existing
	// pre-pinning workflow can dispatch, but never claims a verified flow.
	version.SourceProofVersion = 1
	version.SourceManifestSHA256 = ""
	if result := CheckVersionForTenant(root, "compiled-proof", "acme", version); result.Status != "legacy_manifest_unpinned" {
		t.Fatalf("version-1 compatibility proof = %+v", result)
	}
	if err := ValidateVersionForTenant(root, "compiled-proof", "acme", version); err != nil {
		t.Fatalf("version-1 compatibility policy changed: %v", err)
	}
}

func TestCheckForTenantRejectsForeignSameSlugArtifact(t *testing.T) {
	root := t.TempDir()
	reg := registry.New(filepath.Join(root, "workflows"))
	artifactSource := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(artifactSource, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("shared", artifactSource)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.ClaimTenant("shared", "acme"); err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mainGo := []byte(proofStepSource)
	if err := os.WriteFile(filepath.Join(sourceDir, "main.go"), mainGo, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := registry.BuildSourceManifest(map[string][]byte{"main.go": mainGo}, []string{"main.go"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, registry.SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mainGo)
	codeHash := hex.EncodeToString(sum[:])[:16]
	manifestSum := sha256.Sum256(manifest)
	manifestHash := hex.EncodeToString(manifestSum[:])
	if got := Check(root, "shared", artifact.Digest, codeHash, []byte(proofStepDAG), manifestHash); got.Status != "verified" {
		t.Fatalf("legacy proof status = %#v, want verified", got)
	}
	if got := CheckForTenant(root, "shared", "globex", artifact.Digest, codeHash, []byte(proofStepDAG), manifestHash); got.Status != "unavailable" {
		t.Fatalf("foreign tenant proof status = %#v, want unavailable", got)
	}
	version := journal.WorkflowVersion{WorkflowID: "wf_shared_globex", Version: 1, ArtifactSHA256: artifact.Digest, CodeHash: codeHash, SourceProofVersion: 1, DAG: []byte(proofStepDAG)}
	if err := ValidateVersionForTenant(root, "shared", "globex", version); err == nil {
		t.Fatal("foreign tenant version proof unexpectedly passed")
	}
}

func TestCheckLabelsLegacySource(t *testing.T) {
	root := t.TempDir()
	reg := registry.New(filepath.Join(root, "workflows"))
	artifactSource := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(artifactSource, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("legacy-proof", artifactSource)
	if err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mainGo := []byte(proofStepSource)
	if err := os.WriteFile(filepath.Join(sourceDir, "main.go"), mainGo, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mainGo)
	if got := Check(root, "legacy-proof", artifact.Digest, hex.EncodeToString(sum[:]), []byte(proofStepDAG)); got.Status != "legacy_unverified" {
		t.Fatalf("legacy status = %#v, want legacy_unverified", got)
	}
}

func TestCheckRejectsAmbiguousDAGBeforeSourceDiscovery(t *testing.T) {
	root := t.TempDir()
	reg := registry.New(filepath.Join(root, "workflows"))
	artifactSource := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(artifactSource, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("duplicate-dag", artifactSource)
	if err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mainGo := []byte(`package main
import (
  "context"
  reactor "github.com/bright-interaction/reactor/sdk"
)
func Run(ctx context.Context, flow reactor.Flow) error {
  _, err := reactor.Step(flow, ctx, "send", reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
  return err
}
`)
	if err := os.WriteFile(filepath.Join(sourceDir, "main.go"), mainGo, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := registry.BuildSourceManifest(map[string][]byte{"main.go": mainGo})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, registry.SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mainGo)
	codeHash := hex.EncodeToString(sum[:])[:16]
	ambiguous := []byte(`{"steps":[{"name":"send","kind":"step","kind":"step"}]}`)
	got := Check(root, "duplicate-dag", artifact.Digest, codeHash, ambiguous)
	if got.Status != "mismatch" || !strings.Contains(got.Reason, "duplicate object key") {
		t.Fatalf("ambiguous DAG proof = %#v, want duplicate-key mismatch", got)
	}
}

func TestCheckBoundsRetainedDAGBeforeComparingSnapshots(t *testing.T) {
	root := t.TempDir()
	reg := registry.New(filepath.Join(root, "workflows"))
	artifactSource := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(artifactSource, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("oversized-proof", artifactSource)
	if err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mainGo := []byte(proofStepSource)
	if err := os.WriteFile(filepath.Join(sourceDir, "main.go"), mainGo, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mainGo)
	codeHash := hex.EncodeToString(sum[:])[:16]
	retained := []byte(`{"steps":[],"padding":"` + strings.Repeat("x", maxProofDAGBytes) + `"}`)
	if err := os.WriteFile(filepath.Join(sourceDir, "dag.json"), retained, 0o600); err != nil {
		t.Fatal(err)
	}
	got := Check(root, "oversized-proof", artifact.Digest, codeHash, []byte(proofStepDAG))
	if got.Status != "mismatch" || !strings.Contains(got.Reason, "bounded proof limit") {
		t.Fatalf("oversized retained DAG proof = %#v, want bounded mismatch", got)
	}
}
