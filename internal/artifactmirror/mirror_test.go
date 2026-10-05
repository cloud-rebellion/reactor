package artifactmirror

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/workflowproof"
)

const stepDAG = `{"steps":[{"name":"execute","kind":"step"}]}`

func sourceVersion(t *testing.T, root, slug, tenant string, scoped bool) journal.WorkflowVersion {
	t.Helper()
	reg := registry.New(filepath.Join(root, "workflows"))
	if scoped {
		if _, err := reg.EnsureScopedTenant(slug, tenant); err != nil {
			t.Fatal(err)
		}
	} else if err := reg.ClaimTenant(slug, tenant); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(binary, []byte("binary for "+tenant), 0o700); err != nil {
		t.Fatal(err)
	}
	var artifact registry.Artifact
	var err error
	if scoped {
		artifact, err = reg.PublishArtifactForTenant(slug, binary, tenant)
	} else {
		artifact, err = reg.PublishArtifact(slug, binary)
	}
	if err != nil {
		t.Fatal(err)
	}
	source := []byte(`package main
import (
  "context"
  reactor "github.com/bright-interaction/reactor/sdk"
)
func Run(ctx context.Context, flow reactor.Flow) error {
  _, err := reactor.Step(flow, ctx, "execute", reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
  return err
}
func main() {}
// tenant: ` + tenant + "\n")
	files := map[string][]byte{"main.go": source, "dag.json": []byte(stepDAG)}
	sourceDir := filepath.Join(filepath.Dir(artifact.Path), "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(sourceDir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := registry.BuildSourceManifest(files, []string{"main.go"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, registry.SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	codeSum := sha256.Sum256(source)
	manifestSum := sha256.Sum256(manifest)
	version := journal.WorkflowVersion{
		WorkflowID: "wf_" + tenant, Version: 1, ArtifactSHA256: artifact.Digest,
		CodeHash: hex.EncodeToString(codeSum[:])[:16], SourceManifestSHA256: hex.EncodeToString(manifestSum[:]),
		SourceProofVersion: 2, DAG: []byte(stepDAG),
	}
	if result := workflowproof.CheckVersionForTenant(root, slug, tenant, version); result.Status != "verified" {
		t.Fatalf("source fixture proof: %+v", result)
	}
	return version
}

func TestMirrorVersionPublishesExactTenantArtifactsAndRejectsTampering(t *testing.T) {
	sourceRoot, destinationRoot := t.TempDir(), t.TempDir()
	const slug = "shared"
	legacy := sourceVersion(t, sourceRoot, slug, "acme", false)
	scoped := sourceVersion(t, sourceRoot, slug, "globex", true)
	for _, candidate := range []struct {
		tenant  string
		version journal.WorkflowVersion
	}{
		{"acme", legacy}, {"globex", scoped},
	} {
		path, err := MirrorVersion(context.Background(), sourceRoot, destinationRoot, slug, candidate.tenant, candidate.version)
		if err != nil {
			t.Fatalf("mirror %s: %v", candidate.tenant, err)
		}
		if !strings.Contains(path, candidate.version.ArtifactSHA256) {
			t.Fatalf("mirrored path %q lacks exact digest", path)
		}
		if result := workflowproof.CheckVersionForTenant(destinationRoot, slug, candidate.tenant, candidate.version); result.Status != "verified" {
			t.Fatalf("destination %s proof: %+v", candidate.tenant, result)
		}
		if _, err := MirrorVersion(context.Background(), sourceRoot, destinationRoot, slug, candidate.tenant, candidate.version); err != nil {
			t.Fatalf("idempotent mirror %s: %v", candidate.tenant, err)
		}
	}
	if _, err := MirrorVersion(context.Background(), sourceRoot, destinationRoot, slug, "globex", legacy); err == nil {
		t.Fatal("foreign tenant's pinned version was accepted")
	}
	legacyBinary, err := registry.New(filepath.Join(destinationRoot, "workflows")).ArtifactPathForTenant(slug, legacy.ArtifactSHA256, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(legacyBinary), "source", "main.go"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MirrorVersion(context.Background(), sourceRoot, destinationRoot, slug, "acme", legacy); err == nil || !strings.Contains(err.Error(), "does not match pinned manifest") {
		t.Fatalf("tampered destination = %v, want fail-closed mismatch", err)
	}
}

func TestMirrorVersionRefusesSymlinkAndUnclaimedDestination(t *testing.T) {
	sourceRoot := t.TempDir()
	version := sourceVersion(t, sourceRoot, "blocked", "acme", false)
	t.Run("destination nested in retained source", func(t *testing.T) {
		binary, err := registry.New(filepath.Join(sourceRoot, "workflows")).ArtifactPathForTenant("blocked", version.ArtifactSHA256, "acme")
		if err != nil {
			t.Fatal(err)
		}
		destinationRoot := filepath.Join(filepath.Dir(binary), "source", "publisher")
		if err := os.Mkdir(destinationRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := MirrorVersion(context.Background(), sourceRoot, destinationRoot, "blocked", "acme", version); err == nil || !strings.Contains(err.Error(), "must not overlap") {
			t.Fatalf("nested destination = %v, want overlap refusal", err)
		}
		if _, err := os.Lstat(filepath.Join(destinationRoot, "workflows")); !os.IsNotExist(err) {
			t.Fatalf("nested destination was mutated: %v", err)
		}
	})
	t.Run("symlinked workflow root", func(t *testing.T) {
		destinationRoot := t.TempDir()
		if err := os.Symlink(t.TempDir(), filepath.Join(destinationRoot, "workflows")); err != nil {
			t.Fatal(err)
		}
		if _, err := MirrorVersion(context.Background(), sourceRoot, destinationRoot, "blocked", "acme", version); err == nil {
			t.Fatal("symlinked destination was accepted")
		}
	})
	t.Run("unclaimed existing namespace", func(t *testing.T) {
		destinationRoot := t.TempDir()
		dir := filepath.Join(destinationRoot, "workflows", "blocked")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "workflow"), []byte("foreign"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := MirrorVersion(context.Background(), sourceRoot, destinationRoot, "blocked", "acme", version); err == nil {
			t.Fatal("unclaimed existing namespace was adopted")
		}
	})
}

func TestMirrorVersionBoundsUnmanifestedEmptyDirectoryDepth(t *testing.T) {
	sourceRoot, destinationRoot := t.TempDir(), t.TempDir()
	version := sourceVersion(t, sourceRoot, "deep", "acme", false)
	binary, err := registry.New(filepath.Join(sourceRoot, "workflows")).ArtifactPathForTenant("deep", version.ArtifactSHA256, "acme")
	if err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(filepath.Dir(binary), "source")
	for i := 0; i <= maxSourceDepth; i++ {
		deep = filepath.Join(deep, "d")
		if err := os.Mkdir(deep, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if result := workflowproof.CheckVersionForTenant(sourceRoot, "deep", "acme", version); result.Status != "verified" {
		t.Fatalf("empty directories should not change source manifest proof: %+v", result)
	}
	if _, err := MirrorVersion(context.Background(), sourceRoot, destinationRoot, "deep", "acme", version); err == nil || !strings.Contains(err.Error(), "depth exceeds copy limit") {
		t.Fatalf("deep source copy = %v, want bounded refusal", err)
	}
}

func TestMirrorVersionRetriesVerifiedDestinationWithoutWriting(t *testing.T) {
	sourceRoot, destinationRoot := t.TempDir(), t.TempDir()
	version := sourceVersion(t, sourceRoot, "already-published", "acme", false)
	firstPath, err := MirrorVersion(context.Background(), sourceRoot, destinationRoot, "already-published", "acme", version)
	if err != nil {
		t.Fatal(err)
	}
	// A full or write-fenced artifact volume still permits reads. Retrying an
	// uncertain acknowledgement must recognize the fully verified destination
	// without allocating another binary stage in this directory.
	base := filepath.Dir(filepath.Dir(firstPath))
	if err := os.Chmod(base, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(base, 0o700)
	retryPath, err := MirrorVersion(context.Background(), sourceRoot, destinationRoot, "already-published", "acme", version)
	if err != nil || retryPath != firstPath {
		t.Fatalf("verified destination retry: path=%q err=%v", retryPath, err)
	}
}

func TestMirrorVersionVerifiedRetryKeepsNamespaceLayout(t *testing.T) {
	sourceRoot, destinationRoot := t.TempDir(), t.TempDir()
	const slug, tenant = "layout-fence", "acme"
	scoped := sourceVersion(t, sourceRoot, slug, tenant, true)
	legacy := sourceVersion(t, destinationRoot, slug, tenant, false)
	if scoped.ArtifactSHA256 != legacy.ArtifactSHA256 || scoped.SourceManifestSHA256 != legacy.SourceManifestSHA256 {
		t.Fatal("fixture versions must have identical contents in different namespace layouts")
	}
	if proof := workflowproof.CheckVersionForTenant(destinationRoot, slug, tenant, scoped); proof.Status != "verified" {
		t.Fatalf("destination fixture proof: %+v", proof)
	}
	if _, err := MirrorVersion(context.Background(), sourceRoot, destinationRoot, slug, tenant, scoped); err == nil || !strings.Contains(err.Error(), "already uses the legacy namespace") {
		t.Fatalf("scoped source with verified legacy destination = %v, want namespace refusal", err)
	}
}
