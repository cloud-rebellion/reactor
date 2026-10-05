package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/workflowproof"
)

func TestWorkflowMirrorSelectsExactHistoricalVersion(t *testing.T) {
	ctx := context.Background()
	dbURL, j := newSeededDB(t)
	sourceRoot, destinationRoot := t.TempDir(), t.TempDir()
	const slug = "historical-mirror"
	reg := registry.New(filepath.Join(sourceRoot, "workflows"))
	if err := reg.ClaimTenant(slug, journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(binary, []byte("version one binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact(slug, binary)
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
`)
	dag := json.RawMessage(`{"steps":[{"name":"execute","kind":"step"}]}`)
	files := map[string][]byte{"main.go": source, "dag.json": dag}
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
	codeSum, manifestSum := sha256.Sum256(source), sha256.Sum256(manifest)
	codeHash, manifestHash := hex.EncodeToString(codeSum[:])[:16], hex.EncodeToString(manifestSum[:])
	if err := j.CreateWorkflowInTenantWithArtifactDisabled(ctx, "wf_mirror", slug, codeHash, "0.1.0", artifact.Digest, dag, journal.DefaultTenant, manifestHash); err != nil {
		t.Fatal(err)
	}
	versionOne, err := j.WorkflowVersionAt(ctx, "wf_mirror", 1)
	if err != nil {
		t.Fatal(err)
	}
	if result := workflowproof.CheckVersionForTenant(sourceRoot, slug, journal.DefaultTenant, versionOne); result.Status != "verified" {
		t.Fatalf("version one source proof: %+v", result)
	}
	// The mutable current pointer advances, but publication must still select
	// the exact historical journal version requested by the operator.
	if _, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_mirror", "0.1.0", codeHash, hex.EncodeToString(make([]byte, 32)), dag, manifestHash); err != nil {
		t.Fatal(err)
	}
	args := []string{"--db=" + dbURL, "--root=" + sourceRoot, "--destination-root=" + destinationRoot, "--slug=" + slug, "--tenant=" + journal.DefaultTenant, "--version=1"}
	if err := cmdWorkflowMirror(ctx, args); err != nil {
		t.Fatalf("mirror pinned historical version: %v", err)
	}
	if result := workflowproof.CheckVersionForTenant(destinationRoot, slug, journal.DefaultTenant, versionOne); result.Status != "verified" {
		t.Fatalf("destination historical proof: %+v", result)
	}
	args[len(args)-1] = "--version=2"
	if err := cmdWorkflowMirror(ctx, args); err == nil {
		t.Fatal("missing current-version artifact was accepted")
	}
}
