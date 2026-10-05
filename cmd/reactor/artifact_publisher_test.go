package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/workflowproof"
)

func seededArtifactPublication(t *testing.T) (*journal.Journal, string, string, journal.ArtifactPublication) {
	t.Helper()
	ctx := context.Background()
	_, j := newSeededDB(t)
	sourceRoot, destinationRoot := t.TempDir(), t.TempDir()
	const slug = "publisher-exact"
	reg := registry.New(filepath.Join(sourceRoot, "workflows"))
	if err := reg.ClaimTenant(slug, journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(binary, []byte("publisher test executable"), 0o700); err != nil {
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
	if err := j.CreateWorkflowInTenantWithArtifactDisabled(ctx, "wf_publisher_exact", slug, hex.EncodeToString(codeSum[:])[:16], "0.1.0", artifact.Digest, dag, journal.DefaultTenant, hex.EncodeToString(manifestSum[:])); err != nil {
		t.Fatal(err)
	}
	v, err := j.WorkflowVersionAt(ctx, "wf_publisher_exact", 1)
	if err != nil {
		t.Fatal(err)
	}
	if proof := workflowproof.CheckVersionForTenant(sourceRoot, slug, journal.DefaultTenant, v); proof.Status != "verified" {
		t.Fatalf("source fixture proof: %+v", proof)
	}
	if _, err := j.EnqueueArtifactPublication(ctx, journal.DefaultTenant, "wf_publisher_exact", 1, artifact.Digest); err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimArtifactPublications(ctx, 1, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim artifact publication: %+v, %v", claimed, err)
	}
	return j, sourceRoot, destinationRoot, claimed[0]
}

func TestArtifactPublisherVerifiesBeforeAcknowledgement(t *testing.T) {
	j, sourceRoot, destinationRoot, p := seededArtifactPublication(t)
	if code, err := processArtifactPublication(context.Background(), j, sourceRoot, destinationRoot, p, time.Minute); err != nil || code != "" {
		t.Fatalf("publication: code=%q err=%v", code, err)
	}
	status, err := j.GetArtifactPublicationForTenant(context.Background(), p.ID, p.TenantID)
	if err != nil || status.Status != journal.ArtifactPublicationPublished || status.PublishedAt == nil {
		t.Fatalf("published receipt: %+v, %v", status, err)
	}
	v, err := j.WorkflowVersionAt(context.Background(), p.WorkflowID, p.Version)
	if err != nil {
		t.Fatal(err)
	}
	if proof := workflowproof.CheckVersionForTenant(destinationRoot, p.Slug, p.TenantID, v); proof.Status != "verified" {
		t.Fatalf("destination proof: %+v", proof)
	}
	wf, err := j.GetWorkflow(context.Background(), p.WorkflowID)
	if err != nil || wf.Enabled {
		t.Fatalf("publication enabled workflow: %+v, %v", wf, err)
	}
}

func TestArtifactPublisherFailureIsRetryableAndDoesNotClaimSuccess(t *testing.T) {
	j, sourceRoot, destinationRoot, p := seededArtifactPublication(t)
	if err := os.Remove(destinationRoot); err != nil {
		t.Fatal(err)
	}
	if code, err := processArtifactPublication(context.Background(), j, sourceRoot, destinationRoot, p, time.Minute); err == nil || code != "destination_unavailable" {
		t.Fatalf("missing destination: code=%q err=%v", code, err)
	}
	status, err := j.GetArtifactPublicationForTenant(context.Background(), p.ID, p.TenantID)
	if err != nil || status.Status != journal.ArtifactPublicationPending || status.PublishedAt != nil || status.LastFailureCode != "destination_unavailable" {
		t.Fatalf("failure receipt: %+v, %v", status, err)
	}
}

func TestArtifactPublisherRejectsOverlappingRoots(t *testing.T) {
	source := t.TempDir()
	if err := requireArtifactPublisherRoots(source, source); err == nil {
		t.Fatal("publisher accepted identical source and destination roots")
	}
	nested := filepath.Join(source, "worker")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := requireArtifactPublisherRoots(source, nested); err == nil {
		t.Fatal("publisher accepted nested destination root")
	}
}
