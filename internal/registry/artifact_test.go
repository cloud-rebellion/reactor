package registry

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactSurvivesCanonicalReplacementAndDetectsTampering(t *testing.T) {
	root := t.TempDir()
	reg := New(root)
	slugDir := filepath.Join(root, "signing")
	if err := os.MkdirAll(slugDir, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "workflow")
	writeExecutable(t, source, "version-one")
	v1, err := reg.PublishArtifact("signing", source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.ActivateArtifact("signing", v1.Digest); err != nil {
		t.Fatal(err)
	}

	// A split CLI build is allowed to replace only the mutable compatibility
	// path. The v1 artifact selected by already-dispatched runs is unchanged.
	writeExecutable(t, filepath.Join(slugDir, "workflow"), "version-two")
	pinned, err := reg.ArtifactPath("signing", v1.Digest)
	if err != nil {
		t.Fatalf("resolve pinned v1 after canonical replacement: %v", err)
	}
	if got, _ := os.ReadFile(pinned); string(got) != "version-one" {
		t.Fatalf("pinned artifact changed with canonical: %q", got)
	}

	// Even an owner-level accidental mutation is detected before execution.
	if err := os.Chmod(pinned, 0o700); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, pinned, "tampered")
	if _, err := reg.ArtifactPath("signing", v1.Digest); err == nil {
		t.Fatal("tampered content-addressed artifact resolved successfully")
	}
}

func TestPublishArtifactConcurrentSameDigestIsNonOverwriting(t *testing.T) {
	root := t.TempDir()
	reg := New(root)
	source := filepath.Join(t.TempDir(), "workflow")
	writeExecutable(t, source, "same immutable bytes")

	const publishers = 12
	results := make(chan Artifact, publishers)
	errs := make(chan error, publishers)
	var wg sync.WaitGroup
	for range publishers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			artifact, err := reg.PublishArtifact("signing", source)
			if err != nil {
				errs <- err
				return
			}
			results <- artifact
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Errorf("concurrent publish: %v", err)
	}
	var first Artifact
	for artifact := range results {
		if first.Digest == "" {
			first = artifact
		}
		if artifact != first {
			t.Errorf("publish result = %+v, want %+v", artifact, first)
		}
	}
	if _, err := reg.ArtifactPath("signing", first.Digest); err != nil {
		t.Fatalf("published artifact failed verification: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "signing", "artifacts", "sha256", first.Digest)); err != nil {
		t.Fatalf("digest directory missing after atomic publish: %v", err)
	}
}

func TestBuildArtifactReferenceDoesNotFollowCompatibilityActivation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "fresh", "registry")
	reg := New(root)
	v1Source := filepath.Join(t.TempDir(), "workflow-v1")
	v2Source := filepath.Join(t.TempDir(), "workflow-v2")
	writeExecutable(t, v1Source, "candidate-v1")
	writeExecutable(t, v2Source, "activated-v2")
	v1, err := reg.PublishArtifact("signing", v1Source)
	if err != nil {
		t.Fatalf("publish on fresh hierarchy: %v", err)
	}
	v2, err := reg.PublishArtifact("signing", v2Source)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.SetBuildArtifact("signing", v1.Digest); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.ActivateArtifact("signing", v2.Digest); err != nil {
		t.Fatal(err)
	}
	candidate, err := reg.BuildArtifact("signing")
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Digest != v1.Digest {
		t.Fatalf("candidate followed unrelated activation: got %s want %s", candidate.Digest, v1.Digest)
	}
	bytes, err := os.ReadFile(candidate.Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(bytes) != "candidate-v1" {
		t.Fatalf("candidate bytes = %q", bytes)
	}
}

func TestBuildArtifactRejectsForgedReferenceAndTampering(t *testing.T) {
	root := t.TempDir()
	reg := New(root)
	source := filepath.Join(t.TempDir(), "workflow")
	writeExecutable(t, source, "trusted")
	artifact, err := reg.PublishArtifact("signing", source)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.SetBuildArtifact("signing", artifact.Digest); err != nil {
		t.Fatal(err)
	}
	reference := filepath.Join(root, "signing", buildArtifactFileName)
	if err := os.WriteFile(reference, []byte("../../mutable-workflow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.BuildArtifact("signing"); err == nil {
		t.Fatal("forged candidate reference resolved")
	}
	if err := reg.SetBuildArtifact("signing", artifact.Digest); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(artifact.Path, 0o700); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, artifact.Path, "tampered")
	if _, err := reg.BuildArtifact("signing"); err == nil {
		t.Fatal("tampered candidate artifact resolved")
	}
}

func TestArtifactPathRejectsNonCanonicalIdentifiers(t *testing.T) {
	reg := New(t.TempDir())
	for _, tc := range []struct{ slug, digest string }{
		{"../escape", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"signing", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"signing", "short"},
	} {
		if _, err := reg.ArtifactPath(tc.slug, tc.digest); err == nil {
			t.Fatalf("ArtifactPath(%q, %q) accepted", tc.slug, tc.digest)
		}
	}
}
