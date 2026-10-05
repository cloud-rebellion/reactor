package registry

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestTenantOwnerManifestIsImmutable(t *testing.T) {
	root := t.TempDir()
	reg := New(root)
	if err := reg.EnsureTenant("owned", "acme", false); err != nil {
		t.Fatalf("claim fresh namespace: %v", err)
	}
	if got, err := reg.TenantOwner("owned"); err != nil || got != "acme" {
		t.Fatalf("owner = %q, err=%v; want acme", got, err)
	}
	if err := reg.EnsureTenant("owned", "acme", false); err != nil {
		t.Fatalf("repeat same-tenant claim: %v", err)
	}
	if err := reg.EnsureTenant("owned", "globex", false); err == nil || !strings.Contains(err.Error(), "owned by tenant") {
		t.Fatalf("cross-tenant claim error = %v, want immutable owner refusal", err)
	}
	ownerPath := filepath.Join(root, "owned", tenantOwnerFileName)
	if err := os.WriteFile(ownerPath, []byte("globex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reg.ClaimTenant("owned", "acme"); err == nil || !strings.Contains(err.Error(), "owned by tenant") {
		t.Fatalf("rewritten owner manifest claim = %v, want fail-closed owner refusal", err)
	}
}

func TestEnsureTenantRejectsUnclaimedExecutableNamespace(t *testing.T) {
	root := t.TempDir()
	reg := New(root)
	source := filepath.Join(t.TempDir(), "workflow")
	writeExecutable(t, source, "stale executable")
	if _, err := reg.PublishArtifact("stale", source); err != nil {
		t.Fatal(err)
	}
	if err := reg.EnsureTenant("stale", "acme", false); err == nil || !strings.Contains(err.Error(), "no tenant owner manifest") {
		t.Fatalf("unclaimed namespace error = %v, want fail-closed adoption refusal", err)
	}
	if err := reg.EnsureTenant("stale", "acme", true); err != nil {
		t.Fatalf("legacy owner adoption with explicit proof: %v", err)
	}
	if got, err := reg.TenantOwner("stale"); err != nil || got != "acme" {
		t.Fatalf("adopted owner = %q, err=%v", got, err)
	}
	if _, err := reg.TenantOwner("missing"); !errors.Is(err, ErrTenantOwnerMissing) {
		t.Fatalf("missing owner err = %v, want ErrTenantOwnerMissing", err)
	}
}

func TestArtifactPathForTenantRejectsCrossTenantAndLegacyNamespaces(t *testing.T) {
	root := t.TempDir()
	reg := New(root)
	source := filepath.Join(t.TempDir(), "workflow")
	writeExecutable(t, source, "tenant-owned bytes")
	artifact, err := reg.PublishArtifact("shared", source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.ArtifactPathForTenant("shared", artifact.Digest, "acme"); err == nil || !errors.Is(err, ErrTenantOwnerMissing) {
		t.Fatalf("legacy namespace resolution = %v, want missing-owner refusal", err)
	}
	if err := reg.ClaimTenant("shared", "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.ArtifactPathForTenant("shared", artifact.Digest, "acme"); err != nil {
		t.Fatalf("same-tenant artifact resolution: %v", err)
	}
	if _, err := reg.ArtifactPathForTenant("shared", artifact.Digest, "globex"); err == nil || !strings.Contains(err.Error(), "owned by tenant") {
		t.Fatalf("cross-tenant artifact resolution = %v, want owner refusal", err)
	}
}

func TestTenantScopedNamespacesAllowSameSlugWithoutCrossTenantReads(t *testing.T) {
	root := t.TempDir()
	reg := New(root)
	acmeSource := filepath.Join(t.TempDir(), "acme-workflow")
	globexSource := filepath.Join(t.TempDir(), "globex-workflow")
	writeExecutable(t, acmeSource, "acme bytes")
	writeExecutable(t, globexSource, "globex bytes")

	acme, err := reg.PublishArtifactForTenant("shared", acmeSource, "acme")
	if err != nil {
		t.Fatalf("publish acme artifact: %v", err)
	}
	globex, err := reg.PublishArtifactForTenant("shared", globexSource, "globex")
	if err != nil {
		t.Fatalf("publish globex artifact: %v", err)
	}
	if acme.Path == globex.Path {
		t.Fatalf("tenant artifacts unexpectedly share a path: %q", acme.Path)
	}
	if _, err := reg.ArtifactPathForTenant("shared", acme.Digest, "acme"); err != nil {
		t.Fatalf("resolve acme artifact: %v", err)
	}
	if _, err := reg.ArtifactPathForTenant("shared", globex.Digest, "globex"); err != nil {
		t.Fatalf("resolve globex artifact: %v", err)
	}
	if _, err := reg.ArtifactPathForTenant("shared", acme.Digest, "globex"); err == nil {
		t.Fatal("globex resolved acme digest from its own namespace")
	}

	if err := reg.SetBuildArtifactForTenant("shared", acme.Digest, "acme"); err != nil {
		t.Fatalf("record acme candidate: %v", err)
	}
	if err := reg.SetBuildArtifactForTenant("shared", globex.Digest, "globex"); err != nil {
		t.Fatalf("record globex candidate: %v", err)
	}
	acmeCandidate, err := reg.BuildArtifactForTenant("shared", "acme")
	if err != nil || acmeCandidate.Digest != acme.Digest {
		t.Fatalf("acme candidate = %+v, err=%v", acmeCandidate, err)
	}
	globexCandidate, err := reg.BuildArtifactForTenant("shared", "globex")
	if err != nil || globexCandidate.Digest != globex.Digest {
		t.Fatalf("globex candidate = %+v, err=%v", globexCandidate, err)
	}
	if _, err := reg.ActivateArtifactForTenant("shared", acme.Digest, "acme"); err != nil {
		t.Fatalf("activate acme artifact: %v", err)
	}
	if _, err := reg.ActivateArtifactForTenant("shared", globex.Digest, "globex"); err != nil {
		t.Fatalf("activate globex artifact: %v", err)
	}

	acmeDir, err := reg.ScopedWorkflowDir("shared", "acme")
	if err != nil {
		t.Fatal(err)
	}
	globexDir, err := reg.ScopedWorkflowDir("shared", "globex")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(filepath.Dir(acmeDir)) == "acme" || filepath.Base(filepath.Dir(globexDir)) == "globex" {
		t.Fatalf("tenant identifier used directly in filesystem namespace: %q / %q", acmeDir, globexDir)
	}
	if _, err := os.Stat(filepath.Join(acmeDir, "workflow")); err != nil {
		t.Fatalf("acme compatibility binary missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(globexDir, "workflow")); err != nil {
		t.Fatalf("globex compatibility binary missing: %v", err)
	}
	all, err := reg.List()
	if err != nil || len(all) != 1 || all[0] != "shared" {
		t.Fatalf("estate registry list = %v, err=%v; want one shared slug", all, err)
	}
	acmeList, err := reg.ListForTenant("acme")
	if err != nil || len(acmeList) != 1 || acmeList[0] != "shared" {
		t.Fatalf("acme registry list = %v, err=%v; want shared", acmeList, err)
	}
	globexList, err := reg.ListForTenant("globex")
	if err != nil || len(globexList) != 1 || globexList[0] != "shared" {
		t.Fatalf("globex registry list = %v, err=%v; want shared", globexList, err)
	}
	otherList, err := reg.ListForTenant("other")
	if err != nil || len(otherList) != 0 {
		t.Fatalf("other registry list = %v, err=%v; want empty", otherList, err)
	}
}

func TestTenantScopedNamespaceRequiresOwnerManifest(t *testing.T) {
	root := t.TempDir()
	reg := New(root)
	dir, err := reg.ScopedWorkflowDir("shared", "acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, artifactDirName, "sha256"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.ArtifactPathForTenant("shared", strings.Repeat("a", 64), "acme"); !errors.Is(err, ErrTenantOwnerMissing) {
		t.Fatalf("unclaimed scoped namespace error = %v, want ErrTenantOwnerMissing", err)
	}
}

func TestTenantScopedNamespaceResolvesAlongsideLegacyOwner(t *testing.T) {
	root := t.TempDir()
	reg := New(root)
	legacySource := filepath.Join(t.TempDir(), "legacy-workflow")
	isolatedSource := filepath.Join(t.TempDir(), "isolated-workflow")
	writeExecutable(t, legacySource, "legacy bytes")
	writeExecutable(t, isolatedSource, "isolated bytes")
	if err := reg.ClaimTenant("shared", "acme"); err != nil {
		t.Fatal(err)
	}
	legacy, err := reg.PublishArtifact("shared", legacySource)
	if err != nil {
		t.Fatal(err)
	}
	isolated, err := reg.PublishArtifactForTenant("shared", isolatedSource, "globex")
	if err != nil {
		t.Fatal(err)
	}
	legacyPath, err := reg.ArtifactPathForTenant("shared", legacy.Digest, "acme")
	if err != nil || legacyPath != legacy.Path {
		t.Fatalf("legacy tenant resolution = %q, err=%v; want %q", legacyPath, err, legacy.Path)
	}
	isolatedPath, err := reg.ArtifactPathForTenant("shared", isolated.Digest, "globex")
	if err != nil || isolatedPath != isolated.Path {
		t.Fatalf("isolated tenant resolution = %q, err=%v; want %q", isolatedPath, err, isolated.Path)
	}
	if _, err := reg.ArtifactPathForTenant("shared", legacy.Digest, "globex"); err == nil {
		t.Fatal("globex resolved legacy acme artifact")
	}
}
