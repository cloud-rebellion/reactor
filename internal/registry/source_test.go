package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifySourceCodeHash(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "main.go")
	contents := []byte("package main\nfunc main() {}\n")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(contents)
	expected := hex.EncodeToString(sum[:])[:16]
	if err := VerifySourceCodeHash(path, expected); err != nil {
		t.Fatalf("matching source hash: %v", err)
	}
	if err := VerifySourceCodeHash(path, strings.Repeat("a", 16)); err == nil {
		t.Fatal("mismatched source hash accepted")
	}
	if err := VerifySourceCodeHash(path, "legacy"); err != nil {
		t.Fatalf("legacy source hash should remain unverifiable rather than fail: %v", err)
	}
}

func TestVerifySourceCodeHashBoundsOversizedSource(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "main.go")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxSourceManifestFileSize + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := VerifySourceCodeHash(path, strings.Repeat("a", 16)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized source was not rejected with a bounded error: %v", err)
	}
}

func TestVerifyDAGSnapshot(t *testing.T) {
	t.Parallel()
	if err := VerifyDAGSnapshot([]byte(`{"steps": []}`), []byte(`{"steps":[]}`)); err != nil {
		t.Fatalf("equivalent DAG rejected: %v", err)
	}
	if err := VerifyDAGSnapshot([]byte(`{"steps":[{"name":"other"}]}`), []byte(`{"steps":[]}`)); err == nil {
		t.Fatal("different DAG accepted")
	}
	if err := VerifyDAGSnapshot([]byte(`{"broken"`), []byte(`{}`)); err == nil {
		t.Fatal("invalid retained DAG accepted")
	}
}

func TestSourceManifestBindsCompleteTree(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	files := map[string][]byte{
		"main.go":            []byte("package main\n"),
		"internal/helper.go": []byte("package internal\n"),
		"assets/schema.json": []byte(`{"version":1}`),
	}
	manifest, err := BuildSourceManifest(files)
	if err != nil {
		t.Fatalf("BuildSourceManifest: %v", err)
	}
	for name, data := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifySourceManifest(dir, manifest); err != nil {
		t.Fatalf("matching source manifest rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "internal", "helper.go"), []byte("package internal\n// tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifySourceManifest(dir, manifest); err == nil {
		t.Fatal("tampered helper accepted")
	}
}

func TestSourceManifestPinsCompiledRootSelection(t *testing.T) {
	dir := t.TempDir()
	files := map[string][]byte{
		"main.go":         []byte("package main\nfunc main() {}\n"),
		"helper.go":       []byte("package main\nfunc helper() {}\n"),
		"unused/decoy.go": []byte("package unused\n"),
	}
	for name, data := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := BuildSourceManifest(files, []string{"main.go", "helper.go"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, SourceManifestFilename), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if present, _, err := VerifySourceManifestDigestIfPresent(dir); err != nil || !present {
		t.Fatalf("compiled selection manifest invalid: present=%v err=%v", present, err)
	}
	selected, present, err := SourceManifestCompiledGoFiles(dir)
	if err != nil || !present || strings.Join(selected, ",") != "helper.go,main.go" {
		t.Fatalf("compiled selection = %v, present=%v err=%v", selected, present, err)
	}
	if _, err := BuildSourceManifest(files, []string{"main.go", "unused/decoy.go"}); err != nil {
		t.Fatalf("imported nested package could not be pinned: %v", err)
	}
	if _, err := BuildSourceManifest(files, []string{"main.go", "../outside.go"}); err == nil {
		t.Fatal("traversing compiled source path was accepted")
	}
	if _, err := BuildSourceManifest(files, []string{"main.go", "missing.go"}); err == nil {
		t.Fatal("missing compiled root file was accepted")
	}
}

func TestSourceManifestDigestPinsExactVerifiedBytes(t *testing.T) {
	dir := t.TempDir()
	mainGo := []byte("package main\nfunc main() {}\n")
	if err := os.WriteFile(filepath.Join(dir, "main.go"), mainGo, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildSourceManifest(map[string][]byte{"main.go": mainGo})
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, SourceManifestFilename)
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(manifest)
	want := hex.EncodeToString(sum[:])
	if present, digest, err := VerifySourceManifestDigestIfPresent(dir); err != nil || !present || digest != want {
		t.Fatalf("manifest digest = present:%t digest:%q err:%v, want %q", present, digest, err, want)
	}
	// The file list still verifies after an innocuous formatting change, but
	// a workflow version pinning the exact manifest bytes will detect it.
	changed := append([]byte(" \n"), manifest...)
	if err := os.WriteFile(manifestPath, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if present, digest, err := VerifySourceManifestDigestIfPresent(dir); err != nil || !present || digest == want {
		t.Fatalf("changed valid manifest digest = present:%t digest:%q err:%v; want changed digest", present, digest, err)
	}
}

func TestVerifySourceManifestIfPresentBoundsRead(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, SourceManifestFilename)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxSourceManifestBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	present, err := VerifySourceManifestIfPresent(dir)
	if !present || err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized source manifest present=%v err=%v; want bounded too-large error", present, err)
	}
}

func TestSourceManifestRejectsUnexpectedFilesAndTraversal(t *testing.T) {
	t.Parallel()
	if _, err := BuildSourceManifest(map[string][]byte{"../escape.go": []byte("x")}); err == nil {
		t.Fatal("path traversal accepted")
	}
	dir := t.TempDir()
	files := map[string][]byte{"main.go": []byte("package main\n")}
	manifest, err := BuildSourceManifest(files)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), files["main.go"], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "extra.txt"), []byte("unexpected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifySourceManifest(dir, manifest); err == nil {
		t.Fatal("unexpected file accepted")
	}
}
