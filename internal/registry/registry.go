// Package registry resolves a workflow slug to the compiled binary the
// supervisor exec's. Production deployments store binaries under
// <root>/<slug>/workflow; tests inject a fake.
//
// Convention is simple by design: one directory per workflow, the
// binary always named "workflow". This matches the codegen
// orchestrator's atomic rename target (reactor-workflows/<slug>/) so
// `reactor workflow build <slug>` writes into the same shape the
// daemon reads from.
package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	artifactDirName       = "artifacts"
	buildArtifactFileName = "candidate.sha256"
)

// Artifact is an immutable, content-addressed workflow executable. Digest is
// the lowercase SHA-256 of the exact bytes at Path.
type Artifact struct {
	Path   string
	Digest string
}

// FileRegistry resolves slugs against a root directory.
type FileRegistry struct {
	Root string
}

// New returns a FileRegistry rooted at the given directory.
func New(root string) *FileRegistry {
	return &FileRegistry{Root: root}
}

// BinaryPath implements dispatcher.BinaryLookup. Returns an error if
// the binary doesn't exist or isn't executable.
func (r *FileRegistry) BinaryPath(slug string) (string, error) {
	if slug == "" {
		return "", fmt.Errorf("registry: empty slug")
	}
	path := filepath.Join(r.Root, slug, "workflow")
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("registry: stat %s: %w", path, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("registry: %s is a directory", path)
	}
	if info.Mode()&0o111 == 0 {
		return "", fmt.Errorf("registry: %s is not executable", path)
	}
	return path, nil
}

// PublishArtifact copies a compiled executable into the content-addressed
// registry. Publication is atomic and never overwrites an existing digest. If
// another publisher won the race, its bytes are re-hashed before reuse.
func (r *FileRegistry) PublishArtifact(slug, sourcePath string) (Artifact, error) {
	if !safeSlug(slug) {
		return Artifact{}, fmt.Errorf("registry: invalid slug")
	}
	srcInfo, err := os.Lstat(sourcePath)
	if err != nil {
		return Artifact{}, fmt.Errorf("registry: stat artifact source: %w", err)
	}
	if !srcInfo.Mode().IsRegular() || srcInfo.Mode()&os.ModeSymlink != 0 {
		return Artifact{}, fmt.Errorf("registry: artifact source is not a regular file")
	}
	src, err := os.Open(sourcePath)
	if err != nil {
		return Artifact{}, fmt.Errorf("registry: open artifact source: %w", err)
	}
	defer src.Close()

	base := filepath.Join(r.Root, slug, artifactDirName, "sha256")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return Artifact{}, fmt.Errorf("registry: create artifact root: %w", err)
	}
	// MkdirAll may have created every component from Root through sha256.
	// Sync the hierarchy bottom-up before any DB row can refer to the artifact;
	// syncing only the final digest directory does not durably persist those
	// ancestor directory entries across a power loss on a fresh node.
	if err := syncDirHierarchy(base, filepath.Dir(r.Root)); err != nil {
		return Artifact{}, err
	}
	tmp, err := os.CreateTemp(base, ".publish-")
	if err != nil {
		return Artifact{}, fmt.Errorf("registry: create artifact stage: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), src); err != nil {
		_ = tmp.Close()
		return Artifact{}, fmt.Errorf("registry: copy artifact: %w", err)
	}
	if err := tmp.Chmod(0o500); err != nil {
		_ = tmp.Close()
		return Artifact{}, fmt.Errorf("registry: chmod artifact: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return Artifact{}, fmt.Errorf("registry: sync artifact: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return Artifact{}, fmt.Errorf("registry: close artifact: %w", err)
	}
	digest := hex.EncodeToString(h.Sum(nil))
	digestDir := filepath.Join(base, digest)
	if err := os.MkdirAll(digestDir, 0o700); err != nil {
		return Artifact{}, fmt.Errorf("registry: create digest directory: %w", err)
	}
	final := filepath.Join(digestDir, "workflow")
	if err := os.Link(tmpPath, final); err != nil {
		if !os.IsExist(err) {
			return Artifact{}, fmt.Errorf("registry: publish artifact: %w", err)
		}
		if _, verifyErr := r.ArtifactPath(slug, digest); verifyErr != nil {
			return Artifact{}, fmt.Errorf("registry: existing artifact verification failed: %w", verifyErr)
		}
	}
	if err := syncDir(digestDir); err != nil {
		return Artifact{}, err
	}
	// Persist both directory entries: syncing digestDir covers `workflow`,
	// while syncing base covers the newly-created `<digest>/` name itself.
	if err := syncDir(base); err != nil {
		return Artifact{}, err
	}
	return Artifact{Path: final, Digest: digest}, nil
}

// ArtifactPath resolves and verifies one immutable executable. The digest is
// checked on every resolution, so accidental mutation/tampering fails before
// the dispatcher starts a subprocess.
func (r *FileRegistry) ArtifactPath(slug, digest string) (string, error) {
	if !safeSlug(slug) {
		return "", fmt.Errorf("registry: invalid slug")
	}
	if !validDigest(digest) {
		return "", fmt.Errorf("registry: invalid artifact sha256")
	}
	path := filepath.Join(r.Root, slug, artifactDirName, "sha256", digest, "workflow")
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("registry: stat artifact %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("registry: artifact %s is not a regular file", path)
	}
	if info.Mode()&0o111 == 0 {
		return "", fmt.Errorf("registry: artifact %s is not executable", path)
	}
	got, err := fileSHA256(path)
	if err != nil {
		return "", err
	}
	if got != digest {
		return "", fmt.Errorf("registry: artifact digest mismatch")
	}
	return path, nil
}

// SetBuildArtifact atomically records the exact immutable executable produced
// by the split `workflow build` command. Registration and replay testing read
// this digest instead of re-hashing the mutable compatibility binary, so an
// unrelated activation cannot silently change which bytes are registered or
// tested between the two commands.
func (r *FileRegistry) SetBuildArtifact(slug, digest string) error {
	if _, err := r.ArtifactPath(slug, digest); err != nil {
		return err
	}
	dir := filepath.Join(r.Root, slug)
	tmp, err := os.CreateTemp(dir, ".candidate-")
	if err != nil {
		return fmt.Errorf("registry: create candidate reference: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := io.WriteString(tmp, digest+"\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("registry: write candidate reference: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("registry: chmod candidate reference: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("registry: sync candidate reference: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("registry: close candidate reference: %w", err)
	}
	if err := os.Rename(tmpPath, filepath.Join(dir, buildArtifactFileName)); err != nil {
		return fmt.Errorf("registry: publish candidate reference: %w", err)
	}
	return syncDir(dir)
}

// BuildArtifact returns the immutable executable selected by the latest split
// build. The reference has a fixed shape and the artifact is re-hashed before
// use, so corrupt, forged, or legacy mutable-only candidates fail closed.
func (r *FileRegistry) BuildArtifact(slug string) (Artifact, error) {
	if !safeSlug(slug) {
		return Artifact{}, fmt.Errorf("registry: invalid slug")
	}
	path := filepath.Join(r.Root, slug, buildArtifactFileName)
	info, err := os.Lstat(path)
	if err != nil {
		return Artifact{}, fmt.Errorf("registry: stat candidate reference: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != sha256.Size*2+1 {
		return Artifact{}, fmt.Errorf("registry: invalid candidate reference")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Artifact{}, fmt.Errorf("registry: read candidate reference: %w", err)
	}
	if len(raw) != sha256.Size*2+1 || raw[len(raw)-1] != '\n' {
		return Artifact{}, fmt.Errorf("registry: invalid candidate reference")
	}
	digest := string(raw[:len(raw)-1])
	artifactPath, err := r.ArtifactPath(slug, digest)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{Path: artifactPath, Digest: digest}, nil
}

// ActivateArtifact atomically refreshes the legacy/current binary path used by
// status and direct tooling. Callers which also update workflow_versions must
// invoke this only from Journal.ActivateWorkflowArtifactIfCurrent; that row-lock
// guard prevents an older, delayed registration from overwriting a newer
// compatibility binary. Production run execution resolves ArtifactPath and
// never this mutable compatibility copy.
func (r *FileRegistry) ActivateArtifact(slug, digest string) (string, error) {
	artifactPath, err := r.ArtifactPath(slug, digest)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(r.Root, slug)
	tmp, err := os.CreateTemp(dir, ".activate-")
	if err != nil {
		return "", fmt.Errorf("registry: create activation stage: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	src, err := os.Open(artifactPath)
	if err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("registry: open artifact for activation: %w", err)
	}
	_, copyErr := io.Copy(tmp, src)
	closeSrcErr := src.Close()
	if copyErr != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("registry: copy activation: %w", copyErr)
	}
	if closeSrcErr != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("registry: close activation source: %w", closeSrcErr)
	}
	if err := tmp.Chmod(0o700); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("registry: chmod activation: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("registry: sync activation: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("registry: close activation: %w", err)
	}
	current := filepath.Join(dir, "workflow")
	if err := os.Rename(tmpPath, current); err != nil {
		return "", fmt.Errorf("registry: activate artifact: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return "", err
	}
	return current, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("registry: open artifact: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("registry: hash artifact: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func validDigest(v string) bool {
	if len(v) != sha256.Size*2 {
		return false
	}
	b, err := hex.DecodeString(v)
	return err == nil && hex.EncodeToString(b) == v
}

func safeSlug(v string) bool {
	return v != "" && v != "." && v != ".." && filepath.Base(v) == v
}

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("registry: open directory for sync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("registry: sync directory: %w", err)
	}
	return nil
}

func syncDirHierarchy(from, through string) error {
	current, err := filepath.Abs(from)
	if err != nil {
		return fmt.Errorf("registry: resolve sync hierarchy: %w", err)
	}
	stop, err := filepath.Abs(through)
	if err != nil {
		return fmt.Errorf("registry: resolve sync hierarchy stop: %w", err)
	}
	for {
		if err := syncDir(current); err != nil {
			return err
		}
		if current == stop {
			return nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("registry: sync hierarchy %s does not contain %s", stop, from)
		}
		current = parent
	}
}

// List returns every slug with a deployable binary under Root. Used by
// the status server's home page so operators can see what's available.
func (r *FileRegistry) List() ([]string, error) {
	entries, err := os.ReadDir(r.Root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("registry: read dir: %w", err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := r.BinaryPath(e.Name()); err == nil {
			out = append(out, e.Name())
		}
	}
	return out, nil
}
