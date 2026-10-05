// Package registry resolves a workflow slug and tenant to the compiled binary
// the supervisor exec's. Production deployments retain the legacy
// <root>/<slug>/workflow layout for an existing owner and use a hashed
// <root>/tenants/<tenant-hash>/<slug>/workflow namespace for same-slug
// workflows in other tenants; tests inject a fake.
//
// Convention is simple by design: one directory per workflow, the
// binary always named "workflow". This matches the codegen
// orchestrator's atomic rename target (reactor-workflows/<slug>/) so
// `reactor workflow build <slug>` writes into the same shape the
// daemon reads from.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	artifactDirName        = "artifacts"
	buildArtifactFileName  = "candidate.sha256"
	tenantOwnerFileName    = ".tenant-owner"
	tenantNamespaceDirName = "tenants"
	maxTenantOwnerBytes    = 256
)

// ErrTenantOwnerMissing means the executable slug namespace has not been
// claimed by an authoring path yet. An unclaimed namespace must not be adopted
// by an import merely because a digest happens to exist under the slug.
var ErrTenantOwnerMissing = errors.New("registry: tenant owner manifest missing")

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

// ScopedWorkflowDir returns the tenant-isolated namespace used when two
// tenants use the same workflow slug. Tenant IDs are encoded as a SHA-256
// directory component instead of being used as a path directly: tenant IDs
// are database data and may contain path separators or other characters that
// must never influence filesystem traversal. The namespace still carries a
// .tenant-owner manifest, so a hash collision or a copied directory fails
// closed rather than silently becoming executable under another tenant.
func (r *FileRegistry) ScopedWorkflowDir(slug, tenant string) (string, error) {
	if !safeSlug(slug) {
		return "", fmt.Errorf("registry: invalid slug")
	}
	tenant, err := normalizeTenant(tenant)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(tenant))
	return filepath.Join(r.Root, tenantNamespaceDirName, hex.EncodeToString(sum[:]), slug), nil
}

// EnsureScopedTenant creates and immutably claims a tenant-isolated workflow
// namespace. It is used by authoring paths when a shared legacy slug
// directory is already owned by another tenant. Callers should hold
// AcquireSlugLock while invoking it.
func (r *FileRegistry) EnsureScopedTenant(slug, tenant string) (string, error) {
	dir, err := r.ScopedWorkflowDir(slug, tenant)
	if err != nil {
		return "", err
	}
	if err := r.claimTenantAt(dir, tenant); err != nil {
		return "", err
	}
	return dir, nil
}

// EnsureTenant binds a slug's mutable executable namespace to one tenant.
//
// The journal permits the same slug in multiple tenants, while the current
// node-local artifact layout has one directory per slug. The owner manifest is
// deliberately separate from candidate.sha256 and the immutable digest tree:
// changing a candidate or activating a reviewed digest can never change the
// tenant that owns the namespace. Callers should hold AcquireSlugLock while
// invoking this method. When allowLegacy is true, an existing database row
// for the requested tenant is an explicit migration proof that permits adding
// the manifest to a pre-manifest installation. With no such proof, a
// pre-existing unclaimed directory is rejected rather than adopting stale
// executable bytes.
func (r *FileRegistry) EnsureTenant(slug, tenant string, allowLegacy bool) error {
	tenant, err := normalizeTenant(tenant)
	if err != nil {
		return err
	}
	owner, err := r.TenantOwner(slug)
	if err == nil {
		if owner != tenant {
			return fmt.Errorf("registry: slug %q is owned by tenant %q, not %q", slug, owner, tenant)
		}
		return nil
	}
	if !errors.Is(err, ErrTenantOwnerMissing) {
		return err
	}
	if !allowLegacy {
		dir := filepath.Join(r.Root, slug)
		if info, statErr := os.Stat(dir); statErr == nil {
			if !info.IsDir() {
				return fmt.Errorf("registry: slug namespace %q is not a directory", slug)
			}
			entries, readErr := os.ReadDir(dir)
			if readErr != nil {
				return fmt.Errorf("registry: inspect unclaimed slug namespace: %w", readErr)
			}
			if len(entries) > 0 {
				return fmt.Errorf("registry: slug %q has executable state but no tenant owner manifest; explicit adoption is required", slug)
			}
		} else if !os.IsNotExist(statErr) {
			return fmt.Errorf("registry: inspect slug namespace: %w", statErr)
		}
	}
	return r.ClaimTenant(slug, tenant)
}

// ClaimTenant atomically creates the immutable tenant-owner manifest for a
// slug, or verifies the existing manifest. It never overwrites an owner. This
// is kept separate from PublishArtifact because content-addressed bytes do
// not carry tenant identity and must not be used to infer it.
func (r *FileRegistry) ClaimTenant(slug, tenant string) error {
	if !safeSlug(slug) {
		return fmt.Errorf("registry: invalid slug")
	}
	tenant, err := normalizeTenant(tenant)
	if err != nil {
		return err
	}
	dir := filepath.Join(r.Root, slug)
	return r.claimTenantAt(dir, tenant)
}

// TenantOwner reads the immutable tenant-owner manifest for a slug.
func (r *FileRegistry) TenantOwner(slug string) (string, error) {
	if !safeSlug(slug) {
		return "", fmt.Errorf("registry: invalid slug")
	}
	return r.tenantOwnerAt(filepath.Join(r.Root, slug))
}

func (r *FileRegistry) tenantOwnerAt(dir string) (string, error) {
	path := filepath.Join(dir, tenantOwnerFileName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrTenantOwnerMissing
	}
	if err != nil {
		return "", fmt.Errorf("registry: stat tenant owner manifest: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 2 || info.Size() > maxTenantOwnerBytes {
		return "", fmt.Errorf("registry: invalid tenant owner manifest")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("registry: read tenant owner manifest: %w", err)
	}
	if len(raw) < 2 || len(raw) > maxTenantOwnerBytes || raw[len(raw)-1] != '\n' {
		return "", fmt.Errorf("registry: invalid tenant owner manifest")
	}
	owner, err := normalizeTenant(string(raw[:len(raw)-1]))
	if err != nil {
		return "", fmt.Errorf("registry: invalid tenant owner manifest: %w", err)
	}
	return owner, nil
}

// claimTenantAt creates or verifies the immutable owner manifest for an
// already validated namespace directory. The same helper is used by the
// legacy slug directory and the hashed tenant-isolated namespace so both
// layouts have identical fail-closed owner semantics.
func (r *FileRegistry) claimTenantAt(dir, tenant string) error {
	tenant, err := normalizeTenant(tenant)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("registry: create tenant namespace: %w", err)
	}
	path := filepath.Join(dir, tenantOwnerFileName)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		ok := false
		defer func() {
			_ = f.Close()
			if !ok {
				_ = os.Remove(path)
			}
		}()
		if _, err := io.WriteString(f, tenant+"\n"); err != nil {
			return fmt.Errorf("registry: write tenant owner manifest: %w", err)
		}
		if err := f.Sync(); err != nil {
			return fmt.Errorf("registry: sync tenant owner manifest: %w", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("registry: close tenant owner manifest: %w", err)
		}
		if err := syncDirHierarchy(dir, filepath.Dir(r.Root)); err != nil {
			return err
		}
		ok = true
		return nil
	}
	if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("registry: create tenant owner manifest: %w", err)
	}
	owner, err := r.tenantOwnerAt(dir)
	if err != nil {
		return err
	}
	if owner != tenant {
		return fmt.Errorf("registry: tenant namespace is owned by tenant %q, not %q", owner, tenant)
	}
	return nil
}

func normalizeTenant(tenant string) (string, error) {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" || len(tenant) >= maxTenantOwnerBytes || strings.ContainsAny(tenant, "\r\n") {
		return "", fmt.Errorf("registry: invalid tenant owner")
	}
	return tenant, nil
}

// AcquireSlugLock serializes every publisher that shares a node-local slug
// namespace. The lock is an advisory flock on a stable file, so it is shared
// by separate Reactor processes (CLI + daemon) and released by the kernel if a
// process crashes. Callers must invoke the returned release function.
//
// The lock file itself is intentionally retained under .locks; its inode is
// stable across acquisitions, which avoids the unlink/recreate race where two
// processes can each believe they own a lock for the same slug.
func (r *FileRegistry) AcquireSlugLock(ctx context.Context, slug string) (func(), error) {
	if !safeSlug(slug) {
		return nil, fmt.Errorf("registry: invalid slug")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	lockDir := filepath.Join(r.Root, ".locks")
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		return nil, fmt.Errorf("registry: create slug lock directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(lockDir, slug+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("registry: open slug lock: %w", err)
	}
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() {
				_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			_ = f.Close()
			return nil, fmt.Errorf("registry: acquire slug lock: %w", err)
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = f.Close()
			return nil, fmt.Errorf("registry: acquire slug lock: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

// BinaryPath implements dispatcher.BinaryLookup. Returns an error if
// the binary doesn't exist or isn't executable.
func (r *FileRegistry) BinaryPath(slug string) (string, error) {
	if slug == "" {
		return "", fmt.Errorf("registry: empty slug")
	}
	return r.binaryPathInDir(filepath.Join(r.Root, slug), slug)
}

func (r *FileRegistry) binaryPathInDir(dir, label string) (string, error) {
	path := filepath.Join(dir, "workflow")
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("registry: stat %s: %w", label, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
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
	return r.publishArtifactInDir(filepath.Join(r.Root, slug), sourcePath)
}

// PublishArtifactForTenant publishes into the hashed tenant-isolated
// namespace. It is the authoring primitive for a tenant whose slug collides
// with a legacy/shared namespace owned by another tenant. Callers that already
// resolved a legacy owner should continue to use PublishArtifact so existing
// installations retain their on-disk layout.
func (r *FileRegistry) PublishArtifactForTenant(slug, sourcePath, tenant string) (Artifact, error) {
	dir, err := r.EnsureScopedTenant(slug, tenant)
	if err != nil {
		return Artifact{}, err
	}
	return r.publishArtifactInDir(dir, sourcePath)
}

func (r *FileRegistry) publishArtifactInDir(dir, sourcePath string) (Artifact, error) {
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

	base := filepath.Join(dir, artifactDirName, "sha256")
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
		if _, verifyErr := r.artifactPathInDir(dir, digest); verifyErr != nil {
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
	return r.artifactPathInDir(filepath.Join(r.Root, slug), digest)
}

func (r *FileRegistry) artifactPathInDir(dir, digest string) (string, error) {
	if !validDigest(digest) {
		return "", fmt.Errorf("registry: invalid artifact sha256")
	}
	path := filepath.Join(dir, artifactDirName, "sha256", digest, "workflow")
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

// ArtifactPathForTenant resolves an immutable executable only when the
// namespace owner manifest matches the workflow tenant. It first preserves the
// original <root>/<slug> layout for installations with a matching owner, then
// checks the hashed tenant-isolated layout used for same-slug workflows in
// another tenant. ArtifactPath remains available for legacy in-process
// fixtures and low-level maintenance, but all tenant-aware read and execution
// paths should use this method. A missing owner manifest fails closed; a digest
// alone never establishes tenant ownership.
func (r *FileRegistry) ArtifactPathForTenant(slug, digest, tenant string) (string, error) {
	tenant, err := normalizeTenant(tenant)
	if err != nil {
		return "", err
	}
	legacyDir := filepath.Join(r.Root, slug)
	owner, ownerErr := r.TenantOwner(slug)
	if ownerErr == nil && owner == tenant {
		return r.artifactPathInDir(legacyDir, digest)
	}
	if ownerErr != nil && !errors.Is(ownerErr, ErrTenantOwnerMissing) {
		return "", fmt.Errorf("registry: verify tenant owner for artifact: %w", ownerErr)
	}

	// A legacy owner belonging to another tenant does not make the digest
	// invalid for this tenant; it selects the isolated namespace instead. The
	// isolated owner manifest is still mandatory, so copying bytes into the
	// hashed path without the claim cannot bypass the fence.
	scopedDir, err := r.ScopedWorkflowDir(slug, tenant)
	if err != nil {
		return "", err
	}
	scopedOwner, scopedErr := r.tenantOwnerAt(scopedDir)
	if scopedErr == nil && scopedOwner == tenant {
		return r.artifactPathInDir(scopedDir, digest)
	}
	if scopedErr != nil && !errors.Is(scopedErr, ErrTenantOwnerMissing) {
		return "", fmt.Errorf("registry: verify scoped tenant owner for artifact: %w", scopedErr)
	}
	if ownerErr == nil {
		return "", fmt.Errorf("registry: artifact namespace %q is owned by tenant %q, not %q", slug, owner, tenant)
	}
	return "", fmt.Errorf("registry: verify tenant owner for artifact: %w", ErrTenantOwnerMissing)
}

// TenantArtifactPath is the dispatcher/scheduler callback shape: tenant first,
// followed by the workflow slug and immutable digest. Keep this adapter next
// to the canonical slug,digest,tenant method so assigning a method value to a
// three-string callback cannot silently reorder the security-sensitive args.
func (r *FileRegistry) TenantArtifactPath(tenant, slug, digest string) (string, error) {
	return r.ArtifactPathForTenant(slug, digest, tenant)
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
	return r.setBuildArtifactInDir(filepath.Join(r.Root, slug), digest)
}

// SetBuildArtifactForTenant records a candidate in the isolated namespace.
// The owner manifest is checked before the candidate pointer is written.
func (r *FileRegistry) SetBuildArtifactForTenant(slug, digest, tenant string) error {
	dir, err := r.EnsureScopedTenant(slug, tenant)
	if err != nil {
		return err
	}
	if _, err := r.artifactPathInDir(dir, digest); err != nil {
		return err
	}
	return r.setBuildArtifactInDir(dir, digest)
}

func (r *FileRegistry) setBuildArtifactInDir(dir, digest string) error {
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
	return r.buildArtifactInDir(filepath.Join(r.Root, slug))
}

// BuildArtifactForTenant reads the candidate from a tenant-isolated namespace.
func (r *FileRegistry) BuildArtifactForTenant(slug, tenant string) (Artifact, error) {
	dir, err := r.ScopedWorkflowDir(slug, tenant)
	if err != nil {
		return Artifact{}, err
	}
	owner, err := r.tenantOwnerAt(dir)
	if err != nil {
		return Artifact{}, fmt.Errorf("registry: verify tenant owner for candidate: %w", err)
	}
	normalized, _ := normalizeTenant(tenant)
	if owner != normalized {
		return Artifact{}, fmt.Errorf("registry: candidate namespace is owned by tenant %q, not %q", owner, normalized)
	}
	return r.buildArtifactInDir(dir)
}

func (r *FileRegistry) buildArtifactInDir(dir string) (Artifact, error) {
	path := filepath.Join(dir, buildArtifactFileName)
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
	artifactPath, err := r.artifactPathInDir(dir, digest)
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
	return r.activateArtifactInDir(filepath.Join(r.Root, slug), artifactPath)
}

// ActivateArtifactForTenant refreshes the isolated compatibility binary after
// a version row has passed its journal compare-and-swap fence.
func (r *FileRegistry) ActivateArtifactForTenant(slug, digest, tenant string) (string, error) {
	dir, err := r.EnsureScopedTenant(slug, tenant)
	if err != nil {
		return "", err
	}
	artifactPath, err := r.artifactPathInDir(dir, digest)
	if err != nil {
		return "", err
	}
	return r.activateArtifactInDir(dir, artifactPath)
}

func (r *FileRegistry) activateArtifactInDir(dir, artifactPath string) (string, error) {
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
	seen := make(map[string]struct{})
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if e.Name() == tenantNamespaceDirName || e.Name() == ".locks" {
			continue
		}
		if _, err := r.BinaryPath(e.Name()); err == nil {
			seen[e.Name()] = struct{}{}
		}
	}
	// Include tenant-isolated namespaces in estate-wide status views. The
	// hashed directory is an implementation detail; status exposes the journal
	// slug, and the set naturally de-duplicates a slug shared by tenants.
	scopedRoot := filepath.Join(r.Root, tenantNamespaceDirName)
	hashEntries, hashErr := os.ReadDir(scopedRoot)
	if hashErr != nil && !os.IsNotExist(hashErr) {
		return nil, fmt.Errorf("registry: read tenant namespaces: %w", hashErr)
	}
	for _, hashEntry := range hashEntries {
		if !hashEntry.IsDir() {
			continue
		}
		slugEntries, readErr := os.ReadDir(filepath.Join(scopedRoot, hashEntry.Name()))
		if readErr != nil {
			return nil, fmt.Errorf("registry: read tenant workflow namespaces: %w", readErr)
		}
		for _, slugEntry := range slugEntries {
			if !slugEntry.IsDir() {
				continue
			}
			if _, pathErr := r.binaryPathInDir(filepath.Join(scopedRoot, hashEntry.Name(), slugEntry.Name()), slugEntry.Name()); pathErr == nil {
				seen[slugEntry.Name()] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for slug := range seen {
		out = append(out, slug)
	}
	sort.Strings(out)
	return out, nil
}

// ListForTenant returns only executable workflow slugs whose owner manifest
// matches tenant. It covers both legacy slug directories and hashed isolated
// namespaces, so a member's dashboard cannot report another tenant's
// executable as available merely because the slug is shared.
func (r *FileRegistry) ListForTenant(tenant string) ([]string, error) {
	tenant, err := normalizeTenant(tenant)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	entries, err := os.ReadDir(r.Root)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("registry: read dir: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == tenantNamespaceDirName || entry.Name() == ".locks" {
			continue
		}
		owner, ownerErr := r.TenantOwner(entry.Name())
		if ownerErr != nil || owner != tenant {
			continue
		}
		if _, pathErr := r.binaryPathInDir(filepath.Join(r.Root, entry.Name()), entry.Name()); pathErr == nil {
			seen[entry.Name()] = struct{}{}
		}
	}
	sum := sha256.Sum256([]byte(tenant))
	scopedRoot := filepath.Join(r.Root, tenantNamespaceDirName, hex.EncodeToString(sum[:]))
	slugEntries, readErr := os.ReadDir(scopedRoot)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("registry: read tenant workflow namespaces: %w", readErr)
	}
	for _, entry := range slugEntries {
		if !entry.IsDir() {
			continue
		}
		owner, ownerErr := r.tenantOwnerAt(filepath.Join(scopedRoot, entry.Name()))
		if ownerErr != nil || owner != tenant {
			continue
		}
		if _, pathErr := r.binaryPathInDir(filepath.Join(scopedRoot, entry.Name()), entry.Name()); pathErr == nil {
			seen[entry.Name()] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for slug := range seen {
		out = append(out, slug)
	}
	sort.Strings(out)
	return out, nil
}
