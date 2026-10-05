// Package artifactmirror publishes one journal-pinned, source-proven workflow
// version to the artifact tree mounted by distributed workers.
package artifactmirror

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/workflowproof"
)

const (
	maxSourceFileBytes = 16 << 20
	maxSourceTreeBytes = 65 << 20 // source files plus the bounded manifest
	maxSourceEntries   = 8192
	maxSourceDepth     = 32
	maxStaleStages     = 8
)

// MirrorVersion copies only the exact immutable artifact and retained source
// pinned by version. It never copies mutable current/candidate pointers. The
// destination must be an existing, writable state root (for example the root
// of the worker artifact PVC) and must not be the source state root.
func MirrorVersion(ctx context.Context, sourceRoot, destinationRoot, slug, tenant string, version journal.WorkflowVersion) (string, error) {
	if ctx == nil {
		return "", errors.New("artifact mirror: context is required")
	}
	if !filepath.IsAbs(sourceRoot) || !filepath.IsAbs(destinationRoot) || strings.TrimSpace(slug) == "" || strings.TrimSpace(tenant) == "" || version.Version < 1 {
		return "", errors.New("artifact mirror: absolute source/destination roots, slug, tenant, and an exact version are required")
	}
	sourceReal, err := filepath.EvalSymlinks(sourceRoot)
	if err != nil {
		return "", fmt.Errorf("artifact mirror: resolve source root: %w", err)
	}
	destinationReal, err := filepath.EvalSymlinks(destinationRoot)
	if err != nil {
		return "", fmt.Errorf("artifact mirror: resolve destination root: %w", err)
	}
	if sourceReal == destinationReal {
		return "", errors.New("artifact mirror: source and destination roots must differ")
	}
	if pathWithin(sourceReal, destinationReal) || pathWithin(destinationReal, sourceReal) {
		return "", errors.New("artifact mirror: source and destination roots must not overlap")
	}
	if info, err := os.Lstat(destinationRoot); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("artifact mirror: destination root must be an existing directory, not a symlink")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	proof := workflowproof.CheckVersionForTenant(sourceRoot, slug, tenant, version)
	if version.SourceProofVersion != 2 || proof.Status != "verified" {
		return "", fmt.Errorf("artifact mirror: source version lacks verified immutable artifact, retained source, and visual DAG proof: %s", proof.Error())
	}
	sourceRegistry := registry.New(filepath.Join(sourceRoot, "workflows"))
	sourceBinary, err := sourceRegistry.ArtifactPathForTenant(slug, version.ArtifactSHA256, tenant)
	if err != nil {
		return "", fmt.Errorf("artifact mirror: resolve pinned source artifact: %w", err)
	}
	// EvalSymlinks alone cannot detect a bind mount that aliases part of the
	// source tree at another path. Compare directory identities too, before
	// creating anything in the destination.
	sourceDirs := []string{filepath.Join(filepath.Dir(sourceBinary), "source")}
	for current := filepath.Dir(sourceBinary); ; current = filepath.Dir(current) {
		sourceDirs = append(sourceDirs, current)
		if current == filepath.Clean(sourceRoot) || filepath.Dir(current) == current {
			break
		}
	}
	for _, sourceDir := range sourceDirs {
		if aliasedAncestor(sourceDir, destinationRoot) || aliasedAncestor(destinationRoot, sourceDir) {
			return "", errors.New("artifact mirror: destination aliases the source artifact tree")
		}
	}
	sourceNamespace := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(sourceBinary))))
	namespaceRel, err := filepath.Rel(sourceRegistry.Root, sourceNamespace)
	if err != nil {
		return "", fmt.Errorf("artifact mirror: resolve source namespace: %w", err)
	}
	scopedNamespace, err := sourceRegistry.ScopedWorkflowDir(slug, tenant)
	if err != nil {
		return "", err
	}
	scopedRel, err := filepath.Rel(sourceRegistry.Root, scopedNamespace)
	if err != nil {
		return "", err
	}
	if namespaceRel != slug && namespaceRel != scopedRel {
		return "", errors.New("artifact mirror: source namespace is not the tenant's expected layout")
	}
	if err := ensureDirectories(destinationRoot, "workflows", filepath.Join("workflows", ".locks")); err != nil {
		return "", err
	}
	destinationRegistry := registry.New(filepath.Join(destinationRoot, "workflows"))
	release, err := destinationRegistry.AcquireSlugLock(ctx, slug)
	if err != nil {
		return "", fmt.Errorf("artifact mirror: lock destination slug: %w", err)
	}
	defer release()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	// A previous publisher may have copied and verified these exact bytes but
	// lost its database acknowledgement. Recheck the complete destination
	// proof under the namespace lock before attempting another write: a full
	// PVC must not turn an already-published artifact into a failed request.
	// Require the same namespace layout as the source; a tenant-aware lookup
	// can otherwise resolve a legacy path when this source is scoped (or vice
	// versa), bypassing the layout checks below.
	expectedPath := filepath.Join(destinationRegistry.Root, namespaceRel, "artifacts", "sha256", version.ArtifactSHA256, "workflow")
	if existingPath, pathErr := destinationRegistry.ArtifactPathForTenant(slug, version.ArtifactSHA256, tenant); pathErr == nil && existingPath == expectedPath {
		if result := workflowproof.CheckVersionForTenant(destinationRoot, slug, tenant, version); result.Status == "verified" {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			return existingPath, nil
		}
	}
	if err := ensureDirectories(destinationRoot, filepath.Join("workflows", namespaceRel)); err != nil {
		return "", err
	}
	if namespaceRel == slug {
		if err := destinationRegistry.EnsureTenant(slug, tenant, false); err != nil {
			return "", fmt.Errorf("artifact mirror: claim destination namespace: %w", err)
		}
	} else {
		if owner, err := destinationRegistry.TenantOwner(slug); err == nil && owner == tenant {
			return "", errors.New("artifact mirror: destination already uses the legacy namespace for this tenant")
		} else if err != nil && !errors.Is(err, registry.ErrTenantOwnerMissing) {
			return "", fmt.Errorf("artifact mirror: inspect destination legacy owner: %w", err)
		}
		dir := filepath.Join(destinationRegistry.Root, namespaceRel)
		if err := requireClaimableNamespace(dir); err != nil {
			return "", err
		}
		if _, err := destinationRegistry.EnsureScopedTenant(slug, tenant); err != nil {
			return "", fmt.Errorf("artifact mirror: claim scoped destination namespace: %w", err)
		}
	}
	if err := ensureDirectories(destinationRoot, filepath.Join("workflows", namespaceRel, "artifacts", "sha256", version.ArtifactSHA256)); err != nil {
		return "", err
	}
	var published registry.Artifact
	if namespaceRel == slug {
		published, err = destinationRegistry.PublishArtifact(slug, sourceBinary)
	} else {
		published, err = destinationRegistry.PublishArtifactForTenant(slug, sourceBinary, tenant)
	}
	if err != nil {
		return "", fmt.Errorf("artifact mirror: publish pinned artifact: %w", err)
	}
	if published.Digest != version.ArtifactSHA256 {
		return "", errors.New("artifact mirror: source artifact changed during publication")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	destinationSource := filepath.Join(filepath.Dir(published.Path), "source")
	if err := publishSource(ctx, filepath.Join(filepath.Dir(sourceBinary), "source"), destinationSource, version.SourceManifestSHA256); err != nil {
		return "", err
	}
	if result := workflowproof.CheckVersionForTenant(destinationRoot, slug, tenant, version); result.Status != "verified" {
		return "", fmt.Errorf("artifact mirror: destination proof failed: %s", result.Status)
	}
	return published.Path, nil
}

func pathWithin(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// aliasedAncestor detects a bind mount of ancestor anywhere in descendant's
// path, including aliases that EvalSymlinks cannot resolve.
func aliasedAncestor(ancestor, descendant string) bool {
	ancestorInfo, err := os.Stat(ancestor)
	if err != nil {
		return false
	}
	for current := descendant; ; current = filepath.Dir(current) {
		if info, err := os.Stat(current); err == nil && os.SameFile(ancestorInfo, info) {
			return true
		}
		if parent := filepath.Dir(current); parent == current {
			return false
		}
	}
}

func requireClaimableNamespace(dir string) error {
	if _, err := os.Lstat(filepath.Join(dir, ".tenant-owner")); err == nil {
		return nil // EnsureScopedTenant verifies the existing owner.
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("artifact mirror: inspect scoped owner: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("artifact mirror: inspect scoped namespace: %w", err)
	}
	if len(entries) != 0 {
		return errors.New("artifact mirror: scoped destination namespace has unclaimed contents")
	}
	return nil
}

// ensureDirectories never adopts a symlink below the operator-supplied root.
func ensureDirectories(root string, relatives ...string) error {
	for _, relative := range relatives {
		current := root
		for _, component := range strings.Split(relative, string(filepath.Separator)) {
			if component == "" || component == "." || component == ".." {
				return errors.New("artifact mirror: invalid destination directory")
			}
			current = filepath.Join(current, component)
			if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("artifact mirror: create destination directory: %w", err)
			}
			info, err := os.Lstat(current)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("artifact mirror: destination path contains a symlink or non-directory")
			}
		}
	}
	return nil
}

func publishSource(ctx context.Context, sourceDir, destinationDir, pinnedManifest string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if info, err := os.Lstat(destinationDir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("artifact mirror: destination source is not a regular directory")
		}
		present, digest, err := registry.VerifySourceManifestDigestIfPresent(destinationDir)
		if err != nil || !present || digest != pinnedManifest {
			return errors.New("artifact mirror: existing destination source does not match pinned manifest")
		}
		return syncDirectory(filepath.Dir(destinationDir))
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("artifact mirror: inspect destination source: %w", err)
	}
	parent := filepath.Dir(destinationDir)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return fmt.Errorf("artifact mirror: inspect prior source stages: %w", err)
	}
	stale := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".mirror-source-") {
			stale++
		}
	}
	if stale >= maxStaleStages {
		return errors.New("artifact mirror: too many abandoned source stages under exact artifact digest; inspect and remove stale stages before retrying")
	}
	stage, err := os.MkdirTemp(parent, ".mirror-source-")
	if err != nil {
		return fmt.Errorf("artifact mirror: stage source: %w", err)
	}
	defer os.RemoveAll(stage)
	if err := copySourceTree(ctx, sourceDir, stage); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	present, digest, err := registry.VerifySourceManifestDigestIfPresent(stage)
	if err != nil || !present || digest != pinnedManifest {
		return errors.New("artifact mirror: staged source does not match pinned manifest")
	}
	if err := os.Rename(stage, destinationDir); err != nil {
		return fmt.Errorf("artifact mirror: publish retained source: %w", err)
	}
	return syncDirectory(parent)
}

func copySourceTree(ctx context.Context, sourceDir, stage string) error {
	var total int64
	var directories []string
	entries := 0
	err := filepath.WalkDir(sourceDir, func(path string, entry os.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		entries++
		if entries > maxSourceEntries || strings.Count(filepath.ToSlash(rel), "/") >= maxSourceDepth {
			return errors.New("artifact mirror: retained source entry count or depth exceeds copy limit")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("artifact mirror: retained source contains a symlink")
		}
		target := filepath.Join(stage, rel)
		if entry.IsDir() {
			if err := os.Mkdir(target, 0o700); err != nil {
				return err
			}
			directories = append(directories, target)
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("artifact mirror: retained source contains a special file")
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			_ = input.Close()
			return err
		}
		n, copyErr := io.Copy(output, io.LimitReader(&contextReader{ctx: ctx, source: input}, maxSourceFileBytes+1))
		total += n
		if copyErr == nil && (n > maxSourceFileBytes || total > maxSourceTreeBytes) {
			copyErr = errors.New("artifact mirror: retained source exceeds copy limit")
		}
		if copyErr == nil {
			copyErr = output.Sync()
		}
		closeErr := output.Close()
		_ = input.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err != nil {
		return fmt.Errorf("artifact mirror: copy retained source: %w", err)
	}
	for i := len(directories) - 1; i >= 0; i-- {
		if err := syncDirectory(directories[i]); err != nil {
			return err
		}
	}
	return syncDirectory(stage)
}

// contextReader checks cancellation between bounded source-copy chunks. An
// expired publisher claim must stop before source publication and ACK.
type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(p)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
