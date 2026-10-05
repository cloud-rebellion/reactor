package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// SourceManifestFilename is stored beside retained workflow source. It binds
// every regular file that was present in the staged build tree (including
// helper Go files and go:embed assets), so review and later dashboard edits
// cannot silently drop or replace code that entered the executable.
const SourceManifestFilename = ".reactor-source-manifest.json"

const (
	sourceManifestVersion     = 1
	maxSourceManifestBytes    = 1 << 20
	maxSourceManifestFileSize = 16 << 20
	maxSourceManifestTotal    = 64 << 20
)

type sourceManifest struct {
	Version         int                   `json:"version"`
	Files           []sourceManifestEntry `json:"files"`
	CompiledGoFiles []string              `json:"compiled_go_files,omitempty"`
}

type sourceManifestEntry struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// BuildSourceManifest creates deterministic metadata for a retained source
// snapshot. The manifest itself is intentionally excluded; callers add it to
// the snapshot after this function returns.
func BuildSourceManifest(files map[string][]byte, compiledGoFiles ...[]string) ([]byte, error) {
	if len(compiledGoFiles) > 1 {
		return nil, errors.New("source manifest compiled file selection is ambiguous")
	}
	entries := make([]sourceManifestEntry, 0, len(files))
	var total int64
	for name, data := range files {
		clean, err := normalizeSourceManifestPath(name)
		if err != nil {
			return nil, err
		}
		if clean == SourceManifestFilename || clean == ".artifact_sha256" {
			return nil, fmt.Errorf("source manifest path %q is reserved", clean)
		}
		if int64(len(data)) > maxSourceManifestFileSize {
			return nil, fmt.Errorf("source file %q exceeds %d-byte limit", clean, maxSourceManifestFileSize)
		}
		total += int64(len(data))
		if total > maxSourceManifestTotal {
			return nil, fmt.Errorf("source files exceed %d-byte total limit", maxSourceManifestTotal)
		}
		sum := sha256.Sum256(data)
		entries = append(entries, sourceManifestEntry{
			Path: clean, Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:]),
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Path == entries[i].Path {
			return nil, fmt.Errorf("duplicate source manifest path %q", entries[i].Path)
		}
	}
	manifest := sourceManifest{Version: sourceManifestVersion, Files: entries}
	if len(compiledGoFiles) == 1 {
		manifest.CompiledGoFiles = append([]string(nil), compiledGoFiles[0]...)
		sort.Strings(manifest.CompiledGoFiles)
		if err := validateManifestCompiledGoFiles(manifest.CompiledGoFiles, files); err != nil {
			return nil, err
		}
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// VerifySourceManifest checks that dir contains exactly the files and bytes
// described by raw. The reserved dashboard artifact marker is ignored because
// it is metadata outside the retained source snapshot.
func VerifySourceManifest(dir string, raw []byte) error {
	if len(raw) == 0 || len(raw) > maxSourceManifestBytes {
		return errors.New("source manifest is missing or too large")
	}
	var manifest sourceManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return fmt.Errorf("source manifest is invalid JSON")
	}
	if manifest.Version != sourceManifestVersion {
		return fmt.Errorf("unsupported source manifest version %d", manifest.Version)
	}
	if len(manifest.Files) == 0 {
		return errors.New("source manifest contains no files")
	}
	wanted := make(map[string]sourceManifestEntry, len(manifest.Files))
	var total int64
	for i, entry := range manifest.Files {
		clean, err := normalizeSourceManifestPath(entry.Path)
		if err != nil || clean != entry.Path || clean == SourceManifestFilename || clean == ".artifact_sha256" {
			return fmt.Errorf("invalid source manifest path %q", entry.Path)
		}
		if i > 0 && manifest.Files[i-1].Path >= entry.Path {
			return errors.New("source manifest files are not sorted uniquely")
		}
		if entry.Bytes < 0 || entry.Bytes > maxSourceManifestFileSize {
			return fmt.Errorf("source manifest file %q exceeds size limit", entry.Path)
		}
		if len(entry.SHA256) != sha256.Size*2 {
			return fmt.Errorf("source manifest file %q has invalid hash", entry.Path)
		}
		if _, err := hex.DecodeString(entry.SHA256); err != nil || strings.ToLower(entry.SHA256) != entry.SHA256 {
			return fmt.Errorf("source manifest file %q has invalid hash", entry.Path)
		}
		if _, exists := wanted[entry.Path]; exists {
			return fmt.Errorf("duplicate source manifest path %q", entry.Path)
		}
		wanted[entry.Path] = entry
		total += entry.Bytes
		if total > maxSourceManifestTotal {
			return errors.New("source manifest exceeds total size limit")
		}
	}
	if manifest.CompiledGoFiles != nil {
		if err := validateManifestCompiledGoFiles(manifest.CompiledGoFiles, wanted); err != nil {
			return err
		}
	}
	seen := make(map[string]struct{}, len(wanted))
	for name, entry := range wanted {
		pathOnDisk := filepath.Join(dir, filepath.FromSlash(name))
		info, err := os.Lstat(pathOnDisk)
		if err != nil {
			return fmt.Errorf("source manifest file %q is missing", name)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("source manifest file %q is not regular", name)
		}
		if info.Size() != entry.Bytes {
			return fmt.Errorf("source manifest file %q size mismatch", name)
		}
		file, err := os.Open(pathOnDisk)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxSourceManifestFileSize+1))
		_ = file.Close()
		if readErr != nil {
			return readErr
		}
		if int64(len(data)) > maxSourceManifestFileSize || int64(len(data)) != entry.Bytes {
			return fmt.Errorf("source manifest file %q size changed during verification", name)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != entry.SHA256 {
			return fmt.Errorf("source manifest file %q hash mismatch", name)
		}
		seen[name] = struct{}{}
	}
	err := filepath.WalkDir(dir, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(dir, filePath)
		if err != nil {
			return err
		}
		if rel == "." || rel == SourceManifestFilename || rel == ".artifact_sha256" {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("source manifest tree contains symlink %q", rel)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("source manifest tree contains special file %q", rel)
		}
		name, err := normalizeSourceManifestPath(rel)
		if err != nil {
			return err
		}
		if _, ok := wanted[name]; !ok {
			return fmt.Errorf("source manifest has unexpected file %q", name)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(wanted) {
		return errors.New("source manifest is incomplete")
	}
	return nil
}

// SourceManifestCompiledGoFiles returns the build-selected workflow files
// from a previously verified retained source manifest. An absent selection is
// a legacy manifest and cannot certify the executable's visual graph.
func SourceManifestCompiledGoFiles(dir string) ([]string, bool, error) {
	file, err := os.Open(filepath.Join(dir, SourceManifestFilename))
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxSourceManifestBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(raw) > maxSourceManifestBytes {
		return nil, false, errors.New("source manifest is too large")
	}
	var manifest sourceManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, false, errors.New("source manifest is invalid JSON")
	}
	if manifest.CompiledGoFiles == nil {
		return nil, false, nil
	}
	return append([]string(nil), manifest.CompiledGoFiles...), true, nil
}

func validateManifestCompiledGoFiles[T any](selected []string, files map[string]T) error {
	if len(selected) == 0 {
		return errors.New("source manifest has no compiled root Go files")
	}
	mainSelected := false
	for i, name := range selected {
		clean, err := normalizeSourceManifestPath(name)
		base := path.Base(name)
		if err != nil || clean != name || !strings.HasSuffix(base, ".go") || strings.HasPrefix(base, ".") || strings.HasPrefix(base, "_") || strings.HasSuffix(base, "_test.go") {
			return fmt.Errorf("invalid compiled workflow Go file %q", name)
		}
		if i > 0 && selected[i-1] >= name {
			return errors.New("compiled workflow Go files are not sorted uniquely")
		}
		if _, ok := files[name]; !ok {
			return fmt.Errorf("compiled workflow Go file %q is missing from source manifest", name)
		}
		mainSelected = mainSelected || name == "main.go"
	}
	if !mainSelected {
		return errors.New("main.go is not selected for compiled workflow")
	}
	return nil
}

// VerifySourceManifestIfPresent preserves compatibility with artifacts
// created before full-tree retention. New artifacts always carry a manifest;
// callers should require the returned bool when they need modern full-source
// proof.
func VerifySourceManifestIfPresent(dir string) (bool, error) {
	present, _, err := VerifySourceManifestDigestIfPresent(dir)
	return present, err
}

// VerifySourceManifestDigestIfPresent returns the SHA-256 of the exact verified
// manifest bytes. New immutable workflow versions pin this digest in the
// journal, so editing source files and re-signing the local manifest cannot
// silently change the source proof accepted for that version.
func VerifySourceManifestDigestIfPresent(dir string) (present bool, digest string, err error) {
	pathOnDisk := filepath.Join(dir, SourceManifestFilename)
	info, err := os.Lstat(pathOnDisk)
	if errors.Is(err, os.ErrNotExist) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return true, "", errors.New("source manifest is not a regular file")
	}
	file, err := os.Open(pathOnDisk)
	if err != nil {
		return true, "", err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxSourceManifestBytes+1))
	if err != nil {
		return true, "", err
	}
	if len(raw) > maxSourceManifestBytes {
		return true, "", errors.New("source manifest is missing or too large")
	}
	if err := VerifySourceManifest(dir, raw); err != nil {
		return true, "", err
	}
	sum := sha256.Sum256(raw)
	return true, hex.EncodeToString(sum[:]), nil
}

func normalizeSourceManifestPath(name string) (string, error) {
	name = filepath.ToSlash(name)
	if name == "" || name == "." || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("invalid source manifest path %q", name)
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != name {
		return "", fmt.Errorf("invalid source manifest path %q", name)
	}
	return clean, nil
}

// VerifySourceCodeHash checks the short source hash recorded on an immutable
// workflow version. Modern build paths record the first 16 lowercase SHA-256
// characters of main.go. Empty or non-conforming values are legacy metadata
// and intentionally remain unverifiable; callers must still require a valid
// immutable artifact before reading such source.
func VerifySourceCodeHash(path, expected string) error {
	if len(expected) != 16 {
		return nil
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("source main.go is not a regular file")
	}
	if info.Size() > maxSourceManifestFileSize {
		return fmt.Errorf("source main.go exceeds %d-byte limit", maxSourceManifestFileSize)
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	main, err := io.ReadAll(io.LimitReader(file, maxSourceManifestFileSize+1))
	if err != nil {
		return err
	}
	if int64(len(main)) > maxSourceManifestFileSize {
		return fmt.Errorf("source main.go exceeds %d-byte limit", maxSourceManifestFileSize)
	}
	sum := sha256.Sum256(main)
	got := hex.EncodeToString(sum[:])[:16]
	if got != expected {
		return fmt.Errorf("source code hash mismatch")
	}
	return nil
}

// VerifyDAGSnapshot compares two JSON DAG documents by value, ignoring only
// insignificant whitespace. The version row is the durable flow record; a
// retained dag.json that differs from it must never be presented as the
// executable workflow's visual representation.
func VerifyDAGSnapshot(got, expected []byte) error {
	var gotValue, expectedValue any
	if err := json.Unmarshal(bytes.TrimSpace(got), &gotValue); err != nil {
		return fmt.Errorf("retained DAG is invalid JSON")
	}
	if err := json.Unmarshal(bytes.TrimSpace(expected), &expectedValue); err != nil {
		return fmt.Errorf("recorded DAG is invalid JSON")
	}
	if !reflect.DeepEqual(gotValue, expectedValue) {
		return fmt.Errorf("retained DAG does not match recorded workflow version")
	}
	return nil
}
