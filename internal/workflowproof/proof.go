// Package workflowproof contains the execution-boundary checks that connect
// an immutable workflow artifact to the source and visual DAG it was built
// from. Authoring and review can expose legacy metadata, but an executable
// workflow must pass this proof before it is enabled or dispatched.
package workflowproof

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bright-interaction/reactor/internal/codegen"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

const (
	maxReasonBytes             = 4 << 10
	maxProofDAGBytes           = 1 << 20
	missingExecutableDAGReason = "workflow visual DAG has no executable nodes; rebuild with at least one durable Step, SideEffect, Sleep, or AwaitSignal node"
)

// Result is the bounded, operator-facing outcome of a retained source check.
// Status is one of: verified, visual_unverified, legacy_manifest_unpinned,
// compiled_files_unverified, unavailable, legacy_unverified, or mismatch.
// A v2 pinned manifest without compiled-file selection cannot prove that its
// declared durable nodes entered the root executable and is not dispatchable.
type Result struct {
	Status string
	Reason string
}

// Executable reports whether this proof passes the current execution policy.
// Legacy-compatible results remain distinguishable from fully verified proof
// in operator receipts even though they may be dispatched.
func (r Result) Executable() bool { return executionProofPassed(r.Status) }

func (r Result) Error() string {
	if r.Reason == "" {
		return "workflow source proof " + r.Status
	}
	return "workflow source proof " + r.Status + ": " + r.Reason
}

// Check validates the source snapshot associated with one immutable artifact.
// It deliberately uses the recorded version DAG rather than trusting a
// mutable compatibility file or a client-supplied visual projection.
func Check(stateRoot, slug, artifactSHA256, codeHash string, dag []byte, sourceManifestSHA256 ...string) Result {
	return check(stateRoot, slug, "", artifactSHA256, codeHash, dag, sourceManifestSHA256, legacyOrPinnedPolicy(sourceManifestSHA256))
}

// CheckForTenant validates source proof only when the immutable artifact
// namespace belongs to tenant. The journal permits duplicate slugs across
// tenants while the node-local registry has one slug directory, so an
// unscoped ArtifactPath lookup can otherwise make a foreign artifact look
// reviewable. Production control-plane callers should use this variant.
func CheckForTenant(stateRoot, slug, tenant, artifactSHA256, codeHash string, dag []byte, sourceManifestSHA256 ...string) Result {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return Result{Status: "unavailable", Reason: "workflow tenant is unavailable"}
	}
	return check(stateRoot, slug, tenant, artifactSHA256, codeHash, dag, sourceManifestSHA256, legacyOrPinnedPolicy(sourceManifestSHA256))
}

// CheckVersionForTenant is the production read surface. The persisted policy
// cannot be inferred from a local manifest or a digest-shaped value: migration
// 0056 marks pre-existing rows as 1 and all new rows default to 2.
func CheckVersionForTenant(stateRoot, slug, tenant string, version journal.WorkflowVersion) Result {
	if strings.TrimSpace(tenant) == "" {
		return Result{Status: "unavailable", Reason: "workflow tenant is unavailable"}
	}
	return check(stateRoot, slug, tenant, version.ArtifactSHA256, version.CodeHash, version.DAG, []string{version.SourceManifestSHA256}, version.SourceProofVersion)
}

func legacyOrPinnedPolicy(sourceManifestSHA256 []string) int {
	if len(sourceManifestSHA256) == 1 && sourceManifestSHA256[0] != "" {
		return 2
	}
	return 1
}

func check(stateRoot, slug, tenant, artifactSHA256, codeHash string, dag []byte, sourceManifestSHA256 []string, proofVersion int) Result {
	if proofVersion != 1 && proofVersion != 2 {
		return Result{Status: "mismatch", Reason: "workflow source proof policy is invalid"}
	}
	if len(sourceManifestSHA256) > 1 {
		return Result{Status: "mismatch", Reason: "workflow source manifest pin is ambiguous"}
	}
	pinnedManifest := ""
	if len(sourceManifestSHA256) == 1 {
		pinnedManifest = sourceManifestSHA256[0]
	}
	if proofVersion == 2 && pinnedManifest == "" {
		return Result{Status: "mismatch", Reason: "new workflow version has no pinned source manifest"}
	}
	if proofVersion == 1 && pinnedManifest != "" {
		return Result{Status: "mismatch", Reason: "legacy workflow source proof policy conflicts with manifest pin"}
	}
	if pinnedManifest != "" {
		if len(pinnedManifest) != 64 {
			return Result{Status: "mismatch", Reason: "workflow source manifest pin is invalid"}
		}
		if _, err := hex.DecodeString(pinnedManifest); err != nil || strings.ToLower(pinnedManifest) != pinnedManifest {
			return Result{Status: "mismatch", Reason: "workflow source manifest pin is invalid"}
		}
	}
	if strings.TrimSpace(artifactSHA256) == "" {
		return Result{Status: "unavailable", Reason: "immutable artifact is not pinned"}
	}
	if strings.TrimSpace(stateRoot) == "" {
		return Result{Status: "unavailable", Reason: "state root is not configured"}
	}
	reg := registry.New(filepath.Join(stateRoot, "workflows"))
	var artifactPath string
	var err error
	if tenant == "" {
		artifactPath, err = reg.ArtifactPath(slug, artifactSHA256)
	} else {
		artifactPath, err = reg.ArtifactPathForTenant(slug, artifactSHA256, tenant)
	}
	if err != nil {
		return Result{Status: "unavailable", Reason: "immutable artifact is unavailable"}
	}
	// Dispatch, resume, and dashboard lifecycle enablement call this proof
	// directly. Require an actual, bounded visual graph here so a legacy or
	// direct journal row with a valid source manifest but no durable nodes
	// cannot become a successful-looking, visually invisible run.
	if len(dag) > maxProofDAGBytes {
		return Result{Status: "mismatch", Reason: "workflow visual DAG exceeds the bounded proof limit"}
	}
	trimmedDAG := bytes.TrimSpace(dag)
	if len(trimmedDAG) == 0 || bytes.Equal(trimmedDAG, []byte(`{}`)) {
		return Result{Status: "mismatch", Reason: missingExecutableDAGReason}
	}
	if err := registry.ValidateDAG(dag); err != nil {
		return Result{Status: "mismatch", Reason: boundReason(err.Error())}
	}
	var shape struct {
		Steps []json.RawMessage `json:"steps"`
		Nodes []json.RawMessage `json:"nodes"`
	}
	if err := json.Unmarshal(dag, &shape); err != nil {
		return Result{Status: "mismatch", Reason: "workflow visual DAG cannot be decoded"}
	}
	if len(shape.Steps) == 0 && len(shape.Nodes) == 0 {
		return Result{Status: "mismatch", Reason: missingExecutableDAGReason}
	}
	sourceDir := filepath.Join(filepath.Dir(artifactPath), "source")
	info, err := os.Lstat(sourceDir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return Result{Status: "unavailable", Reason: "retained workflow source is unavailable"}
	}
	manifestPresent, manifestDigest, err := registry.VerifySourceManifestDigestIfPresent(sourceDir)
	if err != nil {
		return Result{Status: "mismatch", Reason: "retained workflow source manifest does not match"}
	}
	if pinnedManifest != "" {
		if !manifestPresent {
			return Result{Status: "unavailable", Reason: "pinned workflow source manifest is unavailable"}
		}
		if manifestDigest != pinnedManifest {
			return Result{Status: "mismatch", Reason: "retained workflow source manifest differs from immutable version pin"}
		}
	}
	if len(codeHash) != 16 {
		return Result{Status: "legacy_unverified", Reason: "workflow source code hash is unavailable"}
	}
	if _, err := hex.DecodeString(codeHash); err != nil {
		return Result{Status: "legacy_unverified", Reason: "workflow source code hash is unavailable"}
	}
	if err := registry.VerifySourceCodeHash(filepath.Join(sourceDir, "main.go"), codeHash); err != nil {
		return Result{Status: "mismatch", Reason: "retained workflow source code does not match the immutable version"}
	}
	retainedDAGPath := filepath.Join(sourceDir, "dag.json")
	if file, openErr := os.Open(retainedDAGPath); openErr == nil {
		retainedDAG, readErr := io.ReadAll(io.LimitReader(file, maxProofDAGBytes+1))
		_ = file.Close()
		if readErr != nil {
			return Result{Status: "unavailable", Reason: "retained workflow DAG is unavailable"}
		}
		if len(retainedDAG) > maxProofDAGBytes {
			return Result{Status: "mismatch", Reason: "retained workflow DAG exceeds the bounded proof limit"}
		}
		if err := registry.VerifyDAGSnapshot(retainedDAG, dag); err != nil {
			return Result{Status: "mismatch", Reason: err.Error()}
		}
	} else if !os.IsNotExist(openErr) {
		return Result{Status: "unavailable", Reason: "retained workflow DAG is unavailable"}
	}
	selectedGoFiles := []string(nil)
	selectionPinned := false
	if manifestPresent {
		selectedGoFiles, selectionPinned, err = registry.SourceManifestCompiledGoFiles(sourceDir)
		if err != nil {
			return Result{Status: "mismatch", Reason: "retained workflow source selection is unavailable"}
		}
	}
	var sourceDAGErr error
	if selectionPinned {
		sourceDAGErr = codegen.ValidateSourceDAGFiles(sourceDir, dag, selectedGoFiles)
	} else {
		// Old manifests have no record of which Go files entered the root
		// executable. Their recursive check can still detect obvious source
		// drift, but it cannot certify visual equivalence to the binary.
		sourceDAGErr = codegen.ValidateSourceDAGDir(sourceDir, dag)
	}
	if err := sourceDAGErr; err != nil {
		var visualMismatch *codegen.VisualSourceMismatch
		if manifestPresent && proofVersion == 1 && errors.As(err, &visualMismatch) {
			return Result{Status: "visual_unverified", Reason: boundReason(err.Error())}
		}
		return Result{Status: "mismatch", Reason: boundReason(err.Error())}
	}
	if !manifestPresent {
		return Result{Status: "legacy_unverified", Reason: "retained workflow source manifest is unavailable"}
	}
	if proofVersion == 1 {
		return Result{Status: "legacy_manifest_unpinned", Reason: "retained source manifest predates immutable version pinning; rebuild for verified visual proof"}
	}
	if !selectionPinned {
		return Result{Status: "compiled_files_unverified", Reason: "retained source manifest has no compiled workflow Go file selection; rebuild before enabling or dispatch"}
	}
	return Result{Status: "verified"}
}

func boundReason(reason string) string {
	if len(reason) <= maxReasonBytes {
		return reason
	}
	return reason[:maxReasonBytes] + "..."
}

// Validate is the execution-boundary form of Check. It returns an error for
// every result except verified or an intact legacy artifact with only an
// unverified visual-block annotation. The latter does not certify the visual
// graph and must not pass activation/review gates.
func Validate(stateRoot, slug, artifactSHA256, codeHash string, dag []byte) error {
	result := Check(stateRoot, slug, artifactSHA256, codeHash, dag)
	if !executionProofPassed(result.Status) {
		return result
	}
	return nil
}

// ValidateForTenant is the tenant-scoped execution-boundary form of Check.
// Empty or malformed tenant identity fails closed through the registry owner
// manifest check rather than falling back to the legacy unscoped lookup.
func ValidateForTenant(stateRoot, slug, tenant, artifactSHA256, codeHash string, dag []byte) error {
	result := CheckForTenant(stateRoot, slug, tenant, artifactSHA256, codeHash, dag)
	if !executionProofPassed(result.Status) {
		return result
	}
	return nil
}

// ValidateVersion is the adapter used at dispatch and dashboard lifecycle
// boundaries. Keeping the version record as one value makes it harder for a
// caller to validate a digest from one version with source metadata from
// another.
func ValidateVersion(stateRoot, slug string, version journal.WorkflowVersion) error {
	result := check(stateRoot, slug, "", version.ArtifactSHA256, version.CodeHash, version.DAG, []string{version.SourceManifestSHA256}, version.SourceProofVersion)
	return validateVersionResult(result, version)
}

// ValidateVersionForTenant applies the immutable namespace owner fence before
// checking retained source and DAG proof. It preserves the typed mismatch
// error used by dispatcher/scheduler admission while treating owner, source,
// and artifact availability failures as non-executable.
func ValidateVersionForTenant(stateRoot, slug, tenant string, version journal.WorkflowVersion) error {
	result := CheckVersionForTenant(stateRoot, slug, tenant, version)
	return validateVersionResult(result, version)
}

func validateVersionResult(result Result, version journal.WorkflowVersion) error {
	if result.Status == "mismatch" {
		return &journal.WorkflowArtifactFenceError{
			WorkflowID: version.WorkflowID, Version: version.Version,
			PinnedDigest: version.ArtifactSHA256, Reason: result.Reason,
		}
	}
	if !executionProofPassed(result.Status) {
		return result
	}
	return nil
}

func executionProofPassed(status string) bool {
	return status == "verified" || status == "visual_unverified" || status == "legacy_manifest_unpinned"
}
