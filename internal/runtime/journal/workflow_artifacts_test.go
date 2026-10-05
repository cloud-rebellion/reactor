package journal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/registry"
)

func TestBoundedWorkflowVersionProjectionReportsOversizedDAGWithoutMaterializingIt(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	// Keep the row valid JSON while making the retained graph much larger than
	// the control-plane budget. The bounded SQL projection must preserve the
	// durable byte count and omit the blob, rather than scanning it and then
	// trimming in Go.
	largeDAG := append([]byte(`{"steps":[],"padding":"`), bytes.Repeat([]byte("x"), 70<<10)...)
	largeDAG = append(largeDAG, []byte(`"}`)...)
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_bounded_dag", "bounded-dag", "h1", "0.1.0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", largeDAG); err != nil {
		t.Fatal(err)
	}
	current, err := j.CurrentWorkflowVersionRecordBounded(ctx, "wf_bounded_dag", 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	if !current.DAGTruncated || current.DAGBytes <= 64<<10 || len(current.DAG) != 0 {
		t.Fatalf("bounded current = bytes=%d truncated=%v dag_len=%d", current.DAGBytes, current.DAGTruncated, len(current.DAG))
	}
	historical, err := j.WorkflowVersionAtBounded(ctx, "wf_bounded_dag", current.Version, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	if !historical.DAGTruncated || historical.DAGBytes != current.DAGBytes || len(historical.DAG) != 0 {
		t.Fatalf("bounded historical = bytes=%d truncated=%v dag_len=%d", historical.DAGBytes, historical.DAGTruncated, len(historical.DAG))
	}
	page, hasMore, err := j.ListWorkflowVersionsPageBounded(ctx, "wf_bounded_dag", 10, 0, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	if hasMore || len(page) != 1 || !page[0].DAGTruncated || page[0].DAGBytes != current.DAGBytes || len(page[0].DAG) != 0 {
		t.Fatalf("bounded page = len=%d more=%v row=%+v", len(page), hasMore, page)
	}
	legacyDAG, legacyBytes, legacyTruncated, err := j.WorkflowDAGBounded(ctx, "wf_bounded_dag", 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	if legacyBytes != current.DAGBytes || !legacyTruncated || len(legacyDAG) != 0 {
		t.Fatalf("bounded legacy DAG = bytes=%d truncated=%v dag_len=%d", legacyBytes, legacyTruncated, len(legacyDAG))
	}
}

func TestConcurrentWorkflowVersionRegistrationAllocatesUniqueVersions(t *testing.T) {
	ctx := context.Background()
	url := "sqlite://" + filepath.Join(t.TempDir(), "versions.db")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(ctx, log, url); err != nil {
		t.Fatal(err)
	}
	db, _, err := migrate.Open(url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j := New(db, EngineSQLite)
	first := "1111111111111111111111111111111111111111111111111111111111111111"
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_versions", "versions", "h1", "0.1.0", first, json.RawMessage(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}

	const writers = 8
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := range writers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			digest := fmt.Sprintf("%064x", i+2)
			_, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_versions", "0.1.0", fmt.Sprintf("h%d", i+2), digest, json.RawMessage(fmt.Sprintf(`{"v":%d}`, i+2)))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent version registration: %v", err)
		}
	}
	versions, err := j.ListWorkflowVersions(ctx, "wf_versions")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != writers+1 {
		t.Fatalf("version rows = %d, want %d", len(versions), writers+1)
	}
	seen := make(map[int]bool, len(versions))
	for _, version := range versions {
		if seen[version.Version] {
			t.Fatalf("duplicate allocated version %d", version.Version)
		}
		seen[version.Version] = true
	}
	for want := 1; want <= writers+1; want++ {
		if !seen[want] {
			t.Fatalf("missing allocated version %d: %+v", want, versions)
		}
	}
}

func TestValidateRunWorkflowArtifactRejectsCrossVersionDigest(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	v1 := "2222222222222222222222222222222222222222222222222222222222222222"
	if _, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_1", "0.1.0", "h2", v1, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	_, err := j.ValidateRunWorkflowArtifact(ctx, RunInfo{
		WorkflowID: "wf_1", WorkflowVersion: 2,
		WorkflowArtifactSHA256: "3333333333333333333333333333333333333333333333333333333333333333",
	})
	if err == nil || !errors.Is(err, ErrWorkflowArtifactFence) {
		t.Fatalf("cross-version digest validation = %v, want fence", err)
	}
}

func TestRollbackWorkflowVersionAppendsDisabledImmutableVersion(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	v1 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	v2 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_rollback", "rollback", "h1", "0.1.0", v1, json.RawMessage(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_rollback", "0.1.0", "h2", v2, json.RawMessage(`{"v":2}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RollbackWorkflowVersion(ctx, "wf_rollback", 1); !errors.Is(err, ErrWorkflowEnabled) {
		t.Fatalf("enabled rollback error = %v, want ErrWorkflowEnabled", err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_rollback", false); err != nil {
		t.Fatal(err)
	}
	rolled, err := j.RollbackWorkflowVersion(ctx, "wf_rollback", 1)
	if err != nil {
		t.Fatal(err)
	}
	if rolled.Version != 3 || rolled.ArtifactSHA256 != v1 || string(rolled.DAG) != `{"v":1}` {
		t.Fatalf("rollback version = %+v", rolled)
	}
	current, err := j.CurrentWorkflowVersionRecord(ctx, "wf_rollback")
	if err != nil || current.Version != 3 || current.ArtifactSHA256 != v1 {
		t.Fatalf("current after rollback = %+v, err=%v", current, err)
	}
}

func TestWorkflowVersionPinsSourceManifestAcrossReadsAndRollback(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	artifact1 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	artifact2 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	manifest1 := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	manifest2 := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_source_pin", "source-pin", "h1", "0.1.0", artifact1, json.RawMessage(`{"steps":[]}`), DefaultTenant, manifest1); err != nil {
		t.Fatal(err)
	}
	if current, err := j.CurrentWorkflowVersionRecord(ctx, "wf_source_pin"); err != nil || current.SourceManifestSHA256 != manifest1 {
		t.Fatalf("current source pin = %+v err=%v", current, err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_source_pin", "0.1.0", "h2", artifact2, json.RawMessage(`{"steps":[]}`), manifest2); err != nil {
		t.Fatal(err)
	}
	for _, read := range []struct {
		name string
		fn   func() (WorkflowVersion, error)
	}{
		{"current", func() (WorkflowVersion, error) { return j.CurrentWorkflowVersionRecord(ctx, "wf_source_pin") }},
		{"bounded", func() (WorkflowVersion, error) {
			return j.CurrentWorkflowVersionRecordBounded(ctx, "wf_source_pin", 1024)
		}},
		{"historical", func() (WorkflowVersion, error) { return j.WorkflowVersionAt(ctx, "wf_source_pin", 2) }},
		{"historical_bounded", func() (WorkflowVersion, error) { return j.WorkflowVersionAtBounded(ctx, "wf_source_pin", 2, 1024) }},
	} {
		version, err := read.fn()
		if err != nil || version.SourceManifestSHA256 != manifest2 {
			t.Fatalf("%s source pin = %+v err=%v", read.name, version, err)
		}
	}
	versions, err := j.ListWorkflowVersions(ctx, "wf_source_pin")
	if err != nil || len(versions) != 2 || versions[0].SourceManifestSHA256 != manifest2 || versions[1].SourceManifestSHA256 != manifest1 {
		t.Fatalf("listed source pins = %+v err=%v", versions, err)
	}
	page, _, err := j.ListWorkflowVersionsPageBounded(ctx, "wf_source_pin", 10, 0, 1024)
	if err != nil || len(page) != 2 || page[0].SourceManifestSHA256 != manifest2 || page[1].SourceManifestSHA256 != manifest1 {
		t.Fatalf("bounded listed source pins = %+v err=%v", page, err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_source_pin", false); err != nil {
		t.Fatal(err)
	}
	rolled, err := j.RollbackWorkflowVersion(ctx, "wf_source_pin", 1)
	if err != nil || rolled.SourceManifestSHA256 != manifest1 {
		t.Fatalf("rollback source pin = %+v err=%v", rolled, err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_source_pin", "0.1.0", "h3", artifact1, json.RawMessage(`{}`), "bad"); err == nil {
		t.Fatal("malformed source manifest pin accepted")
	}
}

func TestRollbackRetainsMigratedLegacySourceProofPolicy(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	artifact := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_legacy_policy_rollback", "legacy-policy-rollback", "h", "0.1.0", artifact, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	// Migration 0056 marks pre-existing rows as policy 1. Recreate that row
	// state here after the fresh-test schema has already been migrated.
	if _, err := j.db.ExecContext(ctx, `UPDATE workflow_versions SET source_proof_version=1
		WHERE workflow_id=? AND version=1`, "wf_legacy_policy_rollback"); err != nil {
		t.Fatal(err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_legacy_policy_rollback", false); err != nil {
		t.Fatal(err)
	}
	rolled, err := j.RollbackWorkflowVersion(ctx, "wf_legacy_policy_rollback", 1)
	if err != nil || rolled.SourceProofVersion != 1 || rolled.SourceManifestSHA256 != "" {
		t.Fatalf("rolled legacy proof policy = %+v err=%v", rolled, err)
	}
}

func TestRollbackWorkflowVersionIfCurrentRejectsStaleRevision(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	v1 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_rollback_fence", "rollback-fence", "h1", "0.1.0", v1, json.RawMessage(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_rollback_fence", "0.1.0", "h2", v1, json.RawMessage(`{"v":2}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_rollback_fence", false); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_rollback_fence", "0.1.0", "h3", v1, json.RawMessage(`{"v":3}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RollbackWorkflowVersionIfCurrent(ctx, "wf_rollback_fence", 1, 2); !errors.Is(err, ErrWorkflowVersionConflict) {
		t.Fatalf("stale rollback = %v, want ErrWorkflowVersionConflict", err)
	}
	if _, err := j.RollbackWorkflowVersionIfCurrent(ctx, "wf_rollback_fence", 1, 3); err != nil {
		t.Fatalf("current rollback: %v", err)
	}
}

func TestMCPAuthoringStagesDisabledAndRejectsActiveReplacement(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := j.CreateWorkflowInTenantWithArtifactDisabled(ctx, "wf_stage", "stage", "h1", "0.1.0", digest, json.RawMessage(`{"steps":[]}`), "acme"); err != nil {
		t.Fatal(err)
	}
	enabled, err := j.IsWorkflowEnabled(ctx, "wf_stage")
	if err != nil || enabled {
		t.Fatalf("new MCP workflow enabled=%v err=%v, want disabled", enabled, err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifactIfDisabled(ctx, "wf_stage", "0.1.0", "h2", digest, json.RawMessage(`{"steps":[]}`)); err != nil {
		t.Fatalf("disabled replacement rejected: %v", err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_stage", true); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifactIfDisabled(ctx, "wf_stage", "0.1.0", "h3", digest, json.RawMessage(`{"steps":[]}`)); !errors.Is(err, ErrWorkflowEnabled) {
		t.Fatalf("active replacement error=%v, want ErrWorkflowEnabled", err)
	}
}

func TestMCPExactArtifactRetryRequiresDisabledWorkflow(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := j.CreateWorkflowInTenantWithArtifactDisabled(ctx, "wf_retry_stage", "retry-stage", "h1", "0.1.0", digest, json.RawMessage(`{"steps":[]}`), "acme"); err != nil {
		t.Fatal(err)
	}
	activated := false
	callback := func() error { activated = true; return nil }
	if ok, err := j.ActivateWorkflowArtifactIfCurrentAndDisabled(ctx, "wf_retry_stage", 1, digest, callback); err != nil || !ok || !activated {
		t.Fatalf("disabled exact retry activation = %v, %v, callback=%v", ok, err, activated)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_retry_stage", true); err != nil {
		t.Fatal(err)
	}
	activated = false
	if ok, err := j.ActivateWorkflowArtifactIfCurrentAndDisabled(ctx, "wf_retry_stage", 1, digest, callback); !errors.Is(err, ErrWorkflowEnabled) || ok || activated {
		t.Fatalf("enabled exact retry activation = %v, %v, callback=%v; want no activation", ok, err, activated)
	}
}

func TestMCPAuthoringExpectedVersionIsAtomic(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	digest := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := j.CreateWorkflowInTenantWithArtifactDisabled(ctx, "wf_cas", "cas", "h1", "0.1.0", digest, json.RawMessage(`{"steps":[]}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifactIfDisabledExpected(ctx, "wf_cas", "0.1.0", "h2", digest, json.RawMessage(`{"steps":[]}`), 0); err == nil {
		t.Fatal("expected non-positive expected version to be rejected")
	}
	if _, err := j.RecordWorkflowVersionWithArtifactIfDisabledExpected(ctx, "wf_cas", "0.1.0", "h2", digest, json.RawMessage(`{"steps":[]}`), 2); !errors.Is(err, ErrWorkflowVersionConflict) {
		t.Fatalf("stale expected version error=%v, want ErrWorkflowVersionConflict", err)
	}
	version, err := j.RecordWorkflowVersionWithArtifactIfDisabledExpected(ctx, "wf_cas", "0.1.0", "h2", digest, json.RawMessage(`{"steps":[]}`), 1)
	if err != nil || version != 2 {
		t.Fatalf("matching expected version = %d, err=%v; want version 2", version, err)
	}
}

func TestDashboardExpectedVersionFenceWorksForEnabledWorkflow(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	digest := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_editor_cas", "editor-cas", "h1", "0.1.0", digest, json.RawMessage(`{"steps":[]}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifactExpected(ctx, "wf_editor_cas", "0.1.0", "h2", digest, json.RawMessage(`{"steps":[]}`), 2); !errors.Is(err, ErrWorkflowVersionConflict) {
		t.Fatalf("stale dashboard expected version error=%v, want ErrWorkflowVersionConflict", err)
	}
	version, err := j.RecordWorkflowVersionWithArtifactExpected(ctx, "wf_editor_cas", "0.1.0", "h2", digest, json.RawMessage(`{"steps":[]}`), 1)
	if err != nil || version != 2 {
		t.Fatalf("matching dashboard expected version = %d, err=%v; want version 2", version, err)
	}
}

func TestDelayedOlderActivationCannotRegressCompatibilityBinary(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	reg := registry.New(filepath.Join(t.TempDir(), "workflows"))
	publish := func(body string) registry.Artifact {
		t.Helper()
		source := filepath.Join(t.TempDir(), "workflow")
		if err := os.WriteFile(source, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
		artifact, err := reg.PublishArtifact("demo", source)
		if err != nil {
			t.Fatal(err)
		}
		return artifact
	}
	v2Artifact := publish("version-two")
	v3Artifact := publish("version-three")
	v2, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_1", "0.1.0", "h2", v2Artifact.Digest, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	v3, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_1", "0.1.0", "h3", v3Artifact.Digest, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}

	// Registration A has committed v2 but is paused before activation. B commits
	// and activates v3 first; A then resumes concurrently/out of order.
	type activationResult struct {
		activated   bool
		callbackRan bool
		err         error
	}
	releaseOlder := make(chan struct{})
	olderResult := make(chan activationResult, 1)
	go func() {
		<-releaseOlder
		callbackRan := false
		activated, err := j.ActivateWorkflowArtifactIfCurrent(ctx, "wf_1", v2, v2Artifact.Digest, func() error {
			callbackRan = true
			_, err := reg.ActivateArtifact("demo", v2Artifact.Digest)
			return err
		})
		olderResult <- activationResult{activated: activated, callbackRan: callbackRan, err: err}
	}()
	activated, err := j.ActivateWorkflowArtifactIfCurrent(ctx, "wf_1", v3, v3Artifact.Digest, func() error {
		_, err := reg.ActivateArtifact("demo", v3Artifact.Digest)
		return err
	})
	if err != nil || !activated {
		t.Fatalf("activate current v3 = %v, %v", activated, err)
	}
	close(releaseOlder)
	older := <-olderResult
	if older.err != nil || older.activated || older.callbackRan {
		t.Fatalf("delayed v2 activation = activated %v callback %v err %v", older.activated, older.callbackRan, older.err)
	}
	current, err := os.ReadFile(filepath.Join(reg.Root, "demo", "workflow"))
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != "version-three" {
		t.Fatalf("compatibility binary regressed to %q", current)
	}
}
