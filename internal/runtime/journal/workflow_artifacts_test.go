package journal

import (
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
