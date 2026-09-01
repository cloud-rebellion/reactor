package dispatcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/supervisor"
)

func TestDistributedDeadLetterRedriveSucceedsThroughLeasedWorkerAndClearsAllDLQ(t *testing.T) {
	ctx := context.Background()
	j := newJournal(t)
	const (
		workflowID = "wf_redrive"
		runID      = "run_redrive"
		slug       = "test-replay"
	)
	if err := j.CreateWorkflowWithArtifact(ctx, workflowID, slug, "h", "0.1.0", testArtifactSHA256, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRunPinned(ctx, runID, workflowID, "webhook", json.RawMessage(`{}`), 1, testArtifactSHA256); err != nil {
		t.Fatal(err)
	}
	// Keep one historical item plus the exact current send failure. Success must
	// clear both, not merely the selected row.
	if err := j.MoveStepToDeadLetter(ctx, runID, "old-step", "old failure", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	inputHashBytes := sha256.Sum256([]byte("k|0|0"))
	inputHash := hex.EncodeToString(inputHashBytes[:8])
	claim, err := j.ClaimStepAttemptSeq(ctx, runID, "send", 2, 1, "k", inputHash)
	if err != nil {
		t.Fatal(err)
	}
	if deadLettered, err := j.FinalizeStepAttemptSeq(ctx, runID, "send", 2, claim.Attempt, nil, "current failure", false); err != nil || !deadLettered {
		t.Fatalf("seed exact failure = %v, %v", deadLettered, err)
	}
	if err := j.MarkRunFinished(ctx, runID, "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	current, err := j.FindDeadLetterByRun(ctx, runID)
	if err != nil || current.StepAttempt == nil {
		t.Fatalf("current exact DLQ = %+v, %v", current, err)
	}

	binary := filepath.Join(t.TempDir(), "testworkflow")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", binary,
		"github.com/bright-interaction/reactor/internal/runtime/supervisor/testworkflow")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build test workflow: %v\n%s", err, output)
	}
	d := &Dispatcher{
		Journal: j,
		Resolver: &fakeResolver{idByslug: map[string]string{
			slug: workflowID,
		}},
		ArtifactPath: func(gotSlug, gotSHA string) (string, error) {
			if gotSlug != slug || gotSHA != testArtifactSHA256 {
				t.Fatalf("artifact lookup = %q/%q", gotSlug, gotSHA)
			}
			return binary, nil
		},
		Sup: supervisor.Supervisor{
			Vault:         noopVault{},
			ACLPermissive: true,
		},
		Enqueue: true,
	}

	status, err := d.RetryDeadLetter(ctx, current.ID)
	if err != nil || status != "queued" {
		t.Fatalf("distributed retry authorization = %q, %v", status, err)
	}
	if run, err := j.GetRun(ctx, runID); err != nil || run.Status != "queued" || !run.FinishedAt.IsZero() {
		t.Fatalf("queued redrive state = %+v, %v", run, err)
	}
	leases, err := j.ClaimQueuedRuns(ctx, "worker-redrive", 1, time.Minute)
	if err != nil || len(leases) != 1 || leases[0].RunID != runID {
		t.Fatalf("worker claim = %+v, %v", leases, err)
	}
	if err := d.ExecuteRun(ctx, runID, leases[0].Owner); err != nil {
		t.Fatalf("leased redrive execution: %v", err)
	}
	if run, err := j.GetRun(ctx, runID); err != nil || run.Status != "succeeded" || run.FinishedAt.IsZero() {
		t.Fatalf("redrive terminal state = %+v, %v", run, err)
	}
	if items, err := j.ListDeadLetterItems(ctx, 10, 0); err != nil || len(items) != 0 {
		t.Fatalf("successful distributed redrive left DLQ items = %+v, %v", items, err)
	}
	if err := j.ExtendLease(ctx, runID, leases[0].Owner, time.Minute); !errors.Is(err, journal.ErrLeaseOwnershipLost) {
		t.Fatalf("successful distributed redrive left lease: %v", err)
	}
}
