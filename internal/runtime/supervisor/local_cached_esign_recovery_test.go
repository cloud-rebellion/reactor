package supervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestLocalStartupRecoveryReplaysCommittedESignSideEffectsWithoutClosureCalls(t *testing.T) {
	binary := buildTestWorkflow(t)
	recordPath := filepath.Join(t.TempDir(), "calls.txt")
	if err := os.WriteFile(recordPath, nil, 0o600); err != nil {
		t.Fatalf("create empty closure record: %v", err)
	}

	const runID = "run_local_cached_esign_recovery"
	sup, j, closeDB := newTestSupervisorEnv(t, runID)
	defer closeDB()
	sup.BinaryPath = binary
	sup.ExtraEnv = ffTestEnv("FF_TEST_RECORD", recordPath)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Match the test workflow's real Step options: IdempotencyKey "k", no
	// timeout, and no retry policy. Ordinal replay is authoritative, but using
	// the genuine hash keeps this fixture representative of committed wire data.
	inputFingerprint := sha256.Sum256([]byte("k|0|0"))
	inputHash := hex.EncodeToString(inputFingerprint[:8])
	committed := []struct {
		name   string
		seq    int64
		output json.RawMessage
	}{
		{name: "fetch", seq: 1, output: json.RawMessage(`"fetched-customer"`)},
		{name: "send", seq: 2, output: json.RawMessage(`"sent"`)},
	}
	for _, step := range committed {
		inserted, err := j.RecordStepStartSeq(ctx, runID, step.name, step.seq, 1, "k", inputHash)
		if err != nil || !inserted {
			t.Fatalf("seed %s StepStart = %v, %v", step.name, inserted, err)
		}
		if err := j.RecordStepEndSeq(ctx, runID, step.name, step.seq, 1, step.output, ""); err != nil {
			t.Fatalf("seed %s StepEnd: %v", step.name, err)
		}
	}
	verifyRecord(t, recordPath, nil)
	if run, err := j.GetRun(ctx, runID); err != nil || run.Status != "running" || !run.FinishedAt.IsZero() {
		t.Fatalf("pre-recovery run = %+v, %v; want unfinished running", run, err)
	}

	classified, err := j.ReapOrphanedRuns(ctx)
	if err != nil || classified != 1 {
		t.Fatalf("startup recovery classification = %d, %v", classified, err)
	}
	if run, err := j.GetRun(ctx, runID); err != nil || run.Status != "suspended" || !run.FinishedAt.IsZero() {
		t.Fatalf("classified run = %+v, %v; want suspended continuation", run, err)
	}

	advanced := time.Now().Add(time.Minute)
	due, err := j.FindDueSchedules(ctx, advanced, 10)
	if err != nil || len(due) != 1 || due[0].RunID != runID || due[0].Kind != journal.KindRecovery || due[0].Fired {
		t.Fatalf("startup recovery schedule = %+v, %v", due, err)
	}
	recoveryScheduleID := due[0].ID

	artifactLookups := 0
	var artifactSlug, artifactDigest string
	var terminal TerminalInfo
	sched := &Scheduler{
		Journal: j,
		Vault:   sup.Vault,
		Log:     sup.Log,
		Now:     func() time.Time { return advanced },
		ArtifactPath: func(slug, digest string) (string, error) {
			artifactLookups++
			artifactSlug = slug
			artifactDigest = digest
			return binary, nil
		},
		SupervisorTemplate: *sup,
		Batch:              10,
		OnTerminal: func(_ context.Context, event TerminalInfo) {
			terminal = event
		},
	}
	if err := sched.Tick(ctx); err != nil {
		t.Fatalf("scheduler recovery tick: %v", err)
	}

	if artifactLookups != 1 || artifactSlug != "test-replay" || artifactDigest != supervisorTestArtifactSHA256 {
		t.Fatalf("immutable artifact resolution = calls %d slug %q digest %q", artifactLookups, artifactSlug, artifactDigest)
	}
	if terminal.RunID != runID || terminal.Status != "succeeded" {
		t.Fatalf("recovery terminal event = %+v", terminal)
	}
	run, err := j.GetRun(ctx, runID)
	if err != nil || run.ID != runID || run.Status != "succeeded" || run.FinishedAt.IsZero() {
		t.Fatalf("recovered same run = %+v, %v", run, err)
	}
	verifyRecord(t, recordPath, nil)

	remaining, err := j.FindDueSchedules(ctx, advanced.Add(time.Hour), 10)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("consumed recovery schedule still due = %+v, %v", remaining, err)
	}
	if claimed, err := j.ClaimSchedule(ctx, recoveryScheduleID); err != nil || claimed {
		t.Fatalf("consumed recovery schedule reclaim = %v, %v", claimed, err)
	}
	for _, step := range committed {
		out, recordedName, err := j.FindCachedOutputBySeq(ctx, runID, step.seq)
		if err != nil || recordedName != step.name || string(out) != string(step.output) {
			t.Fatalf("cached %s replay = %s/%q, %v", step.name, out, recordedName, err)
		}
		attempts, err := j.AttemptCountSeq(ctx, runID, step.name, step.seq)
		if err != nil || attempts != 1 {
			t.Fatalf("%s replay attempts = %d, %v; want one seeded attempt", step.name, attempts, err)
		}
	}
}
