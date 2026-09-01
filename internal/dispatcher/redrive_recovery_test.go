package dispatcher

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/supervisor"
)

func distributedExactRedriveFixture(t *testing.T) (*Dispatcher, *journal.Journal, journal.DeadLetterItem) {
	t.Helper()
	ctx := context.Background()
	j := newJournal(t)
	const (
		workflowID = "wf_recover_redrive"
		runID      = "run_recover_redrive"
		slug       = "recover-redrive"
	)
	if err := j.CreateWorkflowWithArtifact(ctx, workflowID, slug, "h", "0.1.0", testArtifactSHA256, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRunPinned(ctx, runID, workflowID, "webhook", json.RawMessage(`{"customer":"original"}`), 1, testArtifactSHA256); err != nil {
		t.Fatal(err)
	}
	claim, err := j.ClaimStepAttemptSeq(ctx, runID, "send", 3, 1, "idem", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if deadLettered, err := j.FinalizeStepAttemptSeq(ctx, runID, "send", 3, claim.Attempt, nil, "permanent", false); err != nil || !deadLettered {
		t.Fatalf("seed exact redrive failure = %v, %v", deadLettered, err)
	}
	if err := j.MarkRunFinished(ctx, runID, "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	item, err := j.FindDeadLetterByRun(ctx, runID)
	if err != nil || item.StepSeq == nil || item.StepAttempt == nil {
		t.Fatalf("seed exact redrive item = %+v, %v", item, err)
	}
	d := &Dispatcher{
		Journal: j,
		Resolver: &fakeResolver{idByslug: map[string]string{
			slug: workflowID,
		}},
		Sup:     supervisor.Supervisor{Vault: noopVault{}},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Enqueue: true,
	}
	return d, j, item
}

func assertRecoveredDistributedRedrive(t *testing.T, j *journal.Journal, item journal.DeadLetterItem, owner string) {
	t.Helper()
	ctx := context.Background()
	info, err := j.GetRun(ctx, item.RunID)
	if err != nil || info.Status != "failed_dlq" || info.FinishedAt.IsZero() {
		t.Fatalf("pre-start redrive recovery = %+v, %v; want terminal failed_dlq", info, err)
	}
	state, err := j.LatestStepAttemptSeq(ctx, item.RunID, item.StepName, *item.StepSeq)
	if err != nil || state.Status != journal.StatusFailed || state.Attempt != *item.StepAttempt {
		t.Fatalf("pre-start redrive attempt recovery = %+v, %v", state, err)
	}
	if _, err := j.GetDeadLetterItem(ctx, item.ID); err != nil {
		t.Fatalf("pre-start recovery removed selected DLQ: %v", err)
	}
	if err := j.ExtendLease(ctx, item.RunID, owner, time.Minute); !errors.Is(err, journal.ErrLeaseOwnershipLost) {
		t.Fatalf("pre-start recovery left worker lease: %v", err)
	}
}

func TestDistributedRedriveArtifactFailureRestoresOperatorAuthorization(t *testing.T) {
	ctx := context.Background()
	d, j, item := distributedExactRedriveFixture(t)
	failWorkerLookup := false
	d.ArtifactPath = func(_, _ string) (string, error) {
		if failWorkerLookup {
			return "", errors.New("artifact disappeared after queue authorization")
		}
		return "/nonexistent/recover-redrive", nil
	}
	var terminal TerminalEvent
	deadLetterHook := 0
	d.OnTerminal = func(_ context.Context, event TerminalEvent) { terminal = event }
	d.OnDeadLetter = func(_ context.Context, _ string) { deadLetterHook++ }

	status, err := d.RetryDeadLetter(ctx, item.ID)
	if err != nil || status != "queued" {
		t.Fatalf("queue exact redrive = %q, %v", status, err)
	}
	leases, err := j.ClaimQueuedRuns(ctx, "worker-artifact", 1, time.Minute)
	if err != nil || len(leases) != 1 {
		t.Fatalf("claim exact redrive = %+v, %v", leases, err)
	}
	failWorkerLookup = true
	if err := d.ExecuteRun(ctx, item.RunID, leases[0].Owner); err == nil || errors.Is(err, journal.ErrWorkflowArtifactFence) {
		t.Fatalf("artifact availability failure = %v; want recoverable availability error", err)
	}
	info, err := j.GetRun(ctx, item.RunID)
	if err != nil || info.Status != "running" || !info.FinishedAt.IsZero() {
		t.Fatalf("artifact availability terminalized redrive = %+v, %v", info, err)
	}
	state, err := j.LatestStepAttemptSeq(ctx, item.RunID, item.StepName, *item.StepSeq)
	if err != nil || state.Status != journal.StatusRedrive || state.Attempt != *item.StepAttempt {
		t.Fatalf("artifact availability lost exact redrive authorization = %+v, %v", state, err)
	}
	if terminal.Status != "" || deadLetterHook != 0 {
		t.Fatalf("availability failure published terminal lifecycle = status %q dead-letter hooks %d", terminal.Status, deadLetterHook)
	}
	if err := j.ExtendLease(ctx, item.RunID, leases[0].Owner, -time.Minute); err != nil {
		t.Fatalf("availability failure lost exact worker lease: %v", err)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("availability redrive reap = %d, %v", n, err)
	}
	if info, err := j.GetRun(ctx, item.RunID); err != nil || info.Status != "queued" {
		t.Fatalf("availability redrive was not recoverably queued = %+v, %v", info, err)
	}
	replacement, err := j.ClaimQueuedRuns(ctx, "healthy-worker", 1, time.Minute)
	if err != nil || len(replacement) != 1 || replacement[0].RunID != item.RunID {
		t.Fatalf("availability redrive replacement claim = %+v, %v", replacement, err)
	}
}

func TestDistributedRedriveStartFailureRestoresOperatorAuthorization(t *testing.T) {
	ctx := context.Background()
	d, j, item := distributedExactRedriveFixture(t)
	d.ArtifactPath = func(_, _ string) (string, error) {
		return "/nonexistent/recover-redrive", nil
	}
	var terminal TerminalEvent
	d.OnTerminal = func(_ context.Context, event TerminalEvent) { terminal = event }

	status, err := d.RetryDeadLetter(ctx, item.ID)
	if err != nil || status != "queued" {
		t.Fatalf("queue exact redrive = %q, %v", status, err)
	}
	leases, err := j.ClaimQueuedRuns(ctx, "worker-start", 1, time.Minute)
	if err != nil || len(leases) != 1 {
		t.Fatalf("claim exact redrive = %+v, %v", leases, err)
	}
	err = d.ExecuteRun(ctx, item.RunID, leases[0].Owner)
	if err == nil || !strings.Contains(err.Error(), "supervisor: start") {
		t.Fatalf("child start failure = %v", err)
	}
	assertRecoveredDistributedRedrive(t, j, item, leases[0].Owner)
	if terminal.Status != "failed_dlq" {
		t.Fatalf("start recovery terminal hook status = %q, want failed_dlq", terminal.Status)
	}

	status, err = d.RetryDeadLetter(ctx, item.ID)
	if err != nil || status != "queued" {
		t.Fatalf("requeue after start recovery = %q, %v", status, err)
	}
}
