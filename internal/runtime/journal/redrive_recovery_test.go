package journal

import (
	"context"
	"errors"
	"testing"
	"time"
)

func seedExactRedriveForRecovery(t *testing.T, j *Journal) (DeadLetterItem, StepAttemptClaim) {
	t.Helper()
	ctx := context.Background()
	claim, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 7, 1, "idem", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if deadLettered, err := j.FinalizeStepAttemptSeq(ctx, "run_1", "send", 7, claim.Attempt, nil, "permanent", false); err != nil || !deadLettered {
		t.Fatalf("seed terminal attempt = %v, %v", deadLettered, err)
	}
	if err := j.MarkRunFinished(ctx, "run_1", "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	item, err := j.FindDeadLetterByRun(ctx, "run_1")
	if err != nil || item.StepSeq == nil || item.StepAttempt == nil {
		t.Fatalf("seed exact dead letter = %+v, %v", item, err)
	}
	return item, claim
}

func TestRecoverOwnedPendingDeadLetterRedriveRestoresExactAuthorization(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	item, claim := seedExactRedriveForRecovery(t, j)

	claimed, err := j.StartDeadLetterRetryQueuedItem(ctx, "run_1", item.ID)
	if err != nil || !claimed {
		t.Fatalf("queue exact redrive = %v, %v", claimed, err)
	}
	leases, err := j.ClaimQueuedRuns(ctx, "worker-a", 1, time.Minute)
	if err != nil || len(leases) != 1 {
		t.Fatalf("claim exact redrive = %+v, %v", leases, err)
	}
	recovered, err := j.RecoverOwnedPendingDeadLetterRedrive(ctx, "run_1", leases[0].Owner)
	if err != nil || !recovered {
		t.Fatalf("recover unused exact redrive = %v, %v", recovered, err)
	}
	info, err := j.GetRun(ctx, "run_1")
	if err != nil || info.Status != "failed_dlq" || info.FinishedAt.IsZero() {
		t.Fatalf("recovered redrive run = %+v, %v; want terminal failed_dlq", info, err)
	}
	state, err := j.LatestStepAttemptSeq(ctx, "run_1", "send", 7)
	if err != nil || state.Status != StatusFailed || state.Attempt != claim.Attempt {
		t.Fatalf("restored exact attempt = %+v, %v", state, err)
	}
	if _, err := j.GetDeadLetterItem(ctx, item.ID); err != nil {
		t.Fatalf("recovery removed operator item: %v", err)
	}
	if err := j.ExtendLease(ctx, "run_1", leases[0].Owner, time.Minute); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("recovery left owned lease: %v", err)
	}
	effects, err := j.ClaimTerminalEffects(ctx, 10, time.Minute)
	if err != nil || len(effects) != 1 || effects[0].RunID != "run_1" || effects[0].Status != "failed_dlq" {
		t.Fatalf("recovered redrive terminal effect = %+v, %v; want failed_dlq receipt", effects, err)
	}

	// The same exact item is operator-visible and can authorize a fresh attempt
	// again; no manual database repair is needed after the launch failure.
	claimed, err = j.StartDeadLetterRetryQueuedItem(ctx, "run_1", item.ID)
	if err != nil || !claimed {
		t.Fatalf("re-authorize recovered exact redrive = %v, %v", claimed, err)
	}
}

func TestLocalInterruptedFailureEnqueuesTerminalEffect(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	status, err := j.RecoverLocalInterruptedRun(ctx, "run_1", false)
	if err != nil || status != "failed" {
		t.Fatalf("local interrupted recovery = %q, %v; want failed", status, err)
	}
	effects, err := j.ClaimTerminalEffects(ctx, 10, time.Minute)
	if err != nil || len(effects) != 1 || effects[0].RunID != "run_1" || effects[0].Status != "failed" {
		t.Fatalf("local interrupted terminal effect = %+v, %v; want failed receipt", effects, err)
	}
}

func TestRecoverOwnedPendingDeadLetterRedriveRefusesAfterStepStart(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	item, first := seedExactRedriveForRecovery(t, j)

	if claimed, err := j.StartDeadLetterRetryQueuedItem(ctx, "run_1", item.ID); err != nil || !claimed {
		t.Fatalf("queue exact redrive = %v, %v", claimed, err)
	}
	leases, err := j.ClaimQueuedRuns(ctx, "worker-a", 1, time.Minute)
	if err != nil || len(leases) != 1 {
		t.Fatalf("claim exact redrive = %+v, %v", leases, err)
	}
	next, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 7, 1, "idem", "hash")
	if err != nil || next.Exhausted || next.Attempt != first.Attempt+1 || next.BudgetAttempt != 1 {
		t.Fatalf("first attempt in redrive generation = %+v, %v", next, err)
	}

	recovered, err := j.RecoverOwnedPendingDeadLetterRedrive(ctx, "run_1", leases[0].Owner)
	if err != nil || recovered {
		t.Fatalf("recovery after StepStart = %v, %v; want refused", recovered, err)
	}
	info, err := j.GetRun(ctx, "run_1")
	if err != nil || info.Status != "running" || !info.FinishedAt.IsZero() {
		t.Fatalf("refused recovery mutated run = %+v, %v", info, err)
	}
	state, err := j.LatestStepAttemptSeq(ctx, "run_1", "send", 7)
	if err != nil || state.Status != StatusRunning || state.Attempt != next.Attempt {
		t.Fatalf("refused recovery mutated new attempt = %+v, %v", state, err)
	}
	if err := j.ExtendLease(ctx, "run_1", leases[0].Owner, time.Minute); err != nil {
		t.Fatalf("refused recovery released live lease: %v", err)
	}
}

func TestLocalStartupRestoresUnusedExactRedriveWithoutScheduling(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	item, claim := seedExactRedriveForRecovery(t, j)
	if started, err := j.StartDeadLetterRetryItem(ctx, "run_1", item.ID); err != nil || !started {
		t.Fatalf("authorize local redrive = %v, %v", started, err)
	}

	classified, err := j.ReapOrphanedRuns(ctx)
	if err != nil || classified != 1 {
		t.Fatalf("startup redrive classification = %d, %v", classified, err)
	}
	if run, err := j.GetRun(ctx, "run_1"); err != nil || run.Status != "failed_dlq" || run.FinishedAt.IsZero() {
		t.Fatalf("startup redrive state = %+v, %v", run, err)
	}
	state, err := j.LatestStepAttemptSeq(ctx, "run_1", "send", 7)
	if err != nil || state.Status != StatusFailed || state.Attempt != claim.Attempt {
		t.Fatalf("startup redrive attempt = %+v, %v", state, err)
	}
	if due, err := j.FindDueSchedules(ctx, time.Now().Add(time.Hour), 10); err != nil || len(due) != 0 {
		t.Fatalf("unused redrive unexpectedly scheduled = %+v, %v", due, err)
	}
}

func TestLocalPendingDeadLetterRepairSurvivesStartupWithoutClosureReset(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	claim, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 9, 1, "idem", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndWithRetrySeq(ctx, "run_1", "send", 9, claim.Attempt, nil, "permanent", false); err != nil {
		t.Fatal(err)
	}
	const reject = `CREATE TRIGGER reject_local_recovery_dlq
		BEFORE INSERT ON dead_letter
		BEGIN SELECT RAISE(ABORT, 'forced local dlq failure'); END`
	if _, err := j.db.ExecContext(ctx, reject); err != nil {
		t.Fatal(err)
	}
	if _, err := j.EnsureStepAttemptDeadLetter(ctx, "run_1", "send", 9, claim.Attempt, "permanent", nil); err == nil {
		t.Fatal("forced local DLQ repair unexpectedly succeeded")
	}
	if _, err := j.db.ExecContext(ctx, `DROP TRIGGER reject_local_recovery_dlq`); err != nil {
		t.Fatal(err)
	}

	if classified, err := j.ReapOrphanedRuns(ctx); err != nil || classified != 1 {
		t.Fatalf("startup pending-repair classification = %d, %v", classified, err)
	}
	if run, err := j.GetRun(ctx, "run_1"); err != nil || run.Status != "suspended" {
		t.Fatalf("pending repair startup state = %+v, %v", run, err)
	}
	due, err := j.FindDueSchedules(ctx, time.Now().Add(time.Minute), 10)
	if err != nil || len(due) != 1 || due[0].Kind != KindRecovery {
		t.Fatalf("pending repair recovery schedule = %+v, %v", due, err)
	}
	if resumed, err := j.ClaimScheduleResume(ctx, due[0].ID, false); err != nil || !resumed {
		t.Fatalf("claim pending repair recovery = %v, %v", resumed, err)
	}
	blocked, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 9, 1, "idem", "hash")
	if err != nil || !blocked.Exhausted || blocked.Previous == nil || blocked.Previous.Status != StatusDLQPending {
		t.Fatalf("pending repair closure fence = %+v, %v", blocked, err)
	}
	if created, err := j.EnsureStepAttemptDeadLetter(ctx, "run_1", "send", 9, claim.Attempt, "permanent", nil); err != nil || !created {
		t.Fatalf("startup pending repair completion = %v, %v", created, err)
	}
	if count, err := j.AttemptCountSeq(ctx, "run_1", "send", 9); err != nil || count != 1 {
		t.Fatalf("pending repair reset closure budget = %d, %v", count, err)
	}
}

func TestLocalStartupSchedulesRunAfterCommittedStepEnd(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := j.RecordStepStartSeq(ctx, "run_1", "hash-send", 1, 1, "idem", "hash"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndSeq(ctx, "run_1", "hash-send", 1, 1, []byte(`{"document_id":"doc_1"}`), ""); err != nil {
		t.Fatal(err)
	}

	if classified, err := j.ReapOrphanedRuns(ctx); err != nil || classified != 1 {
		t.Fatalf("startup committed-step classification = %d, %v", classified, err)
	}
	if run, err := j.GetRun(ctx, "run_1"); err != nil || run.Status != "suspended" {
		t.Fatalf("committed-step startup state = %+v, %v", run, err)
	}
	due, err := j.FindDueSchedules(ctx, time.Now().Add(time.Minute), 10)
	if err != nil || len(due) != 1 || due[0].Kind != KindRecovery {
		t.Fatalf("committed-step recovery schedule = %+v, %v", due, err)
	}
	if cached, recorded, err := j.FindCachedOutputBySeq(ctx, "run_1", 1); err != nil || recorded != "hash-send" || string(cached) != `{"document_id":"doc_1"}` {
		t.Fatalf("committed Hash result is not replayable = %s/%q, %v", cached, recorded, err)
	}
}
