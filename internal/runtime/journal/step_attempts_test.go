package journal

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestClaimStepAttemptSeqCrashConsumesBudgetAndScopesOrdinal(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	first, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 7, 3, "idem", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if first.Attempt != 1 || first.Exhausted || first.Previous != nil {
		t.Fatalf("first claim = %+v, want attempt 1", first)
	}

	// No step_end: a worker died after the durable start. That start consumes
	// attempt 1, so the restarted worker receives attempt 2 rather than
	// overwriting the existing row.
	second, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 7, 3, "idem", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if second.Attempt != 2 || second.Exhausted || second.Previous == nil || second.Previous.Attempt != 1 || second.Previous.Status != StatusRunning {
		t.Fatalf("second claim after crash = %+v, want running attempt 1 -> attempt 2", second)
	}

	third, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 7, 3, "idem", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if third.Attempt != 3 || third.Exhausted {
		t.Fatalf("third claim = %+v, want attempt 3", third)
	}
	if err := j.RecordStepEndWithRetrySeq(ctx, "run_1", "send", 7, second.Attempt, json.RawMessage(`"stale"`), "", false); err == nil {
		t.Fatal("late step_end from reaped attempt 2 overwrote its interrupted fence")
	}
	exhausted, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 7, 3, "idem", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if !exhausted.Exhausted || exhausted.Previous == nil || exhausted.Previous.Attempt != 3 {
		t.Fatalf("fourth claim = %+v, want exhausted after attempt 3", exhausted)
	}
	if count, err := j.AttemptCountSeq(ctx, "run_1", "send", 7); err != nil || count != 3 {
		t.Fatalf("attempt count = %d, %v; want 3", count, err)
	}
	if latest, err := j.LatestStepAttemptSeq(ctx, "run_1", "send", 7); err != nil || latest.Attempt != 3 {
		t.Fatalf("latest = %+v, %v; want attempt 3", latest, err)
	}

	// The same step name at a different call ordinal owns an independent
	// budget; loop iterations cannot consume one another's attempts.
	otherSeq, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 8, 3, "idem-2", "hash-2")
	if err != nil || otherSeq.Attempt != 1 || otherSeq.Exhausted {
		t.Fatalf("other seq claim = %+v, %v; want independent attempt 1", otherSeq, err)
	}

	// New SDK frames can still carry seq=0 while crossing a rolling boundary.
	// That legacy identity must fail safe too, not reset attempt one forever.
	legacy, err := j.ClaimStepAttemptSeq(ctx, "run_1", "legacy", 0, 1, "", "legacy-hash")
	if err != nil || legacy.Attempt != 1 || legacy.Exhausted {
		t.Fatalf("legacy first claim = %+v, %v", legacy, err)
	}
	legacyExhausted, err := j.ClaimStepAttemptSeq(ctx, "run_1", "legacy", 0, 1, "", "legacy-hash")
	if err != nil || !legacyExhausted.Exhausted {
		t.Fatalf("legacy second claim = %+v, %v; want exhausted", legacyExhausted, err)
	}
}

func TestDurableStepEndContinuationSurvivesCrashWindow(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	first, err := j.ClaimStepAttemptSeq(ctx, "run_1", "retryable", 1, 0, "idem", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndWithRetrySeq(ctx, "run_1", "retryable", 1, first.Attempt, nil, "temporary", true); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndWithRetrySeq(ctx, "run_1", "retryable", 1, first.Attempt, json.RawMessage(`"late"`), "", false); err == nil {
		t.Fatal("duplicate step_end overwrote a completed retryable checkpoint")
	}
	state, err := j.LatestStepAttemptSeq(ctx, "run_1", "retryable", 1)
	if err != nil || state.Status != StatusRetrying {
		t.Fatalf("retryable step_end state = %+v, %v; want retrying", state, err)
	}
	// Simulate a host crash after the UPDATE but before ack. StatusRetrying is
	// the durable continuation grant, so even an unbounded custom policy may
	// consume exactly the already-authorized next attempt.
	next, err := j.ClaimStepAttemptSeq(ctx, "run_1", "retryable", 1, 0, "idem", "hash")
	if err != nil || next.Attempt != 2 || next.Exhausted {
		t.Fatalf("claim after retryable step_end = %+v, %v; want attempt 2", next, err)
	}
	// Once the next owner has claimed attempt 2, attempt 1 is no longer
	// running. A late StepEnd from the expired owner must fail its CAS rather
	// than publishing stale success into the replay cache.
	if err := j.RecordStepEndWithRetrySeq(ctx, "run_1", "retryable", 1, first.Attempt, json.RawMessage(`"stale"`), "", false); err == nil {
		t.Fatal("late step_end from prior attempt was accepted")
	}

	terminal, err := j.ClaimStepAttemptSeq(ctx, "run_1", "terminal", 2, 5, "idem-t", "hash-t")
	if err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndWithRetrySeq(ctx, "run_1", "terminal", 2, terminal.Attempt, json.RawMessage("null"), "permanent", false); err != nil {
		t.Fatal(err)
	}
	state, err = j.LatestStepAttemptSeq(ctx, "run_1", "terminal", 2)
	if err != nil || state.Status != StatusFailed {
		t.Fatalf("terminal step_end state = %+v, %v; want failed", state, err)
	}
	// A crash before the separate DLQ insert/ack must not turn the permanent
	// failure into another closure execution merely because Max has room.
	blocked, err := j.ClaimStepAttemptSeq(ctx, "run_1", "terminal", 2, 5, "idem-t", "hash-t")
	if err != nil || !blocked.Exhausted || blocked.Previous == nil || blocked.Previous.Attempt != 1 {
		t.Fatalf("claim after terminal step_end = %+v, %v; want exhausted", blocked, err)
	}
	if count, err := j.AttemptCountSeq(ctx, "run_1", "terminal", 2); err != nil || count != 1 {
		t.Fatalf("terminal attempt count = %d, %v; want 1", count, err)
	}
}

func TestFinalizeStepAttemptAtomicallyCreatesDeadLetterAndRejectsDuplicateEnd(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	claim, err := j.ClaimStepAttemptSeq(ctx, "run_1", "terminal", 4, 1, "idem", "hash")
	if err != nil {
		t.Fatal(err)
	}
	deadLettered, err := j.FinalizeStepAttemptSeq(ctx, "run_1", "terminal", 4, claim.Attempt, nil, "permanent", false)
	if err != nil || !deadLettered {
		t.Fatalf("terminal finalize = deadLettered %v, err %v", deadLettered, err)
	}
	state, err := j.LatestStepAttemptSeq(ctx, "run_1", "terminal", 4)
	if err != nil || state.Status != StatusFailed || state.ErrorText != "permanent" {
		t.Fatalf("terminal state = %+v, %v", state, err)
	}
	hasDLQ, err := j.HasDeadLetterForStep(ctx, "run_1", "terminal")
	if err != nil || !hasDLQ {
		t.Fatalf("atomic DLQ probe = %v, %v", hasDLQ, err)
	}
	if _, err := j.FinalizeStepAttemptSeq(ctx, "run_1", "terminal", 4, claim.Attempt, json.RawMessage(`"late-success"`), "", false); !errors.Is(err, ErrStepAttemptNotRunning) {
		t.Fatalf("duplicate terminal step_end = %v, want ErrStepAttemptNotRunning", err)
	}
	state, err = j.LatestStepAttemptSeq(ctx, "run_1", "terminal", 4)
	if err != nil || state.Status != StatusFailed || state.ErrorText != "permanent" {
		t.Fatalf("duplicate end changed terminal state = %+v, %v", state, err)
	}
}

func TestEnsureStepAttemptDeadLetterFailureRemainsRepairable(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	claim, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 9, 1, "idem", "hash")
	if err != nil {
		t.Fatal(err)
	}
	// Model a crash-era terminal row that committed before its old, separate
	// DLQ insert. Claiming it again is exhausted and must repair before ACK.
	if err := j.RecordStepEndWithRetrySeq(ctx, "run_1", "send", 9, claim.Attempt, nil, "permanent", false); err != nil {
		t.Fatal(err)
	}
	const reject = `CREATE TRIGGER reject_test_exact_dlq
		BEFORE INSERT ON dead_letter
		BEGIN SELECT RAISE(ABORT, 'forced dlq failure'); END`
	if _, err := j.db.ExecContext(ctx, reject); err != nil {
		t.Fatal(err)
	}
	if created, err := j.EnsureStepAttemptDeadLetter(ctx, "run_1", "send", 9, claim.Attempt, "permanent", nil); err == nil || created {
		t.Fatalf("forced repair = %v, %v; want fatal error", created, err)
	}
	if has, err := j.HasDeadLetterForStepAttempt(ctx, "run_1", "send", 9, claim.Attempt); err != nil || has {
		t.Fatalf("failed repair leaked DLQ = %v, %v", has, err)
	}
	if state, err := j.LatestStepAttemptSeq(ctx, "run_1", "send", 9); err != nil || state.Status != StatusDLQPending {
		t.Fatalf("failed repair checkpoint = %+v, %v; want durable dlq_pending", state, err)
	}
	if recoverable, err := j.HasRecoverableStepAttempt(ctx, "run_1"); err != nil || !recoverable {
		t.Fatalf("failed repair recoverability = %v, %v; want true", recoverable, err)
	}
	blocked, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 9, 1, "idem", "hash")
	if err != nil || !blocked.Exhausted || blocked.Previous == nil || blocked.Previous.Status != StatusDLQPending {
		t.Fatalf("claim while repair pending = %+v, %v; want exhausted/no closure", blocked, err)
	}
	if _, err := j.db.ExecContext(ctx, `DROP TRIGGER reject_test_exact_dlq`); err != nil {
		t.Fatal(err)
	}
	if created, err := j.EnsureStepAttemptDeadLetter(ctx, "run_1", "send", 9, claim.Attempt, "permanent", nil); err != nil || !created {
		t.Fatalf("repair retry = %v, %v; want created", created, err)
	}
	if created, err := j.EnsureStepAttemptDeadLetter(ctx, "run_1", "send", 9, claim.Attempt, "permanent", nil); err != nil || created {
		t.Fatalf("idempotent repair = %v, %v; want observed existing", created, err)
	}
	if state, err := j.LatestStepAttemptSeq(ctx, "run_1", "send", 9); err != nil || state.Status != StatusFailed {
		t.Fatalf("completed repair checkpoint = %+v, %v; want failed", state, err)
	}
	if recoverable, err := j.HasRecoverableStepAttempt(ctx, "run_1"); err != nil || recoverable {
		t.Fatalf("completed repair recoverability = %v, %v; want false", recoverable, err)
	}
}

func TestPendingDeadLetterRepairSurvivesLeaseReap(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if err := j.SetRunStatus(ctx, "run_1", "queued"); err != nil {
		t.Fatal(err)
	}
	firstLease, err := j.ClaimQueuedRuns(ctx, "worker-a", 1, -time.Minute)
	if err != nil || len(firstLease) != 1 {
		t.Fatalf("first distributed claim = %+v, %v", firstLease, err)
	}
	claim, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 9, 1, "idem", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndWithRetrySeq(ctx, "run_1", "send", 9, claim.Attempt, nil, "permanent", false); err != nil {
		t.Fatal(err)
	}
	const reject = `CREATE TRIGGER reject_reaped_exact_dlq
		BEFORE INSERT ON dead_letter
		BEGIN SELECT RAISE(ABORT, 'forced dlq failure'); END`
	if _, err := j.db.ExecContext(ctx, reject); err != nil {
		t.Fatal(err)
	}
	if _, err := j.EnsureStepAttemptDeadLetter(ctx, "run_1", "send", 9, claim.Attempt, "permanent", nil); err == nil {
		t.Fatal("forced DLQ repair unexpectedly succeeded")
	}
	if recoverable, err := j.HasRecoverableStepAttempt(ctx, "run_1"); err != nil || !recoverable {
		t.Fatalf("pending repair recoverability = %v, %v", recoverable, err)
	}
	if reaped, err := j.ReapExpiredLeases(ctx); err != nil || reaped != 1 {
		t.Fatalf("reap pending repair = %d, %v; want one requeued run", reaped, err)
	}
	if info, err := j.GetRun(ctx, "run_1"); err != nil || info.Status != "queued" {
		t.Fatalf("reaped repair run = %+v, %v; want queued", info, err)
	}

	replacement, err := j.ClaimQueuedRuns(ctx, "worker-b", 1, time.Minute)
	if err != nil || len(replacement) != 1 {
		t.Fatalf("replacement distributed claim = %+v, %v", replacement, err)
	}
	blocked, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 9, 1, "idem", "hash")
	if err != nil || !blocked.Exhausted || blocked.Previous == nil || blocked.Previous.Status != StatusDLQPending {
		t.Fatalf("replacement claim at pending repair = %+v, %v; closure must stay fenced", blocked, err)
	}
	if count, err := j.AttemptCountSeq(ctx, "run_1", "send", 9); err != nil || count != 1 {
		t.Fatalf("pending repair attempt count = %d, %v; want one", count, err)
	}
	if _, err := j.db.ExecContext(ctx, `DROP TRIGGER reject_reaped_exact_dlq`); err != nil {
		t.Fatal(err)
	}
	if created, err := j.EnsureStepAttemptDeadLetter(ctx, "run_1", "send", 9, claim.Attempt, "permanent", nil); err != nil || !created {
		t.Fatalf("replacement repair = %v, %v; want created", created, err)
	}
	if err := j.FinalizeOwnedRun(ctx, "run_1", replacement[0].Owner, "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	if info, err := j.GetRun(ctx, "run_1"); err != nil || info.Status != "failed_dlq" || info.FinishedAt.IsZero() {
		t.Fatalf("repaired run terminal state = %+v, %v", info, err)
	}
	if has, err := j.HasDeadLetterForStepAttempt(ctx, "run_1", "send", 9, claim.Attempt); err != nil || !has {
		t.Fatalf("repaired exact DLQ = %v, %v", has, err)
	}
}

func TestFinalizeExhaustedRetryingAttemptAtomicallyDeadLetters(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	claim, err := j.ClaimStepAttemptSeq(ctx, "run_1", "hostile", 11, 1, "idem", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndWithRetrySeq(ctx, "run_1", "hostile", 11, claim.Attempt, nil, "misreported transient", true); err != nil {
		t.Fatal(err)
	}
	exhausted, err := j.ClaimStepAttemptSeq(ctx, "run_1", "hostile", 11, 1, "idem", "hash")
	if err != nil || !exhausted.Exhausted || exhausted.Previous == nil || exhausted.Previous.Status != StatusRetrying {
		t.Fatalf("mismatched retry claim = %+v, %v", exhausted, err)
	}
	if err := j.FinalizeExhaustedStepAttemptSeq(ctx, "run_1", "hostile", 11, claim.Attempt, nil, "retry budget exhausted"); err != nil {
		t.Fatal(err)
	}
	state, err := j.LatestStepAttemptSeq(ctx, "run_1", "hostile", 11)
	if err != nil || state.Status != StatusFailed || state.ErrorText != "retry budget exhausted" {
		t.Fatalf("exhausted retrying state = %+v, %v", state, err)
	}
	if has, err := j.HasDeadLetterForStepAttempt(ctx, "run_1", "hostile", 11, claim.Attempt); err != nil || !has {
		t.Fatalf("exhausted retrying DLQ = %v, %v", has, err)
	}
	if err := j.FinalizeExhaustedStepAttemptSeq(ctx, "run_1", "hostile", 11, claim.Attempt, nil, "late"); !errors.Is(err, ErrStepAttemptNotRunning) {
		t.Fatalf("duplicate exhausted finalize = %v, want ErrStepAttemptNotRunning", err)
	}
}

func TestClaimStepAttemptSeqRejectsRetryInputDrift(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 1, 3, "idem", "hash-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 1, 3, "idem", "hash-b"); !errors.Is(err, ErrStepAttemptDivergence) {
		t.Fatalf("input drift error = %v, want ErrStepAttemptDivergence", err)
	}
	if count, err := j.AttemptCountSeq(ctx, "run_1", "send", 1); err != nil || count != 1 {
		t.Fatalf("drift allocated another attempt: count=%d err=%v", count, err)
	}
}

func TestDeadLetterRedriveGetsFreshBoundedAttemptWindow(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	first, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 2, 2, "idem", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndWithRetrySeq(ctx, "run_1", "send", 2, first.Attempt, nil, "temporary-1", true); err != nil {
		t.Fatal(err)
	}
	second, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 2, 2, "idem", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if deadLettered, err := j.FinalizeStepAttemptSeq(ctx, "run_1", "send", 2, second.Attempt, nil, "final-1", false); err != nil || !deadLettered {
		t.Fatalf("initial terminal finalize = %v, %v", deadLettered, err)
	}
	if err := j.MarkRunFinished(ctx, "run_1", "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	item, err := j.FindDeadLetterByRun(ctx, "run_1")
	if err != nil {
		t.Fatal(err)
	}

	claimed, err := j.StartDeadLetterRetryItem(ctx, "run_1", item.ID)
	if err != nil || !claimed {
		t.Fatalf("first redrive claim = %v, %v", claimed, err)
	}
	redrivingRun, err := j.GetRun(ctx, "run_1")
	if err != nil {
		t.Fatal(err)
	}
	if redrivingRun.Status != "running" || !redrivingRun.FinishedAt.IsZero() {
		t.Fatalf("claimed redrive still looks terminal: status=%q finished_at=%v", redrivingRun.Status, redrivingRun.FinishedAt)
	}
	baseline, err := j.LatestStepAttemptSeq(ctx, "run_1", "send", 2)
	if err != nil || baseline.Attempt != 2 || baseline.Status != StatusRedrive {
		t.Fatalf("first redrive baseline = %+v, %v", baseline, err)
	}

	third, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 2, 2, "idem", "hash")
	if err != nil || third.Attempt != 3 || third.BudgetAttempt != 1 || third.Exhausted {
		t.Fatalf("first redrive attempt = %+v, %v; want absolute=3 budget=1", third, err)
	}
	if err := j.RecordStepEndWithRetrySeq(ctx, "run_1", "send", 2, third.Attempt, nil, "temporary-2", true); err != nil {
		t.Fatal(err)
	}
	fourth, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 2, 2, "idem", "hash")
	if err != nil || fourth.Attempt != 4 || fourth.BudgetAttempt != 2 || fourth.Exhausted {
		t.Fatalf("second redrive attempt = %+v, %v; want absolute=4 budget=2", fourth, err)
	}
	if deadLettered, err := j.FinalizeStepAttemptSeq(ctx, "run_1", "send", 2, fourth.Attempt, nil, "final-2", false); err != nil || !deadLettered {
		t.Fatalf("first redrive terminal finalize = %v, %v", deadLettered, err)
	}
	blocked, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 2, 2, "idem", "hash")
	if err != nil || !blocked.Exhausted {
		t.Fatalf("first redrive exceeded fresh Max: %+v, %v", blocked, err)
	}

	// The DLQ item deliberately remains while a redrive fails. A second
	// operator redrive marks attempt 4 as the next generation baseline and gets
	// another two-attempt window without colliding with attempts 1..4.
	if err := j.MarkRunFinished(ctx, "run_1", "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	currentItem, err := j.FindDeadLetterByRun(ctx, "run_1")
	if err != nil {
		t.Fatal(err)
	}
	if currentItem.ID == item.ID || currentItem.StepAttempt == nil || *currentItem.StepAttempt != fourth.Attempt {
		t.Fatalf("current repeated-failure DLQ = %+v, want attempt %d", currentItem, fourth.Attempt)
	}
	if claimed, err := j.StartDeadLetterRetryItem(ctx, "run_1", item.ID); claimed || !errors.Is(err, ErrDeadLetterNotCurrent) {
		t.Fatalf("older generation DLQ claim = %v, %v; want stale rejection", claimed, err)
	}
	claimed, err = j.StartDeadLetterRetryItem(ctx, "run_1", currentItem.ID)
	if err != nil || !claimed {
		t.Fatalf("second redrive claim = %v, %v", claimed, err)
	}
	fifth, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 2, 2, "idem", "hash")
	if err != nil || fifth.Attempt != 5 || fifth.BudgetAttempt != 1 || fifth.Exhausted {
		t.Fatalf("repeated redrive attempt = %+v, %v; want absolute=5 budget=1", fifth, err)
	}
	if err := j.RecordStepEndWithRetrySeq(ctx, "run_1", "send", 2, fifth.Attempt, json.RawMessage(`"sent"`), "", false); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, "run_1", "succeeded"); err != nil {
		t.Fatal(err)
	}
	deleted, err := j.DeleteDeadLettersByRun(ctx, "run_1")
	if err != nil || deleted != 2 {
		t.Fatalf("successful redrive DLQ cleanup = %d, %v; want 2", deleted, err)
	}
	if _, err := j.GetDeadLetterItem(ctx, item.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("resolved DLQ item still exists: %v", err)
	}
}

func TestDeadLetterRedriveRejectsStaleSelectedItem(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.MarkRunFinished(ctx, "run_1", "failed_dlq"); err != nil {
		t.Fatal(err)
	}

	if err := j.MoveStepToDeadLetter(ctx, "run_1", "first", "old", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	old, err := j.FindDeadLetterByRun(ctx, "run_1")
	if err != nil {
		t.Fatal(err)
	}
	if err := j.MoveStepToDeadLetter(ctx, "run_1", "second", "new", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	items, err := j.ListDeadLetterItems(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	var newerID string
	for _, candidate := range items {
		if candidate.ID != old.ID {
			newerID = candidate.ID
			break
		}
	}
	if newerID == "" {
		t.Fatal("test setup did not create a second DLQ item")
	}
	// SQLite can give two inserts the same default timestamp. Make the intended
	// current item explicit without sleeping the test.
	if _, err := j.db.ExecContext(ctx, `UPDATE dead_letter SET moved_at = '9999-12-31T23:59:59Z' WHERE id = ?`, newerID); err != nil {
		t.Fatal(err)
	}
	if claimed, err := j.StartDeadLetterRetryItem(ctx, "run_1", old.ID); claimed || !errors.Is(err, ErrDeadLetterNotCurrent) {
		t.Fatalf("stale DLQ claim = %v, %v; want ErrDeadLetterNotCurrent", claimed, err)
	}
	info, err := j.GetRun(ctx, "run_1")
	if err != nil {
		t.Fatal(err)
	}
	if info.Status == "running" {
		t.Fatal("stale DLQ selection mutated run to running")
	}
}

func TestDeadLetterExactIdentityAcrossRepeatedStepNames(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	fail := func(step string, seq int64, errText string) DeadLetterItem {
		t.Helper()
		claim, err := j.ClaimStepAttemptSeq(ctx, "run_1", step, seq, 1, step, "hash-"+step)
		if err != nil {
			t.Fatal(err)
		}
		if deadLettered, err := j.FinalizeStepAttemptSeq(ctx, "run_1", step, seq, claim.Attempt, nil, errText, false); err != nil || !deadLettered {
			t.Fatalf("finalize %s/%d = %v, %v", step, seq, deadLettered, err)
		}
		if err := j.MarkRunFinished(ctx, "run_1", "failed_dlq"); err != nil {
			t.Fatal(err)
		}
		item, err := j.FindDeadLetterByRun(ctx, "run_1")
		if err != nil {
			t.Fatal(err)
		}
		if item.StepSeq == nil || *item.StepSeq != seq || item.StepAttempt == nil || *item.StepAttempt != claim.Attempt {
			t.Fatalf("current DLQ identity = %+v, want %s seq=%d attempt=%d", item, step, seq, claim.Attempt)
		}
		return item
	}
	redrive := func(item DeadLetterItem) {
		t.Helper()
		claimed, err := j.StartDeadLetterRetryItem(ctx, "run_1", item.ID)
		if err != nil || !claimed {
			t.Fatalf("redrive %+v = %v, %v", item, claimed, err)
		}
	}

	firstA := fail("A", 1, "a-1")
	redrive(firstA)
	b := fail("B", 2, "b-1")
	if b.FailureOrder <= firstA.FailureOrder {
		t.Fatalf("failure order did not advance: A=%d B=%d", firstA.FailureOrder, b.FailureOrder)
	}
	redrive(b)
	lastA := fail("A", 3, "a-2")
	if lastA.FailureOrder <= b.FailureOrder {
		t.Fatalf("failure order did not advance: B=%d A2=%d", b.FailureOrder, lastA.FailureOrder)
	}
	if claimed, err := j.StartDeadLetterRetryItem(ctx, "run_1", firstA.ID); claimed || !errors.Is(err, ErrDeadLetterNotCurrent) {
		t.Fatalf("old A item authorized = %v, %v; want stale rejection", claimed, err)
	}
	redrive(lastA)
	latest, err := j.LatestStepAttemptSeq(ctx, "run_1", "A", 3)
	if err != nil || latest.Status != StatusRedrive {
		t.Fatalf("last A exact attempt not authorized: %+v, %v", latest, err)
	}
}

func TestDeadLetterRedriveRequiresFailedDLQRun(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.MoveStepToDeadLetter(ctx, "run_1", "send", "old", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	item, err := j.FindDeadLetterByRun(ctx, "run_1")
	if err != nil {
		t.Fatal(err)
	}

	for _, status := range []string{"succeeded", "failed", "queued", "suspended", "running", "cancelled"} {
		if err := j.SetRunStatus(ctx, "run_1", status); err != nil {
			t.Fatal(err)
		}
		claimed, err := j.StartDeadLetterRetryItem(ctx, "run_1", item.ID)
		if err != nil || claimed {
			t.Fatalf("status %q redrive claim = %v, %v; want false", status, claimed, err)
		}
		info, err := j.GetRun(ctx, "run_1")
		if err != nil || info.Status != status {
			t.Fatalf("status %q mutated by rejected redrive: %+v, %v", status, info, err)
		}
	}
}

func TestDeadLetterDistributedRedriveQueuesBeforeWorkerClaim(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	claim, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 2, 1, "idem", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if deadLettered, err := j.FinalizeStepAttemptSeq(ctx, "run_1", "send", 2, claim.Attempt, nil, "permanent", false); err != nil || !deadLettered {
		t.Fatalf("terminal finalize = %v, %v", deadLettered, err)
	}
	if err := j.MarkRunFinished(ctx, "run_1", "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	item, err := j.FindDeadLetterByRun(ctx, "run_1")
	if err != nil {
		t.Fatal(err)
	}

	claimed, err := j.StartDeadLetterRetryQueuedItem(ctx, "run_1", item.ID)
	if err != nil || !claimed {
		t.Fatalf("queued redrive = %v, %v", claimed, err)
	}
	info, err := j.GetRun(ctx, "run_1")
	if err != nil || info.Status != "queued" || !info.FinishedAt.IsZero() {
		t.Fatalf("distributed redrive run = %+v, %v; want queued and nonterminal", info, err)
	}
	baseline, err := j.LatestStepAttemptSeq(ctx, "run_1", "send", 2)
	if err != nil || baseline.Status != StatusRedrive || baseline.Attempt != claim.Attempt {
		t.Fatalf("distributed redrive baseline = %+v, %v", baseline, err)
	}
	if claimed, err := j.StartDeadLetterRetryQueuedItem(ctx, "run_1", item.ID); err != nil || claimed {
		t.Fatalf("second distributed redrive claim = %v, %v; want false", claimed, err)
	}
}
