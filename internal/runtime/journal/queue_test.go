package journal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestOldestQueuedAgeTracksEligibleBacklog(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if age, err := j.OldestQueuedAge(ctx); err != nil || age != 0 {
		t.Fatalf("empty queue age = %s, %v; want zero", age, err)
	}
	if err := j.CreateWorkflow(ctx, "wf_queue_age", "queue-age", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	for _, runID := range []string{"run_age_old", "run_age_new"} {
		if err := j.CreateQueuedRun(ctx, runID, "wf_queue_age", "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	for _, item := range []struct {
		id  string
		age time.Duration
	}{{"run_age_old", 90 * time.Second}, {"run_age_new", 20 * time.Second}} {
		if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE runs SET created_at = $1 WHERE id = $2`), j.formatTime(now.Add(-item.age)), item.id); err != nil {
			t.Fatal(err)
		}
	}
	assertAge := func(want time.Duration) {
		t.Helper()
		age, err := j.OldestQueuedAge(ctx)
		if err != nil || age < want-time.Second || age > want+5*time.Second {
			t.Fatalf("oldest queue age = %s, %v; want about %s", age, err, want)
		}
	}
	assertAge(90 * time.Second)
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE runs SET cancel_requested = $1 WHERE id = $2`), j.boolValue(true), "run_age_old"); err != nil {
		t.Fatal(err)
	}
	assertAge(20 * time.Second)
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE runs SET cancel_requested = $1 WHERE id = $2`), j.boolValue(true), "run_age_new"); err != nil {
		t.Fatal(err)
	}
	if age, err := j.OldestQueuedAge(ctx); err != nil || age != 0 {
		t.Fatalf("cancelled-only queue age = %s, %v; want zero", age, err)
	}
}

func TestQueueClaimLeaseReap(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_q", "queue-demo", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}

	// Enqueue two runs.
	if err := j.CreateQueuedRun(ctx, "run_a", "wf_q", "webhook", json.RawMessage(`{"x":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateQueuedRun(ctx, "run_b", "wf_q", "webhook", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if n, _ := j.CountQueued(ctx); n != 2 {
		t.Fatalf("CountQueued = %d, want 2", n)
	}
	initialRunning, err := j.CountRunning(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Claim one: FIFO (run_a first), flips to running, writes a lease.
	ids, err := j.ClaimQueuedRuns(ctx, "worker-1", 1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0].RunID != "run_a" || ids[0].Owner == "worker-1" {
		t.Fatalf("claim = %v, want [run_a]", ids)
	}
	if info, _ := j.GetRun(ctx, "run_a"); info.Status != "running" {
		t.Fatalf("claimed run status = %q, want running", info.Status)
	}
	if n, _ := j.CountRunning(ctx); n != initialRunning+1 {
		t.Fatalf("CountRunning after claim = %d, want %d", n, initialRunning+1)
	}
	if n, _ := j.CountQueued(ctx); n != 1 {
		t.Fatalf("CountQueued after one claim = %d, want 1", n)
	}

	// Extend + release the lease.
	if err := j.ExtendLease(ctx, "run_a", ids[0].Owner, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := j.ReleaseLease(ctx, "run_a", ids[0].Owner); err != nil {
		t.Fatal(err)
	}

	// Claim run_b with an already-expired lease, then reap it: the run
	// should requeue (worker died mid-run) and re-enter the queue.
	ids, err = j.ClaimQueuedRuns(ctx, "worker-2", 5, -time.Hour)
	if err != nil || len(ids) != 1 || ids[0].RunID != "run_b" {
		t.Fatalf("claim run_b = %v, %v", ids, err)
	}
	reaped, err := j.ReapExpiredLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if reaped != 1 {
		t.Fatalf("reaped = %d, want 1", reaped)
	}
	if info, _ := j.GetRun(ctx, "run_b"); info.Status != "queued" {
		t.Fatalf("reaped run status = %q, want queued (requeued)", info.Status)
	}
	if n, _ := j.CountQueued(ctx); n != 1 {
		t.Fatalf("CountQueued after reap = %d, want 1", n)
	}
	// Releasing a lease does not terminalize its run; the executor owns that
	// transition. The reaped run is queued again, so the first claimed row is
	// the only new running row left here.
	if n, _ := j.CountRunning(ctx); n != initialRunning+1 {
		t.Fatalf("CountRunning after reap = %d, want %d", n, initialRunning+1)
	}

	// An empty queue claim returns nothing, no error.
	_, _ = j.ClaimQueuedRuns(ctx, "w", 10, time.Minute) // drains run_b
	got, err := j.ClaimQueuedRuns(ctx, "w", 10, time.Minute)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty claim = %v, %v; want nil/nil", got, err)
	}
}

func TestReturnUnstartedLeaseImmediatelyRequeuesExactClaim(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateQueuedRun(ctx, "run_unstarted", "wf_1", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	first, err := j.ClaimQueuedRuns(ctx, "stopping-worker", 1, time.Hour)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim = %+v, %v", first, err)
	}
	if err := j.ReturnUnstartedLease(ctx, first[0].RunID, first[0].Owner); err != nil {
		t.Fatal(err)
	}
	if run, err := j.GetRun(ctx, first[0].RunID); err != nil || run.Status != "queued" {
		t.Fatalf("returned run = %+v, %v; want queued", run, err)
	}
	if err := j.ExtendLease(ctx, first[0].RunID, first[0].Owner, time.Minute); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("old claim retained lease: %v", err)
	}
	second, err := j.ClaimQueuedRuns(ctx, "replacement-worker", 1, time.Minute)
	if err != nil || len(second) != 1 || second[0].RunID != first[0].RunID || second[0].Owner == first[0].Owner {
		t.Fatalf("immediate replacement = %+v, %v", second, err)
	}
	if err := j.ReturnUnstartedLease(ctx, first[0].RunID, first[0].Owner); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("stale return changed replacement claim: %v", err)
	}
	if err := j.ExtendLease(ctx, second[0].RunID, second[0].Owner, time.Minute); err != nil {
		t.Fatalf("replacement lost lease: %v", err)
	}
}

func TestReturnUnstartedLeaseHonorsAcceptedCancellation(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateQueuedRun(ctx, "run_unstarted_cancel", "wf_1", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	claim, err := j.ClaimQueuedRuns(ctx, "stopping-worker", 1, time.Hour)
	if err != nil || len(claim) != 1 {
		t.Fatalf("claim = %+v, %v", claim, err)
	}
	if outcome, err := j.RequestRunCancel(ctx, claim[0].RunID); err != nil || outcome != CancelRequested {
		t.Fatalf("cancel = %q, %v", outcome, err)
	}
	if err := j.ReturnUnstartedLease(ctx, claim[0].RunID, claim[0].Owner); err != nil {
		t.Fatal(err)
	}
	if run, err := j.GetRun(ctx, claim[0].RunID); err != nil || run.Status != "cancelled" || run.FinishedAt.IsZero() {
		t.Fatalf("returned cancelled run = %+v, %v", run, err)
	}
	if next, err := j.ClaimQueuedRuns(ctx, "replacement-worker", 1, time.Minute); err != nil || len(next) != 0 {
		t.Fatalf("cancelled run became claimable = %+v, %v", next, err)
	}
}

func TestLeaseGenerationFencesStaleWorkerTerminalAndRelease(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateQueuedRun(ctx, "run_fenced", "wf_1", "webhook", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	first, err := j.ClaimQueuedRuns(ctx, "worker-a", 1, -time.Hour)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim = %v, %v", first, err)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("reap first = %d, %v", n, err)
	}
	second, err := j.ClaimQueuedRuns(ctx, "worker-b", 1, time.Minute)
	if err != nil || len(second) != 1 {
		t.Fatalf("replacement claim = %v, %v", second, err)
	}
	if first[0].Owner == second[0].Owner {
		t.Fatal("replacement reused stale lease generation")
	}

	if err := j.ExtendLease(ctx, "run_fenced", first[0].Owner, time.Minute); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("stale extend = %v, want ErrLeaseOwnershipLost", err)
	}
	if err := j.ReleaseLease(ctx, "run_fenced", first[0].Owner); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("stale release = %v, want ErrLeaseOwnershipLost", err)
	}
	if err := j.FinalizeOwnedRun(ctx, "run_fenced", first[0].Owner, "succeeded"); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("stale terminal = %v, want ErrLeaseOwnershipLost", err)
	}
	if err := j.FailLeasedRunArtifactFence(ctx, "run_fenced", first[0].Owner); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("stale artifact fence = %v, want ErrLeaseOwnershipLost", err)
	}
	if run, err := j.GetRun(ctx, "run_fenced"); err != nil || run.Status != "running" {
		t.Fatalf("stale worker changed replacement run = %+v, %v", run, err)
	}
	if err := j.ExtendLease(ctx, "run_fenced", second[0].Owner, time.Minute); err != nil {
		t.Fatalf("stale worker damaged replacement lease: %v", err)
	}
	if err := j.FinalizeOwnedRun(ctx, "run_fenced", second[0].Owner, "succeeded"); err != nil {
		t.Fatalf("replacement terminal: %v", err)
	}
	if run, err := j.GetRun(ctx, "run_fenced"); err != nil || run.Status != "succeeded" || run.FinishedAt.IsZero() {
		t.Fatalf("replacement terminal state = %+v, %v", run, err)
	}
}

func TestExpiredLeaseCannotBeRenewedBeforeReap(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateQueuedRun(ctx, "run_expired_renew", "wf_1", "webhook", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	claims, err := j.ClaimQueuedRuns(ctx, "paused-worker", 1, -time.Minute)
	if err != nil || len(claims) != 1 {
		t.Fatalf("expired claim = %v, %v", claims, err)
	}

	// A worker that wakes after its deadline must not be able to revive its
	// generation merely because the reaper has not observed it yet. The
	// replacement boundary is the lease timestamp itself, not reaper timing.
	if err := j.ExtendLease(ctx, "run_expired_renew", claims[0].Owner, time.Minute); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("expired lease renewal = %v, want ErrLeaseOwnershipLost", err)
	}
	if err := j.VerifyLeaseOwner(ctx, "run_expired_renew", claims[0].Owner); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("expired lease verification = %v, want ErrLeaseOwnershipLost", err)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("expired lease reap = %d, %v", n, err)
	}
	if run, err := j.GetRun(ctx, "run_expired_renew"); err != nil || run.Status != "queued" {
		t.Fatalf("expired lease run state = %+v, %v; want queued", run, err)
	}
}

func TestLeaseRenewalWaitingPastDeadlineCannotReviveClaim(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const runID = "run_waiting_renew"
	if err := j.CreateQueuedRun(ctx, runID, "wf_1", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	claims, err := j.ClaimQueuedRuns(ctx, "waiting-worker", 1, 750*time.Millisecond)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim = %+v, %v", claims, err)
	}

	// Hold the only database connection until the claim expires. The former
	// single UPDATE captured its comparison time before waiting for this
	// connection, so it could revive the claim after the deadline.
	j.db.SetMaxOpenConns(1)
	holder, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	var rawDeadline string
	if err := holder.QueryRowContext(ctx, j.bind(`SELECT expires_at FROM leases WHERE run_id = $1`), runID).Scan(&rawDeadline); err != nil {
		t.Fatal(err)
	}
	deadline, err := j.parseTime(rawDeadline)
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(deadline) < 300*time.Millisecond {
		t.Fatalf("claim deadline too near for blocked renewal test: %s", time.Until(deadline))
	}
	beforeWait := j.db.Stats().WaitCount
	renewed := make(chan error, 1)
	go func() { renewed <- j.ExtendLease(ctx, runID, claims[0].Owner, time.Minute) }()
	for j.db.Stats().WaitCount == beforeWait {
		if time.Until(deadline) < 100*time.Millisecond {
			t.Fatal("renewal did not reach the held connection before the deadline")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if wait := time.Until(deadline.Add(20 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-renewed:
		if !errors.Is(err, ErrLeaseOwnershipLost) {
			t.Fatalf("renewal after connection wait = %v, want ownership loss", err)
		}
	case <-ctx.Done():
		t.Fatalf("renewal did not return: %v", ctx.Err())
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("reap expired claim = %d, %v; want one", n, err)
	}
	if replacement, err := j.ClaimQueuedRuns(ctx, "replacement", 1, time.Minute); err != nil || len(replacement) != 1 || replacement[0].RunID != runID {
		t.Fatalf("replacement claim = %+v, %v", replacement, err)
	}
}

func TestExpiredLeaseCannotFinalizeBeforeReap(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateQueuedRun(ctx, "run_expired_finalizer", "wf_1", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	claims, err := j.ClaimQueuedRuns(ctx, "paused-worker", 1, -time.Minute)
	if err != nil || len(claims) != 1 {
		t.Fatalf("expired claim = %v, %v", claims, err)
	}
	owner := claims[0].Owner
	if err := j.FinalizeOwnedRun(ctx, "run_expired_finalizer", owner, "succeeded"); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("expired finalization = %v, want ownership loss", err)
	}
	if _, err := j.FailLeasedRunArtifactFenceStatus(ctx, "run_expired_finalizer", owner); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("expired artifact-fence finalization = %v, want ownership loss", err)
	}
	if _, err := j.RecoverOwnedPendingDeadLetterRedrive(ctx, "run_expired_finalizer", owner); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("expired redrive recovery = %v, want ownership loss", err)
	}
	if run, err := j.GetRun(ctx, "run_expired_finalizer"); err != nil || run.Status != "running" || !run.FinishedAt.IsZero() {
		t.Fatalf("expired worker changed run = %+v, %v", run, err)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("reap expired claim = %d, %v", n, err)
	}
	replacement, err := j.ClaimQueuedRuns(ctx, "replacement", 1, time.Minute)
	if err != nil || len(replacement) != 1 || replacement[0].RunID != "run_expired_finalizer" {
		t.Fatalf("replacement claim = %+v, %v", replacement, err)
	}
	if err := j.FinalizeOwnedRun(ctx, "run_expired_finalizer", replacement[0].Owner, "succeeded"); err != nil {
		t.Fatalf("replacement finalization: %v", err)
	}
}

func TestReaperFinalizesCancelRequestedDeadOwnerWithoutReplacement(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateQueuedRun(ctx, "run_dead_cancel", "wf_1", "webhook", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	claims, err := j.ClaimQueuedRuns(ctx, "dead-worker", 1, -time.Hour)
	if err != nil || len(claims) != 1 {
		t.Fatalf("dead owner claim = %v, %v", claims, err)
	}
	if _, err := j.ScheduleSleep(ctx, "run_dead_cancel", "must-not-fire", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if outcome, err := j.RequestRunCancel(ctx, "run_dead_cancel"); err != nil || outcome != CancelRequested {
		t.Fatalf("cancel dead owner = %q, %v; want requested", outcome, err)
	}

	// The owner is gone, so the reaper is responsible for preserving the
	// accepted cancellation. It must terminalize rather than enqueue work that
	// could execute after the operator asked it to stop.
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 0 {
		t.Fatalf("reap cancelled dead owner = %d, %v; want no requeue", n, err)
	}
	run, err := j.GetRun(ctx, "run_dead_cancel")
	if err != nil || run.Status != "cancelled" || run.FinishedAt.IsZero() {
		t.Fatalf("cancelled dead-owner state = %+v, %v", run, err)
	}
	if schedule, err := j.FindLatestSleepSchedule(ctx, "run_dead_cancel", "must-not-fire"); err != nil || !schedule.Fired {
		t.Fatalf("cancelled dead-owner schedule = %+v, %v; want fired fence", schedule, err)
	}
	if err := j.ExtendLease(ctx, "run_dead_cancel", claims[0].Owner, time.Minute); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("dead owner lease retained = %v, want ownership loss", err)
	}
	if replacements, err := j.ClaimQueuedRuns(ctx, "replacement", 1, time.Minute); err != nil || len(replacements) != 0 {
		t.Fatalf("cancelled run became replacement work = %v, %v", replacements, err)
	}
}

func TestQueuedCancelAndFairClaimAreLinearized(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	// RequestRunCancel and the fair queue admission path both serialize on the
	// run row (and SQLite's writer lock). Whichever wins is valid: cancellation
	// either prevents the claim, or marks the already-claimed run requested.
	// There must never be a claimed child with cancellation silently lost.
	for i := 0; i < 8; i++ {
		runID := fmt.Sprintf("run_claim_cancel_%d", i)
		if err := j.CreateQueuedRun(ctx, runID, "wf_1", "webhook", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
		type claimResult struct {
			claims []RunLease
			err    error
		}
		type cancelResult struct {
			outcome string
			err     error
		}
		start := make(chan struct{})
		claimDone := make(chan claimResult, 1)
		cancelDone := make(chan cancelResult, 1)
		go func() {
			<-start
			claims, err := j.ClaimQueuedRuns(context.Background(), "worker", 1, time.Minute)
			claimDone <- claimResult{claims: claims, err: err}
		}()
		go func() {
			<-start
			outcome, err := j.RequestRunCancel(context.Background(), runID)
			cancelDone <- cancelResult{outcome: outcome, err: err}
		}()
		close(start)
		claimed := <-claimDone
		cancelled := <-cancelDone
		// SQLite can surface SQLITE_BUSY when two deferred transactions try to
		// become the sole writer at once. Retrying the loser after the winner's
		// commit is the documented local-mode behavior; PostgreSQL blocks on the
		// row lock instead. An accepted cancellation still must never be lost.
		if claimed.err != nil {
			claimed.claims, claimed.err = j.ClaimQueuedRuns(ctx, "worker", 1, time.Minute)
		}
		if cancelled.err != nil {
			cancelled.outcome, cancelled.err = j.RequestRunCancel(ctx, runID)
		}
		if claimed.err != nil || cancelled.err != nil {
			t.Fatalf("iteration %d race errors: claim=%v cancel=%v", i, claimed.err, cancelled.err)
		}

		run, err := j.GetRun(ctx, runID)
		if err != nil {
			t.Fatal(err)
		}
		switch cancelled.outcome {
		case CancelDone:
			if len(claimed.claims) != 0 || run.Status != "cancelled" {
				t.Fatalf("iteration %d cancel-first state: claims=%v run=%+v", i, claimed.claims, run)
			}
		case CancelRequested:
			if len(claimed.claims) != 1 || claimed.claims[0].RunID != runID || run.Status != "running" {
				t.Fatalf("iteration %d claim-first state: claims=%v run=%+v", i, claimed.claims, run)
			}
			var requested any
			if err := j.db.QueryRowContext(ctx, j.bind(`SELECT cancel_requested FROM runs WHERE id = $1`), runID).Scan(&requested); err != nil {
				t.Fatal(err)
			}
			if !parseBool(requested) {
				t.Fatalf("iteration %d claimed run lost cancel_requested", i)
			}
			if err := j.FinalizeOwnedRun(ctx, runID, claimed.claims[0].Owner, "cancelled"); err != nil {
				t.Fatalf("iteration %d cleanup finalization: %v", i, err)
			}
		default:
			t.Fatalf("iteration %d unexpected cancel outcome %q", i, cancelled.outcome)
		}
	}
}

func TestFairClaimSkipsCancelRequestedQueuedRun(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateQueuedRun(ctx, "run_flagged_queued", "wf_1", "webhook", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	// Simulate a legacy/crash-recovered flagged queued row. Normal cancellation
	// now terminalizes queued rows atomically, but queue admission must remain a
	// final defense against executing already-accepted operator intent.
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE runs SET cancel_requested = $1 WHERE id = $2`), j.boolValue(true), "run_flagged_queued"); err != nil {
		t.Fatal(err)
	}
	if claims, err := j.ClaimQueuedRuns(ctx, "worker", 1, time.Minute); err != nil || len(claims) != 0 {
		t.Fatalf("cancel-requested queued row was claimed: %v, %v", claims, err)
	}
	if run, err := j.GetRun(ctx, "run_flagged_queued"); err != nil || run.Status != "queued" {
		t.Fatalf("flagged row changed unexpectedly: %+v, %v", run, err)
	}
	if outcome, err := j.RequestRunCancel(ctx, "run_flagged_queued"); err != nil || outcome != CancelDone {
		t.Fatalf("flagged queued cleanup = %q, %v", outcome, err)
	}
}

func TestQueueDepthExcludesCancelRequestedRows(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateQueuedRun(ctx, "run_count_cancelled", "wf_1", "webhook", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if n, err := j.CountQueued(ctx); err != nil || n != 1 {
		t.Fatalf("initial queue depth = %d, %v; want 1", n, err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE runs SET cancel_requested = $1 WHERE id = $2`), j.boolValue(true), "run_count_cancelled"); err != nil {
		t.Fatal(err)
	}
	if n, err := j.CountQueued(ctx); err != nil || n != 0 {
		t.Fatalf("cancel-requested queue depth = %d, %v; want 0", n, err)
	}
}

func TestReaperCannotDeleteConcurrentRenewal(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateQueuedRun(ctx, "run_renew", "wf_1", "webhook", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	claims, err := j.ClaimQueuedRuns(ctx, "worker", 1, -time.Hour)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim = %v, %v", claims, err)
	}

	// Hold SQLite's writer lock around the exact-owner renewal while a reaper
	// starts. The reaper may block or report SQLITE_BUSY, but it must never
	// delete/requeue the generation after the renewal commits.
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, j.bind(`UPDATE leases SET expires_at = $1 WHERE run_id = $2 AND worker_id = $3`),
		j.formatTime(time.Now().Add(time.Hour)), "run_renew", claims[0].Owner); err != nil {
		t.Fatal(err)
	}
	type reapResult struct {
		n   int64
		err error
	}
	done := make(chan reapResult, 1)
	go func() {
		n, err := j.ReapExpiredLeases(context.Background())
		done <- reapResult{n: n, err: err}
	}()
	reaperReturned := false
	select {
	case result := <-done:
		reaperReturned = true
		if result.err == nil && result.n != 0 {
			t.Fatalf("reaper moved uncommitted renewal: %+v", result)
		}
	case <-time.After(30 * time.Millisecond):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if !reaperReturned {
		result := <-done
		if result.err == nil && result.n != 0 {
			t.Fatalf("reaper moved renewed lease: %+v", result)
		}
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 0 {
		t.Fatalf("post-renew reap = %d, %v; want 0", n, err)
	}
	if run, _ := j.GetRun(ctx, "run_renew"); run.Status != "running" {
		t.Fatalf("renewed run status = %q, want running", run.Status)
	}
	if err := j.ExtendLease(ctx, "run_renew", claims[0].Owner, time.Minute); err != nil {
		t.Fatalf("renewed owner lost lease: %v", err)
	}
}

func TestOwnedTerminalPersistenceFailureKeepsRunAndLeaseRecoverable(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateQueuedRun(ctx, "run_persist", "wf_1", "webhook", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	claims, err := j.ClaimQueuedRuns(ctx, "worker", 1, time.Minute)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim = %v, %v", claims, err)
	}
	if err := j.MoveStepToDeadLetter(ctx, "run_persist", "send", "old failure", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	const reject = `CREATE TRIGGER reject_owned_terminal
		BEFORE UPDATE OF status ON runs
		WHEN OLD.id = 'run_persist' AND NEW.status = 'succeeded'
		BEGIN SELECT RAISE(ABORT, 'forced terminal failure'); END`
	if _, err := j.db.ExecContext(ctx, reject); err != nil {
		t.Fatal(err)
	}
	if err := j.FinalizeOwnedRun(ctx, "run_persist", claims[0].Owner, "succeeded"); err == nil {
		t.Fatal("forced terminal persistence unexpectedly succeeded")
	}
	if run, _ := j.GetRun(ctx, "run_persist"); run.Status != "running" || !run.FinishedAt.IsZero() {
		t.Fatalf("failed terminal transaction changed run: %+v", run)
	}
	if err := j.ExtendLease(ctx, "run_persist", claims[0].Owner, time.Minute); err != nil {
		t.Fatalf("failed terminal transaction lost lease: %v", err)
	}
	if items, _ := j.ListDeadLetterItems(ctx, 10, 0); len(items) != 1 {
		t.Fatalf("failed terminal transaction cleared DLQ: %+v", items)
	}
	if _, err := j.db.ExecContext(ctx, `DROP TRIGGER reject_owned_terminal`); err != nil {
		t.Fatal(err)
	}
	if err := j.FinalizeOwnedRun(ctx, "run_persist", claims[0].Owner, "succeeded"); err != nil {
		t.Fatal(err)
	}
	if items, _ := j.ListDeadLetterItems(ctx, 10, 0); len(items) != 0 {
		t.Fatalf("owned success did not atomically clear DLQ: %+v", items)
	}
}
