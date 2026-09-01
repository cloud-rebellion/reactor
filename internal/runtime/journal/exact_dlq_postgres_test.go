package journal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
)

// TestExactDeadLetterRecoveryPostgres exercises the PostgreSQL row locks and
// exact-DLQ constraints used by production workers. The default journal suite
// remains self-contained; CI/developers opt in with an isolated database.
func TestExactDeadLetterRecoveryPostgres(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL to run the PostgreSQL exact-DLQ recovery contract")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(ctx, log, rawURL); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}
	db, engine, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("close postgres exact-DLQ database: %v", closeErr)
		}
	})
	if engine != migrate.EnginePostgres {
		t.Fatalf("REACTOR_TEST_POSTGRES_URL selected %s, want postgres", engine)
	}
	j := New(db, EnginePostgres)

	suffix, err := newID("")
	if err != nil {
		t.Fatal(err)
	}
	wfID := "wf_exact_dlq_pg_" + suffix
	repairRunID := "run_dlq_repair_pg_" + suffix
	redriveRunID := "run_dlq_redrive_pg_" + suffix
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		for _, statement := range []string{
			`DELETE FROM dead_letter WHERE run_id IN ($1, $2)`,
			`DELETE FROM run_usage WHERE run_id IN ($1, $2)`,
			`DELETE FROM runs WHERE id IN ($1, $2)`,
		} {
			if _, cleanupErr := db.ExecContext(cleanupCtx, statement, repairRunID, redriveRunID); cleanupErr != nil {
				t.Errorf("postgres exact-DLQ cleanup: %v", cleanupErr)
			}
		}
		if _, cleanupErr := db.ExecContext(cleanupCtx, `DELETE FROM workflows WHERE id = $1`, wfID); cleanupErr != nil {
			t.Errorf("postgres exact-DLQ workflow cleanup: %v", cleanupErr)
		}
	})

	if err := j.CreateWorkflow(ctx, wfID, "exact-dlq-pg-"+suffix, "hash", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}

	t.Run("repairs durable pending checkpoint without another attempt", func(t *testing.T) {
		if err := j.CreateRun(ctx, repairRunID, wfID, "webhook", json.RawMessage(`{"event_id":"repair"}`)); err != nil {
			t.Fatal(err)
		}
		claim, err := j.ClaimStepAttemptSeq(ctx, repairRunID, "hash-send", 9, 1, "idem-repair", "input-repair")
		if err != nil {
			t.Fatal(err)
		}
		if err := j.RecordStepEndWithRetrySeq(ctx, repairRunID, "hash-send", 9, claim.Attempt, nil, "permanent", false); err != nil {
			t.Fatal(err)
		}

		// Model a crash after the first repair transaction committed its durable
		// marker but before the exact dead_letter insert committed.
		res, err := db.ExecContext(ctx, `UPDATE steps SET status = $1
			WHERE run_id = $2 AND step_name = $3 AND seq = $4 AND attempt = $5 AND status = $6`,
			StatusDLQPending, repairRunID, "hash-send", 9, claim.Attempt, StatusFailed)
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("seed dlq_pending rows = %d, want 1", n)
		}
		if recoverable, err := j.HasRecoverableStepAttempt(ctx, repairRunID); err != nil || !recoverable {
			t.Fatalf("pending checkpoint recoverable = %v, %v", recoverable, err)
		}

		created, err := j.EnsureStepAttemptDeadLetter(ctx, repairRunID, "hash-send", 9, claim.Attempt,
			"permanent", json.RawMessage(`{"safe":"payload"}`))
		if err != nil || !created {
			t.Fatalf("repair pending exact DLQ = %v, %v", created, err)
		}
		created, err = j.EnsureStepAttemptDeadLetter(ctx, repairRunID, "hash-send", 9, claim.Attempt,
			"permanent", json.RawMessage(`{"safe":"payload"}`))
		if err != nil || created {
			t.Fatalf("idempotent exact DLQ observation = %v, %v", created, err)
		}

		state, err := j.LatestStepAttemptSeq(ctx, repairRunID, "hash-send", 9)
		if err != nil || state.Status != StatusFailed || state.Attempt != claim.Attempt {
			t.Fatalf("repaired attempt = %+v, %v", state, err)
		}
		item, err := j.FindDeadLetterByRun(ctx, repairRunID)
		if err != nil || item.StepSeq == nil || *item.StepSeq != 9 || item.StepAttempt == nil || *item.StepAttempt != claim.Attempt {
			t.Fatalf("repaired exact DLQ identity = %+v, %v", item, err)
		}
		var exactRows int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dead_letter
			WHERE run_id = $1 AND step_name = $2 AND step_seq = $3 AND step_attempt = $4`,
			repairRunID, "hash-send", 9, claim.Attempt).Scan(&exactRows); err != nil {
			t.Fatal(err)
		}
		if exactRows != 1 {
			t.Fatalf("exact DLQ rows = %d, want 1", exactRows)
		}
		blocked, err := j.ClaimStepAttemptSeq(ctx, repairRunID, "hash-send", 9, 1, "idem-repair", "input-repair")
		if err != nil || !blocked.Exhausted || blocked.Attempt != claim.Attempt {
			t.Fatalf("repaired closure fence = %+v, %v", blocked, err)
		}
		if attempts, err := j.AttemptCountSeq(ctx, repairRunID, "hash-send", 9); err != nil || attempts != 1 {
			t.Fatalf("repair allocated attempts = %d, %v; want 1", attempts, err)
		}
	})

	t.Run("fences stale and duplicate owners during exact redrive recovery", func(t *testing.T) {
		if err := j.CreateRun(ctx, redriveRunID, wfID, "webhook", json.RawMessage(`{"event_id":"redrive"}`)); err != nil {
			t.Fatal(err)
		}
		claim, err := j.ClaimStepAttemptSeq(ctx, redriveRunID, "hash-send", 7, 1, "idem-redrive", "input-redrive")
		if err != nil {
			t.Fatal(err)
		}
		deadLettered, err := j.FinalizeStepAttemptSeq(ctx, redriveRunID, "hash-send", 7, claim.Attempt, nil, "permanent", false)
		if err != nil || !deadLettered {
			t.Fatalf("seed exact dead letter = %v, %v", deadLettered, err)
		}
		if err := j.MarkRunFinished(ctx, redriveRunID, "failed_dlq"); err != nil {
			t.Fatal(err)
		}
		item, err := j.FindDeadLetterByRun(ctx, redriveRunID)
		if err != nil || item.StepSeq == nil || item.StepAttempt == nil {
			t.Fatalf("seed exact DLQ item = %+v, %v", item, err)
		}
		claimed, err := j.StartDeadLetterRetryQueuedItem(ctx, redriveRunID, item.ID)
		if err != nil || !claimed {
			t.Fatalf("authorize queued exact redrive = %v, %v", claimed, err)
		}

		staleOwner, err := newLeaseOwner("pg-stale")
		if err != nil {
			t.Fatal(err)
		}
		currentOwner, err := newLeaseOwner("pg-current")
		if err != nil {
			t.Fatal(err)
		}
		// Claim only this synthetic row so an opt-in database containing other
		// queued fixtures is not disturbed. Replacing the opaque owner models the
		// generation change made by expiry/reclaim while retaining the exact
		// production lease predicate exercised by recovery.
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		res, err := tx.ExecContext(ctx, `UPDATE runs SET status = 'running', started_at = $1
			WHERE id = $2 AND status = 'queued'`, time.Now().UTC(), redriveRunID)
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("claim redrive run rows = %d, want 1", n)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO leases (run_id, worker_id, expires_at) VALUES ($1, $2, $3)`,
			redriveRunID, staleOwner, time.Now().UTC().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		res, err = tx.ExecContext(ctx, `UPDATE leases SET worker_id = $1 WHERE run_id = $2 AND worker_id = $3`,
			currentOwner, redriveRunID, staleOwner)
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("replace lease generation rows = %d, want 1", n)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := j.VerifyLeaseOwner(ctx, redriveRunID, staleOwner); !errors.Is(err, ErrLeaseOwnershipLost) {
			t.Fatalf("stale generation preflight = %v, want ownership loss", err)
		}
		if err := j.VerifyLeaseOwner(ctx, redriveRunID, currentOwner); err != nil {
			t.Fatalf("current generation preflight: %v", err)
		}

		type recoveryResult struct {
			owner     string
			recovered bool
			err       error
		}
		raceCtx, raceCancel := context.WithTimeout(ctx, 15*time.Second)
		defer raceCancel()
		start := make(chan struct{})
		results := make(chan recoveryResult, 3)
		for _, owner := range []string{staleOwner, currentOwner, currentOwner} {
			owner := owner
			go func() {
				<-start
				recovered, recoverErr := j.RecoverOwnedPendingDeadLetterRedrive(raceCtx, redriveRunID, owner)
				results <- recoveryResult{owner: owner, recovered: recovered, err: recoverErr}
			}()
		}
		close(start)

		currentWins := 0
		currentFenced := 0
		staleFenced := 0
		var unexpected []recoveryResult
		for i := 0; i < 3; i++ {
			result := <-results
			switch result.owner {
			case staleOwner:
				if result.recovered || !errors.Is(result.err, ErrLeaseOwnershipLost) {
					unexpected = append(unexpected, result)
					continue
				}
				staleFenced++
			case currentOwner:
				if result.recovered && result.err == nil {
					currentWins++
				} else if !result.recovered && errors.Is(result.err, ErrLeaseOwnershipLost) {
					currentFenced++
				} else {
					unexpected = append(unexpected, result)
				}
			}
		}
		if len(unexpected) != 0 {
			t.Fatalf("unexpected concurrent recovery results: %+v", unexpected)
		}
		if currentWins != 1 || currentFenced != 1 || staleFenced != 1 {
			t.Fatalf("recovery arbitration: current wins=%d fenced=%d stale fenced=%d", currentWins, currentFenced, staleFenced)
		}

		run, err := j.GetRun(ctx, redriveRunID)
		if err != nil || run.Status != "failed_dlq" || run.FinishedAt.IsZero() {
			t.Fatalf("recovered redrive run = %+v, %v", run, err)
		}
		state, err := j.LatestStepAttemptSeq(ctx, redriveRunID, "hash-send", 7)
		if err != nil || state.Status != StatusFailed || state.Attempt != claim.Attempt {
			t.Fatalf("recovered exact redrive attempt = %+v, %v", state, err)
		}
		if recoveredItem, err := j.GetDeadLetterItem(ctx, item.ID); err != nil || recoveredItem.RunID != redriveRunID {
			t.Fatalf("recovery preserved selected DLQ = %+v, %v", recoveredItem, err)
		}
		var leases int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM leases WHERE run_id = $1`, redriveRunID).Scan(&leases); err != nil {
			t.Fatal(err)
		}
		if leases != 0 {
			t.Fatalf("recovered redrive leases = %d, want 0", leases)
		}
		if claimed, err := j.StartDeadLetterRetryQueuedItem(ctx, redriveRunID, item.ID); err != nil || !claimed {
			t.Fatalf("recovered exact item cannot be re-authorized = %v, %v", claimed, err)
		}
	})
}
