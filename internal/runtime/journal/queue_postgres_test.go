package journal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
)

func TestReturnUnstartedLeasePostgres(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL to run the PostgreSQL unstarted-claim contract")
	}
	ctx := context.Background()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(ctx, quiet, rawURL); err != nil {
		t.Fatal(err)
	}
	db, engine, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if engine != migrate.EnginePostgres {
		t.Fatalf("test database engine = %s, want PostgreSQL", engine)
	}
	j := New(db, EnginePostgres)
	suffix := strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	wfID := "wf_unstarted_pg_" + suffix
	runID := "run_unstarted_pg_" + suffix
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM runs WHERE id = $1`, runID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM workflows WHERE id = $1`, wfID)
	}()
	if err := j.CreateWorkflow(ctx, wfID, "unstarted-pg-"+suffix, "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateQueuedRun(ctx, runID, wfID, "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	first, err := j.ClaimQueuedRuns(ctx, "stopping-worker", 1, time.Hour)
	if err != nil || len(first) != 1 || first[0].RunID != runID {
		t.Fatalf("first claim = %+v, %v", first, err)
	}
	if err := j.ReturnUnstartedLease(ctx, runID, first[0].Owner); err != nil {
		t.Fatal(err)
	}
	second, err := j.ClaimQueuedRuns(ctx, "replacement-worker", 1, time.Minute)
	if err != nil || len(second) != 1 || second[0].RunID != runID || second[0].Owner == first[0].Owner {
		t.Fatalf("replacement claim before original hour-long expiry = %+v, %v", second, err)
	}
	if err := j.ReturnUnstartedLease(ctx, runID, first[0].Owner); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("stale claim changed replacement = %v", err)
	}
	if err := j.ExtendLease(ctx, runID, second[0].Owner, time.Minute); err != nil {
		t.Fatalf("replacement lost lease: %v", err)
	}
}

// TestRunLeaseGenerationPostgres exercises the production SQL path, including
// FOR UPDATE SKIP LOCKED reaping. CI/developers opt in with an isolated
// PostgreSQL database; SQLite remains the default self-contained suite.
func TestRunLeaseGenerationPostgres(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL to run the PostgreSQL run-lease contract")
	}
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(ctx, log, rawURL); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}
	db, engine, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if engine != migrate.EnginePostgres {
		t.Fatalf("REACTOR_TEST_POSTGRES_URL selected %s, want postgres", engine)
	}
	j := New(db, EnginePostgres)
	suffix := strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	wfID := "wf_lease_pg_" + suffix
	runID := "run_lease_pg_" + suffix
	runCancelID := "run_lease_cancel_pg_" + suffix
	runRaceID := "run_lease_race_pg_" + suffix
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM runs WHERE id IN ($1, $2, $3)`, runID, runCancelID, runRaceID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM workflows WHERE id = $1`, wfID)
	}()
	if err := j.CreateWorkflow(ctx, wfID, "lease-pg-"+suffix, "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateQueuedRun(ctx, runID, wfID, "webhook", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}

	first, err := j.ClaimQueuedRuns(ctx, "worker-a", 1, time.Minute)
	if err != nil || len(first) != 1 || first[0].RunID != runID {
		t.Fatalf("first postgres claim = %v, %v", first, err)
	}
	if err := j.ExtendLease(ctx, runID, first[0].Owner, time.Minute); err != nil {
		t.Fatal(err)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 0 {
		t.Fatalf("postgres reaped renewed lease = %d, %v", n, err)
	}
	if err := j.ExtendLease(ctx, runID, first[0].Owner, -time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := j.ExtendLease(ctx, runID, first[0].Owner, time.Minute); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("postgres expired renewal = %v, want ownership loss", err)
	}
	if err := j.VerifyLeaseOwner(ctx, runID, first[0].Owner); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("postgres expired verification = %v, want ownership loss", err)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("postgres expired reap = %d, %v", n, err)
	}
	second, err := j.ClaimQueuedRuns(ctx, "worker-b", 1, time.Minute)
	if err != nil || len(second) != 1 || second[0].RunID != runID {
		t.Fatalf("replacement postgres claim = %v, %v", second, err)
	}
	if err := j.FinalizeOwnedRun(ctx, runID, first[0].Owner, "succeeded"); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("stale postgres finalization = %v, want ownership loss", err)
	}
	if err := j.ReleaseLease(ctx, runID, first[0].Owner); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("stale postgres release = %v, want ownership loss", err)
	}
	if err := j.FinalizeOwnedRun(ctx, runID, second[0].Owner, "succeeded"); err != nil {
		t.Fatalf("replacement postgres finalization: %v", err)
	}

	// An operator cancellation accepted while the owning worker is dead must
	// be terminalized by the reaper, never turned back into runnable work.
	if err := j.CreateQueuedRun(ctx, runCancelID, wfID, "webhook", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	dead, err := j.ClaimQueuedRuns(ctx, "dead-worker", 1, -time.Minute)
	if err != nil || len(dead) != 1 || dead[0].RunID != runCancelID {
		t.Fatalf("dead-owner postgres claim = %v, %v", dead, err)
	}
	if outcome, err := j.RequestRunCancel(ctx, runCancelID); err != nil || outcome != CancelRequested {
		t.Fatalf("dead-owner postgres cancel = %q, %v", outcome, err)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 0 {
		t.Fatalf("dead-owner postgres cancel reap = %d, %v; want no requeue", n, err)
	}
	if run, err := j.GetRun(ctx, runCancelID); err != nil || run.Status != "cancelled" || run.FinishedAt.IsZero() {
		t.Fatalf("dead-owner postgres cancellation state = %+v, %v", run, err)
	}
	if replacement, err := j.ClaimQueuedRuns(ctx, "replacement", 1, time.Minute); err != nil || len(replacement) != 0 {
		t.Fatalf("dead-owner cancelled run became postgres work = %v, %v", replacement, err)
	}

	// Exercise the production row-lock ordering between fair queue admission
	// and queued cancellation. Either operation may linearize first, but an
	// accepted cancellation may not be lost behind a newly spawned child.
	if err := j.CreateQueuedRun(ctx, runRaceID, wfID, "webhook", json.RawMessage(`{}`)); err != nil {
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
		claims, err := j.ClaimQueuedRuns(context.Background(), "race-worker", 1, time.Minute)
		claimDone <- claimResult{claims: claims, err: err}
	}()
	go func() {
		<-start
		outcome, err := j.RequestRunCancel(context.Background(), runRaceID)
		cancelDone <- cancelResult{outcome: outcome, err: err}
	}()
	close(start)
	claimed := <-claimDone
	cancelled := <-cancelDone
	if claimed.err != nil || cancelled.err != nil {
		t.Fatalf("postgres claim/cancel race errors: claim=%v cancel=%v", claimed.err, cancelled.err)
	}
	tracedRun, err := j.GetRun(ctx, runRaceID)
	if err != nil {
		t.Fatal(err)
	}
	switch cancelled.outcome {
	case CancelDone:
		if len(claimed.claims) != 0 || tracedRun.Status != "cancelled" {
			t.Fatalf("postgres cancel-first race: claims=%v run=%+v", claimed.claims, tracedRun)
		}
	case CancelRequested:
		if len(claimed.claims) != 1 || claimed.claims[0].RunID != runRaceID || tracedRun.Status != "running" {
			t.Fatalf("postgres claim-first race: claims=%v run=%+v", claimed.claims, tracedRun)
		}
		var requested any
		if err := db.QueryRowContext(ctx, `SELECT cancel_requested FROM runs WHERE id = $1`, runRaceID).Scan(&requested); err != nil {
			t.Fatal(err)
		}
		if !parseBool(requested) {
			t.Fatal("postgres claim-first race lost cancel_requested")
		}
		if err := j.FinalizeOwnedRun(ctx, runRaceID, claimed.claims[0].Owner, "cancelled"); err != nil {
			t.Fatalf("postgres race cleanup: %v", err)
		}
	default:
		t.Fatalf("postgres race unexpected cancel outcome %q", cancelled.outcome)
	}
}
