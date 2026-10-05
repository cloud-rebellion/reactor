package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/dispatcher"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/cancelreg"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

type workerClaimNotice struct{ claimFailed chan struct{} }

func (w workerClaimNotice) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("worker: claim failed")) {
		select {
		case w.claimFailed <- struct{}{}:
		default:
		}
	}
	return len(p), nil
}

func TestWorkerShutdownInterruptsFailedClaimBackoff(t *testing.T) {
	ctx := context.Background()
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "worker-claim-shutdown.db")
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(ctx, quiet, dbURL); err != nil {
		t.Fatal(err)
	}
	db, engine, err := migrate.Open(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if engine != migrate.EngineSQLite {
		t.Fatalf("opened engine %q, want SQLite", engine)
	}
	// Heartbeat registration remains valid, but the queue claim must fail.
	// The worker should enter its error backoff and still honor SIGTERM's
	// cancellation immediately rather than sleeping for the poll interval.
	if _, err := db.ExecContext(ctx, `DROP TABLE workflows`); err != nil {
		t.Fatal(err)
	}
	notice := workerClaimNotice{claimFailed: make(chan struct{}, 1)}
	log := slog.New(slog.NewTextHandler(notice, nil))
	deps := &serveDeps{
		db:         db,
		journal:    journal.New(db, journal.EngineSQLite),
		dispatcher: &dispatcher.Dispatcher{},
		cancels:    cancelreg.New(),
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runWorkerLoop(runCtx, log, deps, workerOpts{
			concurrency: 1, leaseTTL: time.Minute,
			pollInterval: 5 * time.Second, drainTimeout: time.Second,
		})
	}()
	select {
	case <-notice.claimFailed:
	case err := <-done:
		t.Fatalf("worker exited before claim backoff: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not enter claim-error backoff")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("worker shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker remained in claim-error backoff after cancellation")
	}
}

func TestWorkerShutdownStopsLaunchingReturnedClaimBatch(t *testing.T) {
	claims := []journal.RunLease{
		{RunID: "run_first", Owner: "owner_first"},
		{RunID: "run_second", Owner: "owner_second"},
		{RunID: "run_third", Owner: "owner_third"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	var started []string
	skipped := launchClaimedBatch(ctx, claims, func(claim journal.RunLease) {
		started = append(started, claim.RunID)
		cancel() // SIGTERM arrives after the first claim begins execution.
	})
	if len(started) != 1 || started[0] != "run_first" || skipped != 2 {
		t.Fatalf("mid-batch shutdown started %v and skipped %d; want first only, two recoverable", started, skipped)
	}
	started = nil
	if skipped := launchClaimedBatch(ctx, claims, func(claim journal.RunLease) {
		started = append(started, claim.RunID)
	}); skipped != len(claims) || len(started) != 0 {
		t.Fatalf("pre-cancelled batch started %v and skipped %d; want no execution", started, skipped)
	}
}

func TestWorkerReturnsUnstartedClaimBatchWithoutWaitingForExpiry(t *testing.T) {
	ctx := context.Background()
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "worker-return-unstarted.db")
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(ctx, quiet, dbURL); err != nil {
		t.Fatal(err)
	}
	db, engine, err := migrate.Open(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j := journal.New(db, journal.Engine(engine))
	if err := j.CreateWorkflow(ctx, "wf_shutdown", "worker-shutdown", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"run_shutdown_a", "run_shutdown_b"} {
		if err := j.CreateQueuedRun(ctx, id, "wf_shutdown", "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	claims, err := j.ClaimQueuedRuns(ctx, "stopping-worker", 2, time.Hour)
	if err != nil || len(claims) != 2 {
		t.Fatalf("batch claim = %+v, %v", claims, err)
	}
	stopping, cancel := context.WithCancel(ctx)
	cancel()
	if skipped := launchClaimedBatch(stopping, claims, func(journal.RunLease) {
		t.Fatal("started work after shutdown")
	}); skipped != len(claims) {
		t.Fatalf("skipped = %d, want %d", skipped, len(claims))
	}
	returnUnstartedClaims(quiet, j, claims)
	replacement, err := j.ClaimQueuedRuns(ctx, "replacement-worker", 2, time.Minute)
	if err != nil || len(replacement) != 2 {
		t.Fatalf("replacement before original lease expired = %+v, %v", replacement, err)
	}
}
