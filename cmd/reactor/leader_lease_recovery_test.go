package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestLeaderLeaseRecoveryRequeuesRunsWithoutWorkers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "leader-recovery.db")
	if err := migrate.Up(ctx, log, dbURL); err != nil {
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
	j := journal.New(db, journal.EngineSQLite)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := j.EnablePayloadEncryption(ctx, key, nil); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflow(ctx, "wf_leader_recovery", "leader-recovery", "h", "0.1.0", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	// More than two journal batches expire; one run is cancelled while its
	// owner is dead, and one healthy lease must remain running.
	const expired = 257
	for i := 0; i < expired; i++ {
		id := fmt.Sprintf("run_leader_recovery_%03d", i)
		if err := j.CreateQueuedRun(ctx, id, "wf_leader_recovery", "manual", []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	const healthyID = "run_leader_recovery_healthy"
	if err := j.CreateQueuedRun(ctx, healthyID, "wf_leader_recovery", "manual", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	// A queue poll is bounded even when more runs are waiting. Fill the
	// fixture across two polls so every run has a lease before the recovery
	// check, just as a worker keeps polling when it has free slots.
	var claims []journal.RunLease
	for len(claims) < expired+1 {
		batch, err := j.ClaimQueuedRuns(ctx, "dead-worker", 256, time.Minute)
		if err != nil || len(batch) == 0 {
			t.Fatalf("claimed %d of %d runs: %v", len(claims), expired+1, err)
		}
		claims = append(claims, batch...)
	}
	if _, err := db.ExecContext(ctx, `UPDATE leases SET expires_at = ? WHERE run_id <> ?`,
		time.Now().UTC().Add(-time.Minute).Format("2006-01-02T15:04:05.000Z"), healthyID); err != nil {
		t.Fatal(err)
	}
	const cancelledID = "run_leader_recovery_000"
	if outcome, err := j.RequestRunCancel(ctx, cancelledID); err != nil || outcome != journal.CancelRequested {
		t.Fatalf("request cancellation = %q, %v", outcome, err)
	}
	if queued, err := j.CountQueued(ctx); err != nil || queued != 0 {
		t.Fatalf("pre-recovery queued = %d, %v; want zero", queued, err)
	}
	if running, err := j.CountRunning(ctx); err != nil || running != expired+1 {
		t.Fatalf("pre-recovery running = %d, %v", running, err)
	}
	// No worker reaper is running. This is exactly the scale-to-zero failure
	// mode: the leader must make the queue visible to autoscaling itself.
	// The production probe passes a native TIMESTAMPTZ parameter to Postgres.
	// SQLite stores lease timestamps as ISO text, so use its matching format.
	sqliteExpired := func(ctx context.Context) (bool, error) {
		var exists bool
		err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM leases WHERE expires_at < ?)`,
			time.Now().UTC().Format("2006-01-02T15:04:05.000Z")).Scan(&exists)
		return exists, err
	}
	more, err := drainExpiredRunLeases(ctx, log, j, sqliteExpired)
	if err != nil || more {
		t.Fatalf("leader recovery remaining=%v, err=%v", more, err)
	}
	if queued, err := j.CountQueued(ctx); err != nil || queued != expired-1 {
		t.Fatalf("recovered queue = %d, %v; want %d", queued, err, expired-1)
	}
	if running, err := j.CountRunning(ctx); err != nil || running != 1 {
		t.Fatalf("running after recovery = %d, %v; want healthy lease only", running, err)
	}
	if run, err := j.GetRun(ctx, cancelledID); err != nil || run.Status != "cancelled" {
		t.Fatalf("cancelled run status = %q, %v", run.Status, err)
	}
	if run, err := j.GetRun(ctx, healthyID); err != nil || run.Status != "running" {
		t.Fatalf("healthy run status = %q, %v", run.Status, err)
	}
	if err := j.VerifyLeaseOwner(ctx, claims[0].RunID, claims[0].Owner); !errors.Is(err, journal.ErrLeaseOwnershipLost) {
		t.Fatalf("dead worker retained old lease: %v", err)
	}
	// A worker reaper arriving after the leader cannot requeue those runs a
	// second time; the exact expired lease generations have been deleted.
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 0 {
		t.Fatalf("worker follow-up reaped %d duplicate runs: %v", n, err)
	}
}

type syntheticLeaseBacklog struct {
	expired int
	calls   int
}

func (s *syntheticLeaseBacklog) reap(context.Context) (int64, error) {
	s.calls++
	n := min(s.expired, 128)
	s.expired -= n
	return int64(n), nil
}

type syntheticLeaseReaper struct{ backlog *syntheticLeaseBacklog }

func (s syntheticLeaseReaper) ReapExpiredLeases(ctx context.Context) (int64, error) {
	return s.backlog.reap(ctx)
}

func TestLeaderLeaseRecoveryBoundsOnePassAndContinuesBacklog(t *testing.T) {
	backlog := &syntheticLeaseBacklog{expired: leaderLeaseReapMaxBatches*128 + 1}
	probe := func(context.Context) (bool, error) { return backlog.expired > 0, nil }
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	more, err := drainExpiredRunLeases(context.Background(), log, syntheticLeaseReaper{backlog}, probe)
	if err != nil || !more || backlog.calls != leaderLeaseReapMaxBatches || backlog.expired != 1 {
		t.Fatalf("bounded pass: more=%v err=%v calls=%d expired=%d", more, err, backlog.calls, backlog.expired)
	}
	more, err = drainExpiredRunLeases(context.Background(), log, syntheticLeaseReaper{backlog}, probe)
	if err != nil || more || backlog.expired != 0 {
		t.Fatalf("catch-up pass: more=%v err=%v expired=%d", more, err, backlog.expired)
	}
}
