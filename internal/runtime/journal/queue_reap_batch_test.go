package journal

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// seedReapBatch creates real running runs with exact lease generations. Using
// distinct expiry times lets the assertions distinguish the oldest batch from
// a merely arbitrary bounded subset.
func seedReapBatch(t *testing.T, ctx context.Context, j *Journal, workflowID, prefix string) (string, string) {
	t.Helper()
	base := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Millisecond)
	for i := 0; i < expiredLeaseReapBatch*2+3; i++ {
		runID := fmt.Sprintf("%s_%03d", prefix, i)
		if err := j.CreateRun(ctx, runID, workflowID, "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatalf("create expired run %d: %v", i, err)
		}
		if _, err := j.db.ExecContext(ctx, j.bind(`INSERT INTO leases (run_id, worker_id, expires_at)
			VALUES ($1, $2, $3)`), runID, "owner-"+runID, j.formatTime(base.Add(time.Duration(i)*time.Millisecond))); err != nil {
			t.Fatalf("insert expired lease %d: %v", i, err)
		}
	}
	liveRunID := prefix + "_renewed"
	liveOwner := "owner-" + liveRunID
	if err := j.CreateRun(ctx, liveRunID, workflowID, "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("create renewed run: %v", err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`INSERT INTO leases (run_id, worker_id, expires_at)
		VALUES ($1, $2, $3)`), liveRunID, liveOwner, j.formatTime(time.Now().UTC().Add(time.Minute))); err != nil {
		t.Fatalf("insert live lease: %v", err)
	}
	if err := j.ExtendLease(ctx, liveRunID, liveOwner, time.Hour); err != nil {
		t.Fatalf("renew live lease: %v", err)
	}
	return liveRunID, liveOwner
}

func assertReapBatchDrains(t *testing.T, ctx context.Context, j *Journal, prefix, liveRunID, liveOwner string) {
	t.Helper()
	for tick, want := range []int64{expiredLeaseReapBatch, expiredLeaseReapBatch, 3, 0} {
		n, err := j.ReapExpiredLeases(ctx)
		if err != nil || n != want {
			t.Fatalf("reap tick %d = %d, %v; want %d", tick+1, n, err, want)
		}
		for _, check := range []struct {
			index  int
			status string
		}{
			{0, "queued"},
			{expiredLeaseReapBatch - 1, "queued"},
			{expiredLeaseReapBatch, []string{"running", "queued", "queued", "queued"}[tick]},
			{expiredLeaseReapBatch*2 - 1, []string{"running", "queued", "queued", "queued"}[tick]},
			{expiredLeaseReapBatch * 2, []string{"running", "running", "queued", "queued"}[tick]},
			{expiredLeaseReapBatch*2 + 2, []string{"running", "running", "queued", "queued"}[tick]},
		} {
			runID := fmt.Sprintf("%s_%03d", prefix, check.index)
			run, err := j.GetRun(ctx, runID)
			if err != nil || run.Status != check.status {
				t.Fatalf("tick %d run %s = %q, %v; want %q", tick+1, runID, run.Status, err, check.status)
			}
		}
		if err := j.VerifyLeaseOwner(ctx, liveRunID, liveOwner); err != nil {
			t.Fatalf("tick %d invalidated renewed generation: %v", tick+1, err)
		}
		if run, err := j.GetRun(ctx, liveRunID); err != nil || run.Status != "running" {
			t.Fatalf("tick %d renewed run = %+v, %v; want running", tick+1, run, err)
		}
	}
}

func TestReapExpiredLeasesBoundsSQLiteWriterWorkAndDrains(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const prefix = "run_reap_batch_sqlite"
	liveRunID, liveOwner := seedReapBatch(t, ctx, j, "wf_1", prefix)
	// The preselect write is only a lock acquisition. Counting UPDATE events
	// verifies it never touches the entire expired backlog in SQLite.
	if _, err := j.db.ExecContext(ctx, `CREATE TABLE reap_lock_updates (n INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, `INSERT INTO reap_lock_updates (n) VALUES (0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, `CREATE TRIGGER count_reap_lock_updates
		AFTER UPDATE OF worker_id ON leases
		BEGIN UPDATE reap_lock_updates SET n = n + 1; END`); err != nil {
		t.Fatal(err)
	}
	assertReapBatchDrains(t, ctx, j, prefix, liveRunID, liveOwner)
	var writes int
	if err := j.db.QueryRowContext(ctx, `SELECT n FROM reap_lock_updates`).Scan(&writes); err != nil || writes != 3 {
		t.Fatalf("SQLite lease lock writes = %d, %v; want one per nonempty tick", writes, err)
	}
}
