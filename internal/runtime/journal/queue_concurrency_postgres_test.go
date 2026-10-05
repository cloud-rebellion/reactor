package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
)

// ClaimQueuedRuns must recheck the tenant's current running count after a
// concurrent transaction changes it. An isolated PostgreSQL URL is required
// because SQLite's single writer cannot reproduce this MVCC race.
func TestPostgresClaimRechecksTenantCapacityAfterLockWait(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL to run the PostgreSQL tenant-claim race")
	}
	ctx := context.Background()
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), rawURL); err != nil {
		t.Fatal(err)
	}
	db, engine, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if engine != migrate.EnginePostgres {
		t.Fatalf("test URL selected %s, want postgres", engine)
	}
	j := New(db, EnginePostgres)
	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantID := "claim-cap-" + suffix
	wfQueued := "wf_claim_queue_" + suffix
	wfBusy := "wf_claim_busy_" + suffix
	runQueued := "run_claim_queue_" + suffix
	runBusy := "run_claim_busy_" + suffix
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM runs WHERE id IN ($1,$2)`, runQueued, runBusy)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM workflows WHERE id IN ($1,$2)`, wfQueued, wfBusy)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE tenant_id = $1`, tenantID)
	}()
	if err := j.UpsertTenant(ctx, Tenant{TenantID: tenantID, MaxConcurrentRuns: 1}); err != nil {
		t.Fatal(err)
	}
	mkWorkflowTenant(t, j, ctx, wfQueued, tenantID)
	mkWorkflowTenant(t, j, ctx, wfBusy, tenantID)
	if err := j.CreateQueuedRun(ctx, runQueued, wfQueued, "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}

	// Hold the tenant policy row. The claimer can select and lock the queued
	// run, but must wait here before changing it to running.
	policyTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer policyTx.Rollback()
	var lockedID string
	if err := policyTx.QueryRowContext(ctx, `SELECT tenant_id FROM tenants WHERE tenant_id = $1 FOR UPDATE`, tenantID).Scan(&lockedID); err != nil {
		t.Fatal(err)
	}
	type result struct {
		claims []RunLease
		err    error
	}
	claimCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	done := make(chan result, 1)
	go func() {
		claims, err := j.ClaimQueuedRuns(claimCtx, "capacity-race-worker", 1, time.Minute)
		done <- result{claims: claims, err: err}
	}()
	// Observe the actual PostgreSQL lock wait, rather than relying on a sleep
	// or assuming the goroutine reached the boundary before the next INSERT.
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case early := <-done:
			t.Fatalf("claim crossed locked tenant admission: claims=%v err=%v", early.claims, early.err)
		default:
		}
		var waiting bool
		err := db.QueryRowContext(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity
			WHERE pid <> pg_backend_pid() AND wait_event_type = 'Lock'
			AND query LIKE '%FROM tenants WHERE tenant_id = $1 FOR UPDATE%'
		)`).Scan(&waiting)
		if err != nil {
			t.Fatalf("inspect PostgreSQL tenant lock wait: %v", err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("claimer did not reach the tenant row lock")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// This run belongs to another workflow, so the waiting claimer's
	// workflow-row lock does not block the insert. It consumes the last slot
	// before the tenant lock is released.
	if _, err := policyTx.ExecContext(ctx, `INSERT INTO runs
		(id, workflow_id, tenant_id, trigger_kind, trigger_meta, status, started_at, created_at)
		VALUES ($1,$2,$3,'manual','{}'::jsonb,'running',NOW(),NOW())`, runBusy, wfBusy, tenantID); err != nil {
		t.Fatal(err)
	}
	if err := policyTx.Commit(); err != nil {
		t.Fatal(err)
	}
	claimed := <-done
	if claimed.err != nil || len(claimed.claims) != 0 {
		t.Fatalf("claim after tenant cap filled = %v, %v; want no claim", claimed.claims, claimed.err)
	}
	if run, err := j.GetRun(ctx, runQueued); err != nil || run.Status != "queued" {
		t.Fatalf("rejected queue run state = %+v, %v", run, err)
	}
	var running int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs WHERE tenant_id = $1 AND status = 'running'`, tenantID).Scan(&running); err != nil || running != 1 {
		t.Fatalf("tenant running count = %d, %v; want 1", running, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE runs SET status = 'succeeded', finished_at = NOW() WHERE id = $1`, runBusy); err != nil {
		t.Fatal(err)
	}
	claims, err := j.ClaimQueuedRuns(ctx, "capacity-after-release", 1, time.Minute)
	if err != nil || len(claims) != 1 || claims[0].RunID != runQueued {
		t.Fatalf("claim after capacity released = %v, %v", claims, err)
	}
}

// Two workers can lock different queued run rows for the same tenant. Their
// candidate sets do not overlap, so SKIP LOCKED alone cannot protect the
// tenant-wide limit. The admission lock must serialize their final decisions.
func TestPostgresConcurrentTenantClaimsShareOneSlot(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL to run the PostgreSQL concurrent-claim contract")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), rawURL); err != nil {
		t.Fatal(err)
	}
	db, engine, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if engine != migrate.EnginePostgres {
		t.Fatalf("test URL selected %s, want postgres", engine)
	}
	j := New(db, EnginePostgres)
	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantID := "claim-share-" + suffix
	wfIDs := []string{"wf_claim_left_" + suffix, "wf_claim_right_" + suffix}
	runIDs := []string{"run_claim_left_" + suffix, "run_claim_right_" + suffix}
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM runs WHERE id IN ($1,$2)`, runIDs[0], runIDs[1])
		_, _ = db.ExecContext(context.Background(), `DELETE FROM workflows WHERE id IN ($1,$2)`, wfIDs[0], wfIDs[1])
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE tenant_id = $1`, tenantID)
	}()
	if err := j.UpsertTenant(ctx, Tenant{TenantID: tenantID, MaxConcurrentRuns: 1}); err != nil {
		t.Fatal(err)
	}
	for i := range wfIDs {
		mkWorkflowTenant(t, j, ctx, wfIDs[i], tenantID)
		if err := j.CreateQueuedRun(ctx, runIDs[i], wfIDs[i], "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}

	type result struct {
		claimed bool
		err     error
	}
	ready := make(chan struct{}, 2)
	start := make(chan struct{})
	done := make(chan result, 2)
	for _, runID := range runIDs {
		go func(runID string) {
			tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
			if err != nil {
				done <- result{err: err}
				return
			}
			defer tx.Rollback()
			var lockedID string
			if err := tx.QueryRowContext(ctx, `SELECT id FROM runs WHERE id = $1 FOR UPDATE`, runID).Scan(&lockedID); err != nil {
				done <- result{err: err}
				return
			}
			ready <- struct{}{}
			<-start
			admitted, err := j.admitLockedTenantClaimsTx(ctx, tx, []string{runID}, map[string]string{runID: tenantID}, 1)
			if err != nil {
				done <- result{err: err}
				return
			}
			if len(admitted) == 1 {
				if _, err := tx.ExecContext(ctx, `UPDATE runs SET status = 'running', started_at = NOW() WHERE id = $1`, runID); err != nil {
					done <- result{err: err}
					return
				}
			}
			if err := tx.Commit(); err != nil {
				done <- result{err: err}
				return
			}
			done <- result{claimed: len(admitted) == 1}
		}(runID)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-ready:
		case early := <-done:
			t.Fatalf("worker could not lock its distinct queued row: %v", early.err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	close(start)
	claimedCount := 0
	for i := 0; i < 2; i++ {
		select {
		case outcome := <-done:
			if outcome.err != nil {
				t.Fatal(outcome.err)
			}
			if outcome.claimed {
				claimedCount++
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if claimedCount != 1 {
		t.Fatalf("concurrent tenant claims admitted %d, want exactly 1", claimedCount)
	}
	var running, queued int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FILTER (WHERE status = 'running'), COUNT(*) FILTER (WHERE status = 'queued')
		FROM runs WHERE tenant_id = $1 AND id IN ($2,$3)`, tenantID, runIDs[0], runIDs[1]).Scan(&running, &queued); err != nil {
		t.Fatal(err)
	}
	if running != 1 || queued != 1 {
		t.Fatalf("concurrent tenant state: running=%d queued=%d, want 1/1", running, queued)
	}
}

func TestPostgresUnlimitedTenantClaimPolicyLockIsShared(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL to run the PostgreSQL unlimited-tenant lock contract")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), rawURL); err != nil {
		t.Fatal(err)
	}
	db, engine, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if engine != migrate.EnginePostgres {
		t.Fatalf("test URL selected %s, want postgres", engine)
	}
	j := New(db, EnginePostgres)
	tenantID := fmt.Sprintf("claim-unlimited-%d", time.Now().UTC().UnixNano())
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE tenant_id = $1`, tenantID)
	}()
	if err := j.UpsertTenant(ctx, Tenant{TenantID: tenantID}); err != nil {
		t.Fatal(err)
	}
	tx1, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer tx1.Rollback()
	tenant, exists, becameCapped, err := j.lockTenantForClaimTx(ctx, tx1, tenantID)
	if err != nil || !exists || becameCapped || tenant.MaxConcurrentRuns != 0 {
		t.Fatalf("unlimited tenant lock = %+v, exists=%t becameCapped=%t err=%v", tenant, exists, becameCapped, err)
	}
	tx2, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer tx2.Rollback()
	var concurrentID string
	if err := tx2.QueryRowContext(ctx, `SELECT tenant_id FROM tenants WHERE tenant_id = $1 FOR SHARE NOWAIT`, tenantID).Scan(&concurrentID); err != nil {
		t.Fatalf("second unlimited claim could not acquire compatible policy lock: %v", err)
	}
}

// A claim that saw an unlimited tenant in its advisory candidate query must
// not run past a policy edit that adds a cap while the claim waits. It skips
// that tenant this poll and lets the next claim take the exclusive-lock path.
func TestPostgresClaimSkipsTenantNewlyCappedDuringPolicyEdit(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL to run the PostgreSQL cap-edit race")
	}
	ctx := context.Background()
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), rawURL); err != nil {
		t.Fatal(err)
	}
	db, engine, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if engine != migrate.EnginePostgres {
		t.Fatalf("test URL selected %s, want postgres", engine)
	}
	j := New(db, EnginePostgres)
	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantID := "claim-edit-" + suffix
	wfQueued := "wf_claim_edit_queue_" + suffix
	wfBusy := "wf_claim_edit_busy_" + suffix
	runQueued := "run_claim_edit_queue_" + suffix
	runBusy := "run_claim_edit_busy_" + suffix
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM runs WHERE id IN ($1,$2)`, runQueued, runBusy)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM workflows WHERE id IN ($1,$2)`, wfQueued, wfBusy)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE tenant_id = $1`, tenantID)
	}()
	if err := j.UpsertTenant(ctx, Tenant{TenantID: tenantID}); err != nil {
		t.Fatal(err)
	}
	mkWorkflowTenant(t, j, ctx, wfQueued, tenantID)
	mkWorkflowTenant(t, j, ctx, wfBusy, tenantID)
	if err := j.CreateQueuedRun(ctx, runQueued, wfQueued, "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	policyTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer policyTx.Rollback()
	if _, err := policyTx.ExecContext(ctx, `UPDATE tenants SET max_concurrent_runs = 1 WHERE tenant_id = $1`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := policyTx.ExecContext(ctx, `INSERT INTO runs
		(id, workflow_id, tenant_id, trigger_kind, trigger_meta, status, started_at, created_at)
		VALUES ($1,$2,$3,'manual','{}'::jsonb,'running',NOW(),NOW())`, runBusy, wfBusy, tenantID); err != nil {
		t.Fatal(err)
	}
	type result struct {
		claims []RunLease
		err    error
	}
	claimCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	done := make(chan result, 1)
	go func() {
		claims, err := j.ClaimQueuedRuns(claimCtx, "cap-edit-worker", 1, time.Minute)
		done <- result{claims: claims, err: err}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case early := <-done:
			t.Fatalf("claim crossed concurrent cap edit: claims=%v err=%v", early.claims, early.err)
		default:
		}
		var waiting bool
		err := db.QueryRowContext(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity
			WHERE pid <> pg_backend_pid() AND wait_event_type = 'Lock'
			AND query LIKE '%FROM tenants WHERE tenant_id = $1 FOR SHARE%'
		)`).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("claimer did not wait on the concurrent policy edit")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := policyTx.Commit(); err != nil {
		t.Fatal(err)
	}
	claimed := <-done
	if claimed.err != nil || len(claimed.claims) != 0 {
		t.Fatalf("claim after cap edit = %v, %v; want no claim", claimed.claims, claimed.err)
	}
	if run, err := j.GetRun(ctx, runQueued); err != nil || run.Status != "queued" {
		t.Fatalf("newly capped queue run state = %+v, %v", run, err)
	}
}
