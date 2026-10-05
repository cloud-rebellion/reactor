package journal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
)

// A finalizer can wait on the lease row while another transaction changes
// its deadline, or wait on the run row after its lease was checked. Both waits
// must leave the terminal transaction unable to commit past the deadline.
func TestPostgresExpiredOwnedOperationsWaitingForLocks(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for the PostgreSQL lease-expiry race")
	}
	engine, err := migrate.EngineFromURL(rawURL)
	if err != nil || engine != migrate.EnginePostgres {
		t.Fatalf("test URL must be PostgreSQL: engine=%q err=%v", engine, err)
	}
	u, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(strings.ToLower(strings.Trim(u.Path, "/")), "test") {
		t.Fatal("PostgreSQL test database name must contain test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	base, _, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	schema := fmt.Sprintf("lease_expiry_%d", time.Now().UnixNano())
	if _, err := base.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer base.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
	q := u.Query()
	q.Set("search_path", schema)
	q.Set("application_name", schema)
	u.RawQuery = q.Encode()
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), u.String()); err != nil {
		t.Fatalf("migrate isolated PostgreSQL schema: %v", err)
	}
	db, engine, err := migrate.Open(u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j := New(db, EnginePostgres)
	if err := j.CreateWorkflow(ctx, "wf_expiry", "lease-expiry", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateQueuedRun(ctx, "run_expiry", "wf_expiry", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	claims, err := j.ClaimQueuedRuns(ctx, "waiting-worker", 1, time.Minute)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim = %+v, %v", claims, err)
	}
	owner := claims[0].Owner

	holder, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	var heldOwner string
	if err := holder.QueryRowContext(ctx, `SELECT worker_id FROM leases WHERE run_id = $1 FOR UPDATE`, "run_expiry").Scan(&heldOwner); err != nil || heldOwner != owner {
		t.Fatalf("lock lease = %q, %v", heldOwner, err)
	}
	done := make(chan error, 1)
	go func() { done <- j.FinalizeOwnedRun(ctx, "run_expiry", owner, "succeeded") }()
	for {
		select {
		case err := <-done:
			t.Fatalf("finalizer returned before the lease lock was released: %v", err)
		default:
		}
		var waiting int
		err := base.QueryRowContext(ctx, `SELECT COUNT(*) FROM pg_stat_activity
			WHERE application_name = $1 AND wait_event_type = 'Lock'
			AND query LIKE '%SELECT expires_at FROM leases%' AND query LIKE '%FOR UPDATE%'`, schema).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for finalizer to reach held lease: %v", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if _, err := holder.ExecContext(ctx, `UPDATE leases SET expires_at = $1 WHERE run_id = $2`,
		j.formatTime(time.Now().UTC().Add(-time.Minute)), "run_expiry"); err != nil {
		t.Fatal(err)
	}
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrLeaseOwnershipLost) {
			t.Fatalf("finalization after lease expiry = %v, want ownership loss", err)
		}
	case <-ctx.Done():
		t.Fatalf("finalizer did not return after lease lock released: %v", ctx.Err())
	}
	if run, err := j.GetRun(ctx, "run_expiry"); err != nil || run.Status != "running" || !run.FinishedAt.IsZero() {
		t.Fatalf("expired finalizer changed run = %+v, %v", run, err)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("reap after expired finalization = %d, %v", n, err)
	}
	replacement, err := j.ClaimQueuedRuns(ctx, "replacement", 1, time.Minute)
	if err != nil || len(replacement) != 1 || replacement[0].RunID != "run_expiry" {
		t.Fatalf("replacement claim = %+v, %v", replacement, err)
	}
	if err := j.FinalizeOwnedRun(ctx, "run_expiry", replacement[0].Owner, "succeeded"); err != nil {
		t.Fatalf("valid replacement finalization: %v", err)
	}

	// This time the finalizer passes its initial lease check, then blocks on
	// the run row. Its transaction must roll back if the deadline passes while
	// it waits, even though it still holds the lease lock.
	if err := j.CreateQueuedRun(ctx, "run_late", "wf_expiry", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	late, err := j.ClaimQueuedRuns(ctx, "late-worker", 1, 2*time.Second)
	if err != nil || len(late) != 1 || late[0].RunID != "run_late" {
		t.Fatalf("late claim = %+v, %v", late, err)
	}
	var lateDeadline time.Time
	if err := db.QueryRowContext(ctx, `SELECT expires_at FROM leases WHERE run_id = $1`, "run_late").Scan(&lateDeadline); err != nil {
		t.Fatal(err)
	}
	runHolder, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runHolder.Rollback()
	var heldStatus string
	if err := runHolder.QueryRowContext(ctx, `SELECT status FROM runs WHERE id = $1 FOR UPDATE`, "run_late").Scan(&heldStatus); err != nil || heldStatus != "running" {
		t.Fatalf("lock run = %q, %v", heldStatus, err)
	}
	lateDone := make(chan error, 1)
	go func() { lateDone <- j.FinalizeOwnedRun(ctx, "run_late", late[0].Owner, "succeeded") }()
	for {
		select {
		case err := <-lateDone:
			t.Fatalf("late finalizer returned before run lock released: %v", err)
		default:
		}
		var waiting int
		err := base.QueryRowContext(ctx, `SELECT COUNT(*) FROM pg_stat_activity
			WHERE application_name = $1 AND wait_event_type = 'Lock'
			AND query LIKE '%SELECT status FROM runs%' AND query LIKE '%FOR UPDATE%'`, schema).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for finalizer to reach held run: %v", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if wait := time.Until(lateDeadline.Add(20 * time.Millisecond)); wait > 0 {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(wait):
		}
	}
	if err := runHolder.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-lateDone:
		if !errors.Is(err, ErrLeaseOwnershipLost) {
			t.Fatalf("finalization after later run-lock wait = %v, want ownership loss", err)
		}
	case <-ctx.Done():
		t.Fatalf("late finalizer did not return after run lock released: %v", ctx.Err())
	}
	if run, err := j.GetRun(ctx, "run_late"); err != nil || run.Status != "running" || !run.FinishedAt.IsZero() {
		t.Fatalf("late finalizer changed run = %+v, %v", run, err)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("reap after later run-lock wait = %d, %v", n, err)
	}
	lateReplacement, err := j.ClaimQueuedRuns(ctx, "late-replacement", 1, time.Minute)
	if err != nil || len(lateReplacement) != 1 || lateReplacement[0].RunID != "run_late" {
		t.Fatalf("late replacement claim = %+v, %v", lateReplacement, err)
	}
	if err := j.FinalizeOwnedRun(ctx, "run_late", lateReplacement[0].Owner, "succeeded"); err != nil {
		t.Fatalf("valid late replacement finalization: %v", err)
	}

	// A lease renewal may also start before expiry and wait on the exact
	// lease row until after expiry. It must not revive that generation.
	if err := j.CreateQueuedRun(ctx, "run_waiting_renew_pg", "wf_expiry", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	waiting, err := j.ClaimQueuedRuns(ctx, "renew-worker", 1, 2*time.Second)
	if err != nil || len(waiting) != 1 || waiting[0].RunID != "run_waiting_renew_pg" {
		t.Fatalf("renewal claim = %+v, %v", waiting, err)
	}
	var renewalDeadline time.Time
	if err := db.QueryRowContext(ctx, `SELECT expires_at FROM leases WHERE run_id = $1`, "run_waiting_renew_pg").Scan(&renewalDeadline); err != nil {
		t.Fatal(err)
	}
	renewHolder, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer renewHolder.Rollback()
	var heldRenewOwner string
	if err := renewHolder.QueryRowContext(ctx, `SELECT worker_id FROM leases WHERE run_id = $1 FOR UPDATE`, "run_waiting_renew_pg").Scan(&heldRenewOwner); err != nil || heldRenewOwner != waiting[0].Owner {
		t.Fatalf("lock renewal lease = %q, %v", heldRenewOwner, err)
	}
	renewDone := make(chan error, 1)
	go func() { renewDone <- j.ExtendLease(ctx, "run_waiting_renew_pg", waiting[0].Owner, time.Minute) }()
	for {
		select {
		case err := <-renewDone:
			t.Fatalf("renewal returned before lease lock release: %v", err)
		default:
		}
		var lockWaiters int
		err := base.QueryRowContext(ctx, `SELECT COUNT(*) FROM pg_stat_activity
			WHERE application_name = $1 AND wait_event_type = 'Lock'
			AND query LIKE '%SELECT expires_at FROM leases%' AND query LIKE '%FOR UPDATE%'`, schema).Scan(&lockWaiters)
		if err != nil {
			t.Fatal(err)
		}
		if lockWaiters > 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for renewal to reach held lease: %v", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if wait := time.Until(renewalDeadline.Add(20 * time.Millisecond)); wait > 0 {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(wait):
		}
	}
	if err := renewHolder.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-renewDone:
		if !errors.Is(err, ErrLeaseOwnershipLost) {
			t.Fatalf("renewal after lease-lock wait = %v, want ownership loss", err)
		}
	case <-ctx.Done():
		t.Fatalf("renewal did not return after lease lock release: %v", ctx.Err())
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("reap stale renewal = %d, %v; want one", n, err)
	}
	renewReplacement, err := j.ClaimQueuedRuns(ctx, "renew-replacement", 1, time.Minute)
	if err != nil || len(renewReplacement) != 1 || renewReplacement[0].RunID != "run_waiting_renew_pg" {
		t.Fatalf("replacement after stale renewal = %+v, %v", renewReplacement, err)
	}
}
