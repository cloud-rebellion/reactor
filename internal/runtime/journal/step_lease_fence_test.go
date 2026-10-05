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

func TestOwnedStepWritesFenceExpiredAndReplacedLeasesSQLite(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	testOwnedStepWritesFenceExpiredAndReplacedLeases(t, j, "sqlite")
}

func TestOwnedStepWritesFenceExpiredAndReplacedLeasesPostgres(t *testing.T) {
	j, cleanup := newOwnedStepPostgresJournal(t)
	defer cleanup()
	testOwnedStepWritesFenceExpiredAndReplacedLeases(t, j, "postgres")
}

func TestOwnedStepStartCannotCommitAfterRunLockWaitPastDeadlinePostgres(t *testing.T) {
	j, cleanup := newOwnedStepPostgresJournal(t)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	const wfID = "wf_step_wait"
	const runID = "run_step_wait"
	if err := j.CreateWorkflow(ctx, wfID, "step-wait", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateQueuedRun(ctx, runID, wfID, "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	claims, err := j.ClaimQueuedRuns(ctx, "worker-wait", 1, time.Second)
	if err != nil || len(claims) != 1 || claims[0].RunID != runID {
		t.Fatalf("claim = %+v, %v", claims, err)
	}
	var deadline time.Time
	if err := j.db.QueryRowContext(ctx, `SELECT expires_at FROM leases WHERE run_id = $1`, runID).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	holder, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	var lockedID string
	if err := holder.QueryRowContext(ctx, `SELECT id FROM runs WHERE id = $1 FOR UPDATE`, runID).Scan(&lockedID); err != nil || lockedID != runID {
		t.Fatalf("hold run lock = %q, %v", lockedID, err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := j.ClaimOwnedStepAttemptSeq(ctx, runID, claims[0].Owner, "send", 1, 3, "idem", "hash")
		done <- err
	}()
	for {
		select {
		case err := <-done:
			t.Fatalf("step claim returned before run lock released: %v", err)
		default:
		}
		var waiting int
		err := j.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pg_stat_activity
			WHERE application_name = current_schema() AND wait_event_type = 'Lock'
			AND query LIKE '%SELECT id FROM runs%' AND query LIKE '%FOR UPDATE%'`).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for step claim to block on run: %v", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if wait := time.Until(deadline.Add(20 * time.Millisecond)); wait > 0 {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(wait):
		}
	}
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrLeaseOwnershipLost) {
			t.Fatalf("late step claim = %v, want ownership loss", err)
		}
	case <-ctx.Done():
		t.Fatalf("late step claim did not finish: %v", ctx.Err())
	}
	if count, err := j.AttemptCountSeq(ctx, runID, "send", 1); err != nil || count != 0 {
		t.Fatalf("step attempts after expired lock wait = %d, %v", count, err)
	}
}

func testOwnedStepWritesFenceExpiredAndReplacedLeases(t *testing.T, j *Journal, suffix string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	wfID := "wf_owned_step_" + suffix
	runID := "run_owned_step_" + suffix
	if err := j.CreateWorkflow(ctx, wfID, "owned-step-"+suffix, "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateQueuedRun(ctx, runID, wfID, "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	first, err := j.ClaimQueuedRuns(ctx, "worker-a", 1, time.Minute)
	if err != nil || len(first) != 1 || first[0].RunID != runID {
		t.Fatalf("first claim = %+v, %v", first, err)
	}
	a := first[0].Owner
	if claim, err := j.ClaimOwnedStepAttemptSeq(ctx, runID, a, "send", 1, 3, "stable-key", "input-hash"); err != nil || claim.Attempt != 1 {
		t.Fatalf("first owned step = %+v, %v", claim, err)
	}
	if inserted, err := j.RecordOwnedStepStartSeq(ctx, runID, a, "legacy", 2, 1, "legacy-key", "legacy-hash"); err != nil || !inserted {
		t.Fatalf("first legacy step = %t, %v", inserted, err)
	}
	if claim, err := j.ClaimOwnedStepAttemptSeq(ctx, runID, a, "terminal", 5, 1, "terminal-key", "terminal-hash"); err != nil || claim.Attempt != 1 {
		t.Fatalf("first terminal step = %+v, %v", claim, err)
	}
	if deadLettered, err := j.FinalizeOwnedStepAttemptSeqWithRetryAfter(ctx, runID, a, "terminal", 5, 1, json.RawMessage(`null`), "permanent", false, 0); err != nil || !deadLettered {
		t.Fatalf("first terminal outcome = %t, %v", deadLettered, err)
	}
	if err := j.ExtendLease(ctx, runID, a, -time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := j.ClaimOwnedStepAttemptSeq(ctx, runID, a, "late", 3, 3, "late-key", "late-hash"); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("expired owner started a step before reap: %v", err)
	}
	if _, err := j.FinalizeOwnedStepAttemptSeqWithRetryAfter(ctx, runID, a, "send", 1, 1, json.RawMessage(`"old"`), "", false, 0); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("expired owner finalized a step before reap: %v", err)
	}
	if err := j.FinalizeOwnedExhaustedStepAttemptSeq(ctx, runID, a, "send", 1, 1, json.RawMessage(`null`), "exhausted"); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("expired owner exhausted a step before reap: %v", err)
	}
	if _, err := j.EnsureOwnedStepAttemptDeadLetter(ctx, runID, a, "terminal", 5, 1, "permanent", json.RawMessage(`{}`)); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("expired owner repaired a dead letter before reap: %v", err)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("reap = %d, %v", n, err)
	}
	second, err := j.ClaimQueuedRuns(ctx, "worker-b", 1, time.Minute)
	if err != nil || len(second) != 1 || second[0].RunID != runID {
		t.Fatalf("replacement claim = %+v, %v", second, err)
	}
	b := second[0].Owner
	if _, err := j.ClaimOwnedStepAttemptSeq(ctx, runID, a, "late", 3, 3, "late-key", "late-hash"); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("replaced owner started a step: %v", err)
	}
	if _, err := j.FinalizeOwnedStepAttemptSeqWithRetryAfter(ctx, runID, a, "send", 1, 1, json.RawMessage(`"old"`), "", false, 0); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("replaced owner finalized a step: %v", err)
	}
	if err := j.RecordOwnedStepEndSeq(ctx, runID, a, "legacy", 2, 1, json.RawMessage(`"old"`), ""); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("replaced owner finalized a legacy step: %v", err)
	}
	if _, err := j.RecordOwnedStepStartSeq(ctx, runID, a, "late-legacy", 4, 1, "", ""); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("replaced owner started a legacy step: %v", err)
	}
	var rows int
	if err := j.db.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM steps WHERE run_id = $1`), runID).Scan(&rows); err != nil || rows != 3 {
		t.Fatalf("stale writes changed step rows = %d, %v", rows, err)
	}
	claim, err := j.ClaimOwnedStepAttemptSeq(ctx, runID, b, "send", 1, 3, "stable-key", "input-hash")
	if err != nil || claim.Attempt != 2 {
		t.Fatalf("replacement step claim = %+v, %v", claim, err)
	}
	if _, err := j.FinalizeOwnedStepAttemptSeqWithRetryAfter(ctx, runID, b, "send", 1, 2, json.RawMessage(`"new"`), "", false, 0); err != nil {
		t.Fatalf("replacement step end: %v", err)
	}
	if _, err := j.RecordOwnedStepStartSeq(ctx, runID, b, "legacy", 2, 1, "legacy-key", "legacy-hash"); err != nil {
		t.Fatalf("replacement legacy start: %v", err)
	}
	if err := j.RecordOwnedStepEndSeq(ctx, runID, b, "legacy", 2, 1, json.RawMessage(`"new"`), ""); err != nil {
		t.Fatalf("replacement legacy end: %v", err)
	}
	if out, name, _, _, err := j.FindCachedOutputBySeqForInput(ctx, runID, 1); err != nil || name != "send" || string(out) != `"new"` {
		t.Fatalf("replacement durable output = %s, %q, %v", out, name, err)
	}
	if out, name, _, _, err := j.FindCachedOutputBySeqForInput(ctx, runID, 2); err != nil || name != "legacy" || string(out) != `"new"` {
		t.Fatalf("replacement legacy output = %s, %q, %v", out, name, err)
	}
}

func newOwnedStepPostgresJournal(t *testing.T) (*Journal, func()) {
	t.Helper()
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for the PostgreSQL owned-step lease fence")
	}
	engine, err := migrate.EngineFromURL(rawURL)
	if err != nil || engine != migrate.EnginePostgres {
		t.Fatalf("test requires PostgreSQL: engine=%q err=%v", engine, err)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(strings.ToLower(strings.Trim(parsed.Path, "/")), "test") {
		t.Fatal("PostgreSQL test database name must contain test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	base, _, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("owned_step_%d", time.Now().UnixNano())
	if _, err := base.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		base.Close()
		t.Fatal(err)
	}
	q := parsed.Query()
	q.Set("search_path", schema)
	q.Set("application_name", schema)
	parsed.RawQuery = q.Encode()
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), parsed.String()); err != nil {
		_, _ = base.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		base.Close()
		t.Fatal(err)
	}
	db, opened, err := migrate.Open(parsed.String())
	if err != nil || opened != migrate.EnginePostgres {
		_, _ = base.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		base.Close()
		t.Fatalf("open isolated PostgreSQL schema: %v (%s)", err, opened)
	}
	return New(db, EnginePostgres), func() {
		db.Close()
		_, _ = base.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		base.Close()
	}
}
