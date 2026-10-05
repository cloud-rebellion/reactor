package journal

import (
	"context"
	"encoding/json"
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

// A workflow may have many queued runs. Holding one run must not stop another
// worker claiming a distinct run of that same workflow, while the workflow
// row remains protected against a concurrent enable/disable update.
func TestPostgresClaimSharesWorkflowLockAcrossDistinctRuns(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL to run the PostgreSQL workflow claim lock contract")
	}
	engine, err := migrate.EngineFromURL(rawURL)
	if err != nil || engine != migrate.EnginePostgres {
		t.Fatalf("test requires a PostgreSQL URL: engine=%q err=%v", engine, err)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(strings.ToLower(strings.Trim(parsed.Path, "/")), "test") {
		t.Fatal("test database name must contain 'test'")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), rawURL); err != nil {
		t.Fatal(err)
	}
	db, openedEngine, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if openedEngine != migrate.EnginePostgres {
		t.Fatalf("test URL opened %q, want PostgreSQL", openedEngine)
	}
	var active int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs WHERE status IN ('queued', 'running')`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 0 {
		t.Fatalf("test requires an idle, dedicated queue; found %d queued/running runs", active)
	}
	j := New(db, EnginePostgres)
	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantID := "claim-workflow-lock-" + suffix
	wfID := "wf_claim_workflow_lock_" + suffix
	runA := "run_claim_workflow_lock_a_" + suffix
	runB := "run_claim_workflow_lock_b_" + suffix
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, err := db.ExecContext(cleanupCtx, `DELETE FROM runs WHERE id IN ($1,$2)`, runA, runB); err != nil {
			t.Errorf("remove claim test runs: %v", err)
		}
		if _, err := db.ExecContext(cleanupCtx, `DELETE FROM workflows WHERE id = $1`, wfID); err != nil {
			t.Errorf("remove claim test workflow: %v", err)
		}
		if _, err := db.ExecContext(cleanupCtx, `DELETE FROM tenants WHERE tenant_id = $1`, tenantID); err != nil {
			t.Errorf("remove claim test tenant: %v", err)
		}
	}()
	if err := j.UpsertTenant(ctx, Tenant{TenantID: tenantID}); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenant(ctx, wfID, wfID, "h", "0.1.0", json.RawMessage(`{}`), tenantID); err != nil {
		t.Fatal(err)
	}
	for _, runID := range []string{runA, runB} {
		if err := j.CreateQueuedRun(ctx, runID, wfID, "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	// This transaction models another claimer that already owns run A and
	// holds the workflow's compatible shared admission lock. The claim must
	// skip A and take B without waiting for this transaction to commit.
	holder, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	var lockedID string
	if err := holder.QueryRowContext(ctx, `SELECT id FROM workflows WHERE id = $1 FOR SHARE`, wfID).Scan(&lockedID); err != nil {
		t.Fatal(err)
	}
	if err := holder.QueryRowContext(ctx, `SELECT id FROM runs WHERE id = $1 FOR UPDATE`, runA).Scan(&lockedID); err != nil {
		t.Fatal(err)
	}
	claims, err := j.ClaimQueuedRuns(ctx, "distinct-run-worker", 1, time.Minute)
	if err != nil || len(claims) != 1 || claims[0].RunID != runB {
		t.Fatalf("claim with first run locked = %+v, %v; want only %s", claims, err, runB)
	}
	if err := holder.Rollback(); err != nil {
		t.Fatal(err)
	}
	claims, err = j.ClaimQueuedRuns(ctx, "after-first-run-unlocked", 1, time.Minute)
	if err != nil || len(claims) != 1 || claims[0].RunID != runA {
		t.Fatalf("claim after first run unlocked = %+v, %v; want only %s", claims, err, runA)
	}
}
