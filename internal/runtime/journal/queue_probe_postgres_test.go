package journal

import (
	"context"
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

// TestPostgresQueueClaimBoundedProbe is an explicit, fixed-size diagnostic of
// the real fair-candidate and leased-claim paths. It is not a capacity result:
// one query plan and a few claim calls cannot establish fleet throughput.
func TestPostgresQueueClaimBoundedProbe(t *testing.T) {
	if os.Getenv("REACTOR_TEST_POSTGRES_QUEUE_PROBE") != "1" {
		t.Skip("set REACTOR_TEST_POSTGRES_QUEUE_PROBE=1 for the bounded PostgreSQL claim probe")
	}
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	engine, err := migrate.EngineFromURL(rawURL)
	if err != nil || engine != migrate.EnginePostgres {
		t.Fatalf("probe requires REACTOR_TEST_POSTGRES_URL for PostgreSQL: engine=%q err=%v", engine, err)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(strings.ToLower(strings.Trim(parsed.Path, "/")), "test") {
		t.Fatal("probe database name must contain 'test'")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), rawURL); err != nil {
		t.Fatal(err)
	}
	db, openedEngine, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	if openedEngine != migrate.EnginePostgres {
		db.Close()
		t.Fatalf("probe URL opened %q, want PostgreSQL", openedEngine)
	}
	// This probe exercises the global queue claim path. Running it against a
	// shared test database could claim another suite's rows, so require an
	// otherwise idle queue as well as the explicit opt-in environment flag.
	var active int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM runs WHERE status IN ('queued', 'running')`).Scan(&active); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if active != 0 {
		db.Close()
		t.Fatalf("probe requires an idle, dedicated test queue; found %d queued/running runs", active)
	}
	j := New(db, EnginePostgres)
	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantIDs := [3]string{"probe-noisy-" + suffix, "probe-quiet-" + suffix, "probe-paused-" + suffix}
	wfIDs := [3]string{"wf_probe_noisy_" + suffix, "wf_probe_quiet_" + suffix, "wf_probe_paused_" + suffix}
	runPrefixes := [3]string{"run_probe_noisy_" + suffix + "_", "run_probe_quiet_" + suffix + "_", "run_probe_paused_" + suffix + "_"}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if _, err := db.ExecContext(cleanupCtx, `DELETE FROM runs WHERE workflow_id IN ($1,$2,$3)`, wfIDs[0], wfIDs[1], wfIDs[2]); err != nil {
			t.Errorf("remove probe runs: %v", err)
		}
		if _, err := db.ExecContext(cleanupCtx, `DELETE FROM workflows WHERE id IN ($1,$2,$3)`, wfIDs[0], wfIDs[1], wfIDs[2]); err != nil {
			t.Errorf("remove probe workflows: %v", err)
		}
		if _, err := db.ExecContext(cleanupCtx, `DELETE FROM tenants WHERE tenant_id IN ($1,$2,$3)`, tenantIDs[0], tenantIDs[1], tenantIDs[2]); err != nil {
			t.Errorf("remove probe tenants: %v", err)
		}
		_ = db.Close()
	})
	for i, tenantID := range tenantIDs {
		if err := j.UpsertTenant(ctx, Tenant{TenantID: tenantID, MaxConcurrentRuns: 8, Disabled: i == 2}); err != nil {
			t.Fatal(err)
		}
		if err := j.CreateWorkflowInTenant(ctx, wfIDs[i], "queue-probe-"+suffix+fmt.Sprint(i), "h", "0.1.0", []byte(`{}`), tenantID); err != nil {
			t.Fatal(err)
		}
	}
	// A noisy tenant owns 1024 older jobs, a quiet tenant owns 8 newer jobs,
	// and a disabled tenant owns 128. The fixed 1160-row ceiling keeps this
	// diagnostic bounded while exercising fairness, caps, and blocked backlog.
	base := time.Now().UTC().Add(-2 * time.Hour)
	for i, n := range []int{1024, 8, 128} {
		if _, err := db.ExecContext(ctx, `INSERT INTO runs
			(id, workflow_id, tenant_id, trigger_kind, trigger_meta, status, created_at)
			SELECT $1 || lpad(g::text, 4, '0'), $2, $3, 'manual', '{}'::jsonb, 'queued',
				$4::timestamptz + g * INTERVAL '1 microsecond'
			FROM generate_series(0, $5::int - 1) AS g`,
			runPrefixes[i], wfIDs[i], tenantIDs[i], base.Add(time.Duration(i)*time.Hour), n); err != nil {
			t.Fatalf("seed %d probe queue rows: %v", n, err)
		}
	}
	// The synthetic fixture was inserted in one burst. Refresh planner stats
	// before comparing plans so a one-row estimate does not obscure the
	// actual fair-rank and cap-filter work on the 1160-row queue.
	if _, err := db.ExecContext(ctx, `ANALYZE runs, workflows, tenants`); err != nil {
		t.Fatalf("analyze probe queue: %v", err)
	}
	// EXPLAIN ANALYZE runs only this bounded read-only candidate query. Keep
	// the plan in verbose test output so a future index/query change can be
	// compared on the same fixture; it is not a latency SLO or load benchmark.
	rows, err := db.QueryContext(ctx, `EXPLAIN (ANALYZE, BUFFERS) `+j.fairCandidateQuery(64))
	if err != nil {
		t.Fatalf("candidate query plan: %v", err)
	}
	var plan []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		plan = append(plan, line)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	planText := strings.Join(plan, "\n")
	// The planner can choose the older general workflow index when the
	// fixture is almost entirely queued. Keep the plan visible as a diagnostic
	// rather than making one cost-based choice a correctness requirement.
	t.Logf("bounded 1160-row fair-candidate plan:\n%s", planText)
	start := time.Now()
	claims, err := j.ClaimQueuedRuns(ctx, "queue-probe", 16, time.Minute)
	t.Logf("one 16-slot leased claim elapsed=%s", time.Since(start))
	if err != nil || len(claims) != 16 {
		t.Fatalf("leased claim = %d runs, %v; want 16", len(claims), err)
	}
	var noisy, quiet int
	for _, claim := range claims {
		switch {
		case strings.HasPrefix(claim.RunID, runPrefixes[0]):
			noisy++
		case strings.HasPrefix(claim.RunID, runPrefixes[1]):
			quiet++
		default:
			t.Fatalf("disabled or foreign run was claimed: %q", claim.RunID)
		}
	}
	if noisy != 8 || quiet != 8 {
		t.Fatalf("tenant-fair capped claim = noisy %d / quiet %d, want 8 / 8", noisy, quiet)
	}
	for i := 0; i < 3; i++ {
		start = time.Now()
		extra, err := j.ClaimQueuedRuns(ctx, "queue-probe-empty", 1, time.Minute)
		t.Logf("blocked-backlog empty claim %d elapsed=%s", i+1, time.Since(start))
		if err != nil || len(extra) != 0 {
			t.Fatalf("blocked-backlog claim %d = %+v, %v; want no claim", i+1, extra, err)
		}
	}
	// Reap one deliberately expired generation, then prove the replacement
	// can claim that exact run while the stale owner loses its fence.
	old := claims[0]
	if err := j.ExtendLease(ctx, old.RunID, old.Owner, -time.Minute); err != nil {
		t.Fatal(err)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("expired lease reap = %d, %v", n, err)
	}
	replacement, err := j.ClaimQueuedRuns(ctx, "queue-probe-replacement", 1, time.Minute)
	if err != nil || len(replacement) != 1 || replacement[0].RunID != old.RunID || replacement[0].Owner == old.Owner {
		t.Fatalf("replacement claim = %+v, %v; want exact run with new owner", replacement, err)
	}
	if err := j.ExtendLease(ctx, old.RunID, old.Owner, time.Minute); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("stale owner extended replacement lease: %v", err)
	}
}
