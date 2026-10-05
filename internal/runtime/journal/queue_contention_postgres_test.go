package journal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
)

// The first candidate window can be entirely row-locked by another claimer.
// A second worker must be able to reach later fair-order work without waiting
// for those locks or silently treating the queue as empty.
func TestPostgresClaimRetriesPastLockedCandidateWindow(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for the PostgreSQL claim contention contract")
	}
	engine, err := migrate.EngineFromURL(rawURL)
	if err != nil || engine != migrate.EnginePostgres {
		t.Fatalf("test URL must be PostgreSQL: engine=%q err=%v", engine, err)
	}
	u, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(strings.ToLower(strings.Trim(u.Path, "/")), "test") {
		t.Fatal("PostgreSQL test database name must contain test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	base, _, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	schema := fmt.Sprintf("claim_contention_%d", time.Now().UnixNano())
	if _, err := base.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer base.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
	q := u.Query()
	q.Set("search_path", schema)
	q.Set("application_name", schema)
	u.RawQuery = q.Encode()
	scopedURL := u.String()
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), scopedURL); err != nil {
		t.Fatalf("migrate isolated PostgreSQL schema: %v", err)
	}
	db, engine, err := migrate.Open(scopedURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if engine != migrate.EnginePostgres {
		t.Fatalf("opened engine %q, want PostgreSQL", engine)
	}
	j := New(db, EnginePostgres)
	for _, tenantID := range []string{"a", "b"} {
		if err := j.UpsertTenant(ctx, Tenant{TenantID: tenantID, MaxConcurrentRuns: 8}); err != nil {
			t.Fatal(err)
		}
		mkWorkflowTenant(t, j, ctx, "wf_"+tenantID, tenantID)
	}
	for i := 0; i < 8; i++ {
		for _, tenantID := range []string{"a", "b"} {
			if err := j.CreateQueuedRun(ctx, fmt.Sprintf("%s%d", tenantID, i), "wf_"+tenantID, "manual", json.RawMessage(`{}`)); err != nil {
				t.Fatal(err)
			}
		}
	}
	first, err := scanIDs(db.QueryContext(ctx, j.fairCandidateQuery(8)))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a0", "b0", "a1", "b1", "a2", "b2", "a3", "b3"}; !reflect.DeepEqual(first, want) {
		t.Fatalf("first fair candidate window = %v, want %v", first, want)
	}
	// Hold the first tenant policy row so claimer A pauses after it locks the
	// first eight candidate runs, but before it changes any status. Claimer B
	// then sees those same oldest rows locked and must expand its window.
	holder, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	var held string
	if err := holder.QueryRowContext(ctx, `SELECT tenant_id FROM tenants WHERE tenant_id = 'a' FOR UPDATE`).Scan(&held); err != nil {
		t.Fatal(err)
	}
	claimCtx, claimCancel := context.WithTimeout(ctx, 10*time.Second)
	defer claimCancel()
	type result struct {
		claims []RunLease
		err    error
	}
	firstDone := make(chan result, 1)
	secondDone := make(chan result, 1)
	go func() {
		claims, err := j.ClaimQueuedRuns(claimCtx, "contention-first", 2, time.Minute)
		firstDone <- result{claims, err}
	}()
	waitForPolicyLock := func(want int, early <-chan result) {
		t.Helper()
		for {
			select {
			case outcome := <-early:
				t.Fatalf("claimer returned before tenant lock released: claims=%v err=%v", outcome.claims, outcome.err)
			default:
			}
			var waiting int
			if err := db.QueryRowContext(claimCtx, `SELECT COUNT(*) FROM pg_stat_activity
				WHERE application_name = $1 AND wait_event_type = 'Lock'
				AND query LIKE '%FROM tenants WHERE tenant_id = $1 FOR UPDATE%'`, schema).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting >= want {
				return
			}
			select {
			case <-claimCtx.Done():
				t.Fatalf("waiting for %d claimers at tenant lock: %v", want, claimCtx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	waitForPolicyLock(1, firstDone)
	go func() {
		claims, err := j.ClaimQueuedRuns(claimCtx, "contention-second", 2, time.Minute)
		secondDone <- result{claims, err}
	}()
	waitForPolicyLock(2, secondDone)
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	for i, done := range []<-chan result{firstDone, secondDone} {
		var outcome result
		select {
		case outcome = <-done:
		case <-claimCtx.Done():
			t.Fatal(claimCtx.Err())
		}
		if outcome.err != nil {
			t.Fatalf("claimer %d: %v", i+1, outcome.err)
		}
		got := make([]string, len(outcome.claims))
		for n, claim := range outcome.claims {
			got[n] = claim.RunID
			if claim.Owner == "" {
				t.Fatalf("claim %q has no fencing token", claim.RunID)
			}
		}
		want := []string{"a0", "b0"}
		if i == 1 {
			want = []string{"a4", "b4"}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("claimer %d claims = %v, want %v", i+1, got, want)
		}
	}
}
