package journal

import (
	"context"
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

// A tenant may spread its queue across several workflows. A per-workflow
// bounded read must still return that tenant's oldest runs in fair order, and
// the migration trigger must index queued rows written by old processes.
func TestPostgresQueuedWorkflowIndexFairnessAndOldWriters(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for the PostgreSQL queue index contract")
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
	schema := fmt.Sprintf("queue_index_%d", time.Now().UnixNano())
	if _, err := base.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer base.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
	q := u.Query()
	q.Set("search_path", schema)
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
	j := New(db, EnginePostgres)
	for _, tenantID := range []string{"a", "b", "c"} {
		if err := j.UpsertTenant(ctx, Tenant{TenantID: tenantID, MaxConcurrentRuns: 2}); err != nil {
			t.Fatal(err)
		}
	}
	for _, wf := range [][2]string{{"wf_a1", "a"}, {"wf_a2", "a"}, {"wf_b", "b"}, {"wf_c", "c"}} {
		mkWorkflowTenant(t, j, ctx, wf[0], wf[1])
	}
	baseTime := time.Now().UTC().Add(-time.Hour)
	insert := func(id, wf string, offset time.Duration, status string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO runs
			(id, workflow_id, tenant_id, trigger_kind, trigger_meta, status, created_at)
			VALUES ($1,$2,(SELECT tenant_id FROM workflows WHERE id=$2),'manual','{}',$3,$4)`,
			id, wf, status, baseTime.Add(offset)); err != nil {
			t.Fatal(err)
		}
	}
	// A legacy/direct writer can persist a run under a workflow owned by a
	// different tenant. Such rows must remain visible in raw backlog but
	// cannot hide later valid rows in the bounded candidate read or be claimed.
	for i := 0; i < 32; i++ {
		if _, err := db.ExecContext(ctx, `INSERT INTO runs
			(id, workflow_id, tenant_id, trigger_kind, trigger_meta, status, created_at)
			VALUES ($1, 'wf_a1', 'other', 'manual', '{}', 'queued', $2)`,
			fmt.Sprintf("wrong_%02d", i), baseTime.Add(-time.Hour+time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	insert("a0", "wf_a1", 0, "queued")
	insert("a1", "wf_a2", time.Second, "queued")
	for i := 2; i < 102; i++ {
		insert(fmt.Sprintf("a%d", i), "wf_a1", time.Duration(i)*time.Second, "queued")
	}
	insert("b0", "wf_b", 10*time.Minute, "queued")
	insert("b1", "wf_b", 11*time.Minute, "queued")
	// A legacy writer can requeue a row directly. The database trigger, not a
	// Go call site, must add the workflow to the candidate index.
	insert("c0", "wf_c", 12*time.Minute, "running")
	if _, err := db.ExecContext(ctx, `UPDATE runs SET status='queued' WHERE id='c0'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE workflows SET enabled=false WHERE id='wf_c'`); err != nil {
		t.Fatal(err)
	}
	var indexed int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM queue_workflow_index`).Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if indexed != 4 {
		t.Fatalf("indexed workflows = %d, want 4 including direct requeue", indexed)
	}
	// A mixed-version writer may still maintain the old append-only hint,
	// but a claim must derive active workflows from queued runs themselves.
	// Removing one live hint reproduces a missed membership update: wf_b's
	// work must remain claimable instead of disappearing from the queue.
	if _, err := db.ExecContext(ctx, `DELETE FROM queue_workflow_index WHERE workflow_id = 'wf_b'`); err != nil {
		t.Fatal(err)
	}
	got, err := scanIDs(db.QueryContext(ctx, j.fairCandidateQuery(4)))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a0", "b0", "a1", "b1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("fair candidates across workflows = %v, want %v", got, want)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	locked, lockErr := j.lockQueuedCandidatesTx(ctx, tx, []string{"wrong_00", "a0"})
	rollbackErr := tx.Rollback()
	if lockErr != nil || rollbackErr != nil {
		t.Fatalf("candidate lock = %v; rollback = %v", lockErr, rollbackErr)
	}
	if _, bad := locked["wrong_00"]; bad || locked["a0"] != "a" {
		t.Fatalf("tenant-fenced candidate lock = %v, want only a0", locked)
	}
	if raw, err := j.CountQueued(ctx); err != nil || raw != 137 {
		t.Fatalf("raw PostgreSQL queue = %d, %v; want 137 including malformed rows", raw, err)
	}
	if claimable, err := j.CountClaimableQueued(ctx); err != nil || claimable != 4 {
		t.Fatalf("claimable PostgreSQL queue = %d, %v; want four tenant slots", claimable, err)
	}
	for _, tc := range []struct{ limit, want int }{{1, 1}, {4, 4}, {8, 4}, {257, 4}} {
		if bounded, err := j.CountClaimableQueuedUpTo(ctx, tc.limit); err != nil || bounded != tc.want {
			t.Fatalf("claimable PostgreSQL up to %d = %d, %v; want %d", tc.limit, bounded, err, tc.want)
		}
	}
	claims, err := j.ClaimQueuedRuns(ctx, "queue-index-test", 4, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claimed := make([]string, len(claims))
	for i, claim := range claims {
		claimed[i] = claim.RunID
	}
	if want := []string{"a0", "b0", "a1", "b1"}; !reflect.DeepEqual(claimed, want) {
		t.Fatalf("fair claims across workflows = %v, want %v", claimed, want)
	}
	if claimable, err := j.CountClaimableQueued(ctx); err != nil || claimable != 0 {
		t.Fatalf("claimable PostgreSQL queue after caps fill = %d, %v; want zero", claimable, err)
	}
	if further, err := j.ClaimQueuedRuns(ctx, "queue-index-test", 1, time.Minute); err != nil || len(further) != 0 {
		t.Fatalf("over-cap or disabled workflow claim = %+v, %v", further, err)
	}
}
