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

func TestRuntimeSecretAuditBindsRunIdentityAndFollowsRetention(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_secret_audit", "secret-audit", "h", "0.1.0", json.RawMessage(`{}`), "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_secret_audit", "wf_secret_audit", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	entry := RuntimeSecretAccess{
		TenantID: "tenant-a", WorkflowID: "wf_secret_audit", RunID: "run_secret_audit",
		SecretRef: "oauth:conn_1", SecretKind: "oauth",
	}
	if err := j.AppendRuntimeSecretAccess(ctx, "", RuntimeSecretAccess{
		TenantID: "tenant-b", WorkflowID: entry.WorkflowID, RunID: entry.RunID,
		SecretRef: entry.SecretRef, SecretKind: entry.SecretKind,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign tenant receipt = %v, want not found", err)
	}
	if err := j.AppendRuntimeSecretAccess(ctx, "", RuntimeSecretAccess{
		TenantID: entry.TenantID, WorkflowID: "other-workflow", RunID: entry.RunID,
		SecretRef: entry.SecretRef, SecretKind: entry.SecretKind,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mismatched workflow receipt = %v, want not found", err)
	}
	if err := j.AppendRuntimeSecretAccess(ctx, "", entry); err != nil {
		t.Fatal(err)
	}
	// A receipt is the last gate before a vault value or OAuth token is sent
	// to the child. A stale live-mode supervisor must not be able to mint one
	// after cancellation, suspension, or completion of its run.
	for _, state := range []struct {
		status    string
		cancelled bool
	}{
		{status: "queued"},
		{status: "suspended"},
		{status: "succeeded"},
		{status: "failed"},
		{status: "cancelled"},
		{status: "running", cancelled: true},
	} {
		if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE runs SET status = $1, cancel_requested = $2 WHERE id = $3`),
			state.status, j.boolValue(state.cancelled), entry.RunID); err != nil {
			t.Fatal(err)
		}
		if err := j.AppendRuntimeSecretAccess(ctx, "", entry); !errors.Is(err, ErrNotFound) {
			t.Fatalf("status %q, cancel_requested %t: receipt = %v, want not found", state.status, state.cancelled, err)
		}
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE runs SET status = $1, cancel_requested = $2 WHERE id = $3`),
		"running", j.boolValue(false), entry.RunID); err != nil {
		t.Fatal(err)
	}
	if err := j.AppendRuntimeSecretAccess(ctx, "", RuntimeSecretAccess{
		TenantID: entry.TenantID, WorkflowID: entry.WorkflowID, RunID: entry.RunID,
		SecretRef: entry.SecretRef, SecretKind: "invalid",
	}); err == nil {
		t.Fatal("invalid secret kind accepted")
	}
	rows, err := j.ListRuntimeSecretAccessForTenant(ctx, "tenant-a", 10, 0)
	if err != nil || len(rows) != 1 || rows[0].SecretRef != entry.SecretRef || rows[0].At.IsZero() {
		t.Fatalf("access receipt = %+v, %v", rows, err)
	}
	if err := j.MarkRunFinished(ctx, entry.RunID, "succeeded"); err != nil {
		t.Fatal(err)
	}
	setRunTimes(t, j, ctx, entry.RunID, time.Now().UTC().Add(-30*24*time.Hour))
	if n, err := j.PurgeTerminalRunsOlderThan(ctx, time.Now().UTC().Add(-7*24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("purge = %d, %v", n, err)
	}
	rows, err = j.ListRuntimeSecretAccessForTenant(ctx, "tenant-a", 10, 0)
	if err != nil || len(rows) != 0 {
		t.Fatalf("runtime audit survived deleted run: %+v, %v", rows, err)
	}
}

func TestRuntimeSecretAuditFencesExactLiveLeaseAndLocalBypass(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateQueuedRun(ctx, "run_secret_lease", "wf_1", "webhook", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	entry := RuntimeSecretAccess{
		TenantID: DefaultTenant, WorkflowID: "wf_1", RunID: "run_secret_lease",
		SecretRef: "cred_fixture", SecretKind: "vault",
	}
	first, err := j.ClaimQueuedRuns(ctx, "worker-secret-a", 1, time.Minute)
	if err != nil || len(first) != 1 || first[0].RunID != entry.RunID {
		t.Fatalf("first claim = %+v, %v", first, err)
	}
	if err := j.AppendRuntimeSecretAccess(ctx, "", entry); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("local supervisor bypassed active worker lease: %v", err)
	}
	if err := j.AppendRuntimeSecretAccess(ctx, first[0].Owner, entry); err != nil {
		t.Fatalf("current owner receipt: %v", err)
	}
	if err := j.ExtendLease(ctx, entry.RunID, first[0].Owner, -time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := j.AppendRuntimeSecretAccess(ctx, first[0].Owner, entry); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("expired owner receipt before reap = %v", err)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("reap = %d, %v", n, err)
	}
	second, err := j.ClaimQueuedRuns(ctx, "worker-secret-b", 1, time.Minute)
	if err != nil || len(second) != 1 || second[0].RunID != entry.RunID || second[0].Owner == first[0].Owner {
		t.Fatalf("replacement claim = %+v, %v", second, err)
	}
	if err := j.AppendRuntimeSecretAccess(ctx, first[0].Owner, entry); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("replaced owner receipt = %v", err)
	}
	if err := j.AppendRuntimeSecretAccess(ctx, second[0].Owner, entry); err != nil {
		t.Fatalf("replacement owner receipt: %v", err)
	}
	if outcome, err := j.RequestRunCancel(ctx, entry.RunID); err != nil || outcome != CancelRequested {
		t.Fatalf("cancel = %q, %v", outcome, err)
	}
	if err := j.AppendRuntimeSecretAccess(ctx, second[0].Owner, entry); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cancel-requested run receipt = %v", err)
	}
	rows, err := j.ListRuntimeSecretAccessForTenant(ctx, DefaultTenant, 10, 0)
	if err != nil || len(rows) != 2 {
		t.Fatalf("value-free receipts after rejected attempts = %+v, %v", rows, err)
	}
}

func TestRuntimeSecretAuditPostgresTimestampAndTenantScope(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL to verify the PostgreSQL runtime secret audit")
	}
	engine, err := migrate.EngineFromURL(rawURL)
	if err != nil || engine != migrate.EnginePostgres {
		t.Fatalf("REACTOR_TEST_POSTGRES_URL must target Postgres: engine=%q err=%v", engine, err)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(strings.ToLower(strings.Trim(parsed.Path, "/")), "test") {
		t.Fatal("REACTOR_TEST_POSTGRES_URL database name must contain 'test'")
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
		t.Fatalf("opened engine = %s, want postgres", openedEngine)
	}
	j := New(db, EnginePostgres)
	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantID, workflowID, runID := "secret-audit-test-"+suffix, "wf_secret_audit_pg_"+suffix, "run_secret_audit_pg_"+suffix
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM runs WHERE id = $1`, runID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM workflows WHERE id = $1`, workflowID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE tenant_id = $1`, tenantID)
	}()
	if err := j.UpsertTenant(ctx, Tenant{TenantID: tenantID}); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenant(ctx, workflowID, "secret-audit-"+suffix, "h", "0.1.0", json.RawMessage(`{}`), tenantID); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, runID, workflowID, "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.AppendRuntimeSecretAccess(ctx, "", RuntimeSecretAccess{
		TenantID: tenantID, WorkflowID: workflowID, RunID: runID,
		SecretRef: "oauth:test-conn", SecretKind: "oauth",
	}); err != nil {
		t.Fatal(err)
	}
	for _, state := range []struct {
		status    string
		cancelled bool
	}{
		{status: "suspended"},
		{status: "running", cancelled: true},
	} {
		if _, err := db.ExecContext(ctx, `UPDATE runs SET status = $1, cancel_requested = $2 WHERE id = $3`,
			state.status, state.cancelled, runID); err != nil {
			t.Fatal(err)
		}
		if err := j.AppendRuntimeSecretAccess(ctx, "", RuntimeSecretAccess{
			TenantID: tenantID, WorkflowID: workflowID, RunID: runID,
			SecretRef: "oauth:test-conn", SecretKind: "oauth",
		}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("postgres status %q, cancel_requested %t: receipt = %v, want not found", state.status, state.cancelled, err)
		}
	}
	rows, err := j.ListRuntimeSecretAccessForTenant(ctx, tenantID, 10, 0)
	if err != nil || len(rows) != 1 || rows[0].At.IsZero() || rows[0].SecretRef != "oauth:test-conn" {
		t.Fatalf("postgres runtime secret receipt = %+v, %v", rows, err)
	}
	foreign, err := j.ListRuntimeSecretAccessForTenant(ctx, "other-tenant", 10, 0)
	if err != nil || len(foreign) != 0 {
		t.Fatalf("postgres foreign tenant audit view = %+v, %v", foreign, err)
	}
}

func TestRuntimeSecretAuditPostgresFencesReplacedLease(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL to verify the PostgreSQL runtime secret lease fence")
	}
	engine, err := migrate.EngineFromURL(rawURL)
	if err != nil || engine != migrate.EnginePostgres {
		t.Fatalf("REACTOR_TEST_POSTGRES_URL must target Postgres: engine=%q err=%v", engine, err)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(strings.ToLower(strings.Trim(parsed.Path, "/")), "test") {
		t.Fatal("REACTOR_TEST_POSTGRES_URL database name must contain 'test'")
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
		t.Fatalf("opened engine = %s, want postgres", openedEngine)
	}
	j := New(db, EnginePostgres)
	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantID, workflowID, runID := "secret-lease-test-"+suffix, "wf_secret_lease_pg_"+suffix, "run_secret_lease_pg_"+suffix
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM runs WHERE id = $1`, runID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM workflows WHERE id = $1`, workflowID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE tenant_id = $1`, tenantID)
	}()
	if err := j.UpsertTenant(ctx, Tenant{TenantID: tenantID}); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenant(ctx, workflowID, "secret-lease-"+suffix, "h", "0.1.0", json.RawMessage(`{}`), tenantID); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateQueuedRun(ctx, runID, workflowID, "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	entry := RuntimeSecretAccess{TenantID: tenantID, WorkflowID: workflowID, RunID: runID,
		SecretRef: "oauth:test-conn", SecretKind: "oauth"}
	first, err := j.ClaimQueuedRuns(ctx, "secret-lease-worker-a", 1, time.Minute)
	if err != nil || len(first) != 1 || first[0].RunID != runID {
		t.Fatalf("first postgres claim = %+v, %v", first, err)
	}
	if err := j.AppendRuntimeSecretAccess(ctx, "", entry); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("postgres local bypass of owned run = %v", err)
	}
	if err := j.AppendRuntimeSecretAccess(ctx, first[0].Owner, entry); err != nil {
		t.Fatalf("postgres current owner receipt: %v", err)
	}
	if err := j.ExtendLease(ctx, runID, first[0].Owner, -time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := j.AppendRuntimeSecretAccess(ctx, first[0].Owner, entry); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("postgres expired owner receipt before reap = %v", err)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("postgres reap = %d, %v", n, err)
	}
	second, err := j.ClaimQueuedRuns(ctx, "secret-lease-worker-b", 1, time.Minute)
	if err != nil || len(second) != 1 || second[0].RunID != runID {
		t.Fatalf("replacement postgres claim = %+v, %v", second, err)
	}
	if err := j.AppendRuntimeSecretAccess(ctx, first[0].Owner, entry); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("postgres replaced owner receipt = %v", err)
	}
	if err := j.AppendRuntimeSecretAccess(ctx, second[0].Owner, entry); err != nil {
		t.Fatalf("postgres replacement owner receipt: %v", err)
	}
	if outcome, err := j.RequestRunCancel(ctx, runID); err != nil || outcome != CancelRequested {
		t.Fatalf("postgres cancel = %q, %v", outcome, err)
	}
	if err := j.AppendRuntimeSecretAccess(ctx, second[0].Owner, entry); !errors.Is(err, ErrNotFound) {
		t.Fatalf("postgres cancel-requested receipt = %v", err)
	}
	rows, err := j.ListRuntimeSecretAccessForTenant(ctx, tenantID, 10, 0)
	if err != nil || len(rows) != 2 {
		t.Fatalf("postgres receipts after rejected attempts = %+v, %v", rows, err)
	}
}
