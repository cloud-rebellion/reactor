package supervisor

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/wire"
	"github.com/bright-interaction/reactor/internal/vault"
	_ "modernc.org/sqlite"
)

// buildTestWorkflow compiles the testworkflow binary into a tempdir and
// returns its path. Cached across tests via t.Cleanup.
func buildTestWorkflow(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "testworkflow")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, "./testworkflow")
	cmd.Dir = "."
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build testworkflow: %v", err)
	}
	return out
}

const supervisorTestArtifactSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func newTestSupervisorEnv(t *testing.T, runID string) (*Supervisor, *journal.Journal, func()) {
	sup, j, _, cleanup := newTestSupervisorEnvWithDB(t, runID)
	return sup, j, cleanup
}

func newTestSupervisorEnvWithDB(t *testing.T, runID string) (*Supervisor, *journal.Journal, *sql.DB, func()) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	url := "sqlite://" + dbPath

	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(context.Background(), silent, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	j := journal.New(db, journal.EngineSQLite)
	if err := j.CreateWorkflowWithArtifact(context.Background(), "wf_test", "test-replay", "h", "0.1.0", supervisorTestArtifactSHA256, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("create wf: %v", err)
	}
	// The supervisor now enforces credential tenant identity even when the
	// legacy permissive ACL mode is enabled. Seed the test credential row that
	// backs the matching in-memory vault entry; without this row the fixture
	// would intentionally exercise an unknown-credential denial rather than
	// the durable execution path these tests cover.
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO credentials (id, tenant_id, name, service, blob) VALUES (?,?,?,?,?)`,
		"never-used", journal.DefaultTenant, "test credential", "test", []byte("fixture")); err != nil {
		t.Fatalf("seed test credential: %v", err)
	}
	if err := j.CreateRunPinned(context.Background(), runID, "wf_test", "manual", json.RawMessage(`{}`), 1, supervisorTestArtifactSHA256); err != nil {
		t.Fatalf("create run: %v", err)
	}

	v, err := vault.NewStore(vault.NewMemoryBackend(), bytesN(32, 0xAB))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	if err := v.Put(context.Background(), "never-used", []byte("placeholder")); err != nil {
		t.Fatalf("vault put: %v", err)
	}

	logBuf := &slog.Logger{}
	_ = logBuf
	// Warn, not Error. The supervisor forwards the workflow subprocess's stderr
	// through stderrForwarder, which logs at WARN, so an Error threshold threw
	// away the only explanation of why a workflow failed. Six of these tests
	// have been red on GitHub Actions and green everywhere else (alpine, glibc,
	// the published mirror, a CPU-constrained runner all pass), and the CI
	// output says nothing beyond "status = failed, want succeeded" because of
	// this line. go test only prints t.Log output for FAILING tests, so this
	// costs nothing on a green run and gives the whole picture on a red one.
	logger := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))

	sup := &Supervisor{
		WorkflowSlug:     "test-replay",
		RunID:            runID,
		Mode:             "live",
		Journal:          j,
		Vault:            v,
		Log:              logger,
		SuspendThreshold: time.Second,
		// Durable-execution tests pre-date the per-workflow ACL; opt
		// them into the legacy empty-table-permissive mode so the
		// testworkflow's vault.MustGet("never-used") still resolves
		// without seeding a grant. The dedicated ACL tests in
		// acl_test.go cover the strict default.
		ACLPermissive: true,
	}
	return sup, j, db, func() { db.Close() }
}

func TestSupervisorStartFailurePersistsTerminal(t *testing.T) {
	sup, j, cleanup := newTestSupervisorEnv(t, "run_start_failure")
	defer cleanup()
	sup.BinaryPath = filepath.Join(t.TempDir(), "missing-workflow")
	status, err := sup.Run(context.Background())
	if err == nil || status != "failed" {
		t.Fatalf("start failure = status %q err %v; want durable failed + error", status, err)
	}
	if run, getErr := j.GetRun(context.Background(), "run_start_failure"); getErr != nil || run.Status != "failed" || run.FinishedAt.IsZero() {
		t.Fatalf("start failure state = %+v, %v", run, getErr)
	}
}

func TestSupervisorLocalTerminalWriteFailureParksRecovery(t *testing.T) {
	binary := buildTestWorkflow(t)
	sup, j, db, cleanup := newTestSupervisorEnvWithDB(t, "run_local_terminal_write_failure")
	defer cleanup()
	sup.BinaryPath = binary
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Make only the terminal transition fail. Step rows still commit, which
	// models a transient/uncertain final transaction after the workflow has
	// completed. A local run has no lease expiry to recover it; the supervisor
	// must park a due recovery schedule while this daemon is still alive.
	if _, err := db.ExecContext(ctx, `CREATE TRIGGER reject_local_terminal
		BEFORE UPDATE OF status ON runs
		WHEN OLD.id = 'run_local_terminal_write_failure' AND NEW.status IN ('succeeded', 'failed')
		BEGIN SELECT RAISE(ABORT, 'forced terminal failure'); END`); err != nil {
		t.Fatalf("create terminal failure trigger: %v", err)
	}
	status, err := sup.Run(ctx)
	if status != "suspended" || err == nil {
		t.Fatalf("terminal write failure = status %q err %v; want suspended recovery with original error", status, err)
	}
	if run, getErr := j.GetRun(ctx, "run_local_terminal_write_failure"); getErr != nil || run.Status != "suspended" || !run.FinishedAt.IsZero() {
		t.Fatalf("parked local recovery state = %+v, %v", run, getErr)
	}
	due, err := j.FindDueSchedules(ctx, time.Now().Add(time.Minute), 10)
	if err != nil {
		t.Fatalf("find parked recovery schedule: %v", err)
	}
	var found bool
	for _, schedule := range due {
		if schedule.RunID == "run_local_terminal_write_failure" && schedule.Kind == journal.KindRecovery && !schedule.Fired {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("terminal write failure did not create a due local recovery schedule: %+v", due)
	}
}

func TestDistributedSupervisorStartFailureFinalizesOwnedLease(t *testing.T) {
	sup, j, cleanup := newTestSupervisorEnv(t, "run_owned_start_failure")
	defer cleanup()
	ctx := context.Background()
	if err := j.SetRunStatus(ctx, "run_owned_start_failure", "queued"); err != nil {
		t.Fatal(err)
	}
	claims, err := j.ClaimQueuedRuns(ctx, "worker", 1, time.Minute)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim = %v, %v", claims, err)
	}
	sup.BinaryPath = filepath.Join(t.TempDir(), "missing-workflow")
	sup.LeaseOwner = claims[0].Owner
	status, err := sup.Run(ctx)
	if err == nil || status != "failed" {
		t.Fatalf("owned start failure = status %q err %v", status, err)
	}
	if run, getErr := j.GetRun(ctx, "run_owned_start_failure"); getErr != nil || run.Status != "failed" || run.FinishedAt.IsZero() {
		t.Fatalf("owned start failure state = %+v, %v", run, getErr)
	}
	if err := j.ExtendLease(ctx, "run_owned_start_failure", claims[0].Owner, time.Minute); !errors.Is(err, journal.ErrLeaseOwnershipLost) {
		t.Fatalf("owned terminal retained lease: %v", err)
	}
}

func TestDistributedChildCrashLeavesDurableStepRecoverableForReaper(t *testing.T) {
	binary := buildTestWorkflow(t)
	recordPath := filepath.Join(t.TempDir(), "calls.txt")
	sup, j, cleanup := newTestSupervisorEnv(t, "run_owned_crash")
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := j.SetRunStatus(ctx, "run_owned_crash", "queued"); err != nil {
		t.Fatal(err)
	}
	claims, err := j.ClaimQueuedRuns(ctx, "worker", 1, time.Minute)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim = %v, %v", claims, err)
	}
	sup.BinaryPath = binary
	sup.LeaseOwner = claims[0].Owner
	sup.ExtraEnv = ffTestEnv(
		"FF_TEST_RECORD", recordPath,
		"FF_TEST_RETRY_AT", "send",
		"FF_TEST_RETRY_MAX", "3",
		"FF_TEST_CRASH_SEND_CALL", "2",
	)
	status, err := sup.Run(ctx)
	if status != "" || !errors.Is(err, ErrRunRecoverable) {
		t.Fatalf("owned child crash = status %q err %v; want recoverable/no terminal", status, err)
	}
	if run, getErr := j.GetRun(ctx, "run_owned_crash"); getErr != nil || run.Status != "running" || !run.FinishedAt.IsZero() {
		t.Fatalf("recoverable crash state = %+v, %v", run, getErr)
	}
	if err := j.ExtendLease(ctx, "run_owned_crash", claims[0].Owner, -time.Hour); err != nil {
		t.Fatalf("recoverable crash lost lease prematurely: %v", err)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("recoverable crash reap = %d, %v", n, err)
	}
	if run, _ := j.GetRun(ctx, "run_owned_crash"); run.Status != "queued" {
		t.Fatalf("recoverable crash was not requeued: %+v", run)
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) { w.t.Log(string(p)); return len(p), nil }

func bytesN(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// ffTestEnv builds an ExtraEnv slice for the testworkflow from key/value
// pairs. The supervisor's child-env allowlist (childEnv) deliberately
// strips the parent's environment so a workflow can't read the vault
// master key, so test instrumentation (FF_TEST_*) must be injected via
// ExtraEnv, its documented purpose, rather than os.Setenv. Empty values
// are skipped since os.Getenv can't distinguish unset from set-to-empty.
func ffTestEnv(kv ...string) []string {
	out := make([]string, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			continue
		}
		out = append(out, kv[i]+"="+kv[i+1])
	}
	return out
}

// TestSupervisorHappyPath exercises the full pipe: spawn workflow, run two
// steps to completion, verify journal has both, run terminates succeeded.
func TestSupervisorHappyPath(t *testing.T) {
	binary := buildTestWorkflow(t)
	recordPath := filepath.Join(t.TempDir(), "calls.txt")

	sup, j, closeDB := newTestSupervisorEnv(t, "run_happy")
	defer closeDB()
	sup.BinaryPath = binary

	// Inject test instrumentation via ExtraEnv; the child-env allowlist
	// strips the parent process environment.
	sup.ExtraEnv = ffTestEnv("FF_TEST_RECORD", recordPath)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, err := sup.Run(ctx)
	if err != nil {
		t.Fatalf("supervisor run: %v", err)
	}
	if status != "succeeded" {
		t.Fatalf("status = %s, want succeeded", status)
	}
	verifyRecord(t, recordPath, []string{"fetch", "send"})

	// Journal should have both step rows succeeded.
	out, err := j.FindCachedOutput(context.Background(), "run_happy", "fetch", "k")
	if err != nil {
		t.Fatalf("fetch cache: %v", err)
	}
	if !strings.Contains(string(out), "fetched-customer") {
		t.Fatalf("fetch output = %s", out)
	}
	if _, err := j.FindCachedOutput(context.Background(), "run_happy", "send", "k"); err != nil {
		t.Fatalf("send cache: %v", err)
	}
}

// TestSupervisorReplayAfterCrash is the durable-execution proof: the
// workflow os.Exit(7)s during the fetch step (the SDK does NOT send
// step_end before the crash because os.Exit bypasses defers). The supervisor
// observes EOF and parks the run behind a local recovery schedule. We then
// claim that recovery and re-run with the same
// run_id; the second supervisor reads the journal: fetch is "running" not
// "succeeded", so it re-executes (and fetch records a SECOND line). After
// the second run completes both steps, calls.txt contains:
//
//	fetch
//	fetch    <-- re-executed because previous attempt didn't reach step_end
//	send     <-- only ran once because fetch had to re-execute first
//
// This proves the journal correctly distinguishes incomplete-step from
// completed-step on restart.
//
// In week 4 we'll add idempotency-key short-circuit so the second fetch
// can be skipped if the SAME idempotency key was already recorded as
// running (i.e. attempt-deduplication), but the v0 contract is "running
// rows are inconclusive; re-execute on restart". The test asserts the
// per-step journal status moves to succeeded by the second run.
func TestSupervisorReplayAfterCrash(t *testing.T) {
	binary := buildTestWorkflow(t)
	recordPath := filepath.Join(t.TempDir(), "calls.txt")

	sup1, j, closeDB := newTestSupervisorEnv(t, "run_replay")
	defer closeDB()
	sup1.BinaryPath = binary

	// First run: crash inside fetch.
	sup1.ExtraEnv = ffTestEnv(
		"FF_TEST_RECORD", recordPath,
		"FF_TEST_FAIL_AT", "fetch",
		"FF_TEST_FETCH_RETRY_MAX", "2",
	)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status1, _ := sup1.Run(ctx)
	if status1 != "suspended" {
		t.Fatalf("first run status = %s, want suspended recovery", status1)
	}

	// Calls so far: only "fetch" (the closure ran, then os.Exit(7)).
	verifyRecord(t, recordPath, []string{"fetch"})

	// Second run: restart, this time without the crash flag.
	resumeLocalRecoveryRun(t, j, "run_replay")
	sup2 := *sup1 // share Journal + Vault
	sup2.ExtraEnv = ffTestEnv("FF_TEST_RECORD", recordPath, "FF_TEST_FETCH_RETRY_MAX", "2")
	status2, err := sup2.Run(ctx)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if status2 != "succeeded" {
		t.Fatalf("second run status = %s, want succeeded", status2)
	}

	// fetch ran twice (once in each subprocess); send ran once.
	verifyRecord(t, recordPath, []string{"fetch", "fetch", "send"})

	// Journal: fetch should now have a succeeded attempt; send too.
	if _, err := j.FindCachedOutput(context.Background(), "run_replay", "fetch", "k"); err != nil {
		t.Fatalf("fetch cache after restart: %v", err)
	}
	if _, err := j.FindCachedOutput(context.Background(), "run_replay", "send", "k"); err != nil {
		t.Fatalf("send cache after restart: %v", err)
	}
	if attempts, err := j.AttemptCountSeq(context.Background(), "run_replay", "fetch", 1); err != nil || attempts != 2 {
		t.Fatalf("fetch attempts after crash/restart = %d, %v; want 2", attempts, err)
	}
}

// TestSupervisorRetryBudgetSurvivesLeaseReapAndRestart proves the local
// crash-recovery path end to end. Attempts 2 and 3 die after step_start; each
// crash is parked behind a synthetic schedule and a fresh workflow subprocess
// starts its local counter at one. The journal must nevertheless allocate
// absolute attempts 2 and 3, then refuse closure call 4 because Max=3 was
// consumed.
func TestSupervisorRetryBudgetSurvivesLeaseReapAndRestart(t *testing.T) {
	binary := buildTestWorkflow(t)
	recordPath := filepath.Join(t.TempDir(), "calls.txt")

	sup1, j, closeDB := newTestSupervisorEnv(t, "run_retry_reap")
	defer closeDB()
	sup1.BinaryPath = binary
	sup1.ExtraEnv = ffTestEnv(
		"FF_TEST_RECORD", recordPath,
		"FF_TEST_RETRY_AT", "send",
		"FF_TEST_RETRY_MAX", "3",
		"FF_TEST_CRASH_SEND_CALL", "2",
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, _ := sup1.Run(ctx)
	if status != "suspended" {
		t.Fatalf("first crashed worker status = %s, want suspended recovery", status)
	}
	verifyRecord(t, recordPath, []string{"fetch", "send", "send"})
	resumeLocalRecoveryRun(t, j, "run_retry_reap")

	sup2 := *sup1
	sup2.ExtraEnv = ffTestEnv(
		"FF_TEST_RECORD", recordPath,
		"FF_TEST_RETRY_AT", "send",
		"FF_TEST_RETRY_MAX", "3",
		"FF_TEST_CRASH_SEND_CALL", "3",
	)
	status, _ = sup2.Run(ctx)
	if status != "suspended" {
		t.Fatalf("second crashed worker status = %s, want suspended recovery", status)
	}
	verifyRecord(t, recordPath, []string{"fetch", "send", "send", "send"})
	resumeLocalRecoveryRun(t, j, "run_retry_reap")

	sup3 := *sup1
	sup3.ExtraEnv = ffTestEnv(
		"FF_TEST_RECORD", recordPath,
		"FF_TEST_RETRY_AT", "send",
		"FF_TEST_RETRY_MAX", "3",
	)
	status, err := sup3.Run(ctx)
	if err != nil {
		t.Fatalf("exhausted restart: %v", err)
	}
	if status != "failed_dlq" {
		t.Fatalf("exhausted restart status = %s, want failed_dlq", status)
	}
	// The third restart received RetryExhausted before the closure. A fourth
	// send line would prove the worker-local Max budget had reset.
	verifyRecord(t, recordPath, []string{"fetch", "send", "send", "send"})

	if attempts, err := j.AttemptCountSeq(ctx, "run_retry_reap", "send", 2); err != nil || attempts != 3 {
		t.Fatalf("durable send attempts = %d, %v; want 3", attempts, err)
	}
	latest, err := j.LatestStepAttemptSeq(ctx, "run_retry_reap", "send", 2)
	if err != nil {
		t.Fatal(err)
	}
	if latest.Attempt != 3 || latest.Status != journal.StatusFailed || !strings.Contains(latest.ErrorText, "retry budget exhausted") {
		t.Fatalf("latest durable attempt = %+v, want failed attempt 3", latest)
	}
	items, err := j.ListDeadLetterItems(ctx, 10, 0)
	if err != nil || len(items) != 1 || items[0].StepName != "send" {
		t.Fatalf("exhausted DLQ = %+v, %v; want one send item", items, err)
	}
}

func TestSupervisorHostBudgetOverridesRetryableHint(t *testing.T) {
	binary := buildTestWorkflow(t)
	recordPath := filepath.Join(t.TempDir(), "calls.txt")
	sup, j, closeDB := newTestSupervisorEnv(t, "run_host_budget")
	defer closeDB()
	sup.BinaryPath = binary
	sup.ExtraEnv = ffTestEnv(
		"FF_TEST_RECORD", recordPath,
		"FF_TEST_RETRY_AT", "send",
		"FF_TEST_RETRY_MAX", "2",
		"FF_TEST_RETRY_WIRE_MAX", "1",
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, err := sup.Run(ctx)
	if err != nil {
		t.Fatalf("mismatched retry run: %v", err)
	}
	if status != "failed_dlq" {
		t.Fatalf("mismatched retry status = %q, want failed_dlq", status)
	}
	// NextDelay requested closure #2, but the host's durable Max=1 must win.
	verifyRecord(t, recordPath, []string{"fetch", "send"})
	state, err := j.LatestStepAttemptSeq(ctx, "run_host_budget", "send", 2)
	if err != nil || state.Attempt != 1 || state.Status != journal.StatusFailed || !strings.Contains(state.ErrorText, "retry budget exhausted") {
		t.Fatalf("host-budget terminal state = %+v, %v", state, err)
	}
	items, err := j.ListDeadLetterItems(ctx, 10, 0)
	if err != nil || len(items) != 1 || items[0].StepAttempt == nil || *items[0].StepAttempt != 1 {
		t.Fatalf("host-budget DLQ = %+v, %v", items, err)
	}
}

func resumeLocalRecoveryRun(t *testing.T, j *journal.Journal, runID string) {
	t.Helper()
	ctx := context.Background()
	due, err := j.FindDueSchedules(ctx, time.Now().Add(time.Minute), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, schedule := range due {
		if schedule.RunID != runID || schedule.Kind != journal.KindRecovery {
			continue
		}
		claimed, err := j.ClaimScheduleResume(ctx, schedule.ID, false)
		if err != nil || !claimed {
			t.Fatalf("claim local recovery = %v, %v", claimed, err)
		}
		return
	}
	t.Fatalf("no pending local recovery schedule for %s", runID)
}

// TestSupervisorLongSleepSuspendAndResume is the week-4 proof: a workflow
// with a Sleep beyond the supervisor's SuspendThreshold is upgraded to a
// schedule row, the subprocess exits cleanly, the run is marked suspended.
// The scheduler then ticks with a clock past wake_at, re-spawns the run,
// the workflow replays fetch from journal, hits the Sleep frame again,
// the supervisor sees wait <= 0 and acks immediately, send executes, run
// succeeds.
//
// This is the test that turns "Sleep(72h)" from a placeholder into a real
// durable primitive. Without it, anything longer than SuspendThreshold
// would either pin a goroutine or fail.
func TestSupervisorLongSleepSuspendAndResume(t *testing.T) {
	binary := buildTestWorkflow(t)
	recordPath := filepath.Join(t.TempDir(), "calls.txt")

	sup, j, closeDB := newTestSupervisorEnv(t, "run_long_sleep")
	defer closeDB()
	sup.BinaryPath = binary
	sup.SuspendThreshold = 100 * time.Millisecond // anything past this suspends

	sup.ExtraEnv = ffTestEnv(
		"FF_TEST_RECORD", recordPath,
		"FF_TEST_SLEEP", "1h", // guaranteed to exceed the threshold
	)

	// First run: should suspend at the Sleep boundary.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status1, err := sup.Run(ctx)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if status1 != "suspended" {
		t.Fatalf("first run status = %s, want suspended", status1)
	}
	verifyRecord(t, recordPath, []string{"fetch", "sleep"}) // fetch ran, sleep
	// closure ran (it just records before calling flow.Sleep)

	// Scheduler ticks with a clock past wake_at.
	advanced := time.Now().Add(2 * time.Hour)
	resumed := *sup
	resumed.Now = func() time.Time { return advanced }
	sched := &Scheduler{
		Journal:            j,
		Vault:              sup.Vault,
		Log:                sup.Log,
		Now:                func() time.Time { return advanced },
		ArtifactPath:       func(_, _ string) (string, error) { return binary, nil },
		TickInterval:       time.Hour, // doesn't matter; we call Tick directly
		Batch:              10,
		SupervisorTemplate: resumed,
	}
	if err := sched.Tick(ctx); err != nil {
		t.Fatalf("scheduler tick: %v", err)
	}

	// After scheduler tick, the run should be succeeded. Calls:
	//   fetch (run 1)
	//   sleep (run 1)
	//   fetch (run 2 replay path: closure NOT called because cache hit)  <- not recorded
	//   sleep (run 2 replay: closure IS called, then flow.Sleep returns ack instantly)
	//   send  (run 2 actual execution)
	verifyRecord(t, recordPath, []string{"fetch", "sleep", "sleep", "send"})

	// Both real steps cached.
	if _, err := j.FindCachedOutput(ctx, "run_long_sleep", "fetch", "k"); err != nil {
		t.Fatalf("fetch not cached: %v", err)
	}
	if _, err := j.FindCachedOutput(ctx, "run_long_sleep", "send", "k"); err != nil {
		t.Fatalf("send not cached: %v", err)
	}
}

func TestStartupRecoveryReusesCommittedWaitWithoutWakingLaterSleep(t *testing.T) {
	binary := buildTestWorkflow(t)
	recordPath := filepath.Join(t.TempDir(), "calls.txt")
	sup, j, closeDB := newTestSupervisorEnv(t, "run_wait_crash_window")
	defer closeDB()
	sup.BinaryPath = binary
	sup.SuspendThreshold = 100 * time.Millisecond
	sup.ExtraEnv = ffTestEnv(
		"FF_TEST_RECORD", recordPath,
		"FF_TEST_SLEEP", "1h",
		"FF_TEST_SECOND_SLEEP", "2h",
	)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, err := sup.Run(ctx)
	if err != nil || status != "suspended" {
		t.Fatalf("seed first durable wait = %q, %v", status, err)
	}
	verifyRecord(t, recordPath, []string{"fetch", "sleep"})

	// Model a hard stop after ScheduleSleep committed but before the run's
	// suspended status did. Startup recovery must reuse that exact wait rather
	// than adding a synthetic row that could wake wait-two later.
	if err := j.SetRunStatus(ctx, sup.RunID, "running"); err != nil {
		t.Fatal(err)
	}
	if n, err := j.ReapOrphanedRuns(ctx); err != nil || n != 1 {
		t.Fatalf("startup wait classification = %d, %v", n, err)
	}
	advanced := time.Now().Add(90 * time.Minute)
	resumed := *sup
	resumed.Now = func() time.Time { return advanced }
	sched := &Scheduler{
		Journal:            j,
		Vault:              sup.Vault,
		Log:                sup.Log,
		Now:                func() time.Time { return advanced },
		ArtifactPath:       func(string, string) (string, error) { return binary, nil },
		SupervisorTemplate: resumed,
		Batch:              10,
	}
	if err := sched.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	verifyRecord(t, recordPath, []string{"fetch", "sleep", "sleep", "send", "sleep2"})
	if run, err := j.GetRun(ctx, sup.RunID); err != nil || run.Status != "suspended" {
		t.Fatalf("second wait state = %+v, %v", run, err)
	}
	first, err := j.FindScheduleBySeq(ctx, sup.RunID, 2, journal.KindSleep)
	if err != nil || !first.Fired {
		t.Fatalf("first wait not retired = %+v, %v", first, err)
	}
	second, err := j.FindScheduleBySeq(ctx, sup.RunID, 4, journal.KindSleep)
	if err != nil || second.Fired || second.StepName != "wait-two" {
		t.Fatalf("second wait checkpoint = %+v, %v", second, err)
	}
	due, err := j.FindDueSchedules(ctx, time.Now().Add(4*time.Hour), 10)
	if err != nil || len(due) != 1 || due[0].ID != second.ID || due[0].Kind != journal.KindSleep {
		t.Fatalf("stale recovery can wake later wait = %+v, %v", due, err)
	}
}

// TestSupervisorReplayUsesCacheOnSecondRun verifies the strongest property:
// when a step DID succeed in run 1 and we re-run, that step's closure is
// NOT executed again, the journal output is replayed verbatim. This is the
// idempotency replay guarantee the durable-execution model promises.
func TestSupervisorReplayUsesCacheOnSecondRun(t *testing.T) {
	binary := buildTestWorkflow(t)
	recordPath := filepath.Join(t.TempDir(), "calls.txt")

	sup1, j, closeDB := newTestSupervisorEnv(t, "run_cached")
	defer closeDB()
	sup1.BinaryPath = binary

	// First run: complete both steps successfully then force a non-zero
	// exit AFTER both succeeded so we have a complete journal but the run
	// is marked failed. Restarting should replay both steps from cache
	// without invoking either closure.
	sup1.ExtraEnv = ffTestEnv("FF_TEST_RECORD", recordPath, "FF_TEST_FAIL_AFTER_SEND", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status1, _ := sup1.Run(ctx)
	if status1 != "failed" {
		t.Fatalf("first run status = %s, want failed (post-send return error)", status1)
	}
	verifyRecord(t, recordPath, []string{"fetch", "send"})

	// Drop the failure flag and restart with the same run_id.
	sup2 := *sup1
	sup2.ExtraEnv = ffTestEnv("FF_TEST_RECORD", recordPath)
	status2, err := sup2.Run(ctx)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if status2 != "succeeded" {
		t.Fatalf("second run status = %s, want succeeded (cache replay)", status2)
	}

	// CRITICAL: calls file must STILL be just [fetch, send], because the
	// second run replayed both from the journal without invoking either
	// closure. This is the durable-execution promise.
	verifyRecord(t, recordPath, []string{"fetch", "send"})

	// Sanity: cached outputs are intact.
	out, err := j.FindCachedOutput(context.Background(), "run_cached", "fetch", "k")
	if err != nil || !strings.Contains(string(out), "fetched-customer") {
		t.Fatalf("fetch cache stale: out=%s err=%v", out, err)
	}
}

func TestStartupRecoveryReplaysCommittedHashResultToSuccess(t *testing.T) {
	binary := buildTestWorkflow(t)
	recordPath := filepath.Join(t.TempDir(), "calls.txt")
	sup, j, closeDB := newTestSupervisorEnv(t, "run_hash_committed_restart")
	defer closeDB()
	sup.BinaryPath = binary
	sup.ExtraEnv = ffTestEnv("FF_TEST_RECORD", recordPath)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if status, err := sup.Run(ctx); err != nil || status != "succeeded" {
		t.Fatalf("seed committed Hash result = %q, %v", status, err)
	}
	verifyRecord(t, recordPath, []string{"fetch", "send"})

	// Simulate daemon death after both StepEnd/cache commits but before durable
	// terminal status. The startup classifier sees a running orphan and the
	// scheduler must replay cached values, not send the document again.
	if err := j.SetRunStatus(ctx, sup.RunID, "running"); err != nil {
		t.Fatal(err)
	}
	if n, err := j.ReapOrphanedRuns(ctx); err != nil || n != 1 {
		t.Fatalf("startup committed-result classification = %d, %v", n, err)
	}
	sched := &Scheduler{
		Journal:            j,
		Vault:              sup.Vault,
		Log:                sup.Log,
		Now:                time.Now,
		ArtifactPath:       func(string, string) (string, error) { return binary, nil },
		SupervisorTemplate: *sup,
		Batch:              10,
	}
	if err := sched.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	verifyRecord(t, recordPath, []string{"fetch", "send"})
	if run, err := j.GetRun(ctx, sup.RunID); err != nil || run.Status != "succeeded" || run.FinishedAt.IsZero() {
		t.Fatalf("startup committed-result recovery = %+v, %v", run, err)
	}
}

func TestReplaySuccessDoesNotMutateHistoricalRun(t *testing.T) {
	binary := buildTestWorkflow(t)
	sup, j, closeDB := newTestSupervisorEnv(t, "run_readonly_replay")
	defer closeDB()
	sup.BinaryPath = binary
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, err := sup.Run(ctx)
	if err != nil || status != "succeeded" {
		t.Fatalf("seed run = %s, %v", status, err)
	}
	before, err := j.GetRun(ctx, "run_readonly_replay")
	if err != nil {
		t.Fatal(err)
	}
	beforeAttempts, err := j.AttemptCountSeq(ctx, "run_readonly_replay", "fetch", 1)
	if err != nil {
		t.Fatal(err)
	}

	replay := *sup
	replay.Mode = "replay"
	status, err = replay.Run(ctx)
	if err != nil || status != "succeeded" {
		t.Fatalf("replay = %s, %v", status, err)
	}
	after, err := j.GetRun(ctx, "run_readonly_replay")
	if err != nil {
		t.Fatal(err)
	}
	afterAttempts, _ := j.AttemptCountSeq(ctx, "run_readonly_replay", "fetch", 1)
	if after.Status != before.Status || !after.FinishedAt.Equal(before.FinishedAt) || afterAttempts != beforeAttempts {
		t.Fatalf("successful replay mutated history: before=%+v/%d after=%+v/%d", before, beforeAttempts, after, afterAttempts)
	}
}

func TestReplayDivergenceDoesNotMutateHistoricalRun(t *testing.T) {
	binary := buildTestWorkflow(t)
	sup, j, closeDB := newTestSupervisorEnv(t, "run_readonly_divergence")
	defer closeDB()
	sup.BinaryPath = binary
	sup.ExtraEnv = ffTestEnv("FF_TEST_FAIL_AT", "fetch", "FF_TEST_FETCH_RETRY_MAX", "2")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if status, _ := sup.Run(ctx); status != "suspended" {
		t.Fatalf("seed crash status = %s, want suspended recovery", status)
	}
	before, err := j.GetRun(ctx, "run_readonly_divergence")
	if err != nil {
		t.Fatal(err)
	}
	beforeAttempts, err := j.AttemptCountSeq(ctx, "run_readonly_divergence", "fetch", 1)
	if err != nil {
		t.Fatal(err)
	}

	replay := *sup
	replay.Mode = "replay"
	replay.ExtraEnv = nil
	if _, err := replay.Run(ctx); !errors.Is(err, ErrReplayDivergence) {
		t.Fatalf("replay divergence = %v, want ErrReplayDivergence", err)
	}
	after, err := j.GetRun(ctx, "run_readonly_divergence")
	if err != nil {
		t.Fatal(err)
	}
	afterAttempts, _ := j.AttemptCountSeq(ctx, "run_readonly_divergence", "fetch", 1)
	if after.Status != before.Status || !after.FinishedAt.Equal(before.FinishedAt) || afterAttempts != beforeAttempts {
		t.Fatalf("divergent replay mutated history: before=%+v/%d after=%+v/%d", before, beforeAttempts, after, afterAttempts)
	}
}

func TestOrdinalReplayRejectsIdentityDrift(t *testing.T) {
	sup, j, cleanup := newTestSupervisorEnv(t, "run_ordinal_identity")
	defer cleanup()
	ctx := context.Background()
	if _, err := j.RecordStepStartSeq(ctx, sup.RunID, "send", 1, 1, "idem-v1", "hash-v1"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndSeq(ctx, sup.RunID, "send", 1, 1, json.RawMessage(`{"sent":true}`), ""); err != nil {
		t.Fatal(err)
	}

	// A resumed workflow reached the same ordinal and name, but its operation
	// identity changed. The cached side effect must not be handed back to it.
	var response bytes.Buffer
	d := &dispatcher{sup: sup, enc: wire.NewEncoder(&response), writeMu: &sync.Mutex{}}
	frame, err := wire.Wrap(1, 0, wire.KindStepStart, wire.StepStart{
		StepName: "send", Seq: 1, Attempt: 1, IdempotencyKey: "idem-v2", InputHash: "hash-v2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.handleStepStart(ctx, frame); !errors.Is(err, ErrReplayDivergence) {
		t.Fatalf("ordinal identity drift error = %v, want ErrReplayDivergence", err)
	}
	if response.Len() != 0 {
		t.Fatalf("identity drift wrote a replay response: %s", response.Bytes())
	}
}

func TestOrdinalLiveResumeRejectsNameDriftAfterFailedAttempt(t *testing.T) {
	sup, j, cleanup := newTestSupervisorEnv(t, "run_ordinal_failed_drift")
	defer cleanup()
	ctx := context.Background()
	if _, err := j.RecordStepStartSeq(ctx, sup.RunID, "charge", 1, 1, "idem-v1", "hash-v1"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndSeq(ctx, sup.RunID, "charge", 1, 1, json.RawMessage(`null`), "provider unavailable"); err != nil {
		t.Fatal(err)
	}

	// This models a live scheduler/worker resume after the first attempt
	// failed. There is no successful cache row, so the old check would have
	// opened a new row for the renamed step and executed it.
	var response bytes.Buffer
	d := &dispatcher{sup: sup, enc: wire.NewEncoder(&response), writeMu: &sync.Mutex{}}
	frame, err := wire.Wrap(1, 0, wire.KindStepStart, wire.StepStart{
		StepName: "charge-v2", Seq: 1, Attempt: 1, IdempotencyKey: "idem-v2", InputHash: "hash-v2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.handleStepStart(ctx, frame); !errors.Is(err, ErrReplayDivergence) {
		t.Fatalf("failed-attempt name drift error = %v, want ErrReplayDivergence", err)
	}
	if response.Len() != 0 {
		t.Fatalf("failed-attempt name drift wrote a response: %s", response.Bytes())
	}
}

// TestSupervisorAwaitSignalSuspendAndResume drives the full week-7 signal
// flow: workflow blocks on AwaitSignal, supervisor persists the schedule
// + suspends, an external "delivery" via journal.FireSignal sets the
// payload, scheduler tick re-spawns the workflow, AwaitSignal returns the
// payload, send step executes, run completes succeeded.
func TestSupervisorAwaitSignalSuspendAndResume(t *testing.T) {
	binary := buildTestWorkflow(t)
	recordPath := filepath.Join(t.TempDir(), "calls.txt")

	sup, j, closeDB := newTestSupervisorEnv(t, "run_signal")
	defer closeDB()
	sup.BinaryPath = binary
	// Exercise the SECURE signal-token path: with a signing key wired, the
	// token is HMAC(perRunKey, name) delivered to the workflow over Hello, not
	// derivable from the (semi-public) runID alone.
	sup.SignalSigningKey = []byte("test-signal-signing-key-0123456789")

	sup.ExtraEnv = ffTestEnv("FF_TEST_RECORD", recordPath, "FF_TEST_AWAIT_SIGNAL", "1")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// First run: should suspend at the AwaitSignal boundary.
	status1, err := sup.Run(ctx)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if status1 != "suspended" {
		t.Fatalf("first run status = %s, want suspended", status1)
	}

	// The recorded await line includes the token; assert format and
	// confirm the supervisor wrote a matching schedule row.
	lines := readRecord(t, recordPath)
	if len(lines) < 2 || lines[0] != "fetch" || !strings.HasPrefix(lines[1], "await:sig_") {
		t.Fatalf("expected fetch + await:sig_..., got %v", lines)
	}
	token := strings.TrimPrefix(lines[1], "await:")
	perRunKey := perRunSignalKey(sup.SignalSigningKey, "run_signal")
	if expect := DeriveSignalToken(perRunKey, "run_signal", "approval"); token != expect {
		t.Fatalf("token mismatch: workflow=%s supervisor=%s", token, expect)
	}
	// The token must NOT be derivable from the (semi-public) runID alone.
	if legacy := DeriveSignalToken("", "run_signal", "approval"); token == legacy {
		t.Fatalf("signal token %s is forgeable from runID (HMAC signing not applied)", token)
	}

	sched, err := j.FindLatestSignalSchedule(ctx, "run_signal", "wait-approval")
	// Step name in the SDK defaults to signal name if the workflow side
	// passes name as both step name and signal name. Look up by what
	// pipeflow actually sends: step_name = signal_name = "approval".
	if err != nil {
		sched, err = j.FindLatestSignalSchedule(ctx, "run_signal", "approval")
	}
	if err != nil {
		t.Fatalf("schedule not persisted: %v", err)
	}
	if sched.SignalToken != token {
		t.Fatalf("schedule token = %s, want %s", sched.SignalToken, token)
	}

	// External delivery.
	if _, _, err := j.FireSignal(ctx, token, []byte(`{"approved":true}`)); err != nil {
		t.Fatalf("fire signal: %v", err)
	}

	// Scheduler tick re-spawns the workflow.
	resumed := *sup
	sched2 := &Scheduler{
		Journal:            j,
		Vault:              sup.Vault,
		Log:                sup.Log,
		ArtifactPath:       func(_, _ string) (string, error) { return binary, nil },
		TickInterval:       time.Hour,
		Batch:              10,
		SupervisorTemplate: resumed,
		Now:                func() time.Time { return time.Now().Add(time.Second) },
	}
	if err := sched2.Tick(ctx); err != nil {
		t.Fatalf("scheduler tick: %v", err)
	}

	// After resume, send must have executed and the run must be succeeded.
	info, err := j.GetRun(ctx, "run_signal")
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	if info.Status != "succeeded" {
		t.Fatalf("run status = %s, want succeeded", info.Status)
	}

	// Recording shape: fetch, await, signal:{...}, send. Across the two
	// runs the await line appears twice (once per spawn) because the
	// workflow records BEFORE calling AwaitSignal; on resume the host
	// short-circuits AwaitSignal so the closure that runs the recordCall
	// is invoked again before the wire reply.
	finalLines := readRecord(t, recordPath)
	wantContains := []string{"fetch", `signal:{"approved":true}`, "send"}
	for _, w := range wantContains {
		found := false
		for _, l := range finalLines {
			if l == w {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing %q in calls: %v", w, finalLines)
		}
	}
}

// TestSupervisorPermanentErrorMovesToDLQ proves the dead-letter path.
// The send step returns reactor.Permanent(err); the supervisor records
// the step as failed, writes a dead_letter row, and marks the run as
// failed_dlq instead of failed.
func TestSupervisorPermanentErrorMovesToDLQ(t *testing.T) {
	binary := buildTestWorkflow(t)
	recordPath := filepath.Join(t.TempDir(), "calls.txt")

	sup, j, closeDB := newTestSupervisorEnv(t, "run_dlq")
	defer closeDB()
	sup.BinaryPath = binary

	sup.ExtraEnv = ffTestEnv("FF_TEST_RECORD", recordPath, "FF_TEST_PERMANENT_AT", "send")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, err := sup.Run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if status != "failed_dlq" {
		t.Fatalf("status = %s, want failed_dlq", status)
	}

	items, err := j.ListDeadLetterItems(ctx, 10, 0)
	if err != nil {
		t.Fatalf("list dead-letter: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d dead_letter rows, want 1", len(items))
	}
	got := items[0]
	if got.RunID != "run_dlq" || got.StepName != "send" || !strings.Contains(got.ErrorText, "smtp permanent") {
		t.Fatalf("dead_letter row shape wrong: %+v", got)
	}

	info, err := j.GetRun(ctx, "run_dlq")
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	if info.Status != "failed_dlq" {
		t.Fatalf("run status = %s, want failed_dlq", info.Status)
	}
}

// readRecord returns the lines of the FF_TEST_RECORD file or nil when empty.
func readRecord(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	out := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(out) == 1 && out[0] == "" {
		return nil
	}
	return out
}

// verifyRecord reads the record file and asserts its lines match want.
func verifyRecord(t *testing.T, path string, want []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}
	if len(lines) != len(want) {
		t.Fatalf("calls = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("call %d = %q, want %q (full=%v)", i, lines[i], want[i], lines)
		}
	}
}
