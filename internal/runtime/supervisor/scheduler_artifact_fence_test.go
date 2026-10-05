package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestScheduledResumeArtifactFenceFailsClosedBeforeQueueOrSpawn(t *testing.T) {
	for _, enqueue := range []bool{false, true} {
		name := "local"
		if enqueue {
			name = "distributed"
		}
		t.Run(name, func(t *testing.T) {
			runID := "run_resume_fenced_" + name
			_, j, closeDB := newTestSupervisorEnv(t, "unused_"+runID)
			defer closeDB()
			ctx := context.Background()
			// A legacy/unpinned run produces the validator's typed permanent
			// identity fence. Node-local ArtifactPath failures are tested below and
			// must remain pending instead.
			if err := j.CreateRun(ctx, runID, "wf_test", "manual", json.RawMessage(`{}`)); err != nil {
				t.Fatal(err)
			}
			if err := j.SetRunStatus(ctx, runID, "suspended"); err != nil {
				t.Fatal(err)
			}
			if _, err := j.ScheduleSleep(ctx, runID, "wait", time.Now().UTC().Add(-time.Hour)); err != nil {
				t.Fatal(err)
			}
			artifactChecks := 0
			terminals := 0
			sched := &Scheduler{
				Journal: j,
				Now:     time.Now,
				ArtifactPath: func(string, string) (string, error) {
					artifactChecks++
					return "", errors.New("tampered immutable artifact")
				},
				Enqueue: enqueue,
				Batch:   10,
				OnTerminal: func(_ context.Context, info TerminalInfo) {
					terminals++
					if info.Status != "failed" || info.ErrorText != journal.WorkflowArtifactFenceRunLog {
						t.Errorf("terminal = %+v", info)
					}
				},
			}
			if err := sched.Tick(ctx); err != nil {
				t.Fatal(err)
			}
			if artifactChecks != 0 || terminals != 1 {
				t.Fatalf("artifact checks=%d terminals=%d", artifactChecks, terminals)
			}
			run, err := j.GetRun(ctx, runID)
			if err != nil {
				t.Fatal(err)
			}
			if run.Status != "failed" || run.FinishedAt.IsZero() {
				t.Fatalf("fenced resumed run = %+v", run)
			}
			if due, err := j.FindDueSchedules(ctx, time.Now().UTC(), 10); err != nil || len(due) != 0 {
				t.Fatalf("artifact-fenced schedule remained due: %+v, %v", due, err)
			}
			logs, err := j.GetRunLogs(ctx, runID)
			if err != nil || len(logs) == 0 || logs[len(logs)-1] != journal.WorkflowArtifactFenceRunLog {
				t.Fatalf("artifact-fence logs = %v, %v", logs, err)
			}
		})
	}
}

func TestScheduledResumeIntegrityFenceFailsBeforeQueueOrSpawn(t *testing.T) {
	_, j, closeDB := newTestSupervisorEnv(t, "run_resume_integrity_fenced")
	defer closeDB()
	ctx := context.Background()
	if err := j.SetRunStatus(ctx, "run_resume_integrity_fenced", "suspended"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.ScheduleSleep(ctx, "run_resume_integrity_fenced", "wait", time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	terminals := 0
	sched := &Scheduler{
		Journal: j, Now: time.Now, Batch: 10,
		ArtifactPath: func(string, string) (string, error) { return "/immutable/workflow", nil },
		IntegrityCheck: func(_ context.Context, slug string, version journal.WorkflowVersion) error {
			if slug != "test-replay" || version.Version != 1 {
				t.Fatalf("integrity callback received slug=%q version=%+v", slug, version)
			}
			return &journal.WorkflowArtifactFenceError{
				WorkflowID: "wf_test", Version: version.Version,
				PinnedDigest: version.ArtifactSHA256, Reason: "retained source mismatch",
			}
		},
		OnTerminal: func(_ context.Context, info TerminalInfo) {
			terminals++
			if info.Status != "failed" || info.ErrorText != journal.WorkflowArtifactFenceRunLog {
				t.Errorf("terminal = %+v", info)
			}
		},
	}
	if err := sched.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if terminals != 1 {
		t.Fatalf("integrity fence terminal callbacks = %d, want 1", terminals)
	}
	run, err := j.GetRun(ctx, "run_resume_integrity_fenced")
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "failed" || run.FinishedAt.IsZero() {
		t.Fatalf("integrity-fenced resumed run = %+v", run)
	}
}

func TestScheduledSleepAndSignalArtifactAvailabilityStayPending(t *testing.T) {
	for _, kind := range []string{journal.KindSleep, journal.KindSignal} {
		for _, enqueue := range []bool{false, true} {
			name := kind + "_local"
			if enqueue {
				name = kind + "_distributed"
			}
			t.Run(name, func(t *testing.T) {
				runID := "run_artifact_wait_" + name
				_, j, closeDB := newTestSupervisorEnv(t, runID)
				defer closeDB()
				ctx := context.Background()
				if err := j.SetRunStatus(ctx, runID, "suspended"); err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC()
				var scheduleID string
				var err error
				if kind == journal.KindSleep {
					scheduleID, err = j.ScheduleSleep(ctx, runID, "wait", now.Add(-time.Hour))
				} else {
					scheduleID, err = j.ScheduleSignal(ctx, runID, "wait", "approval", "token_"+name, now.Add(-time.Hour))
				}
				if err != nil {
					t.Fatal(err)
				}
				checks := 0
				terminals := 0
				sched := &Scheduler{
					Journal: j,
					Now:     func() time.Time { return now },
					ArtifactPath: func(string, string) (string, error) {
						checks++
						return "", errors.New("artifact mount unavailable")
					},
					Enqueue: enqueue,
					Batch:   10,
					OnTerminal: func(context.Context, TerminalInfo) {
						terminals++
					},
				}
				if err := sched.Tick(ctx); err != nil {
					t.Fatal(err)
				}
				if err := sched.Tick(ctx); err != nil {
					t.Fatal(err)
				}
				if checks != 1 || terminals != 0 {
					t.Fatalf("artifact checks=%d terminals=%d", checks, terminals)
				}
				if run, err := j.GetRun(ctx, runID); err != nil || run.Status != "suspended" || !run.FinishedAt.IsZero() {
					t.Fatalf("artifact outage terminalized run = %+v, %v", run, err)
				}
				if due, err := j.FindDueSchedules(ctx, now, 10); err != nil || len(due) != 0 {
					t.Fatalf("artifact outage was not backed off = %+v, %v", due, err)
				}
				due, err := j.FindDueSchedules(ctx, now.Add(2*time.Minute), 10)
				if err != nil || len(due) != 1 || due[0].ID != scheduleID || due[0].Kind != kind {
					t.Fatalf("artifact outage lost exact schedule = %+v, %v", due, err)
				}
				logs, err := j.GetRunLogs(ctx, runID)
				if err != nil || len(logs) != 1 || logs[0] != journal.WorkflowArtifactFenceRunLog {
					t.Fatalf("artifact outage durable marker = %v, %v", logs, err)
				}
			})
		}
	}
}

func TestDistributedScheduledResumeWaitsForWorkerArtifactTree(t *testing.T) {
	const runID = "run_worker_artifact_wait"
	_, j, closeDB := newTestSupervisorEnv(t, runID)
	defer closeDB()
	ctx := context.Background()
	if err := j.SetRunStatus(ctx, runID, "suspended"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scheduleID, err := j.ScheduleSleep(ctx, runID, "wait", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	workerReady := false
	checks := 0
	sched := &Scheduler{
		Journal: j,
		Now:     func() time.Time { return now },
		ArtifactPath: func(string, string) (string, error) {
			return "/immutable/workflow", nil
		},
		QueueArtifactCheck: func(context.Context, string, journal.WorkflowVersion) error {
			checks++
			if !workerReady {
				return errors.New("worker PVC artifact missing")
			}
			return nil
		},
		Enqueue: true,
		Batch:   10,
	}
	if err := sched.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if checks != 1 {
		t.Fatalf("worker artifact checks = %d, want one", checks)
	}
	if run, err := j.GetRun(ctx, runID); err != nil || run.Status != "suspended" || !run.FinishedAt.IsZero() {
		t.Fatalf("missing worker artifact consumed or failed continuation: %+v, %v", run, err)
	}
	if due, err := j.FindDueSchedules(ctx, now, 10); err != nil || len(due) != 0 {
		t.Fatalf("missing worker artifact did not back off schedule: %+v, %v", due, err)
	}
	workerReady = true
	now = now.Add(2 * time.Minute)
	if due, err := j.FindDueSchedules(ctx, now, 10); err != nil || len(due) != 1 || due[0].ID != scheduleID {
		t.Fatalf("worker artifact outage lost exact schedule: %+v, %v", due, err)
	}
	if err := sched.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if checks != 2 {
		t.Fatalf("recovered worker artifact checks = %d, want two", checks)
	}
	if run, err := j.GetRun(ctx, runID); err != nil || run.Status != "queued" || !run.FinishedAt.IsZero() {
		t.Fatalf("repaired worker artifact did not re-enqueue exact continuation: %+v, %v", run, err)
	}
	if due, err := j.FindDueSchedules(ctx, now, 10); err != nil || len(due) != 0 {
		t.Fatalf("repaired schedule remained due: %+v, %v", due, err)
	}
	logs, err := j.GetRunLogs(ctx, runID)
	if err != nil || len(logs) != 1 || logs[0] != journal.WorkflowArtifactFenceRunLog {
		t.Fatalf("worker artifact outage marker = %v, %v", logs, err)
	}
}

func TestRecoveryArtifactOutageStaysPendingWithBoundedDurableLog(t *testing.T) {
	_, j, closeDB := newTestSupervisorEnv(t, "run_recovery_artifact_wait")
	defer closeDB()
	ctx := context.Background()
	if status, err := j.RecoverLocalInterruptedRun(ctx, "run_recovery_artifact_wait", true); err != nil || status != "suspended" {
		t.Fatalf("seed recovery schedule = %q, %v", status, err)
	}
	now := time.Now().UTC()
	checks := 0
	sched := &Scheduler{
		Journal: j,
		Now:     func() time.Time { return now },
		ArtifactPath: func(string, string) (string, error) {
			checks++
			return "", errors.New("pinned bytes temporarily unavailable")
		},
		TickInterval: time.Second,
		Batch:        10,
	}
	if err := sched.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sched.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if checks != 1 {
		t.Fatalf("recovery artifact probes before backoff = %d, want 1", checks)
	}
	now = now.Add(2 * time.Minute)
	if err := sched.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if checks != 2 {
		t.Fatalf("recovery artifact probes after backoff = %d, want 2", checks)
	}
	logs, err := j.GetRunLogs(ctx, "run_recovery_artifact_wait")
	if err != nil || len(logs) != 1 || logs[0] != journal.WorkflowArtifactFenceRunLog {
		t.Fatalf("repeated recovery fence logs = %v, %v", logs, err)
	}
	if run, err := j.GetRun(ctx, "run_recovery_artifact_wait"); err != nil || run.Status != "suspended" {
		t.Fatalf("recovery artifact outage terminalized run = %+v, %v", run, err)
	}
}

func TestRecoveryInvalidPinnedIdentityFailsTerminalInsteadOfDeferringForever(t *testing.T) {
	_, j, closeDB := newTestSupervisorEnv(t, "unused_pinned_run")
	defer closeDB()
	ctx := context.Background()
	if err := j.CreateRun(ctx, "run_legacy_unpinned_recovery", "wf_test", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if status, err := j.RecoverLocalInterruptedRun(ctx, "run_legacy_unpinned_recovery", true); err != nil || status != "suspended" {
		t.Fatalf("seed legacy recovery schedule = %q, %v", status, err)
	}
	artifactCalled := false
	sched := &Scheduler{
		Journal: j,
		Now:     time.Now,
		ArtifactPath: func(string, string) (string, error) {
			artifactCalled = true
			return "", nil
		},
		Batch: 10,
	}
	if err := sched.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if artifactCalled {
		t.Fatal("invalid persisted artifact identity reached filesystem lookup")
	}
	if run, err := j.GetRun(ctx, "run_legacy_unpinned_recovery"); err != nil || run.Status != "failed" || run.FinishedAt.IsZero() {
		t.Fatalf("invalid recovery identity = %+v, %v", run, err)
	}
	if due, err := j.FindDueSchedules(ctx, time.Now().Add(time.Hour), 10); err != nil || len(due) != 0 {
		t.Fatalf("invalid recovery identity remained pending = %+v, %v", due, err)
	}
}

func TestSchedulerCancellationBeforeArtifactResolutionLeavesSchedulePending(t *testing.T) {
	_, j, closeDB := newTestSupervisorEnv(t, "run_cancelled_recovery_probe")
	defer closeDB()
	ctx := context.Background()
	if status, err := j.RecoverLocalInterruptedRun(ctx, "run_cancelled_recovery_probe", true); err != nil || status != "suspended" {
		t.Fatalf("seed cancelled recovery probe = %q, %v", status, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	sched := &Scheduler{
		Journal:      j,
		Now:          time.Now,
		ArtifactPath: func(string, string) (string, error) { t.Fatal("cancelled tick resolved artifact"); return "", nil },
		Batch:        10,
	}
	if err := sched.Tick(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scheduler tick = %v", err)
	}
	if run, err := j.GetRun(ctx, "run_cancelled_recovery_probe"); err != nil || run.Status != "suspended" {
		t.Fatalf("cancelled recovery probe mutated run = %+v, %v", run, err)
	}
	if due, err := j.FindDueSchedules(ctx, time.Now().Add(time.Minute), 10); err != nil || len(due) != 1 {
		t.Fatalf("cancelled recovery probe consumed schedule = %+v, %v", due, err)
	}
}

func TestSchedulerStopRacesInitializationWithoutReopeningAdmission(t *testing.T) {
	_, j, closeDB := newTestSupervisorEnv(t, "run_scheduler_stop_race")
	defer closeDB()
	for i := 0; i < 100; i++ {
		sched := &Scheduler{Journal: j, TickInterval: time.Millisecond, Batch: 1}
		done := make(chan error, 1)
		go func() { done <- sched.Run(context.Background()) }()
		sched.Stop()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("iteration %d scheduler run after Stop = %v", i, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("iteration %d scheduler Stop lost closed channel", i)
		}
		if err := sched.beginDispatch(context.Background()); !errors.Is(err, context.Canceled) {
			t.Fatalf("iteration %d reopened scheduler admission: %v", i, err)
		}
	}
}
