package supervisor

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/cancelreg"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestDistributedCancellationCauseControlsTerminalPersistence(t *testing.T) {
	binary := buildTestWorkflow(t)

	t.Run("drain timeout remains recoverable", func(t *testing.T) {
		sup, j, cleanup := newTestSupervisorEnv(t, "run_shutdown_recoverable")
		defer cleanup()
		ctx := context.Background()
		if err := j.SetRunStatus(ctx, sup.RunID, "queued"); err != nil {
			t.Fatal(err)
		}
		claims, err := j.ClaimQueuedRuns(ctx, "worker", 1, time.Minute)
		if err != nil || len(claims) != 1 {
			t.Fatalf("claim = %v, %v", claims, err)
		}
		sup.BinaryPath = binary
		sup.LeaseOwner = claims[0].Owner

		execCtx, cancelExec := context.WithCancelCause(context.Background())
		registry := cancelreg.New()
		registry.RegisterCause(sup.RunID, cancelExec)
		if got := registry.CancelAllWithCause(cancelreg.ErrInfrastructureShutdown); got != 1 {
			t.Fatalf("shutdown signal count = %d, want 1", got)
		}
		status, runErr := sup.Run(execCtx)
		if status != "" || !errors.Is(runErr, cancelreg.ErrInfrastructureShutdown) {
			t.Fatalf("infrastructure stop = status %q err %v; want recoverable empty status", status, runErr)
		}
		if run, getErr := j.GetRun(ctx, sup.RunID); getErr != nil || run.Status != "running" || !run.FinishedAt.IsZero() {
			t.Fatalf("infrastructure stop persisted terminal state = %+v, %v", run, getErr)
		}
		if err := j.ExtendLease(ctx, sup.RunID, claims[0].Owner, -time.Minute); err != nil {
			t.Fatalf("recoverable shutdown lost owned lease: %v", err)
		}
		if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
			t.Fatalf("recoverable shutdown reap = %d, %v", n, err)
		}
		if run, _ := j.GetRun(ctx, sup.RunID); run.Status != "queued" {
			t.Fatalf("recoverable shutdown status after reap = %q, want queued", run.Status)
		}
	})

	t.Run("operator cancel is terminal", func(t *testing.T) {
		sup, j, cleanup := newTestSupervisorEnv(t, "run_operator_cancelled")
		defer cleanup()
		ctx := context.Background()
		if err := j.SetRunStatus(ctx, sup.RunID, "queued"); err != nil {
			t.Fatal(err)
		}
		claims, err := j.ClaimQueuedRuns(ctx, "worker", 1, time.Minute)
		if err != nil || len(claims) != 1 {
			t.Fatalf("claim = %v, %v", claims, err)
		}
		sup.BinaryPath = binary
		sup.LeaseOwner = claims[0].Owner

		execCtx, cancelExec := context.WithCancelCause(context.Background())
		registry := cancelreg.New()
		registry.RegisterCause(sup.RunID, cancelExec)
		if !registry.Cancel(sup.RunID) {
			t.Fatal("operator cancel did not signal registered run")
		}
		status, _ := sup.Run(execCtx)
		if status != "cancelled" {
			t.Fatalf("operator cancel status = %q, want cancelled", status)
		}
		if run, getErr := j.GetRun(ctx, sup.RunID); getErr != nil || run.Status != "cancelled" || run.FinishedAt.IsZero() {
			t.Fatalf("operator cancel state = %+v, %v", run, getErr)
		}
		if err := j.ExtendLease(ctx, sup.RunID, claims[0].Owner, time.Minute); !errors.Is(err, journal.ErrLeaseOwnershipLost) {
			t.Fatalf("operator-cancelled run retained lease: %v", err)
		}
		if replacement, err := j.ClaimQueuedRuns(ctx, "replacement", 1, time.Minute); err != nil || len(replacement) != 0 {
			t.Fatalf("operator-cancelled run became replacement work = %v, %v", replacement, err)
		}
	})
}

func TestLocalCancellationCauseControlsRecovery(t *testing.T) {
	binary := buildTestWorkflow(t)

	t.Run("infrastructure stop schedules local recovery", func(t *testing.T) {
		sup, j, cleanup := newTestSupervisorEnv(t, "run_local_shutdown_recovery")
		defer cleanup()
		sup.BinaryPath = binary
		execCtx, cancelExec := context.WithCancelCause(context.Background())
		cancelExec(cancelreg.ErrInfrastructureShutdown)

		status, runErr := sup.Run(execCtx)
		if status != "suspended" || !errors.Is(runErr, cancelreg.ErrInfrastructureShutdown) {
			t.Fatalf("local infrastructure stop = status %q err %v", status, runErr)
		}
		if run, err := j.GetRun(context.Background(), sup.RunID); err != nil || run.Status != "suspended" || !run.FinishedAt.IsZero() {
			t.Fatalf("local infrastructure recovery state = %+v, %v", run, err)
		}
		due, err := j.FindDueSchedules(context.Background(), time.Now().Add(time.Minute), 10)
		if err != nil || len(due) != 1 || due[0].Kind != journal.KindRecovery {
			t.Fatalf("local infrastructure recovery schedule = %+v, %v", due, err)
		}
	})

	t.Run("operator cancel remains terminal", func(t *testing.T) {
		sup, j, cleanup := newTestSupervisorEnv(t, "run_local_operator_cancel")
		defer cleanup()
		sup.BinaryPath = binary
		execCtx, cancelExec := context.WithCancelCause(context.Background())
		cancelExec(context.Canceled)

		status, _ := sup.Run(execCtx)
		if status != "cancelled" {
			t.Fatalf("local operator cancel status = %q", status)
		}
		if run, err := j.GetRun(context.Background(), sup.RunID); err != nil || run.Status != "cancelled" || run.FinishedAt.IsZero() {
			t.Fatalf("local operator cancellation state = %+v, %v", run, err)
		}
		if due, err := j.FindDueSchedules(context.Background(), time.Now().Add(time.Minute), 10); err != nil || len(due) != 0 {
			t.Fatalf("operator cancellation scheduled recovery = %+v, %v", due, err)
		}
	})
}

func TestSchedulerOnlyExecutionDrainsAndInfrastructureCancelRecovers(t *testing.T) {
	binary := buildTestWorkflow(t)
	recordPath := t.TempDir() + "/calls.txt"
	sup, j, cleanup := newTestSupervisorEnv(t, "run_scheduler_shutdown")
	defer cleanup()
	ctx := context.Background()
	if err := j.SetRunStatus(ctx, sup.RunID, "suspended"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.ScheduleSleep(ctx, sup.RunID, "startup", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	registry := cancelreg.New()
	sched := &Scheduler{
		Journal: j,
		Vault:   sup.Vault,
		Log:     sup.Log,
		Now:     time.Now,
		ArtifactPath: func(string, string) (string, error) {
			return binary, nil
		},
		Cancels: registry,
		SupervisorTemplate: Supervisor{
			ExtraEnv:      ffTestEnv("FF_TEST_RECORD", recordPath, "FF_TEST_BLOCK_SEND", "1"),
			ACLPermissive: true,
		},
	}
	tickDone := make(chan error, 1)
	go func() { tickDone <- sched.Tick(ctx) }()
	// InFlight covers the whole dispatch, including artifact validation and the
	// subprocess handshake. Under a full-suite build those stages can be CPU
	// starved even though dispatch admission has already incremented the count.
	// Give the child the same generous startup window as the other subprocess
	// E2Es; the assertions below retain short deadlines for drain and cancel.
	deadline := time.Now().Add(30 * time.Second)
	for sched.InFlight() == 0 || recordedCallCountForTest(recordPath, "send") == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("scheduler child did not become active; in_flight=%d", sched.InFlight())
		}
		time.Sleep(10 * time.Millisecond)
	}
	sched.Stop()
	if err := sched.Drain(20 * time.Millisecond); err == nil {
		t.Fatal("scheduler-only drain returned while child was blocked")
	}
	if killed := registry.CancelAllWithCause(cancelreg.ErrInfrastructureShutdown); killed != 1 {
		t.Fatalf("scheduler shutdown cancellation count = %d", killed)
	}
	select {
	case err := <-tickDone:
		if err != nil {
			t.Fatalf("scheduler tick after infrastructure cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scheduler tick did not return after infrastructure cancellation")
	}
	if err := sched.Drain(time.Second); err != nil {
		t.Fatal(err)
	}
	if run, err := j.GetRun(ctx, sup.RunID); err != nil || run.Status != "suspended" || !run.FinishedAt.IsZero() {
		t.Fatalf("scheduler infrastructure recovery state = %+v, %v", run, err)
	}
	due, err := j.FindDueSchedules(ctx, time.Now().Add(time.Minute), 10)
	if err != nil || len(due) != 1 || due[0].Kind != journal.KindRecovery {
		t.Fatalf("scheduler infrastructure recovery schedule = %+v, %v", due, err)
	}
}

func recordedCallCountForTest(path, name string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == name {
			count++
		}
	}
	return count
}
