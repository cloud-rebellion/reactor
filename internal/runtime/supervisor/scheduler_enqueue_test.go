package supervisor

import (
	"context"
	"testing"
	"time"
)

// TestSchedulerEnqueueResume proves distributed-mode resume: a due
// schedule re-enqueues its run (status -> "queued") for a worker to claim,
// instead of the scheduler running the supervisor in-process. The schedule
// is claimed (fired) so it won't be picked up again.
func TestSchedulerEnqueueResume(t *testing.T) {
	_, j, closeDB := newTestSupervisorEnv(t, "run_dist")
	defer closeDB()
	ctx := context.Background()

	if err := j.SetRunStatus(ctx, "run_dist", "suspended"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.ScheduleSleep(ctx, "run_dist", "wait", time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	sched := &Scheduler{
		Journal:      j,
		Now:          time.Now,
		ArtifactPath: func(string, string) (string, error) { return "/verified/artifact", nil },
		Enqueue:      true,
		Batch:        10,
		TickInterval: time.Hour,
	}
	if err := sched.Tick(ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}

	if info, _ := j.GetRun(ctx, "run_dist"); info.Status != "queued" {
		t.Fatalf("resumed run status = %q, want queued (re-enqueued for a worker)", info.Status)
	}
	if due, _ := j.FindDueSchedules(ctx, time.Now().UTC(), 10); len(due) != 0 {
		t.Fatalf("schedule should be claimed/fired, got %d due", len(due))
	}
}
