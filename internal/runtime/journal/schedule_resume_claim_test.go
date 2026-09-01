package journal

import (
	"context"
	"testing"
	"time"
)

func TestClaimScheduleResumeIsAtomicAndSingleFlight(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	id, err := j.ScheduleSleep(ctx, "run_1", "wait", time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetRunStatus(ctx, "run_1", "suspended"); err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimScheduleResume(ctx, id, false)
	if err != nil || !claimed {
		t.Fatalf("local resume claim = %v, %v", claimed, err)
	}
	info, err := j.GetRun(ctx, "run_1")
	if err != nil || info.Status != "running" {
		t.Fatalf("local resumed run = %+v, %v", info, err)
	}
	schedule, err := j.FindLatestSleepSchedule(ctx, "run_1", "wait")
	if err != nil || !schedule.Fired {
		t.Fatalf("claimed schedule = %+v, %v", schedule, err)
	}
	if wonAgain, err := j.ClaimScheduleResume(ctx, id, false); err != nil || wonAgain {
		t.Fatalf("second schedule claimant = %v, %v; want false", wonAgain, err)
	}
}

func TestClaimScheduleResumeRollbackDoesNotStrandSuspendedRun(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	id, err := j.ScheduleSleep(ctx, "run_1", "wait", time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetRunStatus(ctx, "run_1", "suspended"); err != nil {
		t.Fatal(err)
	}
	// Force the second statement in ClaimScheduleResume to fail. The first
	// fired=true UPDATE must roll back with it.
	const trigger = `CREATE TRIGGER reject_test_resume
		BEFORE UPDATE OF status ON runs
		WHEN OLD.id = 'run_1' AND NEW.status = 'running'
		BEGIN SELECT RAISE(ABORT, 'forced resume failure'); END`
	if _, err := j.db.ExecContext(ctx, trigger); err != nil {
		t.Fatal(err)
	}
	if claimed, err := j.ClaimScheduleResume(ctx, id, false); err == nil || claimed {
		t.Fatalf("forced failure claim = %v, %v; want error", claimed, err)
	}
	info, err := j.GetRun(ctx, "run_1")
	if err != nil || info.Status != "suspended" {
		t.Fatalf("failed transaction changed run = %+v, %v", info, err)
	}
	schedule, err := j.FindLatestSleepSchedule(ctx, "run_1", "wait")
	if err != nil || schedule.Fired {
		t.Fatalf("failed transaction stranded fired schedule = %+v, %v", schedule, err)
	}
}

func TestClaimScheduleResumeDistributedAndCancellationSafe(t *testing.T) {
	t.Run("distributed queues atomically", func(t *testing.T) {
		j, cleanup := newTestJournal(t)
		defer cleanup()
		ctx := context.Background()
		id, err := j.ScheduleSleep(ctx, "run_1", "wait", time.Now().Add(-time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if err := j.SetRunStatus(ctx, "run_1", "suspended"); err != nil {
			t.Fatal(err)
		}
		claimed, err := j.ClaimScheduleResume(ctx, id, true)
		if err != nil || !claimed {
			t.Fatalf("distributed resume claim = %v, %v", claimed, err)
		}
		if info, err := j.GetRun(ctx, "run_1"); err != nil || info.Status != "queued" {
			t.Fatalf("distributed resumed run = %+v, %v; want queued", info, err)
		}
	})

	t.Run("cancel wins without resurrection", func(t *testing.T) {
		j, cleanup := newTestJournal(t)
		defer cleanup()
		ctx := context.Background()
		id, err := j.ScheduleSleep(ctx, "run_1", "wait", time.Now().Add(-time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if err := j.SetRunStatus(ctx, "run_1", "suspended"); err != nil {
			t.Fatal(err)
		}
		if err := j.SetRunStatus(ctx, "run_1", "cancelled"); err != nil {
			t.Fatal(err)
		}
		claimed, err := j.ClaimScheduleResume(ctx, id, false)
		if err != nil || claimed {
			t.Fatalf("cancelled resume claim = %v, %v; want false", claimed, err)
		}
		if info, err := j.GetRun(ctx, "run_1"); err != nil || info.Status != "cancelled" {
			t.Fatalf("cancelled run resurrected = %+v, %v", info, err)
		}
		schedule, err := j.FindLatestSleepSchedule(ctx, "run_1", "wait")
		if err != nil || !schedule.Fired {
			t.Fatalf("cancelled schedule was not retired = %+v, %v", schedule, err)
		}
	})
}

func TestClaimScheduleResumePreservesCheckpointBeforeSuspendedCommit(t *testing.T) {
	for _, inFlightStatus := range []string{"running", "queued"} {
		t.Run(inFlightStatus, func(t *testing.T) {
			j, cleanup := newTestJournal(t)
			defer cleanup()
			ctx := context.Background()
			id, err := j.ScheduleSignal(ctx, "run_1", "approval", "approval", "crash-window-token", time.Now().Add(-time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if err := j.SetRunStatus(ctx, "run_1", inFlightStatus); err != nil {
				t.Fatal(err)
			}
			if due, err := j.FindDueSchedules(ctx, time.Now(), 10); err != nil || len(due) != 0 {
				t.Fatalf("%s crash-window schedule entered due dispatch = %+v, %v", inFlightStatus, due, err)
			}

			claimed, err := j.ClaimScheduleResume(ctx, id, false)
			if err != nil || claimed {
				t.Fatalf("claim during %s crash window = %v, %v; want false", inFlightStatus, claimed, err)
			}
			checkpoint, err := j.FindLatestSignalSchedule(ctx, "run_1", "approval")
			if err != nil || checkpoint.Fired {
				t.Fatalf("%s crash window destroyed checkpoint = %+v, %v", inFlightStatus, checkpoint, err)
			}

			if err := j.SetRunStatus(ctx, "run_1", "suspended"); err != nil {
				t.Fatal(err)
			}
			if due, err := j.FindDueSchedules(ctx, time.Now(), 10); err != nil || len(due) != 1 || due[0].ID != id {
				t.Fatalf("suspended checkpoint did not become due = %+v, %v", due, err)
			}
			claimed, err = j.ClaimScheduleResume(ctx, id, false)
			if err != nil || !claimed {
				t.Fatalf("claim after suspended commit = %v, %v", claimed, err)
			}
			checkpoint, err = j.FindLatestSignalSchedule(ctx, "run_1", "approval")
			if err != nil || !checkpoint.Fired {
				t.Fatalf("resumed checkpoint = %+v, %v", checkpoint, err)
			}
		})
	}
}

func TestClaimScheduleAndFailArtifactFenceRollsBackAsOneUnit(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	id, err := j.ScheduleSleep(ctx, "run_1", "wait", time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetRunStatus(ctx, "run_1", "suspended"); err != nil {
		t.Fatal(err)
	}
	const trigger = `CREATE TRIGGER reject_test_artifact_failure
		BEFORE UPDATE OF status ON runs
		WHEN OLD.id = 'run_1' AND NEW.status = 'failed'
		BEGIN SELECT RAISE(ABORT, 'forced artifact failure'); END`
	if _, err := j.db.ExecContext(ctx, trigger); err != nil {
		t.Fatal(err)
	}
	if claimed, err := j.ClaimScheduleAndFailArtifactFence(ctx, id, "run_1"); err == nil || claimed {
		t.Fatalf("forced artifact failure claim = %v, %v; want error", claimed, err)
	}
	if info, err := j.GetRun(ctx, "run_1"); err != nil || info.Status != "suspended" {
		t.Fatalf("failed artifact transaction changed run = %+v, %v", info, err)
	}
	if schedule, err := j.FindLatestSleepSchedule(ctx, "run_1", "wait"); err != nil || schedule.Fired {
		t.Fatalf("failed artifact transaction consumed schedule = %+v, %v", schedule, err)
	}
	if logs, err := j.GetRunLogs(ctx, "run_1"); err != nil || len(logs) != 0 {
		t.Fatalf("failed artifact transaction wrote logs = %v, %v", logs, err)
	}

	if _, err := j.db.ExecContext(ctx, `DROP TRIGGER reject_test_artifact_failure`); err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimScheduleAndFailArtifactFence(ctx, id, "run_1")
	if err != nil || !claimed {
		t.Fatalf("artifact fence retry = %v, %v", claimed, err)
	}
	if info, err := j.GetRun(ctx, "run_1"); err != nil || info.Status != "failed" || info.FinishedAt.IsZero() {
		t.Fatalf("artifact-fenced run = %+v, %v", info, err)
	}
	if schedule, err := j.FindLatestSleepSchedule(ctx, "run_1", "wait"); err != nil || !schedule.Fired {
		t.Fatalf("artifact-fenced schedule = %+v, %v", schedule, err)
	}
	logs, err := j.GetRunLogs(ctx, "run_1")
	if err != nil || len(logs) != 1 || logs[0] != WorkflowArtifactFenceRunLog {
		t.Fatalf("artifact-fence logs = %v, %v", logs, err)
	}
}
