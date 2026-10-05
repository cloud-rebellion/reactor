package supervisor

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestSchedulerStopsAfterConsecutiveTickFailures(t *testing.T) {
	_, j, db, cleanup := newTestSupervisorEnvWithDB(t, "run_scheduler_tick_failure")
	defer cleanup()
	if err := db.Close(); err != nil {
		t.Fatalf("close scheduler database: %v", err)
	}

	sched := &Scheduler{
		Journal:                  j,
		Log:                      slog.New(slog.NewTextHandler(io.Discard, nil)),
		TickInterval:             time.Millisecond,
		MaxConsecutiveTickErrors: 3,
	}
	err := sched.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "3 consecutive tick failures") {
		t.Fatalf("scheduler error = %v, want bounded consecutive-failure error", err)
	}
}
