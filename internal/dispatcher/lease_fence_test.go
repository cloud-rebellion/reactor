package dispatcher

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/supervisor"
)

func TestStaleSupervisorPersistenceFailureSuppressesTerminalHooks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j := newJournal(t)
	createExecutableWorkflow(t, j, "wf_stale", "stale")
	if err := j.CreateQueuedRun(ctx, "run_stale", "wf_stale", "webhook", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	first, err := j.ClaimQueuedRuns(ctx, "worker-a", 1, -time.Hour)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim = %v, %v", first, err)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("reap = %d, %v", n, err)
	}
	second, err := j.ClaimQueuedRuns(ctx, "worker-b", 1, time.Minute)
	if err != nil || len(second) != 1 {
		t.Fatalf("replacement claim = %v, %v", second, err)
	}

	hooks := 0
	d := &Dispatcher{
		Journal: j,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnTerminal: func(context.Context, TerminalEvent) {
			hooks++
		},
	}
	sup := supervisor.Supervisor{
		BinaryPath:   filepath.Join(t.TempDir(), "missing-workflow"),
		WorkflowSlug: "stale",
		RunID:        "run_stale",
		Mode:         "live",
		Journal:      j,
		LeaseOwner:   first[0].Owner,
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	status, err := d.execute(ctx, "run_stale", "stale", "wf_stale", "webhook", sup)
	if status != "" || !errors.Is(err, journal.ErrLeaseOwnershipLost) {
		t.Fatalf("stale execute = status %q err %v; want unpersisted ownership loss", status, err)
	}
	if hooks != 0 {
		t.Fatalf("terminal hook fired %d time(s) before durable transition", hooks)
	}
	if run, err := j.GetRun(ctx, "run_stale"); err != nil || run.Status != "running" {
		t.Fatalf("stale supervisor changed replacement run = %+v, %v", run, err)
	}
	if err := j.ExtendLease(ctx, "run_stale", second[0].Owner, time.Minute); err != nil {
		t.Fatalf("stale supervisor removed replacement lease: %v", err)
	}
}
