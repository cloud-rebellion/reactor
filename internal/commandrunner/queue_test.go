package commandrunner

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

type queueExecutor struct {
	mu      sync.Mutex
	started chan Request
	block   <-chan struct{}
}

type queueRejectExecutor struct {
	rejected chan Request
}

type queueCancelExecutor struct {
	started   chan Request
	cancelled chan struct{}
}

type queueRecoveryJournal struct {
	runs []journal.CommandRun
}

func (j *queueRecoveryJournal) ListCommandRunsForTenantPage(_ context.Context, _ journal.CommandRunFilter) ([]journal.CommandRun, error) {
	return nil, errors.New("newest-first inspection query must not drive recovery")
}

func (j *queueRecoveryJournal) ListQueuedCommandRunsForTenantPage(_ context.Context, tenantID string, _ int) ([]journal.CommandRun, error) {
	ordered := make([]journal.CommandRun, 0, len(j.runs))
	for _, run := range j.runs {
		if run.TenantID == tenantID && run.Status == journal.CommandRunQueued {
			ordered = append(ordered, run)
		}
	}
	return ordered, nil
}

func (e *queueRejectExecutor) ExecuteQueued(context.Context, Request) (Result, error) {
	return Result{}, ErrBlocked
}

func (e *queueRejectExecutor) RejectQueued(_ context.Context, req Request, _ error) error {
	e.rejected <- req
	return nil
}

func (e *queueCancelExecutor) ExecuteQueued(ctx context.Context, req Request) (Result, error) {
	e.started <- req
	<-ctx.Done()
	close(e.cancelled)
	return Result{}, ctx.Err()
}

func (e *queueExecutor) ExecuteQueued(ctx context.Context, req Request) (Result, error) {
	e.mu.Lock()
	if e.started != nil {
		e.started <- req
	}
	e.mu.Unlock()
	if e.block != nil {
		select {
		case <-e.block:
		case <-ctx.Done():
			return Result{}, ctx.Err()
		}
	}
	return Result{RunID: req.RunID, Status: journal.CommandRunSucceeded}, nil
}

func TestQueueRequiresBoundedConfiguration(t *testing.T) {
	_, err := NewQueue(&queueExecutor{}, nil, QueueConfig{Workers: 0, Capacity: 1, PollInterval: time.Second, TenantID: "acme", WorkerPrefix: "cmd"})
	if err == nil {
		t.Fatal("invalid worker count was accepted")
	}
	_, err = NewQueue(&queueExecutor{}, nil, QueueConfig{Workers: 2, Capacity: 1, PollInterval: time.Second, TenantID: "acme", WorkerPrefix: "cmd"})
	if err == nil {
		t.Fatal("capacity below workers was accepted")
	}
}

func TestQueueRejectsForeignTenantBeforeScheduling(t *testing.T) {
	q, err := NewQueue(&queueExecutor{}, nil, QueueConfig{Workers: 1, Capacity: 1, PollInterval: time.Second, TenantID: "acme", WorkerPrefix: "cmd"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = q.Stop(context.Background()) }()
	err = q.Enqueue(context.Background(), Request{TenantID: "globex", AutomationID: "auto", Version: 1, RunID: "run_foreign"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("foreign tenant enqueue error = %v, want ErrInvalidRequest", err)
	}
}

func TestQueueAssignsFixedWorkerAndStopsBoundedly(t *testing.T) {
	started := make(chan Request, 1)
	block := make(chan struct{})
	exec := &queueExecutor{started: started, block: block}
	q, err := NewQueue(exec, nil, QueueConfig{Workers: 1, Capacity: 1, PollInterval: time.Hour, TenantID: "acme", WorkerPrefix: "cmd"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := q.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = q.Stop(context.Background()) }()
	req := Request{TenantID: "acme", AutomationID: "auto", Version: 1, RunID: "run_1", WorkerID: "caller", LeaseTTL: time.Minute}
	if err := q.Enqueue(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-started:
		if got.WorkerID != "cmd-1" {
			t.Fatalf("worker id = %q, want cmd-1", got.WorkerID)
		}
		if got.RunID != req.RunID || got.TenantID != req.TenantID {
			t.Fatalf("worker request = %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("queue worker did not receive run")
	}
	close(block)
	stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
	defer stopCancel()
	if err := q.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
}

func TestQueueStopLetsActiveJobFinishBeforeDeadline(t *testing.T) {
	started := make(chan Request, 1)
	block := make(chan struct{})
	exec := &queueExecutor{started: started, block: block}
	q, err := NewQueue(exec, nil, QueueConfig{Workers: 1, Capacity: 1, PollInterval: time.Hour, TenantID: "acme", WorkerPrefix: "cmd"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(context.Background(), Request{TenantID: "acme", AutomationID: "auto", Version: 1, RunID: "run-drain"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("queue worker did not start active run")
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
	defer stopCancel()
	stopDone := make(chan error, 1)
	go func() { stopDone <- q.Stop(stopCtx) }()
	select {
	case err := <-stopDone:
		t.Fatalf("queue stop returned while active run was still executing: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(block)
	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("graceful queue stop = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queue stop did not finish after active run completed")
	}
}

func TestQueueCancelInterruptsActiveWorker(t *testing.T) {
	exec := &queueCancelExecutor{started: make(chan Request, 1), cancelled: make(chan struct{})}
	errorsSeen := make(chan error, 1)
	q, err := NewQueue(exec, nil, QueueConfig{Workers: 1, Capacity: 1, PollInterval: time.Hour, TenantID: "acme", WorkerPrefix: "cmd", OnError: func(err error) { errorsSeen <- err }})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = q.Stop(context.Background()) }()
	request := Request{TenantID: "acme", AutomationID: "auto", Version: 1, RunID: "run-cancel"}
	if err := q.Enqueue(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exec.started:
	case <-time.After(time.Second):
		t.Fatal("queue worker did not start cancellable run")
	}
	if !q.Cancel("acme", request.RunID) {
		t.Fatal("active queue cancellation was not accepted")
	}
	select {
	case <-exec.cancelled:
	case <-time.After(time.Second):
		t.Fatal("active worker did not observe cancellation")
	}
	select {
	case err := <-errorsSeen:
		t.Fatalf("expected cancellation not to report a queue error: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if q.Cancel("acme", request.RunID) {
		t.Fatal("completed worker remained cancellable")
	}
}

func TestQueueFullLeavesAdmissionRecoverable(t *testing.T) {
	block := make(chan struct{})
	started := make(chan Request, 2)
	exec := &queueExecutor{started: started, block: block}
	q, err := NewQueue(exec, nil, QueueConfig{Workers: 1, Capacity: 1, PollInterval: time.Hour, TenantID: "acme", WorkerPrefix: "cmd"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(block)
		_ = q.Stop(context.Background())
	}()
	base := Request{TenantID: "acme", AutomationID: "auto", Version: 1, LeaseTTL: time.Minute}
	if err := q.Enqueue(context.Background(), Request{TenantID: base.TenantID, AutomationID: base.AutomationID, Version: base.Version, RunID: "run_1", LeaseTTL: base.LeaseTTL}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker did not claim first queued item")
	}
	// The worker is blocked on the first item. Fill the one-slot channel with
	// a second item, then prove a third handoff is bounded/nonblocking.
	if err := q.Enqueue(context.Background(), Request{TenantID: "acme", AutomationID: "auto", Version: 1, RunID: "run_2", LeaseTTL: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(context.Background(), Request{TenantID: "acme", AutomationID: "auto", Version: 1, RunID: "run_3", LeaseTTL: time.Minute}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("third enqueue error = %v, want ErrQueueFull", err)
	}
}

func TestQueueTerminalizesPermanentAdmissionError(t *testing.T) {
	exec := &queueRejectExecutor{rejected: make(chan Request, 1)}
	q, err := NewQueue(exec, nil, QueueConfig{Workers: 1, Capacity: 1, PollInterval: 10 * time.Millisecond, TenantID: "acme", WorkerPrefix: "cmd"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = q.Stop(context.Background()) }()
	request := Request{TenantID: "acme", AutomationID: "auto", Version: 1, RunID: "run-permanent"}
	if err := q.Enqueue(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-exec.rejected:
		if got.RunID != request.RunID || got.WorkerID != "cmd-1" {
			t.Fatalf("rejected request = %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("permanent admission error was not terminalized")
	}
	// The item is removed from the retry set after successful rejection. A
	// transient retry loop would invoke RejectQueued repeatedly.
	select {
	case got := <-exec.rejected:
		t.Fatalf("permanent error was retried after rejection: %+v", got)
	case <-time.After(75 * time.Millisecond):
	}
}

func TestQueueRecoveryUsesOldestDurableRunsFirst(t *testing.T) {
	started := make(chan Request, 1)
	block := make(chan struct{})
	exec := &queueExecutor{started: started, block: block}
	durable := &queueRecoveryJournal{runs: []journal.CommandRun{
		{ID: "run-old", TenantID: "acme", AutomationID: "auto", AutomationVersion: 1, Status: journal.CommandRunQueued},
		{ID: "run-new", TenantID: "acme", AutomationID: "auto", AutomationVersion: 1, Status: journal.CommandRunQueued},
	}}
	q, err := NewQueue(exec, durable, QueueConfig{Workers: 1, Capacity: 2, PollInterval: time.Hour, TenantID: "acme", WorkerPrefix: "cmd"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(block)
		_ = q.Stop(context.Background())
	}()
	select {
	case got := <-started:
		if got.RunID != "run-old" {
			t.Fatalf("first recovered run = %q, want oldest run-old", got.RunID)
		}
	case <-time.After(time.Second):
		t.Fatal("durable recovery did not schedule a run")
	}
}
