package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestWorkerRejectsUnsafeLeaseTTLBeforeStartup(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, ttl := range []string{"0s", "-1s", "500ms"} {
		err := cmdWorker(context.Background(), log, []string{
			"--db", "postgres://unused.invalid/reactor",
			"--lease-ttl", ttl,
		})
		if err == nil || !strings.Contains(err.Error(), "--lease-ttl must be at least 1s") {
			t.Fatalf("lease ttl %s error = %v", ttl, err)
		}
	}
}

func TestWorkerRejectsUnboundedOrInvalidConcurrencyBeforeStartup(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("REACTOR_WORKER_CONCURRENCY", "")
	for _, value := range []string{"0", "-1", "65", "1000000", "many"} {
		err := cmdWorker(context.Background(), log, []string{
			"--db", "postgres://unused.invalid/reactor",
			"--concurrency", value,
		})
		if err == nil || !strings.Contains(err.Error(), "between 1 and 64") {
			t.Fatalf("concurrency %q error = %v", value, err)
		}
	}
	t.Setenv("REACTOR_WORKER_CONCURRENCY", "1000000")
	err := cmdWorker(context.Background(), log, []string{"--db", "postgres://unused.invalid/reactor"})
	if err == nil || !strings.Contains(err.Error(), "between 1 and 64") {
		t.Fatalf("environment concurrency error = %v", err)
	}
	if got, err := parseWorkerConcurrency("64"); err != nil || got != 64 {
		t.Fatalf("maximum valid concurrency = %d, %v", got, err)
	}
}

func TestWorkerRejectsInvalidPreviousMasterBeforeDatabaseStartup(t *testing.T) {
	t.Setenv("REACTOR_MASTER_KEY_PREVIOUS", "not-a-32-byte-hex-key")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := cmdWorker(context.Background(), log, []string{
		"--db", "postgres://unused.invalid/reactor_test",
		"--root", t.TempDir(),
		"--master-key", strings.Repeat("1", 64),
	})
	if err == nil || !strings.Contains(err.Error(), "REACTOR_MASTER_KEY_PREVIOUS") {
		t.Fatalf("invalid previous master error = %v", err)
	}
}

type workerHeartbeatStub struct {
	mu        sync.Mutex
	responses []error
	calls     int
	notify    chan struct{}
}

func (s *workerHeartbeatStub) UpsertWorkerHeartbeat(context.Context, string, int) error {
	s.mu.Lock()
	idx := s.calls
	s.calls++
	var err error
	if idx < len(s.responses) {
		err = s.responses[idx]
	} else if len(s.responses) > 0 {
		err = s.responses[len(s.responses)-1]
	}
	s.mu.Unlock()
	if s.notify != nil {
		select {
		case s.notify <- struct{}{}:
		default:
		}
	}
	return err
}

func waitWorkerHeartbeats(t *testing.T, notify <-chan struct{}, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-notify:
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for worker heartbeat %d/%d", i+1, n)
		}
	}
}

func TestRegisterWorkerHeartbeatFailsClosed(t *testing.T) {
	regErr := errors.New("database temporarily unavailable")
	stub := &workerHeartbeatStub{responses: []error{regErr}}
	err := registerWorkerHeartbeat(context.Background(), stub, "worker-a", 4)
	if !errors.Is(err, regErr) {
		t.Fatalf("registration error = %v, want wrapped database error", err)
	}
	if !strings.Contains(err.Error(), "register heartbeat") {
		t.Fatalf("registration error = %v, want worker context", err)
	}
}

func TestHeartbeatWorkerToleratesTransientFailure(t *testing.T) {
	regErr := errors.New("transient database failure")
	stub := &workerHeartbeatStub{
		responses: []error{regErr, nil},
		notify:    make(chan struct{}, 4),
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	done := make(chan struct{})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() {
		heartbeatWorker(ctx, log, stub, "worker-a", 4, time.Millisecond, cancel)
		close(done)
	}()
	waitWorkerHeartbeats(t, stub.notify, 2)
	if cause := context.Cause(ctx); cause != nil {
		t.Fatalf("transient heartbeat failure cancelled worker: %v", cause)
	}
	cancel(nil)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("heartbeat worker did not stop after context cancellation")
	}
}

func TestHeartbeatWorkerStopsAfterConsecutiveFailures(t *testing.T) {
	regErr := errors.New("heartbeat database unavailable")
	stub := &workerHeartbeatStub{
		responses: []error{regErr, regErr, regErr},
		notify:    make(chan struct{}, 4),
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	done := make(chan struct{})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() {
		heartbeatWorker(ctx, log, stub, "worker-a", 4, time.Millisecond, cancel)
		close(done)
	}()
	waitWorkerHeartbeats(t, stub.notify, workerHeartbeatFailureLimit)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("heartbeat worker did not stop after consecutive failures")
	}
	if cause := context.Cause(ctx); !errors.Is(cause, errWorkerHeartbeatUnavailable) {
		t.Fatalf("heartbeat cancellation cause = %v, want unavailable sentinel", cause)
	}
}

type contextBlockedWorkerHeartbeat struct {
	started chan struct{}
}

func (s contextBlockedWorkerHeartbeat) UpsertWorkerHeartbeat(ctx context.Context, _ string, _ int) error {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestHeartbeatWorkerBoundsBlockedRegistryWrites(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	done := make(chan struct{})
	stub := contextBlockedWorkerHeartbeat{started: make(chan struct{}, 4)}
	go func() {
		heartbeatWorker(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), stub,
			"worker-blocked", 2, 20*time.Millisecond, cancel)
		close(done)
	}()
	waitWorkerHeartbeats(t, stub.started, workerHeartbeatFailureLimit)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed-out registry writes did not stop worker")
	}
	if cause := context.Cause(ctx); !errors.Is(cause, errWorkerHeartbeatUnavailable) {
		t.Fatalf("blocked registry writes cancellation cause = %v", cause)
	}
}

type uncooperativeWorkerHeartbeat struct {
	started chan struct{}
	release <-chan struct{}
}

func (s uncooperativeWorkerHeartbeat) UpsertWorkerHeartbeat(context.Context, string, int) error {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-s.release
	return nil
}

func TestHeartbeatWorkerCancelsExecutionWhenRegistryDriverIgnoresDeadline(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseWrite := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseWrite()
	started := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		heartbeatWorker(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)),
			uncooperativeWorkerHeartbeat{started: started, release: release},
			"worker-stalled", 2, 20*time.Millisecond, cancel)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("registry write never started")
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("stalled registry driver left worker active")
	}
	if cause := context.Cause(ctx); !errors.Is(cause, errWorkerHeartbeatUnavailable) {
		t.Fatalf("stalled registry cancellation cause = %v", cause)
	}
	// Let the deliberately uncooperative fake return so no test goroutine is
	// left behind after the watchdog has already cancelled the worker.
	releaseWrite()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("heartbeat loop did not stop after blocked write returned")
	}
}

type heartbeatJournalStub struct {
	extendErr error
	status    string
}

type uncooperativeLeaseHeartbeat struct {
	started chan struct{}
	release <-chan struct{}
}

func (s uncooperativeLeaseHeartbeat) ExtendLease(context.Context, string, string, time.Duration) error {
	close(s.started)
	<-s.release
	return nil
}

func (s uncooperativeLeaseHeartbeat) GetRun(context.Context, string) (journal.RunInfo, error) {
	return journal.RunInfo{Status: "running"}, nil
}

func TestHeartbeatLeaseCancelsExecutionBeforeBlockedRenewalReturns(t *testing.T) {
	const leaseTTL = 120 * time.Millisecond
	if got := leaseRenewalTimeout(leaseTTL); got >= leaseTTL/2 {
		t.Fatalf("renewal deadline %s leaves no safe pre-expiry margin", got)
	}
	execCtx, cancelExec := context.WithCancelCause(context.Background())
	defer cancelExec(context.Canceled)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseWrite := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseWrite()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- heartbeatLease(context.Background(),
			uncooperativeLeaseHeartbeat{started: started, release: release},
			"run", "owner-a", leaseTTL, cancelExec)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("lease renewal never started")
	}
	select {
	case <-execCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("blocked renewal left workflow execution active")
	}
	if cause := context.Cause(execCtx); !errors.Is(cause, errLeaseHeartbeatUnsafe) {
		t.Fatalf("blocked renewal cancellation cause = %v", cause)
	}
	releaseWrite()
	select {
	case err := <-done:
		if !errors.Is(err, errLeaseHeartbeatUnsafe) {
			t.Fatalf("late renewal response error = %v, want unsafe lease", err)
		}
	case <-time.After(time.Second):
		t.Fatal("lease heartbeat did not return after blocked renewal released")
	}
}

func TestWaitLeaseHeartbeatStopsAdmissionWhenDriverDoesNotReturn(t *testing.T) {
	workerCtx, cancelWorker := context.WithCancelCause(context.Background())
	defer cancelWorker(context.Canceled)
	err := waitLeaseHeartbeat(make(chan error), 10*time.Millisecond, cancelWorker)
	if !errors.Is(err, errLeaseHeartbeatUnsafe) || !errors.Is(context.Cause(workerCtx), errLeaseHeartbeatUnsafe) {
		t.Fatalf("stalled heartbeat kept worker active: err=%v cause=%v", err, context.Cause(workerCtx))
	}
	completed := make(chan error, 1)
	completed <- nil
	if err := waitLeaseHeartbeat(completed, time.Second, cancelWorker); err != nil {
		t.Fatalf("completed heartbeat = %v, want no failure", err)
	}
}

func (s heartbeatJournalStub) ExtendLease(context.Context, string, string, time.Duration) error {
	return s.extendErr
}

func (s heartbeatJournalStub) GetRun(context.Context, string) (journal.RunInfo, error) {
	return journal.RunInfo{ID: "run", Status: s.status}, nil
}

func TestHeartbeatOwnershipLossCancelsChildContext(t *testing.T) {
	execCtx, cancelExec := context.WithCancelCause(context.Background())
	defer cancelExec(context.Canceled)
	err := heartbeatLease(
		context.Background(),
		heartbeatJournalStub{extendErr: journal.ErrLeaseOwnershipLost, status: "running"},
		"run", "owner-a", 15*time.Millisecond, cancelExec,
	)
	if !errors.Is(err, errLeaseHeartbeatUnsafe) {
		t.Fatalf("heartbeat error = %v, want unsafe sentinel", err)
	}
	if cause := context.Cause(execCtx); !errors.Is(cause, errLeaseHeartbeatUnsafe) {
		t.Fatalf("execution cancellation cause = %v, want lease heartbeat loss", cause)
	}
}

func TestHeartbeatReapedQueuedLeaseCancelsStaleChild(t *testing.T) {
	execCtx, cancelExec := context.WithCancelCause(context.Background())
	defer cancelExec(context.Canceled)
	err := heartbeatLease(
		context.Background(),
		heartbeatJournalStub{extendErr: journal.ErrLeaseOwnershipLost, status: "queued"},
		"run", "stale-owner", 15*time.Millisecond, cancelExec,
	)
	if !errors.Is(err, errLeaseHeartbeatUnsafe) {
		t.Fatalf("reaped heartbeat error = %v, want unsafe sentinel", err)
	}
	if cause := context.Cause(execCtx); !errors.Is(cause, errLeaseHeartbeatUnsafe) {
		t.Fatalf("stale execution cancellation cause = %v, want lease heartbeat loss", cause)
	}
}

func TestHeartbeatReplacementFinishedFirstStillCancelsStaleChild(t *testing.T) {
	execCtx, cancelExec := context.WithCancelCause(context.Background())
	defer cancelExec(context.Canceled)
	err := heartbeatLease(
		context.Background(),
		heartbeatJournalStub{extendErr: journal.ErrLeaseOwnershipLost, status: "succeeded"},
		"run", "owner-a", 15*time.Millisecond, cancelExec,
	)
	if err != nil {
		t.Fatalf("replacement terminal heartbeat race = %v, want normal logged stop", err)
	}
	if cause := context.Cause(execCtx); !errors.Is(cause, errLeaseHeartbeatUnsafe) {
		t.Fatalf("replacement terminal left stale execution alive: %v", cause)
	}
}

func TestHeartbeatReaperCancellationStopsPossiblyLiveOldChild(t *testing.T) {
	execCtx, cancelExec := context.WithCancelCause(context.Background())
	defer cancelExec(context.Canceled)
	err := heartbeatLease(
		context.Background(),
		heartbeatJournalStub{extendErr: journal.ErrLeaseOwnershipLost, status: "cancelled"},
		"run", "expired-owner", 15*time.Millisecond, cancelExec,
	)
	if err != nil {
		t.Fatalf("cancelled heartbeat race = %v, want normal terminal stop", err)
	}
	if cause := context.Cause(execCtx); !errors.Is(cause, errLeaseHeartbeatUnsafe) {
		t.Fatalf("cancelled stale child cause = %v, want lease heartbeat loss", cause)
	}
}

type reaperJournalStub struct {
	reaped     int64
	pruned     int64
	staleAfter time.Duration
	reapErr    error
	pruneErr   error
}

func (s *reaperJournalStub) ReapExpiredLeases(context.Context) (int64, error) {
	return s.reaped, s.reapErr
}

func (s *reaperJournalStub) PruneStaleWorkers(_ context.Context, staleAfter time.Duration) (int64, error) {
	s.staleAfter = staleAfter
	return s.pruned, s.pruneErr
}

func TestReapWorkerStatePrunesStaleWorkerRows(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	stub := &reaperJournalStub{reaped: 2, pruned: 3}
	const staleAfter = 42 * time.Second

	reapWorkerState(context.Background(), log, stub, staleAfter)

	if stub.staleAfter != staleAfter {
		t.Fatalf("stale threshold = %s, want %s", stub.staleAfter, staleAfter)
	}
}

func TestWorkerHousekeepingThresholdMatchesHeartbeatWindow(t *testing.T) {
	stuckWriteWatchdog := workerHeartbeatFailureLimit*workerHeartbeatInterval + 2*workerHeartbeatTimeout
	if stuckWriteWatchdog >= workerStaleAfter {
		t.Fatalf("stuck-write watchdog at %s reaches the %s stale threshold", stuckWriteWatchdog, workerStaleAfter)
	}
}
