package commandrunner

// Queue is the bounded asynchronous handoff between MCP admission and the
// command runner. Admission creates the durable queued row first; Queue only
// schedules a reference to that row and never carries command text or secret
// material. A small durable poll closes the gap between an admitted request
// and process shutdown, so queued rows can be resumed by a later daemon.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

var (
	ErrQueueNotStarted = errors.New("commandrunner: queue is not started")
	ErrQueueStopped    = errors.New("commandrunner: queue is stopping")
	ErrQueueFull       = errors.New("commandrunner: queue is full")
)

// QueueExecutor is intentionally narrower than Runner so queue lifecycle
// tests cannot accidentally gain a process-launching dependency.
type QueueExecutor interface {
	ExecuteQueued(context.Context, Request) (Result, error)
}

// QueueRejector is implemented by executors that can close a durably queued
// run after an admission/configuration error that cannot be repaired by
// retrying the same receipt. It is optional so small in-memory queue users
// can continue to provide only ExecuteQueued; the production Runner
// implements it to keep stale or unsafe receipts from remaining queued
// forever.
type QueueRejector interface {
	RejectQueued(context.Context, Request, error) error
}

// QueueJournal is the tenant-scoped durable read used for recovery. The
// concrete journal implementation enforces the tenant predicate; the queue
// never scans another tenant to discover work.
type QueueJournal interface {
	ListCommandRunsForTenantPage(context.Context, journal.CommandRunFilter) ([]journal.CommandRun, error)
}

// QueueRecoveryJournal is the optional ordered recovery query implemented by
// the durable journal. Inspection pages are intentionally newest-first, but a
// recovery loop must claim the oldest rows first or a steady stream of new
// admissions can starve durable work indefinitely.
type QueueRecoveryJournal interface {
	ListQueuedCommandRunsForTenantPage(context.Context, string, int) ([]journal.CommandRun, error)
}

type QueueConfig struct {
	Workers      int
	Capacity     int
	PollInterval time.Duration
	TenantID     string
	WorkerPrefix string
	OnError      func(error)
}

func (c QueueConfig) valid() error {
	if c.Workers < 1 || c.Workers > 64 {
		return fmt.Errorf("commandrunner: workers must be 1..64")
	}
	if c.Capacity < c.Workers || c.Capacity > 4096 {
		return fmt.Errorf("commandrunner: queue capacity must be %d..4096", c.Workers)
	}
	if c.PollInterval <= 0 || c.PollInterval > time.Hour {
		return fmt.Errorf("commandrunner: poll interval must be >0 and <=1h")
	}
	if strings.TrimSpace(c.TenantID) == "" {
		return errors.New("commandrunner: recovery tenant is required")
	}
	if strings.TrimSpace(c.WorkerPrefix) == "" {
		return errors.New("commandrunner: worker prefix is required")
	}
	return nil
}

type queueItem struct {
	req Request
	key string
}

type queueRetry struct {
	attempts int
	next     time.Time
}

type activeJob struct {
	token  *struct{}
	cancel context.CancelFunc
}

type Queue struct {
	executor QueueExecutor
	journal  QueueJournal
	config   QueueConfig
	jobs     chan queueItem
	wake     chan struct{}
	stopCh   chan struct{}

	mu             sync.Mutex
	pending        map[string]struct{}
	retry          map[string]queueRetry
	active         map[string]activeJob
	started        bool
	stopped        bool
	cancel         context.CancelFunc // worker cancellation, used only after Stop timeout
	recoveryCancel context.CancelFunc
	stopOnce       sync.Once
	done           chan struct{}
	wg             sync.WaitGroup
}

func NewQueue(executor QueueExecutor, durable QueueJournal, config QueueConfig) (*Queue, error) {
	if executor == nil {
		return nil, errors.New("commandrunner: queue executor is required")
	}
	if err := config.valid(); err != nil {
		return nil, err
	}
	return &Queue{
		executor: executor,
		journal:  durable,
		config:   config,
		jobs:     make(chan queueItem, config.Capacity),
		wake:     make(chan struct{}, 1),
		pending:  make(map[string]struct{}, config.Capacity),
		retry:    make(map[string]queueRetry),
		active:   make(map[string]activeJob, config.Workers),
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
	}, nil
}

// Start starts exactly the configured number of workers and one bounded
// recovery poller. It is safe to call only once; a second call is rejected so
// an operator cannot accidentally create an unbounded second worker set.
func (q *Queue) Start(parent context.Context) error {
	if q == nil {
		return ErrQueueNotStarted
	}
	if parent == nil {
		parent = context.Background()
	}
	q.mu.Lock()
	if q.started {
		q.mu.Unlock()
		return errors.New("commandrunner: queue already started")
	}
	if q.stopped {
		q.mu.Unlock()
		return ErrQueueStopped
	}
	workerCtx, workerCancel := context.WithCancel(parent)
	recoveryCtx, recoveryCancel := context.WithCancel(parent)
	q.cancel = workerCancel
	q.recoveryCancel = recoveryCancel
	q.started = true
	q.wg.Add(q.config.Workers + 1)
	q.mu.Unlock()
	for i := 0; i < q.config.Workers; i++ {
		workerID := fmt.Sprintf("%s-%d", q.config.WorkerPrefix, i+1)
		go q.worker(workerCtx, workerID)
	}
	go q.recovery(recoveryCtx)
	go func() {
		q.wg.Wait()
		close(q.done)
	}()
	// Wake the poller immediately. A newly started daemon should not wait one
	// full interval before recovering durable queued rows.
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return nil
}

// Enqueue schedules a durable run admitted by Runner.Admit. If the in-memory
// queue is full, the durable recovery poller will pick the row up later; the
// caller still receives a successful admission receipt and never has to
// retry a command in order to make it visible.
func (q *Queue) Enqueue(ctx context.Context, req Request) error {
	if q == nil {
		return ErrQueueNotStarted
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(req.TenantID) == "" || strings.TrimSpace(req.AutomationID) == "" || strings.TrimSpace(req.RunID) == "" || req.Version < 1 {
		return ErrInvalidRequest
	}
	if strings.TrimSpace(req.TenantID) != strings.TrimSpace(q.config.TenantID) {
		return ErrInvalidRequest
	}
	if req.LeaseTTL < 0 || req.LeaseTTL > 24*time.Hour {
		return ErrInvalidRequest
	}
	item := queueItem{req: req, key: queueKey(req.TenantID, req.RunID)}
	item.req.WorkerID = "" // assigned by the fixed worker that claims it
	q.mu.Lock()
	if !q.started {
		q.mu.Unlock()
		return ErrQueueNotStarted
	}
	if q.stopped {
		q.mu.Unlock()
		return ErrQueueStopped
	}
	if _, exists := q.pending[item.key]; exists {
		q.mu.Unlock()
		return nil
	}
	q.pending[item.key] = struct{}{}
	q.mu.Unlock()
	select {
	case q.jobs <- item:
		q.clearRetry(item.key)
		return nil
	case <-ctx.Done():
		q.forget(item.key)
		return ctx.Err()
	default:
		// Keep the pending marker out of the recovery poller's way only while
		// this item is actually in the channel. A full channel means the row
		// must become discoverable by the next poll.
		q.forget(item.key)
		return ErrQueueFull
	}
}

// Stop stops new intake and the recovery poller, then lets active workers
// finish until the caller's deadline. Buffered-but-not-started items remain
// durable queued rows and are recovered by the next Queue.Start call. If the
// deadline expires, the worker context is cancelled; Runner leaves that live
// claim recoverable for the lease reaper rather than terminalizing it.
func (q *Queue) Stop(ctx context.Context) error {
	if q == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	q.mu.Lock()
	if !q.started {
		q.stopped = true
		q.mu.Unlock()
		return nil
	}
	q.stopped = true
	workerCancel := q.cancel
	recoveryCancel := q.recoveryCancel
	done := q.done
	q.mu.Unlock()
	if recoveryCancel != nil {
		recoveryCancel()
	}
	// Wake idle workers and make them leave any buffered local items queued for
	// durable recovery. Active workers do not observe this until their executor
	// returns, which is the graceful drain window.
	q.stopOnce.Do(func() { close(q.stopCh) })
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		if workerCancel != nil {
			workerCancel()
		}
		return ctx.Err()
	}
}

// Cancel requests immediate interruption of a locally running command. The
// durable journal cancellation must happen first so a worker that races this
// call is fenced even if the process exits before the context reaches Docker.
// It returns false when no worker currently owns the run in this queue.
func (q *Queue) Cancel(tenantID, runID string) bool {
	if q == nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(runID) == "" || strings.TrimSpace(tenantID) != strings.TrimSpace(q.config.TenantID) {
		return false
	}
	key := queueKey(tenantID, runID)
	q.mu.Lock()
	job, ok := q.active[key]
	q.mu.Unlock()
	if !ok || job.cancel == nil {
		return false
	}
	job.cancel()
	return true
}

func (q *Queue) worker(ctx context.Context, workerID string) {
	defer q.wg.Done()
	for {
		q.mu.Lock()
		stopping := q.stopped
		q.mu.Unlock()
		if stopping {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-q.stopCh:
			return
		case item := <-q.jobs:
			q.mu.Lock()
			stopping = q.stopped
			q.mu.Unlock()
			if stopping {
				// The durable row remains queued; only the local handoff was
				// removed while shutdown was racing the worker receive.
				q.forget(item.key)
				return
			}
			item.req.WorkerID = workerID
			jobCtx, cancel := context.WithCancel(ctx)
			token := &struct{}{}
			q.setActive(item.key, activeJob{token: token, cancel: cancel})
			_, err := q.executor.ExecuteQueued(jobCtx, item.req)
			jobCancelled := jobCtx.Err() != nil
			cancel()
			q.clearActive(item.key, token)
			if err != nil && ctx.Err() == nil {
				if errors.Is(err, context.Canceled) && jobCancelled {
					// Queue.Cancel already fenced the durable row. The worker's
					// context error is an expected interruption, not a retryable
					// admission failure or queue health signal.
					q.clearRetry(item.key)
				} else if q.rejectPermanent(ctx, item, err) {
					q.clearRetry(item.key)
				} else {
					q.markRetry(item.key)
					q.report(err)
				}
			} else {
				q.clearRetry(item.key)
			}
			q.forget(item.key)
		}
	}
}

// rejectPermanent closes a queued run only when the executor explicitly
// supports that operation and the error identifies a receipt/configuration
// that cannot be made safe by retrying it. Database, lease, and sandbox
// execution errors remain retryable and therefore durable.
func (q *Queue) rejectPermanent(ctx context.Context, item queueItem, err error) bool {
	if !isPermanentAdmissionError(err) {
		return false
	}
	rejector, ok := q.executor.(QueueRejector)
	if !ok {
		return false
	}
	if rejectErr := rejector.RejectQueued(ctx, item.req, err); rejectErr != nil {
		// A competing worker may have claimed or completed the row between
		// ExecuteQueued and RejectQueued. That is a successful fence outcome:
		// the competing generation owns the durable state now, so do not spin
		// this item forever in the local retry map.
		if errors.Is(rejectErr, journal.ErrNotFound) || errors.Is(rejectErr, journal.ErrCommandRunNotClaimable) || errors.Is(rejectErr, journal.ErrCommandRunOwnershipLost) {
			return true
		}
		q.report(rejectErr)
		return false
	}
	return true
}

func isPermanentAdmissionError(err error) bool {
	for _, permanent := range []error{
		ErrDisabled,
		ErrBlocked,
		ErrRunnerUnavailable,
		ErrTargetNotAllowed,
		ErrCredentialBoundary,
		ErrAdmissionStale,
		ErrInvalidRequest,
		ErrLeaseTooShort,
		journal.ErrNotFound,
		journal.ErrCommandAutomationConflict,
		journal.ErrCommandRunDefinitionMismatch,
		journal.ErrCommandRunBindingMismatch,
		journal.ErrCommandRunConflict,
	} {
		if errors.Is(err, permanent) {
			return true
		}
	}
	return false
}

func (q *Queue) recovery(ctx context.Context) {
	defer q.wg.Done()
	// A queue without a durable journal still supports direct admission and
	// tests, but it cannot recover after restart. The worker channel remains
	// bounded and newly admitted items are still safe.
	if q.journal == nil {
		<-ctx.Done()
		return
	}
	poll := func() {
		limit := q.config.Capacity
		if limit > 256 {
			limit = 256
		}
		var runs []journal.CommandRun
		var err error
		if ordered, ok := q.journal.(QueueRecoveryJournal); ok {
			runs, err = ordered.ListQueuedCommandRunsForTenantPage(ctx, q.config.TenantID, limit)
		} else {
			// Keep compatibility with small embedded journals while they adopt the
			// ordered query. Production Journal implements QueueRecoveryJournal.
			runs, err = q.journal.ListCommandRunsForTenantPage(ctx, journal.CommandRunFilter{TenantID: q.config.TenantID, Status: journal.CommandRunQueued, Limit: limit})
		}
		if err != nil {
			q.report(err)
			return
		}
		for _, run := range runs {
			if err := q.enqueueRecovered(ctx, run); err != nil && !errors.Is(err, ErrQueueFull) {
				q.report(err)
			}
		}
	}
	poll()
	ticker := time.NewTicker(q.config.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			poll()
		case <-q.wake:
			poll()
		}
	}
}

func (q *Queue) enqueueRecovered(ctx context.Context, run journal.CommandRun) error {
	key := queueKey(run.TenantID, run.ID)
	if !q.retryReady(key) {
		return nil
	}
	return q.Enqueue(ctx, Request{TenantID: run.TenantID, AutomationID: run.AutomationID, Version: run.AutomationVersion, RunID: run.ID, Admission: run.Admission, TriggerKind: run.Admission.TriggerKind, TriggerID: run.Admission.TriggerID, TriggerEventID: run.Admission.TriggerEventID})
}

func (q *Queue) forget(key string) {
	q.mu.Lock()
	delete(q.pending, key)
	q.mu.Unlock()
}

func (q *Queue) setActive(key string, job activeJob) {
	q.mu.Lock()
	q.active[key] = job
	q.mu.Unlock()
}

func (q *Queue) clearActive(key string, token *struct{}) {
	q.mu.Lock()
	if current, ok := q.active[key]; ok && current.token == token {
		delete(q.active, key)
	}
	q.mu.Unlock()
}

func (q *Queue) markRetry(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	state := q.retry[key]
	state.attempts++
	delay := q.config.PollInterval
	for i := 1; i < state.attempts && delay < 5*time.Minute; i++ {
		delay *= 2
	}
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	state.next = time.Now().Add(delay)
	q.retry[key] = state
}

func (q *Queue) retryReady(key string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	state, ok := q.retry[key]
	return !ok || !time.Now().Before(state.next)
}

func (q *Queue) clearRetry(key string) {
	q.mu.Lock()
	delete(q.retry, key)
	q.mu.Unlock()
}

func (q *Queue) report(err error) {
	if err == nil || q.config.OnError == nil {
		return
	}
	q.config.OnError(err)
}

func queueKey(tenantID, runID string) string {
	return strings.TrimSpace(tenantID) + "\x00" + strings.TrimSpace(runID)
}
