package reactor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// InProcFlow is a Flow implementation that runs everything inside the host
// process: no subprocess, no journal, no replay. It records each step's
// outcome in memory so tests + the week-2 example can introspect what ran.
//
// Week 3 replaces this with a JSON-lines RPC bridge to a host supervisor.
// The Flow contract is unchanged; only the implementation moves.
type InProcFlow struct {
	log     *slog.Logger
	now     func() time.Time      // injectable clock for fast tests
	sleep   func(d time.Duration) // injectable sleeper for tests
	mu      sync.Mutex
	steps   []StepRecord
	signals map[string]chan Signal
}

// StepRecord captures what happened for a single step invocation. Useful in
// tests + dry-run output. The runtime journal has more fields (input hash,
// attempt count, dead-letter); this is the SDK-side mirror.
type StepRecord struct {
	Name           string
	IdempotencyKey string
	InputHash      string
	StartedAt      time.Time
	FinishedAt     time.Time
	Output         any
	Err            error
	Attempts       int
}

// NewInProcFlow returns a Flow backed by in-process state.
func NewInProcFlow(log *slog.Logger) *InProcFlow {
	if log == nil {
		log = slog.Default()
	}
	return &InProcFlow{
		log:     log,
		now:     time.Now,
		sleep:   time.Sleep,
		signals: map[string]chan Signal{},
	}
}

// SetSleep overrides the sleeper. Used by tests and the example workflow's
// demo main to short-circuit long Sleep calls.
func (f *InProcFlow) SetSleep(sleep func(time.Duration)) { f.sleep = sleep }

// SetClock overrides the clock. Used by tests with a deterministic time.
func (f *InProcFlow) SetClock(now func() time.Time) { f.now = now }

// Steps returns a copy of the recorded step list. Used in tests + dry-run
// trace output.
func (f *InProcFlow) Steps() []StepRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]StepRecord, len(f.steps))
	copy(out, f.steps)
	return out
}

// Logger returns the bound logger.
func (f *InProcFlow) Logger() *slog.Logger { return f.log }

// Step runs fn with retry semantics applied. Idempotency replay is implemented
// via the (run, name, key, input-hash) cache: the first successful (or
// permanent-failure) result for an exact identity is returned on subsequent
// calls. The host runtime owns this cache durably; here it lives in the Flow.
func (f *InProcFlow) Step(ctx context.Context, name string, opts StepOpts, fn func(context.Context) (any, error)) (any, error) {
	if name == "" {
		return nil, errors.New("reactor: step name required")
	}
	if cached, ok := f.cachedOutput(name, opts.IdempotencyKey, opts.InputHash); ok {
		return cached, nil
	}

	policy := opts.RetryPolicy
	timeout := opts.Timeout

	rec := StepRecord{
		Name:           name,
		IdempotencyKey: opts.IdempotencyKey,
		InputHash:      opts.InputHash,
		StartedAt:      f.now(),
	}

	var (
		out     any
		lastErr error
	)
	for attempt := 1; ; attempt++ {
		rec.Attempts = attempt

		callCtx := ctx
		var cancel context.CancelFunc
		if timeout > 0 {
			callCtx, cancel = context.WithTimeout(ctx, timeout)
		}
		out, lastErr = safeCall(callCtx, fn)
		if cancel != nil {
			cancel()
		}

		if lastErr == nil {
			break
		}
		if !shouldRetry(lastErr) || policy == nil {
			break
		}
		delay, retry := policy.NextDelay(attempt)
		if !retry {
			break
		}
		delay, retry = RespectRetryAfter(lastErr, delay)
		if !retry {
			break
		}
		f.log.Warn("step retry",
			"step", name,
			"attempt", attempt,
			"err", lastErr.Error(),
			"delay_ms", delay.Milliseconds(),
		)
		select {
		case <-ctx.Done():
			lastErr = ctx.Err()
			goto record
		case <-after(f.sleep, delay):
		}
	}

record:
	rec.FinishedAt = f.now()
	rec.Output = out
	rec.Err = lastErr

	f.mu.Lock()
	f.steps = append(f.steps, rec)
	f.mu.Unlock()

	if lastErr != nil {
		return nil, lastErr
	}
	return out, nil
}

// Sleep is a cooperative yield. In-process it sleeps the goroutine; in the
// week-3 supervisor it suspends the run and persists a wake_at row.
func (f *InProcFlow) Sleep(ctx context.Context, name string, d time.Duration) error {
	f.log.Info("step sleep", "step", name, "duration", d)
	if d <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-after(f.sleep, d):
		return nil
	}
}

// AwaitSignal blocks until a matching signal is delivered via Signal(name, data)
// or the timeout elapses.
func (f *InProcFlow) AwaitSignal(ctx context.Context, name string, timeout time.Duration) (Signal, error) {
	f.mu.Lock()
	ch, ok := f.signals[name]
	if !ok {
		ch = make(chan Signal, 1)
		f.signals[name] = ch
	}
	f.mu.Unlock()

	if timeout <= 0 {
		select {
		case <-ctx.Done():
			return Signal{}, ctx.Err()
		case s := <-ch:
			return s, nil
		}
	}
	select {
	case <-ctx.Done():
		return Signal{}, ctx.Err()
	case <-after(f.sleep, timeout):
		return Signal{}, fmt.Errorf("await %q: %w", name, context.DeadlineExceeded)
	case s := <-ch:
		return s, nil
	}
}

// SignalToken implements Flow. The in-process variant has no run-id and
// no external delivery surface, so the token is purely a stable handle a
// test can use to assert that workflow code embedded the right value.
func (f *InProcFlow) SignalToken(name string) string {
	h := sha256.Sum256([]byte("inproc:" + name))
	return "sig_" + hex.EncodeToString(h[:16])
}

// SendSignal delivers a signal to a workflow that is awaiting it. Used in
// tests + by the runtime when a webhook callback resolves a long-running
// AwaitSignal.
func (f *InProcFlow) SendSignal(name string, data []byte) {
	f.mu.Lock()
	ch, ok := f.signals[name]
	if !ok {
		ch = make(chan Signal, 1)
		f.signals[name] = ch
	}
	f.mu.Unlock()
	select {
	case ch <- Signal{Name: name, Data: data}:
	default:
	}
}

// cachedOutput returns a previously recorded successful output for the exact
// (name, idempotency-key, input-hash) identity, if any. Empty key disables
// caching; an empty input hash remains a valid legacy identity.
func (f *InProcFlow) cachedOutput(name, key, inputHash string) (any, bool) {
	if key == "" {
		return nil, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.steps {
		if r.Name == name && r.IdempotencyKey == key && r.InputHash == inputHash && r.Err == nil {
			return r.Output, true
		}
	}
	return nil, false
}

// safeCall recovers panics so a buggy step can't kill the host. The runtime's
// supervisor in week 3 takes over this responsibility once steps run in a
// subprocess.
func safeCall(ctx context.Context, fn func(context.Context) (any, error)) (out any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in step: %v", r)
		}
	}()
	return fn(ctx)
}

// shouldRetry returns true unless the error is wrapped with Permanent.
func shouldRetry(err error) bool {
	if err == nil {
		return false
	}
	var p permanentError
	return !errors.As(err, &p)
}

// after wraps a sleeper as a timer-style channel so select cases stay clean
// even with an injected sleeper for tests.
func after(sleep func(d time.Duration), d time.Duration) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		sleep(d)
		close(ch)
	}()
	return ch
}
