package reactor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func newTestFlow() *InProcFlow {
	f := NewInProcFlow(slog.New(slog.NewTextHandler(io.Discard, nil)))
	// Replace the real sleep so retry/backoff doesn't slow tests.
	f.sleep = func(time.Duration) {}
	return f
}

func TestStepHappyPath(t *testing.T) {
	t.Parallel()
	f := newTestFlow()

	got, err := Step(f, context.Background(), "double", StepOpts{Timeout: time.Second},
		func(ctx context.Context) (int, error) { return 42, nil })
	if err != nil {
		t.Fatal(err)
	}
	if got != 42 {
		t.Fatalf("got %d, want 42", got)
	}
	if len(f.Steps()) != 1 {
		t.Fatalf("recorded %d steps, want 1", len(f.Steps()))
	}
}

func TestSideEffectReturnsValueAndJournals(t *testing.T) {
	t.Parallel()
	f := newTestFlow()

	got, err := SideEffect(f, context.Background(), "captured-time", func() int64 {
		return 1234567890
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != 1234567890 {
		t.Fatalf("got %d, want 1234567890", got)
	}
	if len(f.Steps()) != 1 {
		t.Fatalf("SideEffect should journal exactly one step row, got %d", len(f.Steps()))
	}
	if f.Steps()[0].Name != "captured-time" {
		t.Fatalf("step name = %q, want captured-time", f.Steps()[0].Name)
	}
}

// TestSideEffectCoercesNumbersThroughJSONReplay covers the bug `reactor
// test --latest` caught in production: PipeFlow round-trips outputs
// through JSON for replay, so an int64 closure return decodes back as
// float64 + the direct type assertion fails. coerceTo's JSON re-marshal
// fallback fixes it.
func TestSideEffectCoercesNumbersThroughJSONReplay(t *testing.T) {
	t.Parallel()
	// float64 stands in for what PipeFlow would hand the SDK on
	// replay (JSON Number -> float64). The InProcFlow kept here for
	// the value-shape only; we feed coerceTo directly.
	got, err := coerceTo[int64](float64(1234567890), "side effect")
	if err != nil {
		t.Fatalf("coerceTo: %v", err)
	}
	if got != 1234567890 {
		t.Fatalf("got %d, want 1234567890", got)
	}
}

func TestStepCoercesStructThroughJSONReplay(t *testing.T) {
	t.Parallel()
	type Echo struct {
		Got     string `json:"got"`
		StepRun int64  `json:"step_run_unix"`
	}
	// What the journal cache would surface to the SDK after replay
	// JSON-decode.
	cached := map[string]any{
		"got":           "hello",
		"step_run_unix": float64(42),
	}
	got, err := coerceTo[Echo](cached, "step")
	if err != nil {
		t.Fatalf("coerceTo: %v", err)
	}
	if got.Got != "hello" || got.StepRun != 42 {
		t.Fatalf("coerce mismatch: %+v", got)
	}
}

func TestCoerceToFastPathPreservesInProcType(t *testing.T) {
	t.Parallel()
	// InProcFlow stores the literal; coerceTo's first branch (direct
	// assertion) must hit so we don't pay the JSON cost for in-proc.
	type custom struct{ N int }
	in := custom{N: 7}
	got, err := coerceTo[custom](in, "step")
	if err != nil {
		t.Fatal(err)
	}
	if got.N != 7 {
		t.Fatalf("got %+v", got)
	}
}

func TestSideEffectClosureRunsOncePerCallSite(t *testing.T) {
	t.Parallel()
	f := newTestFlow()

	var calls atomic.Int32
	for i := 0; i < 3; i++ {
		_, err := SideEffect(f, context.Background(), "trace-token", func() string {
			calls.Add(1)
			return "tok-" + fmt.Sprint(i)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// Distinct call SITES (different name each iter) would re-invoke the
	// closure; same name means InProcFlow's per-name dedup kicks in
	// IF an idempotency key is set. SideEffect leaves IdempotencyKey
	// empty intentionally so each call IS a fresh sample. So calls=3.
	// This pins that contract; an idempotency-on default would be wrong
	// for SideEffect (callers may want fresh samples per body iteration).
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3 (SideEffect must NOT dedup; that's Step's job with IdempotencyKey)", calls.Load())
	}
}

func TestStepIdempotencyReplay(t *testing.T) {
	t.Parallel()
	f := newTestFlow()

	var calls atomic.Int32
	step := func(ctx context.Context) (string, error) {
		calls.Add(1)
		return "result", nil
	}

	for i := 0; i < 3; i++ {
		got, err := Step(f, context.Background(), "send-welcome",
			StepOpts{IdempotencyKey: "cust-1"}, step)
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if got != "result" {
			t.Fatalf("got %q", got)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("step ran %d times, want 1 (idempotency replay broken)", calls.Load())
	}
}

func TestStepInputHashPreventsStaleInProcReplay(t *testing.T) {
	t.Parallel()
	f := newTestFlow()
	var calls int
	run := func(inputHash, value string) string {
		out, err := Step(f, context.Background(), "send", StepOpts{
			IdempotencyKey: "customer-1", InputHash: inputHash,
		}, func(context.Context) (string, error) {
			calls++
			return value, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := run("input-v1", "first"); got != "first" {
		t.Fatalf("first output = %q", got)
	}
	if got := run("input-v1", "ignored"); got != "first" {
		t.Fatalf("same input replay = %q, want first", got)
	}
	if got := run("input-v2", "second"); got != "second" {
		t.Fatalf("changed input output = %q, want second", got)
	}
	if calls != 2 {
		t.Fatalf("closure calls = %d, want 2", calls)
	}
}

func TestStepRetryOnTransientError(t *testing.T) {
	t.Parallel()
	f := newTestFlow()

	var calls atomic.Int32
	step := func(ctx context.Context) (string, error) {
		n := calls.Add(1)
		if n < 3 {
			return "", Retryable(errors.New("flaky"))
		}
		return "ok", nil
	}

	got, err := Step(f, context.Background(), "flaky", StepOpts{
		RetryPolicy: ExpBackoff{Max: 5, Base: time.Millisecond},
	}, step)
	if err != nil {
		t.Fatal(err)
	}
	if got != "ok" {
		t.Fatalf("got %q", got)
	}
	if calls.Load() != 3 {
		t.Fatalf("ran %d times, want 3", calls.Load())
	}
	rec := f.Steps()[0]
	if rec.Attempts != 3 {
		t.Fatalf("recorded attempts = %d, want 3", rec.Attempts)
	}
}

func TestStepPermanentErrorSkipsRetry(t *testing.T) {
	t.Parallel()
	f := newTestFlow()

	var calls atomic.Int32
	step := func(ctx context.Context) (string, error) {
		calls.Add(1)
		return "", Permanent(errors.New("400 bad request"))
	}

	_, err := Step(f, context.Background(), "perm", StepOpts{
		RetryPolicy: ExpBackoff{Max: 5, Base: time.Millisecond},
	}, step)
	if err == nil {
		t.Fatal("want error")
	}
	if calls.Load() != 1 {
		t.Fatalf("ran %d times, want 1 (permanent should skip retries)", calls.Load())
	}
}

func TestExpBackoffRespectsMax(t *testing.T) {
	t.Parallel()
	b := ExpBackoff{Max: 3, Base: 10 * time.Millisecond, Cap: time.Second}
	for i := 1; i < 3; i++ {
		if _, ok := b.NextDelay(i); !ok {
			t.Fatalf("attempt %d: want retry, got skip", i)
		}
	}
	if _, ok := b.NextDelay(3); ok {
		t.Fatal("attempt 3 should not retry past Max=3")
	}
}

type providerWindowError struct {
	delay   time.Duration
	allowed bool
}

func (e providerWindowError) Error() string { return "provider rate limited" }
func (e providerWindowError) RetryAfterDelay() (time.Duration, bool) {
	return e.delay, e.allowed
}

func TestInProcStepRespectsProviderWindow(t *testing.T) {
	f := newTestFlow()
	var sleeps []time.Duration
	f.SetSleep(func(d time.Duration) { sleeps = append(sleeps, d) })
	tries := 0
	_, err := f.Step(context.Background(), "provider-read", StepOpts{
		RetryPolicy: ExpBackoff{Max: 2, Base: time.Millisecond, Cap: time.Millisecond},
	}, func(context.Context) (any, error) {
		tries++
		if tries == 1 {
			return nil, providerWindowError{delay: 3 * time.Second, allowed: true}
		}
		return "ok", nil
	})
	if err != nil || tries != 2 || len(sleeps) != 1 || sleeps[0] != 3*time.Second {
		t.Fatalf("provider retry: tries=%d sleeps=%v err=%v", tries, sleeps, err)
	}

	tries = 0
	_, err = f.Step(context.Background(), "provider-long-window", StepOpts{
		RetryPolicy: ExpBackoff{Max: 2, Base: time.Millisecond, Cap: time.Millisecond},
	}, func(context.Context) (any, error) {
		tries++
		return nil, providerWindowError{delay: time.Hour, allowed: false}
	})
	if err == nil || tries != 1 || len(sleeps) != 1 {
		t.Fatalf("long provider window: tries=%d sleeps=%v err=%v", tries, sleeps, err)
	}
}

func TestStepPanicRecovery(t *testing.T) {
	t.Parallel()
	f := newTestFlow()

	_, err := Step(f, context.Background(), "boom", StepOpts{},
		func(ctx context.Context) (int, error) { panic("kaboom") })
	if err == nil {
		t.Fatal("want recovered panic")
	}
	if got := err.Error(); got == "" {
		t.Fatal("recovered err should have a message")
	}
}

func TestSleepCancellation(t *testing.T) {
	t.Parallel()
	f := newTestFlow()
	// Use real sleep so we can verify cancellation actually short-circuits.
	f.sleep = time.Sleep

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	if err := f.Sleep(ctx, "long", time.Hour); err == nil {
		t.Fatal("want cancellation error")
	}
}

func TestAwaitSignal(t *testing.T) {
	t.Parallel()
	f := newTestFlow()
	f.sleep = time.Sleep

	go func() {
		time.Sleep(5 * time.Millisecond)
		f.SendSignal("approval", []byte(`{"approved":true}`))
	}()

	sig, err := f.AwaitSignal(context.Background(), "approval", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Name != "approval" || string(sig.Data) != `{"approved":true}` {
		t.Fatalf("got %#v", sig)
	}
}

func TestAwaitSignalTimeout(t *testing.T) {
	t.Parallel()
	f := newTestFlow()
	f.sleep = time.Sleep

	if _, err := f.AwaitSignal(context.Background(), "never", 10*time.Millisecond); err == nil {
		t.Fatal("want timeout error")
	}
}

func TestStepTypeMismatch(t *testing.T) {
	t.Parallel()
	f := newTestFlow()

	// Recorded step returned a string under "thing"; querying for int errors.
	_, _ = Step(f, context.Background(), "thing", StepOpts{IdempotencyKey: "k"},
		func(ctx context.Context) (string, error) { return "x", nil })
	_, err := Step(f, context.Background(), "thing", StepOpts{IdempotencyKey: "k"},
		func(ctx context.Context) (int, error) { return 0, nil })
	if err == nil {
		t.Fatal("want type mismatch error")
	}
}

// Minimal example mirrors what AI-generated code looks like in
// reactor-workflows/<slug>/workflow.go.
func ExampleStep() {
	f := NewInProcFlow(slog.New(slog.NewTextHandler(io.Discard, nil)))
	greeting, _ := Step(f, context.Background(), "build-greeting", StepOpts{
		IdempotencyKey: "user-1",
	}, func(ctx context.Context) (string, error) {
		return "hello, world", nil
	})
	fmt.Println(greeting)
	// Output: hello, world
}
