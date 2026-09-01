// Test workflow used by the supervisor E2E tests. Behavior is parameterised
// via env vars so one binary serves multiple test scenarios:
//
//	FF_TEST_FAIL_AT=fetch       -> os.Exit(7) before sending step_end for "fetch"
//	FF_TEST_RECORD=/tmp/x       -> append step name to the file each Step call
//	FF_TEST_SLEEP=1h            -> sleep this duration between fetch and send
//	FF_TEST_AWAIT_SIGNAL=1      -> AwaitSignal("approval", 1h) between fetch and send;
//	                                 SignalToken is recorded to FF_TEST_RECORD
//	FF_TEST_PERMANENT_AT=send   -> wrap the send step's error with reactor.Permanent
//	FF_TEST_FETCH_RETRY_MAX=2   -> bounded retry attempts for fetch
//	FF_TEST_RETRY_AT=send       -> return a transient error from send
//	FF_TEST_RETRY_MAX=3         -> bounded retry attempts for send
//	FF_TEST_RETRY_WIRE_MAX=1    -> advertise a hostile/mismatched lower host budget
//	FF_TEST_CRASH_SEND_CALL=2   -> os.Exit after the Nth recorded send closure
//	FF_TEST_BLOCK_SEND=1        -> keep send alive until the host kills the child
//	FF_TEST_SECOND_SLEEP=2h     -> sleep again after send (stale-schedule tests)
//
// The test compiles this once with `go build`, then exec's it multiple
// times for each scenario.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bright-interaction/reactor/sdk"
	"github.com/bright-interaction/reactor/sdk/runtime"
	"github.com/bright-interaction/reactor/sdk/vault"
)

var (
	Workflow = reactor.Workflow{Slug: "test-replay", Version: "0.1.0"}
	Trigger  = reactor.CronTrigger{Spec: "* * * * *", Timezone: "UTC"}
)

func recordCall(name string) {
	if path := os.Getenv("FF_TEST_RECORD"); path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
		defer f.Close()
		fmt.Fprintln(f, name)
	}
}

func recordedCallCount(name string) int {
	path := os.Getenv("FF_TEST_RECORD")
	if path == "" {
		return 0
	}
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

type empty struct{}

// mismatchedRetryPolicy models an old/buggy/malicious wire client that asks
// for another retry in NextDelay while advertising a smaller durable Max to
// the host. Reactor must enforce the host-owned ceiling before closure #2.
type mismatchedRetryPolicy struct {
	fallback   reactor.ExpBackoff
	advertised int
}

func (p mismatchedRetryPolicy) NextDelay(attempt int) (time.Duration, bool) {
	return p.fallback.NextDelay(attempt)
}

func (p mismatchedRetryPolicy) MaxAttempts() int { return p.advertised }

func main() {
	runtime.Serve(Workflow, Trigger, func(ctx context.Context, flow reactor.Flow, _ empty) error {
		var fetchRetryPolicy reactor.RetryPolicy
		if raw := os.Getenv("FF_TEST_FETCH_RETRY_MAX"); raw != "" {
			maxAttempts, parseErr := strconv.Atoi(raw)
			if parseErr != nil {
				return fmt.Errorf("FF_TEST_FETCH_RETRY_MAX: %w", parseErr)
			}
			fetchRetryPolicy = reactor.ExpBackoff{Max: maxAttempts, Base: time.Millisecond, Cap: time.Millisecond}
		}
		// Step 1: fetch. Always increments the record file. If FF_TEST_FAIL_AT=fetch
		// AND this is the first run (record file has 1 line after this call),
		// crash before sending step_end so the journal has a started-but-not-ended
		// row. The supervisor closes its end on EOF; we never reach the second step.
		_, err := reactor.Step(flow, ctx, "fetch", reactor.StepOpts{
			IdempotencyKey: "k",
			RetryPolicy:    fetchRetryPolicy,
		}, func(ctx context.Context) (string, error) {
			recordCall("fetch")
			if os.Getenv("FF_TEST_FAIL_AT") == "fetch" {
				// Exit AFTER the closure returns but we want to bypass the
				// step_end frame. Easiest: exit from inside the closure with
				// a panic that the SDK won't catch (the SDK's safeCall does
				// recover, so we use os.Exit here, fatal, no recover.)
				_ = vault.MustGet("never-used") // pretend we'd use a credential
				os.Exit(7)
			}
			return "fetched-customer", nil
		})
		if err != nil {
			return err
		}

		// Optional long Sleep between fetch and send. Used by the suspend +
		// resume E2E test: the supervisor sees a sleep beyond its
		// SuspendThreshold and writes a schedule row, the scheduler later
		// re-spawns this workflow which replays fetch from cache, hits this
		// Sleep again (now in the past), gets an immediate ack, and proceeds.
		if raw := os.Getenv("FF_TEST_SLEEP"); raw != "" {
			d, err := time.ParseDuration(raw)
			if err != nil {
				return fmt.Errorf("FF_TEST_SLEEP: %w", err)
			}
			recordCall("sleep")
			if err := flow.Sleep(ctx, "wait", d); err != nil {
				return err
			}
		}

		// Optional AwaitSignal between fetch and send. The token derived
		// before suspending lets a test embed it in an outbound URL
		// (here we just record it). On first run the supervisor suspends;
		// on the resume run the host replies SignalDeliver and the
		// recorded payload travels in the AwaitSignal return value.
		var signalPayload []byte
		if os.Getenv("FF_TEST_AWAIT_SIGNAL") == "1" {
			recordCall("await:" + flow.SignalToken("approval"))
			sig, err := flow.AwaitSignal(ctx, "approval", time.Hour)
			if err != nil {
				return fmt.Errorf("await: %w", err)
			}
			signalPayload = sig.Data
			if len(signalPayload) > 0 {
				recordCall("signal:" + string(signalPayload))
			}
		}

		// Step 2: send. Should NOT be recorded twice across runs because step 1
		// is replayed from the journal; only the not-yet-succeeded steps execute.
		var retryPolicy reactor.RetryPolicy
		if os.Getenv("FF_TEST_RETRY_AT") == "send" {
			maxAttempts := 3
			if raw := os.Getenv("FF_TEST_RETRY_MAX"); raw != "" {
				parsed, parseErr := strconv.Atoi(raw)
				if parseErr != nil {
					return fmt.Errorf("FF_TEST_RETRY_MAX: %w", parseErr)
				}
				maxAttempts = parsed
			}
			retryPolicy = reactor.ExpBackoff{Max: maxAttempts, Base: time.Millisecond, Cap: time.Millisecond}
			if raw := os.Getenv("FF_TEST_RETRY_WIRE_MAX"); raw != "" {
				advertised, parseErr := strconv.Atoi(raw)
				if parseErr != nil {
					return fmt.Errorf("FF_TEST_RETRY_WIRE_MAX: %w", parseErr)
				}
				retryPolicy = mismatchedRetryPolicy{
					fallback:   reactor.ExpBackoff{Max: maxAttempts, Base: time.Millisecond, Cap: time.Millisecond},
					advertised: advertised,
				}
			}
		}
		_, err = reactor.Step(flow, ctx, "send", reactor.StepOpts{
			IdempotencyKey: "k",
			RetryPolicy:    retryPolicy,
		}, func(ctx context.Context) (string, error) {
			recordCall("send")
			if os.Getenv("FF_TEST_BLOCK_SEND") == "1" {
				for {
					time.Sleep(time.Second)
				}
			}
			if raw := os.Getenv("FF_TEST_CRASH_SEND_CALL"); raw != "" {
				crashAt, parseErr := strconv.Atoi(raw)
				if parseErr != nil {
					return "", reactor.Permanent(fmt.Errorf("FF_TEST_CRASH_SEND_CALL: %w", parseErr))
				}
				if recordedCallCount("send") == crashAt {
					os.Exit(8)
				}
			}
			if os.Getenv("FF_TEST_PERMANENT_AT") == "send" {
				return "", reactor.Permanent(errors.New("smtp permanent error"))
			}
			if os.Getenv("FF_TEST_RETRY_AT") == "send" {
				return "", errors.New("smtp transient error")
			}
			return "sent", nil
		})
		if err != nil {
			return err
		}

		if raw := os.Getenv("FF_TEST_SECOND_SLEEP"); raw != "" {
			d, err := time.ParseDuration(raw)
			if err != nil {
				return fmt.Errorf("FF_TEST_SECOND_SLEEP: %w", err)
			}
			recordCall("sleep2")
			if err := flow.Sleep(ctx, "wait-two", d); err != nil {
				return err
			}
		}

		if os.Getenv("FF_TEST_FAIL_AFTER_SEND") == "1" {
			return errors.New("forced failure after send")
		}
		return nil
	})
}
