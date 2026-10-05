// Package reactor is the public SDK that AI-generated workflow code imports.
//
// The contract is small on purpose. Workflows declare a Workflow + a Trigger,
// then a Run function that uses Flow to compose Steps. Each Step is the unit
// of durable execution: idempotency keys, retries, timeouts, and journal
// checkpoints all hang off StepOpts.
//
// Week 2 ships an in-process implementation of Flow so the SDK contract can
// be exercised end-to-end. Week 3 swaps in a JSON-lines RPC to a host
// supervisor without changing this package's public API.
package reactor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"
)

// Version is the SDK version. Bumped on breaking changes to the Flow contract.
// AI-emitted workflows declare the SDK version they were authored against in
// the Workflow struct so the runtime can refuse to run incompatible bundles.
const Version = "0.1.0"

// Workflow is the per-bundle metadata. AI-generated code declares a Workflow
// at package level. The runtime reads the slug + version to wire it to the
// workflows table.
type Workflow struct {
	Slug    string
	Version string // semver, bumped by AI on breaking input change
}

// Trigger is the marker interface for workflow trigger sources. Concrete
// triggers are listed below. Generated code declares one Trigger at package
// level; the runtime registers it on workflow create / update.
type Trigger interface {
	triggerMarker()
}

// WebhookTrigger fires on incoming HTTP POSTs to Path. The runtime verifies
// the HMAC using the secret stored under SecretID before invoking the
// workflow.
type WebhookTrigger struct {
	Path     string
	SecretID string // vault credential ID for HMAC verification
	Provider string // "stripe" | "github" | "generic"; controls header parsing
}

// CronTrigger fires on a cron schedule.
type CronTrigger struct {
	Spec     string // robfig/cron/v3 spec
	Timezone string // IANA tz, e.g. "Europe/Stockholm"
}

// EventTrigger fires when another workflow (or the runtime itself) emits the
// named event.
type EventTrigger struct {
	EventName string
}

func (WebhookTrigger) triggerMarker() {}
func (CronTrigger) triggerMarker()    {}
func (EventTrigger) triggerMarker()   {}

// Flow is the runtime handle generated workflow code receives. Step boundaries
// go through Flow so the runtime can record, retry, and replay them.
type Flow interface {
	// Step records a node in the run journal and runs fn.
	// The typed helper Step[T] below is preferred at the call site; this
	// interface method exists for tests and for the typed wrapper to delegate to.
	Step(ctx context.Context, name string, opts StepOpts, fn func(context.Context) (any, error)) (any, error)

	// Sleep yields to the runtime so the workflow can be suspended and
	// resumed past the deadline without holding a goroutine. Cooperative,
	// not real time.Sleep.
	Sleep(ctx context.Context, name string, d time.Duration) error

	// AwaitSignal blocks until a named signal fires or timeout elapses.
	// Backed by the schedules + signals table; survives host restarts.
	AwaitSignal(ctx context.Context, name string, timeout time.Duration) (Signal, error)

	// SignalToken returns the deterministic capability for an awaitable
	// signal in this run. Workflows call this BEFORE AwaitSignal to embed
	// the public delivery URL (POST /signal/{token}) in user-facing
	// content (approval emails, Slack DMs). Safe to call any number of
	// times; the value is stable for the lifetime of the run.
	SignalToken(name string) string

	// Logger returns a logger pre-bound with workflow + run identifiers.
	Logger() *slog.Logger
}

// Signal is the payload returned by AwaitSignal. The runtime fills Name and
// optional JSON Data when an event matching the awaited name is delivered.
type Signal struct {
	Name string
	Data []byte
}

// StepOpts controls how a step is recorded, retried, and timed out.
//
// IdempotencyKey lets the host reuse the output of a completed (run, step,
// key) on replay. It does not make an external provider mutation exactly
// once: a provider may accept it before Reactor records the Step result.
// Required for any Step that produces an external side effect; the lint rule
// enforces this.
//
// InputHash is an optional caller-supplied, stable fingerprint of the values
// captured by the step closure. It is folded into the durable replay identity
// (and hashed before it crosses the workflow boundary), so a changed input
// cannot silently reuse an output just because the side-effect key stayed the
// same. Pass a digest or other bounded opaque fingerprint, never the raw
// payload. When empty, the runtime fingerprints the step options only.
//
// RetryPolicy: nil means no retry. Use ExpBackoff for the default
// full-jitter exponential.
//
// Timeout: zero means inherit from the run's overall budget.
type StepOpts struct {
	IdempotencyKey string
	InputHash      string
	RetryPolicy    RetryPolicy
	Timeout        time.Duration
}

// RetryPolicy decides whether and how long to wait before the next attempt.
// Returns the delay and a "should retry" flag so policies can decline late
// attempts.
type RetryPolicy interface {
	NextDelay(attempt int) (time.Duration, bool)
}

// RetryAfterHint is implemented by provider errors that carry a minimum wait
// before another attempt. The second result is false when the provider's
// window is too long for an automatic in-worker retry. A caller can then
// arrange a durable reschedule or leave the failure for operator redrive.
type RetryAfterHint interface {
	RetryAfterDelay() (time.Duration, bool)
}

// MaxAutomaticRetryAfter is the longest provider window a live Step retry may
// wait through. Longer windows require an explicit durable reschedule.
const MaxAutomaticRetryAfter = 30 * time.Second

// RespectRetryAfter applies a provider's minimum delay to a retry policy's
// chosen delay. It follows wrapped errors and never shortens the policy delay.
// A false result means an automatic retry would violate the provider window.
func RespectRetryAfter(err error, delay time.Duration) (time.Duration, bool) {
	var hint RetryAfterHint
	if !errors.As(err, &hint) {
		return delay, true
	}
	after, allowed := hint.RetryAfterDelay()
	if !allowed || after > MaxAutomaticRetryAfter {
		return 0, false
	}
	if after > delay {
		return after, true
	}
	return delay, true
}

// BoundedRetryPolicy is the crash-safe extension to RetryPolicy. The compiled
// workflow runtime sends this total-attempt ceiling to the host, which owns the
// durable attempt counter. That lets the host reject a resumed attempt before
// invoking the step closure once the budget has been consumed.
//
// Custom policies should implement this interface whenever they have a finite
// budget. Policies that only implement RetryPolicy keep their existing
// in-process retry behaviour, but after a hard crash Reactor fails the
// interrupted step closed because it cannot prove another attempt is allowed.
type BoundedRetryPolicy interface {
	RetryPolicy
	MaxAttempts() int
}

// ExpBackoff is the default policy: full-jitter exponential.
//
//	delay = rand_in [0, min(Cap, Base * 2^(attempt-1)))]
//
// attempt is 1-indexed. Returns false past Max.
type ExpBackoff struct {
	Max  int           // total attempts including the first
	Base time.Duration // floor delay
	Cap  time.Duration // ceiling delay; 0 = no cap
}

// NextDelay implements RetryPolicy.
func (b ExpBackoff) NextDelay(attempt int) (time.Duration, bool) {
	if attempt <= 0 || b.Max <= 0 || attempt >= b.Max {
		return 0, false
	}
	if b.Base <= 0 {
		b.Base = 100 * time.Millisecond
	}
	max := b.Base << (attempt - 1)
	if max <= 0 || (b.Cap > 0 && max > b.Cap) {
		max = b.Cap
		if max <= 0 {
			max = b.Base
		}
	}
	return time.Duration(rand.Int64N(int64(max) + 1)), true
}

// MaxAttempts reports the total durable attempt budget, including the first
// call. ExpBackoff with an unset/invalid Max still executes its initial call,
// so its effective ceiling is one.
func (b ExpBackoff) MaxAttempts() int {
	if b.Max <= 0 {
		return 1
	}
	return b.Max
}

// Retryable wraps an error to mark it as transient. The runtime applies the
// step's RetryPolicy.
func Retryable(err error) error {
	if err == nil {
		return nil
	}
	return retryableError{err: err}
}

// Permanent wraps an error to mark it as non-retryable regardless of the
// step's RetryPolicy.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return permanentError{err: err}
}

// IsPermanent reports whether the error was explicitly marked Permanent, i.e.
// must not be retried whatever the step's RetryPolicy says.
//
// This is the predicate the runtime's retry loop uses, and it is deliberately
// the INVERSE of IsRetryable rather than its complement: a step with a
// RetryPolicy retries anything the author did not mark Permanent. Requiring an
// explicit Retryable() wrapper instead (which is what IsRetryable tests) meant a
// plain errors.New was never retried, so a configured ExpBackoff did nothing and
// the run dead-lettered on the first failure.
func IsPermanent(err error) bool {
	if err == nil {
		return false
	}
	var p permanentError
	return errors.As(err, &p)
}

// IsRetryable reports whether the error was explicitly wrapped with Retryable
// AND not with Permanent. Note this is a strict marker test, not the retry
// DECISION: the runtime retries anything not marked Permanent when a
// RetryPolicy is set, so use IsPermanent to reason about whether a retry will
// happen. (This comment previously claimed "or has no Permanent marker", which
// the code has never done; the mismatch is why the two flows disagreed.)
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	var p permanentError
	if errors.As(err, &p) {
		return false
	}
	var r retryableError
	return errors.As(err, &r)
}

type retryableError struct{ err error }

func (e retryableError) Error() string { return e.err.Error() }
func (e retryableError) Unwrap() error { return e.err }

type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

// Step is the typed entry point AI-generated code uses. It delegates to
// Flow.Step but preserves T at the call site so workflow code stays
// boilerplate-free.
//
//	customer, err := reactor.Step(flow, ctx, "fetch-customer", reactor.StepOpts{
//	    IdempotencyKey: customerID,
//	    RetryPolicy:    reactor.ExpBackoff{Max: 5, Base: 200 * time.Millisecond, Cap: 5 * time.Second},
//	    Timeout:        15 * time.Second,
//	}, func(ctx context.Context) (Customer, error) {
//	    return crm.GetCustomer(ctx, customerID)
//	})
func Step[T any](flow Flow, ctx context.Context, name string, opts StepOpts, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	if flow == nil {
		return zero, errors.New("reactor: nil Flow")
	}
	out, err := flow.Step(ctx, name, opts, func(ctx context.Context) (any, error) {
		return fn(ctx)
	})
	if err != nil {
		return zero, err
	}
	if out == nil {
		return zero, nil
	}
	return coerceTo[T](out, "step")
}

// SideEffect journals a non-deterministic value so replay returns the
// same T without re-executing fn. Distinct from Step: no idempotency
// key, no retry policy, no timeout, the closure can't fail. Used for
// time.Now, crypto/rand, os.Getenv, uuid.New; anything where the
// workflow body needs a value that can't be derived from inputs.
//
// Each call needs a unique name within the workflow so the journal
// can match the cached value to the replay-time call site.
//
//	now, _ := reactor.SideEffect(flow, ctx, "captured-time", func() time.Time {
//	    return time.Now()
//	})
//
// On replay, the closure is NOT invoked: the journal returns the
// originally captured value so control flow downstream stays
// deterministic. This is the workflow-engine equivalent of Temporal's
// SideEffect (https://docs.temporal.io/dev-guide/go/foundations#side-effect).
func SideEffect[T any](flow Flow, ctx context.Context, name string, fn func() T) (T, error) {
	var zero T
	if flow == nil {
		return zero, errors.New("reactor: nil Flow")
	}
	out, err := flow.Step(ctx, name, StepOpts{}, func(_ context.Context) (any, error) {
		return fn(), nil
	})
	if err != nil {
		return zero, err
	}
	if out == nil {
		return zero, nil
	}
	return coerceTo[T](out, "side effect")
}

// coerceTo turns the generic any returned by Flow.Step into the typed T
// the caller asked for. Two paths:
//
//  1. InProcFlow stores the closure's literal return value, so a direct
//     type assertion succeeds.
//  2. PipeFlow round-trips through JSON for replay; on the other side
//     `decodeOutput` produces an untyped `any` where numbers are
//     float64 + objects are map[string]any, even when the original
//     closure returned int64 / a struct. The direct assertion then
//     fails. Falling back to a JSON re-marshal + unmarshal into T
//     fixes the round-trip without forcing every workflow to declare
//     output types as JSON-friendly shapes.
//
// kind is the human-readable label for the error message (so step + side
// effect callers see the right scope).
func coerceTo[T any](out any, kind string) (T, error) {
	var zero T
	if v, ok := out.(T); ok {
		return v, nil
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return zero, fmt.Errorf("reactor: %s output type mismatch: %w", kind, err)
	}
	var typed T
	if err := json.Unmarshal(raw, &typed); err != nil {
		return zero, fmt.Errorf("reactor: %s output type mismatch (cached as %T): %w", kind, out, err)
	}
	return typed, nil
}
