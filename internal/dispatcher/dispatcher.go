// Package dispatcher is the production wiring between trigger sources
// (webhook receiver, cron driver) and the workflow supervisor. A single
// implementation serves both because they share the same Dispatcher
// interface shape.
//
// Lifecycle of one dispatch:
//
//  1. Receive a journal.Trigger + payload from webhook or cron.
//  2. Resolve the workflow_slug via the workflows table.
//  3. Resolve the current workflow version to its verified immutable artifact.
//  4. Generate a fresh run_id and atomically persist the version + artifact pins.
//  5. Spawn a supervisor.Supervisor in its own goroutine. Run() returns
//     either "succeeded", "failed", "failed_dlq", or "suspended"; the
//     supervisor itself records the terminal status, this dispatcher
//     just logs.
//
// Concurrency: Dispatch returns immediately once the goroutine is
// spawned. The webhook handler can return 202 to the caller without
// waiting for the workflow to complete; cron driver's tick continues
// to the next entry.
package dispatcher

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/cancelreg"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/supervisor"
)

// BinaryLookup maps a workflow slug to the mutable compatibility path. It is
// retained for status/legacy wiring; pinned execution uses ArtifactLookup.
type BinaryLookup func(slug string) (string, error)

// ArtifactLookup resolves one immutable executable by workflow slug and full
// SHA-256. Production execution must use this rather than the mutable current
// BinaryPath compatibility pointer.
type ArtifactLookup func(slug, artifactSHA256 string) (string, error)

// TenantArtifactLookup is the tenant-aware immutable artifact boundary. The
// node-local registry has one slug directory while the journal permits the
// same slug in multiple tenants, so production execution supplies this
// callback to prevent a legacy same-slug row from executing another tenant's
// artifact. ArtifactLookup remains for in-memory/legacy fixtures.
type TenantArtifactLookup func(tenant, slug, artifactSHA256 string) (string, error)

// WorkflowResolver returns a workflow's slug + id given a trigger. The
// production impl reads the workflows table; tests inject a fake.
type WorkflowResolver interface {
	WorkflowBySlug(ctx context.Context, slug string) (id string, err error)
	WorkflowSlugByID(ctx context.Context, id string) (slug string, err error)
}

// Dispatcher implements both webhook.Dispatcher and cron.Dispatcher.
type Dispatcher struct {
	Journal               *journal.Journal
	Resolver              WorkflowResolver
	BinaryPath            BinaryLookup // compatibility/status only; never used for a pinned run
	ArtifactPath          ArtifactLookup
	ArtifactPathForTenant TenantArtifactLookup
	// IntegrityCheck proves that the retained source, source manifest, and DAG
	// still match the immutable workflow version immediately before execution.
	// Production wiring supplies this callback; keeping it optional preserves
	// the small in-memory dispatcher fixtures used by package tests.
	IntegrityCheck func(ctx context.Context, slug string, version journal.WorkflowVersion) error
	// QueueArtifactCheck is an optional second proof for a distributed worker
	// artifact tree. It runs only before creating a queued run; local dry runs
	// keep using the daemon's authoring artifact while it is being published.
	QueueArtifactCheck func(ctx context.Context, slug string, version journal.WorkflowVersion) error
	Sup                supervisor.Supervisor // template; RunID + BinaryPath set per dispatch
	Log                *slog.Logger

	// OnDeadLetter fires after a run durably terminates with
	// status="failed_dlq". Wired by the daemon to a postmortem.Generator
	// so every DLQ failure compounds into the knowledge corpus
	// automatically. Optional: nil disables the hook.
	//
	// The essential OnTerminal publication always runs first. This optional
	// hook receives an admission-scoped, bounded context and MUST honor its
	// cancellation so a slow AI provider cannot suppress notifications/chains
	// or outlive the database during forced shutdown.
	OnDeadLetter func(ctx context.Context, runID string)

	// DeadLetterHookTimeout bounds optional postmortem work. Zero uses two
	// minutes, matching the provider's normal request envelope; infrastructure
	// shutdown cancels it earlier through the admission lifetime.
	DeadLetterHookTimeout time.Duration

	// OnLog optionally receives per-run timeline lines (dispatch
	// "spawning", "run finished status=succeeded", etc.) so the
	// dashboard's /runs/{id}/tail SSE has something to emit.
	OnLog func(runID, line string)

	// OnStart resets per-run live state before an execution begins. DLQ
	// retries intentionally reuse their original run id so the durable step
	// journal can replay successful work.
	OnStart func(runID string)

	// OnTerminal fires once per run when the supervisor returns. The
	// daemon uses this to Close the run's log buffer + fire failure
	// notifications. Passing the full TerminalEvent lets the daemon
	// route on workflow + status without a second journal lookup.
	OnTerminal func(ctx context.Context, ev TerminalEvent)

	// Counters, when non-nil, gets bumped on dispatch + terminal so
	// the /metrics endpoint reflects what the dispatcher just did.
	// Defined here as a minimal interface so dispatcher doesn't
	// import server (which would create a cycle).
	Counters Counters

	// Cancels registers each executing run's cancel func so the dashboard
	// cancel handler + the cross-process cancel watcher can kill a live
	// run's subprocess. Optional; nil disables in-process cancellation
	// (the DB flag path still works for suspended runs).
	Cancels *cancelreg.Registry

	// Enqueue switches Dispatch from execute-in-process (local mode) to
	// persist-and-return (distributed mode): the run is written with status
	// "queued" and an `reactor worker` claims + executes it later via
	// ExecuteRun. Default false keeps the single-node behaviour unchanged.
	Enqueue bool

	// MaxConcurrent caps how many runs may execute at once. A webhook
	// storm (or a cron fan-out) would otherwise fork an unbounded number
	// of subprocesses and exhaust the host. Zero means unlimited (the
	// test default). Dispatch returns ErrCapacity when the cap is hit;
	// automatic sources (webhook/cron) surface this as a non-2xx so the
	// provider retries later, shedding load instead of melting the box.
	MaxConcurrent int

	// count tracks both dispatch resolution and supervisor execution so the
	// daemon can drain without an Add-after-Wait admission race.
	mu      sync.Mutex
	count   int
	stopped bool
	// terminalAdmissions are short-lived trusted reservations held by the
	// daemon while a counted dispatcher/scheduler parent publishes terminal
	// hooks. They let that hook hand off downstream workflow-complete work after
	// external admission closes without making trigger kind itself a capability.
	terminalAdmissions int
	admissions         map[uint64]context.CancelCauseFunc
	nextAdmission      uint64
	shutdownCause      error

	sem     chan struct{}
	semOnce sync.Once
}

// ErrCapacity is returned by Dispatch when MaxConcurrent in-flight runs
// are already executing. Callers shed load rather than queue unbounded.
var ErrCapacity = errors.New("dispatcher: at capacity; run not started")

// ErrShuttingDown is returned after the daemon closes external admission.
// Already-running terminal hooks may still admit workflow-complete chains while
// their parent remains counted, allowing a graceful drain to include the whole
// fan-out without accepting a late HTTP/cron run after an observed zero.
var ErrShuttingDown = errors.New("dispatcher: shutting down; run not started")

// ErrRetryInFlight is returned when a dead-letter retry loses the claim race:
// the run is already executing (a concurrent retry won) or was cancelled.
// Surfacing it lets the dashboard say so instead of silently double-running.
var ErrRetryInFlight = errors.New("dispatcher: run is already executing or was cancelled; retry not started")

// acquire takes a concurrency slot. Returns true when a slot was free (or
// the dispatcher is unlimited). Non-blocking: a full pool fails fast so
// the caller can shed load.
func (d *Dispatcher) acquire() bool {
	d.semOnce.Do(func() {
		if d.MaxConcurrent > 0 {
			d.sem = make(chan struct{}, d.MaxConcurrent)
		}
	})
	if d.sem == nil {
		return true
	}
	select {
	case d.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

// release frees a concurrency slot taken by acquire.
func (d *Dispatcher) release() {
	if d.sem == nil {
		return
	}
	select {
	case <-d.sem:
	default:
	}
}

// beginAdmission registers the whole dispatch operation before it performs
// resolution or creates a run. Stop serializes with this method, so Drain can
// never observe zero and then race an accepted HTTP/cron call that adds to the
// active counter afterward. A workflow-complete chain may enter after Stop because
// its terminal parent is synchronously counted by either this dispatcher or
// the scheduler; the daemon's joint count drain therefore has no zero gap.
func (d *Dispatcher) beginAdmission(terminalChain bool) (context.Context, func(), error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.shutdownCause != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrShuttingDown, d.shutdownCause)
	}
	if d.stopped && (!terminalChain || d.terminalAdmissions == 0) {
		return nil, nil, ErrShuttingDown
	}
	lifetime, cancel := context.WithCancelCause(context.Background())
	if d.admissions == nil {
		d.admissions = make(map[uint64]context.CancelCauseFunc)
	}
	d.nextAdmission++
	id := d.nextAdmission
	d.admissions[id] = cancel
	d.count++
	var once sync.Once
	release := func() {
		once.Do(func() {
			cancel(context.Canceled)
			d.mu.Lock()
			delete(d.admissions, id)
			d.count--
			d.mu.Unlock()
		})
	}
	return lifetime, release, nil
}

// Stop closes external admission. It is idempotent. Existing executions and
// their terminal workflow-complete fan-out remain drainable.
func (d *Dispatcher) Stop() {
	d.mu.Lock()
	d.stopped = true
	d.mu.Unlock()
}

// CancelAdmissions interrupts resolver/artifact/DB work admitted before Stop
// and records a cause that every pre-spawn safety check observes. It closes the
// shutdown hole where the one-shot process registry cancellation ran while an
// admission was still resolving, then that admission spawned an unregistered
// child after the timeout. Returns the number of admitted operations signaled.
func (d *Dispatcher) CancelAdmissions(cause error) int {
	if cause == nil {
		cause = cancelreg.ErrInfrastructureShutdown
	}
	d.mu.Lock()
	d.shutdownCause = cause
	cancels := make([]context.CancelCauseFunc, 0, len(d.admissions))
	for _, cancel := range d.admissions {
		cancels = append(cancels, cancel)
	}
	d.mu.Unlock()
	for _, cancel := range cancels {
		cancel(cause)
	}
	return len(cancels)
}

func bindAdmissionContext(parent, lifetime context.Context) (context.Context, func()) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancelCause(parent)
	stop := context.AfterFunc(lifetime, func() { cancel(context.Cause(lifetime)) })
	return ctx, func() {
		stop()
		cancel(context.Canceled)
	}
}

func admissionSafe(lifetime context.Context) error {
	if cause := context.Cause(lifetime); cause != nil {
		return fmt.Errorf("%w: %v", ErrShuttingDown, cause)
	}
	return nil
}

// HoldTerminalAdmission reserves drain ownership for one trusted terminal-hook
// call and returns an idempotent release. The serve wiring acquires it while
// the dispatcher or scheduler parent is still counted, so the joint shutdown
// drain cannot observe a zero between parent completion and chain admission.
func (d *Dispatcher) HoldTerminalAdmission() func() {
	d.mu.Lock()
	d.terminalAdmissions++
	d.count++
	d.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			d.mu.Lock()
			d.terminalAdmissions--
			d.count--
			d.mu.Unlock()
		})
	}
}

// TerminalEvent is the payload OnTerminal receives. Everything the
// daemon needs to fan out to log buffers, notifiers, and chained
// workflows without a second journal round-trip in the dispatcher.
type TerminalEvent struct {
	RunID        string
	WorkflowID   string
	WorkflowSlug string
	Status       string // "succeeded" | "failed" | "failed_dlq" | "suspended"
	TriggerKind  string
	ErrorText    string
	DryRun       bool // a test run: the host suppresses notifications + chains
	// TerminalEffectClaimedAt is set by the durable recovery loop. Direct
	// terminal callbacks leave it zero and claim their receipt before running
	// side effects; carrying the timestamp and token keeps the final
	// acknowledgement fenced to the exact generation that was handled.
	TerminalEffectClaimedAt  time.Time
	TerminalEffectClaimToken string
}

// terminalErrText converts the supervisor's terminal error to a
// human-readable string for the notifier. Empty when err is nil.
func terminalErrText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Counters is the dispatcher's metrics surface. *server.Metrics
// satisfies it. Kept minimal so adding a new gauge doesn't ripple
// through the dispatcher interface.
type Counters interface {
	IncRunsStarted()
	IncRunsTerminal(status string)
}

// RetryDeadLetter re-runs the workflow that owns the dead-letter row
// by spawning a fresh supervisor with the original RunID. The
// supervisor's journal cache short-circuits every previously-succeeded
// step; the failed step has no succeeded output_jsonb row so the
// closure runs again. On terminal "succeeded" status, the dead_letter
// row is removed so the operator's todo list shrinks.
//
// Used by both the dashboard's "Retry from DLQ" button + the CLI's
// `reactor dlq retry` command (which still calls cmdDLQRetry today
// but could migrate to this method for parity). Returns the terminal
// status reached by the retry.
func (d *Dispatcher) RetryDeadLetter(ctx context.Context, dlqID string) (string, error) {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	lifetime, releaseAdmission, err := d.beginAdmission(false)
	if err != nil {
		return "", err
	}
	defer releaseAdmission()
	ctx, releaseOperation := bindAdmissionContext(ctx, lifetime)
	defer releaseOperation()
	item, err := d.Journal.GetDeadLetterItem(ctx, dlqID)
	if err != nil {
		return "", fmt.Errorf("dispatcher: get dlq item: %w", err)
	}
	run, err := d.Journal.GetRun(ctx, item.RunID)
	if err != nil {
		return "", fmt.Errorf("dispatcher: get run: %w", err)
	}
	// A retry is a run, so it goes through the SAME gates dispatch() applies.
	// This path used to call sup.Run directly and skipped all of them: the
	// enabled flag (so "disable" was not a kill switch), the tenant quota, the
	// per-workflow rate limit, the concurrency slot, the drain admission
	// (graceful drain did not wait for it), the cancel registry (the run could
	// not be stopped), and execute()'s panic recovery (a panic left the run
	// stuck in "running" because the status had already been flipped).
	enabled, eErr := d.Journal.IsWorkflowEnabled(ctx, run.WorkflowID)
	if eErr != nil {
		return "", fmt.Errorf("dispatcher: dlq retry workflow enabled-state admission check failed: %w", eErr)
	}
	if !enabled {
		d.Log.Info("dispatcher: refusing dlq retry; workflow disabled",
			"workflow_id", run.WorkflowID, "run_id", item.RunID)
		return "", ErrWorkflowDisabled
	}
	if qErr := d.Journal.CheckWorkflowEnqueueAllowed(ctx, run.WorkflowID); qErr != nil {
		var qe *journal.QuotaError
		if errors.As(qErr, &qe) {
			return "", qErr
		}
		// A quota lookup error is an admission failure, not evidence that this
		// retry is unlimited. Continuing here would let a database/schema outage
		// bypass tenant disabled, queue, or hard monthly-cap controls. Leave the
		// exact DLQ item untouched so a later retry can re-run the check.
		return "", fmt.Errorf("dispatcher: dlq retry quota admission check failed: %w", qErr)
	}
	if allowed, limit, rErr := d.Journal.CheckWorkflowRateLimit(ctx, run.WorkflowID); rErr != nil {
		// The rate-limit read is part of the same admission boundary. A failed
		// count must not be interpreted as an empty window, especially for a
		// retry that can repeat an external side effect.
		return "", fmt.Errorf("dispatcher: dlq retry rate-limit admission check failed: %w", rErr)
	} else if !allowed {
		d.Log.Info("dispatcher: refusing dlq retry; rate limit",
			"workflow_id", run.WorkflowID, "limit_per_min", limit)
		return "", ErrRateLimited
	}

	slug, err := d.Resolver.WorkflowSlugByID(ctx, run.WorkflowID)
	if err != nil {
		return "", fmt.Errorf("dispatcher: resolve workflow: %w", err)
	}
	version, binary, err := d.resolvePinnedVersionAndBinary(ctx, run, slug)
	if err != nil {
		_ = d.Journal.LogRunArtifactFence(context.WithoutCancel(ctx), run.ID)
		return "", fmt.Errorf("dispatcher: dlq retry refused by workflow artifact fence: %w", err)
	}
	if err := d.checkIntegrity(ctx, slug, version); err != nil {
		// A retained-source/DAG fence is a durable identity failure for the
		// pinned retry, while transient validator failures leave the DLQ item
		// available for a later operator retry.
		return "", fmt.Errorf("dispatcher: dlq retry refused by workflow integrity check: %w", err)
	}
	if d.Enqueue {
		if err := d.checkQueueArtifact(ctx, slug, version); err != nil {
			return "", err
		}
		if err := admissionSafe(lifetime); err != nil {
			return "", err
		}
		claimed, cErr := d.Journal.StartDeadLetterRetryQueuedItem(ctx, item.RunID, item.ID)
		if cErr != nil {
			if errors.Is(cErr, journal.ErrWorkflowDisabled) {
				return "", ErrWorkflowDisabled
			}
			return "", fmt.Errorf("dispatcher: queue run for retry: %w", cErr)
		}
		if !claimed {
			return "", ErrRetryInFlight
		}
		d.Log.Info("dispatcher: queued dlq retry", "run_id", item.RunID, "dlq_id", item.ID)
		return "queued", nil
	}

	// Take the slot before mutating any state, so a full pool sheds the retry
	// instead of claiming the run and then failing.
	if !d.acquire() {
		d.Log.Warn("dispatcher: at capacity; rejecting dlq retry", "max", d.MaxConcurrent)
		return "", ErrCapacity
	}
	defer d.release()
	if err := admissionSafe(lifetime); err != nil {
		return "", err
	}

	// Single-flight claim. The old unguarded SetRunStatus meant two operators
	// clicking Retry on the same row both flipped it to running and both
	// spawned a supervisor against the same run id, duplicating side effects.
	// The CAS also refuses a cancelled run, matching MarkRunFinished.
	claimed, cErr := d.Journal.StartDeadLetterRetryItem(ctx, item.RunID, item.ID)
	if cErr != nil {
		if errors.Is(cErr, journal.ErrWorkflowDisabled) {
			return "", ErrWorkflowDisabled
		}
		return "", fmt.Errorf("dispatcher: claim run for retry: %w", cErr)
	}
	if !claimed {
		return "", ErrRetryInFlight
	}
	if d.OnStart != nil {
		d.OnStart(item.RunID)
	}

	sup := d.Sup
	sup.BinaryPath = binary
	sup.WorkflowSlug = slug
	sup.RunID = item.RunID
	sup.Journal = d.Journal
	// Re-spawn the workflow with its original trigger input. dead_letter.payload
	// is the failed Step payload and may not even match the workflow's input
	// schema (the Hash bridge expects the original signed event envelope).
	sup.Input = run.ExecutionInput()
	if sup.Log == nil {
		sup.Log = d.Log
	}
	if sup.Mode == "" {
		sup.Mode = "live"
	}

	// execute() owns the cancellable+registered context, the panic recovery and
	// the terminal hooks. It also decouples the run from the caller's context,
	// so a browser disconnect no longer kills the workflow mid-step.
	status, execErr := d.execute(lifetime, item.RunID, slug, run.WorkflowID, run.TriggerKind, sup)
	if status == "succeeded" {
		if _, err := d.Journal.DeleteDeadLettersByRun(context.WithoutCancel(ctx), item.RunID); err != nil {
			d.Log.Warn("dispatcher: dlq cleanup failed", "err", err)
		}
	}
	return status, execErr
}

// Dispatch creates a run + spawns a supervisor goroutine. Returns once
// the supervisor is running; the caller is freed to ack the trigger.
// Dispatch starts a run for a trigger (fire-and-forget). The public surface is
// unchanged; the body lives in dispatch() so DispatchSync can reuse it + wait.
func (d *Dispatcher) Dispatch(ctx context.Context, t journal.Trigger, payload []byte) error {
	_, err := d.dispatch(ctx, t, payload, "live")
	return err
}

// DispatchTerminalChain is the trusted terminal-hook entry point. External
// HTTP/cron/manual surfaces use Dispatch and cannot bypass Stop merely by
// supplying kind=workflow_complete. During shutdown this succeeds only while
// the daemon holds a terminal admission reservation.
func (d *Dispatcher) DispatchTerminalChain(ctx context.Context, t journal.Trigger, payload []byte) error {
	if t.Kind != journal.TriggerWorkflowComplete {
		return errors.New("dispatcher: terminal-chain admission requires workflow_complete trigger")
	}
	// Terminal-effect recovery may rerun a fan-out after one peer failed or the
	// daemon crashed after another peer accepted its run. Bind the downstream
	// receipt to this immutable trigger row and exact source payload so those
	// retries converge on the original run instead of duplicating side effects.
	key := terminalChainIdempotencyKey(t, payload)
	runID, err := d.dispatchWithIdempotency(ctx, t, payload, "live", true, key)
	if err != nil {
		return err
	}
	if runID == "" {
		// A disabled downstream must remain retryable: returning nil here would
		// acknowledge the upstream terminal effect while creating no run.
		return ErrWorkflowDisabled
	}
	return nil
}

func terminalChainIdempotencyKey(t journal.Trigger, payload []byte) string {
	h := sha256.New()
	h.Write([]byte(string(t.Kind)))
	h.Write([]byte{0})
	h.Write([]byte(t.ID))
	h.Write([]byte{0})
	h.Write([]byte(t.WorkflowID))
	h.Write([]byte{0})
	h.Write(payload)
	return "chain-" + hex.EncodeToString(h.Sum(nil))
}

// DispatchWebhook is the webhook-specific async surface. It has the same
// execution semantics as Dispatch but returns the run id once the run row is
// durable. The receiver stores that id while completing its delivery lease,
// which distinguishes a genuinely dispatched replay from a receipt that was
// only claimed before a host crash.
//
// Keep Dispatch for cron/chain callers whose interface intentionally returns
// only an error; adding this method avoids a broad API break.
func (d *Dispatcher) DispatchWebhook(ctx context.Context, t journal.Trigger, payload []byte) (string, error) {
	runID, err := d.dispatch(ctx, t, payload, "live")
	if err == nil && runID == "" {
		// Automatic dispatch historically treats a disabled workflow as a
		// successful no-op. A webhook receipt must not call that completed: no
		// durable run exists, and acknowledging it would permanently discard the
		// provider event. Let the receiver release its lease and ask for retry.
		return "", ErrWorkflowDisabled
	}
	return runID, err
}

// DispatchTest runs a workflow as a DRY RUN: it executes in-process with
// REACTOR_MODE=dry_run exported to the subprocess (so workflow code can mock
// side effects) and the host suppresses its own side effects (notifications +
// downstream chains) for the run. Used by the dashboard's "test run" so an
// operator can try a workflow with sample input without real-world fallout.
func (d *Dispatcher) DispatchTest(ctx context.Context, t journal.Trigger, payload []byte) (string, error) {
	return d.dispatch(ctx, t, payload, "dry_run")
}

// DispatchManual runs a live manual run (async, like Dispatch) but returns the
// run id so the dashboard can land the operator on that run's live page.
func (d *Dispatcher) DispatchManual(ctx context.Context, t journal.Trigger, payload []byte) (string, error) {
	return d.dispatch(ctx, t, payload, "live")
}

// DispatchManualIdempotent is the MCP/manual control-plane variant. A
// non-empty key is bound to the exact payload digest in the runs journal, so a
// client retry after a lost HTTP response returns the original run instead of
// starting a second automation. Empty keys retain ordinary manual semantics.
func (d *Dispatcher) DispatchManualIdempotent(ctx context.Context, t journal.Trigger, payload []byte, key string) (string, error) {
	return d.dispatchWithIdempotency(ctx, t, payload, "live", false, key)
}

// dispatch runs the gates + starts the run, returning the run id it created
// ("" when the dispatch was skipped or refused). mode is the supervisor run
// mode ("live" or "dry_run"); a dry run always executes in-process.
func (d *Dispatcher) dispatch(ctx context.Context, t journal.Trigger, payload []byte, mode string) (string, error) {
	return d.dispatchWithAdmission(ctx, t, payload, mode, false)
}

func (d *Dispatcher) dispatchWithAdmission(ctx context.Context, t journal.Trigger, payload []byte, mode string, trustedTerminalChain bool) (string, error) {
	return d.dispatchWithIdempotency(ctx, t, payload, mode, trustedTerminalChain, "")
}

func (d *Dispatcher) dispatchWithIdempotency(ctx context.Context, t journal.Trigger, payload []byte, mode string, trustedTerminalChain bool, idempotencyKey string) (string, error) {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	// The runs table's trigger metadata is JSONB on Postgres and cannot store
	// an empty value. Normalize the one empty-input case before hashing,
	// journaling, and spawning so the receipt and the workflow always describe
	// the same bytes. Non-empty payloads remain byte-for-byte unchanged.
	if len(payload) == 0 {
		payload = []byte(`{}`)
	}
	if idempotencyKey != "" && strings.TrimSpace(idempotencyKey) == "" {
		return "", errors.New("dispatcher: invalid MCP dispatch idempotency key")
	}
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if len(idempotencyKey) > 200 || strings.IndexFunc(idempotencyKey, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return "", errors.New("dispatcher: invalid MCP dispatch idempotency key")
	}
	payloadHash := ""
	if idempotencyKey != "" {
		digest := sha256.Sum256(payload)
		payloadHash = hex.EncodeToString(digest[:])
		// Idempotency is a receipt contract, so resolve an existing request
		// before consulting mutable admission state. A client retry after a
		// lost HTTP response must still return the original run if an operator
		// paused the workflow or the current artifact is temporarily unavailable.
		// The durable insert below remains the race-safe authority for two first
		// requests arriving concurrently.
		if existing, findErr := d.Journal.FindMCPDispatchRun(ctx, t.WorkflowID, idempotencyKey, payloadHash); findErr == nil {
			return existing, nil
		} else if !errors.Is(findErr, journal.ErrNotFound) {
			return "", findErr
		}
	}
	lifetime, releaseAdmission, err := d.beginAdmission(trustedTerminalChain)
	if err != nil {
		return "", err
	}
	ctx, releaseOperation := bindAdmissionContext(ctx, lifetime)
	defer releaseOperation()
	transferred := false
	defer func() {
		if !transferred {
			releaseAdmission()
		}
	}()
	// Respect the enabled flag on every LIVE dispatch path (webhook, cron,
	// chain, manual). A disabled workflow stays inert for real events, while
	// an explicit dry run is allowed so a newly authored workflow can be
	// inspected before activation. Dry-run side effects are suppressed by the
	// supervisor/notifier path; workflow code still receives REACTOR_MODE=dry_run.
	enabled, eErr := d.Journal.IsWorkflowEnabled(ctx, t.WorkflowID)
	if eErr != nil {
		if errors.Is(eErr, journal.ErrNotFound) {
			// Preserve the resolver's public unknown-workflow error for callers
			// that supplied a stale trigger id. Existing workflows still fail
			// closed below when the enabled-state read itself is unavailable.
			if _, resolveErr := d.Resolver.WorkflowSlugByID(ctx, t.WorkflowID); resolveErr != nil {
				return "", fmt.Errorf("dispatcher: resolve workflow: %w", resolveErr)
			}
		}
		// Enabled state is the workflow kill switch. A failed read cannot be
		// treated as enabled because that would turn a control-plane outage
		// into an execution bypass.
		return "", fmt.Errorf("dispatcher: workflow enabled-state admission check failed: %w", eErr)
	}
	if !enabled && mode != "dry_run" {
		d.Log.Info("dispatcher: skipping dispatch; workflow disabled",
			"workflow_id", t.WorkflowID, "trigger_kind", t.Kind)
		return dispatchWorkflowDisabled(t)
	}
	if mode == "dry_run" {
		if !enabled {
			d.Log.Info("dispatcher: allowing review dry run for disabled workflow", "workflow_id", t.WorkflowID)
		}
	}

	// Per-tenant quota gate (SaaS control plane). Refuse new runs when the
	// owning tenant is disabled, at its queue cap, or over its monthly quota.
	// Unknown tenants / zero quotas pass, so single-tenant installs are never
	// gated. The QuotaError is returned to all trigger kinds so the caller can
	// back off (a webhook sender retries on error). A failure to CHECK the
	// quota (infra error) fails closed: do not let a transient DB/schema hiccup
	// bypass tenant policy. The caller can retry once admission is readable.
	if qErr := d.Journal.CheckWorkflowEnqueueAllowed(ctx, t.WorkflowID); qErr != nil {
		var qe *journal.QuotaError
		if errors.As(qErr, &qe) {
			d.Log.Info("dispatcher: refusing dispatch; quota",
				"workflow_id", t.WorkflowID, "tenant", qe.TenantID, "reason", qe.Reason)
			return "", qErr
		}
		// An admission read error is fail-closed. Treating a missing tenant row,
		// disabled-state read, or quota-count failure as unlimited would allow a
		// control-plane outage to bypass tenant policy. The next provider retry or
		// operator attempt can safely re-evaluate the same request.
		return "", fmt.Errorf("dispatcher: quota admission check failed: %w", qErr)
	}

	// Per-workflow rate limit (runs/min). Refuse when over; like the quota
	// gate, returned to all trigger kinds so the caller backs off. A failed
	// counter read is also an admission error rather than an empty window.
	if allowed, limit, rErr := d.Journal.CheckWorkflowRateLimit(ctx, t.WorkflowID); rErr != nil {
		// A failed rate-window read is not an empty window. Refuse admission until
		// the journal can prove the configured limit and current usage.
		return "", fmt.Errorf("dispatcher: rate-limit admission check failed: %w", rErr)
	} else if !allowed {
		d.Log.Info("dispatcher: refusing dispatch; rate limit",
			"workflow_id", t.WorkflowID, "trigger_kind", t.Kind, "limit_per_min", limit)
		return "", ErrRateLimited
	}

	// Resolve the current version to its immutable artifact before creating a
	// run. If a deployment activates a newer version after this read, this run
	// still owns these exact bytes; it never follows the mutable canonical path.
	slug, err := d.Resolver.WorkflowSlugByID(ctx, t.WorkflowID)
	if err != nil {
		return "", fmt.Errorf("dispatcher: resolve workflow: %w", err)
	}
	version, binary, err := d.resolveCurrentBinary(ctx, t.WorkflowID, slug)
	if err != nil {
		return "", fmt.Errorf("dispatcher: workflow artifact unavailable: %w", err)
	}
	if err := d.checkIntegrity(ctx, slug, version); err != nil {
		return "", fmt.Errorf("dispatcher: workflow integrity check failed: %w", err)
	}
	// Distributed mode: persist the run as "queued" and return. A worker
	// claims + executes it (ExecuteRun). No slot is taken and no subprocess
	// is spawned here -- the queue absorbs the burst, so this never sheds
	// load the way the in-process path does. A dry run skips the queue and
	// runs in-process so its mode + effect-suppression apply on this node.
	if d.Enqueue && mode != "dry_run" {
		if err := d.checkQueueArtifact(ctx, slug, version); err != nil {
			return "", err
		}
		if err := admissionSafe(lifetime); err != nil {
			return "", err
		}
		runID, err := newRunID()
		if err != nil {
			return "", err
		}
		meta := payload
		var created bool
		if idempotencyKey != "" {
			var id string
			id, created, err = d.Journal.CreateQueuedRunPinnedIdempotentIfEnabled(ctx, runID, t.WorkflowID, string(t.Kind), meta, version.Version, version.ArtifactSHA256, idempotencyKey, payloadHash)
			if isWorkflowRateLimited(err) {
				return "", ErrRateLimited
			}
			if errors.Is(err, journal.ErrWorkflowDisabled) {
				return dispatchWorkflowDisabled(t)
			}
			if !created {
				if err != nil {
					return "", err
				}
				return id, nil
			}
		} else {
			err = d.Journal.CreateQueuedRunPinnedIfEnabled(ctx, runID, t.WorkflowID, string(t.Kind), meta, version.Version, version.ArtifactSHA256)
			if isWorkflowRateLimited(err) {
				return "", ErrRateLimited
			}
			if errors.Is(err, journal.ErrWorkflowDisabled) {
				return dispatchWorkflowDisabled(t)
			}
		}
		if err != nil {
			return "", fmt.Errorf("dispatcher: enqueue run: %w", err)
		}
		if d.Counters != nil {
			d.Counters.IncRunsStarted()
		}
		d.Log.Info("dispatcher: enqueued run", "run_id", runID, "workflow_id", t.WorkflowID, "trigger_kind", t.Kind)
		return runID, nil
	}

	// Take a concurrency slot before creating any state. A full pool fails
	// fast so a webhook storm sheds load instead of forking unbounded
	// subprocesses. The slot is released when the run goroutine exits.
	if !d.acquire() {
		d.Log.Warn("dispatcher: at capacity; rejecting dispatch",
			"workflow_id", t.WorkflowID, "max", d.MaxConcurrent)
		return "", ErrCapacity
	}
	if err := admissionSafe(lifetime); err != nil {
		d.release()
		return "", err
	}

	runID, err := newRunID()
	if err != nil {
		d.release()
		return "", err
	}
	meta := payload
	var created bool
	if idempotencyKey != "" {
		var id string
		id, created, err = d.Journal.CreateRunPinnedIdempotentIfEnabled(ctx, runID, t.WorkflowID, string(t.Kind), meta, version.Version, version.ArtifactSHA256, idempotencyKey, payloadHash)
		if isWorkflowRateLimited(err) {
			d.release()
			return "", ErrRateLimited
		}
		if !created {
			if errors.Is(err, journal.ErrWorkflowDisabled) {
				d.release()
				return dispatchWorkflowDisabled(t)
			}
			d.release()
			if err != nil {
				return "", err
			}
			return id, nil
		}
	} else {
		err = d.Journal.CreateRunPinnedIfEnabled(ctx, runID, t.WorkflowID, string(t.Kind), meta, version.Version, version.ArtifactSHA256)
		if isWorkflowRateLimited(err) {
			d.release()
			return "", ErrRateLimited
		}
		if errors.Is(err, journal.ErrWorkflowDisabled) {
			d.release()
			return dispatchWorkflowDisabled(t)
		}
	}
	if err != nil {
		d.release()
		return "", fmt.Errorf("dispatcher: create run: %w", err)
	}
	if d.Counters != nil {
		d.Counters.IncRunsStarted()
	}
	sup := d.Sup
	sup.BinaryPath = binary
	sup.RunID = runID
	sup.WorkflowSlug = slug
	sup.Journal = d.Journal
	sup.Input = payload
	if sup.Log == nil {
		sup.Log = d.Log
	}
	sup.Mode = mode
	if sup.Mode == "" {
		sup.Mode = "live"
	}
	if sup.Mode == "dry_run" {
		// Tell the workflow subprocess it's a dry run so author code can mock
		// external calls; the host also suppresses its own side effects on
		// terminal (see TerminalInfo.DryRun).
		sup.ExtraEnv = append(append([]string{}, sup.ExtraEnv...), "REACTOR_MODE=dry_run")
	}
	// Fan workflow-emitted log lines into the same per-run sink the
	// dispatcher uses for its status lines so the dashboard's
	// /runs/{id}/tail SSE shows BOTH layers.
	if d.OnLog != nil {
		sup.LogSink = d.OnLog
	}
	if d.OnStart != nil {
		d.OnStart(runID)
	}

	transferred = true
	go func() {
		defer releaseAdmission()
		defer d.release()
		_, _ = d.execute(lifetime, runID, slug, t.WorkflowID, string(t.Kind), sup)
	}()
	return runID, nil
}

// DispatchSync starts a run and waits up to timeout for it to reach a terminal
// status, then returns the run id, final status, and the output of the run's
// last completed step (the workflow's "response"). It powers synchronous
// webhooks -- turning a workflow into a request/response API. Works in both
// local and distributed mode (it polls the journal, which a worker updates).
func (d *Dispatcher) DispatchSync(ctx context.Context, t journal.Trigger, payload []byte, timeout time.Duration) (runID, status string, output json.RawMessage, err error) {
	runID, err = d.dispatch(ctx, t, payload, "live")
	if err != nil {
		return "", "", nil, err
	}
	if runID == "" {
		return "", "", nil, ErrWorkflowDisabled // skipped (disabled)
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		info, gErr := d.Journal.GetRun(ctx, runID)
		if gErr == nil && isTerminalStatus(info.Status) {
			out := d.lastStepOutput(ctx, runID)
			return runID, info.Status, out, nil
		}
		if time.Now().After(deadline) {
			return runID, "running", nil, ErrSyncTimeout
		}
		select {
		case <-ctx.Done():
			return runID, "running", nil, ctx.Err()
		case <-time.After(120 * time.Millisecond):
		}
	}
}

func isTerminalStatus(s string) bool {
	switch s {
	case "succeeded", "failed", "failed_dlq", "cancelled":
		return true
	}
	return false
}

// lastStepOutput returns the output_jsonb of the run's most recently finished
// step -- the closest thing to "the workflow's return value".
func (d *Dispatcher) lastStepOutput(ctx context.Context, runID string) json.RawMessage {
	// Synchronous webhook responses need only the latest successful output.
	// Query that one bounded row instead of materializing every step attempt and
	// output in a run; a workflow can legitimately have thousands of retries or
	// large historical results. Oversized output remains available through the
	// bounded MCP step-output reader, while the request/response surface returns
	// no unbounded blob.
	step, err := d.Journal.LatestSuccessfulStepOutputBounded(ctx, runID, "", 1<<20)
	if err != nil || step.OutputTruncated || len(step.OutputJSONB) == 0 {
		return nil
	}
	return step.OutputJSONB
}

// execute runs one supervisor to terminal and fires the lifecycle hooks
// (cancellation, panic recovery, OnLog, OnDeadLetter, OnTerminal, metrics).
// Shared by the local-mode dispatch goroutine and the distributed-mode
// worker (ExecuteRun). Admission/drain tracking is owned by each public entry
// point; execute only owns the process lifecycle shared by those paths.
// Returns the terminal status so the synchronous caller (the dashboard's
// dead-letter retry) can report it without a second journal read.
func (d *Dispatcher) execute(parent context.Context, runID, slug, workflowID, triggerKind string, sup supervisor.Supervisor) (terminal string, runErr error) {
	supervisorReturned := false
	// Recover so a panicking workflow supervisor (or any callback) fails
	// just this run instead of taking down the daemon/worker and every
	// other in-flight run with it.
	defer func() {
		if rec := recover(); rec != nil {
			runErr = errors.Join(runErr, fmt.Errorf("dispatcher: panic: %v", rec))
			d.Log.Error("dispatcher: run goroutine panicked",
				"run_id", runID, "workflow", slug, "panic", rec)
			// Supervisor.Run catches and persists its own panics. A callback can
			// panic before Run begins, though; persist that early failure through
			// the same owner-fenced path before exposing a terminal status.
			if terminal == "" && !supervisorReturned && sup.Mode != "replay" {
				unsafeLease := sup.LeaseOwner != "" && context.Cause(parent) != nil && !errors.Is(context.Cause(parent), context.Canceled)
				if !unsafeLease {
					durableCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
					persistedStatus, persistErr := sup.PersistOutcomeStatus(durableCtx, "failed")
					cancel()
					if persistErr != nil {
						runErr = errors.Join(runErr, persistErr)
						return
					}
					terminal = persistedStatus
				}
			}
		}
	}()
	// Fresh, cancellable, registered context so an operator can stop the
	// run (exec.CommandContext kills the subprocess on cancel) and a closed
	// HTTP connection doesn't.
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(context.Canceled)
	if d.Cancels != nil {
		registration := d.Cancels.RegisterCause(runID, cancel)
		defer d.Cancels.DeregisterRegistration(runID, registration)
	}
	if d.OnLog != nil {
		d.OnLog(runID, fmt.Sprintf("dispatcher: spawning run_id=%s workflow=%s", runID, slug))
	}
	status, err := sup.Run(ctx)
	supervisorReturned = true
	terminal, runErr = status, err
	if err != nil {
		line := fmt.Sprintf("dispatcher: run errored run_id=%s workflow=%s status=%s err=%v", runID, slug, status, err)
		d.Log.Error("dispatcher: run errored", "run_id", runID, "workflow", slug, "status", status, "err", err)
		if d.OnLog != nil {
			d.OnLog(runID, line)
		}
	} else {
		line := fmt.Sprintf("dispatcher: run finished run_id=%s workflow=%s status=%s", runID, slug, status)
		d.Log.Info("dispatcher: run finished", "run_id", runID, "workflow", slug, "status", status)
		if d.OnLog != nil {
			d.OnLog(runID, line)
		}
	}
	// An empty status means durable persistence failed or distributed
	// execution deliberately remained recoverable. Never publish hooks or
	// metrics before the state transition commits.
	if status == "" {
		return terminal, runErr
	}
	d.publishTerminal(ctx, TerminalEvent{
		RunID:        runID,
		WorkflowID:   workflowID,
		WorkflowSlug: slug,
		Status:       status,
		TriggerKind:  triggerKind,
		ErrorText:    terminalErrText(err),
		DryRun:       sup.Mode == "dry_run",
	})
	return terminal, runErr
}

// ExecuteRun is the distributed-mode worker entry point: it reconstructs a
// claimed run from the journal (slug, binary, input), executes it through
// the shared lifecycle, and releases the lease when it reaches terminal.
// Synchronous -- the worker spawns goroutines + bounds its own concurrency.
func (d *Dispatcher) ExecuteRun(ctx context.Context, runID, leaseOwner string) error {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	lifetime, releaseAdmission, err := d.beginAdmission(false)
	if err != nil {
		return err
	}
	defer releaseAdmission()
	ctx, releaseOperation := bindAdmissionContext(ctx, lifetime)
	defer releaseOperation()
	if leaseOwner == "" {
		return errors.New("dispatcher: execute claimed run: empty lease owner")
	}
	if err := d.Journal.VerifyLeaseOwner(ctx, runID, leaseOwner); err != nil {
		return fmt.Errorf("dispatcher: execute claimed run: %w", err)
	}
	run, err := d.Journal.GetRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("dispatcher: get run %s: %w", runID, err)
	}
	slug, err := d.Resolver.WorkflowSlugByID(ctx, run.WorkflowID)
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		// A slug lookup/query failure is operational, not proof that the
		// persisted run/version binding is invalid. Leave the exact lease and
		// running row recoverable for expiry/reap.
		return fmt.Errorf("dispatcher: resolve claimed workflow: %w", err)
	}
	version, binary, err := d.resolvePinnedVersionAndBinary(ctx, run, slug)
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		var fence *journal.WorkflowArtifactFenceError
		if errors.As(err, &fence) {
			return d.failArtifactFencedRun(ctx, run, slug, leaseOwner, err)
		}
		// Validator database errors and node-local artifact lookup/config/hash/
		// permission failures are transient. Only the validator's typed durable
		// identity fence authorizes terminal failure and owned lease release.
		return fmt.Errorf("dispatcher: validate claimed workflow artifact: %w", err)
	}
	if err := d.checkIntegrity(ctx, slug, version); err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		var fence *journal.WorkflowArtifactFenceError
		if errors.As(err, &fence) {
			return d.failArtifactFencedRun(ctx, run, slug, leaseOwner, err)
		}
		// Source retention, manifest, and DAG checks may also fail for a
		// node-local availability reason. Preserve the lease/run for retry when
		// the validator did not establish a durable identity fence.
		return fmt.Errorf("dispatcher: validate claimed workflow source: %w", err)
	}

	sup := d.Sup
	sup.BinaryPath = binary
	sup.RunID = runID
	sup.WorkflowSlug = slug
	sup.Journal = d.Journal
	sup.Input = run.ExecutionInput()
	sup.LeaseOwner = leaseOwner
	if sup.Log == nil {
		sup.Log = d.Log
	}
	if sup.Mode == "" {
		sup.Mode = "live"
	}
	if d.OnLog != nil {
		sup.LogSink = d.OnLog
	}
	if err := admissionSafe(lifetime); err != nil {
		return err
	}
	if d.OnStart != nil {
		d.OnStart(runID)
	}

	_, err = d.execute(ctx, runID, slug, run.WorkflowID, run.TriggerKind, sup)
	return err
}

func (d *Dispatcher) resolveCurrentBinary(ctx context.Context, workflowID, slug string) (journal.WorkflowVersion, string, error) {
	v, err := d.Journal.CurrentWorkflowVersionRecord(ctx, workflowID)
	if err != nil {
		return journal.WorkflowVersion{}, "", err
	}
	run := journal.RunInfo{
		WorkflowID: workflowID, WorkflowVersion: v.Version, WorkflowArtifactSHA256: v.ArtifactSHA256,
	}
	if _, err := d.Journal.ValidateRunWorkflowArtifact(ctx, run); err != nil {
		return journal.WorkflowVersion{}, "", err
	}
	if d.ArtifactPath == nil && d.ArtifactPathForTenant == nil {
		return journal.WorkflowVersion{}, "", fmt.Errorf("%w: immutable artifact lookup is not configured", journal.ErrWorkflowArtifactFence)
	}
	var binary string
	if d.ArtifactPathForTenant != nil {
		tenant, tenantErr := d.Journal.WorkflowTenant(ctx, workflowID)
		if tenantErr != nil {
			return journal.WorkflowVersion{}, "", fmt.Errorf("%w: resolve workflow tenant: %v", journal.ErrWorkflowArtifactFence, tenantErr)
		}
		binary, err = d.ArtifactPathForTenant(tenant, slug, v.ArtifactSHA256)
	} else {
		binary, err = d.ArtifactPath(slug, v.ArtifactSHA256)
	}
	if err != nil {
		return journal.WorkflowVersion{}, "", fmt.Errorf("%w: immutable artifact failed verification", journal.ErrWorkflowArtifactFence)
	}
	return v, binary, nil
}

// resolvePinnedBinary retains the narrow compatibility helper used by older
// in-package callers. New execution paths use resolvePinnedVersionAndBinary
// so the exact journal version validated against the run is available for the
// retained-source integrity callback without a second database read.
func (d *Dispatcher) resolvePinnedBinary(ctx context.Context, run journal.RunInfo, slug string) (string, error) {
	_, binary, err := d.resolvePinnedVersionAndBinary(ctx, run, slug)
	return binary, err
}

func (d *Dispatcher) resolvePinnedVersionAndBinary(ctx context.Context, run journal.RunInfo, slug string) (journal.WorkflowVersion, string, error) {
	version, err := d.Journal.ValidateRunWorkflowArtifact(ctx, run)
	if err != nil {
		return journal.WorkflowVersion{}, "", err
	}
	if d.ArtifactPath == nil && d.ArtifactPathForTenant == nil {
		return journal.WorkflowVersion{}, "", errors.New("dispatcher: immutable artifact lookup is not configured")
	}
	var binary string
	if d.ArtifactPathForTenant != nil {
		tenant := strings.TrimSpace(run.TenantID)
		if tenant == "" {
			tenant, err = d.Journal.WorkflowTenant(ctx, run.WorkflowID)
			if err != nil {
				return journal.WorkflowVersion{}, "", fmt.Errorf("dispatcher: resolve workflow tenant: %w", err)
			}
		}
		binary, err = d.ArtifactPathForTenant(tenant, slug, run.WorkflowArtifactSHA256)
	} else {
		binary, err = d.ArtifactPath(slug, run.WorkflowArtifactSHA256)
	}
	if err != nil {
		// The journal validation above is the authority for the durable
		// workflow/version/digest identity. Failure to read or verify the
		// content-addressed bytes on this node is an availability/deployment
		// problem, not proof that the durable run is invalid. The caller keeps
		// the exact run and lease recoverable so another healthy worker (or the
		// same worker after restoration) can execute it.
		return journal.WorkflowVersion{}, "", fmt.Errorf("dispatcher: immutable artifact is unavailable: %w", err)
	}
	return version, binary, nil
}

// checkIntegrity keeps the callback at the last common point after immutable
// artifact resolution and before any supervisor/queue admission. An unset
// callback preserves the package's test-only/in-memory dispatcher behavior;
// every production constructor wires the retained-source proof.
func (d *Dispatcher) checkIntegrity(ctx context.Context, slug string, version journal.WorkflowVersion) error {
	if d.IntegrityCheck == nil {
		return nil
	}
	return d.IntegrityCheck(ctx, slug, version)
}

func (d *Dispatcher) checkQueueArtifact(ctx context.Context, slug string, version journal.WorkflowVersion) error {
	if d.QueueArtifactCheck == nil {
		return nil
	}
	if err := d.QueueArtifactCheck(ctx, slug, version); err != nil {
		return fmt.Errorf("dispatcher: worker artifact is unavailable for queue admission: %w", err)
	}
	return nil
}

func (d *Dispatcher) failArtifactFencedRun(ctx context.Context, run journal.RunInfo, slug, leaseOwner string, cause error) error {
	durableCtx := context.WithoutCancel(ctx)
	var (
		committedStatus string
		persistErr      error
	)
	if leaseOwner == "" {
		committedStatus, persistErr = d.Journal.FailRunArtifactFenceStatus(durableCtx, run.ID)
	} else {
		committedStatus, persistErr = d.Journal.FailLeasedRunArtifactFenceStatus(durableCtx, run.ID, leaseOwner)
	}
	if persistErr != nil {
		return errors.Join(fmt.Errorf("dispatcher: workflow artifact fence: %w", cause), persistErr)
	}
	d.Log.Error("dispatcher: run blocked by workflow artifact fence",
		"run_id", run.ID, "workflow_id", run.WorkflowID, "workflow_version", run.WorkflowVersion, "err", cause)
	d.publishTerminal(ctx, TerminalEvent{
		RunID: run.ID, WorkflowID: run.WorkflowID, WorkflowSlug: slug,
		Status: committedStatus, TriggerKind: run.TriggerKind, ErrorText: journal.WorkflowArtifactFenceRunLog,
	})
	return fmt.Errorf("dispatcher: workflow artifact fence: %w", cause)
}

const defaultDeadLetterHookTimeout = 2 * time.Minute

// publishTerminal performs essential lifecycle publication before optional AI
// postmortem work. OnTerminal deliberately survives execution-context
// cancellation: the business state is already committed, so notifications and
// workflow-complete chains must be emitted exactly once. OnDeadLetter instead
// inherits the admission cancellation and a hard deadline; the concrete hook
// performs network/DB work and must return when that context is done.
func (d *Dispatcher) publishTerminal(ctx context.Context, event TerminalEvent) {
	if ctx == nil {
		ctx = context.Background()
	}
	if d.OnTerminal != nil {
		d.OnTerminal(context.WithoutCancel(ctx), event)
	}
	if d.Counters != nil && event.Status != "" && event.Status != "suspended" {
		d.Counters.IncRunsTerminal(event.Status)
	}
	if event.Status != "failed_dlq" || d.OnDeadLetter == nil {
		return
	}
	if ctx.Err() != nil {
		// Shutdown/operator cancellation already won. Essential publication above
		// is durable; do not start new optional network/DB work with a dead
		// admission context.
		return
	}
	timeout := d.DeadLetterHookTimeout
	if timeout <= 0 {
		timeout = defaultDeadLetterHookTimeout
	}
	hookCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d.OnDeadLetter(hookCtx, event.RunID)
}

// InFlight returns the current count of dispatched supervisor
// goroutines. Used by the daemon's status logging during shutdown so
// the operator sees "draining N runs" instead of a blind wait.
func (d *Dispatcher) InFlight() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.count
}

// Drain waits for every admitted dispatch/supervisor to finish OR
// for the timeout to elapse. Returns nil on clean drain, non-nil
// when the timer wins; the caller treats timeout as "force shutdown
// imminent" and proceeds with parent ctx cancellation.
//
// Production deploys configure this via REACTOR_DRAIN_TIMEOUT (default 30s)
// in cmd/reactor/serve.go.
func (d *Dispatcher) Drain(timeout time.Duration) error {
	started := time.Now()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if d.InFlight() == 0 {
			return nil
		}
		if timeout > 0 && time.Since(started) >= timeout {
			return fmt.Errorf("dispatcher: drain timed out after %s with %d run(s) in flight", timeout, d.InFlight())
		}
		<-ticker.C
	}
}

// newRunID returns "run_" + 16 hex chars (8 bytes from crypto/rand).
func newRunID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("dispatcher: run id: %w", err)
	}
	return "run_" + hex.EncodeToString(b), nil
}

// SQLResolver is the production WorkflowResolver: reads the workflows
// table directly. Returns ErrNotFound when no row matches.
type SQLResolver struct {
	Journal *journal.Journal
}

// ErrNotFound is returned when no workflow matches the lookup.
var ErrNotFound = errors.New("dispatcher: workflow not found")

// ErrRateLimited is returned by Dispatch when the workflow has hit its
// per-minute rate limit. Callers (webhook senders) should back off + retry.
var ErrRateLimited = errors.New("dispatcher: workflow rate limit exceeded")

func isWorkflowRateLimited(err error) bool {
	var rateErr *journal.WorkflowRateLimitError
	return errors.As(err, &rateErr)
}

// ErrSyncTimeout is returned by DispatchSync when the run didn't reach a
// terminal status within the timeout (the run keeps executing in the
// background).
var ErrSyncTimeout = errors.New("dispatcher: synchronous run timed out")

// ErrWorkflowDisabled is returned by Dispatch for a manual run against a
// disabled workflow so the dashboard can show "this workflow is disabled"
// instead of creating a run. Automatic dispatch paths no-op instead.
var ErrWorkflowDisabled = errors.New("dispatcher: workflow is disabled")

// dispatchWorkflowDisabled preserves the historical trigger semantics: a
// manual request reports the kill-switch to its operator, while automatic
// sources quietly leave the event pending for their normal retry/reconcile
// behavior.
func dispatchWorkflowDisabled(t journal.Trigger) (string, error) {
	if t.Kind == journal.TriggerManual {
		return "", ErrWorkflowDisabled
	}
	return "", nil
}

// WorkflowBySlug returns the workflow id for a slug, or ErrNotFound.
func (r *SQLResolver) WorkflowBySlug(ctx context.Context, slug string) (string, error) {
	id, err := r.Journal.WorkflowIDBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			return "", ErrNotFound
		}
		return "", err
	}
	return id, nil
}

// WorkflowSlugByID is the inverse.
func (r *SQLResolver) WorkflowSlugByID(ctx context.Context, id string) (string, error) {
	slug, err := r.Journal.WorkflowSlugByID(ctx, id)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			return "", ErrNotFound
		}
		return "", err
	}
	return slug, nil
}
