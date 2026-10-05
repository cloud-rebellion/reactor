package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/cancelreg"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// Scheduler walks the schedules table and re-spawns suspended runs whose
// wake time has elapsed. One Scheduler per Reactor process; it owns no
// state beyond its config and the journal handle.
//
// Tick semantics:
//
//  1. Query FindDueSchedules(now, batch).
//  2. For each row: mark fired (so the next tick skips it), spawn a new
//     Supervisor with the same RunID, and let it Run() to completion or
//     re-suspend.
//  3. The new supervisor will replay journal entries for prior steps;
//     when the workflow's Sleep frame arrives, the host sees wait <= 0
//     and immediately acks.
//
// In v0 the scheduler runs each due row sequentially. A worker pool +
// per-run lease handover lands when external workers come online (week 7+).
type Scheduler struct {
	Journal *journal.Journal
	Vault   VaultReader
	Log     *slog.Logger

	// BinaryPath is retained for compatibility/status wiring. Resumed runs must
	// execute ArtifactPath using the digest pinned on their original run.
	BinaryPath func(workflowSlug string) (string, error)

	// ArtifactPath resolves the immutable executable pinned on the run. Resume
	// paths must never fall through to BinaryPath's mutable current pointer.
	ArtifactPath func(workflowSlug, artifactSHA256 string) (string, error)
	// ArtifactPathForTenant is the tenant-aware immutable artifact boundary.
	// Production wiring supplies it so a resumed same-slug run cannot execute
	// another tenant's bytes; ArtifactPath remains for legacy/in-memory tests.
	ArtifactPathForTenant func(tenant, workflowSlug, artifactSHA256 string) (string, error)

	// IntegrityCheck revalidates the retained source, manifest, and visual DAG
	// immediately before a suspended run is resumed. The dispatcher performs
	// the same check for new and queued runs; keeping it here closes the direct
	// scheduler wake-up path.
	IntegrityCheck func(ctx context.Context, workflowSlug string, version journal.WorkflowVersion) error
	// QueueArtifactCheck verifies the worker-visible artifact tree before a
	// distributed wake-up is re-enqueued. Missing or corrupt copies defer the
	// exact schedule; they do not invalidate the run's durable identity.
	QueueArtifactCheck func(ctx context.Context, workflowSlug string, version journal.WorkflowVersion) error

	// Now overrides the clock for tests. Defaults to time.Now.
	Now func() time.Time

	// Tick interval for the polling loop. Defaults to 5 seconds; tests
	// can drop to milliseconds for fast iteration.
	TickInterval time.Duration

	// MaxConsecutiveTickErrors bounds how long a scheduler may continue
	// advertising a healthy daemon while its durable schedule query is
	// failing. A transient database error is tolerated so one blip does not
	// restart the service, but a persistent failure returns from Run and lets
	// the daemon withdraw readiness and restart under its service manager.
	// Zero uses the production default.
	MaxConsecutiveTickErrors int

	// Batch caps schedules processed per tick. Defaults to 50.
	Batch int

	// SupervisorTemplate is copied as the base config for spawned
	// Supervisors. RunID, BinaryPath, WorkflowSlug, Mode are set per row.
	SupervisorTemplate Supervisor

	// OnTerminal fires after a resumed run reaches a real terminal status
	// (anything but "suspended"). The daemon wires this to the same
	// notifier + chain-firing logic the dispatcher's OnTerminal runs, so
	// a workflow that slept or awaited a signal still sends its failure /
	// success alerts and fires downstream chains when it finally finishes.
	// Without it, every long-sleep/signal run terminated silently. Nil
	// disables the hook (tests that only assert run status).
	OnTerminal func(ctx context.Context, ev TerminalInfo)

	// Cancels registers each resumed run's cancel func so an operator can
	// stop a run that woke from a sleep/signal and is executing again.
	// Optional; nil leaves resumed runs uninterruptible mid-step.
	Cancels *cancelreg.Registry

	// Enqueue switches resume from in-process to re-enqueue (distributed
	// mode): a due schedule flips its run back to "queued" for a worker to
	// claim + resume, instead of the scheduler running the supervisor
	// itself. Default false keeps single-node resume in-process.
	Enqueue bool

	once    sync.Once
	stop    chan struct{}
	mu      sync.Mutex
	count   int
	stopped bool
}

const defaultMaxConsecutiveTickErrors = 3

// TerminalInfo is the payload OnTerminal receives when a resumed run
// finishes. Mirrors dispatcher.TerminalEvent's fields but is declared
// here to avoid an import cycle (dispatcher imports supervisor).
type TerminalInfo struct {
	RunID        string
	WorkflowID   string
	WorkflowSlug string
	Status       string
	TriggerKind  string
	ErrorText    string
	DryRun       bool
}

// Run blocks, ticking the scheduler at TickInterval until ctx is cancelled
// or Stop is called. Short-lived tick failures are retried, but persistent
// failures return so the daemon can withdraw readiness instead of silently
// serving a live HTTP endpoint with no schedule processing. Safe for one Run
// per Scheduler.
func (s *Scheduler) Run(ctx context.Context) error {
	s.applyDefaults()
	t := time.NewTicker(s.TickInterval)
	defer t.Stop()
	maxTickErrors := s.MaxConsecutiveTickErrors
	if maxTickErrors <= 0 {
		maxTickErrors = defaultMaxConsecutiveTickErrors
	}
	consecutiveTickErrors := 0
	runTick := func() error {
		if err := s.Tick(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			consecutiveTickErrors++
			s.Log.Error("scheduler tick failed", "err", err,
				"consecutive_failures", consecutiveTickErrors,
				"failure_limit", maxTickErrors)
			if consecutiveTickErrors >= maxTickErrors {
				return fmt.Errorf("scheduler: %d consecutive tick failures: %w", consecutiveTickErrors, err)
			}
			return nil
		}
		consecutiveTickErrors = 0
		return nil
	}

	// Tick once immediately so a fresh process picks up any past-due
	// schedules without waiting for the first interval.
	if err := runTick(); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.stop:
			return nil
		case <-t.C:
			if err := runTick(); err != nil {
				return err
			}
		}
	}
}

// Stop signals Run to return. Idempotent.
func (s *Scheduler) Stop() {
	s.once.Do(func() {
		s.mu.Lock()
		s.stopped = true
		if s.stop == nil {
			s.stop = make(chan struct{})
		}
		close(s.stop)
		s.mu.Unlock()
	})
}

// Tick runs one pass: find due schedules and dispatch each. Exposed so tests
// can drive the scheduler one step at a time without spinning the ticker.
func (s *Scheduler) Tick(ctx context.Context) error {
	s.applyDefaults()
	due, err := s.Journal.FindDueSchedules(ctx, s.Now(), s.Batch)
	if err != nil {
		return err
	}
	for _, sched := range due {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.dispatch(ctx, sched); err != nil {
			s.Log.Error("scheduler dispatch failed",
				"schedule_id", sched.ID, "run_id", sched.RunID, "err", err)
		}
	}
	return nil
}

// dispatch handles one due schedule. Sleep + signal kinds resume the same
// way: mark fired, restore run status, re-spawn a Supervisor with the same
// RunID. The new subprocess replays from the journal cache up to the
// suspending frame, where the supervisor (signal: payload or expired
// already in the schedules row; sleep: wake_at past) immediately acks
// and lets the workflow proceed.
func (s *Scheduler) dispatch(ctx context.Context, sched journal.Schedule) error {
	if err := s.beginDispatch(ctx); err != nil {
		return err
	}
	defer func() {
		s.mu.Lock()
		s.count--
		s.mu.Unlock()
	}()

	// The schedules row only carries run_id, so resolve the run to find
	// its workflow (for the binary lookup + secret ACL) and its original
	// trigger input (so the resumed process decodes the same Input the
	// first spawn saw). Both were dropped by the old code, which called
	// BinaryPath("") with an empty slug and never restored Input.
	run, err := s.Journal.GetRun(ctx, sched.RunID)
	if err != nil {
		return fmt.Errorf("scheduler: get run %s: %w", sched.RunID, err)
	}
	slug, slugErr := s.Journal.WorkflowSlugByID(ctx, run.WorkflowID)
	if slugErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Lookup failures are not proof that the pinned identity is invalid. Keep
		// the schedule pending for the next tick (or startup) rather than turning
		// a transient database error into a durable business failure.
		return fmt.Errorf("scheduler: resolve workflow slug: %w", slugErr)
	}
	version, err := s.Journal.ValidateRunWorkflowArtifact(ctx, run)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var fence *journal.WorkflowArtifactFenceError
		if errors.As(err, &fence) {
			return s.failArtifactFencedSchedule(ctx, sched, run, slug, false, err)
		}
		// Only the typed validator result proves a permanent version/digest
		// mismatch. Operational query errors retain the unfired schedule.
		return fmt.Errorf("scheduler: validate workflow artifact: %w", err)
	}
	if s.ArtifactPath == nil && s.ArtifactPathForTenant == nil {
		return s.failArtifactFencedSchedule(ctx, sched, run, slug, true,
			fmt.Errorf("%w: immutable artifact lookup is not configured", journal.ErrWorkflowArtifactFence))
	}
	var binary string
	if s.ArtifactPathForTenant != nil {
		tenant := strings.TrimSpace(run.TenantID)
		if tenant == "" {
			tenant, err = s.Journal.WorkflowTenant(ctx, run.WorkflowID)
			if err != nil {
				return s.failArtifactFencedSchedule(ctx, sched, run, slug, true,
					fmt.Errorf("%w: resolve workflow tenant: %v", journal.ErrWorkflowArtifactFence, err))
			}
		}
		binary, err = s.ArtifactPathForTenant(tenant, slug, run.WorkflowArtifactSHA256)
	} else {
		binary, err = s.ArtifactPath(slug, run.WorkflowArtifactSHA256)
	}
	if err != nil {
		return s.failArtifactFencedSchedule(ctx, sched, run, slug, true,
			fmt.Errorf("%w: immutable artifact failed verification", journal.ErrWorkflowArtifactFence))
	}
	if s.IntegrityCheck != nil {
		if err := s.IntegrityCheck(ctx, slug, version); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var fence *journal.WorkflowArtifactFenceError
			if errors.As(err, &fence) {
				return s.failArtifactFencedSchedule(ctx, sched, run, slug, false, err)
			}
			// Missing or temporarily unavailable retained source must leave the
			// exact continuation pending for a later repair/retry. A source proof
			// mismatch is returned as the typed fence above and is terminalized.
			return s.failArtifactFencedSchedule(ctx, sched, run, slug, true,
				fmt.Errorf("workflow source proof unavailable: %w", err))
		}
	}

	// Distributed mode: don't resume in-process. Claim the schedule (CAS)
	// and re-enqueue the run so a worker picks it up. The worker's
	// supervisor replays from the journal and the now-fired schedule row
	// (FindLatestSleepSchedule still finds it; only FindDueSchedules
	// filters fired) acks the past-due sleep/signal and resumes.
	if s.Enqueue {
		if s.QueueArtifactCheck != nil {
			if err := s.QueueArtifactCheck(ctx, slug, version); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return s.failArtifactFencedSchedule(ctx, sched, run, slug, true,
					fmt.Errorf("worker artifact unavailable for queued resume: %w", err))
			}
		}
		claimed, err := s.Journal.ClaimScheduleResume(ctx, sched.ID, true)
		if err != nil {
			return err
		}
		if !claimed {
			return nil
		}
		s.Log.Info("scheduler: re-enqueued resumed run for a worker",
			"run_id", sched.RunID, "step", sched.StepName, "kind", sched.Kind)
		return nil
	}

	// Claim the schedule atomically AFTER the binary resolves, so a row we
	// can't service yet isn't consumed. ClaimSchedule is a compare-and-set:
	// claimed=false means a peer daemon already took it, so skip silently.
	claimed, err := s.Journal.ClaimScheduleResume(ctx, sched.ID, false)
	if err != nil {
		return err
	}
	if !claimed {
		return nil
	}

	sup := s.SupervisorTemplate
	sup.BinaryPath = binary
	sup.WorkflowSlug = slug
	sup.RunID = sched.RunID
	sup.Input = run.ExecutionInput()
	sup.Journal = s.Journal
	sup.Vault = s.Vault
	if sup.Log == nil {
		sup.Log = s.Log
	}
	if sup.Now == nil {
		sup.Now = s.Now
	}
	if sup.Mode == "" {
		sup.Mode = "live"
	}

	// Run on a cancellable context decoupled from the tick, registered so
	// an operator can stop a resumed run mid-step (exec.CommandContext
	// kills the subprocess on cancel).
	runCtx, cancel := context.WithCancelCause(context.Background())
	defer cancel(context.Canceled)
	registration := s.Cancels.RegisterCause(sched.RunID, cancel)
	defer s.Cancels.DeregisterRegistration(sched.RunID, registration)

	status, runErr := sup.Run(runCtx)
	s.Log.Info("scheduler woke run",
		"run_id", sched.RunID, "step", sched.StepName, "kind", sched.Kind, "status", status)

	// Fire the terminal hook for resumed runs that actually finished. A
	// re-suspend (status "suspended") is not terminal, so notifications +
	// chains wait for the eventual real terminal status.
	if s.OnTerminal != nil && status != "" && status != "suspended" {
		errText := ""
		if runErr != nil {
			errText = runErr.Error()
		}
		s.OnTerminal(context.WithoutCancel(ctx), TerminalInfo{
			RunID:        sched.RunID,
			WorkflowID:   run.WorkflowID,
			WorkflowSlug: slug,
			Status:       status,
			TriggerKind:  run.TriggerKind,
			ErrorText:    errText,
			DryRun:       sup.Mode == "dry_run",
		})
	}
	return runErr
}

func (s *Scheduler) beginDispatch(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.count++
	return nil
}

func (s *Scheduler) failArtifactFencedSchedule(ctx context.Context, sched journal.Schedule, run journal.RunInfo, slug string, retryableArtifact bool, cause error) error {
	durableCtx := context.WithoutCancel(ctx)
	if retryableArtifact {
		// Every sleep, signal, or synthetic recovery row is the only durable
		// continuation for its suspended run. Once the persisted artifact identity
		// has validated, node-local lookup/config/hash/permission failures are
		// availability problems. Keep the exact row pending until the pinned bytes
		// are restored; consuming it into ordinary failed would strand the run.
		// Back off the next durable probe and append the operator marker only once
		// so a long artifact outage cannot grow run_logs every scheduler tick.
		retryDelay := time.Minute
		if s.TickInterval > retryDelay {
			retryDelay = s.TickInterval
		}
		if _, err := s.Journal.DeferScheduleArtifactAvailability(
			durableCtx, sched.ID, run.ID, s.Now().Add(retryDelay),
		); err != nil {
			return errors.Join(fmt.Errorf("scheduler: scheduled run waiting for pinned workflow artifact: %w", cause), err)
		}
		return fmt.Errorf("scheduler: scheduled run waiting for pinned workflow artifact: %w", cause)
	}
	claimed, err := s.Journal.ClaimScheduleAndFailArtifactFence(durableCtx, sched.ID, run.ID)
	if err != nil {
		return errors.Join(fmt.Errorf("scheduler: workflow artifact fence: %w", cause), err)
	}
	if !claimed {
		return nil
	}
	if s.Log != nil {
		s.Log.Error("scheduler: resumed run blocked by workflow artifact fence",
			"run_id", run.ID, "workflow_id", run.WorkflowID, "workflow_version", run.WorkflowVersion, "err", cause)
	}
	if s.OnTerminal != nil {
		s.OnTerminal(durableCtx, TerminalInfo{
			RunID: run.ID, WorkflowID: run.WorkflowID, WorkflowSlug: slug,
			Status: "failed", TriggerKind: run.TriggerKind, ErrorText: journal.WorkflowArtifactFenceRunLog,
		})
	}
	return fmt.Errorf("scheduler: workflow artifact fence: %w", cause)
}

// InFlight returns schedule dispatches currently resolving, claiming, or
// executing. Tracking the whole dispatch closes the shutdown race between a
// due-row claim and child registration.
func (s *Scheduler) InFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

// Drain waits for every active schedule dispatch, including a resumed
// workflow subprocess. A zero timeout waits indefinitely.
func (s *Scheduler) Drain(timeout time.Duration) error {
	started := time.Now()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if s.InFlight() == 0 {
			return nil
		}
		if timeout > 0 && time.Since(started) >= timeout {
			return fmt.Errorf("scheduler: drain timed out after %s with %d dispatch(es) in flight", timeout, s.InFlight())
		}
		<-ticker.C
	}
}

func (s *Scheduler) applyDefaults() {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.TickInterval == 0 {
		s.TickInterval = 5 * time.Second
	}
	if s.Batch == 0 {
		s.Batch = 50
	}
	if s.Cancels == nil {
		s.Cancels = cancelreg.New()
	}
	s.mu.Lock()
	if s.stop == nil {
		s.stop = make(chan struct{})
	}
	s.mu.Unlock()
}

// ErrNoBinary is returned by BinaryPath when no workflow binary is registered.
// Surfaces clearly in scheduler logs.
var ErrNoBinary = errors.New("scheduler: no workflow binary registered")
