package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/bright-interaction/reactor/internal/commandrunner"
	"github.com/bright-interaction/reactor/internal/dispatcher"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

const commandChainWriteTimeout = 10 * time.Second
const commandChainWriteAttempts = 5

// commandChainDispatcher is the daemon-side terminal adapter for command
// automation chains. It deliberately has no workflow payload or command
// text input: the source run and the exact trigger row are the only event
// facts that cross into command admission.
type commandChainDispatcher struct {
	Journal  *journal.Journal
	Runner   commandChainRunner
	Queue    commandChainQueue
	TenantID string
	Log      *slog.Logger
}

// ErrCommandChainRuntimeUnavailable means that a durable active chain exists
// but this daemon generation does not have the command runner handoff needed
// to admit it. The terminal-effect caller must keep the receipt retryable in
// this case; acknowledging the workflow terminal event would otherwise lose
// a one-shot chain when Reactor is restarted with command execution disabled.
var ErrCommandChainRuntimeUnavailable = errors.New("command chain runtime is unavailable")

// Keep the terminal adapter's two mutable handoff dependencies narrow. The
// production values are the concrete command runner and queue, while these
// interfaces let the durable trigger/queue-full policy be tested without
// starting a sandbox worker.
type commandChainRunner interface {
	AdmitChain(context.Context, commandrunner.Request, journal.CommandAutomationChainTrigger) (commandrunner.Result, error)
}

type commandChainQueue interface {
	Enqueue(context.Context, commandrunner.Request) error
}

// FireCommandChains admits and queues every active command chain matching a
// terminal workflow event. The deterministic trigger event id makes a
// terminal-effect retry idempotent, while the runner and journal each repeat
// the exact-version and active-trigger fences immediately before insertion.
func (d *commandChainDispatcher) FireCommandChains(ctx context.Context, ev dispatcher.TerminalEvent) error {
	if d == nil || d.Journal == nil {
		return nil
	}
	if ev.Status != journal.StatusSucceeded && ev.Status != journal.StatusFailed && ev.Status != "failed_dlq" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	source, err := d.Journal.GetRun(ctx, ev.RunID)
	if err != nil {
		return fmt.Errorf("read command-chain source run: %w", err)
	}
	if strings.TrimSpace(source.WorkflowID) == "" || source.WorkflowID != ev.WorkflowID {
		return fmt.Errorf("command-chain source workflow identity mismatch for run %s", ev.RunID)
	}
	if strings.TrimSpace(source.Status) != ev.Status {
		return fmt.Errorf("command-chain source status mismatch for run %s", ev.RunID)
	}
	tenantID := strings.TrimSpace(source.TenantID)
	if tenantID == "" {
		return fmt.Errorf("command-chain source tenant identity missing for run %s", ev.RunID)
	}
	if configured := strings.TrimSpace(d.TenantID); configured != "" && configured != tenantID {
		return fmt.Errorf("command-chain source tenant is outside the configured runner tenant")
	}
	triggers, err := d.Journal.ListCommandAutomationChainTriggersForSource(ctx, tenantID, ev.WorkflowID, ev.Status)
	if err != nil {
		return fmt.Errorf("list command-chain triggers: %w", err)
	}
	if len(triggers) == 0 {
		return nil
	}
	// Keep the terminal effect pending when a previous deployment left an
	// active command chain behind but this daemon was started without the
	// command runner. Returning an explicit error lets the durable effect loop
	// retry after the runner is restored instead of silently acknowledging and
	// losing the one-shot source event.
	if d.Runner == nil || d.Queue == nil {
		return ErrCommandChainRuntimeUnavailable
	}

	var dispatchErrs []error
	for _, trigger := range triggers {
		if trigger.TenantID != tenantID || trigger.SourceWorkflowID != ev.WorkflowID || trigger.State != journal.CommandAutomationChainActive {
			// The concrete journal already applies this fence. Keep the final
			// boundary defensive for imported/legacy rows and do not expose the
			// row to Runner admission.
			if d.Log != nil {
				d.Log.Warn("serve: skipping unowned command-chain trigger", "trigger_id", trigger.ID, "source_run_id", ev.RunID)
			}
			continue
		}
		eventID := journal.CommandAutomationChainEventID(trigger.ID, ev.RunID, ev.Status)
		admitted, admitErr := d.Runner.AdmitChain(ctx, commandrunner.Request{
			TenantID: tenantID, AutomationID: trigger.AutomationID, Version: trigger.AutomationVersion,
			TriggerID: trigger.ID, TriggerEventID: eventID,
		}, trigger)
		if admitErr != nil {
			if d.Log != nil {
				d.Log.Warn("serve: command-chain admission failed", "trigger_id", trigger.ID, "source_run_id", ev.RunID, "err", admitErr)
			}
			d.markError(ctx, tenantID, trigger.ID, "command chain admission failed")
			dispatchErrs = append(dispatchErrs, fmt.Errorf("trigger %s admission: %w", trigger.ID, admitErr))
			continue
		}

		// A deterministic retry may resolve to an existing running or terminal
		// row. Only queued rows need a fresh in-memory handoff; the durable row
		// remains the recovery source if the queue is full or the process stops.
		if admitted.Run.Created || admitted.Run.Status == journal.CommandRunQueued {
			err := d.Queue.Enqueue(ctx, commandrunner.Request{
				TenantID: tenantID, AutomationID: trigger.AutomationID, Version: trigger.AutomationVersion,
				RunID: admitted.Run.ID, Admission: admitted.Run.Admission,
				TriggerKind: journal.CommandRunTriggerChain, TriggerID: trigger.ID, TriggerEventID: eventID,
			})
			if err != nil && !errors.Is(err, commandrunner.ErrQueueFull) {
				if d.Log != nil {
					d.Log.Warn("serve: command-chain queue handoff failed", "trigger_id", trigger.ID, "run_id", admitted.Run.ID, "err", err)
				}
				d.markError(ctx, tenantID, trigger.ID, "command chain queue unavailable")
				dispatchErrs = append(dispatchErrs, fmt.Errorf("trigger %s queue: %w", trigger.ID, err))
				continue
			}
			if errors.Is(err, commandrunner.ErrQueueFull) && d.Log != nil {
				d.Log.Warn("serve: command-chain queue full; durable recovery will retry", "trigger_id", trigger.ID, "run_id", admitted.Run.ID)
			}
		}
		if err := d.markFired(ctx, tenantID, trigger.ID); err != nil {
			dispatchErrs = append(dispatchErrs, fmt.Errorf("trigger %s acknowledgement: %w", trigger.ID, err))
			continue
		}
		if d.Log != nil {
			d.Log.Info("serve: command automation chain queued", "trigger_id", trigger.ID, "source_run_id", ev.RunID, "run_id", admitted.Run.ID)
		}
	}
	return errors.Join(dispatchErrs...)
}

func (d *commandChainDispatcher) markFired(ctx context.Context, tenantID, triggerID string) error {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), commandChainWriteTimeout)
	defer cancel()
	return retryCommandChainWrite(writeCtx, func(attemptCtx context.Context) error {
		return d.Journal.MarkCommandAutomationChainTriggerFired(attemptCtx, tenantID, triggerID)
	})
}

func (d *commandChainDispatcher) markError(ctx context.Context, tenantID, triggerID, message string) {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), commandChainWriteTimeout)
	defer cancel()
	if err := retryCommandChainWrite(writeCtx, func(attemptCtx context.Context) error {
		return d.Journal.MarkCommandAutomationChainTriggerError(attemptCtx, tenantID, triggerID, message)
	}); err != nil && d.Log != nil {
		d.Log.Warn("serve: mark command-chain trigger error failed", "trigger_id", triggerID, "err", err)
	}
}

// retryCommandChainWrite closes the small SQLite writer-lock race between
// command-run admission and trigger receipt acknowledgement. Admission is
// durable and idempotent, so retrying only the known busy error cannot create
// a second execution; returning every other error keeps the terminal effect
// fail-closed and retryable.
func retryCommandChainWrite(ctx context.Context, write func(context.Context) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	delay := 10 * time.Millisecond
	var err error
	for attempt := 0; attempt < commandChainWriteAttempts; attempt++ {
		err = write(ctx)
		if err == nil || !commandChainSQLiteBusy(err) || attempt == commandChainWriteAttempts-1 {
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
		if delay < 200*time.Millisecond {
			delay *= 2
		}
	}
	return err
}

func commandChainSQLiteBusy(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database is locked") || strings.Contains(message, "sqlite_busy")
}
