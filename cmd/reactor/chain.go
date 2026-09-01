package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/bright-interaction/reactor/internal/dispatcher"
	"github.com/bright-interaction/reactor/internal/notifier"
	"github.com/bright-interaction/reactor/internal/runlogs"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// handleRunTerminal is the single terminal-handling path shared by the
// dispatcher's OnTerminal (first spawn) and the scheduler's OnTerminal
// (resumed runs). It closes the run's log buffer, fires notifications,
// and dispatches chained workflows. A "suspended" status is NOT terminal
// (a long sleep or signal-await), so it returns early: closing the log
// buffer or firing chains then would be wrong, and the eventual real
// terminal status re-enters here via the scheduler.
func handleRunTerminal(
	ctx context.Context,
	log *slog.Logger,
	notif *notifier.Notifier,
	j *journal.Journal,
	disp *dispatcher.Dispatcher,
	logBuffer *runlogs.Buffer,
	ev dispatcher.TerminalEvent,
) {
	if ev.Status == "suspended" {
		return
	}
	if logBuffer != nil {
		logBuffer.Close(ev.RunID)
	}
	// Dry run (test from the dashboard): the workflow executed, but the host
	// suppresses its own side effects -- no notifications, no downstream chain
	// fan-out. Logs were still flushed above so the test is fully debuggable.
	if ev.DryRun {
		log.Info("run terminal: dry run, suppressing notifications + chains", "run_id", ev.RunID, "status", ev.Status)
		return
	}
	if notif != nil && (ev.Status == "failed" || ev.Status == "failed_dlq" || ev.Status == "succeeded") {
		notif.Notify(ctx, notifier.Event{
			RunID:        ev.RunID,
			WorkflowID:   ev.WorkflowID,
			WorkflowSlug: ev.WorkflowSlug,
			Status:       ev.Status,
			TriggerKind:  ev.TriggerKind,
			ErrorText:    ev.ErrorText,
			StartedAt:    time.Now().UTC(), // best-effort; journal has the real timestamps
			FinishedAt:   time.Now().UTC(),
		})
	}
	// A cancelled run must not trigger downstream chains. Cancellation is
	// an explicit "stop everything" by the operator; firing the chain
	// (even if a trigger's on_statuses CSV were set to include "cancelled")
	// would be the opposite of what cancel means. Logs were still flushed
	// above so the cancelled run is debuggable.
	if ev.Status == "cancelled" {
		return
	}
	// Chain triggers: dispatch downstream workflows whose source matches
	// this run + whose on_statuses CSV includes the terminal status.
	// Failures log but do not block the terminal path.
	fireChainedWorkflows(ctx, log, j, disp, ev)
}

// chainDispatcher is the surface fireChainedWorkflows needs from the
// dispatcher; defined here so the helper can be tested with a stub.
type chainDispatcher interface {
	DispatchTerminalChain(ctx context.Context, t journal.Trigger, payload []byte) error
}

// chainLookup is the subset of *journal.Journal fireChainedWorkflows
// needs. Defined as an interface so tests can stub.
type chainLookup interface {
	ChainTriggersForSource(ctx context.Context, sourceWorkflowID, status string) ([]journal.Trigger, error)
	GetRun(ctx context.Context, runID string) (journal.RunInfo, error)
}

// maxChainDepth caps how many chain hops a single originating run can
// trigger. Create-time cycle detection already rejects A->B->A loops, but
// this is the runtime backstop against a long chain (or a cycle that
// somehow slipped in across a concurrent create) running unbounded. 32 is
// far beyond any legitimate fan-out depth.
const maxChainDepth = 32

// fireChainedWorkflows looks up active workflow_complete triggers
// whose source_workflow_id matches the just-terminated run and whose
// on_statuses CSV includes ev.Status, then dispatches each downstream
// workflow with a synthesised payload carrying the source's identity
// and terminal outcome.
//
// Payload shape:
//
//	{
//	  "source_run_id":        "run_abc",
//	  "source_workflow_id":   "wf_a",
//	  "source_workflow_slug": "demo",
//	  "source_status":        "succeeded",
//	  "source_trigger_kind":  "webhook",
//	  "source_error_text":    "..."  // empty on success
//	}
//
// Wired into the dispatcher's OnTerminal callback in serve.go so chain
// firing happens inside the inFlight goroutine; graceful drain waits.
// Errors log but do not block other downstream peers.
func fireChainedWorkflows(ctx context.Context, log *slog.Logger, j chainLookup, disp chainDispatcher, ev dispatcher.TerminalEvent) {
	if j == nil || disp == nil {
		return
	}
	triggers, err := j.ChainTriggersForSource(ctx, ev.WorkflowID, ev.Status)
	if err != nil {
		log.Warn("serve: chain trigger lookup failed",
			"err", err, "source_workflow_id", ev.WorkflowID, "status", ev.Status)
		return
	}
	if len(triggers) == 0 {
		return
	}

	// Runtime depth backstop: the source run carries a chain_depth in its
	// trigger payload when it was itself dispatched by a chain. Stop before
	// exceeding maxChainDepth so a cycle that slipped past create-time
	// detection (or a legitimately very long chain) can't dispatch forever.
	depth := chainDepthOf(ctx, j, ev.RunID)
	if depth >= maxChainDepth {
		log.Warn("serve: chain depth limit reached; not firing downstream workflows",
			"source_run_id", ev.RunID, "depth", depth, "max", maxChainDepth)
		return
	}

	payload, err := json.Marshal(map[string]any{
		"source_run_id":        ev.RunID,
		"source_workflow_id":   ev.WorkflowID,
		"source_workflow_slug": ev.WorkflowSlug,
		"source_status":        ev.Status,
		"source_trigger_kind":  ev.TriggerKind,
		"source_error_text":    ev.ErrorText,
		"chain_depth":          depth + 1,
	})
	if err != nil {
		log.Warn("serve: chain payload marshal failed", "err", err)
		return
	}
	for _, t := range triggers {
		t := t
		if err := disp.DispatchTerminalChain(ctx, t, payload); err != nil {
			log.Warn("serve: chain dispatch failed",
				"err", err,
				"source_run_id", ev.RunID,
				"downstream_workflow_id", t.WorkflowID,
				"trigger_id", t.ID)
			continue
		}
		log.Info("serve: chained workflow dispatched",
			"source_run_id", ev.RunID,
			"source_status", ev.Status,
			"downstream_workflow_id", t.WorkflowID,
			"trigger_id", t.ID)
	}
}

// chainDepthOf reads the chain_depth recorded in a run's trigger payload.
// Returns 0 when the run wasn't dispatched by a chain (no chain_depth
// field) or when the run can't be read; treating an unreadable run as
// depth 0 fails open for non-chained roots but the cap still bounds any
// real chain because each hop's payload carries an incremented value.
func chainDepthOf(ctx context.Context, j chainLookup, runID string) int {
	run, err := j.GetRun(ctx, runID)
	if err != nil || len(run.TriggerMeta) == 0 {
		return 0
	}
	var meta struct {
		ChainDepth int `json:"chain_depth"`
	}
	if err := json.Unmarshal(run.TriggerMeta, &meta); err != nil {
		return 0
	}
	if meta.ChainDepth < 0 {
		return 0
	}
	return meta.ChainDepth
}
