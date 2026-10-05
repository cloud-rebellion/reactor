package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

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
	handleRunTerminalWithCommandChains(ctx, log, notif, j, disp, logBuffer, ev, nil)
}

// commandChainFire is the narrow terminal side-effect boundary for command
// automations. Keeping it separate from workflow-chain dispatch prevents a
// command plan from being smuggled into the legacy workflow trigger table or
// dispatcher path.
type commandChainFire interface {
	FireCommandChains(context.Context, dispatcher.TerminalEvent) error
}

// handleRunTerminalWithCommandChains is the shared terminal path used by the
// daemon. The wrapper above keeps small unit tests and older callers focused
// on workflow effects while production can opt into the dedicated command
// trigger runtime once it has been fully wired.
func handleRunTerminalWithCommandChains(
	ctx context.Context,
	log *slog.Logger,
	notif *notifier.Notifier,
	j *journal.Journal,
	disp *dispatcher.Dispatcher,
	logBuffer *runlogs.Buffer,
	ev dispatcher.TerminalEvent,
	commandChains commandChainFire,
) {
	if ctx == nil {
		ctx = context.Background()
	}
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
	// Direct dispatcher/scheduler callbacks do not come through the recovery
	// loop, so claim their durable receipt before running any external side
	// effects. Recovery passes the existing claim timestamp in the event. The
	// claim fence prevents a late handler from acknowledging a newer DLQ retry
	// that reuses the same run id.
	var effect journal.TerminalEffect
	if ev.Status == "succeeded" || ev.Status == "failed" || ev.Status == "failed_dlq" {
		if j == nil {
			log.Warn("serve: terminal effect journal unavailable", "run_id", ev.RunID, "status", ev.Status)
			return
		}
		if ev.TerminalEffectClaimedAt.IsZero() {
			claimed, err := j.ClaimTerminalEffect(context.WithoutCancel(ctx), ev.RunID, ev.Status, 2*time.Minute)
			if err != nil {
				log.Warn("serve: terminal effect claim lost before side effects", "run_id", ev.RunID, "status", ev.Status, "err", err)
				return
			}
			ev.TerminalEffectClaimedAt = claimed.ClaimedAt
			ev.TerminalEffectClaimToken = claimed.ClaimToken
		}
		effect = journal.TerminalEffect{RunID: ev.RunID, Status: ev.Status, ClaimedAt: ev.TerminalEffectClaimedAt, ClaimToken: ev.TerminalEffectClaimToken}
	}
	var sideEffectErr error
	// Command-chain admission is a one-shot terminal side effect when the
	// source workflow finishes. Run it before notifications and workflow-chain
	// fan-out so an unavailable command runner keeps the durable terminal
	// receipt retryable without duplicating those other effects on every retry.
	// Admission itself is idempotent per trigger/source/status, so chains that
	// succeeded before a later peer failed remain safe to retry.
	if commandChains != nil {
		if err := commandChains.FireCommandChains(ctx, ev); err != nil {
			sideEffectErr = errors.Join(sideEffectErr, fmt.Errorf("command chain delivery: %w", err))
		}
	}
	if sideEffectErr != nil {
		if !effect.ClaimedAt.IsZero() {
			ackCtx := context.WithoutCancel(ctx)
			if releaseErr := j.ReleaseTerminalEffectForClaim(ackCtx, effect, sideEffectErr.Error()); releaseErr != nil && !errors.Is(releaseErr, journal.ErrTerminalEffectClaimLost) {
				log.Warn("serve: release terminal effect after command-chain failure failed", "run_id", ev.RunID, "err", releaseErr)
			}
		}
		return
	}
	if notif != nil && (ev.Status == "failed" || ev.Status == "failed_dlq" || ev.Status == "succeeded") {
		if err := notif.NotifyClaimed(ctx, notifier.Event{
			RunID:        ev.RunID,
			WorkflowID:   ev.WorkflowID,
			WorkflowSlug: ev.WorkflowSlug,
			Status:       ev.Status,
			TriggerKind:  ev.TriggerKind,
			ErrorText:    ev.ErrorText,
			StartedAt:    time.Now().UTC(), // best-effort; journal has the real timestamps
			FinishedAt:   time.Now().UTC(),
		}, effect); err != nil {
			sideEffectErr = errors.Join(sideEffectErr, fmt.Errorf("notification delivery: %w", err))
			log.Warn("serve: terminal notification delivery failed; receipt will retry", "run_id", ev.RunID, "err", err)
		}
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
	// Every peer is attempted, but any failed handoff keeps the durable receipt
	// retryable. Downstream dispatch is idempotent per source/trigger payload,
	// so a later retry cannot duplicate peers that already accepted their run.
	if err := fireChainedWorkflows(ctx, log, j, disp, ev); err != nil {
		sideEffectErr = errors.Join(sideEffectErr, fmt.Errorf("chain delivery: %w", err))
	}
	if !effect.ClaimedAt.IsZero() {
		ackCtx := context.WithoutCancel(ctx)
		if sideEffectErr != nil {
			if releaseErr := j.ReleaseTerminalEffectForClaim(ackCtx, effect, sideEffectErr.Error()); releaseErr != nil && !errors.Is(releaseErr, journal.ErrTerminalEffectClaimLost) {
				log.Warn("serve: release terminal effect after side-effect failure failed", "run_id", ev.RunID, "err", releaseErr)
			}
			return
		}
		if err := j.MarkTerminalEffectDeliveredForClaim(ackCtx, effect); err != nil {
			// A lost claim means a newer retry generation owns the row; do not
			// release it. Other failures should be made eligible for recovery.
			if !errors.Is(err, journal.ErrTerminalEffectClaimLost) {
				if releaseErr := j.ReleaseTerminalEffectForClaim(ackCtx, effect, err.Error()); releaseErr != nil && !errors.Is(releaseErr, journal.ErrTerminalEffectClaimLost) {
					log.Warn("serve: release terminal effect after acknowledgement failure failed", "run_id", ev.RunID, "err", releaseErr)
				}
			}
			log.Warn("serve: acknowledge terminal side effects failed", "run_id", ev.RunID, "err", err)
		}
	}
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

// Chain payloads are sent back through the normal dispatcher admission path.
// Keep the copied source diagnostic well below its 1 MiB input ceiling even
// when a workflow emitted a very large error frame; the full diagnostic stays
// available in the source run's operator/MCP timeline.
const maxChainErrorBytes = 32 << 10

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
// Every downstream is attempted even when one fails. A non-nil return keeps
// the terminal-effect receipt retryable; DispatchTerminalChain is idempotent
// for the source/trigger payload, so successful peers are safe to revisit.
func fireChainedWorkflows(ctx context.Context, log *slog.Logger, j chainLookup, disp chainDispatcher, ev dispatcher.TerminalEvent) error {
	if j == nil || disp == nil {
		return nil
	}
	triggers, err := j.ChainTriggersForSource(ctx, ev.WorkflowID, ev.Status)
	if err != nil {
		log.Warn("serve: chain trigger lookup failed",
			"err", err, "source_workflow_id", ev.WorkflowID, "status", ev.Status)
		return fmt.Errorf("lookup chain triggers: %w", err)
	}
	if len(triggers) == 0 {
		return nil
	}

	// The journal query fences normal rows, but terminal delivery also accepts
	// an abstract chainLookup for recovery and tests. Re-read the authoritative
	// source run before dispatching so an imported/stale trigger row cannot be
	// used to bridge tenants (or a mismatched event can smuggle another run's
	// payload into this source's chain).
	sourceRun, err := j.GetRun(ctx, ev.RunID)
	if err != nil {
		log.Warn("serve: chain source identity unavailable; not firing downstream workflows",
			"source_run_id", ev.RunID, "err", err)
		return fmt.Errorf("read chain source identity: %w", err)
	}
	if strings.TrimSpace(sourceRun.WorkflowID) == "" || sourceRun.WorkflowID != ev.WorkflowID {
		log.Warn("serve: chain source workflow identity mismatch; not firing downstream workflows",
			"source_run_id", ev.RunID, "event_workflow_id", ev.WorkflowID,
			"run_workflow_id", sourceRun.WorkflowID)
		return fmt.Errorf("chain source workflow identity mismatch for run %s", ev.RunID)
	}
	sourceTenant := strings.TrimSpace(sourceRun.TenantID)
	if sourceTenant == "" {
		log.Warn("serve: chain source tenant identity unavailable; not firing downstream workflows",
			"source_run_id", ev.RunID)
		return fmt.Errorf("chain source tenant identity missing for run %s", ev.RunID)
	}

	// Runtime depth backstop: the source run carries a chain_depth in its
	// trigger payload when it was itself dispatched by a chain. Stop before
	// exceeding maxChainDepth so a cycle that slipped past create-time
	// detection (or a legitimately very long chain) can't dispatch forever.
	depth, err := chainDepthFromRun(sourceRun, ev.RunID)
	if err != nil {
		log.Warn("serve: chain depth unavailable; not firing downstream workflows",
			"source_run_id", ev.RunID, "err", err)
		return fmt.Errorf("read chain depth: %w", err)
	}
	if depth >= maxChainDepth {
		log.Warn("serve: chain depth limit reached; not firing downstream workflows",
			"source_run_id", ev.RunID, "depth", depth, "max", maxChainDepth)
		return nil
	}

	errorText, errorTruncated, errorBytes := boundChainErrorText(ev.ErrorText)
	payloadView := map[string]any{
		"source_run_id":        ev.RunID,
		"source_workflow_id":   ev.WorkflowID,
		"source_workflow_slug": ev.WorkflowSlug,
		"source_status":        ev.Status,
		"source_trigger_kind":  ev.TriggerKind,
		"source_error_text":    errorText,
		"chain_depth":          depth + 1,
	}
	if errorTruncated {
		payloadView["source_error_text_truncated"] = true
		payloadView["source_error_text_bytes"] = errorBytes
	}
	payload, err := json.Marshal(payloadView)
	if err != nil {
		log.Warn("serve: chain payload marshal failed", "err", err)
		return fmt.Errorf("marshal chain payload: %w", err)
	}
	var dispatchErrs []error
	for _, t := range triggers {
		t := t
		// ChainTriggersForSource applies the same fence in the concrete journal,
		// but keep this final dispatch boundary fail-closed for legacy/imported
		// implementations of chainLookup too. A missing marker is as unsafe as a
		// different tenant because the downstream owner cannot be proven.
		if tenant := strings.TrimSpace(t.TenantID); tenant == "" || tenant != sourceTenant {
			log.Warn("serve: skipping cross-tenant or unowned chain trigger",
				"source_run_id", ev.RunID,
				"source_tenant", sourceTenant,
				"trigger_id", t.ID,
				"trigger_tenant", t.TenantID,
				"downstream_workflow_id", t.WorkflowID)
			continue
		}
		if err := disp.DispatchTerminalChain(ctx, t, payload); err != nil {
			log.Warn("serve: chain dispatch failed",
				"err", err,
				"source_run_id", ev.RunID,
				"downstream_workflow_id", t.WorkflowID,
				"trigger_id", t.ID)
			dispatchErrs = append(dispatchErrs, fmt.Errorf("trigger %s: %w", t.ID, err))
			continue
		}
		log.Info("serve: chained workflow dispatched",
			"source_run_id", ev.RunID,
			"source_status", ev.Status,
			"downstream_workflow_id", t.WorkflowID,
			"trigger_id", t.ID)
	}
	if len(dispatchErrs) > 0 {
		return errors.Join(dispatchErrs...)
	}
	return nil
}

func boundChainErrorText(value string) (text string, truncated bool, sourceBytes int) {
	sourceBytes = len(value)
	if sourceBytes <= maxChainErrorBytes {
		return strings.ToValidUTF8(value, "�"), false, sourceBytes
	}
	prefix := value[:maxChainErrorBytes]
	for len(prefix) > 0 && !utf8.ValidString(prefix) {
		prefix = prefix[:len(prefix)-1]
	}
	return strings.ToValidUTF8(prefix, "�"), true, sourceBytes
}

// chainDepthOf reads the trusted chain_depth recorded for a chain run. Other
// trigger payloads are external input and cannot set the chain depth. If the
// source run or a chain depth cannot be read, downstream dispatch must stop:
// assuming depth zero would bypass the runtime loop backstop.
func chainDepthOf(ctx context.Context, j chainLookup, runID string) (int, error) {
	run, err := j.GetRun(ctx, runID)
	if err != nil {
		return 0, fmt.Errorf("read source run: %w", err)
	}
	return chainDepthFromRun(run, runID)
}

func chainDepthFromRun(run journal.RunInfo, runID string) (int, error) {
	if run.TriggerKind != string(journal.TriggerWorkflowComplete) {
		return 0, nil
	}
	var meta struct {
		ChainDepth *int `json:"chain_depth"`
	}
	if err := json.Unmarshal(run.TriggerMeta, &meta); err != nil {
		return 0, fmt.Errorf("decode chain depth: %w", err)
	}
	if meta.ChainDepth == nil || *meta.ChainDepth < 1 {
		return 0, fmt.Errorf("missing or invalid chain depth for run %s", runID)
	}
	return *meta.ChainDepth, nil
}
