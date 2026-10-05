package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bright-interaction/reactor/internal/dispatcher"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// stubChainLookup returns whatever triggers were seeded so the
// fireChainedWorkflows path can be tested without a real journal.
type stubChainLookup struct {
	triggers []journal.Trigger
	err      error
	runErr   error
	run      journal.RunInfo // returned by GetRun
}

func (s *stubChainLookup) ChainTriggersForSource(_ context.Context, _, _ string) ([]journal.Trigger, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.triggers, nil
}

func (s *stubChainLookup) GetRun(_ context.Context, _ string) (journal.RunInfo, error) {
	return s.run, s.runErr
}

// captureDispatcher records the (trigger, payload) of every Dispatch
// call so a test can assert the chain fired the right downstreams.
type captureDispatcher struct {
	calls   atomic.Int32
	fail    error
	lastT   journal.Trigger
	lastPay []byte
}

func (c *captureDispatcher) DispatchTerminalChain(_ context.Context, t journal.Trigger, payload []byte) error {
	c.calls.Add(1)
	c.lastT = t
	c.lastPay = append([]byte(nil), payload...)
	return c.fail
}

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestFireChainedWorkflowsDispatchesEveryTrigger(t *testing.T) {
	t.Parallel()
	disp := &captureDispatcher{}
	lookup := &stubChainLookup{
		triggers: []journal.Trigger{
			{ID: "t1", TenantID: "acme", WorkflowID: "wf_a"},
			{ID: "t2", TenantID: "acme", WorkflowID: "wf_b"},
		},
		run: journal.RunInfo{WorkflowID: "wf_src", TenantID: "acme"},
	}
	ev := dispatcher.TerminalEvent{
		RunID: "run_src", WorkflowID: "wf_src",
		WorkflowSlug: "src", Status: "succeeded",
		TriggerKind: "webhook",
	}
	fireChainedWorkflows(context.Background(), discardLog(), lookup, disp, ev)
	if got := disp.calls.Load(); got != 2 {
		t.Fatalf("dispatch calls = %d, want 2", got)
	}
	// Payload carries source identity + the incremented chain depth.
	var payload struct {
		SourceRunID        string `json:"source_run_id"`
		SourceWorkflowSlug string `json:"source_workflow_slug"`
		SourceStatus       string `json:"source_status"`
		ChainDepth         int    `json:"chain_depth"`
	}
	if err := json.Unmarshal(disp.lastPay, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.SourceRunID != "run_src" || payload.SourceWorkflowSlug != "src" || payload.SourceStatus != "succeeded" {
		t.Fatalf("payload = %+v", payload)
	}
	// Source run had no chain_depth (root), so downstream gets depth 1.
	if payload.ChainDepth != 1 {
		t.Fatalf("chain_depth = %d, want 1", payload.ChainDepth)
	}
}

func TestFireChainedWorkflowsContinuesPastFailures(t *testing.T) {
	t.Parallel()
	disp := &captureDispatcher{fail: errors.New("downstream wedged")}
	lookup := &stubChainLookup{
		triggers: []journal.Trigger{
			{ID: "t1", TenantID: "acme", WorkflowID: "wf_a"},
			{ID: "t2", TenantID: "acme", WorkflowID: "wf_b"},
		},
		run: journal.RunInfo{WorkflowID: "wf_src", TenantID: "acme"},
	}
	// Both downstreams should be ATTEMPTED even when the first fails, and the
	// aggregate error must keep the terminal receipt retryable.
	err := fireChainedWorkflows(context.Background(), discardLog(), lookup, disp,
		dispatcher.TerminalEvent{RunID: "run_src", WorkflowID: "wf_src", Status: "succeeded"})
	if got := disp.calls.Load(); got != 2 {
		t.Fatalf("calls = %d, want 2 (both attempted)", got)
	}
	if err == nil || !strings.Contains(err.Error(), "downstream wedged") {
		t.Fatalf("chain error = %v, want downstream failure", err)
	}
}

func TestFireChainedWorkflowsNoopsOnEmpty(t *testing.T) {
	t.Parallel()
	disp := &captureDispatcher{}
	lookup := &stubChainLookup{}
	fireChainedWorkflows(context.Background(), discardLog(), lookup, disp,
		dispatcher.TerminalEvent{Status: "succeeded"})
	if got := disp.calls.Load(); got != 0 {
		t.Fatalf("calls = %d, want 0", got)
	}
}

func TestFireChainedWorkflowsNilGuards(t *testing.T) {
	t.Parallel()
	// nil journal + nil dispatcher must not panic.
	fireChainedWorkflows(context.Background(), discardLog(), nil, nil,
		dispatcher.TerminalEvent{Status: "succeeded"})
}

func TestFireChainedWorkflowsErrorTextPropagates(t *testing.T) {
	t.Parallel()
	disp := &captureDispatcher{}
	lookup := &stubChainLookup{
		triggers: []journal.Trigger{{ID: "t1", TenantID: "acme", WorkflowID: "wf_a"}},
		run:      journal.RunInfo{WorkflowID: "wf_src", TenantID: "acme"},
	}
	ev := dispatcher.TerminalEvent{
		RunID: "run_src", WorkflowID: "wf_src",
		Status: "failed_dlq", ErrorText: "step 'charge' returned 500",
	}
	fireChainedWorkflows(context.Background(), discardLog(), lookup, disp, ev)
	if !strings.Contains(string(disp.lastPay), `charge`) || !strings.Contains(string(disp.lastPay), `failed_dlq`) {
		t.Fatalf("error_text not in payload: %s", disp.lastPay)
	}
}

func TestFireChainedWorkflowsBoundsLargeErrorText(t *testing.T) {
	t.Parallel()
	disp := &captureDispatcher{}
	lookup := &stubChainLookup{
		triggers: []journal.Trigger{{ID: "t1", TenantID: "acme", WorkflowID: "wf_a"}},
		run:      journal.RunInfo{WorkflowID: "wf_src", TenantID: "acme"},
	}
	large := strings.Repeat("error-secret-", 8<<10)
	fireChainedWorkflows(context.Background(), discardLog(), lookup, disp, dispatcher.TerminalEvent{
		RunID: "run_src", WorkflowID: "wf_src", Status: "failed_dlq", ErrorText: large,
	})
	var payload struct {
		ErrorText        string `json:"source_error_text"`
		Truncated        bool   `json:"source_error_text_truncated"`
		SourceErrorBytes int    `json:"source_error_text_bytes"`
	}
	if err := json.Unmarshal(disp.lastPay, &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Truncated || payload.SourceErrorBytes != len(large) || len(payload.ErrorText) > maxChainErrorBytes {
		t.Fatalf("bounded chain error = truncated=%v bytes=%d len=%d", payload.Truncated, payload.SourceErrorBytes, len(payload.ErrorText))
	}
}

func TestFireChainedWorkflowsSkipsCrossTenantTriggerRows(t *testing.T) {
	t.Parallel()
	lookup := &stubChainLookup{
		triggers: []journal.Trigger{
			{ID: "t_same", TenantID: "acme", WorkflowID: "wf_same"},
			{ID: "t_foreign", TenantID: "globex", WorkflowID: "wf_foreign"},
		},
		run: journal.RunInfo{WorkflowID: "wf_src", TenantID: "acme"},
	}
	disp := &captureDispatcher{}
	err := fireChainedWorkflows(context.Background(), discardLog(), lookup, disp, dispatcher.TerminalEvent{
		RunID: "run_src", WorkflowID: "wf_src", Status: "succeeded",
	})
	if err != nil {
		t.Fatalf("cross-tenant trigger should be skipped without poisoning the terminal receipt: %v", err)
	}
	if got := disp.calls.Load(); got != 1 {
		t.Fatalf("dispatch calls = %d, want only same-tenant trigger", got)
	}
	if disp.lastT.ID != "t_same" {
		t.Fatalf("dispatched trigger = %q, want t_same", disp.lastT.ID)
	}
}

func TestFireChainedWorkflowsRejectsMismatchedSourceRun(t *testing.T) {
	t.Parallel()
	lookup := &stubChainLookup{
		triggers: []journal.Trigger{{ID: "t1", TenantID: "acme", WorkflowID: "wf_down"}},
		run:      journal.RunInfo{WorkflowID: "wf_other", TenantID: "acme"},
	}
	disp := &captureDispatcher{}
	err := fireChainedWorkflows(context.Background(), discardLog(), lookup, disp, dispatcher.TerminalEvent{
		RunID: "run_src", WorkflowID: "wf_src", Status: "succeeded",
	})
	if err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("mismatched source run error = %v, want identity mismatch", err)
	}
	if got := disp.calls.Load(); got != 0 {
		t.Fatalf("dispatch calls = %d, want 0 for mismatched source run", got)
	}
}

func TestFireChainedWorkflowsFailsClosedWhenChainDepthCannotBeRead(t *testing.T) {
	t.Parallel()
	lookup := &stubChainLookup{
		triggers: []journal.Trigger{{ID: "t1", TenantID: "acme", WorkflowID: "wf_down"}},
		run:      journal.RunInfo{WorkflowID: "wf_src", TenantID: "acme", TriggerKind: string(journal.TriggerWorkflowComplete), TriggerMeta: json.RawMessage(`{"not_chain_depth":true}`)},
	}
	disp := &captureDispatcher{}
	fireChainedWorkflows(context.Background(), discardLog(), lookup, disp, dispatcher.TerminalEvent{
		RunID: "run_chain", WorkflowID: "wf_src", Status: "succeeded",
	})
	if got := disp.calls.Load(); got != 0 {
		t.Fatalf("chain dispatches = %d, want 0 when depth is unverifiable", got)
	}

	lookup.runErr = errors.New("journal unavailable")
	fireChainedWorkflows(context.Background(), discardLog(), lookup, disp, dispatcher.TerminalEvent{
		RunID: "run_chain", WorkflowID: "wf_src", Status: "succeeded",
	})
	if got := disp.calls.Load(); got != 0 {
		t.Fatalf("chain dispatches = %d after lookup failure, want 0", got)
	}
}
