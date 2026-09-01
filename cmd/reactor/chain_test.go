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
	run      journal.RunInfo // returned by GetRun; zero value => chain depth 0
}

func (s *stubChainLookup) ChainTriggersForSource(_ context.Context, _, _ string) ([]journal.Trigger, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.triggers, nil
}

func (s *stubChainLookup) GetRun(_ context.Context, _ string) (journal.RunInfo, error) {
	return s.run, nil
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
			{ID: "t1", WorkflowID: "wf_a"},
			{ID: "t2", WorkflowID: "wf_b"},
		},
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
			{ID: "t1", WorkflowID: "wf_a"},
			{ID: "t2", WorkflowID: "wf_b"},
		},
	}
	// Both downstreams should be ATTEMPTED even when the first fails.
	fireChainedWorkflows(context.Background(), discardLog(), lookup, disp,
		dispatcher.TerminalEvent{Status: "succeeded"})
	if got := disp.calls.Load(); got != 2 {
		t.Fatalf("calls = %d, want 2 (both attempted)", got)
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
		triggers: []journal.Trigger{{ID: "t1", WorkflowID: "wf_a"}},
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
