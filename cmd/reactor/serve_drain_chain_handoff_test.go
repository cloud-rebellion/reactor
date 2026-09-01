package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/dispatcher"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/supervisor"
)

const drainHandoffArtifactSHA256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

func TestDrainServeExecutionsTracksSchedulerTerminalChainHandoff(t *testing.T) {
	_, j := newSeededDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	const (
		sourceWorkflowID     = "wf_drain_source"
		downstreamWorkflowID = "wf_drain_downstream"
		sourceRunID          = "run_drain_source"
	)
	if err := j.CreateWorkflowWithArtifact(ctx, sourceWorkflowID, "drain-source", "h", "0.1.0", drainHandoffArtifactSHA256, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowWithArtifact(ctx, downstreamWorkflowID, "drain-downstream", "h", "0.1.0", drainHandoffArtifactSHA256, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRunPinned(ctx, sourceRunID, sourceWorkflowID, "manual", json.RawMessage(`{}`), 1, drainHandoffArtifactSHA256); err != nil {
		t.Fatal(err)
	}
	if err := j.SetRunStatus(ctx, sourceRunID, "suspended"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.ScheduleSleepSeq(ctx, sourceRunID, "wait", 1, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	schedulerEntered := make(chan struct{})
	releaseScheduler := make(chan struct{})
	defer func() {
		select {
		case <-releaseScheduler:
		default:
			close(releaseScheduler)
		}
	}()
	var sourceSlug, sourceDigest string
	sched := &supervisor.Scheduler{
		Journal: j,
		Log:     log,
		Now:     time.Now,
		ArtifactPath: func(slug, digest string) (string, error) {
			sourceSlug = slug
			sourceDigest = digest
			close(schedulerEntered)
			<-releaseScheduler
			return "", errors.New("release scheduler source without spawning")
		},
		Batch: 1,
	}

	downstreamTerminal := make(chan dispatcher.TerminalEvent, 1)
	releaseDownstream := make(chan struct{})
	defer func() {
		select {
		case <-releaseDownstream:
		default:
			close(releaseDownstream)
		}
	}()
	var downstreamSlug, downstreamDigest string
	disp := &dispatcher.Dispatcher{
		Journal:  j,
		Resolver: &dispatcher.SQLResolver{Journal: j},
		ArtifactPath: func(slug, digest string) (string, error) {
			downstreamSlug = slug
			downstreamDigest = digest
			// Supervisor start failure is sufficient here: execute() still owns
			// the admission through durable terminal persistence and OnTerminal.
			return filepath.Join(t.TempDir(), "missing-downstream-workflow"), nil
		},
		Log: log,
		OnTerminal: func(_ context.Context, event dispatcher.TerminalEvent) {
			downstreamTerminal <- event
			<-releaseDownstream
		},
	}
	deps := &serveDeps{dispatcher: disp, scheduler: sched}

	schedulerDone := make(chan error, 1)
	go func() { schedulerDone <- sched.Tick(ctx) }()
	select {
	case <-schedulerEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler source never entered immutable artifact resolution")
	}
	if got := sched.InFlight(); got != 1 {
		t.Fatalf("scheduler source count = %d, want 1", got)
	}

	// Close both admission gates before sampling, matching runServeLoop.
	sched.Stop()
	disp.Stop()
	chainTrigger := journal.Trigger{
		ID:         "trg_drain_chain",
		WorkflowID: downstreamWorkflowID,
		Kind:       journal.TriggerWorkflowComplete,
	}
	if err := disp.DispatchTerminalChain(ctx, chainTrigger, json.RawMessage(`{"source_run_id":"late"}`)); !errors.Is(err, dispatcher.ErrShuttingDown) {
		t.Fatalf("terminal chain without source reservation = %v, want shutdown rejection", err)
	}

	drainStarted := make(chan struct{})
	drainDone := make(chan error, 1)
	go func() {
		close(drainStarted)
		drainDone <- drainServeExecutions(deps, 0)
	}()
	<-drainStarted
	runtime.Gosched()
	select {
	case err := <-drainDone:
		t.Fatalf("drain returned while scheduler source was held: %v", err)
	default:
	}

	// This is the synchronous scheduler-terminal handoff used by serve wiring:
	// reserve dispatcher drain ownership while the scheduler source is still
	// counted, then admit the trusted workflow-complete child before releasing
	// either count.
	releaseTerminalAdmission := disp.HoldTerminalAdmission()
	chainErr := disp.DispatchTerminalChain(ctx, chainTrigger, json.RawMessage(`{"source_run_id":"run_drain_source"}`))
	releaseTerminalAdmission()
	if chainErr != nil {
		t.Fatalf("trusted terminal chain admission: %v", chainErr)
	}
	if downstreamSlug != "drain-downstream" || downstreamDigest != drainHandoffArtifactSHA256 {
		t.Fatalf("downstream immutable artifact = %q/%q", downstreamSlug, downstreamDigest)
	}

	var terminal dispatcher.TerminalEvent
	select {
	case terminal = <-downstreamTerminal:
	case <-time.After(2 * time.Second):
		t.Fatal("downstream dispatcher lifetime never reached terminal hook")
	}
	if terminal.WorkflowID != downstreamWorkflowID || terminal.Status != "failed" {
		t.Fatalf("downstream terminal event = %+v", terminal)
	}

	close(releaseScheduler)
	select {
	case err := <-schedulerDone:
		if err != nil {
			t.Fatalf("release scheduler source: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler source did not release")
	}
	if sourceSlug != "drain-source" || sourceDigest != drainHandoffArtifactSHA256 {
		t.Fatalf("source immutable artifact = %q/%q", sourceSlug, sourceDigest)
	}
	if scheduled, dispatched := sched.InFlight(), disp.InFlight(); scheduled != 0 || dispatched != 1 {
		t.Fatalf("post-handoff counts = scheduler %d dispatcher %d; want 0/1", scheduled, dispatched)
	}
	// A synchronous bounded probe makes the assertion independent of whether
	// the original drain goroutine happens to be between ticker samples: the
	// joint drain itself must observe dispatcher=1 and refuse clean completion.
	probeErr := drainServeExecutions(deps, time.Nanosecond)
	if probeErr == nil || !strings.Contains(probeErr.Error(), "dispatcher=1") {
		t.Fatalf("downstream lifetime drain probe = %v, want dispatcher=1 timeout", probeErr)
	}
	runtime.Gosched()
	select {
	case err := <-drainDone:
		t.Fatalf("drain returned during downstream terminal lifetime: %v", err)
	default:
	}

	close(releaseDownstream)
	select {
	case err := <-drainDone:
		if err != nil {
			t.Fatalf("drain after downstream release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("drain did not return after downstream release")
	}
	if scheduled, dispatched := sched.InFlight(), disp.InFlight(); scheduled != 0 || dispatched != 0 {
		t.Fatalf("final counts = scheduler %d dispatcher %d; want 0/0", scheduled, dispatched)
	}
}
