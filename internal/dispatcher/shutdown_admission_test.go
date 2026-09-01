package dispatcher

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/cancelreg"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

type blockingShutdownResolver struct {
	entered chan struct{}
	release chan struct{}
}

func (r *blockingShutdownResolver) WorkflowBySlug(context.Context, string) (string, error) {
	return "", ErrNotFound
}

func (r *blockingShutdownResolver) WorkflowSlugByID(ctx context.Context, _ string) (string, error) {
	select {
	case <-r.entered:
	default:
		close(r.entered)
	}
	select {
	case <-r.release:
		return "", errors.New("released resolver probe")
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func TestDispatcherStopClosesPostZeroExternalAdmission(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j := newJournal(t)
	createExecutableWorkflow(t, j, "wf_shutdown", "shutdown")
	resolver := &blockingShutdownResolver{entered: make(chan struct{}), release: make(chan struct{})}
	d := &Dispatcher{
		Journal:  j,
		Resolver: resolver,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	trigger := journal.Trigger{WorkflowID: "wf_shutdown", Kind: journal.TriggerWebhook}
	if got := d.InFlight(); got != 0 {
		t.Fatalf("initial admission count = %d", got)
	}

	firstDone := make(chan error, 1)
	go func() { firstDone <- d.Dispatch(ctx, trigger, nil) }()
	select {
	case <-resolver.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("accepted dispatch never entered resolver")
	}
	d.Stop()
	if got := d.InFlight(); got != 1 {
		t.Fatalf("accepted pre-stop dispatch was not registered: %d", got)
	}
	if err := d.Drain(20 * time.Millisecond); err == nil {
		t.Fatal("drain returned while accepted pre-stop dispatch was resolving")
	}
	if err := d.Dispatch(ctx, trigger, nil); !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("post-stop external dispatch = %v, want ErrShuttingDown", err)
	}

	close(resolver.release)
	if err := <-firstDone; err == nil {
		t.Fatal("resolver probe unexpectedly dispatched")
	}
	if err := d.Drain(time.Second); err != nil {
		t.Fatalf("drain after accepted dispatch exit: %v", err)
	}
}

func TestDispatcherStopRequiresTrustedTerminalChainHandoff(t *testing.T) {
	t.Parallel()
	d := &Dispatcher{
		Journal:  newJournal(t),
		Resolver: &fakeResolver{idByslug: map[string]string{}},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	d.Stop()
	trigger := journal.Trigger{
		WorkflowID: "missing-downstream",
		Kind:       journal.TriggerWorkflowComplete,
	}
	if err := d.Dispatch(context.Background(), trigger, nil); !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("external workflow_complete bypassed shutdown gate: %v", err)
	}
	if err := d.DispatchTerminalChain(context.Background(), trigger, nil); !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("terminal chain without parent handoff bypassed stable zero: %v", err)
	}
	release := d.HoldTerminalAdmission()
	err := d.DispatchTerminalChain(context.Background(), trigger, nil)
	release()
	if errors.Is(err, ErrShuttingDown) {
		t.Fatalf("trusted terminal chain was rejected during parent handoff: %v", err)
	}
	if err == nil {
		t.Fatal("missing downstream fixture unexpectedly dispatched")
	}
	if got := d.InFlight(); got != 0 {
		t.Fatalf("failed terminal chain leaked admission count: %d", got)
	}
}

func TestDispatcherInfrastructureCancelPreventsPostTimeoutSpawn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j := newJournal(t)
	createExecutableWorkflow(t, j, "wf_slow_artifact", "slow-artifact")
	entered := make(chan struct{})
	releaseArtifact := make(chan struct{})
	d := &Dispatcher{
		Journal:  j,
		Resolver: &fakeResolver{idByslug: map[string]string{"slow-artifact": "wf_slow_artifact"}},
		ArtifactPath: func(string, string) (string, error) {
			close(entered)
			<-releaseArtifact // deliberately ignores context, like a wedged filesystem
			return "/nonexistent/late-child", nil
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	done := make(chan error, 1)
	go func() {
		done <- d.Dispatch(ctx, journal.Trigger{WorkflowID: "wf_slow_artifact", Kind: journal.TriggerWebhook}, nil)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatch never reached blocking artifact lookup")
	}
	d.Stop()
	if interrupted := d.CancelAdmissions(cancelreg.ErrInfrastructureShutdown); interrupted != 1 {
		t.Fatalf("interrupted admissions = %d, want 1", interrupted)
	}
	close(releaseArtifact)
	select {
	case err := <-done:
		if !errors.Is(err, ErrShuttingDown) {
			t.Fatalf("post-timeout artifact admission = %v, want ErrShuttingDown", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled artifact admission did not return")
	}
	if err := d.Drain(time.Second); err != nil {
		t.Fatal(err)
	}
	runs, err := j.ListRecentRuns(ctx, 10)
	if err != nil || len(runs) != 0 {
		t.Fatalf("post-timeout admission spawned/persisted run = %+v, %v", runs, err)
	}
}

func TestExecuteRunCancelledDuringLookupRetainsOwnedLease(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j := newJournal(t)
	createExecutableWorkflow(t, j, "wf_worker_lookup", "worker-lookup")
	if err := j.CreateQueuedRunPinned(ctx, "run_worker_lookup", "wf_worker_lookup", "webhook", json.RawMessage(`{}`), 1, testArtifactSHA256); err != nil {
		t.Fatal(err)
	}
	claims, err := j.ClaimQueuedRuns(ctx, "worker-lookup", 1, time.Minute)
	if err != nil || len(claims) != 1 {
		t.Fatalf("worker lookup claim = %+v, %v", claims, err)
	}
	resolver := &blockingShutdownResolver{entered: make(chan struct{}), release: make(chan struct{})}
	d := &Dispatcher{Journal: j, Resolver: resolver, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	done := make(chan error, 1)
	go func() { done <- d.ExecuteRun(ctx, "run_worker_lookup", claims[0].Owner) }()
	select {
	case <-resolver.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("worker never entered slug lookup")
	}
	d.Stop()
	d.CancelAdmissions(cancelreg.ErrInfrastructureShutdown)
	select {
	case err := <-done:
		if !errors.Is(err, cancelreg.ErrInfrastructureShutdown) {
			t.Fatalf("cancelled worker lookup = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled worker lookup did not return")
	}
	if run, err := j.GetRun(ctx, "run_worker_lookup"); err != nil || run.Status != "running" || !run.FinishedAt.IsZero() {
		t.Fatalf("cancelled lookup terminalized run = %+v, %v", run, err)
	}
	if err := j.ExtendLease(ctx, "run_worker_lookup", claims[0].Owner, time.Minute); err != nil {
		t.Fatalf("cancelled lookup released exact lease: %v", err)
	}
}

func TestTerminalPublicationPrecedesCancellableDeadLetterPostmortem(t *testing.T) {
	t.Parallel()
	d := &Dispatcher{
		Log:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		DeadLetterHookTimeout: time.Hour,
	}
	terminalPublished := make(chan struct{})
	postmortemEntered := make(chan struct{})
	postmortemCause := make(chan error, 3)
	done := make(chan struct{})
	terminalCalls := 0
	d.OnTerminal = func(_ context.Context, event TerminalEvent) {
		terminalCalls++
		if event.Status != "failed_dlq" {
			postmortemCause <- errors.New("terminal hook received wrong status")
		}
		close(terminalPublished)
	}
	d.OnDeadLetter = func(ctx context.Context, _ string) {
		select {
		case <-terminalPublished:
			// Essential lifecycle publication won the ordering race.
		default:
			postmortemCause <- errors.New("postmortem started before terminal publication")
		}
		close(postmortemEntered)
		<-ctx.Done()
		postmortemCause <- context.Cause(ctx)
	}

	lifetime, release, err := d.beginAdmission(false)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(done)
		defer release()
		d.publishTerminal(lifetime, TerminalEvent{RunID: "run_dlq_shutdown", Status: "failed_dlq"})
	}()

	select {
	case <-terminalPublished:
	case <-time.After(time.Second):
		t.Fatal("essential terminal publication did not run")
	}
	select {
	case <-postmortemEntered:
	case <-time.After(time.Second):
		t.Fatal("optional postmortem did not start")
	}
	d.Stop()
	if err := d.Drain(20 * time.Millisecond); err == nil {
		t.Fatal("drain returned while optional postmortem was still admitted")
	}
	if interrupted := d.CancelAdmissions(cancelreg.ErrInfrastructureShutdown); interrupted != 1 {
		t.Fatalf("cancelled postmortem admissions = %d, want 1", interrupted)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("optional postmortem ignored infrastructure cancellation")
	}
	if err := d.Drain(time.Second); err != nil {
		t.Fatalf("drain after postmortem cancellation: %v", err)
	}
	if terminalCalls != 1 {
		t.Fatalf("terminal hook calls = %d, want exactly 1", terminalCalls)
	}
	select {
	case cause := <-postmortemCause:
		if cause != nil && !errors.Is(cause, cancelreg.ErrInfrastructureShutdown) {
			t.Fatalf("postmortem observation = %v", cause)
		}
	default:
		t.Fatal("postmortem did not report cancellation")
	}
}
