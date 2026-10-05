package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/dispatcher"
	"github.com/bright-interaction/reactor/internal/notifier"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

type terminalEffectSender struct {
	fail  atomic.Bool
	calls atomic.Int32
}

func (s *terminalEffectSender) Kind() string { return journal.ChannelKindGenericWebhook }

func (s *terminalEffectSender) Send(context.Context, json.RawMessage, notifier.Event) error {
	s.calls.Add(1)
	if s.fail.Load() {
		return errors.New("provider unavailable")
	}
	return nil
}

func TestHandleRunTerminalReleasesReceiptWhenNotificationFails(t *testing.T) {
	t.Parallel()
	_, j := newSeededDB(t)
	ctx := context.Background()
	channelID, err := j.CreateNotificationChannel(ctx, "terminal-receipt", journal.ChannelKindGenericWebhook,
		json.RawMessage(`{"url":"https://example.invalid"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.AddNotificationRoute(ctx, "wf_t", channelID, "failed"); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, "run_t", journal.StatusFailed); err != nil {
		t.Fatal(err)
	}
	sender := &terminalEffectSender{}
	sender.fail.Store(true)
	notif := notifier.New(j, slog.New(slog.NewTextHandler(io.Discard, nil))).WithSender(sender)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	handleRunTerminal(ctx, log, notif, j, nil, nil, dispatcher.TerminalEvent{
		RunID: "run_t", WorkflowID: "wf_t", WorkflowSlug: "demo", Status: journal.StatusFailed,
	})

	claimed, err := j.ClaimTerminalEffects(ctx, 1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 {
		t.Fatalf("failed notification receipt was acknowledged: %+v", claimed)
	}
	if got := sender.calls.Load(); got != 1 {
		t.Fatalf("notification attempts = %d, want 1", got)
	}
	if err := j.ReleaseTerminalEffectForClaim(ctx, claimed[0], "asserting retryability"); err != nil {
		t.Fatal(err)
	}

	sender.fail.Store(false)
	handleRunTerminal(ctx, log, notif, j, nil, nil, dispatcher.TerminalEvent{
		RunID: "run_t", WorkflowID: "wf_t", WorkflowSlug: "demo", Status: journal.StatusFailed,
	})
	claimed, err = j.ClaimTerminalEffects(ctx, 1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 0 {
		t.Fatalf("successful retry left terminal receipt pending: %+v", claimed)
	}
	if got := sender.calls.Load(); got != 2 {
		t.Fatalf("notification attempts = %d, want 2 after retry", got)
	}
}
