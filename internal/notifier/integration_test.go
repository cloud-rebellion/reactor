package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bright-interaction/reactor/internal/dispatcher"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// TestDispatcherTerminalEventReachesNotifier proves the daemon's
// OnTerminal closure shape: feeding a synthetic TerminalEvent through
// the same wiring serve.go uses ends in a real HTTP POST landing in
// the receiver. Lock-in for the integration; serve.go's literal
// closure is type-checked elsewhere.
func TestDispatcherTerminalEventReachesNotifier(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	var lastBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		lastBody = string(body)
		hits.Add(1)
	}))
	defer srv.Close()

	ch := journal.NotificationChannel{
		ID:   "c1",
		Kind: "generic_webhook",
		ConfigJSON: mustJSON(map[string]any{
			"url": srv.URL,
		}),
	}
	lookup := &fakeLookup{channels: []journal.NotificationChannel{ch}}
	n := New(lookup, nil).
		WithSender((&WebhookSender{Client: ssrfSafeClient(true)})).
		WithDashboardURL("https://reactor.example.com")

	// This closure is the exact shape serve.go's OnTerminal uses, just
	// without the runlogs.Buffer.Close call. If the dispatcher contract
	// changes, this test fails at compile time.
	onTerminal := func(ctx context.Context, ev dispatcher.TerminalEvent) {
		if ev.Status == "failed" || ev.Status == "failed_dlq" || ev.Status == "succeeded" {
			n.Notify(ctx, Event{
				RunID:        ev.RunID,
				WorkflowID:   ev.WorkflowID,
				WorkflowSlug: ev.WorkflowSlug,
				Status:       ev.Status,
				TriggerKind:  ev.TriggerKind,
				ErrorText:    ev.ErrorText,
			})
		}
	}

	onTerminal(context.Background(), dispatcher.TerminalEvent{
		RunID:        "run_xyz",
		WorkflowID:   "wf_demo",
		WorkflowSlug: "demo",
		Status:       "failed_dlq",
		TriggerKind:  "webhook",
		ErrorText:    "credential-canary",
	})

	if got := hits.Load(); got != 1 {
		t.Fatalf("receiver hits = %d, want 1", got)
	}
	for _, want := range []string{
		`"status":"failed_dlq"`,
		`"workflow_slug":"demo"`,
		`"run_id":"run_xyz"`,
		`https://reactor.example.com/runs/run_xyz`,
	} {
		if !strings.Contains(lastBody, want) {
			t.Fatalf("missing %q in receiver body\n--- body ---\n%s", want, lastBody)
		}
	}
	if strings.Contains(lastBody, "credential-canary") || strings.Contains(lastBody, `"error_text"`) {
		t.Fatal("raw step error escaped from terminal event into webhook HTTP payload")
	}
}

// fakeLookup, mustJSON: defined in notifier_test.go.
var _ = json.Marshal
