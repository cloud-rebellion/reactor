package notifier

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	_ "modernc.org/sqlite"
)

type receiptSender struct {
	mu      sync.Mutex
	calls   map[string]int
	last    map[string]Event
	failFor string
}

func (s *receiptSender) Kind() string { return journal.ChannelKindGenericWebhook }

func (s *receiptSender) Send(_ context.Context, cfg json.RawMessage, ev Event) error {
	var c struct {
		Destination string `json:"destination"`
	}
	if err := json.Unmarshal(cfg, &c); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[c.Destination]++
	s.last[c.Destination] = ev
	if c.Destination == s.failFor {
		return errors.New("synthetic provider outage")
	}
	return nil
}

func TestNotifyClaimedDoesNotResendSuccessfulChannelsAfterPeerFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "notifier.db")
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), "sqlite://"+path); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j := journal.New(db, journal.EngineSQLite)
	if err := j.CreateWorkflow(ctx, "wf_receipt", "receipt", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_receipt", "wf_receipt", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{"alpha", "bravo"} {
		id, err := j.CreateNotificationChannel(ctx, destination, journal.ChannelKindGenericWebhook,
			json.RawMessage(`{"destination":"`+destination+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		if err := j.AddNotificationRoute(ctx, "wf_receipt", id, "failed"); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.MarkRunFinished(ctx, "run_receipt", "failed"); err != nil {
		t.Fatal(err)
	}
	sender := &receiptSender{calls: map[string]int{}, last: map[string]Event{}, failFor: "bravo"}
	n := New(j, slog.New(slog.NewTextHandler(io.Discard, nil))).WithSender(sender)
	event := Event{RunID: "run_receipt", WorkflowID: "wf_receipt", Status: "failed"}
	first, err := j.ClaimTerminalEffect(ctx, event.RunID, event.Status, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.NotifyClaimed(ctx, event, first); err == nil || !strings.Contains(err.Error(), "synthetic provider outage") {
		t.Fatalf("first attempt = %v", err)
	}
	if err := j.ReleaseTerminalEffectForClaim(ctx, first, "provider unavailable"); err != nil {
		t.Fatal(err)
	}
	sender.mu.Lock()
	sender.failFor = ""
	sender.mu.Unlock()
	second, err := j.ClaimTerminalEffect(ctx, event.RunID, event.Status, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.NotifyClaimed(ctx, event, second); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkTerminalEffectDeliveredForClaim(ctx, second); err != nil {
		t.Fatal(err)
	}
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if sender.calls["alpha"] != 1 || sender.calls["bravo"] != 2 {
		t.Fatalf("provider calls = %+v, want alpha once and bravo twice", sender.calls)
	}
	if sender.last["alpha"].TerminalGeneration != 1 || sender.last["alpha"].NotificationChannelID == "" ||
		sender.last["bravo"].NotificationChannelID == "" {
		t.Fatalf("provider event identity missing: %+v", sender.last)
	}
}

func TestNotifyClaimedRequiresDurableLedger(t *testing.T) {
	t.Parallel()
	n := New(&fakeLookup{}, nil)
	err := n.NotifyClaimed(context.Background(), Event{RunID: "r", WorkflowID: "wf", Status: "failed"},
		journal.TerminalEffect{RunID: "r", Status: "failed", ClaimedAt: time.Now(), ClaimToken: "claim"})
	if err == nil || !strings.Contains(err.Error(), "ledger unavailable") {
		t.Fatalf("missing delivery ledger = %v", err)
	}
}
