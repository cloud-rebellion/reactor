package notifier

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	_ "modernc.org/sqlite"
)

type failingRoundTrip func(*http.Request) (*http.Response, error)

func (f failingRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestWebhookSenderTransportErrorsNeverExposeRequestSecrets(t *testing.T) {
	t.Parallel()
	const canary = "synthetic-credential-canary"
	url := "https://hooks.example.invalid/services/" + canary + "?token=" + canary
	transportErr := errors.New("transport echoed " + canary)
	client := &http.Client{Transport: failingRoundTrip(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != url {
			t.Fatalf("request URL changed before transport")
		}
		return nil, transportErr
	})}
	for _, tc := range []struct {
		name   string
		sender Sender
		cfg    json.RawMessage
	}{
		{name: "slack vault URL", sender: &SlackSender{Client: client}, cfg: json.RawMessage(`{"url":"` + url + `"}`)},
		{name: "generic webhook query", sender: &WebhookSender{Client: client}, cfg: json.RawMessage(`{"url":"` + url + `","headers":{"Authorization":"` + canary + `"}}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.sender.Send(context.Background(), tc.cfg, Event{Status: "failed"})
			if err == nil || !strings.Contains(err.Error(), "post failed") {
				t.Fatalf("transport failure = %v, want retryable safe category", err)
			}
			if strings.Contains(fmt.Sprintf("%+v", err), canary) || errors.Is(err, transportErr) {
				t.Fatalf("transport error retained request secret or original error: %v", err)
			}
		})
	}
}

func TestSafePostErrorPreservesContextClassificationWithoutOriginalURL(t *testing.T) {
	t.Parallel()
	const canary = "synthetic-credential-canary"
	for _, tc := range []struct {
		name string
		in   error
		want error
	}{
		{name: "canceled", in: fmt.Errorf("%s: %w", canary, context.Canceled), want: context.Canceled},
		{name: "deadline", in: fmt.Errorf("%s: %w", canary, context.DeadlineExceeded), want: context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := safePostError("webhook", tc.in)
			if !errors.Is(err, tc.want) || strings.Contains(fmt.Sprintf("%+v", err), canary) {
				t.Fatalf("safe error = %v, want classified context without canary", err)
			}
		})
	}
}

func TestSlackTransportFailureLeavesSafeTerminalReceiptAndLog(t *testing.T) {
	const canary = "synthetic-slack-webhook-credential-canary"
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
	if err := j.CreateWorkflow(ctx, "wf_safe_transport", "safe-transport", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_safe_transport", "wf_safe_transport", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	channelID, err := j.CreateNotificationChannel(ctx, "slack-safe-transport", journal.ChannelKindSlackWebhook,
		json.RawMessage(`{"url_credential_id":"cred_slack_canary"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.AddNotificationRoute(ctx, "wf_safe_transport", channelID, "failed"); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, "run_safe_transport", "failed"); err != nil {
		t.Fatal(err)
	}
	effect, err := j.ClaimTerminalEffect(ctx, "run_safe_transport", "failed", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	client := &http.Client{Transport: failingRoundTrip(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("dial failed for %s", req.URL.String())
	})}
	n := New(j, log).WithSender(&SlackSender{Client: client}).WithSecretResolver(
		func(_ context.Context, tenantID, credentialID string) (string, error) {
			if tenantID != journal.DefaultTenant || credentialID != "cred_slack_canary" {
				return "", errors.New("unexpected credential reference")
			}
			return "https://hooks.example.invalid/services/" + canary, nil
		})
	notifyErr := n.NotifyClaimed(ctx, Event{RunID: "run_safe_transport", WorkflowID: "wf_safe_transport", Status: "failed"}, effect)
	if notifyErr == nil {
		t.Fatal("failed send was acknowledged")
	}
	if err := j.ReleaseTerminalEffectForClaim(ctx, effect, notifyErr.Error()); err != nil {
		t.Fatal(err)
	}
	var stored string
	var delivered sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT last_error, delivered_at FROM terminal_effects WHERE run_id = ?`,
		"run_safe_transport").Scan(&stored, &delivered); err != nil {
		t.Fatal(err)
	}
	if delivered.Valid || !strings.Contains(stored, "post failed") {
		t.Fatalf("failed send lost retry receipt: delivered=%v error=%q", delivered.Valid, stored)
	}
	for _, surface := range []string{notifyErr.Error(), logs.String(), stored} {
		if strings.Contains(surface, canary) {
			t.Fatal("Slack URL credential escaped into a log or terminal receipt")
		}
	}
}
