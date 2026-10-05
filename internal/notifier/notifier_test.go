package notifier

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// fakeLookup implements ChannelLookup so the notifier tests don't
// require a real journal.
type fakeLookup struct {
	channels  []journal.NotificationChannel
	byID      map[string]journal.NotificationChannel
	lookupErr error
}

func (f *fakeLookup) ChannelsForRunTerminal(_ context.Context, workflowID, status string) ([]journal.NotificationChannel, error) {
	if f.lookupErr != nil {
		return nil, f.lookupErr
	}
	return f.channels, nil
}

func (f *fakeLookup) GetNotificationChannel(_ context.Context, id string) (journal.NotificationChannel, error) {
	ch, ok := f.byID[id]
	if !ok {
		return journal.NotificationChannel{}, errors.New("not found")
	}
	return ch, nil
}

// countingSender records call counts + the last event so dispatch
// behaviour can be asserted without a real HTTP server.
type countingSender struct {
	kind  string
	calls atomic.Int32
	last  atomic.Pointer[Event]
	fail  error
}

type blockingSender struct {
	started chan struct{}
	release <-chan struct{}
	calls   atomic.Int32
	active  atomic.Int32
	peak    atomic.Int32
}

func (b *blockingSender) Kind() string { return journal.ChannelKindGenericWebhook }
func (b *blockingSender) Send(ctx context.Context, _ json.RawMessage, _ Event) error {
	b.calls.Add(1)
	active := b.active.Add(1)
	defer b.active.Add(-1)
	for {
		peak := b.peak.Load()
		if active <= peak || b.peak.CompareAndSwap(peak, active) {
			break
		}
	}
	b.started <- struct{}{}
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestNotifyBoundsConcurrentSendsAcrossRuns(t *testing.T) {
	t.Parallel()
	channels := make([]journal.NotificationChannel, 4)
	for i := range channels {
		channels[i] = journal.NotificationChannel{ID: "channel", Kind: journal.ChannelKindGenericWebhook, ConfigJSON: []byte(`{"url":"https://example.com"}`)}
	}
	release := make(chan struct{})
	sender := &blockingSender{started: make(chan struct{}, 8), release: release}
	n := New(&fakeLookup{channels: channels}, nil).WithSender(sender).WithTimeout(2 * time.Second)
	// Exercise a smaller instance-wide cap without waiting for 16 sends.
	n.sendSlots = make(chan struct{}, 2)
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			results <- n.Notify(context.Background(), Event{RunID: "run", WorkflowID: "wf", Status: "failed"})
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-sender.started:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("first two sends did not start")
		}
	}
	select {
	case <-sender.started:
		close(release)
		t.Fatal("a third send started while both shared slots were occupied")
	case <-time.After(40 * time.Millisecond):
	}
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if got := sender.calls.Load(); got != 8 {
		t.Fatalf("sender calls = %d, want all 8", got)
	}
	if got := sender.peak.Load(); got > 2 {
		t.Fatalf("peak concurrent sends = %d, want at most 2", got)
	}
}

func TestNotifierCapacityTimeoutKeepsSendsRetryable(t *testing.T) {
	t.Parallel()
	ch := journal.NotificationChannel{ID: "c1", Kind: journal.ChannelKindGenericWebhook, ConfigJSON: []byte(`{"url":"https://example.com"}`)}
	lookup := &fakeLookup{channels: []journal.NotificationChannel{ch}, byID: map[string]journal.NotificationChannel{"c1": ch}}
	sender := &countingSender{kind: journal.ChannelKindGenericWebhook}
	n := New(lookup, nil).WithSender(sender).WithTimeout(20 * time.Millisecond)
	n.sendSlots = make(chan struct{}, 1)
	n.sendSlots <- struct{}{}
	defer n.releaseSendSlot()
	if err := n.TestChannel(context.Background(), "c1"); err == nil || !strings.Contains(err.Error(), "send capacity unavailable") {
		t.Fatalf("test send error = %v, want capacity error", err)
	}
	if err := n.Notify(context.Background(), Event{RunID: "r1", WorkflowID: "wf", Status: "failed"}); err == nil || !strings.Contains(err.Error(), "send capacity unavailable") {
		t.Fatalf("notify error = %v, want retryable capacity error", err)
	}
	if got := sender.calls.Load(); got != 0 {
		t.Fatalf("sender calls = %d, want zero", got)
	}
}

func (c *countingSender) Kind() string { return c.kind }
func (c *countingSender) Send(_ context.Context, _ json.RawMessage, ev Event) error {
	c.calls.Add(1)
	c.last.Store(&ev)
	return c.fail
}

func TestNotifyFiresEverySender(t *testing.T) {
	t.Parallel()
	chSlack := journal.NotificationChannel{ID: "c1", Name: "ops", Kind: "slack_webhook", ConfigJSON: []byte(`{"url":"x"}`)}
	chHook := journal.NotificationChannel{ID: "c2", Name: "ops2", Kind: "generic_webhook", ConfigJSON: []byte(`{"url":"x"}`)}
	lookup := &fakeLookup{channels: []journal.NotificationChannel{chSlack, chHook}}
	slackS := &countingSender{kind: "slack_webhook"}
	hookS := &countingSender{kind: "generic_webhook"}

	n := New(lookup, nil).WithSender(slackS).WithSender(hookS).WithDashboardURL("https://reactor.example.com")
	n.Notify(context.Background(), Event{RunID: "r1", WorkflowID: "wf_1", Status: "failed", ErrorText: "credential-canary"})

	if got := slackS.calls.Load(); got != 1 {
		t.Fatalf("slack calls = %d, want 1", got)
	}
	if got := hookS.calls.Load(); got != 1 {
		t.Fatalf("hook calls = %d, want 1", got)
	}
	lastSlack, lastHook := slackS.last.Load(), hookS.last.Load()
	if lastSlack == nil || lastHook == nil {
		t.Fatal("sender did not record a delivered event")
	}
	if lastSlack.DashboardURL != "https://reactor.example.com/runs/r1" {
		t.Fatalf("DashboardURL = %q", lastSlack.DashboardURL)
	}
	if lastSlack.ErrorText != "" || lastHook.ErrorText != "" {
		t.Fatal("raw step error passed through the notifier dispatch boundary")
	}
}

func TestNotifyReturnsSenderErrorsAfterAttemptingDelivery(t *testing.T) {
	t.Parallel()
	ch := journal.NotificationChannel{ID: "c1", Kind: "generic_webhook", ConfigJSON: []byte(`{"url":"x"}`)}
	lookup := &fakeLookup{channels: []journal.NotificationChannel{ch}}
	bad := &countingSender{kind: "generic_webhook", fail: errors.New("boom")}
	n := New(lookup, nil).WithSender(bad)
	// The sender is still attempted, but the terminal receipt must remain
	// retryable when the provider rejects the alert.
	err := n.Notify(context.Background(), Event{RunID: "r1", WorkflowID: "wf_1", Status: "failed"})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("notify error = %v, want sender failure", err)
	}
	if got := bad.calls.Load(); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}
}

func TestNotifySkipsUnregisteredKind(t *testing.T) {
	t.Parallel()
	ch := journal.NotificationChannel{ID: "c1", Kind: "mystery_kind", ConfigJSON: []byte(`{}`)}
	lookup := &fakeLookup{channels: []journal.NotificationChannel{ch}}
	n := New(lookup, nil) // no senders registered
	err := n.Notify(context.Background(), Event{RunID: "r1", WorkflowID: "wf_1", Status: "failed"})
	if err == nil || !strings.Contains(err.Error(), "no sender registered") {
		t.Fatalf("notify error = %v, want missing sender error", err)
	}
}

func TestNotifyAttemptsEveryChannelAndAggregatesErrors(t *testing.T) {
	t.Parallel()
	channels := []journal.NotificationChannel{
		{ID: "c1", Kind: "generic_webhook", ConfigJSON: []byte(`{"url":"x"}`)},
		{ID: "c2", Kind: "generic_webhook", ConfigJSON: []byte(`{"url":"x"}`)},
	}
	lookup := &fakeLookup{channels: channels}
	bad := &countingSender{kind: "generic_webhook", fail: errors.New("provider down")}
	n := New(lookup, nil).WithSender(bad)
	err := n.Notify(context.Background(), Event{RunID: "r1", WorkflowID: "wf_1", Status: "failed"})
	if err == nil {
		t.Fatal("notify error = nil, want aggregate failure")
	}
	if got := bad.calls.Load(); got != 2 {
		t.Fatalf("sender calls = %d, want both channels attempted", got)
	}
}

func TestTestChannelDeliversToSender(t *testing.T) {
	t.Parallel()
	ch := journal.NotificationChannel{ID: "c1", Kind: "generic_webhook", ConfigJSON: []byte(`{"url":"x"}`)}
	lookup := &fakeLookup{byID: map[string]journal.NotificationChannel{"c1": ch}}
	s := &countingSender{kind: "generic_webhook"}
	n := New(lookup, nil).WithSender(s)
	if err := n.TestChannel(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	if got := s.calls.Load(); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}
	last := s.last.Load()
	if last == nil || last.Status != "test" {
		t.Fatalf("event status = %v, want test", last)
	}
}

func TestTestChannelResolvesVaultHeaderOnlyForSend(t *testing.T) {
	t.Parallel()
	gotHeader := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader <- r.Header.Get("X-Test-Token")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	cfg, err := json.Marshal(map[string]string{
		"url":                  srv.URL,
		"header_name":          "X-Test-Token",
		"header_credential_id": "cred_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	ch := journal.NotificationChannel{ID: "c1", TenantID: "tenant-a", Kind: journal.ChannelKindGenericWebhook, ConfigJSON: cfg}
	lookup := &fakeLookup{byID: map[string]journal.NotificationChannel{"c1": ch}}
	resolved := 0
	n := New(lookup, nil).
		WithSender(&WebhookSender{Client: ssrfSafeClient(true)}).
		WithSecretResolver(func(_ context.Context, tenantID, id string) (string, error) {
			resolved++
			if tenantID != "tenant-a" || id != "cred_test" {
				return "", errors.New("unexpected credential")
			}
			return "synthetic-token", nil
		})
	if err := n.TestChannel(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	if received := <-gotHeader; resolved != 1 || received != "synthetic-token" {
		t.Fatalf("vault resolutions = %d, receiver got expected token = %v", resolved, received == "synthetic-token")
	}
	if strings.Contains(string(ch.ConfigJSON), "synthetic-token") {
		t.Fatal("resolved token was written into the stored channel config")
	}
}

func TestReferencedChannelWithoutResolverFailsClosed(t *testing.T) {
	t.Parallel()
	ch := journal.NotificationChannel{ID: "c1", Kind: journal.ChannelKindSlackWebhook, ConfigJSON: []byte(`{"url_credential_id":"cred_test"}`)}
	lookup := &fakeLookup{channels: []journal.NotificationChannel{ch}, byID: map[string]journal.NotificationChannel{"c1": ch}}
	sender := &countingSender{kind: journal.ChannelKindSlackWebhook}
	n := New(lookup, nil).WithSender(sender)
	if err := n.TestChannel(context.Background(), "c1"); err == nil || !strings.Contains(err.Error(), "vault resolver unavailable") {
		t.Fatalf("test channel error = %v, want missing resolver", err)
	}
	if err := n.Notify(context.Background(), Event{RunID: "r1", WorkflowID: "wf_1", Status: "failed"}); err == nil || !strings.Contains(err.Error(), "vault resolver unavailable") {
		t.Fatalf("notify error = %v, want missing resolver", err)
	}
	if got := sender.calls.Load(); got != 0 {
		t.Fatalf("sender calls = %d, want 0", got)
	}
}

func TestReferencedChannelCannotResolveAnotherTenantsCredential(t *testing.T) {
	t.Parallel()
	ch := journal.NotificationChannel{ID: "c1", TenantID: "tenant-b", Kind: journal.ChannelKindSlackWebhook, ConfigJSON: []byte(`{"url_credential_id":"cred_a"}`)}
	lookup := &fakeLookup{channels: []journal.NotificationChannel{ch}}
	sender := &countingSender{kind: journal.ChannelKindSlackWebhook}
	n := New(lookup, nil).WithSender(sender).WithSecretResolver(func(_ context.Context, tenantID, credentialID string) (string, error) {
		if tenantID != "tenant-a" || credentialID != "cred_a" {
			return "", errors.New("credential unavailable to tenant")
		}
		return "synthetic-token", nil
	})
	err := n.Notify(context.Background(), Event{RunID: "r1", WorkflowID: "wf_b", Status: "failed"})
	if err == nil || !strings.Contains(err.Error(), "credential unavailable to tenant") {
		t.Fatalf("notify error = %v, want tenant mismatch", err)
	}
	if got := sender.calls.Load(); got != 0 {
		t.Fatalf("sender calls = %d, want 0", got)
	}
}

func TestSlackSenderPostsBlockKit(t *testing.T) {
	t.Parallel()
	var gotBody []byte
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	// ssrfSafeClient(true) so the loopback httptest server is reachable (the
	// production NewSlackSender blocks private IPs).
	sender := &SlackSender{Client: ssrfSafeClient(true)}
	cfg, _ := json.Marshal(map[string]string{"url": srv.URL})
	ev := Event{RunID: "r1", WorkflowSlug: "demo", Status: "failed", ErrorText: "credential-canary"}
	if err := sender.Send(context.Background(), cfg, ev); err != nil {
		t.Fatal(err)
	}
	if gotCT != "application/json" {
		t.Fatalf("content type = %q", gotCT)
	}
	if !strings.Contains(string(gotBody), `"blocks"`) || !strings.Contains(string(gotBody), `demo`) {
		t.Fatalf("missing block payload: %s", gotBody)
	}
	if strings.Contains(string(gotBody), "credential-canary") {
		t.Fatal("raw step error escaped in Slack HTTP payload")
	}
}

func TestSlackSenderSurfacesNon2xx(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte("invalid_token"))
	}))
	defer srv.Close()
	cfg, _ := json.Marshal(map[string]string{"url": srv.URL})
	err := (&SlackSender{Client: ssrfSafeClient(true)}).Send(context.Background(), cfg, Event{Status: "failed"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want 403 surfaced", err)
	}
}

func TestWebhookSenderPostsJSONWithHeaders(t *testing.T) {
	t.Parallel()
	var gotBody string
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		gotHeader = r.Header.Get("X-Auth")
	}))
	defer srv.Close()
	cfg, _ := json.Marshal(map[string]any{
		"url":     srv.URL,
		"headers": map[string]string{"X-Auth": "secret"},
	})
	ev := Event{RunID: "r1", WorkflowSlug: "wf", Status: "failed", ErrorText: "credential-canary"}
	if err := (&WebhookSender{Client: ssrfSafeClient(true)}).Send(context.Background(), cfg, ev); err != nil {
		t.Fatal(err)
	}
	if gotHeader != "secret" {
		t.Fatalf("auth header = %q", gotHeader)
	}
	if !strings.Contains(gotBody, `"run_id":"r1"`) {
		t.Fatalf("body missing run_id: %s", gotBody)
	}
	if strings.Contains(gotBody, "credential-canary") || strings.Contains(gotBody, `"error_text"`) {
		t.Fatal("raw step error escaped in generic webhook HTTP payload")
	}
}

func TestSlackSenderRejectsEmptyURL(t *testing.T) {
	t.Parallel()
	err := NewSlackSender().Send(context.Background(), []byte(`{}`), Event{Status: "failed"})
	if err == nil || !strings.Contains(err.Error(), "missing url") {
		t.Fatalf("err = %v", err)
	}
}

func TestDirectSendersKeepSSRFProtectionWithoutFactory(t *testing.T) {
	// A zero-value sender is easy to construct in an integration or plugin.
	// It must retain the same private-network block as the production factory.
	t.Setenv("REACTOR_WEBHOOK_ALLOW_PRIVATE", "")
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	cfg, _ := json.Marshal(map[string]string{"url": srv.URL})
	if err := (&WebhookSender{}).Send(context.Background(), cfg, Event{Status: "failed"}); err == nil {
		t.Fatal("zero-value webhook sender reached a private target")
	}
	if err := (&SlackSender{}).Send(context.Background(), cfg, Event{Status: "failed"}); err == nil {
		t.Fatal("zero-value Slack sender reached a private target")
	}
}

func TestNotifyHonoursPerSendTimeout(t *testing.T) {
	t.Parallel()
	// Slow handler (1s); notifier timeout 50ms.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(1 * time.Second)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	ch := journal.NotificationChannel{ID: "c1", Kind: "generic_webhook", ConfigJSON: mustJSON(map[string]string{"url": srv.URL})}
	lookup := &fakeLookup{channels: []journal.NotificationChannel{ch}}
	n := New(lookup, nil).WithSender((&WebhookSender{Client: ssrfSafeClient(true)})).WithTimeout(50 * time.Millisecond)
	start := time.Now()
	n.Notify(context.Background(), Event{RunID: "r1", WorkflowID: "wf_1", Status: "failed"})
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("notify did not honour timeout; took %s", elapsed)
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
