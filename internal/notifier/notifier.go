// Package notifier delivers run-status alerts to configured channels.
//
// One Notifier instance owns a small set of senders (slack_webhook,
// generic_webhook, email_smtp). The dispatcher's OnTerminal callback
// invokes NotifyClaimed with terminal metadata; the notifier snapshots routed
// channels through the journal's delivery ledger and fires each in a bounded
// fan-out.
//
// Failure modes are bounded and retryable: a Slack outage must not block
// forever or prevent other channels from being attempted. Each sender has a
// per-attempt timeout (5s default); failures are logged and returned to the
// terminal-effect owner, which leaves the durable receipt eligible for a
// later retry. Operators needing provider-side deduplication should route to
// a queue-backed webhook (e.g. an internal POST endpoint that lands the alert
// in a journal of its own).
package notifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// Event is everything a sender needs to render an alert. Snake_case
// JSON tags so generic-webhook receivers can route without re-mapping.
type Event struct {
	RunID                 string    `json:"run_id"`
	TerminalGeneration    int64     `json:"terminal_generation,omitempty"`
	NotificationChannelID string    `json:"notification_channel_id,omitempty"`
	WorkflowSlug          string    `json:"workflow_slug"`
	WorkflowID            string    `json:"workflow_id"`
	Status                string    `json:"status"` // "succeeded" | "failed" | "failed_dlq"
	TriggerKind           string    `json:"trigger_kind"`
	StartedAt             time.Time `json:"started_at"`
	FinishedAt            time.Time `json:"finished_at"`
	// ErrorText is retained for internal callers but must never enter an
	// external notification. Step errors can contain untrusted data or secrets.
	ErrorText    string `json:"-"`
	DashboardURL string `json:"dashboard_url,omitempty"`
}

// Sender is the per-kind delivery shape. Implementations should be
// stateless or own internal pool state; the Notifier instantiates
// one per channel kind, not one per channel.
type Sender interface {
	Send(ctx context.Context, cfg json.RawMessage, ev Event) error
	Kind() string
}

// ChannelLookup is the read surface the notifier needs from the
// journal. Defined as an interface so tests can stub without spinning
// up a real DB.
type ChannelLookup interface {
	ChannelsForRunTerminal(ctx context.Context, workflowID, status string) ([]journal.NotificationChannel, error)
	GetNotificationChannel(ctx context.Context, id string) (journal.NotificationChannel, error)
}

// NotificationDeliveryLedger is the durable path used by the daemon. Keeping
// it separate from ChannelLookup preserves the older Notify helper for local
// send tests; a production call fails closed if a ledger is unavailable.
type NotificationDeliveryLedger interface {
	BeginNotificationDelivery(ctx context.Context, effect journal.TerminalEffect, workflowID string) (journal.NotificationSnapshot, error)
	PendingNotificationDeliveryPage(ctx context.Context, effect journal.TerminalEffect, snap journal.NotificationSnapshot, after string, limit int) ([]journal.NotificationDeliveryTarget, bool, error)
	MarkNotificationDelivery(ctx context.Context, effect journal.TerminalEffect, snap journal.NotificationSnapshot, channelID string) error
	SkipNotificationDelivery(ctx context.Context, effect journal.TerminalEffect, snap journal.NotificationSnapshot, channelID string) error
}

// Notifier dispatches Events to routed channels. Construct one per
// daemon via New + register senders via WithSender.
type Notifier struct {
	lookup       ChannelLookup
	senders      map[string]Sender
	log          *slog.Logger
	dashboardURL string
	timeout      time.Duration
	// Shared by all run notifications and operator test sends. Acquiring a
	// slot before starting a goroutine bounds process-wide sender fan-out.
	sendSlots chan struct{}

	// resolveSecret resolves a vault credential id to its plaintext value.
	// Wired by the daemon to the vault so a channel can reference a credential by id
	// (e.g. an SMTP password or a webhook auth header). The journal seals new
	// channel configs at rest; referenced credentials still resolve only when
	// sending. A referenced credential fails closed if this resolver is absent.
	resolveSecret func(ctx context.Context, tenantID, credentialID string) (string, error)
}

// WithSecretResolver wires the vault lookup used to resolve channel
// credential references at send time. Returns the Notifier for chaining.
func (n *Notifier) WithSecretResolver(f func(ctx context.Context, tenantID, credentialID string) (string, error)) *Notifier {
	n.resolveSecret = f
	return n
}

// New builds a Notifier with the default 5s per-send timeout. Senders
// must be registered with WithSender before Notify will deliver.
func New(lookup ChannelLookup, log *slog.Logger) *Notifier {
	if log == nil {
		log = slog.Default()
	}
	return &Notifier{
		lookup:    lookup,
		senders:   map[string]Sender{},
		log:       log,
		timeout:   5 * time.Second,
		sendSlots: make(chan struct{}, 16),
	}
}

func (n *Notifier) acquireSendSlot(ctx context.Context) error {
	select {
	case n.sendSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (n *Notifier) releaseSendSlot() { <-n.sendSlots }

// WithSender registers a sender keyed by its Kind(). Subsequent
// registrations under the same kind replace the previous sender.
func (n *Notifier) WithSender(s Sender) *Notifier {
	n.senders[s.Kind()] = s
	return n
}

// WithDashboardURL sets the public base URL used to render "view this
// run" links in the alert body. Empty (the default) means senders
// omit the link.
func (n *Notifier) WithDashboardURL(u string) *Notifier {
	n.dashboardURL = u
	return n
}

// WithTimeout overrides the default 5s per-send timeout.
func (n *Notifier) WithTimeout(d time.Duration) *Notifier {
	if d > 0 {
		n.timeout = d
	}
	return n
}

// NotifyClaimed is the daemon's terminal alert path. It freezes matching route
// IDs under the outer terminal-effect claim, sends only recipients without a
// success receipt, and acknowledges each confirmed send independently. A
// provider success followed by a process crash before the DB acknowledgement
// remains at-least-once; generic webhook receivers can deduplicate by run ID,
// terminal generation, and channel ID.
func (n *Notifier) NotifyClaimed(ctx context.Context, ev Event, effect journal.TerminalEffect) error {
	ledger, ok := n.lookup.(NotificationDeliveryLedger)
	if !ok {
		return errors.New("notifier: durable notification delivery ledger unavailable")
	}
	if ev.RunID == "" || ev.WorkflowID == "" || ev.Status == "" ||
		effect.RunID != ev.RunID || effect.Status != ev.Status {
		return journal.ErrTerminalEffectClaimLost
	}
	snap, err := ledger.BeginNotificationDelivery(ctx, effect, ev.WorkflowID)
	if err != nil {
		return fmt.Errorf("notifier: snapshot routed channels: %w", err)
	}
	if ev.DashboardURL == "" && n.dashboardURL != "" {
		ev.DashboardURL = n.dashboardURL + "/runs/" + ev.RunID
	}
	ev.TerminalGeneration = snap.Generation
	var deliveryErrs []error
	var errMu sync.Mutex
	recordError := func(err error) {
		if err != nil {
			errMu.Lock()
			deliveryErrs = append(deliveryErrs, err)
			errMu.Unlock()
		}
	}
	ack := func(channelID string, skip bool) error {
		// A successful external send must still get a chance to persist its
		// receipt when the callback context is cancelled during shutdown.
		ackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), n.timeout)
		defer cancel()
		if skip {
			return ledger.SkipNotificationDelivery(ackCtx, effect, snap, channelID)
		}
		return ledger.MarkNotificationDelivery(ackCtx, effect, snap, channelID)
	}
	after := ""
	for {
		page, more, err := ledger.PendingNotificationDeliveryPage(ctx, effect, snap, after, 16)
		if err != nil {
			return errors.Join(errors.Join(deliveryErrs...), fmt.Errorf("notifier: pending delivery page: %w", err))
		}
		if len(page) == 0 {
			if more {
				return errors.Join(errors.Join(deliveryErrs...), errors.New("notifier: empty pending page with continuation"))
			}
			break
		}
		after = page[len(page)-1].ChannelID
		var wg sync.WaitGroup
		capacityLost := false
		for _, target := range page {
			target := target
			if target.Missing {
				if err := ack(target.ChannelID, true); err != nil {
					recordError(fmt.Errorf("notifier: skip deleted channel %s: %w", target.ChannelID, err))
				}
				continue
			}
			sender, ok := n.senders[target.Channel.Kind]
			if !ok {
				recordError(fmt.Errorf("notifier: no sender registered for kind %q (channel %s)", target.Channel.Kind, target.ChannelID))
				continue
			}
			waitCtx, cancel := context.WithTimeout(ctx, n.timeout)
			acquireErr := n.acquireSendSlot(waitCtx)
			cancel()
			if acquireErr != nil {
				recordError(fmt.Errorf("notifier: send capacity unavailable before channel %s: %w", target.ChannelID, acquireErr))
				capacityLost = true
				break
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer n.releaseSendSlot()
				// dispatch isolates a sender panic and returns an error, leaving
				// the delivery receipt pending for a later claim.
				targetEvent := ev
				targetEvent.NotificationChannelID = target.ChannelID
				if err := n.dispatch(ctx, target.Channel, sender, targetEvent); err != nil {
					recordError(err)
					return
				}
				if err := ack(target.ChannelID, false); err != nil {
					recordError(fmt.Errorf("notifier: acknowledge channel %s: %w", target.ChannelID, err))
				}
			}()
		}
		wg.Wait()
		if capacityLost || !more {
			break
		}
	}
	return errors.Join(deliveryErrs...)
}

// Notify is the legacy direct-send helper retained for tests and external
// callers. It dispatches to every currently routed channel and returns an
// aggregate error, but does not create per-channel receipts. The daemon uses
// NotifyClaimed so terminal effects cannot be acknowledged before durable
// delivery receipts exist.
//
// dashboardURL is the public base URL ("https://reactor.acme.com"); the
// sender appends "/runs/<id>" to build a clickable link.
func (n *Notifier) Notify(ctx context.Context, ev Event) error {
	channels, err := n.lookup.ChannelsForRunTerminal(ctx, ev.WorkflowID, ev.Status)
	if err != nil {
		n.log.Warn("notifier: channel lookup failed", "err", err, "workflow_id", ev.WorkflowID, "status", ev.Status)
		return fmt.Errorf("notifier: channel lookup: %w", err)
	}
	if len(channels) == 0 {
		return nil
	}
	if ev.DashboardURL == "" && n.dashboardURL != "" {
		ev.DashboardURL = n.dashboardURL + "/runs/" + ev.RunID
	}
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var deliveryErrs []error
	recordError := func(err error) {
		if err == nil {
			return
		}
		errMu.Lock()
		deliveryErrs = append(deliveryErrs, err)
		errMu.Unlock()
	}
dispatchLoop:
	for _, ch := range channels {
		ch := ch
		sender, ok := n.senders[ch.Kind]
		if !ok {
			n.log.Warn("notifier: no sender registered for kind",
				"kind", ch.Kind, "channel", ch.Name)
			recordError(fmt.Errorf("notifier: no sender registered for kind %q (channel %s)", ch.Kind, ch.ID))
			continue
		}
		// A saturated notifier must not launch a goroutine for every routed
		// channel. Give existing sends one attempt timeout to free a slot;
		// otherwise return an error and leave the durable terminal receipt
		// retryable for channels that were not attempted.
		waitCtx, cancel := context.WithTimeout(ctx, n.timeout)
		acquireErr := n.acquireSendSlot(waitCtx)
		cancel()
		if acquireErr != nil {
			recordError(fmt.Errorf("notifier: send capacity unavailable before channel %s: %w", ch.ID, acquireErr))
			break dispatchLoop
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer n.releaseSendSlot()
			// A panicking sender must not take down the daemon mid-flight;
			// isolate it to this one channel send.
			defer func() {
				if rec := recover(); rec != nil {
					n.log.Error("notifier: sender panicked",
						"kind", ch.Kind, "channel", ch.Name, "panic", rec)
					recordError(fmt.Errorf("notifier: sender %s panicked: %v", ch.Kind, rec))
				}
			}()
			recordError(n.dispatch(ctx, ch, sender, ev))
		}()
	}
	wg.Wait()
	if len(deliveryErrs) > 0 {
		return errors.Join(deliveryErrs...)
	}
	return nil
}

// TestChannel fires a synthetic alert through one channel id so the
// operator's "Send test" button can confirm credentials + connectivity
// without waiting for a real run to fail.
func (n *Notifier) TestChannel(ctx context.Context, channelID string) error {
	ch, err := n.lookup.GetNotificationChannel(ctx, channelID)
	if err != nil {
		return fmt.Errorf("notifier: lookup channel: %w", err)
	}
	sender, ok := n.senders[ch.Kind]
	if !ok {
		return fmt.Errorf("notifier: no sender registered for kind %q", ch.Kind)
	}
	ev := Event{
		RunID:        "test_" + fmtNow(),
		WorkflowSlug: "(test channel)",
		WorkflowID:   "test",
		Status:       "test",
		TriggerKind:  "test",
		StartedAt:    time.Now().UTC(),
		FinishedAt:   time.Now().UTC(),
		DashboardURL: n.dashboardURL,
	}
	tctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()
	if err := n.acquireSendSlot(tctx); err != nil {
		return fmt.Errorf("notifier: send capacity unavailable: %w", err)
	}
	defer n.releaseSendSlot()
	cfg, err := resolveChannelSecrets(tctx, ch.TenantID, ch.Kind, ch.ConfigJSON, n.resolveSecret)
	if err != nil {
		return fmt.Errorf("notifier: resolve channel secret for channel %s: %w", ch.ID, err)
	}
	return sender.Send(tctx, cfg, ev)
}

func (n *Notifier) dispatch(ctx context.Context, ch journal.NotificationChannel, sender Sender, ev Event) (err error) {
	tctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("notifier: sender %s panicked: %v", ch.Kind, rec)
			n.log.Error("notifier: sender panicked",
				"kind", ch.Kind, "channel", ch.Name, "panic", rec)
		}
	}()
	cfg, err := resolveChannelSecrets(tctx, ch.TenantID, ch.Kind, ch.ConfigJSON, n.resolveSecret)
	if err != nil {
		// A channel that references a vault secret must not be sent with
		// a blank credential when the resolver is unavailable or fails.
		n.log.Warn("notifier: resolve channel secret failed; skipping send",
			"channel", ch.Name, "kind", ch.Kind, "err", err)
		return fmt.Errorf("notifier: resolve channel secret for channel %s: %w", ch.ID, err)
	}
	// Apply the boundary even to a newly registered Sender implementation.
	// The built-in senders also omit ErrorText when called directly.
	ev.ErrorText = ""
	if err := sender.Send(tctx, cfg, ev); err != nil {
		n.log.Warn("notifier: send failed",
			"channel", ch.Name, "kind", ch.Kind, "run_id", ev.RunID, "err", err)
		return fmt.Errorf("notifier: send channel %s: %w", ch.ID, err)
	}
	n.log.Info("notifier: alert sent",
		"channel", ch.Name, "kind", ch.Kind, "run_id", ev.RunID, "status", ev.Status)
	return nil
}

func fmtNow() string {
	return time.Now().UTC().Format("20060102T150405Z")
}
