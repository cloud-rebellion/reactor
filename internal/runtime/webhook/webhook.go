// Package webhook is the inbound HTTP receiver for trigger payloads. The
// chi handler at POST /webhook/{tokenID} resolves the token to a trigger,
// verifies HMAC against the vault-stored shared secret, leases the delivery by
// (trigger, provider, delivery_id), and dispatches a run via the registered
// Dispatcher. The lease is completed only after a durable run exists, so a
// host crash before dispatch can be recovered by a provider retry.
//
// HMAC verification is provider-aware:
//
//	automation-v1 - X-Webhook-Timestamp, X-Webhook-Delivery, and
//	                X-Webhook-Signature headers; signed payload is
//	                "<timestamp>.<delivery_id>.<raw_body>"; timestamp skew
//	                window is 5 minutes and delivery_id must equal the body's
//	                sole top-level event_id.
//	hash-v1 - X-Hash-Signature: t=<unix>,v1=<64 lower-case hex>; signed payload is
//	          "<t>.<raw_body>"; timestamp skew window is 5 minutes and the
//	          body's sole top-level event_id is the delivery deduplication key.
//	stripe   - Stripe-Signature header: t=<unix>,v1=<hex>; signed payload
//	           is "<t>.<body>"; ts skew window 5 minutes.
//	github   - X-Hub-Signature-256 header: "sha256=<hex>"; signed payload
//	           is the raw body.
//	generic  - X-Webhook-Signature header: "sha256=<hex>"; signed payload
//	           is the raw body. The dedup ID comes from X-Webhook-Delivery
//	           or, when absent, a SHA-256 fingerprint of the body.
//
// All HMAC compares use crypto/subtle.ConstantTimeCompare; bad sigs return
// 401. Completed replays inside the dedup window return 200 with no run
// dispatched. A duplicate that arrives while another request owns the live
// lease gets 503 + Retry-After; returning a false 2xx there could acknowledge a
// delivery whose owner then crashes before creating its run.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/dispatcher"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/vault"
	hashesign "github.com/bright-interaction/reactor/sdk/esign/hash"
)

// MaxBodyBytes caps the inbound body so a misconfigured upstream cannot
// exhaust host memory. Larger payloads should ride object storage with a
// reference; webhooks themselves stay small.
const MaxBodyBytes = 1 << 20 // 1 MiB

// defaultDeliveryLease bounds the pre-completion ownership window. It exceeds
// the maximum 120-second synchronous webhook timeout so a normal sync run does
// not get reclaimed while its original request is still waiting.
const defaultDeliveryLease = 5 * time.Minute

// deliveryFinalizeTimeout bounds the DB write that completes or releases a
// claim after dispatch. It deliberately outlives SQLite's five-second busy
// timeout but does not let a disconnected HTTP request hang forever.
const deliveryFinalizeTimeout = 10 * time.Second

// stripeSkew is the maximum acceptable clock drift between the upstream
// and the host for Stripe signature timestamps. Stripe's own docs use 5
// minutes as the recommended ceiling.
const stripeSkew = 5 * time.Minute

// ProviderAutomationV1 is the signed envelope used by CRM, Google Apps
// Script, and standalone automation producers. The version is part of the
// provider name so future envelope changes cannot silently weaken or alter an
// existing trigger's verification contract.
const ProviderAutomationV1 = "automation-v1"

// ProviderHashV1 authenticates lifecycle callbacks emitted by Hash. It is
// intentionally separate from Stripe's similar-looking envelope: Hash accepts
// exactly one canonical t=...,v1=... signature and derives delivery identity
// from the signed JSON event_id rather than an unsigned header.
const ProviderHashV1 = "hash-v1"

// automationSkew bounds replay of a captured, otherwise valid envelope. The
// event ID remains stable across retries, but every delivery attempt gets a
// fresh timestamp and signature.
const automationSkew = 5 * time.Minute

// hashSkew bounds replay of a captured Hash lifecycle callback.
const hashSkew = 5 * time.Minute

// IsSupportedProvider reports whether provider has a verifier with an explicit
// contract. Callers that create triggers use this to reject typos instead of
// accidentally falling back to the generic verifier.
func IsSupportedProvider(provider string) bool {
	switch provider {
	case ProviderAutomationV1, ProviderHashV1, "generic", "github", "stripe":
		return true
	default:
		return false
	}
}

// VaultReader is the slice of the vault interface this package needs.
// Defined locally to keep imports tight.
type VaultReader interface {
	Get(ctx context.Context, id string) (*vault.Secret, error)
}

// syncConfig is the subset of a webhook trigger's config JSON that controls
// synchronous (request/response) behaviour.
type syncConfig struct {
	Sync           bool `json:"sync"`
	TimeoutSeconds int  `json:"timeout_seconds"`
}

// parseSyncConfig reads the sync flag + timeout from a trigger's config. A sync
// trigger with no timeout defaults to 30s; the timeout is clamped to 120s so a
// hung run can't pin an HTTP connection indefinitely.
func parseSyncConfig(cfg []byte) syncConfig {
	var sc syncConfig
	if len(cfg) > 0 {
		_ = json.Unmarshal(cfg, &sc)
	}
	if sc.Sync {
		if sc.TimeoutSeconds <= 0 {
			sc.TimeoutSeconds = 30
		}
		if sc.TimeoutSeconds > 120 {
			sc.TimeoutSeconds = 120
		}
	}
	return sc
}

// Dispatcher is the contract that fan-outs a verified webhook payload into
// a workflow run. The supervisor lives behind this interface so the webhook
// package can be tested with a fake.
type Dispatcher interface {
	// DispatchWebhook returns after the run row is durable, with its id. The
	// delivery claim is completed only after this succeeds.
	DispatchWebhook(ctx context.Context, t journal.Trigger, payload []byte) (runID string, err error)
	// DispatchSync starts the run and waits for its result (for synchronous
	// webhook triggers that return the workflow's output to the caller).
	DispatchSync(ctx context.Context, t journal.Trigger, payload []byte, timeout time.Duration) (runID, status string, output json.RawMessage, err error)
}

// Receiver wires the components.
type Receiver struct {
	Journal *journal.Journal
	Vault   VaultReader
	Disp    Dispatcher
	Log     *slog.Logger

	// Now overrides the clock for deterministic tests.
	Now func() time.Time

	// DeliveryLease overrides the recovery lease for tests. Zero uses the
	// five-minute production default.
	DeliveryLease time.Duration
}

// Mount registers the receiver's routes:
//
//	POST /webhook/{token_id}         HMAC-verified trigger payload
//	GET  /webhook/{token_id}/status  signed automation-v1 reconciliation
//	POST /signal/{token}             AwaitSignal external delivery
func (r *Receiver) Mount(router chi.Router) {
	router.Post("/webhook/{token_id}", r.handle)
	router.Get("/webhook/{token_id}/status", r.handleDeliveryStatus)
	router.Post("/signal/{token}", r.handleSignal)
}

// Handler returns the bare chi handler for callers that compose their own
// router (e.g. tests).
func (r *Receiver) Handler() http.HandlerFunc { return r.handle }

// SignalHandler returns the bare signal-delivery handler for tests that
// compose their own router.
func (r *Receiver) SignalHandler() http.HandlerFunc { return r.handleSignal }

func (r *Receiver) handle(w http.ResponseWriter, req *http.Request) {
	if r.Log == nil {
		r.Log = slog.Default()
	}
	tokenID := chi.URLParam(req, "token_id")
	if tokenID == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, MaxBodyBytes))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			r.Log.Warn("webhook: body too large", "limit", maxErr.Limit)
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Log.Warn("webhook: body read", "op", "webhook", "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	ctx := req.Context()
	trig, err := r.Journal.FindWebhookByToken(ctx, tokenID)
	if err != nil {
		// Don't leak whether the token was bad vs. inactive; both 404.
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	provider := trig.Provider
	if provider == "" {
		provider = "generic"
	}
	if provider == ProviderAutomationV1 {
		if err := requireAutomationJSONContentType(req.Header.Values("Content-Type")); err != nil {
			// Content-Type is part of automation-v1's canonical ingress contract.
			// Keep the public response fixed because the supplied header is
			// unauthenticated until the HMAC check below.
			r.Log.Warn("webhook: invalid automation-v1 content type",
				"trigger_id", trig.ID, "provider", provider, "err", err)
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
	}

	if err := r.verifyHMAC(ctx, trig, provider, req.Header, body); err != nil {
		// The full reason goes to the log (operator-only). The trigger row gets
		// a FIXED string, never err.Error(): this branch is reachable by anyone
		// who learns the webhook token, which is semi-public (it lives in the
		// URL held by the upstream provider), so echoing the parse error would
		// let an unauthenticated caller write text of their choosing into
		// last_error and have the dashboard render it back to the operator.
		r.Log.Warn("webhook: hmac verify failed", "trigger_id", trig.ID, "provider", provider, "err", err)
		_ = r.Journal.MarkTriggerError(ctx, trig.ID, "hmac: signature verification failed (see daemon logs for the reason)")
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	dispatchBody := body
	if provider == ProviderAutomationV1 {
		if err := validateAutomationEventID(body, req.Header.Get("X-Webhook-Delivery")); err != nil {
			// The envelope was authenticated, but it is not a valid automation-v1
			// request. Keep the public response and persisted trigger error fixed;
			// detailed parse context belongs only in the operator log.
			r.Log.Warn("webhook: invalid automation-v1 event",
				"trigger_id", trig.ID, "provider", provider, "err", err)
			_ = r.Journal.MarkTriggerError(ctx, trig.ID,
				"automation-v1: invalid event envelope (see daemon logs for the reason)")
			http.Error(w, "invalid automation event", http.StatusBadRequest)
			return
		}
	}
	if provider == ProviderHashV1 {
		if _, err := hashEventID(body); err != nil {
			// Authentication succeeded, so this is a malformed callback from a
			// holder of the Hash webhook secret. Keep the persisted/public error
			// generic; detailed JSON parse context belongs in operator logs only.
			r.Log.Warn("webhook: invalid hash-v1 event",
				"trigger_id", trig.ID, "provider", provider, "err", err)
			_ = r.Journal.MarkTriggerError(ctx, trig.ID,
				"hash-v1: invalid event envelope (see daemon logs for the reason)")
			http.Error(w, "invalid Hash event", http.StatusBadRequest)
			return
		}
		projected, err := hashesign.ProjectWebhookEvent(body)
		if err != nil {
			// The signed bytes remain the dedup/conflict input below, but the run
			// receives only a strict non-PII lifecycle projection. This happens
			// after authentication so unauthenticated bodies never reach SDK parsing.
			r.Log.Warn("webhook: invalid hash-v1 projection",
				"trigger_id", trig.ID, "provider", provider, "err", err)
			_ = r.Journal.MarkTriggerError(ctx, trig.ID,
				"hash-v1: invalid event envelope (see daemon logs for the reason)")
			http.Error(w, "invalid Hash event", http.StatusBadRequest)
			return
		}
		dispatchBody = projected
	}

	deliveryID := pickDeliveryID(provider, req.Header, body)
	payloadSHA256 := hashPayload(body)
	now := r.now().UTC()
	lease := r.DeliveryLease
	if lease <= 0 {
		lease = defaultDeliveryLease
	}
	// Scoped to THIS trigger: the dedup namespace used to be global, so a
	// delivery id consumed by any other trigger silently suppressed this one.
	claim, err := r.Journal.ClaimWebhookDelivery(
		ctx, trig.ID, provider, deliveryID, payloadSHA256, now, lease)
	if err != nil {
		r.Log.Error("webhook: delivery claim", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	switch claim.State {
	case journal.WebhookDeliveryCompleted:
		// A completed replay is an idempotent success. The earlier owner
		// durably created its run before setting completed_at.
		writeDeliveryReceipt(w, http.StatusOK, true, claim.RunID)
		return
	case journal.WebhookDeliveryInProgress:
		// Do not acknowledge an active claim as completed: the owner may crash
		// before dispatch. Retry-After keeps a provider from hot-looping while
		// still guaranteeing an eventual retry can reclaim an expired lease.
		retryAfter := retryAfterSeconds(now, claim.LeaseExpiresAt)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"in_progress":         true,
			"retry_after_seconds": retryAfter,
		})
		return
	case journal.WebhookDeliveryPayloadMismatch:
		r.Log.Warn("webhook: delivery id reused with different payload",
			"trigger_id", trig.ID, "provider", provider, "delivery_id_fp", deliveryIDFingerprint(deliveryID))
		http.Error(w, "delivery id reused with different payload", http.StatusConflict)
		return
	case journal.WebhookDeliveryClaimed:
		// Continue below; this request owns claim.ClaimToken.
	default:
		r.Log.Error("webhook: unknown delivery claim state", "state", claim.State)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Synchronous trigger: run the workflow and return its result to the
	// caller (request/response API), instead of fire-and-forget.
	// automation-v1 and hash-v1 are deliberately receipt-based and asynchronous.
	// Their 202/200 contract means the producer can durably reconcile run_id
	// without holding its request open (Hash has a 10-second sender timeout), and
	// prevents a legacy trigger checkbox from silently changing either signed
	// integration protocol.
	if sc := parseSyncConfig(trig.Config); sc.Sync &&
		provider != ProviderAutomationV1 && provider != ProviderHashV1 {
		runID, status, output, derr := r.Disp.DispatchSync(ctx, trig, dispatchBody, time.Duration(sc.TimeoutSeconds)*time.Second)
		if derr != nil {
			if errors.Is(derr, dispatcher.ErrWorkflowDisabled) {
				r.releaseClaim(ctx, trig, provider, deliveryID, claim.ClaimToken)
				w.Header().Set("Retry-After", "300")
				http.Error(w, "workflow disabled; retry later", http.StatusServiceUnavailable)
				return
			}
			if errors.Is(derr, dispatcher.ErrRateLimited) || errors.Is(derr, dispatcher.ErrCapacity) {
				r.releaseClaim(ctx, trig, provider, deliveryID, claim.ClaimToken)
				http.Error(w, "rate limited; retry later", http.StatusTooManyRequests)
				return
			}
			if errors.Is(derr, dispatcher.ErrSyncTimeout) {
				// The run keeps executing; hand back 202 + the run id to poll.
				if !r.completeClaim(ctx, trig, provider, deliveryID, claim.ClaimToken, runID) {
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
				_ = r.Journal.MarkTriggerFired(ctx, trig.ID)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted)
				_ = json.NewEncoder(w).Encode(map[string]any{"accepted": true, "run_id": runID, "timed_out": true})
				return
			}
			r.Log.Error("webhook: sync dispatch", "trigger_id", trig.ID, "err", derr)
			_ = r.Journal.MarkTriggerError(ctx, trig.ID, "dispatch: "+derr.Error())
			r.releaseClaim(ctx, trig, provider, deliveryID, claim.ClaimToken)
			http.Error(w, "dispatch failed", http.StatusInternalServerError)
			return
		}
		if !r.completeClaim(ctx, trig, provider, deliveryID, claim.ClaimToken, runID) {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		_ = r.Journal.MarkTriggerFired(ctx, trig.ID)
		code := http.StatusOK
		if status != "succeeded" {
			code = http.StatusBadGateway // the workflow ran but did not succeed
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{"run_id": runID, "status": status, "output": json.RawMessage(output)})
		return
	}

	runID, err := r.Disp.DispatchWebhook(ctx, trig, dispatchBody)
	if err != nil {
		r.Log.Error("webhook: dispatch", "trigger_id", trig.ID, "err", err)
		_ = r.Journal.MarkTriggerError(ctx, trig.ID, "dispatch: "+err.Error())
		// Roll back the dedup claim so the provider's retry of this exact
		// delivery is processed instead of silently deduped. Otherwise a
		// transient dispatch failure permanently eats a Stripe/GitHub
		// webhook.
		r.releaseClaim(ctx, trig, provider, deliveryID, claim.ClaimToken)
		if errors.Is(err, dispatcher.ErrWorkflowDisabled) {
			w.Header().Set("Retry-After", "300")
			http.Error(w, "workflow disabled; retry later", http.StatusServiceUnavailable)
			return
		}
		// Rate-limit / capacity are backpressure, not server faults: 429 tells
		// the sender to retry later rather than alarming on a 500.
		if errors.Is(err, dispatcher.ErrRateLimited) || errors.Is(err, dispatcher.ErrCapacity) {
			http.Error(w, "rate limited; retry later", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "dispatch failed", http.StatusInternalServerError)
		return
	}
	if !r.completeClaim(ctx, trig, provider, deliveryID, claim.ClaimToken, runID) {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := r.Journal.MarkTriggerFired(ctx, trig.ID); err != nil {
		r.Log.Warn("webhook: mark fired", "err", err)
	}

	writeDeliveryReceipt(w, http.StatusAccepted, false, runID)
}

type deliveryReceipt struct {
	Accepted bool   `json:"accepted"`
	Deduped  bool   `json:"deduped"`
	RunID    string `json:"run_id,omitempty"`
}

func writeDeliveryReceipt(w http.ResponseWriter, status int, deduped bool, runID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(deliveryReceipt{
		Accepted: true,
		Deduped:  deduped,
		RunID:    runID,
	})
}

type deliveryStatusResponse struct {
	RunID      string          `json:"run_id"`
	Status     string          `json:"status"`
	Terminal   bool            `json:"terminal"`
	HashResult *safeHashResult `json:"hash_result,omitempty"`
}

// safeHashResult is the only step output the public reconciliation endpoint
// can return. The generated bridge's Hash adapter already excludes signing
// links and customer fields; this projection additionally prevents arbitrary
// workflow output, errors, logs, or trigger metadata from crossing the token
// boundary.
type safeHashResult struct {
	AutomationRequestID string `json:"automation_request_id"`
	DocumentID          string `json:"document_id"`
	Status              string `json:"status"`
	Replayed            bool   `json:"replayed"`
}

func (r *Receiver) handleDeliveryStatus(w http.ResponseWriter, req *http.Request) {
	// Apply on every response, including malformed/auth failures, so a shared
	// proxy or browser never retains a signed status lookup.
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Log == nil {
		r.Log = slog.Default()
	}
	if req.Body != nil {
		body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, 0))
		if err != nil || len(body) != 0 {
			http.Error(w, "status request body must be empty", http.StatusBadRequest)
			return
		}
	}
	tokenID := chi.URLParam(req, "token_id")
	if tokenID == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	deliveryID, err := statusDeliveryID(req.URL.RawQuery)
	if err != nil {
		http.Error(w, "invalid delivery query", http.StatusBadRequest)
		return
	}

	ctx := req.Context()
	trig, err := r.Journal.FindWebhookByToken(ctx, tokenID)
	if errors.Is(err, journal.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		r.Log.Error("webhook: status trigger lookup", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Only automation-v1 producers have this signed reconciliation contract.
	// Respond as if absent for every other provider so the public token does not
	// become a secondary run-inspection API.
	if trig.Provider != ProviderAutomationV1 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := r.verifyHMAC(ctx, trig, ProviderAutomationV1, req.Header, nil); err != nil {
		r.Log.Warn("webhook: status hmac verify failed",
			"trigger_id", trig.ID, "provider", ProviderAutomationV1, "err", err)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	signedDeliveryID, err := singleRequiredHeader(req.Header, "X-Webhook-Delivery")
	if err != nil || signedDeliveryID != deliveryID {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	run, err := r.Journal.FindCompletedWebhookDeliveryRun(
		ctx, trig.ID, ProviderAutomationV1, deliveryID)
	if errors.Is(err, journal.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		r.Log.Error("webhook: status delivery lookup",
			"trigger_id", trig.ID, "provider", ProviderAutomationV1, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	terminal, known := classifyRunStatus(run.Status)
	if !known {
		r.Log.Error("webhook: status delivery has unknown run status",
			"trigger_id", trig.ID, "run_id", run.RunID, "status", run.Status)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	response := deliveryStatusResponse{
		RunID:    run.RunID,
		Status:   run.Status,
		Terminal: terminal,
	}
	statusCode := http.StatusAccepted
	if terminal {
		steps, err := r.Journal.ListSteps(ctx, run.RunID)
		if err != nil {
			r.Log.Error("webhook: status step lookup", "run_id", run.RunID, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Only a successful workflow may publish the Hash step projection as a
		// completed producer result. A later failed/cancelled workflow can still
		// be inspected by operators, but its public delivery capability must not
		// present an intermediate side effect as successful completion.
		if run.Status == "succeeded" {
			response.HashResult = findSafeHashResult(steps)
		}
		statusCode = http.StatusOK
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(response)
}

func statusDeliveryID(rawQuery string) (string, error) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil || len(values) != 1 {
		return "", errors.New("status query must contain only delivery_id")
	}
	deliveryValues, ok := values["delivery_id"]
	if !ok || len(deliveryValues) != 1 {
		return "", errors.New("status query must contain exactly one delivery_id")
	}
	deliveryID := deliveryValues[0]
	if err := validateDeliveryID(deliveryID); err != nil {
		return "", err
	}
	return deliveryID, nil
}

func classifyRunStatus(status string) (terminal, known bool) {
	switch status {
	case "queued", "running", "suspended":
		return false, true
	case "succeeded", "failed", "failed_dlq", "cancelled":
		return true, true
	default:
		return false, false
	}
}

func findSafeHashResult(steps []journal.StepRow) *safeHashResult {
	for index := len(steps) - 1; index >= 0; index-- {
		step := steps[index]
		if step.StepName != "hash-create-and-send" || step.Status != journal.StatusSucceeded ||
			len(step.OutputJSONB) == 0 || len(step.OutputJSONB) > 4<<10 {
			continue
		}
		var result safeHashResult
		if err := json.Unmarshal(step.OutputJSONB, &result); err != nil ||
			validateDeliveryID(result.AutomationRequestID) != nil ||
			validateDeliveryID(result.DocumentID) != nil ||
			!isKnownHashStatus(result.Status) {
			continue
		}
		return &result
	}
	return nil
}

func isKnownHashStatus(status string) bool {
	switch status {
	case "sent", "in_progress", "changes_requested", "finalizing", "completed", "declined", "voided", "expired":
		return true
	default:
		return false
	}
}

func (r *Receiver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func hashPayload(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func deliveryIDFingerprint(deliveryID string) string {
	sum := sha256.Sum256([]byte(deliveryID))
	return hex.EncodeToString(sum[:8])
}

func retryAfterSeconds(now, leaseExpiresAt time.Time) int {
	remaining := leaseExpiresAt.Sub(now)
	if remaining <= 0 {
		return 1
	}
	// HTTP Retry-After uses whole seconds; round up so a compliant sender does
	// not arrive a fraction before the lease can be reclaimed.
	seconds := int((remaining + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

func (r *Receiver) releaseClaim(
	ctx context.Context,
	trig journal.Trigger,
	provider, deliveryID, claimToken string,
) {
	durableCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), deliveryFinalizeTimeout)
	defer cancel()
	if err := r.Journal.ReleaseWebhookDelivery(durableCtx, trig.ID, provider, deliveryID, claimToken); err != nil {
		// A lost token means an expired lease was already reclaimed; never
		// delete that newer owner's row. Any other failure leaves this claim
		// recoverable at lease expiry rather than permanently suppressing it.
		r.Log.Warn("webhook: delivery claim release failed",
			"err", err, "trigger_id", trig.ID, "provider", provider)
	}
}

func (r *Receiver) completeClaim(
	ctx context.Context,
	trig journal.Trigger,
	provider, deliveryID, claimToken, runID string,
) bool {
	durableCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), deliveryFinalizeTimeout)
	defer cancel()
	if err := r.Journal.CompleteWebhookDelivery(
		durableCtx, trig.ID, provider, deliveryID, claimToken, runID, r.now().UTC(),
	); err != nil {
		// Dispatch may already have happened. Do not release here: keeping the
		// lease active avoids an immediate duplicate storm. A provider retry
		// after expiry can reclaim it, which is at-least-once and relies on the
		// workflow's downstream idempotency rather than risking permanent loss.
		r.Log.Error("webhook: delivery completion failed",
			"err", err, "trigger_id", trig.ID, "provider", provider, "run_id", runID)
		_ = r.Journal.MarkTriggerError(durableCtx, trig.ID,
			"delivery completion failed after dispatch; retry will recover after lease expiry")
		return false
	}
	return true
}

// handleSignal accepts an external delivery for a workflow's AwaitSignal.
// The token is the per-await capability the supervisor minted when the run
// suspended; the SDK exposes the same value via DeriveSignalToken so
// workflows can embed the URL in approval emails before suspending.
//
// HMAC is not enforced here. The token is the auth gate; brute-forcing
// 128 bits of randomness via 1 MiB-bounded HTTP requests is infeasible
// inside the sub-day windows typical for human-in-the-loop signals.
//
// Status codes:
//
//	202 Accepted  payload recorded; scheduler will resume the run on next tick
//	404 Not Found token doesn't match any active signal schedule
//	410 Gone      a prior delivery already won; idempotent retry
//	413 Payload Too Large body exceeded MaxBodyBytes
//	500           journal write failed; client may retry
func (r *Receiver) handleSignal(w http.ResponseWriter, req *http.Request) {
	if r.Log == nil {
		r.Log = slog.Default()
	}

	token := chi.URLParam(req, "token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, MaxBodyBytes))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			r.Log.Warn("signal: body too large", "limit", maxErr.Limit)
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Log.Warn("signal: body read", "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	runID, signalName, err := r.Journal.FireSignal(req.Context(), token, body)
	switch {
	case errors.Is(err, journal.ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
		return
	case errors.Is(err, journal.ErrAlreadyFired):
		http.Error(w, "already delivered", http.StatusGone)
		return
	case err != nil:
		r.Log.Error("signal: fire", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Log only a fingerprint of the token, never the token itself: it is
	// a bearer capability that grants POST /signal/{token} access without
	// HMAC, so anyone who reads the logs could otherwise replay the
	// signal with an attacker-controlled payload.
	r.Log.Info("signal delivered",
		"run_id", runID, "signal", signalName, "token_fp", tokenFP(token), "bytes", len(body))
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"accepted":true}`))
}

// tokenFP returns a short, non-reversible fingerprint of a capability
// token so it can be correlated in logs without leaking the token.
func tokenFP(token string) string {
	if len(token) <= 8 {
		return "********"
	}
	return token[:8] + "..."
}

// verifyHMAC dispatches per-provider HMAC validation.
func (r *Receiver) verifyHMAC(ctx context.Context, trig journal.Trigger, provider string, h http.Header, body []byte) error {
	if trig.SecretID == "" {
		return errors.New("no secret bound to trigger")
	}
	sec, err := r.Vault.Get(ctx, trig.SecretID)
	if err != nil {
		return fmt.Errorf("vault get: %w", err)
	}
	key := sec.Reveal()

	switch provider {
	case ProviderAutomationV1:
		return verifyAutomationV1(h, body, key, r.now())
	case ProviderHashV1:
		return verifyHashV1(h, body, key, r.now())
	case "stripe":
		return verifyStripe(h.Get("Stripe-Signature"), body, key, r.now())
	case "github":
		return verifyGitHub(h.Get("X-Hub-Signature-256"), body, key)
	case "generic":
		return verifyGeneric(h.Get("X-Webhook-Signature"), body, key)
	default:
		return fmt.Errorf("unsupported webhook provider %q", provider)
	}
}

// verifyHashV1 validates Hash's strict, timestamped lifecycle-callback
// signature. The one accepted header shape is exactly:
//
//	X-Hash-Signature: t=<unix>,v1=<64 lower-case hex characters>
//
// The MAC input uses the exact received body bytes; JSON decoding happens only
// after authentication and cannot change what was signed.
func verifyHashV1(h http.Header, body, key []byte, now time.Time) error {
	header, err := singleRequiredHeader(h, "X-Hash-Signature")
	if err != nil {
		return err
	}
	parts := strings.Split(header, ",")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "t=") || !strings.HasPrefix(parts[1], "v1=") {
		return errors.New("malformed X-Hash-Signature")
	}
	timestamp := strings.TrimPrefix(parts[0], "t=")
	signatureHex := strings.TrimPrefix(parts[1], "v1=")
	if timestamp == "" || !isASCIIDigits(timestamp) || !isLowerHexDigest(signatureHex) {
		return errors.New("malformed X-Hash-Signature")
	}

	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || strconv.FormatInt(seconds, 10) != timestamp {
		return errors.New("malformed X-Hash-Signature")
	}
	signedAt := time.Unix(seconds, 0)
	if signedAt.Before(now.Add(-hashSkew)) || signedAt.After(now.Add(hashSkew)) {
		return errors.New("X-Hash-Signature timestamp outside skew window")
	}

	got, err := hex.DecodeString(signatureHex)
	if err != nil { // isLowerHexDigest already checked; retain fail-closed parsing.
		return errors.New("malformed X-Hash-Signature")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write(body)
	if subtle.ConstantTimeCompare(got, mac.Sum(nil)) != 1 {
		return errors.New("signature mismatch")
	}
	return nil
}

func isASCIIDigits(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func isLowerHexDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

// verifyAutomationV1 validates the versioned automation envelope. Both the
// delivery ID and the timestamp are covered by the MAC, preventing an attacker
// from replaying a captured body/signature under a fresh deduplication key.
func verifyAutomationV1(h http.Header, body, key []byte, now time.Time) error {
	timestamp, err := singleRequiredHeader(h, "X-Webhook-Timestamp")
	if err != nil {
		return err
	}
	deliveryID, err := singleRequiredHeader(h, "X-Webhook-Delivery")
	if err != nil {
		return err
	}
	if err := validateDeliveryID(deliveryID); err != nil {
		return err
	}
	signature, err := singleRequiredHeader(h, "X-Webhook-Signature")
	if err != nil {
		return err
	}

	if timestamp != strings.TrimSpace(timestamp) {
		return errors.New("malformed X-Webhook-Timestamp")
	}
	for _, char := range timestamp {
		if char < '0' || char > '9' {
			return errors.New("malformed X-Webhook-Timestamp")
		}
	}
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return errors.New("malformed X-Webhook-Timestamp")
	}
	signedAt := time.Unix(seconds, 0)
	if signedAt.Before(now.Add(-automationSkew)) || signedAt.After(now.Add(automationSkew)) {
		return errors.New("X-Webhook-Timestamp outside skew window")
	}

	const prefix = "sha256="
	if !strings.HasPrefix(signature, prefix) {
		return errors.New("malformed X-Webhook-Signature")
	}
	signatureHex := strings.TrimPrefix(signature, prefix)
	if !isLowerHexDigest(signatureHex) {
		return errors.New("malformed X-Webhook-Signature")
	}
	got, err := hex.DecodeString(signatureHex)
	if err != nil { // isLowerHexDigest already checked; retain fail-closed parsing.
		return errors.New("malformed X-Webhook-Signature")
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write([]byte(deliveryID))
	mac.Write([]byte{'.'})
	mac.Write(body)
	if subtle.ConstantTimeCompare(got, mac.Sum(nil)) != 1 {
		return errors.New("signature mismatch")
	}
	return nil
}

// requireAutomationJSONContentType keeps automation-v1's media-type contract
// provider-specific. Generic/GitHub/Stripe/Hash triggers retain their existing
// behavior because only automation-v1 calls this helper.
func requireAutomationJSONContentType(values []string) error {
	if len(values) != 1 {
		return errors.New("exactly one Content-Type: application/json header is required")
	}
	mediaType, parameters, err := mime.ParseMediaType(values[0])
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return errors.New("Content-Type must be application/json")
	}
	if len(parameters) == 0 {
		return nil
	}
	charset, ok := parameters["charset"]
	if len(parameters) != 1 || !ok || !strings.EqualFold(charset, "utf-8") {
		return errors.New("Content-Type must use UTF-8 JSON")
	}
	return nil
}

func validateDeliveryID(deliveryID string) error {
	if deliveryID == "" || len(deliveryID) > 200 || !utf8.ValidString(deliveryID) ||
		deliveryID != strings.TrimSpace(deliveryID) {
		return errors.New("invalid delivery id")
	}
	for _, char := range deliveryID {
		if unicode.IsControl(char) {
			return errors.New("invalid delivery id")
		}
	}
	return nil
}

func singleRequiredHeader(h http.Header, name string) (string, error) {
	values := h.Values(name)
	if len(values) != 1 || values[0] == "" {
		return "", fmt.Errorf("missing or repeated %s", name)
	}
	return values[0], nil
}

// validateAutomationEventID requires exactly one top-level event_id string and
// binds it to the already authenticated delivery header. Decoding each value as
// RawMessage preserves duplicate keys for detection while safely skipping
// arbitrary nested JSON without recursive application code.
func validateAutomationEventID(body []byte, deliveryID string) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return errors.New("body must be one JSON object")
	}

	var eventID *string
	count := 0
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return errors.New("malformed JSON object")
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("malformed JSON object key")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return errors.New("malformed JSON value")
		}
		if key != "event_id" {
			continue
		}
		count++
		if count > 1 {
			return errors.New("duplicate top-level event_id")
		}
		if err := json.Unmarshal(value, &eventID); err != nil || eventID == nil || *eventID == "" {
			return errors.New("event_id must be a non-empty string")
		}
	}
	if _, err := dec.Token(); err != nil {
		return errors.New("malformed JSON object")
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("body must contain exactly one JSON value")
	}
	if count != 1 || eventID == nil {
		return errors.New("missing top-level event_id")
	}
	if *eventID != deliveryID {
		return errors.New("event_id does not match X-Webhook-Delivery")
	}
	return nil
}

// hashEventID returns Hash's one authenticated delivery identifier. Hash puts
// event_id in the signed JSON rather than a separate delivery header, so this
// parser rejects ambiguity (including escaped duplicate keys) and trailing JSON
// before the value can enter the durable deduplication key.
func hashEventID(body []byte) (string, error) {
	if !utf8.Valid(body) {
		return "", errors.New("body must be valid UTF-8 JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return "", errors.New("body must be one JSON object")
	}

	var eventID *string
	count := 0
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return "", errors.New("malformed JSON object")
		}
		key, ok := keyToken.(string)
		if !ok {
			return "", errors.New("malformed JSON object key")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return "", errors.New("malformed JSON value")
		}
		if key != "event_id" {
			continue
		}
		count++
		if count > 1 {
			return "", errors.New("duplicate top-level event_id")
		}
		if err := json.Unmarshal(value, &eventID); err != nil || eventID == nil || *eventID == "" {
			return "", errors.New("event_id must be a non-empty string")
		}
	}
	if _, err := dec.Token(); err != nil {
		return "", errors.New("malformed JSON object")
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return "", errors.New("body must contain exactly one JSON value")
	}
	if count != 1 || eventID == nil {
		return "", errors.New("missing top-level event_id")
	}
	if err := validateDeliveryID(*eventID); err != nil {
		return "", errors.New("invalid event_id")
	}
	return *eventID, nil
}

// verifyStripe parses "t=<unix>,v1=<hex>[,v0=<hex>]" headers, recomputes
// HMAC-SHA256 over "<t>.<body>", and compares constant-time. Rejects when
// the timestamp is older than the skew window.
func verifyStripe(header string, body, key []byte, now time.Time) error {
	if header == "" {
		return errors.New("missing Stripe-Signature")
	}
	var (
		ts         string
		signatures []string
	)
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			ts = kv[1]
		case "v1":
			signatures = append(signatures, kv[1])
		}
	}
	if ts == "" || len(signatures) == 0 {
		return errors.New("malformed Stripe-Signature")
	}
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return fmt.Errorf("bad timestamp: %w", err)
	}
	skew := now.Sub(time.Unix(tsInt, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > stripeSkew {
		return fmt.Errorf("timestamp outside skew window: %s", skew)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)
	want := mac.Sum(nil)
	for _, s := range signatures {
		got, err := hex.DecodeString(s)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare(got, want) == 1 {
			return nil
		}
	}
	return errors.New("no v1 signature matched")
}

// verifyGitHub validates "sha256=<hex>" against HMAC-SHA256(body, key).
func verifyGitHub(header string, body, key []byte) error {
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return errors.New("missing or malformed X-Hub-Signature-256")
	}
	got, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return fmt.Errorf("bad hex: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	want := mac.Sum(nil)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return errors.New("signature mismatch")
	}
	return nil
}

// verifyGeneric validates "sha256=<hex>" or bare "<hex>" against
// HMAC-SHA256(body, key). The bare form is convenient for clients that
// can't set a custom prefix.
func verifyGeneric(header string, body, key []byte) error {
	header = strings.TrimSpace(header)
	if header == "" {
		return errors.New("missing X-Webhook-Signature")
	}
	header = strings.TrimPrefix(header, "sha256=")
	got, err := hex.DecodeString(header)
	if err != nil {
		return fmt.Errorf("bad hex: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	want := mac.Sum(nil)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return errors.New("signature mismatch")
	}
	return nil
}

// pickDeliveryID resolves a stable delivery identifier for dedup. Providers
// that supply one in headers win; otherwise the SHA-256 of the body is used.
func pickDeliveryID(provider string, h http.Header, body []byte) string {
	switch provider {
	case ProviderHashV1:
		if id, err := hashEventID(body); err == nil {
			return id
		}
		// handle validates hash-v1 JSON before reaching this helper. Keep a
		// deterministic fallback for defensive/internal callers.
		return sha256Hex(body)
	case "stripe":
		// Stripe doesn't ship a delivery header on every event type; fall
		// back to the body hash. Real Stripe payloads include "id" in JSON
		// which we could parse, but parsing JSON in dedup adds attack
		// surface; the body hash is uniform across event shapes.
		return sha256Hex(body)
	case "github":
		if id := h.Get("X-GitHub-Delivery"); id != "" {
			return id
		}
		return sha256Hex(body)
	case ProviderAutomationV1, "generic":
		if id := h.Get("X-Webhook-Delivery"); id != "" {
			return id
		}
		return sha256Hex(body)
	default:
		return sha256Hex(body)
	}
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
