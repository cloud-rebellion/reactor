// Package commandwebhook is the authenticated HTTP ingress for command
// automations. It is intentionally separate from workflow webhook dispatch:
// the token namespace, durable binding, runner admission, and queue handoff
// are all command-specific. The signed request body is used only for HMAC and
// delivery deduplication; it is never copied into a command run or shell
// environment by this receiver.
package commandwebhook

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/commandrunner"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/webhook"
	"github.com/bright-interaction/reactor/internal/vault"
)

const (
	maxBodyBytes       = 1 << 20
	deliveryLease      = 5 * time.Minute
	deliveryWriteLimit = 10 * time.Second
)

// VaultReader is the narrow secret lookup needed for HMAC verification.
type VaultReader interface {
	Get(context.Context, string) (*vault.Secret, error)
}

// Receiver wires the dedicated command ingress to the durable journal and
// command queue. TenantID is mandatory: this daemon runs one command runner
// tenant, so a token from another tenant is indistinguishable from not found.
type Receiver struct {
	Journal  *journal.Journal
	Vault    VaultReader
	Runner   *commandrunner.Runner
	Queue    *commandrunner.Queue
	TenantID string
	Log      *slog.Logger
	Now      func() time.Time
}

// Mount registers POST /command-webhook/{token_id}. Workflow webhook routes
// remain owned by internal/runtime/webhook and use a different token lookup.
func (r *Receiver) Mount(router chi.Router) {
	router.Post("/command-webhook/{token_id}", r.handle)
}

// Handler returns the bare handler for tests and custom routers.
func (r *Receiver) Handler() http.HandlerFunc { return r.handle }

func (r *Receiver) handle(w http.ResponseWriter, req *http.Request) {
	setNoStoreResponseHeaders(w)
	log := r.Log
	if log == nil {
		log = slog.Default()
	}
	if r.Journal == nil || r.Vault == nil || r.Runner == nil || r.Queue == nil || strings.TrimSpace(r.TenantID) == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	tokenID := strings.TrimSpace(chi.URLParam(req, "token_id"))
	if tokenID == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	trigger, err := r.Journal.FindActiveCommandAutomationWebhookByToken(req.Context(), tokenID)
	if err != nil || trigger.TenantID != strings.TrimSpace(r.TenantID) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxBodyBytes))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	provider := trigger.Provider
	if provider == "" {
		provider = "generic"
	}
	if provider == webhook.ProviderAutomationV1 {
		if err := webhook.RequireAutomationJSONContentType(req.Header.Values("Content-Type")); err != nil {
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
	}
	secretTenant, err := r.Journal.SecretTenant(req.Context(), trigger.SecretID)
	if err != nil || secretTenant != trigger.TenantID {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	secret, err := r.Vault.Get(req.Context(), trigger.SecretID)
	if err != nil || secret == nil {
		log.Warn("command webhook: secret lookup failed", "trigger_id", trigger.ID, "err", err)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	key := append([]byte(nil), secret.Reveal()...)
	verifyErr := webhook.VerifySignedPayload(provider, req.Header, body, key, r.now())
	clearBytes(key)
	if verifyErr != nil {
		log.Warn("command webhook: signature verification failed", "trigger_id", trigger.ID, "provider", provider, "err", verifyErr)
		_ = r.Journal.MarkCommandAutomationWebhookError(req.Context(), trigger.TenantID, trigger.ID, "signature verification failed")
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	if provider == webhook.ProviderAutomationV1 {
		deliveryHeader := req.Header.Get("X-Webhook-Delivery")
		if err := webhook.ValidateAutomationEventID(body, deliveryHeader); err != nil {
			_ = r.Journal.MarkCommandAutomationWebhookError(req.Context(), trigger.TenantID, trigger.ID, "invalid automation event envelope")
			http.Error(w, "invalid automation event", http.StatusBadRequest)
			return
		}
	}
	if provider == webhook.ProviderHashV1 {
		if _, err := webhook.HashEventID(body); err != nil {
			_ = r.Journal.MarkCommandAutomationWebhookError(req.Context(), trigger.TenantID, trigger.ID, "invalid Hash event envelope")
			http.Error(w, "invalid event", http.StatusBadRequest)
			return
		}
	}
	// Command ingress uses a body-bound identity for generic and GitHub
	// providers. Their delivery headers are not included in the body HMAC, so
	// trusting them would allow one valid signed body to be replayed as an
	// unbounded sequence of distinct command runs.
	deliveryID := webhook.PickCommandDeliveryID(provider, req.Header, body)
	if err := webhook.ValidateDeliveryID(deliveryID); err != nil {
		http.Error(w, "invalid delivery", http.StatusBadRequest)
		return
	}
	payloadHash := sha256.Sum256(body)
	claim, err := r.Journal.ClaimWebhookDelivery(req.Context(), trigger.ID, provider, deliveryID, hex.EncodeToString(payloadHash[:]), r.now().UTC(), deliveryLease)
	if err != nil {
		log.Error("command webhook: delivery claim failed", "trigger_id", trigger.ID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	switch claim.State {
	case journal.WebhookDeliveryCompleted:
		writeReceipt(w, http.StatusOK, true, claim.RunID)
		return
	case journal.WebhookDeliveryInProgress:
		w.Header().Set("Retry-After", "5")
		http.Error(w, "delivery in progress; retry later", http.StatusServiceUnavailable)
		return
	case journal.WebhookDeliveryPayloadMismatch:
		http.Error(w, "delivery id reused with different payload", http.StatusConflict)
		return
	case journal.WebhookDeliveryClaimed:
		// Continue with the one owner elected by the journal.
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	result, err := r.Runner.AdmitWebhook(req.Context(), commandrunner.Request{
		TenantID: trigger.TenantID, AutomationID: trigger.AutomationID, Version: trigger.AutomationVersion,
		TriggerID: trigger.ID, TriggerEventID: deliveryID,
	}, trigger)
	if err != nil {
		log.Warn("command webhook: command admission failed", "trigger_id", trigger.ID, "err", err)
		_ = r.Journal.MarkCommandAutomationWebhookError(req.Context(), trigger.TenantID, trigger.ID, "command admission failed")
		r.release(req.Context(), trigger, provider, deliveryID, claim.ClaimToken)
		w.Header().Set("Retry-After", "30")
		http.Error(w, "command unavailable; retry later", http.StatusServiceUnavailable)
		return
	}
	queueReq := commandrunner.Request{
		TenantID: trigger.TenantID, AutomationID: trigger.AutomationID, Version: trigger.AutomationVersion,
		RunID: result.Run.ID, Admission: result.Run.Admission, TriggerKind: journal.CommandRunTriggerWebhook,
		TriggerID: trigger.ID, TriggerEventID: deliveryID,
	}
	if err := r.Queue.Enqueue(req.Context(), queueReq); err != nil && !errors.Is(err, commandrunner.ErrQueueFull) {
		log.Warn("command webhook: queue handoff failed", "trigger_id", trigger.ID, "run_id", result.Run.ID, "err", err)
		_ = r.Journal.MarkCommandAutomationWebhookError(req.Context(), trigger.TenantID, trigger.ID, "command queue unavailable")
		r.release(req.Context(), trigger, provider, deliveryID, claim.ClaimToken)
		http.Error(w, "command unavailable; retry later", http.StatusServiceUnavailable)
		return
	}
	if !r.complete(req.Context(), trigger, provider, deliveryID, claim.ClaimToken, result.Run.ID) {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := r.Journal.MarkCommandAutomationWebhookFired(req.Context(), trigger.TenantID, trigger.ID); err != nil {
		log.Warn("command webhook: mark fired failed", "trigger_id", trigger.ID, "err", err)
	}
	writeReceipt(w, http.StatusAccepted, false, result.Run.ID)
}

func (r *Receiver) release(ctx context.Context, trigger journal.CommandAutomationWebhookTrigger, provider, deliveryID, claimToken string) {
	durable, cancel := context.WithTimeout(context.WithoutCancel(ctx), deliveryWriteLimit)
	defer cancel()
	if err := r.Journal.ReleaseWebhookDelivery(durable, trigger.ID, provider, deliveryID, claimToken); err != nil {
		if r.Log != nil {
			r.Log.Warn("command webhook: release claim failed", "trigger_id", trigger.ID, "err", err)
		}
	}
}

func (r *Receiver) complete(ctx context.Context, trigger journal.CommandAutomationWebhookTrigger, provider, deliveryID, claimToken, runID string) bool {
	durable, cancel := context.WithTimeout(context.WithoutCancel(ctx), deliveryWriteLimit)
	defer cancel()
	if err := r.Journal.CompleteWebhookDelivery(durable, trigger.ID, provider, deliveryID, claimToken, runID, r.now().UTC()); err != nil {
		if r.Log != nil {
			r.Log.Error("command webhook: complete claim failed", "trigger_id", trigger.ID, "run_id", runID, "err", err)
		}
		return false
	}
	return true
}

func (r *Receiver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func writeReceipt(w http.ResponseWriter, status int, deduped bool, runID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"accepted": true, "deduped": deduped, "run_id": runID})
}

// setNoStoreResponseHeaders keeps public command receipts and errors out of
// browser or intermediary caches. A receipt includes a run id tied to a
// bearer webhook capability and must not survive capability rotation.
func setNoStoreResponseHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}
