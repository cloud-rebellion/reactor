package flare

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	reactor "github.com/bright-interaction/reactor/sdk"
)

// DraftConfig belongs to the reviewed workflow source. Neither a webhook nor
// a Flare response may select the origin or project used for evidence reads.
type DraftConfig struct {
	BaseURL   string
	ProjectID string
}

// ClientFactory resolves the workflow's scoped vault credential only when an
// evidence step executes. Completed step replay never needs a live secret.
// A factory must not log credentials or return them as a step result.
type ClientFactory func(context.Context) (*Client, error)

// PrepareDraft creates a reviewable, payload-free Reactor step result from a
// Flare incident. Triage is one separately journaled step with no automatic
// retry: an ambiguous provider response must not silently spend a second AI
// call. The receipt read can retry without repeating triage. Reactor's signed
// webhook dedup prevents a duplicate notice from starting a second run.
// A provider call interrupted before its receipt is journaled is ambiguous:
// reconcile Flare's receipts before manually redriving that run.
func PrepareDraft(ctx context.Context, flow reactor.Flow, config DraftConfig, notice Notice, factory ClientFactory) (Draft, error) {
	origin, err := trustedOrigin(config.BaseURL, config.ProjectID)
	if err != nil || flow == nil || factory == nil || !notice.validFor(config.ProjectID) {
		return Draft{}, ErrInvalidNotice
	}
	if notice.IssueID == "" || notice.Event == "test" {
		return Draft{}, ErrNoIssue
	}
	clientForStep := func(ctx context.Context) (*Client, error) {
		client, err := factory(ctx)
		// Factory errors can contain secret-provider diagnostics. Keep those
		// out of durable errors and recheck the factory's captured trust scope.
		if err != nil || client == nil || client.baseURL != origin || client.projectID != config.ProjectID || client.http == nil {
			return nil, errors.New("scoped Flare evidence client is unavailable")
		}
		return client, nil
	}
	key := notice.DeliveryKey()
	fresh, err := reactor.Step(flow, ctx, "flare-fresh-triage", reactor.StepOpts{
		IdempotencyKey: key, InputHash: draftInputHash(origin, config.ProjectID, key, FreshTriage{}), Timeout: 65 * time.Second,
	}, func(ctx context.Context) (FreshTriage, error) {
		client, err := clientForStep(ctx)
		if err != nil {
			return FreshTriage{}, reactor.Permanent(err)
		}
		return client.TriageFresh(ctx, notice.IssueID)
	})
	if err != nil {
		return Draft{}, fmt.Errorf("Flare fresh triage: %w", err)
	}
	if !validDigest(fresh.EvidenceDigest) || !validID(fresh.AIReceiptID, true) {
		return Draft{}, ErrFreshTriage
	}
	draft, err := reactor.Step(flow, ctx, "flare-confirm-draft", reactor.StepOpts{
		IdempotencyKey: key, InputHash: draftInputHash(origin, config.ProjectID, key, fresh), Timeout: 10 * time.Second,
		RetryPolicy: reactor.ExpBackoff{Max: 4, Base: 250 * time.Millisecond, Cap: time.Second},
	}, func(ctx context.Context) (Draft, error) {
		client, err := clientForStep(ctx)
		if err != nil {
			return Draft{}, reactor.Permanent(err)
		}
		result, err := client.ConfirmDraft(ctx, notice, fresh)
		if errors.Is(err, ErrReceiptPending) {
			return Draft{}, reactor.Retryable(err)
		}
		if err != nil {
			return Draft{}, reactor.Permanent(err)
		}
		return result, nil
	})
	if err != nil {
		return Draft{}, fmt.Errorf("Flare draft evidence: %w", err)
	}
	if draft != (&Client{baseURL: origin, projectID: config.ProjectID}).draft(notice, fresh) {
		return Draft{}, ErrReceiptMismatch
	}
	return draft, nil
}

func draftInputHash(origin, projectID, deliveryKey string, fresh FreshTriage) string {
	input, _ := json.Marshal(struct {
		Origin, ProjectID, DeliveryKey string
		Fresh                          FreshTriage
	}{origin, projectID, deliveryKey, fresh})
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:])
}
