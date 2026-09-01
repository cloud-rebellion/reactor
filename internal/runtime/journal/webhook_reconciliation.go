package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// WebhookDeliveryRun is the deliberately small run view exposed to the
// signed webhook reconciliation endpoint. It omits tenant, workflow, trigger
// metadata, errors, and logs because producers need only the durable run ID
// and its state.
type WebhookDeliveryRun struct {
	RunID  string
	Status string
}

// FindCompletedWebhookDeliveryRun resolves one completed delivery receipt to
// the run it durably created. Every ownership dimension is bound in the same
// query: trigger, provider, delivery, workflow, tenant, and trigger kind. An
// incomplete receipt or a stale/mismatched run reference is indistinguishable
// from a nonexistent delivery and returns ErrNotFound.
func (j *Journal) FindCompletedWebhookDeliveryRun(
	ctx context.Context,
	triggerID, provider, deliveryID string,
) (WebhookDeliveryRun, error) {
	if triggerID == "" || provider == "" || deliveryID == "" {
		return WebhookDeliveryRun{}, ErrNotFound
	}

	const q = `SELECT r.id, r.status
		FROM webhook_deliveries d
		JOIN triggers t ON t.id = d.trigger_id
		JOIN runs r ON r.id = d.run_id
		WHERE d.trigger_id = $1
		  AND d.provider = $2
		  AND d.delivery_id = $3
		  AND d.completed_at IS NOT NULL
		  AND d.run_id IS NOT NULL
		  AND t.kind = 'webhook'
		  AND t.provider = d.provider
		  AND t.workflow_id = r.workflow_id
		  AND t.tenant_id = r.tenant_id
		  AND r.trigger_kind = 'webhook'
		LIMIT 1`
	var result WebhookDeliveryRun
	err := j.db.QueryRowContext(ctx, j.bind(q), triggerID, provider, deliveryID).
		Scan(&result.RunID, &result.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return WebhookDeliveryRun{}, ErrNotFound
	}
	if err != nil {
		return WebhookDeliveryRun{}, fmt.Errorf("journal: find completed webhook delivery run: %w", err)
	}
	return result, nil
}
