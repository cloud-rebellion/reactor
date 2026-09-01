package journal

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// TriggerKind enumerates the supported trigger sources. Webhook + cron land
// in week 5; cdc + docker + manual ride along on the same table.
type TriggerKind string

const (
	TriggerWebhook          TriggerKind = "webhook"
	TriggerCron             TriggerKind = "cron"
	TriggerManual           TriggerKind = "manual"
	TriggerCDC              TriggerKind = "cdc"
	TriggerDocker           TriggerKind = "docker"
	TriggerWorkflowComplete TriggerKind = "workflow_complete"
)

// Trigger is a row from the triggers table. The webhook fields (TokenID,
// SecretID, Provider) are populated only for webhook triggers.
type Trigger struct {
	ID          string
	TenantID    string
	WorkflowID  string
	Kind        TriggerKind
	Config      []byte // JSON
	State       string
	TokenID     string
	SecretID    string
	Provider    string
	LastFiredAt *time.Time
	LastError   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// CreateWebhookTrigger registers a webhook binding. tokenID is the public
// URL component (POST /webhook/{tokenID}); the caller is responsible for
// generating one via NewTokenID. secretID points at a vault credential
// holding the HMAC shared secret.
func (j *Journal) CreateWebhookTrigger(ctx context.Context, workflowID, tokenID, secretID, provider string, config []byte) (string, error) {
	id, err := newID("trg_")
	if err != nil {
		return "", err
	}
	cfg := outputArg(config, j.engine)
	if cfg == nil {
		cfg = "{}"
		if j.engine != EngineSQLite {
			cfg = []byte("{}")
		}
	}
	// Derive tenant_id from the workflow row in the same statement. Callers must
	// not be able to place a trigger in a tenant merely by supplying a tenant
	// string, and omitting the column would silently use the schema's "default"
	// tenant for every non-default workflow.
	const q = `INSERT INTO triggers
		(id, tenant_id, workflow_id, kind, config_json, state, token_id, secret_id, provider)
		SELECT $1, tenant_id, id, 'webhook', $2, 'active', $3, $4, $5
		FROM workflows WHERE id = $6`
	res, err := j.db.ExecContext(ctx, j.bind(q),
		id, cfg, tokenID, secretID, nullable(provider), workflowID,
	)
	if err != nil {
		return "", fmt.Errorf("journal: create webhook trigger: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("journal: create webhook trigger rows affected: %w", err)
	}
	if n != 1 {
		return "", ErrNotFound
	}
	return id, nil
}

// FindWebhookByToken resolves a public token to its trigger row. Returns
// ErrNotFound if no active webhook trigger exists with that token.
func (j *Journal) FindWebhookByToken(ctx context.Context, tokenID string) (Trigger, error) {
	const q = `SELECT id, tenant_id, workflow_id, kind, config_json, state,
		token_id, secret_id, provider, last_fired_at, last_error, created_at, updated_at
		FROM triggers WHERE token_id = $1 AND state = 'active' AND kind = 'webhook' LIMIT 1`
	row := j.db.QueryRowContext(ctx, j.bind(q), tokenID)
	return j.scanTrigger(row)
}

// MarkTriggerFired updates last_fired_at + clears last_error. Called on
// successful dispatch.
func (j *Journal) MarkTriggerFired(ctx context.Context, id string) error {
	const q = `UPDATE triggers SET last_fired_at = $1, last_error = NULL, updated_at = $2 WHERE id = $3`
	now := j.now()
	_, err := j.db.ExecContext(ctx, j.bind(q), now, now, id)
	return err
}

// SetTriggerState flips a trigger between 'active' and 'disabled'.
// Used by the cron live-reload + the webhook CLI's enable/disable
// subcommands so an operator can pause a trigger without deleting it.
func (j *Journal) SetTriggerState(ctx context.Context, id, state string) error {
	const q = `UPDATE triggers SET state = $1, updated_at = $2 WHERE id = $3`
	_, err := j.db.ExecContext(ctx, j.bind(q), state, j.now(), id)
	if err != nil {
		return fmt.Errorf("journal: set trigger state: %w", err)
	}
	return nil
}

// SetTriggerStateForWorkflow changes a trigger only when it belongs to the
// workflow the caller already authorized. Dashboard routes contain both a
// workflow slug and a trigger id; binding both identifiers in the mutation
// prevents a tenant member from pairing their own slug with another tenant's
// trigger id. A missing or mismatched row is deliberately indistinguishable.
func (j *Journal) SetTriggerStateForWorkflow(ctx context.Context, id, workflowID, state string) error {
	const q = `UPDATE triggers SET state = $1, updated_at = $2
		WHERE id = $3 AND workflow_id = $4`
	res, err := j.db.ExecContext(ctx, j.bind(q), state, j.now(), id, workflowID)
	if err != nil {
		return fmt.Errorf("journal: set trigger state for workflow: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("journal: set trigger state for workflow rows affected: %w", err)
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

// MarkTriggerError stores last_error for dashboard surfacing. Successful
// later fires clear it via MarkTriggerFired.
func (j *Journal) MarkTriggerError(ctx context.Context, id, msg string) error {
	const q = `UPDATE triggers SET last_error = $1, updated_at = $2 WHERE id = $3`
	_, err := j.db.ExecContext(ctx, j.bind(q), msg, j.now(), id)
	return err
}

// WebhookDeliveryClaimState is the durable state returned when a receiver
// tries to own one provider delivery.
type WebhookDeliveryClaimState string

const (
	// WebhookDeliveryClaimed means this caller owns ClaimToken until
	// LeaseExpiresAt and may dispatch the workflow.
	WebhookDeliveryClaimed WebhookDeliveryClaimState = "claimed"
	// WebhookDeliveryCompleted means an earlier owner already created the run.
	// The receiver can acknowledge the provider without dispatching again.
	WebhookDeliveryCompleted WebhookDeliveryClaimState = "completed"
	// WebhookDeliveryInProgress means another live lease owns the delivery.
	// The receiver must not falsely acknowledge it as complete: if that owner
	// crashes, a retry after LeaseExpiresAt is how the delivery recovers.
	WebhookDeliveryInProgress WebhookDeliveryClaimState = "in_progress"
	// WebhookDeliveryPayloadMismatch means one delivery id was reused for a
	// different request body. Treating it as a replay would silently lose data.
	WebhookDeliveryPayloadMismatch WebhookDeliveryClaimState = "payload_mismatch"
)

// WebhookDeliveryClaim is the result of ClaimWebhookDelivery. ClaimToken is
// populated only for the owner; RunID is populated for a completed receipt
// when the dispatcher supplied one.
type WebhookDeliveryClaim struct {
	State          WebhookDeliveryClaimState
	ClaimToken     string
	LeaseExpiresAt time.Time
	RunID          string
}

// ErrWebhookDeliveryClaimLost means a completion/release caller no longer
// owns the row. A retry may have reclaimed an expired lease; token-guarded
// writes prevent the stale owner from deleting or completing the new claim.
var ErrWebhookDeliveryClaimLost = errors.New("journal: webhook delivery claim lost")

// ClaimWebhookDelivery leases one verified delivery to exactly one receiver.
//
// The old RecordWebhookDelivery permanently inserted a dedup row before the
// dispatcher created a durable run. A process crash in that gap caused every
// provider retry to return dedup success even though the workflow never ran.
// A lease makes that gap recoverable: an expired, incomplete row can be
// reclaimed. This is deliberately at-least-once after a crash occurring after
// dispatch but before CompleteWebhookDelivery; downstream effects must use
// their own idempotency key (the provider delivery id is the natural choice).
func (j *Journal) ClaimWebhookDelivery(
	ctx context.Context,
	triggerID, provider, deliveryID, payloadSHA256 string,
	now time.Time,
	lease time.Duration,
) (WebhookDeliveryClaim, error) {
	if lease <= 0 {
		return WebhookDeliveryClaim{}, errors.New("journal: webhook delivery lease must be positive")
	}
	now = now.UTC()
	expires := now.Add(lease)

	// A release can race this method between its failed INSERT and SELECT. Loop
	// a few times so that benign race becomes a fresh claim instead of an
	// internal error. Each mutation remains guarded by the composite key and,
	// for reclaim, the observed expiry predicate.
	for attempt := 0; attempt < 4; attempt++ {
		claimToken, err := newID("whc_")
		if err != nil {
			return WebhookDeliveryClaim{}, err
		}
		const insertQ = `INSERT INTO webhook_deliveries
			(trigger_id, provider, delivery_id, received_at, payload_sha256, claim_token, lease_expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT DO NOTHING`
		res, err := j.db.ExecContext(ctx, j.bind(insertQ),
			triggerID, provider, deliveryID, j.formatTime(now), payloadSHA256, claimToken, j.formatTime(expires))
		if err != nil {
			return WebhookDeliveryClaim{}, fmt.Errorf("journal: claim webhook delivery: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			// Assuming ownership when the driver cannot prove the INSERT won can
			// double-dispatch. Fail closed and let the provider retry instead.
			return WebhookDeliveryClaim{}, fmt.Errorf("journal: claim webhook delivery rows affected: %w", err)
		}
		if n > 0 {
			return WebhookDeliveryClaim{
				State:          WebhookDeliveryClaimed,
				ClaimToken:     claimToken,
				LeaseExpiresAt: expires,
			}, nil
		}

		// One atomic conditional UPDATE elects at most one owner when an old
		// lease expires. Match the digest here so a reused id cannot overwrite
		// the evidence of which payload originally claimed it.
		const reclaimQ = `UPDATE webhook_deliveries
			SET claim_token = $1, lease_expires_at = $2, run_id = NULL
			WHERE trigger_id = $3 AND provider = $4 AND delivery_id = $5
			  AND completed_at IS NULL
			  AND (lease_expires_at IS NULL OR lease_expires_at <= $6)
			  AND payload_sha256 = $7`
		res, err = j.db.ExecContext(ctx, j.bind(reclaimQ),
			claimToken, j.formatTime(expires), triggerID, provider, deliveryID,
			j.formatTime(now), payloadSHA256)
		if err != nil {
			return WebhookDeliveryClaim{}, fmt.Errorf("journal: reclaim webhook delivery: %w", err)
		}
		n, err = res.RowsAffected()
		if err != nil {
			return WebhookDeliveryClaim{}, fmt.Errorf("journal: reclaim webhook delivery rows affected: %w", err)
		}
		if n > 0 {
			return WebhookDeliveryClaim{
				State:          WebhookDeliveryClaimed,
				ClaimToken:     claimToken,
				LeaseExpiresAt: expires,
			}, nil
		}

		const selectQ = `SELECT payload_sha256, lease_expires_at, completed_at, run_id
			FROM webhook_deliveries
			WHERE trigger_id = $1 AND provider = $2 AND delivery_id = $3`
		var (
			storedHash     string
			leaseExpiresDB sql.NullString
			completedDB    sql.NullString
			runIDDB        sql.NullString
		)
		err = j.db.QueryRowContext(ctx, j.bind(selectQ), triggerID, provider, deliveryID).
			Scan(&storedHash, &leaseExpiresDB, &completedDB, &runIDDB)
		if errors.Is(err, sql.ErrNoRows) {
			continue // the current owner released between our INSERT and SELECT
		}
		if err != nil {
			return WebhookDeliveryClaim{}, fmt.Errorf("journal: inspect webhook delivery: %w", err)
		}
		// Empty is the legacy sentinel for receipts migrated from 0027: their
		// body was never stored or hashed, so they remain completed replays but
		// cannot participate in payload-mismatch detection retroactively.
		if storedHash != "" && storedHash != payloadSHA256 {
			return WebhookDeliveryClaim{State: WebhookDeliveryPayloadMismatch}, nil
		}
		if completedDB.Valid {
			return WebhookDeliveryClaim{State: WebhookDeliveryCompleted, RunID: runIDDB.String}, nil
		}
		var leaseExpires time.Time
		if leaseExpiresDB.Valid {
			leaseExpires, err = j.parseTime(leaseExpiresDB.String)
			if err != nil {
				return WebhookDeliveryClaim{}, fmt.Errorf("journal: parse webhook lease expiry: %w", err)
			}
		}
		return WebhookDeliveryClaim{
			State:          WebhookDeliveryInProgress,
			LeaseExpiresAt: leaseExpires,
		}, nil
	}
	return WebhookDeliveryClaim{}, errors.New("journal: webhook delivery changed during claim")
}

// CompleteWebhookDelivery makes a claim a permanent dedup receipt after the
// dispatcher has created the run. The claim token is mandatory: an owner that
// stalls past its lease cannot complete a newer owner's reclaimed row.
func (j *Journal) CompleteWebhookDelivery(
	ctx context.Context,
	triggerID, provider, deliveryID, claimToken, runID string,
	completedAt time.Time,
) error {
	const q = `UPDATE webhook_deliveries
		SET completed_at = $1, lease_expires_at = NULL, run_id = $2
		WHERE trigger_id = $3 AND provider = $4 AND delivery_id = $5
		  AND claim_token = $6 AND completed_at IS NULL`
	res, err := j.db.ExecContext(ctx, j.bind(q), j.formatTime(completedAt.UTC()), nullable(runID),
		triggerID, provider, deliveryID, claimToken)
	if err != nil {
		return fmt.Errorf("journal: complete webhook delivery: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("journal: complete webhook delivery rows affected: %w", err)
	}
	if n == 0 {
		return ErrWebhookDeliveryClaimLost
	}
	return nil
}

// ReleaseWebhookDelivery deletes only the caller's incomplete claim. Dispatch
// failures use it to let the provider retry immediately; a stale owner cannot
// delete a row that another request reclaimed after lease expiry.
func (j *Journal) ReleaseWebhookDelivery(
	ctx context.Context,
	triggerID, provider, deliveryID, claimToken string,
) error {
	const q = `DELETE FROM webhook_deliveries
		WHERE trigger_id = $1 AND provider = $2 AND delivery_id = $3
		  AND claim_token = $4 AND completed_at IS NULL`
	res, err := j.db.ExecContext(ctx, j.bind(q), triggerID, provider, deliveryID, claimToken)
	if err != nil {
		return fmt.Errorf("journal: release webhook delivery: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("journal: release webhook delivery rows affected: %w", err)
	}
	if n == 0 {
		return ErrWebhookDeliveryClaimLost
	}
	return nil
}

// RecordWebhookDelivery is retained for internal callers compiled against the
// pre-0028 journal surface. New receiver code must use Claim/Complete/Release.
// Preserve the old method's permanent-record semantics by completing a claim
// immediately; it is unsuitable for dispatch because it recreates the old
// crash window by design.
func (j *Journal) RecordWebhookDelivery(ctx context.Context, triggerID, provider, deliveryID string) (bool, error) {
	now := time.Now().UTC()
	claim, err := j.ClaimWebhookDelivery(ctx, triggerID, provider, deliveryID, "", now, 5*time.Minute)
	if err != nil {
		return false, err
	}
	if claim.State != WebhookDeliveryClaimed {
		return false, nil
	}
	if err := j.CompleteWebhookDelivery(ctx, triggerID, provider, deliveryID, claim.ClaimToken, "", now); err != nil {
		return false, err
	}
	return true, nil
}

// DeleteWebhookDelivery is the legacy unconditional rollback helper. The live
// receiver uses token-guarded ReleaseWebhookDelivery so an expired owner cannot
// delete a newer claim.
func (j *Journal) DeleteWebhookDelivery(ctx context.Context, triggerID, provider, deliveryID string) error {
	const q = `DELETE FROM webhook_deliveries WHERE trigger_id = $1 AND provider = $2 AND delivery_id = $3`
	if _, err := j.db.ExecContext(ctx, j.bind(q), triggerID, provider, deliveryID); err != nil {
		return fmt.Errorf("journal: delete webhook delivery: %w", err)
	}
	return nil
}

// ListTriggers returns every trigger row regardless of kind or state.
// Used by the graph builder so the AI Environment Lens sees every
// inbound source. Callers that need only active cron triggers should
// keep using ListCronTriggers.
func (j *Journal) ListTriggers(ctx context.Context) ([]Trigger, error) {
	const q = `SELECT id, tenant_id, workflow_id, kind, config_json, state,
		token_id, secret_id, provider, last_fired_at, last_error, created_at, updated_at
		FROM triggers ORDER BY created_at DESC`
	return j.scanTriggers(ctx, q)
}

// ListTriggersForWorkflow returns every trigger row bound to the given
// workflow id, newest first. Used by the dashboard's workflow detail
// page so an operator can see + manage inbound sources without dropping
// into SQL.
func (j *Journal) ListTriggersForWorkflow(ctx context.Context, workflowID string) ([]Trigger, error) {
	const q = `SELECT id, tenant_id, workflow_id, kind, config_json, state,
		token_id, secret_id, provider, last_fired_at, last_error, created_at, updated_at
		FROM triggers WHERE workflow_id = $1 ORDER BY created_at DESC`
	rows, err := j.db.QueryContext(ctx, j.bind(q), workflowID)
	if err != nil {
		return nil, fmt.Errorf("journal: list triggers by workflow: %w", err)
	}
	defer rows.Close()
	return scanTriggerRows(rows, j)
}

// DeleteTrigger removes a trigger row by id. Returns ErrNotFound when
// nothing matched so the dashboard surfaces a 404 rather than silently
// pretending success on a double-click.
func (j *Journal) DeleteTrigger(ctx context.Context, id string) error {
	const q = `DELETE FROM triggers WHERE id = $1`
	res, err := j.db.ExecContext(ctx, j.bind(q), id)
	if err != nil {
		return fmt.Errorf("journal: delete trigger: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteTriggerForWorkflow deletes a trigger only from the workflow the caller
// already authorized. Keep the unscoped DeleteTrigger for internal compensation
// and CLI paths that resolve a globally unique trigger id directly.
func (j *Journal) DeleteTriggerForWorkflow(ctx context.Context, id, workflowID string) error {
	const q = `DELETE FROM triggers WHERE id = $1 AND workflow_id = $2`
	res, err := j.db.ExecContext(ctx, j.bind(q), id, workflowID)
	if err != nil {
		return fmt.Errorf("journal: delete trigger for workflow: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("journal: delete trigger for workflow rows affected: %w", err)
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

// UpdateCronTriggerConfigForWorkflow replaces config only for a cron trigger
// owned by the authorized workflow. The kind predicate prevents a crafted edit
// request from writing cron-shaped config over a webhook verifier binding.
func (j *Journal) UpdateCronTriggerConfigForWorkflow(ctx context.Context, id, workflowID string, config []byte) error {
	cfg := outputArg(config, j.engine)
	if cfg == nil {
		cfg = "{}"
		if j.engine != EngineSQLite {
			cfg = []byte("{}")
		}
	}
	const q = `UPDATE triggers SET config_json = $1, updated_at = $2
		WHERE id = $3 AND workflow_id = $4 AND kind = 'cron'`
	res, err := j.db.ExecContext(ctx, j.bind(q), cfg, j.now(), id, workflowID)
	if err != nil {
		return fmt.Errorf("journal: update cron trigger config for workflow: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("journal: update cron trigger config for workflow rows affected: %w", err)
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

// ListCronTriggers returns every active cron trigger. Used by the cron
// driver at startup; cron-kind triggers added at runtime require a driver
// reload (week 9 wires LISTEN/NOTIFY for live reload on Postgres).
func (j *Journal) ListCronTriggers(ctx context.Context) ([]Trigger, error) {
	const q = `SELECT id, tenant_id, workflow_id, kind, config_json, state,
		token_id, secret_id, provider, last_fired_at, last_error, created_at, updated_at
		FROM triggers WHERE kind = 'cron' AND state = 'active'`
	return j.scanTriggers(ctx, q)
}

// scanTriggers is the shared body for ListTriggers + ListCronTriggers.
// Pulled out so adding a third filter doesn't trigger a fourth copy of
// the same scan loop.
func (j *Journal) scanTriggers(ctx context.Context, q string) ([]Trigger, error) {
	rows, err := j.db.QueryContext(ctx, j.bind(q))
	if err != nil {
		return nil, fmt.Errorf("journal: list triggers: %w", err)
	}
	defer rows.Close()
	return scanTriggerRows(rows, j)
}

// scanTriggerRows materialises Trigger structs from a *sql.Rows that
// returns the canonical 13-column SELECT in the order ListTriggers uses.
// Shared between ListTriggers / ListCronTriggers / ListTriggersForWorkflow.
func scanTriggerRows(rows *sql.Rows, j *Journal) ([]Trigger, error) {
	var out []Trigger
	for rows.Next() {
		var (
			t         Trigger
			tenantID  sql.NullString
			kind      string
			cfg       []byte
			tokenID   sql.NullString
			secretID  sql.NullString
			provider  sql.NullString
			lastFired sql.NullString
			lastErr   sql.NullString
			createdAt sql.NullString
			updatedAt sql.NullString
		)
		if err := rows.Scan(&t.ID, &tenantID, &t.WorkflowID, &kind, &cfg, &t.State,
			&tokenID, &secretID, &provider, &lastFired, &lastErr, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("journal: scan trigger: %w", err)
		}
		t.TenantID = nullableString(tenantID)
		t.Kind = TriggerKind(kind)
		t.Config = cfg
		t.TokenID = nullableString(tokenID)
		t.SecretID = nullableString(secretID)
		t.Provider = nullableString(provider)
		if lastFired.Valid {
			if ts, err := j.parseTime(lastFired.String); err == nil {
				t.LastFiredAt = &ts
			}
		}
		t.LastError = nullableString(lastErr)
		if createdAt.Valid {
			if ts, err := j.parseTime(createdAt.String); err == nil {
				t.CreatedAt = ts
			}
		}
		if updatedAt.Valid {
			if ts, err := j.parseTime(updatedAt.String); err == nil {
				t.UpdatedAt = ts
			}
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CreateCronTrigger registers a cron-kind trigger. config is the JSON for
// {spec, timezone} that the cron driver reads at startup.
func (j *Journal) CreateCronTrigger(ctx context.Context, workflowID string, config []byte) (string, error) {
	id, err := newID("trg_")
	if err != nil {
		return "", err
	}
	cfg := outputArg(config, j.engine)
	if cfg == nil {
		cfg = "{}"
		if j.engine != EngineSQLite {
			cfg = []byte("{}")
		}
	}
	const q = `INSERT INTO triggers (id, tenant_id, workflow_id, kind, config_json, state)
		SELECT $1, tenant_id, id, 'cron', $2, 'active'
		FROM workflows WHERE id = $3`
	res, err := j.db.ExecContext(ctx, j.bind(q), id, cfg, workflowID)
	if err != nil {
		return "", fmt.Errorf("journal: create cron trigger: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("journal: create cron trigger rows affected: %w", err)
	}
	if n != 1 {
		return "", ErrNotFound
	}
	return id, nil
}

// PurgeOldWebhookDeliveries trims rows older than retain. Run periodically
// so the dedup table doesn't grow unbounded. Default retention 7 days.
func (j *Journal) PurgeOldWebhookDeliveries(ctx context.Context, retain time.Duration) error {
	now := time.Now().UTC()
	cutoff := j.formatTime(now.Add(-retain))
	// Never delete a live lease merely because repeated recovery attempts have
	// kept an old delivery active beyond the retention window. Completed rows
	// and abandoned, expired claims are safe to trim.
	const q = `DELETE FROM webhook_deliveries
		WHERE received_at < $1
		  AND (completed_at IS NOT NULL OR lease_expires_at IS NULL OR lease_expires_at <= $2)`
	_, err := j.db.ExecContext(ctx, j.bind(q), cutoff, j.formatTime(now))
	return err
}

// NewTokenID generates a URL-safe webhook token.
func NewTokenID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("journal: token id: %w", err)
	}
	return "whk_" + hex.EncodeToString(b), nil
}

func (j *Journal) scanTrigger(row *sql.Row) (Trigger, error) {
	var (
		t         Trigger
		tenantID  sql.NullString
		kind      string
		cfg       []byte
		tokenID   sql.NullString
		secretID  sql.NullString
		provider  sql.NullString
		lastFired sql.NullString
		lastErr   sql.NullString
		createdAt sql.NullString
		updatedAt sql.NullString
	)
	if err := row.Scan(&t.ID, &tenantID, &t.WorkflowID, &kind, &cfg, &t.State,
		&tokenID, &secretID, &provider, &lastFired, &lastErr, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Trigger{}, ErrNotFound
		}
		return Trigger{}, fmt.Errorf("journal: scan trigger: %w", err)
	}
	t.TenantID = nullableString(tenantID)
	t.Kind = TriggerKind(kind)
	t.Config = cfg
	t.TokenID = nullableString(tokenID)
	t.SecretID = nullableString(secretID)
	t.Provider = nullableString(provider)
	if lastFired.Valid {
		if ts, err := j.parseTime(lastFired.String); err == nil {
			t.LastFiredAt = &ts
		}
	}
	t.LastError = nullableString(lastErr)
	if createdAt.Valid {
		if ts, err := j.parseTime(createdAt.String); err == nil {
			t.CreatedAt = ts
		}
	}
	if updatedAt.Valid {
		if ts, err := j.parseTime(updatedAt.String); err == nil {
			t.UpdatedAt = ts
		}
	}
	return t, nil
}

func nullableString(s sql.NullString) string {
	if s.Valid {
		return s.String
	}
	return ""
}
