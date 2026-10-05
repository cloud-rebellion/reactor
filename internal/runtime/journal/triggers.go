package journal

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
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
	ID         string
	TenantID   string
	WorkflowID string
	Kind       TriggerKind
	Revision   int64
	Config     []byte // JSON
	// ConfigBytes is the durable byte length captured by bounded control-plane
	// reads. It lets callers report a truncated legacy configuration without
	// materialising the value. Runtime reads leave it equal to len(Config).
	ConfigBytes int
	// ConfigTruncated is set when a bounded control-plane read intentionally
	// omitted config_json because it exceeded the caller's limit.
	ConfigTruncated bool
	State           string
	TokenID         string
	SecretID        string
	Provider        string
	LastFiredAt     *time.Time
	LastError       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// CreateWebhookTrigger registers a webhook binding. tokenID is the public
// URL component (POST /webhook/{tokenID}); the caller is responsible for
// generating one via NewTokenID. secretID points at a vault credential
// holding the HMAC shared secret.
func (j *Journal) CreateWebhookTrigger(ctx context.Context, workflowID, tokenID, secretID, provider string, config []byte) (string, error) {
	id, _, _, err := j.createWebhookTrigger(ctx, workflowID, tokenID, secretID, provider, config, "")
	return id, err
}

// CreateWebhookTriggerWithIdempotency creates or replays a webhook trigger
// under a tenant/workflow/kind-scoped caller key. A replay returns the
// original public token so a client that lost its first response can recover
// the delivery capability it deliberately supplied during creation.
func (j *Journal) CreateWebhookTriggerWithIdempotency(ctx context.Context, workflowID, tokenID, secretID, provider string, config []byte, key string) (id, token string, replay bool, err error) {
	return j.createWebhookTrigger(ctx, workflowID, tokenID, secretID, provider, config, key)
}

func (j *Journal) createWebhookTrigger(ctx context.Context, workflowID, tokenID, secretID, provider string, config []byte, key string) (id, token string, replay bool, err error) {
	// A webhook trigger is a relation between an owned workflow and an HMAC
	// secret.  Older rows can predate the tenant guard, so the receiver also
	// checks this relation immediately before reading the vault.  Reject a
	// known cross-tenant secret here to keep new control-plane writes from
	// creating that stale state.  A secret id with no metadata row is retained
	// for legacy vault-only installations; the runtime fence below still
	// refuses to serve it until ownership can be established.
	if err := j.validateWebhookSecretTenant(ctx, workflowID, secretID); err != nil {
		return "", "", false, err
	}
	id, err = newID("trg_")
	if err != nil {
		return "", "", false, err
	}
	cfg := outputArg(config, j.engine)
	compareCfg := append([]byte(nil), config...)
	if cfg == nil {
		cfg = "{}"
		compareCfg = []byte("{}")
		if j.engine != EngineSQLite {
			cfg = []byte("{}")
		}
	}
	// Derive tenant_id from the workflow row in the same statement. Callers must
	// not be able to place a trigger in a tenant merely by supplying a tenant
	// string, and omitting the column would silently use the schema's "default"
	// tenant for every non-default workflow.
	const q = `INSERT INTO triggers
		(id, tenant_id, workflow_id, kind, config_json, state, token_id, secret_id, provider, idempotency_key)
		SELECT $1, tenant_id, id, 'webhook', $2, 'active', $3, $4, $5, $6
		FROM workflows WHERE id = $7
		ON CONFLICT DO NOTHING`
	res, err := j.db.ExecContext(ctx, j.bind(q),
		id, cfg, tokenID, secretID, nullable(provider), nullable(key), workflowID,
	)
	if err != nil {
		return "", "", false, fmt.Errorf("journal: create webhook trigger: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", "", false, fmt.Errorf("journal: create webhook trigger rows affected: %w", err)
	}
	if n == 1 {
		return id, tokenID, false, nil
	}
	if key == "" {
		return "", "", false, ErrNotFound
	}
	var existingID, existingToken, existingSecret, existingProvider string
	var existingCfg []byte
	row := j.db.QueryRowContext(ctx, j.bind(`SELECT id, token_id, secret_id, provider, config_json FROM triggers WHERE workflow_id = $1 AND kind = 'webhook' AND idempotency_key = $2`), workflowID, key)
	if err := row.Scan(&existingID, &existingToken, &existingSecret, &existingProvider, &existingCfg); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", false, ErrNotFound
		}
		return "", "", false, fmt.Errorf("journal: read webhook idempotency record: %w", err)
	}
	if existingSecret != secretID || existingProvider != provider || !bytes.Equal(bytes.TrimSpace(existingCfg), bytes.TrimSpace(compareCfg)) {
		return "", "", false, ErrTriggerIdempotencyConflict
	}
	return existingID, existingToken, true, nil
}

// validateWebhookSecretTenant checks the ownership relation for a webhook
// secret before inserting a trigger. It deliberately maps a known
// cross-tenant relation to ErrNotFound so a caller cannot turn trigger
// creation into a credential-tenant oracle. Unknown secret metadata is left
// to the runtime fence for backwards compatibility with vault-only rows.
func (j *Journal) validateWebhookSecretTenant(ctx context.Context, workflowID, secretID string) error {
	var workflowTenant string
	err := j.db.QueryRowContext(ctx, j.bind(`SELECT tenant_id FROM workflows WHERE id = $1`), workflowID).Scan(&workflowTenant)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("journal: webhook workflow tenant: %w", err)
	}
	secretTenant, err := j.SecretTenant(ctx, secretID)
	if errors.Is(err, ErrNotFound) {
		// Legacy vault-only credentials have no metadata row. The receiver's
		// runtime fence fails closed when it cannot resolve ownership.
		return nil
	}
	if err != nil {
		return fmt.Errorf("journal: webhook secret tenant: %w", err)
	}
	if workflowTenant != secretTenant {
		return ErrNotFound
	}
	return nil
}

// FindWebhookByToken resolves a public token to its trigger row. Returns
// ErrNotFound if no active webhook trigger exists with that token.
func (j *Journal) FindWebhookByToken(ctx context.Context, tokenID string) (Trigger, error) {
	const q = `SELECT id, tenant_id, workflow_id, kind, config_json, state,
		token_id, secret_id, provider, last_fired_at, last_error, created_at, updated_at, revision
		FROM triggers WHERE token_id = $1 AND state = 'active' AND kind = 'webhook' LIMIT 1`
	row := j.db.QueryRowContext(ctx, j.bind(q), tokenID)
	return j.scanTrigger(row)
}

// GetActiveWebhookTrigger resolves a webhook by its durable identity and
// verifies the trigger/workflow tenant relation. Receivers use this at the
// dispatch boundary after leasing a delivery so a disable or verifier update
// racing the initial token lookup cannot turn an already-queued request into a
// run under stale trigger policy.
func (j *Journal) GetActiveWebhookTrigger(ctx context.Context, id string) (Trigger, error) {
	const q = `SELECT t.id, t.tenant_id, t.workflow_id, t.kind, t.config_json, t.state,
		t.token_id, t.secret_id, t.provider, t.last_fired_at, t.last_error,
		t.created_at, t.updated_at, t.revision
		FROM triggers t JOIN workflows w ON w.id = t.workflow_id AND w.tenant_id = t.tenant_id
		WHERE t.id = $1 AND t.state = 'active' AND t.kind = 'webhook'`
	return j.scanTrigger(j.db.QueryRowContext(ctx, j.bind(q), id))
}

// MarkTriggerFired updates last_fired_at + clears last_error. Called on
// successful dispatch.
func (j *Journal) MarkTriggerFired(ctx context.Context, id string) error {
	const q = `UPDATE triggers SET last_fired_at = $1, last_error = NULL, updated_at = $2, revision = revision + 1 WHERE id = $3`
	now := j.now()
	_, err := j.db.ExecContext(ctx, j.bind(q), now, now, id)
	return err
}

// SetTriggerState flips a trigger between 'active' and 'disabled'.
// Used by the cron live-reload + the webhook CLI's enable/disable
// subcommands so an operator can pause a trigger without deleting it.
func (j *Journal) SetTriggerState(ctx context.Context, id, state string) error {
	// A disabled chain is excluded from cycle checks. Re-enabling it directly
	// can close a cycle created while it was paused, so every caller must
	// recreate the edge through CreateChainTrigger instead.
	const q = `UPDATE triggers SET state = $1, updated_at = $2, revision = revision + 1
		WHERE id = $3 AND NOT (kind = 'workflow_complete' AND state = 'disabled' AND $4 = 'active')`
	res, err := j.db.ExecContext(ctx, j.bind(q), state, j.now(), id, state)
	if err != nil {
		return fmt.Errorf("journal: set trigger state: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("journal: set trigger state rows affected: %w", err)
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

// SetTriggerStateForWorkflow changes a trigger only when it belongs to the
// workflow the caller already authorized. Dashboard routes contain both a
// workflow slug and a trigger id; binding both identifiers in the mutation
// prevents a tenant member from pairing their own slug with another tenant's
// trigger id. A missing or mismatched row is deliberately indistinguishable.
func (j *Journal) SetTriggerStateForWorkflow(ctx context.Context, id, workflowID, state string) error {
	return j.setTriggerStateForWorkflow(ctx, id, workflowID, state, nil)
}

// SetTriggerStateForWorkflowIfRevision changes a trigger only when its
// workflow binding and current control-plane revision both match. The check
// is atomic with the update, so a concurrent runtime or authoring mutation
// cannot be overwritten by a stale MCP read.
func (j *Journal) SetTriggerStateForWorkflowIfRevision(ctx context.Context, id, workflowID, state string, expectedRevision int64) error {
	if expectedRevision < 1 {
		return fmt.Errorf("journal: trigger revision must be positive")
	}
	return j.setTriggerStateForWorkflow(ctx, id, workflowID, state, &expectedRevision)
}

func (j *Journal) setTriggerStateForWorkflow(ctx context.Context, id, workflowID, state string, expectedRevision *int64) error {
	q := `UPDATE triggers SET state = $1, updated_at = $2, revision = revision + 1
		WHERE id = $3 AND workflow_id = $4
		  AND tenant_id IN (SELECT tenant_id FROM workflows WHERE id = $5)
		  AND NOT (kind = 'workflow_complete' AND state = 'disabled' AND $6 = 'active')`
	args := []any{state, j.now(), id, workflowID, workflowID, state}
	if expectedRevision != nil {
		q += ` AND revision = $7`
		args = append(args, *expectedRevision)
	}
	res, err := j.db.ExecContext(ctx, j.bind(q), args...)
	if err != nil {
		return fmt.Errorf("journal: set trigger state for workflow: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("journal: set trigger state for workflow rows affected: %w", err)
	}
	if n != 1 {
		if expectedRevision != nil {
			return j.triggerRevisionConflictOrNotFound(ctx, id, workflowID, *expectedRevision)
		}
		return ErrNotFound
	}
	return nil
}

// MarkTriggerError stores last_error for dashboard surfacing. Successful
// later fires clear it via MarkTriggerFired.
func (j *Journal) MarkTriggerError(ctx context.Context, id, msg string) error {
	const q = `UPDATE triggers SET last_error = $1, updated_at = $2, revision = revision + 1 WHERE id = $3`
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

// ErrTriggerRevisionConflict means an authoring mutation used a revision that
// is no longer current. Callers should re-read the scoped trigger and retry
// only after deciding whether the intervening change is still intended.
var ErrTriggerRevisionConflict = errors.New("journal: trigger revision conflict")

// ErrTriggerIdempotencyConflict means a caller reused a trigger-creation key
// for different configuration. The original trigger remains authoritative.
var ErrTriggerIdempotencyConflict = errors.New("journal: trigger idempotency key reused with different configuration")

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
		token_id, secret_id, provider, last_fired_at, last_error, created_at, updated_at, revision
		FROM triggers ORDER BY created_at DESC`
	return j.scanTriggers(ctx, q)
}

// ListTriggersPage returns one bounded page of estate-wide trigger rows.
// Graph rebuilds use it instead of ListTriggers so one very large tenant does
// not force the journal driver to materialise every trigger at once.
func (j *Journal) ListTriggersPage(ctx context.Context, limit, offset int) ([]Trigger, bool, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		return nil, false, fmt.Errorf("journal: list triggers: page limit exceeds 500")
	}
	if offset < 0 {
		return nil, false, fmt.Errorf("journal: list triggers: negative offset")
	}
	q := fmt.Sprintf(`SELECT id, tenant_id, workflow_id, kind, config_json, state,
		token_id, secret_id, provider, last_fired_at, last_error, created_at, updated_at, revision
		FROM triggers ORDER BY created_at DESC, id ASC LIMIT %d OFFSET %d`, limit+1, offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q))
	if err != nil {
		return nil, false, fmt.Errorf("journal: list triggers page: %w", err)
	}
	defer rows.Close()
	out, err := scanTriggerRows(rows, j)
	if err != nil {
		return nil, false, err
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

// ListTriggersForWorkflow returns every trigger row bound to the given
// workflow id, newest first. Used by the dashboard's workflow detail
// page so an operator can see + manage inbound sources without dropping
// into SQL.
func (j *Journal) ListTriggersForWorkflow(ctx context.Context, workflowID string) ([]Trigger, error) {
	// A workflow id is tenant-scoped at the MCP boundary, but old/restored
	// databases can still contain a trigger row whose tenant marker disagrees
	// with its workflow. Keep those rows out of workflow-scoped reads so a
	// stale trigger config or bearer-presence marker cannot cross tenants.
	const q = `SELECT t.id, t.tenant_id, t.workflow_id, t.kind, t.config_json, t.state,
		t.token_id, t.secret_id, t.provider, t.last_fired_at, t.last_error, t.created_at, t.updated_at, t.revision
		FROM triggers t JOIN workflows w ON w.id = t.workflow_id AND t.tenant_id = w.tenant_id
		WHERE t.workflow_id = $1 ORDER BY t.created_at DESC`
	rows, err := j.db.QueryContext(ctx, j.bind(q), workflowID)
	if err != nil {
		return nil, fmt.Errorf("journal: list triggers by workflow: %w", err)
	}
	defer rows.Close()
	return scanTriggerRows(rows, j)
}

// GetTriggerForWorkflow returns one trigger only when it belongs to the
// already-authorized workflow. The revision is the opaque optimistic-concurrency
// token exposed to MCP authoring clients.
func (j *Journal) GetTriggerForWorkflow(ctx context.Context, id, workflowID string) (Trigger, error) {
	const q = `SELECT t.id, t.tenant_id, t.workflow_id, t.kind, t.config_json, t.state,
		t.token_id, t.secret_id, t.provider, t.last_fired_at, t.last_error, t.created_at, t.updated_at, t.revision
		FROM triggers t JOIN workflows w ON w.id = t.workflow_id AND t.tenant_id = w.tenant_id
		WHERE t.id = $1 AND t.workflow_id = $2`
	return j.scanTrigger(j.db.QueryRowContext(ctx, j.bind(q), id, workflowID))
}

// GetTriggerForWorkflowBounded returns a workflow-bound trigger receipt while
// materialising config_json only when it fits maxConfigBytes. A zero bound
// omits the configuration entirely but still reports its durable size. Runtime
// callers that need the verifier or scheduler config should keep using
// GetTriggerForWorkflow, while MCP control-plane reads should use this method
// so a restored legacy row cannot allocate an arbitrary JSON blob.
func (j *Journal) GetTriggerForWorkflowBounded(ctx context.Context, id, workflowID string, maxConfigBytes int) (Trigger, error) {
	if maxConfigBytes < 0 {
		return Trigger{}, errors.New("journal: negative trigger config bound")
	}
	if maxConfigBytes > 16<<20 {
		return Trigger{}, errors.New("journal: trigger config bound exceeds 16 MiB")
	}
	q := j.boundedTriggerQuery(`WHERE t.id = $1 AND t.workflow_id = $2`, maxConfigBytes)
	return j.scanBoundedTrigger(j.db.QueryRowContext(ctx, j.bind(q), id, workflowID))
}

// ListTriggersForWorkflowPage returns one bounded newest-first trigger page
// with a lookahead flag. The unpaged method remains for dashboard and runtime
// callers that already own their response budget.
func (j *Journal) ListTriggersForWorkflowPage(ctx context.Context, workflowID string, limit, offset int) ([]Trigger, bool, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		return nil, false, fmt.Errorf("journal: list triggers by workflow: page limit exceeds 500")
	}
	if offset < 0 {
		return nil, false, fmt.Errorf("journal: list triggers by workflow: negative offset")
	}
	q := fmt.Sprintf(`SELECT t.id, t.tenant_id, t.workflow_id, t.kind, t.config_json, t.state,
		t.token_id, t.secret_id, t.provider, t.last_fired_at, t.last_error, t.created_at, t.updated_at, t.revision
		FROM triggers t JOIN workflows w ON w.id = t.workflow_id AND t.tenant_id = w.tenant_id
		WHERE t.workflow_id = $1 ORDER BY t.created_at DESC, t.id ASC LIMIT %d OFFSET %d`, limit+1, offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q), workflowID)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list triggers page: %w", err)
	}
	defer rows.Close()
	out, err := scanTriggerRows(rows, j)
	if err != nil {
		return nil, false, err
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

// ListTriggersForWorkflowPageBounded is the MCP/read-model variant of the
// trigger inventory. The SQL projection measures config_json and returns NULL
// for values above maxConfigBytes, so the database driver never materialises a
// giant or secret-bearing legacy configuration merely to render token/state
// metadata.
func (j *Journal) ListTriggersForWorkflowPageBounded(ctx context.Context, workflowID string, limit, offset, maxConfigBytes int) ([]Trigger, bool, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		return nil, false, fmt.Errorf("journal: list bounded triggers by workflow: page limit exceeds 500")
	}
	if offset < 0 {
		return nil, false, fmt.Errorf("journal: list bounded triggers by workflow: negative offset")
	}
	if maxConfigBytes < 0 {
		return nil, false, errors.New("journal: negative trigger config bound")
	}
	if maxConfigBytes > 16<<20 {
		return nil, false, errors.New("journal: trigger config bound exceeds 16 MiB")
	}
	q := j.boundedTriggerQuery(fmt.Sprintf("WHERE t.workflow_id = $1 ORDER BY t.created_at DESC, t.id ASC LIMIT %d OFFSET %d", limit+1, offset), maxConfigBytes)
	rows, err := j.db.QueryContext(ctx, j.bind(q), workflowID)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list bounded triggers page: %w", err)
	}
	defer rows.Close()
	out, err := scanBoundedTriggerRows(rows, j)
	if err != nil {
		return nil, false, err
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

// boundedTriggerQuery returns the canonical trigger columns plus config size
// and a conditional config value. maxConfigBytes is validated by callers.
func (j *Journal) boundedTriggerQuery(where string, maxConfigBytes int) string {
	var sizeExpr, valueExpr string
	if j.engine == EnginePostgres {
		sizeExpr = "octet_length(t.config_json::text)"
		valueExpr = "NULL"
		if maxConfigBytes > 0 {
			valueExpr = "CASE WHEN " + sizeExpr + " <= " + strconv.Itoa(maxConfigBytes) + " THEN t.config_json::text ELSE NULL END"
		}
	} else {
		sizeExpr = "length(CAST(t.config_json AS BLOB))"
		valueExpr = "NULL"
		if maxConfigBytes > 0 {
			valueExpr = "CASE WHEN " + sizeExpr + " <= " + strconv.Itoa(maxConfigBytes) + " THEN t.config_json ELSE NULL END"
		}
	}
	return `SELECT t.id, t.tenant_id, t.workflow_id, t.kind, ` + valueExpr + `, ` + sizeExpr + `,
		t.state, t.token_id, t.secret_id, t.provider, t.last_fired_at, t.last_error, t.created_at, t.updated_at, t.revision
		FROM triggers t JOIN workflows w ON w.id = t.workflow_id AND t.tenant_id = w.tenant_id ` + where
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
	return j.deleteTriggerForWorkflow(ctx, id, workflowID, nil)
}

// DeleteTriggerForWorkflowIfRevision permanently removes a trigger only when
// its workflow binding and current control-plane revision both match.
func (j *Journal) DeleteTriggerForWorkflowIfRevision(ctx context.Context, id, workflowID string, expectedRevision int64) error {
	if expectedRevision < 1 {
		return fmt.Errorf("journal: trigger revision must be positive")
	}
	return j.deleteTriggerForWorkflow(ctx, id, workflowID, &expectedRevision)
}

func (j *Journal) deleteTriggerForWorkflow(ctx context.Context, id, workflowID string, expectedRevision *int64) error {
	q := `DELETE FROM triggers
		WHERE id = $1 AND workflow_id = $2
		  AND tenant_id IN (SELECT tenant_id FROM workflows WHERE id = $3)`
	args := []any{id, workflowID, workflowID}
	if expectedRevision != nil {
		q += ` AND revision = $4`
		args = append(args, *expectedRevision)
	}
	res, err := j.db.ExecContext(ctx, j.bind(q), args...)
	if err != nil {
		return fmt.Errorf("journal: delete trigger for workflow: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("journal: delete trigger for workflow rows affected: %w", err)
	}
	if n != 1 {
		if expectedRevision != nil {
			return j.triggerRevisionConflictOrNotFound(ctx, id, workflowID, *expectedRevision)
		}
		return ErrNotFound
	}
	return nil
}

// UpdateCronTriggerConfigForWorkflow replaces config only for a cron trigger
// owned by the authorized workflow. The kind predicate prevents a crafted edit
// request from writing cron-shaped config over a webhook verifier binding.
func (j *Journal) UpdateCronTriggerConfigForWorkflow(ctx context.Context, id, workflowID string, config []byte) error {
	return j.updateCronTriggerConfigForWorkflow(ctx, id, workflowID, config, nil)
}

// UpdateCronTriggerConfigForWorkflowIfRevision replaces a cron config only
// when the caller's workflow binding and trigger revision are still current.
func (j *Journal) UpdateCronTriggerConfigForWorkflowIfRevision(ctx context.Context, id, workflowID string, config []byte, expectedRevision int64) error {
	if expectedRevision < 1 {
		return fmt.Errorf("journal: trigger revision must be positive")
	}
	return j.updateCronTriggerConfigForWorkflow(ctx, id, workflowID, config, &expectedRevision)
}

// UpdateWebhookTriggerForWorkflowIfRevision changes a webhook's credential,
// provider, and verifier options without changing its public bearer token.
// The workflow binding, webhook kind, tenant relation, and optimistic
// concurrency revision are all part of one conditional update, so an agent
// cannot rebind a live endpoint from a stale trigger inventory read.
func (j *Journal) UpdateWebhookTriggerForWorkflowIfRevision(ctx context.Context, id, workflowID, secretID, provider string, config []byte, expectedRevision int64) error {
	if expectedRevision < 1 {
		return fmt.Errorf("journal: trigger revision must be positive")
	}
	if id == "" || workflowID == "" || secretID == "" {
		return ErrNotFound
	}
	if err := j.validateWebhookSecretTenant(ctx, workflowID, secretID); err != nil {
		return err
	}
	cfg := outputArg(config, j.engine)
	if cfg == nil {
		cfg = "{}"
		if j.engine != EngineSQLite {
			cfg = []byte("{}")
		}
	}
	const q = `UPDATE triggers SET secret_id = $1, provider = $2, config_json = $3,
		updated_at = $4, revision = revision + 1
		WHERE id = $5 AND workflow_id = $6 AND kind = 'webhook'
		  AND tenant_id IN (SELECT tenant_id FROM workflows WHERE id = $7)
		  AND revision = $8`
	res, err := j.db.ExecContext(ctx, j.bind(q), secretID, nullable(provider), cfg, j.now(), id, workflowID, workflowID, expectedRevision)
	if err != nil {
		return fmt.Errorf("journal: update webhook trigger for workflow: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("journal: update webhook trigger for workflow rows affected: %w", err)
	}
	if n != 1 {
		return j.triggerRevisionConflictOrNotFound(ctx, id, workflowID, expectedRevision)
	}
	return nil
}

func (j *Journal) updateCronTriggerConfigForWorkflow(ctx context.Context, id, workflowID string, config []byte, expectedRevision *int64) error {
	cfg := outputArg(config, j.engine)
	if cfg == nil {
		cfg = "{}"
		if j.engine != EngineSQLite {
			cfg = []byte("{}")
		}
	}
	q := `UPDATE triggers SET config_json = $1, updated_at = $2, revision = revision + 1
		WHERE id = $3 AND workflow_id = $4 AND kind = 'cron'
		  AND tenant_id IN (SELECT tenant_id FROM workflows WHERE id = $5)`
	args := []any{cfg, j.now(), id, workflowID, workflowID}
	if expectedRevision != nil {
		q += ` AND revision = $6`
		args = append(args, *expectedRevision)
	}
	res, err := j.db.ExecContext(ctx, j.bind(q), args...)
	if err != nil {
		return fmt.Errorf("journal: update cron trigger config for workflow: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("journal: update cron trigger config for workflow rows affected: %w", err)
	}
	if n != 1 {
		if expectedRevision != nil {
			return j.triggerRevisionConflictOrNotFound(ctx, id, workflowID, *expectedRevision)
		}
		return ErrNotFound
	}
	return nil
}

func (j *Journal) triggerRevisionConflictOrNotFound(ctx context.Context, id, workflowID string, expectedRevision int64) error {
	var current int64
	const q = `SELECT t.revision
		FROM triggers t JOIN workflows w ON w.id = t.workflow_id AND t.tenant_id = w.tenant_id
		WHERE t.id = $1 AND t.workflow_id = $2`
	if err := j.db.QueryRowContext(ctx, j.bind(q), id, workflowID).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("journal: read trigger revision after conflict: %w", err)
	}
	return fmt.Errorf("%w: expected %d, current %d", ErrTriggerRevisionConflict, expectedRevision, current)
}

// ListCronTriggers returns every active cron trigger. Used by the cron
// driver at startup; cron-kind triggers added at runtime require a driver
// reload (week 9 wires LISTEN/NOTIFY for live reload on Postgres).
func (j *Journal) ListCronTriggers(ctx context.Context) ([]Trigger, error) {
	const q = `SELECT id, tenant_id, workflow_id, kind, config_json, state,
		token_id, secret_id, provider, last_fired_at, last_error, created_at, updated_at, revision
		FROM triggers WHERE kind = 'cron' AND state = 'active'`
	return j.scanTriggers(ctx, q)
}

// GetActiveCronTrigger resolves the authoritative row immediately before a
// cron callback is dispatched. The in-process cron clock keeps a small cached
// trigger snapshot between reconciles; looking it up again closes the window
// where an operator disables or rewires a trigger after the clock selected its
// old entry but before the reload loop removed that entry. The workflow join
// also rejects imported rows whose trigger tenant no longer matches its owner.
func (j *Journal) GetActiveCronTrigger(ctx context.Context, id string) (Trigger, error) {
	const q = `SELECT t.id, t.tenant_id, t.workflow_id, t.kind, t.config_json, t.state,
		t.token_id, t.secret_id, t.provider, t.last_fired_at, t.last_error,
		t.created_at, t.updated_at, t.revision
		FROM triggers t JOIN workflows w ON w.id = t.workflow_id AND w.tenant_id = t.tenant_id
		WHERE t.id = $1 AND t.kind = 'cron' AND t.state = 'active'`
	return j.scanTrigger(j.db.QueryRowContext(ctx, j.bind(q), id))
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
// returns the canonical 14-column SELECT in the order ListTriggers uses.
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
			&tokenID, &secretID, &provider, &lastFired, &lastErr, &createdAt, &updatedAt, &t.Revision); err != nil {
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

func scanBoundedTriggerRows(rows *sql.Rows, j *Journal) ([]Trigger, error) {
	var out []Trigger
	for rows.Next() {
		trigger, err := scanBoundedTriggerRow(rows, j)
		if err != nil {
			return nil, err
		}
		out = append(out, trigger)
	}
	return out, rows.Err()
}

type triggerRowScanner interface {
	Scan(dest ...any) error
}

func (j *Journal) scanBoundedTrigger(row triggerRowScanner) (Trigger, error) {
	var (
		t         Trigger
		tenantID  sql.NullString
		kind      string
		cfg       []byte
		cfgBytes  sql.NullInt64
		tokenID   sql.NullString
		secretID  sql.NullString
		provider  sql.NullString
		lastFired sql.NullString
		lastErr   sql.NullString
		createdAt sql.NullString
		updatedAt sql.NullString
	)
	if err := row.Scan(&t.ID, &tenantID, &t.WorkflowID, &kind, &cfg, &cfgBytes, &t.State,
		&tokenID, &secretID, &provider, &lastFired, &lastErr, &createdAt, &updatedAt, &t.Revision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Trigger{}, ErrNotFound
		}
		return Trigger{}, fmt.Errorf("journal: scan bounded trigger: %w", err)
	}
	t.TenantID = nullableString(tenantID)
	t.Kind = TriggerKind(kind)
	t.Config = cfg
	if cfgBytes.Valid && cfgBytes.Int64 >= 0 {
		t.ConfigBytes = int(cfgBytes.Int64)
	}
	t.ConfigTruncated = t.ConfigBytes > len(t.Config)
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

func scanBoundedTriggerRow(row triggerRowScanner, j *Journal) (Trigger, error) {
	return j.scanBoundedTrigger(row)
}

// CreateCronTrigger registers a cron-kind trigger. config is the JSON for
// {spec, timezone} that the cron driver reads at startup.
func (j *Journal) CreateCronTrigger(ctx context.Context, workflowID string, config []byte) (string, error) {
	id, _, err := j.createCronTrigger(ctx, workflowID, config, "")
	return id, err
}

// CreateCronTriggerWithIdempotency creates or replays a cron trigger under a
// tenant/workflow/kind-scoped caller key.
func (j *Journal) CreateCronTriggerWithIdempotency(ctx context.Context, workflowID string, config []byte, key string) (id string, replay bool, err error) {
	return j.createCronTrigger(ctx, workflowID, config, key)
}

func (j *Journal) createCronTrigger(ctx context.Context, workflowID string, config []byte, key string) (id string, replay bool, err error) {
	id, err = newID("trg_")
	if err != nil {
		return "", false, err
	}
	cfg := outputArg(config, j.engine)
	compareCfg := append([]byte(nil), config...)
	if cfg == nil {
		cfg = "{}"
		compareCfg = []byte("{}")
		if j.engine != EngineSQLite {
			cfg = []byte("{}")
		}
	}
	const q = `INSERT INTO triggers (id, tenant_id, workflow_id, kind, config_json, state, idempotency_key)
		SELECT $1, tenant_id, id, 'cron', $2, 'active', $3
		FROM workflows WHERE id = $4
		ON CONFLICT DO NOTHING`
	res, err := j.db.ExecContext(ctx, j.bind(q), id, cfg, nullable(key), workflowID)
	if err != nil {
		return "", false, fmt.Errorf("journal: create cron trigger: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", false, fmt.Errorf("journal: create cron trigger rows affected: %w", err)
	}
	if n == 1 {
		return id, false, nil
	}
	if key == "" {
		return "", false, ErrNotFound
	}
	var existingID string
	var existingCfg []byte
	row := j.db.QueryRowContext(ctx, j.bind(`SELECT id, config_json FROM triggers WHERE workflow_id = $1 AND kind = 'cron' AND idempotency_key = $2`), workflowID, key)
	if err := row.Scan(&existingID, &existingCfg); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, ErrNotFound
		}
		return "", false, fmt.Errorf("journal: read cron idempotency record: %w", err)
	}
	if !bytes.Equal(bytes.TrimSpace(existingCfg), bytes.TrimSpace(compareCfg)) {
		return "", false, ErrTriggerIdempotencyConflict
	}
	return existingID, true, nil
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
		&tokenID, &secretID, &provider, &lastFired, &lastErr, &createdAt, &updatedAt, &t.Revision); err != nil {
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
