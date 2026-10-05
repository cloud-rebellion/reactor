package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// NotificationSnapshot freezes the recipients for one terminal run generation.
// It contains no destination configuration or secret material.
type NotificationSnapshot struct {
	RunID      string
	WorkflowID string
	TenantID   string
	Status     string
	Generation int64
}

// NotificationDeliveryTarget is one pending recipient. Missing is true if an
// operator deleted the channel after the route snapshot; the caller records a
// skipped receipt instead of sending to a deleted destination.
type NotificationDeliveryTarget struct {
	ChannelID string
	Channel   NotificationChannel
	Missing   bool
}

const (
	maxSnapshotNotificationRoutes = 256
	maxNotificationStatusesBytes  = 4096
	maxNotificationDeliveryPage   = 16
)

// BeginNotificationDelivery atomically freezes the matching route IDs for the
// exact terminal-effect claim. Retrying a claim reuses the original membership,
// even if an operator subsequently edits routes. A new run terminal generation
// receives a new snapshot, including after a same-status dead-letter retry.
func (j *Journal) BeginNotificationDelivery(ctx context.Context, effect TerminalEffect, workflowID string) (NotificationSnapshot, error) {
	if effect.RunID == "" || workflowID == "" || !terminalEffectStatus(effect.Status) ||
		effect.ClaimedAt.IsZero() || effect.ClaimToken == "" {
		return NotificationSnapshot{}, ErrTerminalEffectClaimLost
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return NotificationSnapshot{}, fmt.Errorf("journal: begin notification snapshot: %w", err)
	}
	defer tx.Rollback()
	snap := NotificationSnapshot{RunID: effect.RunID, WorkflowID: workflowID, Status: effect.Status}
	q := `SELECT r.tenant_id, r.terminal_generation
		FROM runs r JOIN workflows w ON w.id = r.workflow_id AND w.tenant_id = r.tenant_id
		JOIN terminal_effects t ON t.run_id = r.id
		WHERE r.id = $1 AND r.workflow_id = $2 AND r.status = $3
			AND t.status = $4 AND t.claimed_at = $5 AND t.claim_token = $6
			AND t.delivered_at IS NULL`
	if j.engine == EnginePostgres {
		q += ` FOR UPDATE OF r, t`
	}
	if err := tx.QueryRowContext(ctx, j.bind(q), effect.RunID, workflowID, effect.Status, effect.Status,
		j.formatTime(effect.ClaimedAt), effect.ClaimToken).Scan(&snap.TenantID, &snap.Generation); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return NotificationSnapshot{}, ErrTerminalEffectClaimLost
		}
		return NotificationSnapshot{}, fmt.Errorf("journal: inspect notification claim: %w", err)
	}
	res, err := tx.ExecContext(ctx, j.bind(`INSERT INTO notification_dispatches
		(run_id, generation, status, workflow_id, tenant_id) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (run_id, generation, status) DO NOTHING`),
		snap.RunID, snap.Generation, snap.Status, snap.WorkflowID, snap.TenantID)
	if err != nil {
		return NotificationSnapshot{}, fmt.Errorf("journal: insert notification snapshot: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return NotificationSnapshot{}, fmt.Errorf("journal: inspect notification snapshot insertion: %w", err)
	}
	if inserted == 1 {
		if err := j.freezeNotificationRoutesTx(ctx, tx, snap); err != nil {
			return NotificationSnapshot{}, err
		}
	} else {
		var workflow, tenant string
		err := tx.QueryRowContext(ctx, j.bind(`SELECT workflow_id, tenant_id FROM notification_dispatches
			WHERE run_id = $1 AND generation = $2 AND status = $3`),
			snap.RunID, snap.Generation, snap.Status).Scan(&workflow, &tenant)
		if err != nil || workflow != snap.WorkflowID || tenant != snap.TenantID {
			return NotificationSnapshot{}, fmt.Errorf("journal: notification snapshot identity mismatch: %w", ErrTerminalEffectClaimLost)
		}
	}
	if err := tx.Commit(); err != nil {
		return NotificationSnapshot{}, fmt.Errorf("journal: commit notification snapshot: %w", err)
	}
	return snap, nil
}

func (j *Journal) freezeNotificationRoutesTx(ctx context.Context, tx *sql.Tx, snap NotificationSnapshot) error {
	statusSize := `length(CAST(route.on_statuses AS BLOB))`
	if j.engine == EnginePostgres {
		statusSize = `octet_length(route.on_statuses)`
	}
	q := fmt.Sprintf(`SELECT route.channel_id,
		CASE WHEN %s <= %d THEN route.on_statuses ELSE NULL END, channel.tenant_id
		FROM workflow_notification_routes route
		LEFT JOIN notification_channels channel ON channel.id = route.channel_id
		WHERE route.workflow_id = $1 ORDER BY route.channel_id LIMIT %d`,
		statusSize, maxNotificationStatusesBytes, maxSnapshotNotificationRoutes+1)
	rows, err := tx.QueryContext(ctx, j.bind(q), snap.WorkflowID)
	if err != nil {
		return fmt.Errorf("journal: select notification routes for snapshot: %w", err)
	}
	defer rows.Close()
	var selected []string
	count := 0
	for rows.Next() {
		var channelID string
		var tenantID sql.NullString
		var statuses sql.NullString
		if err := rows.Scan(&channelID, &statuses, &tenantID); err != nil {
			return fmt.Errorf("journal: scan notification route for snapshot: %w", err)
		}
		count++
		if count > maxSnapshotNotificationRoutes {
			return fmt.Errorf("journal: notification routes exceed %d for workflow %s", maxSnapshotNotificationRoutes, snap.WorkflowID)
		}
		if !tenantID.Valid {
			return fmt.Errorf("journal: notification route has missing channel for workflow %s", snap.WorkflowID)
		}
		if tenantID.String != snap.TenantID {
			return fmt.Errorf("journal: notification route crosses tenant for workflow %s", snap.WorkflowID)
		}
		if !statuses.Valid {
			return fmt.Errorf("journal: notification route statuses exceed %d bytes", maxNotificationStatusesBytes)
		}
		if routeFiresOn(statuses.String, snap.Status) {
			selected = append(selected, channelID)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("journal: iterate notification routes for snapshot: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("journal: close notification routes for snapshot: %w", err)
	}
	for _, channelID := range selected {
		if _, err := tx.ExecContext(ctx, j.bind(`INSERT INTO notification_deliveries
			(run_id, generation, status, channel_id) VALUES ($1, $2, $3, $4)`),
			snap.RunID, snap.Generation, snap.Status, channelID); err != nil {
			return fmt.Errorf("journal: insert notification delivery receipt: %w", err)
		}
	}
	return nil
}

// PendingNotificationDeliveryPage loads at most 16 pending destination configs
// after a stable channel cursor. This keeps a large fan-out from materializing
// every encrypted config at once. A failed target stays pending for a later
// terminal-effect retry, while later targets can still be attempted now.
func (j *Journal) PendingNotificationDeliveryPage(ctx context.Context, effect TerminalEffect, snap NotificationSnapshot, after string, limit int) ([]NotificationDeliveryTarget, bool, error) {
	if limit <= 0 || limit > maxNotificationDeliveryPage {
		return nil, false, fmt.Errorf("journal: invalid notification delivery page size")
	}
	if err := j.checkNotificationClaim(ctx, effect, snap); err != nil {
		return nil, false, err
	}
	const q = `SELECT delivery.channel_id, channel.tenant_id
		FROM notification_deliveries delivery
		LEFT JOIN notification_channels channel ON channel.id = delivery.channel_id
		WHERE delivery.run_id = $1 AND delivery.generation = $2 AND delivery.status = $3
			AND delivery.channel_id > $4
			AND delivery.delivered_at IS NULL AND delivery.skipped_at IS NULL
		ORDER BY delivery.channel_id LIMIT $5`
	rows, err := j.db.QueryContext(ctx, j.bind(q), snap.RunID, snap.Generation, snap.Status, after, limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("journal: select pending notification deliveries: %w", err)
	}
	type pending struct {
		id     string
		tenant sql.NullString
	}
	var pendingRows []pending
	for rows.Next() {
		var item pending
		if err := rows.Scan(&item.id, &item.tenant); err != nil {
			rows.Close()
			return nil, false, fmt.Errorf("journal: scan pending notification delivery: %w", err)
		}
		pendingRows = append(pendingRows, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, false, fmt.Errorf("journal: iterate pending notification deliveries: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, false, fmt.Errorf("journal: close pending notification deliveries: %w", err)
	}
	hasMore := len(pendingRows) > limit
	if hasMore {
		pendingRows = pendingRows[:limit]
	}
	out := make([]NotificationDeliveryTarget, 0, len(pendingRows))
	for _, item := range pendingRows {
		if item.tenant.Valid && item.tenant.String != snap.TenantID {
			return nil, false, fmt.Errorf("journal: notification channel %s changed tenant", item.id)
		}
		target := NotificationDeliveryTarget{ChannelID: item.id, Missing: !item.tenant.Valid}
		if !target.Missing {
			ch, err := j.getNotificationChannel(ctx, item.id, snap.TenantID)
			if errors.Is(err, ErrNotFound) {
				// The channel was deleted after the metadata query. Distinguish
				// deletion from a tenant change before allowing a skip receipt.
				var tenant string
				probeErr := j.db.QueryRowContext(ctx, j.bind(`SELECT tenant_id FROM notification_channels WHERE id = $1`), item.id).Scan(&tenant)
				if probeErr == nil {
					return nil, false, fmt.Errorf("journal: notification channel %s changed tenant", item.id)
				}
				if !errors.Is(probeErr, sql.ErrNoRows) {
					return nil, false, fmt.Errorf("journal: probe deleted notification channel: %w", probeErr)
				}
				target.Missing = true
			} else if err != nil {
				return nil, false, err
			} else {
				target.Channel = ch
			}
		}
		out = append(out, target)
	}
	return out, hasMore, nil
}

func (j *Journal) checkNotificationClaim(ctx context.Context, effect TerminalEffect, snap NotificationSnapshot) error {
	if effect.RunID == "" || effect.RunID != snap.RunID || effect.Status != snap.Status ||
		effect.ClaimedAt.IsZero() || effect.ClaimToken == "" || snap.WorkflowID == "" || snap.TenantID == "" {
		return ErrTerminalEffectClaimLost
	}
	const q = `SELECT 1 FROM notification_dispatches snap
		JOIN runs run ON run.id = snap.run_id
		JOIN terminal_effects effect ON effect.run_id = run.id
		WHERE snap.run_id = $1 AND snap.generation = $2 AND snap.status = $3
			AND snap.workflow_id = $4 AND snap.tenant_id = $5
			AND run.workflow_id = snap.workflow_id AND run.tenant_id = snap.tenant_id
			AND run.status = snap.status AND run.terminal_generation = snap.generation
			AND effect.status = snap.status AND effect.claimed_at = $6
			AND effect.claim_token = $7 AND effect.delivered_at IS NULL`
	var one int
	err := j.db.QueryRowContext(ctx, j.bind(q), snap.RunID, snap.Generation, snap.Status,
		snap.WorkflowID, snap.TenantID, j.formatTime(effect.ClaimedAt), effect.ClaimToken).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrTerminalEffectClaimLost
	}
	if err != nil {
		return fmt.Errorf("journal: check notification claim: %w", err)
	}
	return nil
}

// MarkNotificationDelivery records only a confirmed send. A send that reached
// the provider but whose acknowledgement was lost can be sent again on retry;
// the receipt deliberately never claims exactly-once external delivery.
func (j *Journal) MarkNotificationDelivery(ctx context.Context, effect TerminalEffect, snap NotificationSnapshot, channelID string) error {
	return j.finishNotificationDelivery(ctx, effect, snap, channelID, false)
}

// SkipNotificationDelivery records an operator-deleted destination. It cannot
// deliver from a channel that no longer exists, and the skipped receipt keeps
// the run from retrying forever after explicit deletion.
func (j *Journal) SkipNotificationDelivery(ctx context.Context, effect TerminalEffect, snap NotificationSnapshot, channelID string) error {
	return j.finishNotificationDelivery(ctx, effect, snap, channelID, true)
}

func (j *Journal) finishNotificationDelivery(ctx context.Context, effect TerminalEffect, snap NotificationSnapshot, channelID string, skip bool) error {
	if channelID == "" || effect.RunID != snap.RunID || effect.Status != snap.Status ||
		effect.ClaimedAt.IsZero() || effect.ClaimToken == "" || snap.WorkflowID == "" || snap.TenantID == "" {
		return ErrTerminalEffectClaimLost
	}
	column := "delivered_at"
	destinationGuard := `AND EXISTS (
		SELECT 1 FROM notification_channels channel
		JOIN notification_dispatches owner ON owner.run_id = notification_deliveries.run_id
			AND owner.generation = notification_deliveries.generation
			AND owner.status = notification_deliveries.status
		WHERE channel.id = notification_deliveries.channel_id AND channel.tenant_id = owner.tenant_id
	)`
	if skip {
		column = "skipped_at"
		destinationGuard = `AND NOT EXISTS (
			SELECT 1 FROM notification_channels channel WHERE channel.id = notification_deliveries.channel_id
		)`
	}
	q := fmt.Sprintf(`UPDATE notification_deliveries SET %s = $1
		WHERE run_id = $2 AND generation = $3 AND status = $4 AND channel_id = $5
			AND delivered_at IS NULL AND skipped_at IS NULL
			%s
			AND EXISTS (
				SELECT 1 FROM notification_dispatches snap
				JOIN runs run ON run.id = snap.run_id
				JOIN terminal_effects effect ON effect.run_id = run.id
				WHERE snap.run_id = notification_deliveries.run_id
					AND snap.generation = notification_deliveries.generation
					AND snap.status = notification_deliveries.status
					AND snap.workflow_id = $6 AND snap.tenant_id = $7
					AND run.workflow_id = snap.workflow_id AND run.tenant_id = snap.tenant_id
					AND run.status = snap.status AND run.terminal_generation = snap.generation
					AND effect.status = snap.status AND effect.claimed_at = $8
					AND effect.claim_token = $9 AND effect.delivered_at IS NULL
			)`, column, destinationGuard)
	res, err := j.db.ExecContext(ctx, j.bind(q), j.now(), snap.RunID, snap.Generation, snap.Status,
		channelID, snap.WorkflowID, snap.TenantID, j.formatTime(effect.ClaimedAt), effect.ClaimToken)
	if err != nil {
		return fmt.Errorf("journal: acknowledge notification delivery: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrTerminalEffectClaimLost
	}
	return nil
}
