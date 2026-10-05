package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Notification channel kinds.
const (
	ChannelKindSlackWebhook   = "slack_webhook"
	ChannelKindGenericWebhook = "generic_webhook"
	ChannelKindEmailSMTP      = "email_smtp"
)

// NotificationChannel is one configured destination an operator wants
// to receive run-status alerts on. config_json shape varies by kind;
// the notifier package owns the per-kind unmarshalling.
type NotificationChannel struct {
	ID         string          `json:"id"`
	TenantID   string          `json:"tenant_id"`
	Name       string          `json:"name"`
	Kind       string          `json:"kind"`
	ConfigJSON json.RawMessage `json:"config_json"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

// NotificationChannelMetadata is the config-free projection used by control
// plane inventories and dashboard selectors. Channel config can contain
// webhook credentials or SMTP secrets, and legacy rows are not guaranteed to
// have a small JSON blob. Keep the metadata read physically separate from
// NotificationChannel so an inventory cannot materialize or accidentally
// serialize config_json.
type NotificationChannelMetadata struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// WorkflowNotificationRoute pairs a workflow with a channel + the list
// of terminal statuses (comma-separated) that should fire it.
type WorkflowNotificationRoute struct {
	WorkflowID string    `json:"workflow_id"`
	ChannelID  string    `json:"channel_id"`
	OnStatuses string    `json:"on_statuses"`
	CreatedAt  time.Time `json:"created_at"`
}

// ErrChannelInUse is returned by DeleteNotificationChannel when at
// least one workflow_notification_routes row still references the
// channel. Operator-side message: detach the routes first.
var ErrChannelInUse = errors.New("journal: notification channel has active routes")

// ErrChannelNameTaken means the tenant already owns a channel by that name.
// It is scoped per tenant (migration 0027), so this can only ever be a
// collision inside the caller's own tenant. It exists so the handler can render
// something an operator can act on instead of the raw driver text: reporting
// "UNIQUE constraint failed: notification_channels.tenant_id, ..." to a browser
// both leaks schema and tells the user nothing about what to do.
var ErrChannelNameTaken = errors.New("journal: a notification channel with that name already exists")

// CreateNotificationChannel inserts a row + returns the generated id.
// (tenant_id, name) is UNIQUE, so re-creating the same name within one tenant
// returns ErrChannelNameTaken while a different tenant may reuse it freely.
func (j *Journal) CreateNotificationChannel(ctx context.Context, name, kind string, config json.RawMessage) (string, error) {
	id, err := newID("nch_")
	if err != nil {
		return "", err
	}
	if name == "" {
		return "", errors.New("journal: notification channel name is required")
	}
	if !validChannelKind(kind) {
		return "", fmt.Errorf("journal: unknown channel kind %q", kind)
	}
	if !json.Valid(config) {
		return "", errors.New("journal: notification channel config must be valid JSON")
	}
	return j.createChannel(ctx, id, DefaultTenant, name, kind, config)
}

// CreateNotificationChannelInTenant records the owning tenant. A channel is a
// top-level entity reachable only by id, so without this it had no tenant
// anchor at all and every list returned every channel in the install.
func (j *Journal) CreateNotificationChannelInTenant(ctx context.Context, tenantID, name, kind string, config json.RawMessage) (string, error) {
	id, err := newID("nch_")
	if err != nil {
		return "", err
	}
	if name == "" {
		return "", errors.New("journal: notification channel name is required")
	}
	if !validChannelKind(kind) {
		return "", fmt.Errorf("journal: unknown channel kind %q", kind)
	}
	if !json.Valid(config) {
		return "", errors.New("journal: notification channel config must be valid JSON")
	}
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	return j.createChannel(ctx, id, tenantID, name, kind, config)
}

func (j *Journal) createChannel(ctx context.Context, id, tenantID, name, kind string, config json.RawMessage) (string, error) {
	cfg, version, plainBytes, err := j.prepareNotificationConfig(ctx, tenantID, id, kind, config)
	if err != nil {
		return "", err
	}
	const q = `INSERT INTO notification_channels
		(id, tenant_id, name, kind, config_json, config_crypto_version, config_plaintext_bytes)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	if _, err := j.db.ExecContext(ctx, j.bind(q), id, tenantID, name, kind, cfg, version, plainBytes); err != nil {
		if isUniqueViolation(err) {
			return "", ErrChannelNameTaken
		}
		return "", fmt.Errorf("journal: create notification channel: %w", err)
	}
	return id, nil
}

// isUniqueViolation probes a driver error for a uniqueness conflict. sqlite says
// "UNIQUE constraint failed", postgres says "duplicate key value violates unique
// constraint", so sniff both rather than binding to either driver's error type.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate")
}

func validChannelKind(kind string) bool {
	switch kind {
	case ChannelKindSlackWebhook, ChannelKindGenericWebhook, ChannelKindEmailSMTP:
		return true
	}
	return false
}

// ListNotificationChannels returns every channel ordered by name.
func (j *Journal) ListNotificationChannels(ctx context.Context) ([]NotificationChannel, error) {
	return j.ListNotificationChannelsByTenant(ctx, "")
}

// ListNotificationChannelsByTenant scopes the list. An empty tenantID means
// every channel, which is correct for a global admin and wrong for anyone else:
// the member-facing workflow detail page builds its attach-channel <select>
// from this, so an unscoped call there leaks the id/name/kind of every channel
// in the install.
func (j *Journal) ListNotificationChannelsByTenant(ctx context.Context, tenantID string) ([]NotificationChannel, error) {
	q := fmt.Sprintf(`SELECT c.id, c.tenant_id, c.name, c.kind, %s,
		c.config_crypto_version, c.config_plaintext_bytes, c.created_at, c.updated_at
		FROM notification_channels c`, j.notificationConfigProjection("c"))
	args := []any{}
	if tenantID != "" {
		q += ` WHERE c.tenant_id = $1`
		args = append(args, tenantID)
	}
	q += ` ORDER BY c.name ASC`
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, fmt.Errorf("journal: list notification channels: %w", err)
	}
	defer rows.Close()
	var out []NotificationChannel
	for rows.Next() {
		ch, err := scanChannel(rows.Scan, j)
		if err != nil {
			return nil, err
		}
		out = append(out, ch)
	}
	return out, rows.Err()
}

// ListNotificationChannelsByTenantPage returns one bounded full-config channel
// page and a lookahead flag. Metadata-only dashboard and MCP inventories use
// the separate projection below.
func (j *Journal) ListNotificationChannelsByTenantPage(ctx context.Context, tenantID string, limit, offset int) ([]NotificationChannel, bool, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		return nil, false, fmt.Errorf("journal: list notification channels: page limit exceeds 500")
	}
	if offset < 0 {
		return nil, false, fmt.Errorf("journal: list notification channels: negative offset")
	}
	q := fmt.Sprintf(`SELECT c.id, c.tenant_id, c.name, c.kind, %s,
		c.config_crypto_version, c.config_plaintext_bytes, c.created_at, c.updated_at
		FROM notification_channels c WHERE c.tenant_id = $1 ORDER BY c.name ASC, c.id ASC LIMIT %d OFFSET %d`,
		j.notificationConfigProjection("c"), limit+1, offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q), tenantID)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list notification channels page: %w", err)
	}
	defer rows.Close()
	var out []NotificationChannel
	for rows.Next() {
		ch, err := scanChannel(rows.Scan, j)
		if err != nil {
			return nil, false, err
		}
		out = append(out, ch)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

// ListNotificationChannelMetadataPage returns a bounded, install-wide page
// without selecting config_json. Callers must enforce an admin role before
// using this unscoped inventory.
func (j *Journal) ListNotificationChannelMetadataPage(ctx context.Context, limit, offset int) ([]NotificationChannelMetadata, bool, error) {
	return j.listNotificationChannelMetadataPage(ctx, "", limit, offset)
}

// ListNotificationChannelMetadataByTenantPage returns a bounded tenant-scoped
// page without selecting config_json. Control-plane inventories and dashboard
// selectors need the id/name/kind metadata, not destination configuration.
func (j *Journal) ListNotificationChannelMetadataByTenantPage(ctx context.Context, tenantID string, limit, offset int) ([]NotificationChannelMetadata, bool, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, false, errors.New("journal: list notification channel metadata: tenant required")
	}
	return j.listNotificationChannelMetadataPage(ctx, tenantID, limit, offset)
}

func (j *Journal) listNotificationChannelMetadataPage(ctx context.Context, tenantID string, limit, offset int) ([]NotificationChannelMetadata, bool, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		return nil, false, fmt.Errorf("journal: list notification channel metadata: page limit exceeds 500")
	}
	if offset < 0 {
		return nil, false, fmt.Errorf("journal: list notification channel metadata: negative offset")
	}
	q := `SELECT id, tenant_id, name, kind, created_at, updated_at FROM notification_channels`
	args := []any{}
	if tenantID != "" {
		q += ` WHERE tenant_id = $1`
		args = append(args, tenantID)
	}
	q += fmt.Sprintf(` ORDER BY name ASC, id ASC LIMIT %d OFFSET %d`, limit+1, offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list notification channel metadata page: %w", err)
	}
	defer rows.Close()
	out := make([]NotificationChannelMetadata, 0, limit)
	for rows.Next() {
		var (
			ch      NotificationChannelMetadata
			created sql.NullString
			updated sql.NullString
		)
		if err := rows.Scan(&ch.ID, &ch.TenantID, &ch.Name, &ch.Kind, &created, &updated); err != nil {
			return nil, false, fmt.Errorf("journal: scan notification channel metadata page: %w", err)
		}
		if created.Valid {
			if t, parseErr := j.parseTime(created.String); parseErr == nil {
				ch.CreatedAt = t
			}
		}
		if updated.Valid {
			if t, parseErr := j.parseTime(updated.String); parseErr == nil {
				ch.UpdatedAt = t
			}
		}
		out = append(out, ch)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("journal: iterate notification channel metadata page: %w", err)
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

// GetNotificationChannel returns one channel by id.
func (j *Journal) GetNotificationChannel(ctx context.Context, id string) (NotificationChannel, error) {
	return j.getNotificationChannel(ctx, id, "")
}

func (j *Journal) getNotificationChannel(ctx context.Context, id, tenantID string) (NotificationChannel, error) {
	q := fmt.Sprintf(`SELECT c.id, c.tenant_id, c.name, c.kind, %s,
		c.config_crypto_version, c.config_plaintext_bytes, c.created_at, c.updated_at
		FROM notification_channels c WHERE c.id = $1`, j.notificationConfigProjection("c"))
	args := []any{id}
	if tenantID != "" {
		q += ` AND c.tenant_id = $2`
		args = append(args, tenantID)
	}
	row := j.db.QueryRowContext(ctx, j.bind(q), args...)
	ch, err := scanChannel(row.Scan, j)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return NotificationChannel{}, ErrNotFound
		}
		return NotificationChannel{}, err
	}
	return ch, nil
}

// GetNotificationChannelMetadataForTenant resolves one channel without
// selecting config_json. Mutation/control-plane callers only need to prove
// ownership and carry the stable id into a route operation; loading the full
// configuration here would materialize webhook credentials or SMTP secrets
// from legacy rows before the tenant check runs.
func (j *Journal) GetNotificationChannelMetadataForTenant(ctx context.Context, id, tenantID string) (NotificationChannelMetadata, error) {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(tenantID) == "" {
		return NotificationChannelMetadata{}, ErrNotFound
	}
	const q = `SELECT id, tenant_id, name, kind, created_at, updated_at
		FROM notification_channels WHERE id = $1 AND tenant_id = $2`
	row := j.db.QueryRowContext(ctx, j.bind(q), id, tenantID)
	var (
		ch      NotificationChannelMetadata
		created sql.NullString
		updated sql.NullString
	)
	if err := row.Scan(&ch.ID, &ch.TenantID, &ch.Name, &ch.Kind, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return NotificationChannelMetadata{}, ErrNotFound
		}
		return NotificationChannelMetadata{}, fmt.Errorf("journal: get notification channel metadata: %w", err)
	}
	if created.Valid {
		if t, parseErr := j.parseTime(created.String); parseErr == nil {
			ch.CreatedAt = t
		}
	}
	if updated.Valid {
		if t, parseErr := j.parseTime(updated.String); parseErr == nil {
			ch.UpdatedAt = t
		}
	}
	return ch, nil
}

// DeleteNotificationChannel removes a channel. Refuses to proceed when
// any workflow_notification_routes row still references it; operator
// is expected to drop the routes first (or use a cascade if they
// really want to).
func (j *Journal) DeleteNotificationChannel(ctx context.Context, id string) error {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM workflow_notification_routes WHERE channel_id = $1`), id).Scan(&n); err != nil {
		return fmt.Errorf("journal: probe routes: %w", err)
	}
	if n > 0 {
		return fmt.Errorf("%w: %d workflow(s) routed", ErrChannelInUse, n)
	}
	res, err := tx.ExecContext(ctx, j.bind(`DELETE FROM notification_channels WHERE id = $1`), id)
	if err != nil {
		return fmt.Errorf("journal: delete notification channel: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// AddNotificationRoute upserts a (workflow_id, channel_id) row with
// the given on_statuses list. Re-adding the same pair replaces the
// trigger statuses so an operator can broaden / narrow without
// dropping the route first.
func (j *Journal) AddNotificationRoute(ctx context.Context, workflowID, channelID, onStatuses string) error {
	if workflowID == "" || channelID == "" {
		return errors.New("journal: workflow_id and channel_id are required")
	}
	onStatuses = normaliseStatuses(onStatuses)
	if onStatuses == "" {
		return errors.New("journal: on_statuses must list at least one terminal status")
	}
	// Cross-tenant refusal, same shape as GrantSecret. A route is a relation
	// between two owned things, and until migration 0026 gave channels a
	// tenant_id this comparison was impossible, so it was never written: an admin
	// could point tenant A's workflow at tenant B's channel and every failure of
	// A's run (slug, error text, dashboard URL) would be delivered into B's Slack.
	// Requiring both rows to resolve is what makes the comparison meaningful,
	// otherwise a route naming a nonexistent channel silently "succeeds".
	wfTenant, chTenant, err := j.routeTenants(ctx, workflowID, channelID)
	if err != nil {
		return err
	}
	if wfTenant != chTenant {
		return fmt.Errorf("journal: notification route refused: workflow tenant %q != channel tenant %q (cross-tenant routes are not allowed)", wfTenant, chTenant)
	}
	const q = `INSERT INTO workflow_notification_routes (workflow_id, channel_id, on_statuses)
		VALUES ($1, $2, $3)
		ON CONFLICT(workflow_id, channel_id) DO UPDATE SET on_statuses = excluded.on_statuses`
	if _, err := j.db.ExecContext(ctx, j.bind(q), workflowID, channelID, onStatuses); err != nil {
		return fmt.Errorf("journal: add notification route: %w", err)
	}
	return nil
}

// normaliseStatuses trims + lowercases + dedupes + sorts so two
// route inserts with the same intended set produce identical rows.
func normaliseStatuses(s string) string {
	parts := strings.Split(s, ",")
	seen := map[string]bool{}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	// Stable order so equality comparisons round-trip.
	return strings.Join(sortStrings(out), ",")
}

func sortStrings(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// DeleteNotificationRoute drops the (workflow_id, channel_id) pair.
func (j *Journal) DeleteNotificationRoute(ctx context.Context, workflowID, channelID string) error {
	const q = `DELETE FROM workflow_notification_routes WHERE workflow_id = $1 AND channel_id = $2`
	res, err := j.db.ExecContext(ctx, j.bind(q), workflowID, channelID)
	if err != nil {
		return fmt.Errorf("journal: delete notification route: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// ListNotificationRoutesForWorkflow returns every routed channel for
// a workflow plus the joined channel row so the dashboard can render
// channel name + kind without a second lookup.
type NotificationRouteWithChannel struct {
	WorkflowID           string
	ChannelID            string
	ChannelName          string
	ChannelKind          string
	OnStatuses           string
	CreatedAt            time.Time
	ChannelNameBytes     int  `json:"-"`
	ChannelNameTruncated bool `json:"-"`
	OnStatusesBytes      int  `json:"-"`
	OnStatusesTruncated  bool `json:"-"`
}

func (j *Journal) ListNotificationRoutesForWorkflow(ctx context.Context, workflowID string) ([]NotificationRouteWithChannel, error) {
	const q = `SELECT r.workflow_id, r.channel_id, c.name, c.kind, r.on_statuses, r.created_at
		FROM workflow_notification_routes r
		JOIN workflows w ON w.id = r.workflow_id
		JOIN notification_channels c ON c.id = r.channel_id AND c.tenant_id = w.tenant_id
		WHERE r.workflow_id = $1
		ORDER BY c.name ASC`
	rows, err := j.db.QueryContext(ctx, j.bind(q), workflowID)
	if err != nil {
		return nil, fmt.Errorf("journal: list routes for workflow: %w", err)
	}
	defer rows.Close()
	var out []NotificationRouteWithChannel
	for rows.Next() {
		var (
			row     NotificationRouteWithChannel
			created sql.NullString
		)
		if err := rows.Scan(&row.WorkflowID, &row.ChannelID, &row.ChannelName, &row.ChannelKind, &row.OnStatuses, &created); err != nil {
			return nil, err
		}
		if created.Valid {
			if t, perr := j.parseTime(created.String); perr == nil {
				row.CreatedAt = t
			}
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// ListNotificationRoutesForWorkflowPage returns one bounded page plus an
// optional lookahead row. The MCP control plane uses the lookahead to expose
// continuation metadata without counting or loading an unbounded route set.
func (j *Journal) ListNotificationRoutesForWorkflowPage(ctx context.Context, workflowID string, limit, offset int) ([]NotificationRouteWithChannel, error) {
	if limit <= 0 || limit > 500 || offset < 0 {
		return nil, fmt.Errorf("journal: invalid notification route page")
	}
	const q = `SELECT r.workflow_id, r.channel_id, c.name, c.kind, r.on_statuses, r.created_at
		FROM workflow_notification_routes r
		JOIN workflows w ON w.id = r.workflow_id
		JOIN notification_channels c ON c.id = r.channel_id AND c.tenant_id = w.tenant_id
		WHERE r.workflow_id = $1
		ORDER BY c.name ASC, r.channel_id ASC
		LIMIT $2 OFFSET $3`
	rows, err := j.db.QueryContext(ctx, j.bind(q), workflowID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("journal: list route page for workflow: %w", err)
	}
	defer rows.Close()
	var out []NotificationRouteWithChannel
	for rows.Next() {
		var (
			row     NotificationRouteWithChannel
			created sql.NullString
		)
		if err := rows.Scan(&row.WorkflowID, &row.ChannelID, &row.ChannelName, &row.ChannelKind, &row.OnStatuses, &created); err != nil {
			return nil, err
		}
		if created.Valid {
			if t, perr := j.parseTime(created.String); perr == nil {
				row.CreatedAt = t
			}
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// ListNotificationRoutesForWorkflowPageBounded is the MCP/read-model route
// projection. Channel names and status CSVs are operator-controlled text and
// older imports may contain arbitrarily large values. Measure each value in
// SQL and return only a bounded prefix so a route inventory cannot allocate a
// legacy blob merely to redact it after scanning.
func (j *Journal) ListNotificationRoutesForWorkflowPageBounded(ctx context.Context, workflowID string, limit, offset, maxNameBytes, maxStatusesBytes int) ([]NotificationRouteWithChannel, error) {
	if limit <= 0 || limit > 500 || offset < 0 {
		return nil, fmt.Errorf("journal: invalid bounded notification route page")
	}
	if maxNameBytes <= 0 || maxStatusesBytes <= 0 || maxNameBytes > 16<<20 || maxStatusesBytes > 16<<20 {
		return nil, fmt.Errorf("journal: invalid notification route text bounds")
	}
	var nameSize, nameValue, statusesSize, statusesValue string
	if j.engine == EnginePostgres {
		nameSize = "octet_length(c.name)"
		nameValue = fmt.Sprintf("CASE WHEN %s <= %d THEN c.name ELSE left(c.name, %d) END", nameSize, maxNameBytes, maxNameBytes)
		statusesSize = "octet_length(r.on_statuses)"
		statusesValue = fmt.Sprintf("CASE WHEN %s <= %d THEN r.on_statuses ELSE left(r.on_statuses, %d) END", statusesSize, maxStatusesBytes, maxStatusesBytes)
	} else {
		nameSize = "length(CAST(c.name AS BLOB))"
		nameValue = fmt.Sprintf("CASE WHEN %s <= %d THEN c.name ELSE substr(c.name, 1, %d) END", nameSize, maxNameBytes, maxNameBytes)
		statusesSize = "length(CAST(r.on_statuses AS BLOB))"
		statusesValue = fmt.Sprintf("CASE WHEN %s <= %d THEN r.on_statuses ELSE substr(r.on_statuses, 1, %d) END", statusesSize, maxStatusesBytes, maxStatusesBytes)
	}
	q := fmt.Sprintf(`SELECT r.workflow_id, r.channel_id, %s, c.kind, %s, r.created_at, %s, %s
		FROM workflow_notification_routes r
		JOIN workflows w ON w.id = r.workflow_id
		JOIN notification_channels c ON c.id = r.channel_id AND c.tenant_id = w.tenant_id
		WHERE r.workflow_id = $1
		ORDER BY c.name ASC, r.channel_id ASC
		LIMIT %d OFFSET %d`, nameValue, statusesValue, nameSize, statusesSize, limit, offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q), workflowID)
	if err != nil {
		return nil, fmt.Errorf("journal: list bounded route page: %w", err)
	}
	defer rows.Close()
	out := make([]NotificationRouteWithChannel, 0, limit)
	for rows.Next() {
		var (
			row           NotificationRouteWithChannel
			created       sql.NullString
			nameBytes     sql.NullInt64
			statusesBytes sql.NullInt64
		)
		if err := rows.Scan(&row.WorkflowID, &row.ChannelID, &row.ChannelName, &row.ChannelKind, &row.OnStatuses, &created, &nameBytes, &statusesBytes); err != nil {
			return nil, fmt.Errorf("journal: scan bounded route page: %w", err)
		}
		if nameBytes.Valid && nameBytes.Int64 >= 0 {
			row.ChannelNameBytes = int(nameBytes.Int64)
			row.ChannelNameTruncated = row.ChannelNameBytes > len([]byte(row.ChannelName))
		}
		if statusesBytes.Valid && statusesBytes.Int64 >= 0 {
			row.OnStatusesBytes = int(statusesBytes.Int64)
			row.OnStatusesTruncated = row.OnStatusesBytes > len([]byte(row.OnStatuses))
		}
		if created.Valid {
			if t, perr := j.parseTime(created.String); perr == nil {
				row.CreatedAt = t
			}
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// ChannelsForRunTerminal returns the channels that should fire for a
// terminal run. It first filters using route metadata, then loads only the
// matching configurations. Unmatched legacy plaintext configs never enter
// the notifier process merely because their workflow has another route.
//
// status comparison is exact (lowercased) against each route's
// on_statuses CSV. Dispatcher calls this from OnTerminal.
func (j *Journal) ChannelsForRunTerminal(ctx context.Context, workflowID, status string) ([]NotificationChannel, error) {
	const q = `SELECT c.id, c.tenant_id, r.on_statuses
		FROM workflow_notification_routes r
		JOIN workflows w ON w.id = r.workflow_id
		JOIN notification_channels c ON c.id = r.channel_id AND c.tenant_id = w.tenant_id
		WHERE r.workflow_id = $1`
	rows, err := j.db.QueryContext(ctx, j.bind(q), workflowID)
	if err != nil {
		return nil, fmt.Errorf("journal: channels for run terminal: %w", err)
	}
	status = strings.ToLower(strings.TrimSpace(status))
	type route struct{ id, tenant string }
	var selected []route
	for rows.Next() {
		var id, tenantID, onStatuses string
		if err := rows.Scan(&id, &tenantID, &onStatuses); err != nil {
			rows.Close()
			return nil, err
		}
		if routeFiresOn(onStatuses, status) {
			selected = append(selected, route{id, tenantID})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	var out []NotificationChannel
	for _, item := range selected {
		ch, err := j.getNotificationChannel(ctx, item.id, item.tenant)
		if err != nil {
			return nil, err
		}
		if ch.TenantID != item.tenant {
			return nil, ErrNotFound
		}
		out = append(out, ch)
	}
	return out, nil
}

func routeFiresOn(csv, status string) bool {
	for _, s := range strings.Split(csv, ",") {
		if strings.ToLower(strings.TrimSpace(s)) == status {
			return true
		}
	}
	return false
}

func scanChannel(scan func(...any) error, j *Journal) (NotificationChannel, error) {
	var (
		ch         NotificationChannel
		cfgBytes   []byte
		version    int
		plainBytes sql.NullInt64
		created    sql.NullString
		updated    sql.NullString
	)
	if err := scan(&ch.ID, &ch.TenantID, &ch.Name, &ch.Kind, &cfgBytes, &version, &plainBytes, &created, &updated); err != nil {
		return NotificationChannel{}, err
	}
	if err := j.openNotificationConfig(&ch, version, plainBytes, cfgBytes); err != nil {
		return NotificationChannel{}, err
	}
	if created.Valid {
		if t, perr := j.parseTime(created.String); perr == nil {
			ch.CreatedAt = t
		}
	}
	if updated.Valid {
		if t, perr := j.parseTime(updated.String); perr == nil {
			ch.UpdatedAt = t
		}
	}
	return ch, nil
}

// routeTenants resolves the owning tenants of a workflow and a notification
// channel, refusing when either row is missing. Mirrors grantTenants: a relation
// whose endpoints cannot both be resolved is not a relation worth writing, and a
// missing row was how phantom grants got in through MCP and the CLI.
func (j *Journal) routeTenants(ctx context.Context, workflowID, channelID string) (string, string, error) {
	var wfTenant, chTenant sql.NullString
	err := j.db.QueryRowContext(ctx,
		j.bind(`SELECT tenant_id FROM workflows WHERE id = $1`), workflowID).Scan(&wfTenant)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", fmt.Errorf("journal: notification route: unknown workflow %q", workflowID)
	}
	if err != nil {
		return "", "", fmt.Errorf("journal: notification route: lookup workflow tenant: %w", err)
	}
	err = j.db.QueryRowContext(ctx,
		j.bind(`SELECT tenant_id FROM notification_channels WHERE id = $1`), channelID).Scan(&chTenant)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", fmt.Errorf("journal: notification route: unknown channel %q", channelID)
	}
	if err != nil {
		return "", "", fmt.Errorf("journal: notification route: lookup channel tenant: %w", err)
	}
	return wfTenant.String, chTenant.String, nil
}
