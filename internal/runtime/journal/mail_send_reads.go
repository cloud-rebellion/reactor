package journal

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// MailSendIntentReceipt is the value-free control-plane view of one durable
// provider-write intent. Admitted means the provider may or may not have
// accepted a send; only confirmed means an acceptance was persisted.
type MailSendIntentReceipt struct {
	ID             string
	RunID          string
	StepName       string
	Seq            int64
	Attempt        int
	Status         string
	ProviderID     string
	ConnectionID   string
	TargetRecorded bool
	MessageIDKnown bool
	CreatedAt      time.Time
	ConfirmedAt    time.Time
	Resolution     *MailSendResolutionReceipt
	createdAtRaw   string
}

var ErrInvalidMailSendCursor = errors.New("journal: invalid mail send cursor")

// ListMailSendIntentsForRunTenant returns a bounded chronological page. The
// run join enforces the tenant fence in the same query as the intent read;
// request bytes, recipient addresses, token material and request hashes are
// deliberately not selected.
func (j *Journal) ListMailSendIntentsForRunTenant(ctx context.Context, runID, tenantID string, limit, offset int) ([]MailSendIntentReceipt, bool, error) {
	if runID == "" || len(runID) > 512 || tenantID == "" || limit < 1 || limit > 100 || offset < 0 || offset > 10000 {
		return nil, false, errors.New("journal: invalid mail send read page")
	}
	const q = `SELECT m.id, m.run_id, m.step_name, m.seq, m.attempt, m.status,
		m.provider_id, m.target_provider_id, m.target_connection_id,
		CASE WHEN m.message_id IS NULL THEN 0 ELSE 1 END, m.created_at, m.confirmed_at,
		x.id, x.decision, x.evidence_kind, x.resolved_at
		FROM mail_send_intents m JOIN runs r ON r.id = m.run_id
		LEFT JOIN mail_send_resolutions x ON x.intent_id = m.id
		WHERE m.run_id = $1 AND r.tenant_id = $2
		ORDER BY m.seq ASC LIMIT $3 OFFSET $4`
	rows, err := j.db.QueryContext(ctx, j.bind(q), runID, tenantID, limit+1, offset)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list mail send intents: %w", err)
	}
	defer rows.Close()
	out := make([]MailSendIntentReceipt, 0, limit)
	for rows.Next() {
		item, err := j.scanMailSendIntent(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("journal: iterate mail send intents: %w", err)
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

// ListAdmittedMailSendIntentsForTenant is the operator's cross-run
// reconciliation queue. A committed admitted row means provider acceptance is
// unknown, even when the run has since failed or been cancelled. The indexed
// tenant/status/time seek avoids scanning another tenant's mail history and a
// growing OFFSET. The run join independently checks the tenant fence.
// Pagination reflects current state: a concurrently confirmed row disappears
// from the queue, and a new send after page one appears on a fresh first page.
func (j *Journal) ListAdmittedMailSendIntentsForTenant(ctx context.Context, tenantID string, limit int, cursor string) ([]MailSendIntentReceipt, bool, string, error) {
	if tenantID == "" || limit < 1 || limit > 100 {
		return nil, false, "", errors.New("journal: invalid admitted mail send page")
	}
	const selectQ = `SELECT m.id, m.run_id, m.step_name, m.seq, m.attempt, m.status,
		m.provider_id, m.target_provider_id, m.target_connection_id,
		CASE WHEN m.message_id IS NULL THEN 0 ELSE 1 END, m.created_at, m.confirmed_at,
		x.id, x.decision, x.evidence_kind, x.resolved_at
		FROM mail_send_intents m JOIN runs r ON r.id = m.run_id
		LEFT JOIN mail_send_resolutions x ON x.intent_id = m.id
		WHERE m.tenant_id = $1 AND r.tenant_id = $2 AND m.status = 'admitted' AND x.id IS NULL`
	q := selectQ + ` ORDER BY m.created_at DESC, m.id DESC LIMIT $3`
	args := []any{tenantID, tenantID, limit + 1}
	if cursor != "" {
		position, err := j.decodeMailSendCursor(cursor)
		if err != nil {
			return nil, false, "", err
		}
		q = selectQ + ` AND (m.created_at < $3 OR (m.created_at = $4 AND m.id < $5))
			ORDER BY m.created_at DESC, m.id DESC LIMIT $6`
		args = []any{tenantID, tenantID, position.CreatedAt, position.CreatedAt, position.ID, limit + 1}
	}
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, false, "", fmt.Errorf("journal: list admitted mail sends: %w", err)
	}
	defer rows.Close()
	out := make([]MailSendIntentReceipt, 0, limit+1)
	for rows.Next() {
		item, err := j.scanMailSendIntent(rows)
		if err != nil {
			return nil, false, "", err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, "", fmt.Errorf("journal: iterate admitted mail sends: %w", err)
	}
	more := len(out) > limit
	if !more {
		return out, false, "", nil
	}
	out = out[:limit]
	next, err := encodeMailSendCursor(mailSendCursor{CreatedAt: out[len(out)-1].createdAtRaw, ID: out[len(out)-1].ID})
	if err != nil {
		return nil, false, "", err
	}
	return out, true, next, nil
}

type mailSendCursor struct {
	CreatedAt string `json:"t"`
	ID        string `json:"i"`
}

func encodeMailSendCursor(cursor mailSendCursor) (string, error) {
	b, err := json.Marshal(cursor)
	if err != nil {
		return "", fmt.Errorf("journal: encode mail send cursor: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (j *Journal) decodeMailSendCursor(raw string) (mailSendCursor, error) {
	if len(raw) > 1024 {
		return mailSendCursor{}, ErrInvalidMailSendCursor
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return mailSendCursor{}, ErrInvalidMailSendCursor
	}
	var cursor mailSendCursor
	if err := json.Unmarshal(b, &cursor); err != nil || cursor.ID == "" || len(cursor.ID) > 512 ||
		cursor.CreatedAt == "" || len(cursor.CreatedAt) > 64 {
		return mailSendCursor{}, ErrInvalidMailSendCursor
	}
	if _, err := j.parseTime(cursor.CreatedAt); err != nil {
		return mailSendCursor{}, ErrInvalidMailSendCursor
	}
	return cursor, nil
}

func (j *Journal) scanMailSendIntent(rows *sql.Rows) (MailSendIntentReceipt, error) {
	var item MailSendIntentReceipt
	var acceptedProvider, targetProvider, targetConnection, createdAt, confirmedAt sql.NullString
	var resolutionID, decision, evidenceKind, resolvedAt sql.NullString
	var messageKnown int
	if err := rows.Scan(&item.ID, &item.RunID, &item.StepName, &item.Seq, &item.Attempt,
		&item.Status, &acceptedProvider, &targetProvider, &targetConnection,
		&messageKnown, &createdAt, &confirmedAt,
		&resolutionID, &decision, &evidenceKind, &resolvedAt); err != nil {
		return item, fmt.Errorf("journal: scan mail send intent: %w", err)
	}
	if !createdAt.Valid {
		return item, errors.New("journal: mail send intent missing creation time")
	}
	var err error
	item.createdAtRaw = createdAt.String
	item.CreatedAt, err = j.parseTime(createdAt.String)
	if err != nil {
		return item, fmt.Errorf("journal: parse mail send creation time: %w", err)
	}
	if confirmedAt.Valid {
		item.ConfirmedAt, err = j.parseTime(confirmedAt.String)
		if err != nil {
			return item, fmt.Errorf("journal: parse mail send confirmation time: %w", err)
		}
	}
	item.ProviderID = targetProvider.String
	if item.ProviderID == "" {
		item.ProviderID = acceptedProvider.String // pre-0074 confirmed rows
	}
	item.ConnectionID = targetConnection.String
	item.TargetRecorded = targetProvider.Valid && targetConnection.Valid
	item.MessageIDKnown = messageKnown == 1
	if resolutionID.Valid {
		if !decision.Valid || !evidenceKind.Valid || !resolvedAt.Valid {
			return item, errors.New("journal: incomplete mail send resolution")
		}
		at, err := j.parseTime(resolvedAt.String)
		if err != nil {
			return item, fmt.Errorf("journal: parse mail send resolution time: %w", err)
		}
		item.Resolution = &MailSendResolutionReceipt{
			ID: resolutionID.String, IntentID: item.ID,
			Decision: decision.String, EvidenceKind: evidenceKind.String, ResolvedAt: at,
		}
	}
	return item, nil
}
