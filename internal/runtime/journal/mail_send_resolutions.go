package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// MailSendResolutionInput identifies one admitted provider write exactly. The
// evidence digest refers to an operator-held provider record or manual
// decision; Reactor never accepts or stores that record's raw contents.
type MailSendResolutionInput struct {
	TenantID           string
	RunID              string
	IntentID           string
	Seq                int64
	TargetProviderID   string
	TargetConnectionID string
	Decision           string
	EvidenceKind       string
	EvidenceSHA256     string
	ActorID            string
}

type MailSendResolutionReceipt struct {
	ID             string
	IntentID       string
	Decision       string
	EvidenceKind   string
	EvidenceSHA256 string
	ResolvedAt     time.Time
	Replayed       bool
}

var ErrMailSendResolutionConflict = errors.New("journal: mail send resolution conflicts with recorded outcome")
var ErrMailSendIdentityMismatch = errors.New("journal: mail send identity or target does not match")
var ErrMailSendNotAdmitted = errors.New("journal: mail send is no longer awaiting reconciliation")
var ErrMailSendRunActive = errors.New("journal: mail send run is still active; wait for terminal run and lease release")

// ResolveAdmittedMailSend records one immutable operator finding. It does not
// call a provider, confirm an API acceptance, or authorize a resend. Locking
// the intent serializes this decision with the provider confirmation path.
func (j *Journal) ResolveAdmittedMailSend(ctx context.Context, input MailSendResolutionInput) (MailSendResolutionReceipt, error) {
	if !validMailResolutionInput(input) {
		return MailSendResolutionReceipt{}, errors.New("journal: invalid mail send resolution")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return MailSendResolutionReceipt{}, fmt.Errorf("journal: begin mail send resolution: %w", err)
	}
	defer tx.Rollback()
	if err := j.lockMailSendIntent(ctx, tx, input.IntentID); err != nil {
		return MailSendResolutionReceipt{}, err
	}
	var runID, status, runStatus string
	var seq int64
	var provider, connection sql.NullString
	const identity = `SELECT m.run_id, m.seq, m.status, r.status, m.target_provider_id, m.target_connection_id
		FROM mail_send_intents m JOIN runs r ON r.id = m.run_id
		WHERE m.id = $1 AND m.tenant_id = $2 AND r.tenant_id = $3`
	err = tx.QueryRowContext(ctx, j.bind(identity), input.IntentID, input.TenantID, input.TenantID).
		Scan(&runID, &seq, &status, &runStatus, &provider, &connection)
	if errors.Is(err, sql.ErrNoRows) {
		return MailSendResolutionReceipt{}, ErrNotFound
	}
	if err != nil {
		return MailSendResolutionReceipt{}, fmt.Errorf("journal: read mail send for resolution: %w", err)
	}
	if runID != input.RunID || seq != input.Seq ||
		provider.String != input.TargetProviderID || connection.String != input.TargetConnectionID ||
		provider.Valid != (input.TargetProviderID != "") || connection.Valid != (input.TargetConnectionID != "") {
		return MailSendResolutionReceipt{}, ErrMailSendIdentityMismatch
	}

	var receipt MailSendResolutionReceipt
	var priorActor, priorResolvedAt string
	const prior = `SELECT id, decision, evidence_kind, evidence_sha256, actor_id, resolved_at
		FROM mail_send_resolutions WHERE intent_id = $1 AND tenant_id = $2 AND run_id = $3`
	err = tx.QueryRowContext(ctx, j.bind(prior), input.IntentID, input.TenantID, input.RunID).
		Scan(&receipt.ID, &receipt.Decision, &receipt.EvidenceKind, &receipt.EvidenceSHA256, &priorActor, &priorResolvedAt)
	if err == nil {
		if receipt.Decision != input.Decision || receipt.EvidenceKind != input.EvidenceKind ||
			receipt.EvidenceSHA256 != input.EvidenceSHA256 || priorActor != input.ActorID {
			return MailSendResolutionReceipt{}, ErrMailSendResolutionConflict
		}
		receipt.IntentID = input.IntentID
		receipt.ResolvedAt, err = j.parseTime(priorResolvedAt)
		if err != nil {
			return MailSendResolutionReceipt{}, fmt.Errorf("journal: parse mail send resolution: %w", err)
		}
		receipt.Replayed = true
		return receipt, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return MailSendResolutionReceipt{}, fmt.Errorf("journal: read mail send resolution: %w", err)
	}
	if status != "admitted" {
		return MailSendResolutionReceipt{}, ErrMailSendNotAdmitted
	}
	if runStatus == "running" || runStatus == "queued" || runStatus == "suspended" {
		return MailSendResolutionReceipt{}, ErrMailSendRunActive
	}
	var leased int
	err = tx.QueryRowContext(ctx, j.bind(`SELECT 1 FROM leases WHERE run_id = $1`), input.RunID).Scan(&leased)
	if err == nil {
		return MailSendResolutionReceipt{}, ErrMailSendRunActive
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return MailSendResolutionReceipt{}, fmt.Errorf("journal: verify mail send lease release: %w", err)
	}
	receipt.ID, err = newID("mailresolve_")
	if err != nil {
		return MailSendResolutionReceipt{}, err
	}
	receipt.IntentID = input.IntentID
	receipt.Decision = input.Decision
	receipt.EvidenceKind = input.EvidenceKind
	receipt.EvidenceSHA256 = input.EvidenceSHA256
	const insert = `INSERT INTO mail_send_resolutions
		(id, intent_id, tenant_id, run_id, decision, evidence_kind, evidence_sha256, actor_id, resolved_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	if _, err := tx.ExecContext(ctx, j.bind(insert), receipt.ID, input.IntentID, input.TenantID, input.RunID,
		input.Decision, input.EvidenceKind, input.EvidenceSHA256, input.ActorID, j.now()); err != nil {
		return MailSendResolutionReceipt{}, fmt.Errorf("journal: insert mail send resolution: %w", err)
	}
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT resolved_at FROM mail_send_resolutions WHERE id = $1`), receipt.ID).
		Scan(&priorResolvedAt); err != nil {
		return MailSendResolutionReceipt{}, fmt.Errorf("journal: read saved mail send resolution: %w", err)
	}
	receipt.ResolvedAt, err = j.parseTime(priorResolvedAt)
	if err != nil {
		return MailSendResolutionReceipt{}, fmt.Errorf("journal: parse saved mail send resolution: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return MailSendResolutionReceipt{}, fmt.Errorf("journal: commit mail send resolution: %w", err)
	}
	return receipt, nil
}

func validMailResolutionInput(in MailSendResolutionInput) bool {
	if !validMailResolutionID(in.TenantID, 256) || !validMailResolutionID(in.RunID, 512) ||
		!validMailResolutionID(in.IntentID, 512) || !validMailResolutionID(in.ActorID, 512) ||
		in.Seq <= 0 || !validMailDigest(in.EvidenceSHA256) {
		return false
	}
	if in.TargetProviderID != "" && in.TargetProviderID != "google" && in.TargetProviderID != "microsoft" {
		return false
	}
	if in.TargetConnectionID != "" && !validMailResolutionID(in.TargetConnectionID, 256) {
		return false
	}
	switch in.Decision {
	case "provider_accepted", "provider_rejected":
		return in.EvidenceKind == "provider_record" || in.EvidenceKind == "provider_audit"
	case "closed_unverified":
		return in.EvidenceKind == "manual_decision"
	default:
		return false
	}
}

func validMailResolutionID(value string, maxBytes int) bool {
	return value != "" && len(value) <= maxBytes && utf8.ValidString(value) &&
		strings.IndexFunc(value, func(r rune) bool { return r < 0x21 || r == 0x7f }) < 0
}

// lockMailSendIntent imposes the same row-lock order on provider confirmation
// and manual resolution. SQLite has no SELECT FOR UPDATE, so the first write
// acquires its serialized writer lock before reading the intent or resolution.
func (j *Journal) lockMailSendIntent(ctx context.Context, tx *sql.Tx, intentID string) error {
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE mail_send_intents SET status = status WHERE id = $1`), intentID); err != nil {
			return fmt.Errorf("journal: lock mail send intent: %w", err)
		}
		return nil
	}
	var locked string
	err := tx.QueryRowContext(ctx, j.bind(`SELECT id FROM mail_send_intents WHERE id = $1 FOR UPDATE`), intentID).Scan(&locked)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("journal: lock mail send intent: %w", err)
	}
	return nil
}
