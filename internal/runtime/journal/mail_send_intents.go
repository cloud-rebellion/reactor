package journal

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// MailSendDispositionSend authorizes exactly one provider POST after a durable
// intent has committed. All other dispositions prohibit egress.
type MailSendDisposition string

const (
	MailSendDispositionSend      MailSendDisposition = "send"
	MailSendDispositionConfirmed MailSendDisposition = "confirmed"
	MailSendDispositionAmbiguous MailSendDisposition = "ambiguous"
)

type MailSendAdmission struct {
	Disposition MailSendDisposition
	IntentID    string
	ProviderID  string
	MessageID   string
}

// MailSendTarget contains non-secret routing IDs, not an OAuth token or
// message address. Recording it before egress lets an operator identify the
// provider account to inspect when the provider response is lost.
type MailSendTarget struct {
	ProviderID   string
	ConnectionID string
}

// AdmitMailSend creates the one durable provider-write intent for a run call
// ordinal before egress. The exact running Step, its nonempty key, the live
// run, and (if distributed) its lease generation must all still be current.
// Empty leaseOwner is accepted only when no lease exists for the local run.
// A replay never authorizes another POST: confirmed matching requests return
// the cached acceptance; all other duplicates need manual reconciliation.
func (j *Journal) AdmitMailSend(ctx context.Context, runID, leaseOwner, stepName string, seq int64, attempt int, idempotencyKey, requestDigest string, target MailSendTarget) (MailSendAdmission, error) {
	if runID == "" || len(runID) > 512 || stepName == "" || len(stepName) > 512 || !utf8.ValidString(stepName) ||
		seq <= 0 || attempt <= 0 || strings.TrimSpace(idempotencyKey) == "" || len(idempotencyKey) > 4096 ||
		!validMailDigest(requestDigest) || (target.ProviderID != "google" && target.ProviderID != "microsoft") ||
		target.ConnectionID == "" || len(target.ConnectionID) > 256 || !utf8.ValidString(target.ConnectionID) ||
		strings.IndexFunc(target.ConnectionID, func(r rune) bool { return r < 0x21 || r == 0x7f }) >= 0 {
		return MailSendAdmission{}, errors.New("journal: invalid mail send identity or digest")
	}
	keyHash := sha256.Sum256([]byte(idempotencyKey))
	keyDigest := hex.EncodeToString(keyHash[:])
	intentID, err := newID("mailsend_")
	if err != nil {
		return MailSendAdmission{}, err
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return MailSendAdmission{}, fmt.Errorf("journal: begin mail send admission: %w", err)
	}
	defer tx.Rollback()

	// This is the lease -> run lock order used by step_start, reaping and
	// finalization. SQLite acquires its writer lock before any state read.
	deadline, err := j.lockStepMutation(ctx, tx, runID, leaseOwner)
	if err != nil {
		return MailSendAdmission{}, err
	}
	var status, runTenant string
	var cancelRequested bool
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT status, cancel_requested, tenant_id FROM runs WHERE id = $1`), runID).
		Scan(&status, &cancelRequested, &runTenant); err != nil {
		return MailSendAdmission{}, fmt.Errorf("journal: read mail send run: %w", err)
	}
	if status != "running" || cancelRequested || runTenant == "" {
		return MailSendAdmission{}, fmt.Errorf("%w: mail send run=%s is no longer active", ErrLeaseOwnershipLost, runID)
	}
	if leaseOwner == "" {
		var leased int
		err := tx.QueryRowContext(ctx, j.bind(`SELECT 1 FROM leases WHERE run_id = $1`), runID).Scan(&leased)
		if err == nil {
			return MailSendAdmission{}, fmt.Errorf("%w: mail send requires lease owner run=%s", ErrLeaseOwnershipLost, runID)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return MailSendAdmission{}, fmt.Errorf("journal: verify unleased mail send run: %w", err)
		}
	}

	// A stale attempt must not send even if a legacy client left its row
	// running. A later attempt with the same ordinal owns the call instead.
	const stepQ = `SELECT 1 FROM steps s WHERE s.run_id = $1 AND s.step_name = $2
		AND s.seq = $3 AND s.attempt = $4 AND s.idempotency_key = $5
		AND s.status = 'running' AND NOT EXISTS (
			SELECT 1 FROM steps newer WHERE newer.run_id = s.run_id
			AND newer.seq = s.seq AND newer.step_name = s.step_name
			AND newer.attempt > s.attempt)`
	var active int
	err = tx.QueryRowContext(ctx, j.bind(stepQ), runID, stepName, seq, attempt, idempotencyKey).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return MailSendAdmission{}, fmt.Errorf("%w: mail send step is not the current running attempt", ErrStepAttemptNotRunning)
	}
	if err != nil {
		return MailSendAdmission{}, fmt.Errorf("journal: verify mail send step: %w", err)
	}

	const insert = `INSERT INTO mail_send_intents
		(id, run_id, step_name, seq, attempt, idempotency_key_sha256, request_sha256,
		 target_provider_id, target_connection_id, tenant_id, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'admitted', $11)
		ON CONFLICT (run_id, seq) DO NOTHING`
	res, err := tx.ExecContext(ctx, j.bind(insert), intentID, runID, stepName, seq, attempt, keyDigest,
		requestDigest, target.ProviderID, target.ConnectionID, runTenant, j.now())
	if err != nil {
		return MailSendAdmission{}, fmt.Errorf("journal: insert mail send intent: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return MailSendAdmission{}, fmt.Errorf("journal: inspect mail send admission: %w", err)
	}
	admission := MailSendAdmission{Disposition: MailSendDispositionSend, IntentID: intentID}
	if inserted == 0 {
		var previousStep, previousKeyHash, previousDigest, previousStatus string
		var previousProvider, previousMessage, previousTargetProvider, previousTargetConnection sql.NullString
		const lookup = `SELECT id, step_name, idempotency_key_sha256, request_sha256,
			status, provider_id, message_id, target_provider_id, target_connection_id
			FROM mail_send_intents WHERE run_id = $1 AND seq = $2`
		err := tx.QueryRowContext(ctx, j.bind(lookup), runID, seq).Scan(
			&admission.IntentID, &previousStep, &previousKeyHash, &previousDigest,
			&previousStatus, &previousProvider, &previousMessage, &previousTargetProvider, &previousTargetConnection)
		if err != nil {
			return MailSendAdmission{}, fmt.Errorf("journal: read prior mail send intent: %w", err)
		}
		admission.Disposition = MailSendDispositionAmbiguous
		if previousStep == stepName && previousKeyHash == keyDigest && previousDigest == requestDigest &&
			previousStatus == "confirmed" && previousProvider.Valid &&
			(!previousTargetProvider.Valid || previousTargetProvider.String == target.ProviderID) &&
			(!previousTargetConnection.Valid || previousTargetConnection.String == target.ConnectionID) {
			admission.Disposition = MailSendDispositionConfirmed
			admission.ProviderID = previousProvider.String
			admission.MessageID = previousMessage.String
		}
	}
	if err := checkStepMutationDeadline(runID, deadline); err != nil {
		return MailSendAdmission{}, err
	}
	if err := tx.Commit(); err != nil {
		return MailSendAdmission{}, fmt.Errorf("journal: commit mail send admission: %w", err)
	}
	return admission, nil
}

// ConfirmMailSend records a provider's accepted response. It intentionally
// does not require a live lease: acceptance can precede cancellation or lease
// loss, and hiding that outcome would make a replay look uncertain. Only the
// same acceptance can be confirmed again.
func (j *Journal) ConfirmMailSend(ctx context.Context, intentID, providerID, messageID string) error {
	if intentID == "" || len(intentID) > 512 || (providerID != "google" && providerID != "microsoft") ||
		len(messageID) > 512 || !utf8.ValidString(messageID) || strings.ContainsAny(messageID, "\x00\r\n") {
		return errors.New("journal: invalid mail send confirmation")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin mail send confirmation: %w", err)
	}
	defer tx.Rollback()
	if err := j.lockMailSendIntent(ctx, tx, intentID); err != nil {
		return err
	}
	var status string
	var targetProvider, previousProvider, previousMessage sql.NullString
	err = tx.QueryRowContext(ctx, j.bind(`SELECT status, target_provider_id, provider_id, message_id
		FROM mail_send_intents WHERE id = $1`), intentID).
		Scan(&status, &targetProvider, &previousProvider, &previousMessage)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("journal: read mail send confirmation: %w", err)
	}
	if status == "confirmed" {
		if previousProvider.String != providerID || previousMessage.String != messageID {
			return errors.New("journal: mail send intent confirmed with a different provider acceptance")
		}
		return nil
	}
	if status != "admitted" || (targetProvider.Valid && targetProvider.String != providerID) {
		return ErrMailSendNotAdmitted
	}
	var resolved int
	err = tx.QueryRowContext(ctx, j.bind(`SELECT 1 FROM mail_send_resolutions WHERE intent_id = $1`), intentID).Scan(&resolved)
	if err == nil {
		return ErrMailSendResolutionConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("journal: check mail send resolution: %w", err)
	}
	var storedMessage any
	if messageID != "" {
		storedMessage = messageID
	}
	const update = `UPDATE mail_send_intents SET status = 'confirmed', provider_id = $1,
		message_id = $2, confirmed_at = $3 WHERE id = $4 AND status = 'admitted'`
	res, err := tx.ExecContext(ctx, j.bind(update), providerID, storedMessage, j.now(), intentID)
	if err != nil {
		return fmt.Errorf("journal: confirm mail send intent: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("journal: inspect mail send confirmation: %w", err)
	}
	if n != 1 {
		return ErrMailSendNotAdmitted
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit mail send confirmation: %w", err)
	}
	return nil
}

func validMailDigest(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	for _, c := range digest {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
