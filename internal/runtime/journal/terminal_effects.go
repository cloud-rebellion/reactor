package journal

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

// TerminalEffect is a durable at-least-once receipt for the side effects that
// follow a committed terminal run (notifications and workflow-complete
// chains). The run status is authoritative; this row records whether the host
// has handed the event to those side-effect handlers plus the claim generation
// that owns an in-flight handoff.
type TerminalEffect struct {
	RunID      string
	Status     string
	ClaimedAt  time.Time
	ClaimToken string
}

// ErrTerminalEffectClaimLost means the receipt was delivered, reset for a
// newer terminal generation, or claimed by another owner before this owner
// could acknowledge/release it. Callers must not clear or acknowledge the row
// after this error: doing so could mutate the newer generation.
var ErrTerminalEffectClaimLost = errors.New("journal: terminal effect claim lost")

// TerminalEffectEvent is the small read model needed to replay a terminal
// hook after a daemon crash. It intentionally contains no step output or
// trigger payload beyond the bounded error summary.
type TerminalEffectEvent struct {
	RunID        string
	WorkflowID   string
	WorkflowSlug string
	Status       string
	TriggerKind  string
	ErrorText    string
}

// maxTerminalEffectErrorBytes bounds the untrusted step error copied into a
// notification or workflow-complete chain payload. A workflow controls its
// error text, and the wire frame limit alone is not a suitable downstream
// contract: one failed step could otherwise make every terminal recovery read
// and fan-out nearly a megabyte of attacker-controlled data.
const maxTerminalEffectErrorBytes = 4096

const terminalEffectErrorTruncatedSuffix = "\n[truncated]"

func boundTerminalEffectError(text string) string {
	if len(text) <= maxTerminalEffectErrorBytes {
		return text
	}
	// Keep the marker inside the limit so callers can safely use this value in
	// JSON, headers, and chained trigger input without a second size check.
	keep := maxTerminalEffectErrorBytes - len(terminalEffectErrorTruncatedSuffix)
	prefix := strings.ToValidUTF8(text[:keep], "�")
	// strings.ToValidUTF8 can replace an incomplete final rune, but it may
	// expand the prefix by a byte. Trim by rune boundary if that happened.
	for len(prefix)+len(terminalEffectErrorTruncatedSuffix) > maxTerminalEffectErrorBytes {
		_, size := utf8.DecodeLastRuneInString(prefix)
		if size == 0 || size > len(prefix) {
			break
		}
		prefix = prefix[:len(prefix)-size]
	}
	return prefix + terminalEffectErrorTruncatedSuffix
}

func terminalEffectStatus(status string) bool {
	switch status {
	case StatusSucceeded, StatusFailed, "failed_dlq":
		return true
	default:
		return false
	}
}

// enqueueTerminalEffectTx must run in the same transaction that commits the
// terminal run status. ON CONFLICT keeps repeated recovery/finalization calls
// idempotent without resetting an already delivered receipt.
func (j *Journal) enqueueTerminalEffectTx(ctx context.Context, tx *sql.Tx, runID, status string) error {
	if !terminalEffectStatus(status) {
		return nil
	}
	_, err := tx.ExecContext(ctx, j.bind(`INSERT INTO terminal_effects (run_id, status, created_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (run_id) DO UPDATE SET status = excluded.status, attempts = 0,
		claimed_at = NULL, claim_token = NULL, delivered_at = NULL, last_error = NULL, created_at = excluded.created_at
		WHERE terminal_effects.delivered_at IS NULL`), runID, status, j.now())
	if err != nil {
		return fmt.Errorf("journal: enqueue terminal effect: %w", err)
	}
	return nil
}

// ClaimTerminalEffects claims a bounded batch for one leader. A stale claim
// is recoverable after a process crash; delivery is intentionally at-least-once
// because a crash between the external side effect and acknowledgement may
// replay the event. Receivers should deduplicate by run id where possible.
func (j *Journal) ClaimTerminalEffects(ctx context.Context, limit int, lease time.Duration) ([]TerminalEffect, error) {
	if limit <= 0 {
		limit = 32
	}
	if limit > 256 {
		limit = 256
	}
	if lease <= 0 {
		lease = 2 * time.Minute
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("journal: begin terminal effect claim: %w", err)
	}
	defer tx.Rollback()
	cutoff := j.formatTime(time.Now().UTC().Add(-lease))
	q := `SELECT run_id, status FROM terminal_effects
		WHERE delivered_at IS NULL AND (claimed_at IS NULL OR claimed_at < $1)
		ORDER BY created_at, run_id LIMIT $2`
	if j.engine == EnginePostgres {
		q += ` FOR UPDATE SKIP LOCKED`
	}
	rows, err := tx.QueryContext(ctx, j.bind(q), cutoff, limit)
	if err != nil {
		return nil, fmt.Errorf("journal: select terminal effects: %w", err)
	}
	defer rows.Close()
	claimAt, now := j.terminalEffectClaimNow()
	var claimed []TerminalEffect
	for rows.Next() {
		var effect TerminalEffect
		if err := rows.Scan(&effect.RunID, &effect.Status); err != nil {
			return nil, fmt.Errorf("journal: scan terminal effect: %w", err)
		}
		claimToken, err := newTerminalEffectClaimToken()
		if err != nil {
			return nil, fmt.Errorf("journal: generate terminal effect claim token: %w", err)
		}
		res, err := tx.ExecContext(ctx, j.bind(`UPDATE terminal_effects
			SET claimed_at = $1, claim_token = $2, attempts = attempts + 1
			WHERE run_id = $3 AND status = $4 AND delivered_at IS NULL
				AND (claimed_at IS NULL OR claimed_at < $5)`), now, claimToken, effect.RunID, effect.Status, cutoff)
		if err != nil {
			return nil, fmt.Errorf("journal: claim terminal effect %s: %w", effect.RunID, err)
		}
		if n, _ := res.RowsAffected(); n == 1 {
			effect.ClaimedAt = claimAt
			effect.ClaimToken = claimToken
			claimed = append(claimed, effect)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("journal: iterate terminal effects: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("journal: close terminal effects: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("journal: commit terminal effect claim: %w", err)
	}
	return claimed, nil
}

// ClaimTerminalEffect claims one known receipt for the direct terminal path.
// Recovery claims a batch with ClaimTerminalEffects; direct dispatches need a
// run-scoped CAS so a slow old handler cannot later acknowledge a newer retry
// generation that reuses the same run id.
func (j *Journal) ClaimTerminalEffect(ctx context.Context, runID, status string, lease time.Duration) (TerminalEffect, error) {
	if runID == "" || !terminalEffectStatus(status) {
		return TerminalEffect{}, ErrTerminalEffectClaimLost
	}
	if lease <= 0 {
		lease = 2 * time.Minute
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return TerminalEffect{}, fmt.Errorf("journal: begin terminal effect claim: %w", err)
	}
	defer tx.Rollback()
	cutoff := j.formatTime(time.Now().UTC().Add(-lease))
	claimAt, now := j.terminalEffectClaimNow()
	claimToken, err := newTerminalEffectClaimToken()
	if err != nil {
		return TerminalEffect{}, fmt.Errorf("journal: generate terminal effect claim token: %w", err)
	}
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE terminal_effects
		SET claimed_at = $1, claim_token = $2, attempts = attempts + 1
		WHERE run_id = $3 AND status = $4 AND delivered_at IS NULL
			AND (claimed_at IS NULL OR claimed_at < $5)
			AND EXISTS (SELECT 1 FROM runs WHERE runs.id = terminal_effects.run_id AND runs.status = $6)`), now, claimToken, runID, status, cutoff, status)
	if err != nil {
		return TerminalEffect{}, fmt.Errorf("journal: claim terminal effect %s: %w", runID, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return TerminalEffect{}, ErrTerminalEffectClaimLost
	}
	if err := tx.Commit(); err != nil {
		return TerminalEffect{}, fmt.Errorf("journal: commit terminal effect claim: %w", err)
	}
	return TerminalEffect{RunID: runID, Status: status, ClaimedAt: claimAt, ClaimToken: claimToken}, nil
}

func newTerminalEffectClaimToken() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// terminalEffectClaimNow returns one timestamp in both the representation
// written to the database and the time.Time carried by the claim token. SQLite
// stores milliseconds, so normalize there or an exact claim fence comparison
// would fail when the value is read back through a later operation.
func (j *Journal) terminalEffectClaimNow() (time.Time, any) {
	now := time.Now().UTC()
	if j.engine == EngineSQLite {
		now = now.Truncate(time.Millisecond)
	}
	return now, j.formatTime(now)
}

// MarkTerminalEffectDelivered acknowledges a receipt by run id. It is retained
// for compatibility with older callers; new terminal handlers must use
// MarkTerminalEffectDeliveredForClaim so a late acknowledgement cannot mutate
// a newer retry generation.
func (j *Journal) MarkTerminalEffectDelivered(ctx context.Context, runID string) error {
	res, err := j.db.ExecContext(ctx, j.bind(`UPDATE terminal_effects
		SET delivered_at = $1, claimed_at = NULL, claim_token = NULL, last_error = NULL
		WHERE run_id = $2 AND delivered_at IS NULL`), j.now(), runID)
	if err != nil {
		return fmt.Errorf("journal: acknowledge terminal effect: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var one int
		if err := j.db.QueryRowContext(ctx, j.bind(`SELECT 1 FROM terminal_effects WHERE run_id = $1`), runID).Scan(&one); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("journal: inspect terminal effect acknowledgement: %w", err)
		}
	}
	return nil
}

// MarkTerminalEffectDeliveredForClaim acknowledges only the exact claim that
// performed the side effects. The status + claimed_at fence protects a retry
// generation that reuses the same run id from a late acknowledgement.
func (j *Journal) MarkTerminalEffectDeliveredForClaim(ctx context.Context, effect TerminalEffect) error {
	if effect.RunID == "" || effect.Status == "" || effect.ClaimedAt.IsZero() || effect.ClaimToken == "" {
		return ErrTerminalEffectClaimLost
	}
	res, err := j.db.ExecContext(ctx, j.bind(`UPDATE terminal_effects
		SET delivered_at = $1, claimed_at = NULL, claim_token = NULL, last_error = NULL
		WHERE run_id = $2 AND status = $3 AND delivered_at IS NULL AND claimed_at = $4 AND claim_token = $5`),
		j.now(), effect.RunID, effect.Status, j.formatTime(effect.ClaimedAt), effect.ClaimToken)
	if err != nil {
		return fmt.Errorf("journal: acknowledge terminal effect claim: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrTerminalEffectClaimLost
	}
	return nil
}

// ReleaseTerminalEffect makes a failed replay eligible for a later leader
// tick while preserving a bounded diagnostic for operators. It is retained for
// compatibility; new handlers should use ReleaseTerminalEffectForClaim.
func (j *Journal) ReleaseTerminalEffect(ctx context.Context, runID, reason string) error {
	if len(reason) > 1000 {
		reason = reason[:1000]
	}
	_, err := j.db.ExecContext(ctx, j.bind(`UPDATE terminal_effects
		SET claimed_at = NULL, claim_token = NULL, last_error = $1 WHERE run_id = $2 AND delivered_at IS NULL`), reason, runID)
	if err != nil {
		return fmt.Errorf("journal: release terminal effect: %w", err)
	}
	return nil
}

// ReleaseTerminalEffectForClaim clears a failed claim only when it still owns
// the same generation. A stale handler must leave any newer retry claim alone.
func (j *Journal) ReleaseTerminalEffectForClaim(ctx context.Context, effect TerminalEffect, reason string) error {
	if len(reason) > 1000 {
		reason = reason[:1000]
	}
	if effect.RunID == "" || effect.Status == "" || effect.ClaimedAt.IsZero() || effect.ClaimToken == "" {
		return ErrTerminalEffectClaimLost
	}
	res, err := j.db.ExecContext(ctx, j.bind(`UPDATE terminal_effects
		SET claimed_at = NULL, claim_token = NULL, last_error = $1
		WHERE run_id = $2 AND status = $3 AND delivered_at IS NULL AND claimed_at = $4 AND claim_token = $5`),
		reason, effect.RunID, effect.Status, j.formatTime(effect.ClaimedAt), effect.ClaimToken)
	if err != nil {
		return fmt.Errorf("journal: release terminal effect claim: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrTerminalEffectClaimLost
	}
	return nil
}

// GetTerminalEffectEvent reconstructs the safe event envelope used by the
// daemon's terminal hook. Error text is limited to the latest failed step and
// never includes arbitrary outputs.
func (j *Journal) GetTerminalEffectEvent(ctx context.Context, runID string) (TerminalEffectEvent, error) {
	const q = `SELECT r.id, r.workflow_id, w.slug, r.status, r.trigger_kind
		FROM runs r JOIN workflows w ON w.id = r.workflow_id WHERE r.id = $1`
	var event TerminalEffectEvent
	if err := j.db.QueryRowContext(ctx, j.bind(q), runID).Scan(
		&event.RunID, &event.WorkflowID, &event.WorkflowSlug, &event.Status, &event.TriggerKind,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TerminalEffectEvent{}, ErrNotFound
		}
		return TerminalEffectEvent{}, fmt.Errorf("journal: get terminal effect event: %w", err)
	}
	query := fmt.Sprintf(`SELECT steps.step_name, steps.seq, steps.attempt, steps.payload_crypto_version,
		steps.error_plaintext_bytes,
		CASE WHEN steps.payload_crypto_version = 1 AND %s <= %d THEN steps.error_text
			WHEN steps.payload_crypto_version = 0 THEN SUBSTR(steps.error_text, 1, %d)
			ELSE NULL END,
		runs.tenant_id FROM steps JOIN runs ON runs.id = steps.run_id
		WHERE steps.run_id = $1 AND steps.error_text IS NOT NULL AND steps.error_text <> ''
		ORDER BY steps.finished_at DESC, steps.seq DESC, steps.attempt DESC LIMIT 1`,
		stepErrorStoredSize(j.engine), payloadcrypto.CiphertextLimit(maxStepPayloadPlaintextBytes),
		maxTerminalEffectErrorBytes)
	var (
		stepName   string
		seq        int64
		attempt    int
		version    int
		plainBytes sql.NullInt64
		errorText  sql.NullString
		tenantID   string
	)
	stepErr := j.db.QueryRowContext(ctx, j.bind(query), runID).Scan(&stepName, &seq, &attempt,
		&version, &plainBytes, &errorText, &tenantID)
	if stepErr == nil {
		if !errorText.Valid || version == 1 && (!plainBytes.Valid || plainBytes.Int64 < 0 || plainBytes.Int64 > maxStepPayloadPlaintextBytes) {
			return TerminalEffectEvent{}, payloadcrypto.ErrInvalidEnvelope
		}
		opened, err := j.openStepError(tenantID, runID, stepName, seq, attempt, version, plainBytes, errorText.String)
		if err != nil {
			return TerminalEffectEvent{}, err
		}
		event.ErrorText = boundTerminalEffectError(opened)
	} else if stepErr != nil && !errors.Is(stepErr, sql.ErrNoRows) {
		// A terminal effect must be retried when its event cannot be
		// reconstructed. Silently dropping the error text would acknowledge a
		// notification/chain with incomplete failure context.
		return TerminalEffectEvent{}, fmt.Errorf("journal: get terminal effect error summary: %w", stepErr)
	}
	return event, nil
}
