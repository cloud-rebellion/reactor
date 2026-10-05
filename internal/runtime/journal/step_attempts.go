package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

// ErrStepAttemptDivergence means a restarted workflow reached the same durable
// call ordinal with different step inputs. Allocating another attempt would
// apply one retry budget to two different operations, so callers must fail the
// run rather than execute the closure.
var ErrStepAttemptDivergence = errors.New("journal: durable step attempt diverged")

// ErrStepAttemptNotRunning is returned when a duplicate/late StepEnd tries to
// mutate an attempt whose ownership was already completed or fenced.
var ErrStepAttemptNotRunning = errors.New("journal: durable step attempt is no longer running")

// StatusRedrive marks the terminal attempt from which an operator explicitly
// authorized a fresh DLQ retry window. It is distinct from StatusRetrying (an
// automatic one-attempt continuation) and cannot be produced by step_end.
const StatusRedrive = "redrive"

// StatusInterrupted fences an in-flight attempt when a reaped/restarted worker
// consumes the next number. A late StepEnd from the expired owner is then
// rejected by the status='running' compare-and-set.
const StatusInterrupted = "interrupted"

// StatusDLQPending is a durable repair checkpoint. The step outcome is
// terminal, but its exact operator-visible dead-letter row did not commit.
// Workers must not execute the closure again; they re-enter the idempotent DLQ
// repair and remain lease-reapable until it succeeds.
const StatusDLQPending = "dlq_pending"

// StepAttemptState is the latest durable checkpoint for one exact logical step
// call. Seq is part of the identity: repeated uses of one step name in a loop
// have independent attempt budgets.
type StepAttemptState struct {
	StepName       string
	Seq            int64
	Attempt        int
	IdempotencyKey string
	InputHash      string
	Status         string
	Output         json.RawMessage
	ErrorText      string
	RetryNotBefore time.Time
}

// StepAttemptClaim is the result of host-owned attempt allocation. Exhausted
// means no row was inserted and the workflow closure must not run. Previous is
// populated whenever an earlier attempt existed, including the interrupted
// running row that consumed the last budget slot.
type StepAttemptClaim struct {
	Attempt       int
	BudgetAttempt int
	Exhausted     bool
	RetryWait     time.Duration
	Previous      *StepAttemptState
}

// ClaimStepAttemptSeq atomically assigns and records the next attempt for the
// exact (run_id, seq, step_name) tuple. A persisted step_start consumes an
// attempt even if its worker dies before step_end. maxAttempts is the total
// finite budget; zero means a custom policy did not expose one.
//
// A completed retryable outcome (StatusRetrying) is an explicit durable grant
// for the next attempt, even for a legacy custom policy with no reported max.
// An interrupted StatusRunning row without a finite bound fails closed when
// maxAttempts is zero because the host cannot prove another call is allowed.
func (j *Journal) ClaimStepAttemptSeq(ctx context.Context, runID, stepName string, seq int64, maxAttempts int, idemKey, inputHash string) (StepAttemptClaim, error) {
	return j.claimStepAttemptSeq(ctx, runID, "", stepName, seq, maxAttempts, idemKey, inputHash)
}

// ClaimOwnedStepAttemptSeq fences a distributed StepStart to the exact live
// lease generation before it grants permission to execute the closure.
func (j *Journal) ClaimOwnedStepAttemptSeq(ctx context.Context, runID, owner, stepName string, seq int64, maxAttempts int, idemKey, inputHash string) (StepAttemptClaim, error) {
	if owner == "" {
		return StepAttemptClaim{}, errors.New("journal: claim owned step: empty lease owner")
	}
	return j.claimStepAttemptSeq(ctx, runID, owner, stepName, seq, maxAttempts, idemKey, inputHash)
}

func (j *Journal) claimStepAttemptSeq(ctx context.Context, runID, owner, stepName string, seq int64, maxAttempts int, idemKey, inputHash string) (StepAttemptClaim, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return StepAttemptClaim{}, fmt.Errorf("journal: begin step attempt claim: %w", err)
	}
	defer tx.Rollback()

	// Lock lease before run, matching reaping/finalization. This also makes
	// allocation atomic with a replacement worker taking over the same run.
	leaseDeadline, err := j.lockStepMutation(ctx, tx, runID, owner)
	if err != nil {
		return StepAttemptClaim{}, err
	}

	previous, found, err := latestStepAttemptTx(ctx, tx, j, runID, stepName, seq)
	if err != nil {
		return StepAttemptClaim{}, err
	}
	claim := StepAttemptClaim{Attempt: 1, BudgetAttempt: 1}
	if found {
		claim.Previous = &previous
		if previous.IdempotencyKey != idemKey || previous.InputHash != inputHash {
			return StepAttemptClaim{}, fmt.Errorf("%w: run=%s step=%s seq=%d", ErrStepAttemptDivergence, runID, stepName, seq)
		}

		redriveBase, err := redriveBaseAttemptTx(ctx, tx, j, runID, stepName, seq)
		if err != nil {
			return StepAttemptClaim{}, err
		}
		switch previous.Status {
		case StatusRunning:
			// The start itself consumed the prior number. A finite budget is
			// required to prove that a post-crash continuation is safe.
			if maxAttempts <= 0 {
				claim.Attempt = previous.Attempt
				claim.Exhausted = true
				return commitStepAttemptClaim(tx, runID, leaseDeadline, claim)
			}
		case StatusRetrying:
			// step_end durably recorded that the policy authorized one more.
		case StatusRedrive:
			// StartDeadLetterRetry atomically changed the terminal attempt into
			// an explicit operator-authorized fresh budget baseline.
		case StatusFailed, StatusSucceeded, StatusDLQPending:
			claim.Attempt = previous.Attempt
			claim.BudgetAttempt = previous.Attempt - redriveBase
			if claim.BudgetAttempt <= 0 {
				claim.BudgetAttempt = previous.Attempt
			}
			claim.Exhausted = true
			return commitStepAttemptClaim(tx, runID, leaseDeadline, claim)
		default:
			return StepAttemptClaim{}, fmt.Errorf("journal: unsupported step status %q for run=%s step=%s seq=%d", previous.Status, runID, stepName, seq)
		}
		claim.Attempt = previous.Attempt + 1
		if claim.Attempt <= 0 {
			return StepAttemptClaim{}, fmt.Errorf("journal: step attempt counter overflow for run=%s step=%s seq=%d", runID, stepName, seq)
		}
		claim.BudgetAttempt = claim.Attempt - redriveBase
		if claim.BudgetAttempt <= 0 {
			return StepAttemptClaim{}, fmt.Errorf("journal: invalid redrive attempt baseline for run=%s step=%s seq=%d", runID, stepName, seq)
		}
	}

	if maxAttempts > 0 && claim.BudgetAttempt > maxAttempts {
		claim.Exhausted = true
		return commitStepAttemptClaim(tx, runID, leaseDeadline, claim)
	}
	if found && previous.Status == StatusRetrying && !previous.RetryNotBefore.IsZero() {
		if wait := time.Until(previous.RetryNotBefore); wait > 0 {
			// Do not consume a retry budget slot while merely waiting. The
			// deadline survives a host/worker crash and is rechecked by the
			// next claimant under the same run lock.
			claim.RetryWait = wait
			return commitStepAttemptClaim(tx, runID, leaseDeadline, claim)
		}
	}
	if found && previous.Status == StatusRunning {
		const fence = `UPDATE steps SET status = $1, finished_at = $2
			WHERE run_id = $3 AND step_name = $4 AND seq = $5 AND attempt = $6 AND status = $7`
		res, err := tx.ExecContext(ctx, j.bind(fence),
			StatusInterrupted, j.now(), runID, stepName, seq, previous.Attempt, StatusRunning,
		)
		if err != nil {
			return StepAttemptClaim{}, fmt.Errorf("journal: fence interrupted step attempt: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return StepAttemptClaim{}, fmt.Errorf("journal: interrupted step attempt changed concurrently for run=%s step=%s seq=%d attempt=%d", runID, stepName, seq, previous.Attempt)
		}
	}

	const insert = `INSERT INTO steps
		(run_id, step_name, seq, attempt, idempotency_key, input_hash, status, started_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	if _, err := tx.ExecContext(ctx, j.bind(insert),
		runID, stepName, seq, claim.Attempt, nullable(idemKey), inputHash, StatusRunning, j.now(),
	); err != nil {
		return StepAttemptClaim{}, fmt.Errorf("journal: insert durable step_start: %w", err)
	}
	if err := checkStepMutationDeadline(runID, leaseDeadline); err != nil {
		return StepAttemptClaim{}, err
	}
	if err := tx.Commit(); err != nil {
		return StepAttemptClaim{}, fmt.Errorf("journal: commit step attempt claim: %w", err)
	}
	return claim, nil
}

func redriveBaseAttemptTx(ctx context.Context, tx *sql.Tx, j *Journal, runID, stepName string, seq int64) (int, error) {
	const q = `SELECT COALESCE(MAX(attempt), 0) FROM steps
		WHERE run_id = $1 AND seq = $2 AND step_name = $3 AND status = $4`
	var base int
	if err := tx.QueryRowContext(ctx, j.bind(q), runID, seq, stepName, StatusRedrive).Scan(&base); err != nil {
		return 0, fmt.Errorf("journal: find step redrive baseline: %w", err)
	}
	return base, nil
}

func commitStepAttemptClaim(tx *sql.Tx, runID string, leaseDeadline time.Time, claim StepAttemptClaim) (StepAttemptClaim, error) {
	if err := checkStepMutationDeadline(runID, leaseDeadline); err != nil {
		return StepAttemptClaim{}, err
	}
	if err := tx.Commit(); err != nil {
		return StepAttemptClaim{}, fmt.Errorf("journal: commit exhausted step attempt claim: %w", err)
	}
	return claim, nil
}

// lockStepMutation uses the lease -> run order shared by the reaper and run
// finalizer. Local steps still serialize on the run; owned steps additionally
// require the exact generation and a running parent before any step mutation.
func (j *Journal) lockStepMutation(ctx context.Context, tx *sql.Tx, runID, owner string) (time.Time, error) {
	var deadline time.Time
	if owner != "" {
		var err error
		deadline, err = j.lockOwnedLease(ctx, tx, runID, owner)
		if err != nil {
			return time.Time{}, err
		}
	}
	if err := lockRunForStepRepair(ctx, tx, j, runID); err != nil {
		return time.Time{}, err
	}
	if owner != "" {
		var status string
		if err := tx.QueryRowContext(ctx, j.bind(`SELECT status FROM runs WHERE id = $1`), runID).Scan(&status); err != nil {
			return time.Time{}, fmt.Errorf("journal: read owned step run status: %w", err)
		}
		if status != "running" {
			return time.Time{}, fmt.Errorf("%w: step run=%s status=%s", ErrLeaseOwnershipLost, runID, status)
		}
	}
	return deadline, nil
}

func checkStepMutationDeadline(runID string, deadline time.Time) error {
	if !deadline.IsZero() {
		return checkOwnedLeaseDeadline(runID, deadline)
	}
	return nil
}

// RecordOwnedStepStartSeq retains old wire-client compatibility while fencing
// its non-durable StepStart to the exact distributed lease generation.
func (j *Journal) RecordOwnedStepStartSeq(ctx context.Context, runID, owner, stepName string, seq int64, attempt int, idemKey, inputHash string) (bool, error) {
	if owner == "" {
		return false, errors.New("journal: record owned step start: empty lease owner")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("journal: begin owned step start: %w", err)
	}
	defer tx.Rollback()
	deadline, err := j.lockStepMutation(ctx, tx, runID, owner)
	if err != nil {
		return false, err
	}
	const q = `INSERT INTO steps
		(run_id, step_name, seq, attempt, idempotency_key, input_hash, status, started_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING`
	res, err := tx.ExecContext(ctx, j.bind(q), runID, stepName, seq, attempt, nullable(idemKey), inputHash, StatusRunning, j.now())
	if err != nil {
		return false, fmt.Errorf("journal: insert owned step start: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("journal: inspect owned step start: %w", err)
	}
	if err := checkStepMutationDeadline(runID, deadline); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("journal: commit owned step start: %w", err)
	}
	return inserted == 1, nil
}

// RecordOwnedStepEndSeq is the old wire-client outcome path. A stale worker
// cannot overwrite a replacement's attempt or cached result.
func (j *Journal) RecordOwnedStepEndSeq(ctx context.Context, runID, owner, stepName string, seq int64, attempt int, output json.RawMessage, errText string) error {
	if owner == "" {
		return errors.New("journal: record owned step end: empty lease owner")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin owned step end: %w", err)
	}
	defer tx.Rollback()
	deadline, err := j.lockStepMutation(ctx, tx, runID, owner)
	if err != nil {
		return err
	}
	payload, err := j.prepareStepPayload(ctx, tx, runID, stepName, seq, attempt, output, errText)
	if err != nil {
		return err
	}
	status := StatusSucceeded
	if errText != "" {
		status = StatusFailed
	}
	const q = `UPDATE steps SET status = $1, output_jsonb = $2, error_text = $3, finished_at = $4,
		payload_crypto_version = $5, output_plaintext_bytes = $6, error_plaintext_bytes = $7
		WHERE run_id = $8 AND step_name = $9 AND seq = $10 AND attempt = $11 AND status = $12`
	res, err := tx.ExecContext(ctx, j.bind(q), status, payload.output, payload.errorText, j.now(),
		payload.version, payload.outputBytes, payload.errorBytes, runID, stepName, seq, attempt, StatusRunning)
	if err != nil {
		return fmt.Errorf("journal: update owned step end: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: (%s, %s, seq=%d, attempt=%d)", ErrStepAttemptNotRunning, runID, stepName, seq, attempt)
	}
	if err := checkStepMutationDeadline(runID, deadline); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit owned step end: %w", err)
	}
	return nil
}

func latestStepAttemptTx(ctx context.Context, tx *sql.Tx, j *Journal, runID, stepName string, seq int64) (StepAttemptState, bool, error) {
	q := fmt.Sprintf(`SELECT steps.step_name, steps.seq, steps.attempt, steps.idempotency_key, steps.input_hash,
		steps.status, %s, %s, steps.retry_not_before,
		runs.tenant_id, steps.payload_crypto_version, steps.output_plaintext_bytes, steps.error_plaintext_bytes,
		steps.output_jsonb IS NOT NULL, steps.error_text IS NOT NULL
		FROM steps JOIN runs ON runs.id = steps.run_id
		WHERE steps.run_id = $1 AND steps.seq = $2 AND steps.step_name = $3
		ORDER BY steps.attempt DESC LIMIT 1`, stepOutputReplayValue(j.engine), stepErrorReplayValue(j.engine))
	return scanStepAttempt(j, tx.QueryRowContext(ctx, j.bind(q), runID, seq, stepName), runID, stepName, seq)
}

// LatestStepAttemptSeq returns the newest row for an exact logical step call.
func (j *Journal) LatestStepAttemptSeq(ctx context.Context, runID, stepName string, seq int64) (StepAttemptState, error) {
	q := fmt.Sprintf(`SELECT steps.step_name, steps.seq, steps.attempt, steps.idempotency_key, steps.input_hash,
		steps.status, %s, %s, steps.retry_not_before,
		runs.tenant_id, steps.payload_crypto_version, steps.output_plaintext_bytes, steps.error_plaintext_bytes,
		steps.output_jsonb IS NOT NULL, steps.error_text IS NOT NULL
		FROM steps JOIN runs ON runs.id = steps.run_id
		WHERE steps.run_id = $1 AND steps.seq = $2 AND steps.step_name = $3
		ORDER BY steps.attempt DESC LIMIT 1`, stepOutputReplayValue(j.engine), stepErrorReplayValue(j.engine))
	state, found, err := scanStepAttempt(j, j.db.QueryRowContext(ctx, j.bind(q), runID, seq, stepName), runID, stepName, seq)
	if err != nil {
		return StepAttemptState{}, err
	}
	if !found {
		return StepAttemptState{}, ErrNotFound
	}
	return state, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanStepAttempt(j *Journal, row rowScanner, runID, stepName string, seq int64) (StepAttemptState, bool, error) {
	var (
		state          StepAttemptState
		idem           sql.NullString
		output         []byte
		errText        sql.NullString
		retryNotBefore sql.NullString
		tenantID       string
		version        int
		outputBytes    sql.NullInt64
		errorBytes     sql.NullInt64
		outputPresent  bool
		errorPresent   bool
	)
	if err := row.Scan(&state.StepName, &state.Seq, &state.Attempt, &idem, &state.InputHash, &state.Status,
		&output, &errText, &retryNotBefore, &tenantID, &version, &outputBytes, &errorBytes,
		&outputPresent, &errorPresent); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return StepAttemptState{}, false, nil
		}
		return StepAttemptState{}, false, fmt.Errorf("journal: latest step attempt for run=%s step=%s seq=%d: %w", runID, stepName, seq, err)
	}
	state.IdempotencyKey = idem.String
	if version == 1 && (outputPresent != outputBytes.Valid || errorPresent != errorBytes.Valid ||
		outputPresent && output == nil || errorPresent && !errText.Valid) {
		return StepAttemptState{}, false, payloadcrypto.ErrInvalidEnvelope
	}
	openedOutput, openedError, err := j.openStepValues(tenantID, runID, state.StepName, state.Seq, state.Attempt,
		version, outputBytes, errorBytes, output, errText)
	if err != nil {
		return StepAttemptState{}, false, fmt.Errorf("journal: open step attempt: %w", err)
	}
	state.Output, state.ErrorText = openedOutput, openedError
	if retryNotBefore.Valid {
		parsed, err := j.parseTime(retryNotBefore.String)
		if err != nil {
			return StepAttemptState{}, false, fmt.Errorf("journal: invalid retry deadline for run=%s step=%s seq=%d: %w", runID, stepName, seq, err)
		}
		state.RetryNotBefore = parsed
	}
	return state, true, nil
}

// AttemptCountSeq returns the number of rows for an exact logical step call.
func (j *Journal) AttemptCountSeq(ctx context.Context, runID, stepName string, seq int64) (int, error) {
	const q = `SELECT COUNT(*) FROM steps WHERE run_id = $1 AND seq = $2 AND step_name = $3`
	var count int
	if err := j.db.QueryRowContext(ctx, j.bind(q), runID, seq, stepName).Scan(&count); err != nil {
		return 0, fmt.Errorf("journal: durable attempt count: %w", err)
	}
	return count, nil
}

// RecordStepEndWithRetrySeq persists the continuation decision made by the
// workflow policy. A retryable error uses StatusRetrying, distinguishing it
// from a terminal failed attempt after a host restart without a schema change.
func (j *Journal) RecordStepEndWithRetrySeq(ctx context.Context, runID, stepName string, seq int64, attempt int, output json.RawMessage, errText string, retryable bool) error {
	status := StatusSucceeded
	if errText != "" {
		status = StatusFailed
		if retryable {
			status = StatusRetrying
		}
	}
	payload, err := j.prepareStepPayload(ctx, j.db, runID, stepName, seq, attempt, output, errText)
	if err != nil {
		return err
	}
	const q = `UPDATE steps SET status = $1, output_jsonb = $2, error_text = $3, finished_at = $4,
		payload_crypto_version = $5, output_plaintext_bytes = $6, error_plaintext_bytes = $7
		WHERE run_id = $8 AND step_name = $9 AND seq = $10 AND attempt = $11 AND status = $12`
	res, err := j.db.ExecContext(ctx, j.bind(q),
		status, payload.output, payload.errorText, j.now(), payload.version, payload.outputBytes, payload.errorBytes,
		runID, stepName, seq, attempt, StatusRunning,
	)
	if err != nil {
		return fmt.Errorf("journal: update durable step_end: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: (%s, %s, seq=%d, attempt=%d)", ErrStepAttemptNotRunning, runID, stepName, seq, attempt)
	}
	return nil
}

// FinalizeStepAttemptSeq atomically persists a durable step outcome and, for a
// terminal failure, ensures a DLQ row exists before commit. If the DLQ insert
// fails the step UPDATE rolls back to running, so restart recovery can safely
// retry/finalize it; Reactor never acknowledges a terminal failed row that has
// silently fallen out of the operator queue.
func (j *Journal) FinalizeStepAttemptSeq(ctx context.Context, runID, stepName string, seq int64, attempt int, output json.RawMessage, errText string, retryable bool) (deadLettered bool, err error) {
	return j.FinalizeStepAttemptSeqWithRetryAfter(ctx, runID, stepName, seq, attempt, output, errText, retryable, 0)
}

// FinalizeStepAttemptSeqWithRetryAfter also persists the provider's minimum
// wait for a retryable attempt. The next claim checks it before allocating a
// new attempt, including after a worker crash or lease reap.
func (j *Journal) FinalizeStepAttemptSeqWithRetryAfter(ctx context.Context, runID, stepName string, seq int64, attempt int, output json.RawMessage, errText string, retryable bool, retryAfter time.Duration) (deadLettered bool, err error) {
	return j.finalizeStepAttemptSeqWithRetryAfter(ctx, runID, "", stepName, seq, attempt, output, errText, retryable, retryAfter)
}

// FinalizeOwnedStepAttemptSeqWithRetryAfter rejects outcomes from a worker
// whose claim expired or was replaced, including an otherwise valid StepEnd.
func (j *Journal) FinalizeOwnedStepAttemptSeqWithRetryAfter(ctx context.Context, runID, owner, stepName string, seq int64, attempt int, output json.RawMessage, errText string, retryable bool, retryAfter time.Duration) (bool, error) {
	if owner == "" {
		return false, errors.New("journal: finalize owned step: empty lease owner")
	}
	return j.finalizeStepAttemptSeqWithRetryAfter(ctx, runID, owner, stepName, seq, attempt, output, errText, retryable, retryAfter)
}

func (j *Journal) finalizeStepAttemptSeqWithRetryAfter(ctx context.Context, runID, owner, stepName string, seq int64, attempt int, output json.RawMessage, errText string, retryable bool, retryAfter time.Duration) (deadLettered bool, err error) {
	if retryAfter < 0 || retryAfter > 30*time.Second || (retryAfter > 0 && (!retryable || errText == "")) {
		return false, errors.New("journal: invalid provider retry delay")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("journal: begin durable step finalize: %w", err)
	}
	defer tx.Rollback()
	var leaseDeadline time.Time
	if owner != "" {
		leaseDeadline, err = j.lockStepMutation(ctx, tx, runID, owner)
		if err != nil {
			return false, err
		}
	}

	status := StatusSucceeded
	if errText != "" {
		status = StatusFailed
		if retryable {
			status = StatusRetrying
		}
	}
	payload, err := j.prepareStepPayload(ctx, tx, runID, stepName, seq, attempt, output, errText)
	if err != nil {
		return false, err
	}
	var retryNotBefore any
	if retryAfter > 0 {
		// SQLite stores millisecond timestamps. Round up so formatting never
		// shaves time off the provider's minimum wait.
		deadline := time.Now().UTC().Add(retryAfter).Add(time.Millisecond - 1).Truncate(time.Millisecond)
		retryNotBefore = j.formatTime(deadline)
	}
	const update = `UPDATE steps SET status = $1, output_jsonb = $2, error_text = $3, finished_at = $4, retry_not_before = $5,
		payload_crypto_version = $6, output_plaintext_bytes = $7, error_plaintext_bytes = $8
		WHERE run_id = $9 AND step_name = $10 AND seq = $11 AND attempt = $12 AND status = $13`
	res, err := tx.ExecContext(ctx, j.bind(update),
		status, payload.output, payload.errorText, j.now(), retryNotBefore,
		payload.version, payload.outputBytes, payload.errorBytes, runID, stepName, seq, attempt, StatusRunning,
	)
	if err != nil {
		return false, fmt.Errorf("journal: update durable step outcome: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, fmt.Errorf("%w: (%s, %s, seq=%d, attempt=%d)", ErrStepAttemptNotRunning, runID, stepName, seq, attempt)
	}

	if errText != "" && !retryable {
		id, idErr := newID("dlq_")
		if idErr != nil {
			return false, idErr
		}
		order, orderErr := j.nextDeadLetterFailureOrder(ctx, tx, runID)
		if orderErr != nil {
			return false, orderErr
		}
		sealed, sealErr := j.prepareDeadLetterPayload(ctx, tx, id, runID, stepName, &seq, &attempt, order, errText, output)
		if sealErr != nil {
			return false, sealErr
		}
		if _, err := tx.ExecContext(ctx, j.bind(insertDeadLetterSQL),
			id, runID, stepName, seq, attempt, order, sealed.errorText, sealed.payload,
			sealed.version, sealed.errorBytes, sealed.payloadBytes); err != nil {
			return false, fmt.Errorf("journal: insert terminal step dead_letter: %w", err)
		}
		deadLettered = true
	}

	if err := checkStepMutationDeadline(runID, leaseDeadline); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("journal: commit durable step finalize: %w", err)
	}
	return deadLettered, nil
}

// FinalizeExhaustedStepAttemptSeq closes the last budget slot when a wire
// client previously advertised retryable=true but its next StepStart proves
// that the durable Max is already exhausted. Both running (crashed after
// StepStart) and retrying (mismatched/hostile continuation hint) are valid
// predecessors; the failed checkpoint and exact DLQ row commit together.
func (j *Journal) FinalizeExhaustedStepAttemptSeq(ctx context.Context, runID, stepName string, seq int64, attempt int, output json.RawMessage, errText string) error {
	return j.finalizeExhaustedStepAttemptSeq(ctx, runID, "", stepName, seq, attempt, output, errText)
}

func (j *Journal) FinalizeOwnedExhaustedStepAttemptSeq(ctx context.Context, runID, owner, stepName string, seq int64, attempt int, output json.RawMessage, errText string) error {
	if owner == "" {
		return errors.New("journal: finalize owned exhausted step: empty lease owner")
	}
	return j.finalizeExhaustedStepAttemptSeq(ctx, runID, owner, stepName, seq, attempt, output, errText)
}

func (j *Journal) finalizeExhaustedStepAttemptSeq(ctx context.Context, runID, owner, stepName string, seq int64, attempt int, output json.RawMessage, errText string) error {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin exhausted step finalize: %w", err)
	}
	defer tx.Rollback()
	var leaseDeadline time.Time
	if owner != "" {
		leaseDeadline, err = j.lockStepMutation(ctx, tx, runID, owner)
		if err != nil {
			return err
		}
	}
	payload, err := j.prepareStepPayload(ctx, tx, runID, stepName, seq, attempt, output, errText)
	if err != nil {
		return err
	}

	const update = `UPDATE steps SET status = $1, output_jsonb = $2, error_text = $3, finished_at = $4,
		payload_crypto_version = $5, output_plaintext_bytes = $6, error_plaintext_bytes = $7
		WHERE run_id = $8 AND step_name = $9 AND seq = $10 AND attempt = $11
			AND status IN ($12, $13)`
	res, err := tx.ExecContext(ctx, j.bind(update),
		StatusFailed, payload.output, payload.errorText, j.now(), payload.version, payload.outputBytes, payload.errorBytes,
		runID, stepName, seq, attempt, StatusRunning, StatusRetrying,
	)
	if err != nil {
		return fmt.Errorf("journal: update exhausted step outcome: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: exhausted (%s, %s, seq=%d, attempt=%d)", ErrStepAttemptNotRunning, runID, stepName, seq, attempt)
	}

	id, err := newID("dlq_")
	if err != nil {
		return err
	}
	order, err := j.nextDeadLetterFailureOrder(ctx, tx, runID)
	if err != nil {
		return err
	}
	sealed, err := j.prepareDeadLetterPayload(ctx, tx, id, runID, stepName, &seq, &attempt, order, errText, output)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, j.bind(insertDeadLetterSQL),
		id, runID, stepName, seq, attempt, order, sealed.errorText, sealed.payload,
		sealed.version, sealed.errorBytes, sealed.payloadBytes,
	); err != nil {
		return fmt.Errorf("journal: insert exhausted step dead_letter: %w", err)
	}
	if err := checkStepMutationDeadline(runID, leaseDeadline); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit exhausted step finalize: %w", err)
	}
	return nil
}

// HasDeadLetterForStep reports whether the current DLQ already has an item for
// the run/step pair. dead_letter predates step ordinals, so this is the
// narrowest identity available without a migration.
func (j *Journal) HasDeadLetterForStep(ctx context.Context, runID, stepName string) (bool, error) {
	const q = `SELECT 1 FROM dead_letter WHERE run_id = $1 AND step_name = $2 LIMIT 1`
	var one int
	if err := j.db.QueryRowContext(ctx, j.bind(q), runID, stepName).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("journal: probe step dead_letter: %w", err)
	}
	return true, nil
}

// HasDeadLetterForStepAttempt probes the exact durable identity used by new
// supervisors. Legacy NULL-identity rows intentionally do not satisfy it.
func (j *Journal) HasDeadLetterForStepAttempt(ctx context.Context, runID, stepName string, seq int64, attempt int) (bool, error) {
	const q = `SELECT 1 FROM dead_letter
		WHERE run_id = $1 AND step_name = $2 AND step_seq = $3 AND step_attempt = $4 LIMIT 1`
	var one int
	if err := j.db.QueryRowContext(ctx, j.bind(q), runID, stepName, seq, attempt).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("journal: probe exact step dead_letter: %w", err)
	}
	return true, nil
}

// EnsureStepAttemptDeadLetter idempotently repairs the exact DLQ identity for
// a terminal durable attempt. A missing row first commits StatusDLQPending,
// then inserts the exact DLQ row and restores StatusFailed atomically in a
// second transaction. If that insert fails, the durable pending marker remains
// visible to the lease reaper and the next worker retries repair without ever
// invoking the closure again.
func (j *Journal) EnsureStepAttemptDeadLetter(ctx context.Context, runID, stepName string, seq int64, attempt int, errorText string, payload json.RawMessage) (bool, error) {
	return j.ensureStepAttemptDeadLetter(ctx, runID, "", stepName, seq, attempt, errorText, payload)
}

func (j *Journal) EnsureOwnedStepAttemptDeadLetter(ctx context.Context, runID, owner, stepName string, seq int64, attempt int, errorText string, payload json.RawMessage) (bool, error) {
	if owner == "" {
		return false, errors.New("journal: repair owned step dead letter: empty lease owner")
	}
	return j.ensureStepAttemptDeadLetter(ctx, runID, owner, stepName, seq, attempt, errorText, payload)
}

func (j *Journal) ensureStepAttemptDeadLetter(ctx context.Context, runID, owner, stepName string, seq int64, attempt int, errorText string, payload json.RawMessage) (bool, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("journal: begin exact dead-letter repair: %w", err)
	}
	defer tx.Rollback()

	leaseDeadline, err := j.lockStepMutation(ctx, tx, runID, owner)
	if err != nil {
		return false, err
	}

	var status string
	const stateQ = `SELECT status FROM steps
		WHERE run_id = $1 AND step_name = $2 AND seq = $3 AND attempt = $4`
	if err := tx.QueryRowContext(ctx, j.bind(stateQ), runID, stepName, seq, attempt).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, fmt.Errorf("journal: read exact dead-letter attempt: %w", err)
	}
	if status != StatusFailed && status != StatusDLQPending {
		return false, fmt.Errorf("%w: exact dead-letter attempt status %q", ErrStepAttemptNotRunning, status)
	}

	const existsQ = `SELECT 1 FROM dead_letter
		WHERE run_id = $1 AND step_name = $2 AND step_seq = $3 AND step_attempt = $4 LIMIT 1`
	var one int
	probeErr := tx.QueryRowContext(ctx, j.bind(existsQ), runID, stepName, seq, attempt).Scan(&one)
	if probeErr == nil {
		if status == StatusDLQPending {
			const repaired = `UPDATE steps SET status = $1 WHERE run_id = $2 AND step_name = $3
				AND seq = $4 AND attempt = $5 AND status = $6`
			res, err := tx.ExecContext(ctx, j.bind(repaired), StatusFailed, runID, stepName, seq, attempt, StatusDLQPending)
			if err != nil {
				return false, fmt.Errorf("journal: close observed dead-letter repair: %w", err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return false, fmt.Errorf("journal: exact dead-letter repair marker changed concurrently")
			}
		}
		if err := checkStepMutationDeadline(runID, leaseDeadline); err != nil {
			return false, err
		}
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("journal: commit exact dead-letter observation: %w", err)
		}
		return false, nil
	}
	if !errors.Is(probeErr, sql.ErrNoRows) {
		return false, fmt.Errorf("journal: probe exact dead-letter repair: %w", probeErr)
	}

	if status == StatusFailed {
		const mark = `UPDATE steps SET status = $1 WHERE run_id = $2 AND step_name = $3
			AND seq = $4 AND attempt = $5 AND status = $6`
		res, err := tx.ExecContext(ctx, j.bind(mark), StatusDLQPending, runID, stepName, seq, attempt, StatusFailed)
		if err != nil {
			return false, fmt.Errorf("journal: mark exact dead-letter repair pending: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return false, fmt.Errorf("journal: exact dead-letter repair state changed concurrently")
		}
	}
	if err := checkStepMutationDeadline(runID, leaseDeadline); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("journal: commit exact dead-letter repair marker: %w", err)
	}

	return j.completeStepAttemptDeadLetterRepair(ctx, runID, owner, stepName, seq, attempt, errorText, payload)
}

func (j *Journal) completeStepAttemptDeadLetterRepair(ctx context.Context, runID, owner, stepName string, seq int64, attempt int, errorText string, payload json.RawMessage) (bool, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("journal: begin pending dead-letter repair: %w", err)
	}
	defer tx.Rollback()
	leaseDeadline, err := j.lockStepMutation(ctx, tx, runID, owner)
	if err != nil {
		return false, err
	}

	var status string
	const stateQ = `SELECT status FROM steps
		WHERE run_id = $1 AND step_name = $2 AND seq = $3 AND attempt = $4`
	if err := tx.QueryRowContext(ctx, j.bind(stateQ), runID, stepName, seq, attempt).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, fmt.Errorf("journal: read pending dead-letter attempt: %w", err)
	}
	if status != StatusDLQPending {
		return false, fmt.Errorf("%w: pending dead-letter attempt status %q", ErrStepAttemptNotRunning, status)
	}

	const existsQ = `SELECT 1 FROM dead_letter
		WHERE run_id = $1 AND step_name = $2 AND step_seq = $3 AND step_attempt = $4 LIMIT 1`
	var one int
	probeErr := tx.QueryRowContext(ctx, j.bind(existsQ), runID, stepName, seq, attempt).Scan(&one)
	created := false
	if !errors.Is(probeErr, sql.ErrNoRows) && probeErr != nil {
		return false, fmt.Errorf("journal: probe pending exact dead-letter repair: %w", probeErr)
	}
	if errors.Is(probeErr, sql.ErrNoRows) {
		id, err := newID("dlq_")
		if err != nil {
			return false, err
		}
		order, orderErr := j.nextDeadLetterFailureOrder(ctx, tx, runID)
		if orderErr != nil {
			return false, orderErr
		}
		sealed, sealErr := j.prepareDeadLetterPayload(ctx, tx, id, runID, stepName, &seq, &attempt, order, errorText, payload)
		if sealErr != nil {
			return false, sealErr
		}
		if _, err := tx.ExecContext(ctx, j.bind(insertDeadLetterSQL),
			id, runID, stepName, seq, attempt, order, sealed.errorText, sealed.payload,
			sealed.version, sealed.errorBytes, sealed.payloadBytes,
		); err != nil {
			return false, fmt.Errorf("journal: insert pending exact dead-letter repair: %w", err)
		}
		created = true
	}

	const repaired = `UPDATE steps SET status = $1 WHERE run_id = $2 AND step_name = $3
		AND seq = $4 AND attempt = $5 AND status = $6`
	res, err := tx.ExecContext(ctx, j.bind(repaired), StatusFailed, runID, stepName, seq, attempt, StatusDLQPending)
	if err != nil {
		return false, fmt.Errorf("journal: finish exact dead-letter repair: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, fmt.Errorf("journal: pending exact dead-letter repair changed concurrently")
	}
	if err := checkStepMutationDeadline(runID, leaseDeadline); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("journal: commit pending exact dead-letter repair: %w", err)
	}
	return created, nil
}

func lockRunForStepRepair(ctx context.Context, tx *sql.Tx, j *Journal, runID string) error {
	if j.engine == EnginePostgres {
		var lockedID string
		if err := tx.QueryRowContext(ctx, j.bind(`SELECT id FROM runs WHERE id = $1 FOR UPDATE`), runID).Scan(&lockedID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("journal: lock run for exact dead-letter repair: %w", err)
		}
		return nil
	}
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE runs SET id = id WHERE id = $1`), runID)
	if err != nil {
		return fmt.Errorf("journal: lock run for exact dead-letter repair: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
