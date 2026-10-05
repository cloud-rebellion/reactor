package journal

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

// Schedule represents a pending wake-up: workflow subprocess was suspended
// at a Sleep or AwaitSignal boundary, the host kept the run alive, and a
// scheduler tick will re-spawn it at wake_at.
type Schedule struct {
	ID            string
	RunID         string
	StepName      string
	Kind          string // sleep | signal | cron
	WakeAt        time.Time
	SignalName    string
	SignalToken   string
	SignalPayload []byte
	Fired         bool
	CreatedAt     time.Time
	// These presence bits are populated by metadata-only control-plane reads
	// so callers can describe signal state without loading bearer tokens or
	// arbitrary delivered payloads.
	SignalTokenPresent   bool `json:"-"`
	SignalPayloadPresent bool `json:"-"`
}

// Keep execution reads on one shape so the signal envelope is authenticated
// before a token or delivered payload can reach the supervisor. Metadata-only
// MCP reads use a separate projection below.
const scheduleSelectFields = `s.id, s.run_id, s.step_name, s.kind, s.wake_at,
	s.signal_name, s.signal_token, s.signal_payload, s.fired, s.created_at,
	s.signal_crypto_version, s.signal_token_ciphertext, s.signal_token_sha256,
	s.signal_token_plaintext_bytes, s.signal_payload_plaintext_bytes, s.seq, r.tenant_id`

// ListPendingSchedulesForRunTenant returns only unfired wake-ups for a run
// owned by tenantID. Callers that present this to an operator must omit the
// signal token and payload: the token is a bearer capability and the payload
// may contain workflow/customer data.
func (j *Journal) ListPendingSchedulesForRunTenant(ctx context.Context, runID, tenantID string) ([]Schedule, error) {
	q := `SELECT ` + scheduleSelectFields + ` FROM schedules s JOIN runs r ON r.id = s.run_id
		WHERE s.run_id = $1 AND s.fired = $2
			AND ($3 = '' OR r.tenant_id = $3)
		ORDER BY s.wake_at ASC, s.created_at ASC, s.id ASC`
	args := []any{runID, j.boolValue(false), tenantID}
	if j.engine == EngineSQLite {
		// The SQLite placeholder rewriter does not preserve PostgreSQL's
		// repeated $3 reference, so bind the tenant predicate twice.
		args = append(args, tenantID)
	}
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, fmt.Errorf("journal: list pending schedules: %w", err)
	}
	defer rows.Close()
	var out []Schedule
	for rows.Next() {
		s, scanErr := scanScheduleRow(rows.Scan, j)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("journal: list pending schedules rows: %w", err)
	}
	return out, nil
}

// ListPendingSchedulesForRunTenantPage returns one bounded page of unfired
// wake-ups for a tenant-owned run. The MCP read model uses this method so a
// workflow that has accumulated many suspended iterations cannot turn one
// inspection request into an unbounded database read or response.
func (j *Journal) ListPendingSchedulesForRunTenantPage(ctx context.Context, runID, tenantID string, limit, offset int) ([]Schedule, bool, error) {
	if limit <= 0 {
		return nil, false, fmt.Errorf("journal: list pending schedules: page limit must be positive")
	}
	if limit > 500 {
		return nil, false, fmt.Errorf("journal: list pending schedules: page limit exceeds 500")
	}
	if offset < 0 {
		return nil, false, fmt.Errorf("journal: list pending schedules: negative offset")
	}
	q := `SELECT ` + scheduleSelectFields + ` FROM schedules s JOIN runs r ON r.id = s.run_id
		WHERE s.run_id = $1 AND s.fired = $2
			AND ($3 = '' OR r.tenant_id = $3)
		ORDER BY s.wake_at ASC, s.created_at ASC, s.id ASC
		LIMIT $4 OFFSET $5`
	args := []any{runID, j.boolValue(false), tenantID, limit + 1, offset}
	if j.engine == EngineSQLite {
		// SQLite's placeholder rewriter expands the repeated $3 predicate to
		// two positional placeholders, unlike PostgreSQL's numbered binding.
		args = []any{runID, j.boolValue(false), tenantID, tenantID, limit + 1, offset}
	}
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list pending schedule page: %w", err)
	}
	defer rows.Close()
	var out []Schedule
	for rows.Next() {
		s, scanErr := scanScheduleRow(rows.Scan, j)
		if scanErr != nil {
			return nil, false, scanErr
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("journal: list pending schedule page rows: %w", err)
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

// ListPendingSchedulesForRunTenantPageMetadata is the MCP/read-model variant
// of ListPendingSchedulesForRunTenantPage. It projects only schedule metadata
// and two presence bits; signal tokens and delivered payloads never cross the
// SQL boundary into the control plane.
func (j *Journal) ListPendingSchedulesForRunTenantPageMetadata(ctx context.Context, runID, tenantID string, limit, offset int) ([]Schedule, bool, error) {
	if limit <= 0 || limit > 500 || offset < 0 {
		return nil, false, fmt.Errorf("journal: invalid pending schedule metadata page")
	}
	var tokenPresent, payloadPresent string
	if j.engine == EnginePostgres {
		tokenPresent = "CASE WHEN schedules.signal_token IS NOT NULL AND octet_length(schedules.signal_token) > 0 OR schedules.signal_token_ciphertext IS NOT NULL THEN TRUE ELSE FALSE END"
		payloadPresent = "CASE WHEN schedules.signal_payload IS NOT NULL AND octet_length(schedules.signal_payload) > 0 THEN TRUE ELSE FALSE END"
	} else {
		tokenPresent = "CASE WHEN schedules.signal_token IS NOT NULL AND length(CAST(schedules.signal_token AS BLOB)) > 0 OR schedules.signal_token_ciphertext IS NOT NULL THEN 1 ELSE 0 END"
		payloadPresent = "CASE WHEN schedules.signal_payload IS NOT NULL AND length(CAST(schedules.signal_payload AS BLOB)) > 0 THEN 1 ELSE 0 END"
	}
	q := fmt.Sprintf(`SELECT schedules.id, schedules.run_id, schedules.step_name, schedules.kind, schedules.wake_at, schedules.signal_name,
		%s, %s, schedules.fired, schedules.created_at
		FROM schedules JOIN runs ON runs.id = schedules.run_id
		WHERE schedules.run_id = $1 AND schedules.fired = $2`, tokenPresent, payloadPresent)
	args := []any{runID, j.boolValue(false)}
	position := 3
	if tenantID != "" {
		q += fmt.Sprintf(" AND runs.tenant_id = $%d", position)
		args = append(args, tenantID)
		position++
	}
	q += fmt.Sprintf(" ORDER BY schedules.wake_at ASC, schedules.created_at ASC, schedules.id ASC LIMIT $%d OFFSET $%d", position, position+1)
	args = append(args, limit+1, offset)
	rows, err := j.db.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list pending schedule metadata page: %w", err)
	}
	defer rows.Close()
	out := make([]Schedule, 0, limit)
	for rows.Next() {
		item, scanErr := scanScheduleMetadataRow(rows.Scan, j)
		if scanErr != nil {
			return nil, false, scanErr
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("journal: list pending schedule metadata rows: %w", err)
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

// ScheduleKind values.
const (
	KindSleep    = "sleep"
	KindSignal   = "signal"
	KindCron     = "cron"
	KindRecovery = "recovery"
)

// ErrAlreadyFired is returned by FireSignal when the token's schedule row
// has already been delivered. Callers map this to HTTP 410 Gone.
var ErrAlreadyFired = errors.New("journal: schedule already fired")

// ErrSignalExpired is returned when a signal capability is presented after
// its durable wake_at deadline. The scheduler owns timeout resumption; a late
// delivery must never race that path and turn an expired approval into a live
// payload.
var ErrSignalExpired = errors.New("journal: signal schedule expired")

// ScheduleSleep persists a sleep schedule. The supervisor calls this when a
// workflow's Sleep frame's UntilUnix is past the suspend threshold; the
// row's wake_at drives the scheduler tick that re-spawns the workflow.
func (j *Journal) ScheduleSleep(ctx context.Context, runID, stepName string, wakeAt time.Time) (string, error) {
	return j.ScheduleSleepSeq(ctx, runID, stepName, 0, wakeAt)
}

// ScheduleSleepSeq records the sleep against its per-run call ordinal so a Sleep
// inside a loop gets one row per iteration. seq = 0 keeps legacy semantics.
func (j *Journal) ScheduleSleepSeq(ctx context.Context, runID, stepName string, seq int64, wakeAt time.Time) (string, error) {
	id, err := newID("sched_")
	if err != nil {
		return "", err
	}
	const q = `INSERT INTO schedules (id, run_id, step_name, seq, kind, wake_at, fired)
		VALUES ($1, $2, $3, $4, 'sleep', $5, $6)`
	_, err = j.db.ExecContext(ctx, j.bind(q),
		id, runID, stepName, seq, j.formatTime(wakeAt), j.boolValue(false),
	)
	if err != nil {
		return "", fmt.Errorf("journal: schedule sleep: %w", err)
	}
	return id, nil
}

// ScheduleSignal persists a signal-await schedule. token is the public
// identifier the external HTTP caller posts to; expiresAt is the timeout
// after which the scheduler returns Expired=true to the resumed workflow.
// Both are required so the row participates in both delivery and timeout
// sweeps via a single FindDueSchedules path.
func (j *Journal) ScheduleSignal(ctx context.Context, runID, stepName, signalName, token string, expiresAt time.Time) (string, error) {
	return j.ScheduleSignalSeq(ctx, runID, stepName, 0, signalName, token, expiresAt)
}

// ScheduleSignalSeq records the await against its per-run call ordinal so two
// AwaitSignal calls sharing a signal name occupy two rows instead of one. That
// is what stops the second await from being served the first's already-delivered
// payload. seq = 0 keeps legacy semantics.
func (j *Journal) ScheduleSignalSeq(ctx context.Context, runID, stepName string, seq int64, signalName, token string, expiresAt time.Time) (string, error) {
	id, err := newID("sched_")
	if err != nil {
		return "", err
	}
	if err := j.requireSignalPayloadKey(ctx, j.db); err != nil {
		return "", err
	}
	var tenantID string
	if err := j.db.QueryRowContext(ctx, j.bind(`SELECT tenant_id FROM runs WHERE id = $1`), runID).Scan(&tenantID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("journal: resolve signal tenant: %w", err)
	}
	var storedToken any = token
	var cipher, digest, tokenBytes any
	version := 0
	if j.payloadKey != nil {
		sealed, hash, err := j.sealSignalToken(tenantID, runID, id, stepName, signalName, seq, token)
		if err != nil {
			return "", err
		}
		storedToken, cipher, digest, tokenBytes, version = nil, sealed, hash, len(token), 1
	}
	const q = `INSERT INTO schedules (id, run_id, step_name, seq, kind, wake_at, signal_name,
		signal_token, signal_token_ciphertext, signal_token_sha256,
		signal_crypto_version, signal_token_plaintext_bytes, fired)
		VALUES ($1, $2, $3, $4, 'signal', $5, $6, $7, $8, $9, $10, $11, $12)`
	_, err = j.db.ExecContext(ctx, j.bind(q),
		id, runID, stepName, seq, j.formatTime(expiresAt), signalName,
		storedToken, cipher, digest, version, tokenBytes, j.boolValue(false),
	)
	if err != nil {
		return "", fmt.Errorf("journal: schedule signal: %w", err)
	}
	return id, nil
}

// FireSignal records the external delivery for a signal token. The schedule
// stays unfired so the scheduler tick picks it up; the signal_payload
// column is the delivery marker (a NULL payload column means pending,
// a non-NULL payload means delivered awaiting resume). wake_at is bumped
// to now so FindDueSchedules surfaces the row immediately rather than
// waiting for the original timeout. This unscoped form is retained for the
// public /signal/{token} capability endpoint, where the token itself is the
// authorization boundary.
//
// Returns ErrNotFound when the token doesn't match any signal schedule,
// and ErrAlreadyFired when the schedule already has a payload (idempotent
// retry semantics).
func (j *Journal) FireSignal(ctx context.Context, token string, payload []byte) (runID, signalName string, err error) {
	return j.fireSignal(ctx, "", token, payload)
}

// FireSignalForTenant is the MCP/control-plane variant of FireSignal. The
// caller must already possess the bearer signal token, but the matching run
// is additionally required to belong to tenantID. This prevents a tenant-
// scoped MCP client that is handed a token for another tenant from learning
// or waking that run. Signal tokens and payloads are never returned by this
// method.
func (j *Journal) FireSignalForTenant(ctx context.Context, tenantID, token string, payload []byte) (runID, signalName string, err error) {
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	return j.fireSignal(ctx, tenantID, token, payload)
}

func (j *Journal) fireSignal(ctx context.Context, tenantID, token string, payload []byte) (runID, signalName string, err error) {
	if len(payload) == 0 {
		// payload-presence is the delivery marker; an empty body would be
		// indistinguishable from "not yet delivered" once the scanner reads
		// it back as nil/empty. Coerce empty bodies to JSON null so every
		// delivered row carries non-zero bytes.
		payload = []byte("null")
	}
	// Prefer the OLDEST row for this token that is still awaiting delivery.
	// The token is derived from the signal NAME, so two AwaitSignal calls
	// sharing a name legitimately share a token; picking an arbitrary row (a
	// bare LIMIT 1) would keep hitting the already-delivered one and report
	// ErrAlreadyFired forever, stranding the pending await. Ordering pending
	// rows first, oldest first, makes repeated deliveries to one signal name
	// fill successive awaits in program order.
	now := time.Now().UTC()
	wakeAfter := "s.wake_at > $5"
	falseLit := "false"
	if j.engine == EngineSQLite {
		// Imported RFC3339 offsets compare incorrectly as TEXT against our
		// canonical UTC timestamp. The Go expiry check below compares parsed
		// instants; make the SQL candidate priority and CAS agree with it.
		wakeAfter = "julianday(s.wake_at) > julianday($5)"
		falseLit = "0"
	}
	sel := `SELECT s.id, s.run_id, s.step_name, s.signal_name, s.seq, r.tenant_id,
		s.signal_crypto_version, s.signal_payload IS NOT NULL, s.fired, s.wake_at
		FROM schedules s JOIN runs r ON r.id = s.run_id
		JOIN workflows w ON w.id = r.workflow_id
		WHERE ((s.signal_token_sha256 = $1 AND s.signal_crypto_version = 1)
			OR (s.signal_token = $2 AND s.signal_crypto_version = 0))
		AND s.kind = 'signal' AND ($3 = '' OR w.tenant_id = $4)
		ORDER BY CASE WHEN s.signal_payload IS NULL AND s.fired = ` + falseLit + `
			AND s.wake_at IS NOT NULL AND ` + wakeAfter + ` THEN 0 ELSE 1 END,
			CASE WHEN s.signal_payload IS NULL AND s.fired = ` + falseLit + ` THEN 0 ELSE 1 END,
			s.created_at ASC, s.seq ASC, s.id ASC
		LIMIT 1`
	args := []any{signalTokenDigest(token), token, tenantID, tenantID, j.formatTime(now)}
	row := j.db.QueryRowContext(ctx, j.bind(sel), args...)
	var (
		id           string
		runIDOut     string
		stepName     sql.NullString
		nameOut      sql.NullString
		seq          int64
		storedTenant string
		version      int
		existing     any
		fired        any
		wakeAt       sql.NullString
	)
	if err := row.Scan(&id, &runIDOut, &stepName, &nameOut, &seq, &storedTenant, &version, &existing, &fired, &wakeAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", ErrNotFound
		}
		return "", "", fmt.Errorf("journal: lookup signal: %w", err)
	}
	if parseBool(existing) || parseBool(fired) {
		return "", "", ErrAlreadyFired
	}
	if version != 0 && version != 1 {
		return "", "", payloadcrypto.ErrInvalidEnvelope
	}
	if !wakeAt.Valid {
		return "", "", ErrSignalExpired
	}
	expiresAt, parseErr := j.parseTime(wakeAt.String)
	if parseErr != nil {
		return "", "", fmt.Errorf("journal: parse signal expiry: %w", parseErr)
	}
	if !expiresAt.After(now) {
		return "", "", ErrSignalExpired
	}

	var res sql.Result
	if j.payloadKey != nil {
		sealedPayload, sealErr := j.sealSignalDelivery(storedTenant, runIDOut, id, stepName.String, nameOut.String, seq, payload)
		if sealErr != nil {
			return "", "", sealErr
		}
		if version == 0 {
			// Promote the exact pending legacy row in the same CAS as delivery.
			// The token remains available to replay only under the envelope.
			sealedToken, hash, sealErr := j.sealSignalToken(storedTenant, runIDOut, id, stepName.String, nameOut.String, seq, token)
			if sealErr != nil {
				return "", "", sealErr
			}
			upd := `UPDATE schedules SET signal_token = NULL, signal_token_ciphertext = $1,
				signal_token_sha256 = $2, signal_token_plaintext_bytes = $3,
				signal_payload = $4, signal_payload_plaintext_bytes = $5,
				signal_crypto_version = 1, wake_at = $6
				WHERE id = $7 AND signal_crypto_version = 0 AND signal_token = $8
					AND signal_payload IS NULL AND fired = $9 AND wake_at > $10`
			if j.engine == EngineSQLite {
				upd = `UPDATE schedules SET signal_token = NULL, signal_token_ciphertext = $1,
					signal_token_sha256 = $2, signal_token_plaintext_bytes = $3,
					signal_payload = $4, signal_payload_plaintext_bytes = $5,
					signal_crypto_version = 1, wake_at = $6
					WHERE id = $7 AND signal_crypto_version = 0 AND signal_token = $8
						AND signal_payload IS NULL AND fired = $9 AND julianday(wake_at) > julianday($10)`
			}
			res, err = j.db.ExecContext(ctx, j.bind(upd), sealedToken, hash, len(token),
				sealedPayload, len(payload), j.formatTime(now), id, token, j.boolValue(false), j.formatTime(now))
		} else {
			upd := `UPDATE schedules SET signal_payload = $1, signal_payload_plaintext_bytes = $2,
				wake_at = $3 WHERE id = $4 AND signal_crypto_version = 1
				AND signal_token_sha256 = $5 AND signal_payload IS NULL AND fired = $6 AND wake_at > $7`
			if j.engine == EngineSQLite {
				upd = `UPDATE schedules SET signal_payload = $1, signal_payload_plaintext_bytes = $2,
					wake_at = $3 WHERE id = $4 AND signal_crypto_version = 1
					AND signal_token_sha256 = $5 AND signal_payload IS NULL AND fired = $6
					AND julianday(wake_at) > julianday($7)`
			}
			res, err = j.db.ExecContext(ctx, j.bind(upd), sealedPayload, len(payload),
				j.formatTime(now), id, signalTokenDigest(token), j.boolValue(false), j.formatTime(now))
		}
	} else {
		if version == 1 {
			return "", "", payloadcrypto.ErrKeyRequired
		}
		if keyErr := j.requireSignalPayloadKey(ctx, j.db); keyErr != nil {
			return "", "", keyErr
		}
		upd := `UPDATE schedules SET signal_payload = $1, wake_at = $2
			WHERE id = $3 AND signal_crypto_version = 0 AND signal_payload IS NULL
				AND fired = $4 AND wake_at > $5`
		if j.engine == EngineSQLite {
			upd = `UPDATE schedules SET signal_payload = $1, wake_at = $2
				WHERE id = $3 AND signal_crypto_version = 0 AND signal_payload IS NULL
					AND fired = $4 AND julianday(wake_at) > julianday($5)`
		}
		res, err = j.db.ExecContext(ctx, j.bind(upd), payload, j.formatTime(now), id, j.boolValue(false), j.formatTime(now))
	}
	if err != nil {
		return "", "", fmt.Errorf("journal: fire signal: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Lost the race to another delivery between SELECT and UPDATE.
		return "", "", ErrAlreadyFired
	}
	return runIDOut, nullableString(nameOut), nil
}

// FindDueSchedules returns up to limit unfired schedules whose wake time has
// already elapsed. The scheduler loop walks these and re-spawns each run.
// Implementation note: this is a polling read rather than LISTEN/NOTIFY so
// SQLite + Postgres share one code path; Postgres-only deployments can
// later add a NOTIFY-based fast-path without breaking the contract.
//
// Signal rows are returned alongside sleep rows. A signal row appears here
// either when its timeout has elapsed (signal_payload is NULL, expired
// resume) or because the delivery handler set wake_at = now and left fired
// = false specifically so the next tick processes it.
func (j *Journal) FindDueSchedules(ctx context.Context, now time.Time, limit int) ([]Schedule, error) {
	rows, err := j.db.QueryContext(ctx, j.bind(j.fairDueScheduleQuery()), j.boolValue(false), j.formatTime(now), limit)
	if err != nil {
		return nil, fmt.Errorf("journal: find due: %w", err)
	}
	defer rows.Close()

	var out []Schedule
	for rows.Next() {
		s, err := scanScheduleRow(rows.Scan, j)
		if err != nil {
			if errors.Is(err, payloadcrypto.ErrInvalidEnvelope) || errors.Is(err, payloadcrypto.ErrKeyRequired) {
				// An authenticated delivery failure must stop dispatch, not
				// masquerade as a malformed imported wake timestamp.
				return nil, err
			}
			// Skip the row instead of failing the whole batch. A single
			// unparseable wake_at (an out-of-range timestamp sorts FIRST as
			// TEXT and always matches "wake_at <= now") would otherwise abort
			// every scheduler tick, so no suspended run in any tenant would
			// ever resume. The supervisor clamps new rows to
			// maxScheduleHorizon; this keeps an already-poisoned table from
			// wedging the daemon.
			j.log.Error("journal: skipping unparseable due schedule row", "err", err)
			continue
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// FireSchedule marks the schedule fired so the scheduler doesn't re-dispatch
// it during the next tick. Called by the supervisor right before re-spawn.
func (j *Journal) FireSchedule(ctx context.Context, id string) error {
	const q = `UPDATE schedules SET fired = $1 WHERE id = $2`
	res, err := j.db.ExecContext(ctx, j.bind(q), j.boolValue(true), id)
	if err != nil {
		return fmt.Errorf("journal: fire schedule: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("journal: schedule %s not found", id)
	}
	return nil
}

// ClaimSchedule atomically marks an unfired schedule fired and reports
// whether THIS caller won the claim. It is the compare-and-set the
// scheduler uses before re-spawning a suspended run: the UPDATE only
// touches a row that is still fired=false, so two daemons (or a tick
// racing a DLQ retry) can't both resume the same RunID and duplicate its
// side effects. claimed=false means someone else already took it; the
// caller skips silently. A missing row also returns claimed=false.
func (j *Journal) ClaimSchedule(ctx context.Context, id string) (bool, error) {
	const q = `UPDATE schedules SET fired = $1 WHERE id = $2 AND fired = $3`
	res, err := j.db.ExecContext(ctx, j.bind(q), j.boolValue(true), id, j.boolValue(false))
	if err != nil {
		return false, fmt.Errorf("journal: claim schedule: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ClaimScheduleResume atomically claims an unfired schedule and moves its run
// from suspended to the execution state required by the scheduler mode:
// running for local execution, queued for distributed workers. A DB error or
// context cancellation rolls both mutations back, so a run can never be left
// suspended behind a fired schedule. If the run is no longer suspended (for
// example cancellation won first), a terminal state's obsolete schedule is
// retired but claimed=false and the terminal state is never overwritten. A
// running/queued run is different: it can be in the crash window after the
// schedule INSERT committed but before the supervisor persisted suspended.
// That exact checkpoint must remain unfired so recovery can reuse it.
func (j *Journal) ClaimScheduleResume(ctx context.Context, id string, enqueue bool) (bool, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("journal: begin schedule resume claim: %w", err)
	}
	defer tx.Rollback()

	// Lock the schedule, its run, and workflow before deciding eligibility.
	// Besides making competing scheduler claims single-flight, the workflow
	// lock closes the disable-between-query-and-claim race: SetWorkflowEnabled
	// cannot commit false immediately after FindDueSchedules and still allow
	// this suspended run to execute.
	if j.engine == EngineSQLite {
		res, err := tx.ExecContext(ctx, j.bind(`UPDATE schedules SET id = id WHERE id = $1`), id)
		if err != nil {
			return false, fmt.Errorf("journal: lock schedule for resume: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return false, tx.Commit()
		}
	}
	lockQ := `SELECT r.id, r.status, r.cancel_requested, w.enabled, w.tenant_id, s.fired
		FROM schedules s
		JOIN runs r ON r.id = s.run_id
		JOIN workflows w ON w.id = r.workflow_id
		WHERE s.id = $1`
	if j.engine == EnginePostgres {
		lockQ += ` FOR UPDATE OF s, r, w`
	}
	var (
		runID           string
		runStatus       string
		cancelRequested any
		enabled         any
		tenantID        string
		fired           any
	)
	if err := tx.QueryRowContext(ctx, j.bind(lockQ), id).Scan(&runID, &runStatus, &cancelRequested, &enabled, &tenantID, &fired); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, tx.Commit()
		}
		return false, fmt.Errorf("journal: read locked schedule resume state: %w", err)
	}
	if parseBool(fired) {
		return false, tx.Commit()
	}
	// A cancellation request may race the supervisor's suspended transition:
	// RequestRunCancel flags a running row first, while the supervisor can
	// commit the schedule + suspended state before the cancel watcher reaches
	// the process. Never consume the wake-up while that flag is set. Retire the
	// continuation and finalize cancellation in this same locked transaction so
	// a scheduler tick cannot resurrect a run that the operator already stopped.
	if parseBool(cancelRequested) && runStatus == "suspended" {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE runs SET status = 'cancelled', finished_at = $1
			WHERE id = (SELECT run_id FROM schedules WHERE id = $2) AND status = 'suspended' AND cancel_requested = $3`),
			j.now(), id, j.boolValue(true)); err != nil {
			return false, fmt.Errorf("journal: finalize cancelled scheduled run: %w", err)
		}
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE schedules SET fired = $1 WHERE run_id = (SELECT run_id FROM schedules WHERE id = $2) AND fired = $3`),
			j.boolValue(true), id, j.boolValue(false)); err != nil {
			return false, fmt.Errorf("journal: retire cancelled schedules: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("journal: commit cancelled schedule resume: %w", err)
		}
		// This terminalization happens at the scheduler admission boundary,
		// outside the supervisor's normal finish path. Keep usage metering
		// complete when a cancellation wins the suspend/resume race.
		j.recordUsageBestEffort(ctx, runID, "cancelled")
		return false, nil
	}
	if runStatus != "suspended" {
		if runStatus == "running" || runStatus == "queued" {
			// Schedule INSERT precedes the supervisor's suspended transition. Do
			// not destroy the only continuation if a scheduler observes that small
			// window (a delivered signal makes it due immediately). The next normal
			// status write or orphan/lease recovery moves the run to suspended/queued
			// and a later scheduler/worker safely consumes this exact row.
			return false, tx.Commit()
		}
		// Cancellation/finalization wins and permanently retires obsolete work.
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE schedules SET fired = $1 WHERE id = $2 AND fired = $3`),
			j.boolValue(true), id, j.boolValue(false)); err != nil {
			return false, fmt.Errorf("journal: retire obsolete schedule: %w", err)
		}
		return false, tx.Commit()
	}
	if !parseBool(enabled) {
		// A disabled workflow is paused, not discarded. Keep the due schedule
		// pending so a later re-enable can resume the same suspended run.
		return false, tx.Commit()
	}
	// FindDueSchedules applies tenant policy while selecting a batch, but that
	// read can become stale before this claim transaction starts (an operator
	// may disable a tenant or another run may fill its concurrency cap). Recheck
	// the policy under the same transaction that flips the schedule and run so a
	// selected wake-up cannot bypass the tenant kill switch or cap.
	allowed, err := j.tenantResumeAdmissionTx(ctx, tx, tenantID)
	if err != nil {
		return false, err
	}
	if !allowed {
		return false, tx.Commit()
	}

	target := "running"
	if enqueue {
		target = "queued"
	}
	const claim = `UPDATE schedules SET fired = $1 WHERE id = $2 AND fired = $3`
	res, err := tx.ExecContext(ctx, j.bind(claim), j.boolValue(true), id, j.boolValue(false))
	if err != nil {
		return false, fmt.Errorf("journal: claim schedule for resume: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, fmt.Errorf("journal: locked schedule changed before resume: %s", id)
	}
	const resume = `UPDATE runs SET status = $1
		WHERE id = (SELECT run_id FROM schedules WHERE id = $2) AND status = 'suspended'`
	res, err = tx.ExecContext(ctx, j.bind(resume), target, id)
	if err != nil {
		return false, fmt.Errorf("journal: transition scheduled run to %s: %w", target, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, fmt.Errorf("journal: locked scheduled run changed before resume: %s", id)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("journal: commit schedule resume claim: %w", err)
	}
	return true, nil
}

// tenantResumeAdmissionTx rechecks tenant-level execution policy for one
// suspended wake-up. The scheduler's due-row query is intentionally a fast
// fair read; this transactional check is the authoritative last gate before a
// schedule is consumed. A tenant row is optional for backwards-compatible
// single-tenant installs, where its absence means unlimited + enabled.
//
// PostgreSQL locks the tenant row so two scheduler claims for the same tenant
// cannot both observe the same max_concurrent_runs budget. SQLite already
// holds its single-writer transaction lock from ClaimScheduleResume.
func (j *Journal) tenantResumeAdmissionTx(ctx context.Context, tx *sql.Tx, tenantID string) (bool, error) {
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	q := `SELECT disabled, max_concurrent_runs FROM tenants WHERE tenant_id = $1`
	if j.engine == EnginePostgres {
		q += ` FOR UPDATE`
	}
	var (
		disabled any
		maxRuns  sql.NullInt64
	)
	err := tx.QueryRowContext(ctx, j.bind(q), tenantID).Scan(&disabled, &maxRuns)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("journal: read tenant resume admission: %w", err)
	}
	if parseBool(disabled) {
		return false, nil
	}
	if !maxRuns.Valid || maxRuns.Int64 <= 0 {
		return true, nil
	}
	var running int64
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM runs WHERE tenant_id = $1 AND status = 'running'`), tenantID).Scan(&running); err != nil {
		return false, fmt.Errorf("journal: count tenant running resumes: %w", err)
	}
	return running < maxRuns.Int64, nil
}

// FindLatestSleepSchedule returns the most recent sleep schedule for a
// (run_id, step_name) pair regardless of fired state. Used by the supervisor
// on re-spawn to decide whether the workflow's repeated Sleep frame is
// already past wake_at (immediate ack) or still pending (re-suspend).
func (j *Journal) FindLatestSleepSchedule(ctx context.Context, runID, stepName string) (Schedule, error) {
	return j.findLatestByKind(ctx, runID, stepName, KindSleep)
}

// FindLatestSignalSchedule returns the most recent signal schedule for a
// (run_id, step_name) pair. The supervisor reads this on resume to decide
// whether to reply SignalDeliver{Payload, Expired:false} (delivered) or
// SignalDeliver{Expired:true} (timeout) without re-suspending.
func (j *Journal) FindLatestSignalSchedule(ctx context.Context, runID, stepName string) (Schedule, error) {
	return j.findLatestByKind(ctx, runID, stepName, KindSignal)
}

// FindScheduleBySeq resolves a schedule by its per-run call ordinal instead of
// by step name, so a Sleep or AwaitSignal repeated in a loop resolves to ITS
// iteration's row. Returns ErrNotFound for seq <= 0 (pre-ordinal binaries use
// the name-keyed lookups) and when the ordinal has not been reached yet.
func (j *Journal) FindScheduleBySeq(ctx context.Context, runID string, seq int64, kind string) (Schedule, error) {
	if seq <= 0 {
		return Schedule{}, ErrNotFound
	}
	q := `SELECT ` + scheduleSelectFields + ` FROM schedules s JOIN runs r ON r.id = s.run_id
		WHERE s.run_id = $1 AND s.seq = $2 AND s.kind = $3
		ORDER BY s.created_at DESC LIMIT 1`
	row := j.db.QueryRowContext(ctx, j.bind(q), runID, seq, kind)
	s, err := scanScheduleRow(row.Scan, j)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Schedule{}, ErrNotFound
		}
		return Schedule{}, err
	}
	return s, nil
}

func (j *Journal) findLatestByKind(ctx context.Context, runID, stepName, kind string) (Schedule, error) {
	q := `SELECT ` + scheduleSelectFields + ` FROM schedules s JOIN runs r ON r.id = s.run_id
		WHERE s.run_id = $1 AND s.step_name = $2 AND s.kind = $3
		ORDER BY s.created_at DESC LIMIT 1`
	row := j.db.QueryRowContext(ctx, j.bind(q), runID, stepName, kind)
	s, err := scanScheduleRow(row.Scan, j)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Schedule{}, ErrNotFound
		}
		return Schedule{}, err
	}
	return s, nil
}

// scanScheduleRow is the shared scanner for the SELECT shape used by both
// FindDueSchedules (rows) and findLatestByKind (row).
func scanScheduleRow(scan func(...any) error, j *Journal) (Schedule, error) {
	var (
		s            Schedule
		wakeAt       sql.NullString
		signalName   sql.NullString
		signalTok    sql.NullString
		payload      []byte
		fired        any
		createdAt    sql.NullString
		version      int
		tokenCipher  sql.NullString
		tokenHash    sql.NullString
		tokenBytes   sql.NullInt64
		payloadBytes sql.NullInt64
		seq          int64
		tenantID     string
	)
	if err := scan(&s.ID, &s.RunID, &s.StepName, &s.Kind, &wakeAt, &signalName, &signalTok, &payload, &fired, &createdAt,
		&version, &tokenCipher, &tokenHash, &tokenBytes, &payloadBytes, &seq, &tenantID); err != nil {
		return Schedule{}, err
	}
	if wakeAt.Valid {
		t, perr := j.parseTime(wakeAt.String)
		if perr != nil {
			return Schedule{}, fmt.Errorf("journal: parse wake_at: %w", perr)
		}
		s.WakeAt = t
	}
	if signalName.Valid {
		s.SignalName = signalName.String
	}
	if err := j.openScheduleSignal(&s, tenantID, seq, version, signalTok, tokenCipher, tokenHash, tokenBytes, payload, payloadBytes); err != nil {
		return Schedule{}, fmt.Errorf("journal: open schedule signal: %w", err)
	}
	s.Fired = parseBool(fired)
	if createdAt.Valid {
		t, perr := j.parseTime(createdAt.String)
		if perr == nil {
			s.CreatedAt = t
		}
	}
	return s, nil
}

func scanScheduleMetadataRow(scan func(...any) error, j *Journal) (Schedule, error) {
	var (
		s          Schedule
		wakeAt     sql.NullString
		signalName sql.NullString
		token      any
		payload    any
		fired      any
		createdAt  sql.NullString
	)
	if err := scan(&s.ID, &s.RunID, &s.StepName, &s.Kind, &wakeAt, &signalName, &token, &payload, &fired, &createdAt); err != nil {
		return Schedule{}, err
	}
	if wakeAt.Valid {
		t, err := j.parseTime(wakeAt.String)
		if err != nil {
			return Schedule{}, fmt.Errorf("journal: parse wake_at: %w", err)
		}
		s.WakeAt = t
	}
	if signalName.Valid {
		s.SignalName = signalName.String
	}
	s.SignalTokenPresent = parseBool(token)
	s.SignalPayloadPresent = parseBool(payload)
	s.Fired = parseBool(fired)
	if createdAt.Valid {
		if t, err := j.parseTime(createdAt.String); err == nil {
			s.CreatedAt = t
		}
	}
	return s, nil
}

// SetRunStatus updates runs.status. Used by the supervisor to mark a run
// suspended (sleeping) or restored (running again).
func (j *Journal) SetRunStatus(ctx context.Context, runID, status string) error {
	const q = `UPDATE runs SET status = $1 WHERE id = $2`
	res, err := j.db.ExecContext(ctx, j.bind(q), status, runID)
	if err != nil {
		return fmt.Errorf("journal: set run status: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("journal: run %s not found", runID)
	}
	return nil
}

// ResumeSuspendedRun flips a run from 'suspended' back to 'running' as a
// guarded compare-and-set. It returns false (no error) when no row moved: the
// run is no longer suspended because it was cancelled or finalized while it
// slept. The scheduler MUST NOT respawn the workflow in that case - an
// unguarded UPDATE here would overwrite a concurrent cancel and resurrect the
// cancelled run, re-running its side effects.
func (j *Journal) ResumeSuspendedRun(ctx context.Context, runID string) (bool, error) {
	const q = `UPDATE runs SET status = 'running' WHERE id = $1 AND status = 'suspended'`
	res, err := j.db.ExecContext(ctx, j.bind(q), runID)
	if err != nil {
		return false, fmt.Errorf("journal: resume suspended run: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// formatTime renders a time for the engine: ISO-8601 string for SQLite,
// time.Time for Postgres (pgx handles TIMESTAMPTZ natively).
func (j *Journal) formatTime(t time.Time) any {
	if j.engine == EngineSQLite {
		return t.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return t.UTC()
}

// parseTime parses what we wrote.
func (j *Journal) parseTime(s string) (time.Time, error) {
	for _, layout := range []string{
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("journal: unparseable time %q", s)
}

// boolValue picks the right bool representation per engine. SQLite stores
// 0/1 INTEGER; Postgres has native bool.
func (j *Journal) boolValue(b bool) any {
	if j.engine == EngineSQLite {
		if b {
			return 1
		}
		return 0
	}
	return b
}

// parseBool reads either an int (SQLite) or a bool (Postgres).
func parseBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int64:
		return x != 0
	case int:
		return x != 0
	case []byte:
		return len(x) == 1 && x[0] == 't'
	case string:
		return x == "t" || x == "true" || x == "1"
	}
	return false
}

// newID generates an opaque ID with the given prefix.
func newID(prefix string) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("journal: id: %w", err)
	}
	return prefix + hex.EncodeToString(b), nil
}

// NewSignalToken generates a 32-byte URL-safe random token. The webhook
// signal endpoint dispatches POST /signal/{token} so the token is the
// per-request capability; brute force is bounded by the 256-bit space.
func NewSignalToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("journal: signal token: %w", err)
	}
	return "sig_" + hex.EncodeToString(b), nil
}

// fairDueScheduleQuery interleaves due schedules ACROSS tenants instead of
// draining them in global wake_at order.
//
// The old query was `WHERE fired = false AND wake_at <= now ORDER BY wake_at ASC
// LIMIT n` with no tenant dimension, so one tenant holding a backlog of due
// sleeps older than everyone else's filled the entire batch every tick and no
// other tenant's suspended run resumed until that backlog drained. That is worse
// than queue starvation: these runs are already mid-execution, so from the other
// tenant's side the workflow has simply hung with no error anywhere.
//
// This mirrors fairCandidateQuery in queue.go, which already solved the same
// problem for run admission, and adds the admission gates that resumption was
// bypassing entirely because it never went through CheckWorkflowEnqueueAllowed:
//
//   - disabled workflows are skipped. Disabling a workflow is a kill switch for
//     both fresh dispatch and suspended continuations; its schedule remains pending
//     and becomes due again if the workflow is re-enabled.
//   - disabled tenants are skipped. Disabling a tenant stopped new runs while its
//     suspended ones kept waking up and executing.
//   - max_concurrent_runs is honoured, so a tenant cannot exceed its cap simply by
//     having workflows sleep. The column defaults to 0 (meaning unlimited), so an
//     install that has not deliberately set a cap sees no change; a capped tenant's
//     wake-up is DELAYED rather than dropped, and the ROW_NUMBER interleave keeps
//     that delay from being starvation.
//
// The cap matters in a different way per scheduler mode, which is worth knowing
// before touching this. In DISTRIBUTED mode (Enqueue) the scheduler only flips the
// run to 'queued' and a worker admits it through queue.go's fairCandidateQuery,
// which already applies both gates, so here they merely apply EARLIER and avoid
// claiming a schedule whose run would then sit un-admittable in 'queued'. In
// IN-PROCESS mode the scheduler resumes the run directly and never touches the
// queue, so this is the ONLY place either gate can be applied at all.
//
// The `running` CTE counts status='running' only. A run parked on a sleep is
// 'suspended' (supervisor.go sets that when it suspends), so a sleeping run does
// NOT consume its own tenant's concurrency slot. If it did, a tenant at its cap
// could never wake anything and the cap would be a permanent deadlock rather than
// backpressure.
//
// schedules has no tenant_id of its own; the tenant comes from the run. The join
// is inner on purpose: a schedule whose run row is gone can never dispatch
// successfully, and previously it was returned every tick to fail in the
// scheduler loop. Only suspended runs enter the due set. A sleep/signal INSERT
// commits before the supervisor's suspended status write, so a due row observed
// while its run is still running/queued is a continuation checkpoint in a small
// crash window, not permission for the scheduler to consume it. Once the status
// commits (or local orphan recovery restores it), the same unfired row becomes
// eligible normally.
func (j *Journal) fairDueScheduleQuery() string {
	falseLit := "false"
	trueLit := "true"
	validWake := ""
	wakeOrder := "s.wake_at"
	wakeDue := "s.wake_at <= $2"
	if j.engine == EngineSQLite {
		falseLit = "0"
		trueLit = "1"
		// SQLite stores wake_at as text. An imported/legacy malformed value
		// can sort before every real timestamp, then occupy both a tenant's
		// first rank and the batch LIMIT forever. Require the RFC3339 shape
		// accepted by parseTime and an in-range date before ranking. SQLite's
		// julianday alone accepts date-only strings that parseTime rejects.
		// PostgreSQL uses TIMESTAMPTZ and cannot store malformed values.
		validWake = ` AND substr(s.wake_at, 11, 1) = 'T'
			AND (substr(s.wake_at, -1, 1) = 'Z' OR substr(s.wake_at, -6, 1) IN ('+', '-'))
			AND julianday(s.wake_at) IS NOT NULL`
		// The accepted RFC3339 offset form is a real instant, but TEXT
		// comparison sorts by its displayed wall clock. Normalize both due
		// admission and tenant-fair order to instants; otherwise a future
		// -01:00 wake runs early while an already-due +02:00 wake is delayed.
		wakeOrder = "julianday(s.wake_at)"
		wakeDue = "julianday(s.wake_at) <= julianday($2)"
	}
	return `WITH running AS (
		SELECT tenant_id, COUNT(*) AS n FROM runs WHERE status = 'running' GROUP BY tenant_id
	),
	ranked AS (
		SELECT s.id, s.run_id, s.step_name, s.kind, s.wake_at, s.signal_name,
			s.signal_token, s.signal_payload, s.fired, s.created_at,
			s.signal_crypto_version, s.signal_token_ciphertext, s.signal_token_sha256,
			s.signal_token_plaintext_bytes, s.signal_payload_plaintext_bytes, s.seq,
			r.tenant_id,
			` + wakeOrder + ` AS wake_order,
			ROW_NUMBER() OVER (PARTITION BY r.tenant_id ORDER BY ` + wakeOrder + `, s.id) AS rn
		FROM schedules s
		JOIN runs r ON r.id = s.run_id
		JOIN workflows w ON w.id = r.workflow_id
		WHERE s.fired = $1 AND s.wake_at IS NOT NULL AND ` + wakeDue + validWake + `
			AND r.status = 'suspended'
			AND w.enabled = ` + trueLit + `
	)
	SELECT k.id, k.run_id, k.step_name, k.kind, k.wake_at, k.signal_name,
		k.signal_token, k.signal_payload, k.fired, k.created_at,
		k.signal_crypto_version, k.signal_token_ciphertext, k.signal_token_sha256,
		k.signal_token_plaintext_bytes, k.signal_payload_plaintext_bytes, k.seq,
		k.tenant_id
	FROM ranked k
	LEFT JOIN tenants t ON t.tenant_id = k.tenant_id
	LEFT JOIN running ru ON ru.tenant_id = k.tenant_id
	WHERE (t.disabled IS NULL OR t.disabled = ` + falseLit + `)
		AND (t.max_concurrent_runs IS NULL OR t.max_concurrent_runs <= 0
			OR k.rn <= t.max_concurrent_runs - COALESCE(ru.n, 0))
	ORDER BY k.rn, k.wake_order, k.id
	LIMIT $3`
}

// ErrDeadLetterNotCurrent is returned when an operator selects an older DLQ
// item after the run has produced a newer failure. Authorizing the older item
// could open a retry window for the wrong step.
var ErrDeadLetterNotCurrent = errors.New("journal: dead-letter item is not the current run failure")

// ErrLegacyDeadLetterIdentity is returned when a pre-0032 nullable DLQ row
// cannot be bound to exactly one failed durable attempt. Guessing would grant a
// fresh execution window to an unknown closure, so authorization fails closed.
var ErrLegacyDeadLetterIdentity = errors.New("journal: legacy dead-letter identity is not unambiguous")

// StartDeadLetterRetry claims the run's current dead-letter item. Retained for
// internal callers/tests that only hold a run id; interactive paths should use
// StartDeadLetterRetryItem so authorization is bound to the selected item.
func (j *Journal) StartDeadLetterRetry(ctx context.Context, runID string) (bool, error) {
	item, err := j.FindDeadLetterByRun(ctx, runID)
	if err != nil {
		return false, err
	}
	return j.StartDeadLetterRetryItem(ctx, runID, item.ID)
}

// StartDeadLetterRetryItem claims a run for a dead-letter retry, moving it to
// "running" only when it is not already executing and was not cancelled.
// The selected DLQ id must still be the run's latest item. Reports whether the
// claim was won.
//
// The retry path used the unguarded SetRunStatus, so two operators clicking
// "Retry from DLQ" on the same row (or one double-click) both flipped the run
// to running and both spawned a supervisor against the SAME run id, duplicating
// every side effect the failed step had not yet completed. The compare-and-set
// makes the retry single-flight, and excluding "cancelled" keeps the
// resurrect-a-cancelled-run guard that MarkRunFinished and ResumeSuspendedRun
// already enforce on their own paths.
func (j *Journal) StartDeadLetterRetryItem(ctx context.Context, runID, dlqID string) (bool, error) {
	return j.startDeadLetterRetryItem(ctx, runID, dlqID, false)
}

// StartDeadLetterRetryQueuedItem is the distributed-mode form: authorization
// is identical, but the run becomes queued so only a leased worker executes it.
func (j *Journal) StartDeadLetterRetryQueuedItem(ctx context.Context, runID, dlqID string) (bool, error) {
	return j.startDeadLetterRetryItem(ctx, runID, dlqID, true)
}

func (j *Journal) startDeadLetterRetryItem(ctx context.Context, runID, dlqID string, enqueue bool) (bool, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("journal: begin dead-letter retry: %w", err)
	}
	defer tx.Rollback()

	// Serialize authorization on the parent run before resolving a nullable
	// legacy item. ClaimStepAttemptSeq uses the same lock, so the identity we
	// promote cannot change between proof and the run-state CAS. The run lock
	// deliberately comes first: the PostgreSQL queue claimant locks runs then
	// their joined workflows, and retaining that order avoids a retry/claim
	// deadlock while the workflow enabled check is added below.
	var (
		workflowID string
		runStatus  string
	)
	if j.engine == EnginePostgres {
		if err := tx.QueryRowContext(ctx, j.bind(`SELECT workflow_id, status FROM runs WHERE id = $1 FOR UPDATE`), runID).Scan(&workflowID, &runStatus); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false, ErrNotFound
			}
			return false, fmt.Errorf("journal: lock dead-letter retry run: %w", err)
		}
	} else {
		res, err := tx.ExecContext(ctx, j.bind(`UPDATE runs SET id = id WHERE id = $1`), runID)
		if err != nil {
			return false, fmt.Errorf("journal: lock dead-letter retry run: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return false, ErrNotFound
		}
		if err := tx.QueryRowContext(ctx, j.bind(`SELECT workflow_id, status FROM runs WHERE id = $1`), runID).Scan(&workflowID, &runStatus); err != nil {
			return false, fmt.Errorf("journal: read dead-letter retry run: %w", err)
		}
	}
	if runStatus != "failed_dlq" {
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("journal: commit rejected dead-letter retry: %w", err)
		}
		return false, nil
	}
	if err := j.lockWorkflowTx(ctx, tx, workflowID); err != nil {
		return false, fmt.Errorf("journal: lock dead-letter retry workflow: %w", err)
	}
	if err := j.requireEnabledWorkflowTx(ctx, tx, workflowID); err != nil {
		return false, err
	}

	var (
		currentDLQID   string
		stepName       string
		stepSeq        sql.NullInt64
		stepAttempt    sql.NullInt64
		payloadVersion int
	)
	currentDLQ := `SELECT id, step_name, step_seq, step_attempt, payload_crypto_version FROM dead_letter
		WHERE run_id = $1
		ORDER BY CASE WHEN failure_order IS NULL THEN 1 ELSE 0 END, failure_order DESC, moved_at DESC, id DESC LIMIT 1`
	if j.engine == EnginePostgres {
		currentDLQ += ` FOR UPDATE`
	}
	if err := tx.QueryRowContext(ctx, j.bind(currentDLQ), runID).Scan(&currentDLQID, &stepName, &stepSeq, &stepAttempt, &payloadVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, fmt.Errorf("journal: find current dead-letter retry item: %w", err)
	}
	if currentDLQID != dlqID {
		return false, ErrDeadLetterNotCurrent
	}
	if payloadVersion != 0 && payloadVersion != 1 {
		return false, payloadcrypto.ErrInvalidEnvelope
	}
	var authenticated DeadLetterItem
	if payloadVersion == 1 {
		// Redrive is an execution-authority boundary. A metadata-only MCP
		// inventory intentionally omits these fields; authenticate them here
		// before accepting the selected item or promoting a nullable identity.
		q := j.deadLetterSelect(-1, -1) + ` FROM dead_letter d JOIN runs r ON r.id = d.run_id
			WHERE d.id = $1 AND d.run_id = $2`
		authenticated, err = scanDeadLetter(tx.QueryRowContext(ctx, j.bind(q), dlqID, runID).Scan, j)
		if err != nil {
			return false, fmt.Errorf("journal: authenticate dead-letter redrive: %w", err)
		}
	}

	// A manual redrive owns a fresh bounded retry window, but it keeps the same
	// run and all prior step rows for cache replay/audit. Mark the exact latest
	// failed attempt behind the selected/current DLQ item as the generation baseline
	// in the SAME transaction as the single-flight run claim. A normal crash
	// after terminal step_end cannot create this marker, so restart recovery
	// cannot be confused with explicit operator authorization.
	if !stepSeq.Valid || !stepAttempt.Valid {
		// Nullable migrated items contain no execution authority. Promote only
		// when exactly one matching failed attempt exists; zero or repeated-name
		// matches are ambiguous and leave both the item and run untouched.
		const legacyMatches = `SELECT seq, attempt FROM steps
			WHERE run_id = $1 AND step_name = $2 AND status = $3
			ORDER BY seq, attempt LIMIT 2`
		rows, err := tx.QueryContext(ctx, j.bind(legacyMatches), runID, stepName, StatusFailed)
		if err != nil {
			return false, fmt.Errorf("journal: resolve legacy dead-letter identity: %w", err)
		}
		var matches [][2]int64
		for rows.Next() {
			var seq, attempt int64
			if err := rows.Scan(&seq, &attempt); err != nil {
				rows.Close()
				return false, fmt.Errorf("journal: scan legacy dead-letter identity: %w", err)
			}
			matches = append(matches, [2]int64{seq, attempt})
		}
		if err := rows.Close(); err != nil {
			return false, fmt.Errorf("journal: close legacy dead-letter identity: %w", err)
		}
		if err := rows.Err(); err != nil {
			return false, fmt.Errorf("journal: iterate legacy dead-letter identity: %w", err)
		}
		if len(matches) != 1 {
			return false, fmt.Errorf("%w: run=%s step=%s matches=%d", ErrLegacyDeadLetterIdentity, runID, stepName, len(matches))
		}
		stepSeq = sql.NullInt64{Int64: matches[0][0], Valid: true}
		stepAttempt = sql.NullInt64{Int64: matches[0][1], Valid: true}
		var res sql.Result
		if payloadVersion == 1 {
			// A keyed legacy row authenticates its original nullable attempt.
			// Promotion changes that identity, so re-seal under the proven exact
			// attempt in the same transaction as the redrive authorization.
			seq, attempt := stepSeq.Int64, int(stepAttempt.Int64)
			sealed, sealErr := j.prepareDeadLetterPayload(ctx, tx, dlqID, runID, stepName,
				&seq, &attempt, authenticated.FailureOrder, authenticated.ErrorText, authenticated.Payload)
			if sealErr != nil {
				return false, fmt.Errorf("journal: seal promoted dead-letter identity: %w", sealErr)
			}
			const promote = `UPDATE dead_letter SET step_seq = $1, step_attempt = $2,
				error_text = $3, payload = $4, payload_crypto_version = $5,
				error_plaintext_bytes = $6, payload_plaintext_bytes = $7
				WHERE id = $8 AND run_id = $9 AND (step_seq IS NULL OR step_attempt IS NULL)`
			res, err = tx.ExecContext(ctx, j.bind(promote), seq, attempt, sealed.errorText,
				sealed.payload, sealed.version, sealed.errorBytes, sealed.payloadBytes, dlqID, runID)
		} else {
			const promote = `UPDATE dead_letter SET step_seq = $1, step_attempt = $2
				WHERE id = $3 AND run_id = $4 AND (step_seq IS NULL OR step_attempt IS NULL)`
			res, err = tx.ExecContext(ctx, j.bind(promote), stepSeq.Int64, stepAttempt.Int64, dlqID, runID)
		}
		if err != nil {
			return false, fmt.Errorf("journal: promote legacy dead-letter identity: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return false, fmt.Errorf("journal: legacy dead-letter identity changed concurrently")
		}
	}

	const authorizeExact = `UPDATE steps SET status = $1
		WHERE run_id = $2 AND step_name = $3 AND seq = $4 AND attempt = $5 AND status = $6`
	res, err := tx.ExecContext(ctx, j.bind(authorizeExact),
		StatusRedrive, runID, stepName, stepSeq.Int64, stepAttempt.Int64, StatusFailed,
	)
	if err != nil {
		return false, fmt.Errorf("journal: authorize exact dead-letter retry window: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, fmt.Errorf("journal: selected dead-letter attempt is no longer terminal")
	}

	// Keep started_at as the beginning of the original run lifecycle, but clear
	// finished_at atomically: a claimed redrive is nonterminal until its new
	// supervisor finishes. This runs only after exact authority is proven.
	target := "running"
	if enqueue {
		target = "queued"
	}
	// An earlier cancel can race terminal DLQ persistence and leave the now
	// operator-visible failed_dlq row flagged. This explicit redrive is fresh
	// operator authority: clear that stale flag in the same CAS that reopens the
	// run, otherwise the local watcher kills it immediately and the distributed
	// queue refuses to claim it.
	const q = `UPDATE runs SET status = $1, finished_at = NULL, cancel_requested = $2
		WHERE id = $3 AND status = 'failed_dlq'`
	res, err = tx.ExecContext(ctx, j.bind(q), target, j.boolValue(false), runID)
	if err != nil {
		return false, fmt.Errorf("journal: start dead-letter retry: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, fmt.Errorf("journal: locked dead-letter retry run changed concurrently")
	}
	// The retry reuses the run id but represents a new terminal side-effect
	// generation. Reset the old receipt atomically so a later terminal outcome
	// is not swallowed by the prior delivered row.
	if _, err := tx.ExecContext(ctx, j.bind(`INSERT INTO terminal_effects (run_id, status, attempts, claimed_at, delivered_at, last_error, created_at)
		VALUES ($1, $2, 0, NULL, NULL, NULL, $3)
		ON CONFLICT (run_id) DO UPDATE SET status = excluded.status, attempts = 0,
		claimed_at = NULL, claim_token = NULL, delivered_at = NULL, last_error = NULL, created_at = excluded.created_at`), runID, "failed_dlq", j.now()); err != nil {
		return false, fmt.Errorf("journal: reset terminal effect for retry: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("journal: commit dead-letter retry: %w", err)
	}
	return true, nil
}
