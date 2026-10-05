package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

// DeadLetterItem is one row of the dead_letter table. The supervisor
// writes a row when a step's final attempt returned a non-retryable error;
// operators read the table via `reactor dlq list/show` to inspect or
// (week 8) re-queue the failed step.
//
// JSON tags use snake_case so the CLI --json output matches what we
// expect from future dashboard / MCP surfaces.
type DeadLetterItem struct {
	ID           string          `json:"id"`
	RunID        string          `json:"run_id"`
	StepName     string          `json:"step_name"`
	StepSeq      *int64          `json:"step_seq,omitempty"`
	StepAttempt  *int            `json:"step_attempt,omitempty"`
	FailureOrder int64           `json:"failure_order,omitempty"`
	ErrorText    string          `json:"error_text"`
	Payload      json.RawMessage `json:"payload"`
	// ErrorBytes and PayloadBytes are durable sizes captured by bounded
	// control-plane reads. The MCP view uses them to report truncation without
	// loading a large failure or payload into the process.
	ErrorBytes       int       `json:"-"`
	PayloadBytes     int       `json:"-"`
	ErrorTruncated   bool      `json:"-"`
	PayloadTruncated bool      `json:"-"`
	MovedAt          time.Time `json:"moved_at"`
}

// MoveStepToDeadLetter inserts a dead_letter row. payload is the step's
// last-attempted output (or input snapshot) JSON-encoded so a manual
// retry can inspect the data the failed attempt was working with.
func (j *Journal) MoveStepToDeadLetter(ctx context.Context, runID, stepName, errorText string, payload json.RawMessage) error {
	return j.moveStepToDeadLetter(ctx, runID, stepName, nil, nil, errorText, payload)
}

// MoveStepAttemptToDeadLetter inserts a DLQ row bound to one exact durable
// attempt. This identity is what lets an operator redrive a repeated step name
// without accidentally authorizing another loop ordinal/generation.
func (j *Journal) MoveStepAttemptToDeadLetter(ctx context.Context, runID, stepName string, seq int64, attempt int, errorText string, payload json.RawMessage) error {
	return j.moveStepToDeadLetter(ctx, runID, stepName, &seq, &attempt, errorText, payload)
}

func (j *Journal) moveStepToDeadLetter(ctx context.Context, runID, stepName string, seq *int64, attempt *int, errorText string, payload json.RawMessage) error {
	id, err := newID("dlq_")
	if err != nil {
		return err
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin dead_letter insert: %w", err)
	}
	defer tx.Rollback()
	order, err := j.nextDeadLetterFailureOrder(ctx, tx, runID)
	if err != nil {
		return err
	}
	sealed, err := j.prepareDeadLetterPayload(ctx, tx, id, runID, stepName, seq, attempt, order, errorText, payload)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, j.bind(insertDeadLetterSQL),
		id, runID, stepName, nullableInt64(seq), nullableInt(attempt), order,
		sealed.errorText, sealed.payload, sealed.version, sealed.errorBytes, sealed.payloadBytes,
	)
	if err != nil {
		return fmt.Errorf("journal: move dead_letter: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit dead_letter insert: %w", err)
	}
	return nil
}

const insertDeadLetterSQL = `INSERT INTO dead_letter
	(id, run_id, step_name, step_seq, step_attempt, failure_order, error_text, payload,
	 payload_crypto_version, error_plaintext_bytes, payload_plaintext_bytes)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

// Allocate a monotonically increasing order without changing the existing
// step-then-run lock order in finalization. PostgreSQL uses a DLQ-only
// advisory lock keyed by run; SQLite takes its writer lock before MAX().
func (j *Journal) nextDeadLetterFailureOrder(ctx context.Context, tx *sql.Tx, runID string) (int64, error) {
	if j.engine == EnginePostgres {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1919250537, hashtext($1::text))`, runID); err != nil {
			return 0, fmt.Errorf("journal: lock dead_letter order: %w", err)
		}
	} else {
		if err := lockRunForStepRepair(ctx, tx, j, runID); err != nil {
			return 0, err
		}
	}
	var order int64
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COALESCE(MAX(failure_order), 0) + 1 FROM dead_letter WHERE run_id = $1`), runID).Scan(&order); err != nil {
		return 0, fmt.Errorf("journal: read dead_letter order: %w", err)
	}
	return order, nil
}

// ListDeadLetterItems pages through dead_letter newest-first. limit caps
// the result; offset supports follow-up pagination from CLI / dashboard.
func (j *Journal) ListDeadLetterItems(ctx context.Context, limit, offset int) ([]DeadLetterItem, error) {
	if limit <= 0 {
		limit = 50
	}
	q := j.deadLetterSelect(-1, -1) + ` FROM dead_letter d JOIN runs r ON r.id = d.run_id
		ORDER BY d.moved_at DESC, d.id DESC LIMIT $1 OFFSET $2`
	rows, err := j.db.QueryContext(ctx, j.bind(q), limit, offset)
	if err != nil {
		return nil, fmt.Errorf("journal: list dead_letter: %w", err)
	}
	defer rows.Close()

	var out []DeadLetterItem
	for rows.Next() {
		item, err := scanDeadLetter(rows.Scan, j)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// ListDeadLetterItemsForTenant is the tenant-scoped variant used by member
// surfaces. The dead_letter table carries no tenant column, so scope through
// its immutable parent run in the join predicate.
func (j *Journal) ListDeadLetterItemsForTenant(ctx context.Context, limit, offset int, tenantID string) ([]DeadLetterItem, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("journal: list dead_letter: tenant required")
	}
	if limit <= 0 {
		limit = 50
	}
	q := j.deadLetterSelect(-1, -1) + ` FROM dead_letter d JOIN runs r ON r.id = d.run_id
		WHERE r.tenant_id = $1
		ORDER BY d.moved_at DESC, d.id DESC LIMIT $2 OFFSET $3`
	rows, err := j.db.QueryContext(ctx, j.bind(q), tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("journal: list dead_letter tenant: %w", err)
	}
	defer rows.Close()
	var out []DeadLetterItem
	for rows.Next() {
		item, err := scanDeadLetter(rows.Scan, j)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// ListDeadLetterItemsForTenantPage is the tenant-scoped lookahead variant
// used by bounded control-plane responses. Callers request limit+1 rows and
// trim the extra row to expose continuation without a separate count query.
func (j *Journal) ListDeadLetterItemsForTenantPage(ctx context.Context, limit, offset int, tenantID string) ([]DeadLetterItem, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("journal: list dead_letter: tenant required")
	}
	q := j.deadLetterSelect(-1, -1) + ` FROM dead_letter d JOIN runs r ON r.id = d.run_id
		WHERE r.tenant_id = $1
		ORDER BY d.moved_at DESC, d.id DESC LIMIT $2 OFFSET $3`
	rows, err := j.db.QueryContext(ctx, j.bind(q), tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("journal: list dead_letter tenant page: %w", err)
	}
	defer rows.Close()
	var out []DeadLetterItem
	for rows.Next() {
		item, err := scanDeadLetter(rows.Scan, j)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// ListDeadLetterItemsForTenantPageBounded is the MCP/read-model variant. The
// SQL projection measures error_text and payload, returning NULL for values
// above the supplied limits so a huge or secret-bearing legacy row is never
// materialised merely to render a DLQ inventory.
func (j *Journal) ListDeadLetterItemsForTenantPageBounded(ctx context.Context, limit, offset int, tenantID string, maxPayloadBytes, maxErrorBytes int) ([]DeadLetterItem, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, fmt.Errorf("journal: list dead_letter: tenant required")
	}
	if limit <= 0 || offset < 0 {
		return nil, fmt.Errorf("journal: list bounded dead_letter: invalid page")
	}
	if err := validateDeadLetterBounds(maxPayloadBytes, maxErrorBytes); err != nil {
		return nil, err
	}
	q := j.boundedDeadLetterQuery(`WHERE r.tenant_id = $1 ORDER BY d.moved_at DESC, d.id DESC LIMIT $2 OFFSET $3`, maxPayloadBytes, maxErrorBytes)
	rows, err := j.db.QueryContext(ctx, j.bind(q), tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("journal: list bounded dead_letter tenant page: %w", err)
	}
	defer rows.Close()
	var out []DeadLetterItem
	for rows.Next() {
		item, scanErr := scanBoundedDeadLetter(rows.Scan, j, maxPayloadBytes, maxErrorBytes)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// GetDeadLetterItem returns the single row by id. Returns ErrNotFound when
// no row matches; callers (dlq show CLI) map this to a non-zero exit.
func (j *Journal) GetDeadLetterItem(ctx context.Context, id string) (DeadLetterItem, error) {
	q := j.deadLetterSelect(-1, -1) + ` FROM dead_letter d JOIN runs r ON r.id = d.run_id WHERE d.id = $1`
	row := j.db.QueryRowContext(ctx, j.bind(q), id)
	item, err := scanDeadLetter(row.Scan, j)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DeadLetterItem{}, ErrNotFound
		}
		return DeadLetterItem{}, err
	}
	return item, nil
}

// GetDeadLetterItemForTenant returns a dead-letter row only when its immutable
// parent run belongs to tenantID. The tenant predicate lives in the same
// query as the row lookup so a foreign id is indistinguishable from a missing
// id and its payload/error text is never loaded by a tenant-scoped caller.
func (j *Journal) GetDeadLetterItemForTenant(ctx context.Context, id, tenantID string) (DeadLetterItem, error) {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(tenantID) == "" {
		return DeadLetterItem{}, ErrNotFound
	}
	q := j.deadLetterSelect(-1, -1) + ` FROM dead_letter d JOIN runs r ON r.id = d.run_id
		WHERE d.id = $1 AND r.tenant_id = $2`
	row := j.db.QueryRowContext(ctx, j.bind(q), id, tenantID)
	item, err := scanDeadLetter(row.Scan, j)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DeadLetterItem{}, ErrNotFound
		}
		return DeadLetterItem{}, err
	}
	return item, nil
}

// GetDeadLetterItemForTenantBounded reads one tenant-owned DLQ row with
// explicit payload/error limits. Zero limits omit both values while retaining
// their durable sizes, which is sufficient for retry authorization.
func (j *Journal) GetDeadLetterItemForTenantBounded(ctx context.Context, id, tenantID string, maxPayloadBytes, maxErrorBytes int) (DeadLetterItem, error) {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(tenantID) == "" {
		return DeadLetterItem{}, ErrNotFound
	}
	if err := validateDeadLetterBounds(maxPayloadBytes, maxErrorBytes); err != nil {
		return DeadLetterItem{}, err
	}
	q := j.boundedDeadLetterQuery(`WHERE d.id = $1 AND r.tenant_id = $2`, maxPayloadBytes, maxErrorBytes)
	row := j.db.QueryRowContext(ctx, j.bind(q), id, tenantID)
	item, err := scanBoundedDeadLetter(row.Scan, j, maxPayloadBytes, maxErrorBytes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DeadLetterItem{}, ErrNotFound
		}
		return DeadLetterItem{}, err
	}
	return item, nil
}

func validateDeadLetterBounds(maxPayloadBytes, maxErrorBytes int) error {
	if maxPayloadBytes < 0 || maxErrorBytes < 0 {
		return errors.New("journal: negative dead_letter read bound")
	}
	if maxPayloadBytes > 16<<20 || maxErrorBytes > 16<<20 {
		return errors.New("journal: dead_letter read bound exceeds 16 MiB")
	}
	return nil
}

func (j *Journal) boundedDeadLetterQuery(where string, maxPayloadBytes, maxErrorBytes int) string {
	return j.deadLetterSelect(maxPayloadBytes, maxErrorBytes) + ` FROM dead_letter d JOIN runs r ON r.id = d.run_id ` + where
}

// A version-one envelope may be larger than the caller's plaintext budget.
// SQL projects the ciphertext only when both the authenticated length marker
// and the stored envelope fit. Version-zero rows retain their old byte bound.
func (j *Journal) deadLetterSelect(maxPayloadBytes, maxErrorBytes int) string {
	var payloadSize, payloadColumn, errorSize string
	if j.engine == EnginePostgres {
		payloadSize = "octet_length(d.payload::text)"
		errorSize = "octet_length(d.error_text)"
		payloadColumn = "d.payload::text"
	} else {
		payloadSize = "length(CAST(d.payload AS BLOB))"
		errorSize = "length(CAST(d.error_text AS BLOB))"
		payloadColumn = "d.payload"
	}
	selectField := func(value, storedSize, plainSize string, maxPlain, maxCipher int) string {
		legacy := "d.payload_crypto_version = 0"
		sealed := "d.payload_crypto_version = 1 AND " + storedSize + " <= " + strconv.Itoa(maxCipher)
		if maxPlain >= 0 {
			if maxPlain == 0 {
				return "NULL"
			}
			legacy += " AND " + storedSize + " <= " + strconv.Itoa(maxPlain)
			sealed += " AND " + plainSize + " <= " + strconv.Itoa(maxPlain)
		}
		return "CASE WHEN " + sealed + " OR " + legacy + " THEN " + value + " ELSE NULL END"
	}
	maxPayloadCipher := payloadcrypto.JSONCiphertextLimit(maxDeadLetterFieldBytes)
	maxErrorCipher := payloadcrypto.CiphertextLimit(maxDeadLetterFieldBytes)
	if maxPayloadBytes > 0 && maxPayloadBytes < maxDeadLetterFieldBytes {
		maxPayloadCipher = payloadcrypto.JSONCiphertextLimit(maxPayloadBytes)
	}
	if maxErrorBytes > 0 && maxErrorBytes < maxDeadLetterFieldBytes {
		maxErrorCipher = payloadcrypto.CiphertextLimit(maxErrorBytes)
	}
	errorValue := selectField("d.error_text", errorSize, "d.error_plaintext_bytes", maxErrorBytes, maxErrorCipher)
	payloadValue := selectField(payloadColumn, payloadSize, "d.payload_plaintext_bytes", maxPayloadBytes, maxPayloadCipher)
	return `SELECT d.id, d.run_id, d.step_name, d.step_seq, d.step_attempt, d.failure_order,
		r.tenant_id, d.payload_crypto_version, d.error_plaintext_bytes, ` + errorValue + `,
		` + errorSize + `, d.payload_plaintext_bytes, ` + payloadValue + `, ` + payloadSize + `, d.moved_at`
}

// FindDeadLetterByRun returns the dead_letter row for the given run id,
// or ErrNotFound when no DLQ row exists for the run. The dashboard's
// run detail page uses this to decide whether to render a "Retry from
// DLQ" button.
func (j *Journal) FindDeadLetterByRun(ctx context.Context, runID string) (DeadLetterItem, error) {
	q := j.deadLetterSelect(-1, -1) + ` FROM dead_letter d JOIN runs r ON r.id = d.run_id
		WHERE d.run_id = $1
		ORDER BY CASE WHEN d.failure_order IS NULL THEN 1 ELSE 0 END,
		d.failure_order DESC, d.moved_at DESC, d.id DESC LIMIT 1`
	row := j.db.QueryRowContext(ctx, j.bind(q), runID)
	item, err := scanDeadLetter(row.Scan, j)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DeadLetterItem{}, ErrNotFound
		}
		return DeadLetterItem{}, err
	}
	return item, nil
}

// DeleteDeadLetter removes a dead_letter row by id. Used by `reactor
// dlq retry` after a successful retry so the operator's todo list
// shrinks. Errors when the row is gone (caller should treat as success).
func (j *Journal) DeleteDeadLetter(ctx context.Context, id string) error {
	const q = `DELETE FROM dead_letter WHERE id = $1`
	res, err := j.db.ExecContext(ctx, j.bind(q), id)
	if err != nil {
		return fmt.Errorf("journal: delete dead_letter: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanDeadLetter(scan func(...any) error, j *Journal) (DeadLetterItem, error) {
	return scanBoundedDeadLetter(scan, j, -1, -1)
}

func scanBoundedDeadLetter(scan func(...any) error, j *Journal, maxPayloadBytes, maxErrorBytes int) (DeadLetterItem, error) {
	var (
		item               DeadLetterItem
		seq                sql.NullInt64
		attempt            sql.NullInt64
		order              sql.NullInt64
		tenantID           string
		version            int
		errorPlainBytes    sql.NullInt64
		storedError        sql.NullString
		errorStoredBytes   sql.NullInt64
		payloadPlainBytes  sql.NullInt64
		storedPayload      []byte
		payloadStoredBytes sql.NullInt64
		moved              sql.NullString
	)
	if err := scan(&item.ID, &item.RunID, &item.StepName, &seq, &attempt, &order,
		&tenantID, &version, &errorPlainBytes, &storedError, &errorStoredBytes,
		&payloadPlainBytes, &storedPayload, &payloadStoredBytes, &moved); err != nil {
		return DeadLetterItem{}, err
	}
	if seq.Valid {
		value := seq.Int64
		item.StepSeq = &value
	}
	if attempt.Valid {
		value := int(attempt.Int64)
		item.StepAttempt = &value
	}
	if order.Valid {
		item.FailureOrder = order.Int64
	}
	if version == 1 && (!order.Valid || order.Int64 <= 0) {
		return DeadLetterItem{}, payloadcrypto.ErrInvalidEnvelope
	}
	if err := j.openDeadLetterPayload(&item, tenantID, version, errorPlainBytes, payloadPlainBytes,
		storedError, storedPayload, errorStoredBytes, payloadStoredBytes,
		maxPayloadBytes, maxErrorBytes); err != nil {
		return DeadLetterItem{}, err
	}
	if moved.Valid {
		if t, err := j.parseTime(moved.String); err == nil {
			item.MovedAt = t
		}
	}
	return item, nil
}

func nullableInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullableInt(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}
