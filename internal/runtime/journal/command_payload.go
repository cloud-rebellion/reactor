package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

type commandStoredField struct {
	Text       string
	Version    int
	PlainBytes any
}

func (j *Journal) requireCommandPayloadKey(ctx context.Context, q queryRowContext) error {
	if j.payloadKey != nil {
		return nil
	}
	var one int
	err := q.QueryRowContext(ctx, j.bind(`SELECT 1 FROM journal_payload_keys WHERE id = $1`), "v1").Scan(&one)
	if err == nil {
		return payloadcrypto.ErrKeyRequired
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return fmt.Errorf("journal payload: inspect command encryption state: %w", err)
}

func commandFieldIdentity(tenantID, runID string, stepSeq, attempt int, field string) []byte {
	identity := payloadcrypto.Identity(tenantID, runID, field)
	return append(identity, payloadcrypto.Identity(strconv.Itoa(stepSeq), strconv.Itoa(attempt), "command-v1")...)
}

func commandFieldLimit(field string) int {
	switch field {
	case "run_error", "step_error", "attempt_error":
		return MaxCommandErrorBytes
	default:
		return MaxCommandOutputBytes
	}
}

// sealCommandField is called only after the enclosing writer checked the
// wrapped-key state. Even an empty field is sealed under a keyed row so a
// projection can move to its next attempt without downgrading version one.
func (j *Journal) sealCommandField(tenantID, runID string, stepSeq, attempt int, field, plain string) (commandStoredField, error) {
	if len(plain) > commandFieldLimit(field) {
		return commandStoredField{}, fmt.Errorf("journal payload: command field exceeds %d-byte limit", commandFieldLimit(field))
	}
	if j.payloadKey == nil {
		return commandStoredField{Text: plain}, nil
	}
	sealed, err := j.payloadKey.SealBytes([]byte(plain), commandFieldIdentity(tenantID, runID, stepSeq, attempt, field))
	if err != nil {
		return commandStoredField{}, fmt.Errorf("journal payload: seal command field: %w", err)
	}
	return commandStoredField{Text: string(sealed), Version: 1, PlainBytes: len(plain)}, nil
}

func (j *Journal) openCommandField(tenantID, runID string, stepSeq, attempt int, field string, version int, stored sql.NullString) (string, error) {
	if !stored.Valid {
		return "", payloadcrypto.ErrInvalidEnvelope
	}
	limit := commandFieldLimit(field)
	switch version {
	case 0:
		if len(stored.String) > limit {
			return "", payloadcrypto.ErrInvalidEnvelope
		}
		return stored.String, nil
	case 1:
		if j.payloadKey == nil {
			return "", payloadcrypto.ErrKeyRequired
		}
		if len(stored.String) > payloadcrypto.CiphertextLimit(limit) {
			return "", payloadcrypto.ErrInvalidEnvelope
		}
		plain, sealed, err := j.payloadKey.OpenBytes([]byte(stored.String), commandFieldIdentity(tenantID, runID, stepSeq, attempt, field))
		if err != nil || !sealed {
			return "", payloadReadError(err)
		}
		if len(plain) > limit {
			return "", payloadcrypto.ErrInvalidEnvelope
		}
		return string(plain), nil
	default:
		return "", payloadcrypto.ErrInvalidEnvelope
	}
}

func (j *Journal) commandTextSize(column string) string {
	if j.engine == EnginePostgres {
		return "octet_length(" + column + ")"
	}
	return "length(CAST(" + column + " AS BLOB))"
}

// An omitted legacy value is never sent to a worker or MCP process. Encrypted
// values have a separate ciphertext bound before they are authenticated.
func (j *Journal) commandTextProjection(alias, field string, legacyLimit, encryptedLimit int) string {
	column := alias + "." + field + "_text"
	version := alias + "." + field + "_crypto_version"
	size := j.commandTextSize(column)
	return fmt.Sprintf(`CASE WHEN %s = 0 AND %s <= %d THEN %s
		WHEN %s = 1 AND %s <= %d THEN %s ELSE NULL END`,
		version, size, legacyLimit, column,
		version, size, payloadcrypto.CiphertextLimit(encryptedLimit), column)
}

func (j *Journal) commandErrorSizeExpr(alias string) string {
	return fmt.Sprintf("CASE WHEN %s.error_crypto_version = 1 THEN %s.error_plaintext_bytes ELSE %s END",
		alias, alias, j.commandTextSize(alias+".error_text"))
}

// Closing a run or recovering an expired claim writes a distinct envelope per
// step and attempt. A bulk SQL update cannot safely reuse one ciphertext:
// step sequence and attempt are authenticated by each field's AAD.
func (j *Journal) closeCommandStepErrors(ctx context.Context, tx *sql.Tx, tenantID, runID string, statuses []string, nextStatus, reason string, at any, clearFinished bool) error {
	for _, status := range statuses {
		rows, err := tx.QueryContext(ctx, j.bind(`SELECT step_seq, attempt FROM command_run_steps WHERE run_id = $1 AND status = $2`), runID, status)
		if err != nil {
			return err
		}
		type ref struct{ seq, attempt int }
		var refs []ref
		for rows.Next() {
			var r ref
			if err := rows.Scan(&r.seq, &r.attempt); err != nil {
				rows.Close()
				return err
			}
			refs = append(refs, r)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, r := range refs {
			field, err := j.sealCommandField(tenantID, runID, r.seq, r.attempt, "step_error", reason)
			if err != nil {
				return err
			}
			var finished any = at
			if clearFinished {
				finished = nil
			}
			if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_run_steps SET status = $1, error_text = $2,
				error_crypto_version = $3, error_plaintext_bytes = $4, finished_at = $5, updated_at = $6
				WHERE run_id = $7 AND step_seq = $8 AND status = $9`), nextStatus, field.Text, field.Version,
				field.PlainBytes, finished, at, runID, r.seq, status); err != nil {
				return err
			}
		}
	}
	return nil
}

func (j *Journal) closeCommandAttemptErrors(ctx context.Context, tx *sql.Tx, tenantID, runID string, currentStatus, nextStatus, reason string, at any, owner, token string) error {
	q := `SELECT step_seq, attempt FROM command_run_step_attempts WHERE run_id = $1 AND status = $2`
	args := []any{runID, currentStatus}
	if owner != "" || token != "" {
		q += ` AND claim_owner = $3 AND claim_token = $4`
		args = append(args, owner, token)
	}
	rows, err := tx.QueryContext(ctx, j.bind(q), args...)
	if err != nil {
		return err
	}
	type ref struct{ seq, attempt int }
	var refs []ref
	for rows.Next() {
		var r ref
		if err := rows.Scan(&r.seq, &r.attempt); err != nil {
			rows.Close()
			return err
		}
		refs = append(refs, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, r := range refs {
		field, err := j.sealCommandField(tenantID, runID, r.seq, r.attempt, "attempt_error", reason)
		if err != nil {
			return err
		}
		update := `UPDATE command_run_step_attempts SET status = $1, error_text = $2,
			error_crypto_version = $3, error_plaintext_bytes = $4, finished_at = $5, updated_at = $6
			WHERE run_id = $7 AND step_seq = $8 AND attempt = $9 AND status = $10`
		updateArgs := []any{nextStatus, field.Text, field.Version, field.PlainBytes, at, at, runID, r.seq, r.attempt, currentStatus}
		if owner != "" || token != "" {
			update += ` AND claim_owner = $11 AND claim_token = $12`
			updateArgs = append(updateArgs, owner, token)
		}
		if _, err := tx.ExecContext(ctx, j.bind(update), updateArgs...); err != nil {
			return err
		}
	}
	return nil
}
