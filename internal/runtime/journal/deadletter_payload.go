package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

// A keyed step field already has this limit; apply it to direct DLQ writers
// too, so a full encrypted row can always be authenticated in bounded memory.
const maxDeadLetterFieldBytes = maxStepPayloadPlaintextBytes

type deadLetterPayloadArgs struct {
	errorText    string
	payload      any
	version      int
	errorBytes   any
	payloadBytes any
}

func deadLetterPayloadIdentity(tenantID, runID, id, stepName string, seq *int64, attempt *int, order int64, field string) []byte {
	ordinal, generation := "legacy", "legacy"
	if seq != nil {
		ordinal = strconv.FormatInt(*seq, 10)
	}
	if attempt != nil {
		generation = strconv.Itoa(*attempt)
	}
	identity := payloadcrypto.Identity(tenantID, runID, field)
	identity = append(identity, payloadcrypto.Identity(id, stepName, ordinal)...)
	return append(identity, payloadcrypto.Identity(generation, strconv.FormatInt(order, 10), "dlq-v1")...)
}

func (j *Journal) prepareDeadLetterPayload(ctx context.Context, q queryRowContext, id, runID, stepName string,
	seq *int64, attempt *int, failureOrder int64, errorText string, payload json.RawMessage,
) (deadLetterPayloadArgs, error) {
	if len(payload) == 0 || string(payload) == "null" {
		payload = json.RawMessage("{}")
	}
	if !json.Valid(payload) {
		return deadLetterPayloadArgs{}, errors.New("journal payload: invalid dead_letter JSON")
	}
	args := deadLetterPayloadArgs{errorText: errorText, payload: outputArg(payload, j.engine)}
	if j.payloadKey == nil {
		var one int
		err := q.QueryRowContext(ctx, j.bind(`SELECT 1 FROM journal_payload_keys WHERE id = $1`), "v1").Scan(&one)
		if err == nil {
			return deadLetterPayloadArgs{}, payloadcrypto.ErrKeyRequired
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return deadLetterPayloadArgs{}, fmt.Errorf("journal payload: inspect dead_letter encryption state: %w", err)
		}
		return args, nil
	}
	if len(errorText) > maxDeadLetterFieldBytes || len(payload) > maxDeadLetterFieldBytes {
		return deadLetterPayloadArgs{}, fmt.Errorf("journal payload: dead_letter field exceeds %d-byte limit", maxDeadLetterFieldBytes)
	}
	var tenantID string
	if err := q.QueryRowContext(ctx, j.bind(`SELECT tenant_id FROM runs WHERE id = $1`), runID).Scan(&tenantID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return deadLetterPayloadArgs{}, ErrNotFound
		}
		return deadLetterPayloadArgs{}, fmt.Errorf("journal payload: resolve dead_letter tenant: %w", err)
	}
	sealedError, err := j.payloadKey.SealBytes([]byte(errorText), deadLetterPayloadIdentity(tenantID, runID, id, stepName, seq, attempt, failureOrder, "dead_letter_error"))
	if err != nil {
		return deadLetterPayloadArgs{}, fmt.Errorf("journal payload: seal dead_letter error: %w", err)
	}
	sealedPayload, err := j.payloadKey.SealJSON(payload, deadLetterPayloadIdentity(tenantID, runID, id, stepName, seq, attempt, failureOrder, "dead_letter_payload"))
	if err != nil {
		return deadLetterPayloadArgs{}, fmt.Errorf("journal payload: seal dead_letter payload: %w", err)
	}
	args.errorText = string(sealedError)
	args.payload = outputArg(sealedPayload, j.engine)
	args.version = 1
	args.errorBytes = len(errorText)
	args.payloadBytes = len(payload)
	return args, nil
}

// The exact DLQ identity, including its row ID and optional durable attempt,
// is authenticated before a caller can inspect the original values.
func (j *Journal) openDeadLetterPayload(item *DeadLetterItem, tenantID string, version int,
	errorLen, payloadLen sql.NullInt64, storedError sql.NullString, storedPayload []byte,
	errorStoredSize, payloadStoredSize sql.NullInt64, maxPayloadBytes, maxErrorBytes int,
) error {
	if version == 0 {
		if errorLen.Valid || payloadLen.Valid {
			return payloadcrypto.ErrInvalidEnvelope
		}
		item.ErrorBytes = int(errorStoredSize.Int64)
		item.PayloadBytes = int(payloadStoredSize.Int64)
		item.ErrorTruncated = !storedError.Valid
		item.PayloadTruncated = storedPayload == nil
		item.ErrorText = storedError.String
		if storedPayload != nil {
			item.Payload = append(json.RawMessage(nil), storedPayload...)
		}
		return nil
	}
	if version != 1 || !errorLen.Valid || !payloadLen.Valid ||
		errorLen.Int64 < 0 || errorLen.Int64 > maxDeadLetterFieldBytes ||
		payloadLen.Int64 < 0 || payloadLen.Int64 > maxDeadLetterFieldBytes ||
		!errorStoredSize.Valid || !payloadStoredSize.Valid ||
		errorStoredSize.Int64 > int64(payloadcrypto.CiphertextLimit(int(errorLen.Int64))) ||
		payloadStoredSize.Int64 > int64(payloadcrypto.JSONCiphertextLimit(int(payloadLen.Int64))) {
		return payloadcrypto.ErrInvalidEnvelope
	}
	item.ErrorBytes = int(errorLen.Int64)
	item.PayloadBytes = int(payloadLen.Int64)
	item.ErrorTruncated = maxErrorBytes >= 0 && (maxErrorBytes == 0 || item.ErrorBytes > maxErrorBytes)
	item.PayloadTruncated = maxPayloadBytes >= 0 && (maxPayloadBytes == 0 || item.PayloadBytes > maxPayloadBytes)
	if item.ErrorTruncated && item.PayloadTruncated {
		return nil
	}
	if j.payloadKey == nil {
		return payloadcrypto.ErrKeyRequired
	}
	if !item.ErrorTruncated {
		if !storedError.Valid {
			return payloadcrypto.ErrInvalidEnvelope
		}
		opened, encrypted, err := j.payloadKey.OpenBytes([]byte(storedError.String),
			deadLetterPayloadIdentity(tenantID, item.RunID, item.ID, item.StepName, item.StepSeq, item.StepAttempt, item.FailureOrder, "dead_letter_error"))
		if err != nil || !encrypted || len(opened) != item.ErrorBytes {
			return payloadReadError(err)
		}
		item.ErrorText = string(opened)
	}
	if !item.PayloadTruncated {
		if storedPayload == nil {
			return payloadcrypto.ErrInvalidEnvelope
		}
		opened, encrypted, err := j.payloadKey.OpenJSON(storedPayload,
			deadLetterPayloadIdentity(tenantID, item.RunID, item.ID, item.StepName, item.StepSeq, item.StepAttempt, item.FailureOrder, "dead_letter_payload"))
		if err != nil || !encrypted || len(opened) != item.PayloadBytes || !json.Valid(opened) {
			return payloadReadError(err)
		}
		item.Payload = json.RawMessage(opened)
	}
	return nil
}
