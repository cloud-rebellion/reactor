package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
	"github.com/bright-interaction/reactor/sdk/wire"
)

// A child StepEnd frame is at most wire.MaxFrameBytes. Keep an additional
// journal-side bound for direct callers: every v1 field can be authenticated
// by a bounded replay or audited export read. Larger data belongs in object
// storage with a reference in the step output.
const maxStepPayloadPlaintextBytes = wire.MaxFrameBytes

type stepPayloadArgs struct {
	output      any
	errorText   any
	version     int
	outputBytes any
	errorBytes  any
}

func (j *Journal) openStepValues(tenantID, runID, stepName string, seq int64, attempt, version int,
	outputBytes, errorBytes sql.NullInt64, storedOutput []byte, storedError sql.NullString,
) (json.RawMessage, string, error) {
	if version == 0 {
		if outputBytes.Valid || errorBytes.Valid {
			return nil, "", payloadcrypto.ErrInvalidEnvelope
		}
		return append(json.RawMessage(nil), storedOutput...), storedError.String, nil
	}
	if version != 1 || (storedOutput == nil) == outputBytes.Valid || storedError.Valid != errorBytes.Valid {
		return nil, "", payloadcrypto.ErrInvalidEnvelope
	}
	if j.payloadKey == nil {
		return nil, "", payloadcrypto.ErrKeyRequired
	}
	var output json.RawMessage
	var errorText string
	var err error
	if storedOutput != nil {
		output, err = j.openStepOutput(tenantID, runID, stepName, seq, attempt, version, outputBytes, storedOutput)
		if err != nil {
			return nil, "", err
		}
	}
	if storedError.Valid {
		errorText, err = j.openStepError(tenantID, runID, stepName, seq, attempt, version, errorBytes, storedError.String)
		if err != nil {
			return nil, "", err
		}
	}
	return output, errorText, nil
}

func stepPayloadIdentity(tenantID, runID, stepName string, seq int64, attempt int, field string) []byte {
	identity := payloadcrypto.Identity(tenantID, runID, field)
	return append(identity, payloadcrypto.Identity(stepName, strconv.FormatInt(seq, 10), strconv.Itoa(attempt))...)
}

func (j *Journal) prepareStepPayload(ctx context.Context, q queryRowContext, runID, stepName string, seq int64, attempt int, output json.RawMessage, errText string) (stepPayloadArgs, error) {
	if j.payloadKey != nil && (len(output) > maxStepPayloadPlaintextBytes || len(errText) > maxStepPayloadPlaintextBytes) {
		return stepPayloadArgs{}, fmt.Errorf("journal payload: step field exceeds %d-byte wire limit", maxStepPayloadPlaintextBytes)
	}
	args := stepPayloadArgs{output: outputArg(output, j.engine), errorText: nullable(errText)}
	if j.payloadKey == nil {
		// A keyed database must never accept a new plaintext step result. The
		// migration trigger fences an older binary racing key initialization.
		var one int
		err := q.QueryRowContext(ctx, j.bind(`SELECT 1 FROM journal_payload_keys WHERE id = $1`), "v1").Scan(&one)
		if err == nil {
			return stepPayloadArgs{}, payloadcrypto.ErrKeyRequired
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return stepPayloadArgs{}, fmt.Errorf("journal payload: inspect step encryption state: %w", err)
		}
		return args, nil
	}
	var tenantID string
	if err := q.QueryRowContext(ctx, j.bind(`SELECT tenant_id FROM runs WHERE id = $1`), runID).Scan(&tenantID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return stepPayloadArgs{}, ErrNotFound
		}
		return stepPayloadArgs{}, fmt.Errorf("journal payload: resolve step tenant: %w", err)
	}
	args.version = 1
	if len(output) != 0 {
		sealed, err := j.payloadKey.SealJSON(output, stepPayloadIdentity(tenantID, runID, stepName, seq, attempt, "step_output"))
		if err != nil {
			return stepPayloadArgs{}, fmt.Errorf("journal payload: seal step output: %w", err)
		}
		args.output, args.outputBytes = outputArg(sealed, j.engine), len(output)
	}
	if errText != "" {
		sealed, err := j.payloadKey.SealBytes([]byte(errText), stepPayloadIdentity(tenantID, runID, stepName, seq, attempt, "step_error"))
		if err != nil {
			return stepPayloadArgs{}, fmt.Errorf("journal payload: seal step error: %w", err)
		}
		args.errorText, args.errorBytes = string(sealed), len(errText)
	}
	return args, nil
}

func (j *Journal) openStepOutput(tenantID, runID, stepName string, seq int64, attempt, version int, plainBytes sql.NullInt64, stored []byte) (json.RawMessage, error) {
	if version == 0 {
		return append(json.RawMessage(nil), stored...), nil
	}
	if version != 1 || !plainBytes.Valid || plainBytes.Int64 < 0 || plainBytes.Int64 > maxStepPayloadPlaintextBytes || stored == nil {
		return nil, payloadcrypto.ErrInvalidEnvelope
	}
	if j.payloadKey == nil {
		return nil, payloadcrypto.ErrKeyRequired
	}
	plain, sealed, err := j.payloadKey.OpenJSON(stored, stepPayloadIdentity(tenantID, runID, stepName, seq, attempt, "step_output"))
	if err != nil || !sealed {
		return nil, payloadReadError(err)
	}
	if int64(len(plain)) != plainBytes.Int64 {
		return nil, payloadcrypto.ErrInvalidEnvelope
	}
	return json.RawMessage(plain), nil
}

func (j *Journal) openStepError(tenantID, runID, stepName string, seq int64, attempt, version int, plainBytes sql.NullInt64, stored string) (string, error) {
	if version == 0 {
		return stored, nil
	}
	if version != 1 || !plainBytes.Valid || plainBytes.Int64 < 0 || plainBytes.Int64 > maxStepPayloadPlaintextBytes || stored == "" {
		return "", payloadcrypto.ErrInvalidEnvelope
	}
	if j.payloadKey == nil {
		return "", payloadcrypto.ErrKeyRequired
	}
	plain, sealed, err := j.payloadKey.OpenBytes([]byte(stored), stepPayloadIdentity(tenantID, runID, stepName, seq, attempt, "step_error"))
	if err != nil || !sealed {
		return "", payloadReadError(err)
	}
	if int64(len(plain)) != plainBytes.Int64 {
		return "", payloadcrypto.ErrInvalidEnvelope
	}
	return string(plain), nil
}

func stepOutputStoredSize(engine Engine) string {
	if engine == EnginePostgres {
		return "octet_length(steps.output_jsonb::text)"
	}
	return "length(CAST(steps.output_jsonb AS BLOB))"
}

func stepErrorStoredSize(engine Engine) string {
	if engine == EnginePostgres {
		return "octet_length(steps.error_text)"
	}
	return "length(CAST(steps.error_text AS BLOB))"
}

func stepOutputText(engine Engine) string {
	if engine == EnginePostgres {
		return "steps.output_jsonb::text"
	}
	return "steps.output_jsonb"
}

// Bound at SQL projection time, before encrypted rows enter this process.
func stepOutputValue(engine Engine, maxPlainBytes int) string {
	if maxPlainBytes <= 0 {
		return "NULL"
	}
	return fmt.Sprintf(`CASE WHEN steps.payload_crypto_version = 1
		AND steps.output_plaintext_bytes <= %d
		AND %s <= %d THEN %s
		WHEN steps.payload_crypto_version = 0 AND %s <= %d THEN %s ELSE NULL END`,
		maxPlainBytes, stepOutputStoredSize(engine), payloadcrypto.JSONCiphertextLimit(maxPlainBytes), stepOutputText(engine),
		stepOutputStoredSize(engine), maxPlainBytes, stepOutputText(engine))
}

func stepOutputReplayValue(engine Engine) string {
	return fmt.Sprintf(`CASE WHEN steps.payload_crypto_version = 1 AND %s <= %d THEN %s
		WHEN steps.payload_crypto_version = 0 THEN %s ELSE NULL END`,
		stepOutputStoredSize(engine), payloadcrypto.JSONCiphertextLimit(maxStepPayloadPlaintextBytes),
		stepOutputText(engine), stepOutputText(engine))
}

func stepErrorValue(engine Engine, maxPlainBytes int) string {
	if maxPlainBytes <= 0 {
		return "NULL"
	}
	return fmt.Sprintf(`CASE WHEN steps.payload_crypto_version = 1
		AND steps.error_plaintext_bytes <= %d
		AND %s <= %d THEN steps.error_text
		WHEN steps.payload_crypto_version = 0 AND %s <= %d THEN steps.error_text ELSE NULL END`,
		maxPlainBytes, stepErrorStoredSize(engine), payloadcrypto.CiphertextLimit(maxPlainBytes),
		stepErrorStoredSize(engine), maxPlainBytes)
}

func stepErrorReplayValue(engine Engine) string {
	return fmt.Sprintf(`CASE WHEN steps.payload_crypto_version = 1 AND %s <= %d THEN steps.error_text
		WHEN steps.payload_crypto_version = 0 THEN steps.error_text ELSE NULL END`,
		stepErrorStoredSize(engine), payloadcrypto.CiphertextLimit(maxStepPayloadPlaintextBytes))
}

func stepOutputPlainSize(engine Engine) string {
	return fmt.Sprintf("CASE WHEN steps.payload_crypto_version = 1 THEN steps.output_plaintext_bytes ELSE %s END", stepOutputStoredSize(engine))
}

func stepErrorPlainSize(engine Engine) string {
	return fmt.Sprintf("CASE WHEN steps.payload_crypto_version = 1 THEN steps.error_plaintext_bytes ELSE %s END", stepErrorStoredSize(engine))
}
