package journal

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
	"github.com/bright-interaction/reactor/sdk/wire"
)

const (
	maxSignalTokenBytes   = 256
	maxSignalPayloadBytes = wire.MaxSignalPayloadBytes
)

func signalTokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func signalPayloadIdentity(tenantID, runID, scheduleID, stepName, signalName string, seq int64, field string) []byte {
	identity := payloadcrypto.Identity(tenantID, runID, "schedule_signal")
	identity = append(identity, payloadcrypto.Identity(scheduleID, strconv.FormatInt(seq, 10), field)...)
	return append(identity, payloadcrypto.Identity(stepName, signalName, "v1")...)
}

// An unkeyed old process may only write before the journal key is created.
// The migration trigger serializes this check with key initialization.
func (j *Journal) requireSignalPayloadKey(ctx context.Context, q queryRowContext) error {
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
	return fmt.Errorf("journal payload: inspect signal encryption state: %w", err)
}

func (j *Journal) sealSignalToken(tenantID, runID, scheduleID, stepName, signalName string, seq int64, token string) (string, string, error) {
	if len(token) == 0 || len(token) > maxSignalTokenBytes {
		return "", "", fmt.Errorf("journal payload: signal token exceeds %d-byte limit or is empty", maxSignalTokenBytes)
	}
	sealed, err := j.payloadKey.SealBytes([]byte(token), signalPayloadIdentity(tenantID, runID, scheduleID, stepName, signalName, seq, "signal_token"))
	if err != nil {
		return "", "", fmt.Errorf("journal payload: seal signal token: %w", err)
	}
	return string(sealed), signalTokenDigest(token), nil
}

func (j *Journal) sealSignalDelivery(tenantID, runID, scheduleID, stepName, signalName string, seq int64, payload []byte) ([]byte, error) {
	if len(payload) == 0 || len(payload) > maxSignalPayloadBytes {
		return nil, fmt.Errorf("journal payload: signal delivery exceeds %d-byte limit or is empty", maxSignalPayloadBytes)
	}
	sealed, err := j.payloadKey.SealBytes(payload, signalPayloadIdentity(tenantID, runID, scheduleID, stepName, signalName, seq, "signal_payload"))
	if err != nil {
		return nil, fmt.Errorf("journal payload: seal signal delivery: %w", err)
	}
	return sealed, nil
}

func (j *Journal) openScheduleSignal(s *Schedule, tenantID string, seq int64, version int,
	storedToken sql.NullString, tokenCipher sql.NullString, tokenDigest sql.NullString, tokenBytes sql.NullInt64,
	storedPayload []byte, payloadBytes sql.NullInt64,
) error {
	switch version {
	case 0:
		if tokenCipher.Valid || tokenDigest.Valid || tokenBytes.Valid || payloadBytes.Valid {
			return payloadcrypto.ErrInvalidEnvelope
		}
		if storedToken.Valid {
			s.SignalToken = storedToken.String
			s.SignalTokenPresent = s.SignalToken != ""
		}
		if len(storedPayload) > 0 {
			s.SignalPayload = append([]byte(nil), storedPayload...)
			s.SignalPayloadPresent = true
		}
		return nil
	case 1:
		if s.Kind != KindSignal || storedToken.Valid || !tokenCipher.Valid || !tokenDigest.Valid ||
			!tokenBytes.Valid || tokenBytes.Int64 < 1 || tokenBytes.Int64 > maxSignalTokenBytes ||
			len(tokenCipher.String) > payloadcrypto.CiphertextLimit(int(tokenBytes.Int64)) ||
			(storedPayload == nil) == payloadBytes.Valid {
			return payloadcrypto.ErrInvalidEnvelope
		}
		if j.payloadKey == nil {
			return payloadcrypto.ErrKeyRequired
		}
		plainToken, sealed, err := j.payloadKey.OpenBytes([]byte(tokenCipher.String),
			signalPayloadIdentity(tenantID, s.RunID, s.ID, s.StepName, s.SignalName, seq, "signal_token"))
		if err != nil || !sealed || len(plainToken) != int(tokenBytes.Int64) ||
			subtle.ConstantTimeCompare([]byte(signalTokenDigest(string(plainToken))), []byte(tokenDigest.String)) != 1 {
			return payloadReadError(err)
		}
		s.SignalToken = string(plainToken)
		s.SignalTokenPresent = true
		if storedPayload == nil {
			return nil
		}
		if !payloadBytes.Valid || payloadBytes.Int64 < 1 || payloadBytes.Int64 > maxSignalPayloadBytes ||
			len(storedPayload) > payloadcrypto.CiphertextLimit(int(payloadBytes.Int64)) {
			return payloadcrypto.ErrInvalidEnvelope
		}
		plainPayload, sealed, err := j.payloadKey.OpenBytes(storedPayload,
			signalPayloadIdentity(tenantID, s.RunID, s.ID, s.StepName, s.SignalName, seq, "signal_payload"))
		if err != nil || !sealed || len(plainPayload) != int(payloadBytes.Int64) {
			return payloadReadError(err)
		}
		s.SignalPayload = plainPayload
		s.SignalPayloadPresent = true
		return nil
	default:
		return payloadcrypto.ErrInvalidEnvelope
	}
}
