package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

const (
	maxNotificationConfigBytes       = 1 << 20
	maxLegacyNotificationConfigBytes = 8 << 20
)

func notificationConfigIdentity(tenantID, channelID, kind string) []byte {
	return payloadcrypto.Identity(tenantID, channelID, "notification_channel_config:"+kind)
}

func (j *Journal) requireNotificationPayloadKey(ctx context.Context, q queryRowContext) error {
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
	return fmt.Errorf("journal payload: inspect notification encryption state: %w", err)
}

func (j *Journal) prepareNotificationConfig(ctx context.Context, tenantID, channelID, kind string, config json.RawMessage) (any, int, any, error) {
	if err := j.requireNotificationPayloadKey(ctx, j.db); err != nil {
		return nil, 0, nil, err
	}
	if j.payloadKey == nil {
		return outputArg(config, j.engine), 0, nil, nil
	}
	if len(config) > maxNotificationConfigBytes {
		return nil, 0, nil, fmt.Errorf("journal payload: notification config exceeds %d-byte limit", maxNotificationConfigBytes)
	}
	sealed, err := j.payloadKey.SealJSON(config, notificationConfigIdentity(tenantID, channelID, kind))
	if err != nil {
		return nil, 0, nil, fmt.Errorf("journal payload: seal notification config: %w", err)
	}
	return outputArg(sealed, j.engine), 1, len(config), nil
}

func (j *Journal) openNotificationConfig(ch *NotificationChannel, version int, plainBytes sql.NullInt64, stored []byte) error {
	switch version {
	case 0:
		if plainBytes.Valid || stored == nil || len(stored) > maxLegacyNotificationConfigBytes || !json.Valid(stored) {
			return payloadcrypto.ErrInvalidEnvelope
		}
		ch.ConfigJSON = append(json.RawMessage(nil), stored...)
		return nil
	case 1:
		if j.payloadKey == nil {
			return payloadcrypto.ErrKeyRequired
		}
		if !plainBytes.Valid || plainBytes.Int64 < 0 || plainBytes.Int64 > maxNotificationConfigBytes ||
			stored == nil || len(stored) > payloadcrypto.JSONCiphertextLimit(int(plainBytes.Int64)) {
			return payloadcrypto.ErrInvalidEnvelope
		}
		plain, sealed, err := j.payloadKey.OpenJSON(stored, notificationConfigIdentity(ch.TenantID, ch.ID, ch.Kind))
		if err != nil || !sealed || len(plain) != int(plainBytes.Int64) || !json.Valid(plain) {
			return payloadReadError(err)
		}
		ch.ConfigJSON = json.RawMessage(plain)
		return nil
	default:
		return payloadcrypto.ErrInvalidEnvelope
	}
}

// SQL keeps an oversized legacy row or malformed envelope out of the Go
// process. Metadata-only inventory queries never select config_json at all.
func (j *Journal) notificationConfigProjection(alias string) string {
	column := alias + ".config_json"
	var value, size string
	if j.engine == EnginePostgres {
		value = column + "::text"
		size = "octet_length(" + value + ")"
	} else {
		value = column
		size = "length(CAST(" + value + " AS BLOB))"
	}
	return fmt.Sprintf(`CASE WHEN %s.config_crypto_version = 0 AND %s <= %d THEN %s
		WHEN %s.config_crypto_version = 1 AND %s <= %d THEN %s ELSE NULL END`,
		alias, size, maxLegacyNotificationConfigBytes, value,
		alias, size, payloadcrypto.JSONCiphertextLimit(maxNotificationConfigBytes), value)
}
