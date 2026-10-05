package journal

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

type commandDefinitionStored struct {
	JSON             any
	CryptoVersion    int
	PlaintextBytes   any
	DefinitionSHA256 any
}

func commandDefinitionIdentity(tenantID, automationID string, version int) []byte {
	return payloadcrypto.Identity(tenantID, automationID, "command_definition:v1:"+strconv.Itoa(version))
}

func validCommandDefinitionDigest(digest string) bool {
	if len(digest) != 64 || strings.ToLower(digest) != digest {
		return false
	}
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == sha256.Size
}

// Historical imports can contain valid, non-canonical JSON. Their version
// summary has always identified the normalized definition when normalization
// succeeds, and the raw bytes otherwise. Keep that receipt stable when the
// storage-only backfill seals their byte-exact original definition.
func commandDefinitionReceiptDigest(raw json.RawMessage) string {
	if _, normalized, err := commandautomations.Normalize(raw); err == nil {
		raw = normalized
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (j *Journal) prepareCommandDefinition(ctx context.Context, q queryRowContext, tenantID, automationID string, version int, normalized json.RawMessage) (commandDefinitionStored, error) {
	if version < 1 || len(normalized) == 0 || len(normalized) > commandautomations.MaxDefinitionBytes || !json.Valid(normalized) {
		return commandDefinitionStored{}, payloadcrypto.ErrInvalidEnvelope
	}
	if j.payloadKey == nil {
		var one int
		err := q.QueryRowContext(ctx, j.bind(`SELECT 1 FROM journal_payload_keys WHERE id = $1`), "v1").Scan(&one)
		if err == nil {
			return commandDefinitionStored{}, payloadcrypto.ErrKeyRequired
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return commandDefinitionStored{}, fmt.Errorf("journal payload: inspect command definition encryption state: %w", err)
		}
		return commandDefinitionStored{JSON: outputArg(normalized, j.engine)}, nil
	}
	sealed, err := j.payloadKey.SealJSON(normalized, commandDefinitionIdentity(tenantID, automationID, version))
	if err != nil {
		return commandDefinitionStored{}, fmt.Errorf("journal payload: seal command definition: %w", err)
	}
	sum := sha256.Sum256(normalized)
	return commandDefinitionStored{
		JSON: outputArg(sealed, j.engine), CryptoVersion: 1,
		PlaintextBytes: len(normalized), DefinitionSHA256: hex.EncodeToString(sum[:]),
	}, nil
}

func (j *Journal) openCommandDefinition(tenantID, automationID string, version, cryptoVersion int, plainBytes sql.NullInt64, definitionSHA256 sql.NullString, stored []byte) (json.RawMessage, error) {
	if version < 1 || stored == nil {
		return nil, payloadcrypto.ErrInvalidEnvelope
	}
	switch cryptoVersion {
	case 0:
		if plainBytes.Valid || definitionSHA256.Valid || len(stored) == 0 || len(stored) > commandautomations.MaxDefinitionBytes || !json.Valid(stored) {
			return nil, payloadcrypto.ErrInvalidEnvelope
		}
		return append(json.RawMessage(nil), stored...), nil
	case 1:
		if j.payloadKey == nil {
			return nil, payloadcrypto.ErrKeyRequired
		}
		if !plainBytes.Valid || plainBytes.Int64 < 1 || plainBytes.Int64 > commandautomations.MaxDefinitionBytes ||
			!definitionSHA256.Valid || !validCommandDefinitionDigest(definitionSHA256.String) ||
			len(stored) > payloadcrypto.JSONCiphertextLimit(int(plainBytes.Int64)) {
			return nil, payloadcrypto.ErrInvalidEnvelope
		}
		plain, sealed, err := j.payloadKey.OpenJSON(stored, commandDefinitionIdentity(tenantID, automationID, version))
		if err != nil || !sealed || len(plain) != int(plainBytes.Int64) || !json.Valid(plain) {
			return nil, payloadReadError(err)
		}
		sum := sha256.Sum256(plain)
		if hex.EncodeToString(sum[:]) != definitionSHA256.String {
			return nil, payloadcrypto.ErrInvalidEnvelope
		}
		return json.RawMessage(plain), nil
	default:
		return nil, payloadcrypto.ErrInvalidEnvelope
	}
}

// The CASE keeps oversized historical JSON and malformed encrypted envelopes
// out of the Go process before authentication. A NULL projection fails closed.
func (j *Journal) commandDefinitionProjection(alias string) string {
	column := alias + ".definition_json"
	var value, size string
	if j.engine == EnginePostgres {
		value = column + "::text"
		size = "octet_length(" + value + ")"
	} else {
		value = column
		size = "length(CAST(" + value + " AS BLOB))"
	}
	return fmt.Sprintf(`CASE WHEN %s.definition_crypto_version = 0 AND %s <= %d THEN %s
		WHEN %s.definition_crypto_version = 1 AND %s <= %d THEN %s ELSE NULL END`,
		alias, size, commandautomations.MaxDefinitionBytes, value,
		alias, size, payloadcrypto.JSONCiphertextLimit(commandautomations.MaxDefinitionBytes), value)
}

// A version index reads only persisted metadata for encrypted rows. Legacy
// version-zero rows still need their bounded JSON to reproduce the historical
// canonical digest before a backfill has populated version-one receipts.
func (j *Journal) commandDefinitionLegacyProjection(alias string) string {
	column := alias + ".definition_json"
	var value, size string
	if j.engine == EnginePostgres {
		value = column + "::text"
		size = "octet_length(" + value + ")"
	} else {
		value = column
		size = "length(CAST(" + value + " AS BLOB))"
	}
	return fmt.Sprintf(`CASE WHEN %s.definition_crypto_version = 0 AND %s <= %d THEN %s ELSE NULL END`,
		alias, size, commandautomations.MaxDefinitionBytes, value)
}

func (j *Journal) commandDefinitionTx(ctx context.Context, tx *sql.Tx, tenantID, automationID string, version int) (json.RawMessage, error) {
	q := fmt.Sprintf(`SELECT %s, v.definition_crypto_version, v.definition_plaintext_bytes, v.definition_sha256
		FROM command_automation_versions v JOIN command_automations a ON a.id = v.automation_id
		WHERE a.tenant_id = $1 AND v.automation_id = $2 AND v.version = $3`, j.commandDefinitionProjection("v"))
	var stored []byte
	var cryptoVersion int
	var plainBytes sql.NullInt64
	var digest sql.NullString
	if err := tx.QueryRowContext(ctx, j.bind(q), tenantID, automationID, version).Scan(&stored, &cryptoVersion, &plainBytes, &digest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("journal payload: read command definition: %w", err)
	}
	return j.openCommandDefinition(tenantID, automationID, version, cryptoVersion, plainBytes, digest, stored)
}
