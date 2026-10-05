package journal

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

const maxCommandDefinitionBackfillBatch = 32

// BackfillLegacyCommandDefinitions seals one bounded batch of historical
// version-zero definitions. It preserves the exact JSON bytes returned by an
// exact-version read and the canonical digest already shown in version
// summaries. Each batch is atomic and restartable; no key is initialized here.
// A corrupt or oversized row aborts the batch without changing any version.
func (j *Journal) BackfillLegacyCommandDefinitions(ctx context.Context, limit int) (converted int, more bool, err error) {
	if j == nil || j.db == nil || j.payloadKey == nil {
		return 0, false, payloadcrypto.ErrKeyRequired
	}
	if limit < 1 || limit > maxCommandDefinitionBackfillBatch {
		return 0, false, fmt.Errorf("journal: command definition backfill limit must be 1..%d", maxCommandDefinitionBackfillBatch)
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, fmt.Errorf("journal: begin command definition backfill: %w", err)
	}
	defer tx.Rollback()

	q := fmt.Sprintf(`SELECT a.tenant_id, v.automation_id, v.version, %s,
		v.definition_plaintext_bytes, v.definition_sha256, v.definition_canonical_sha256
		FROM command_automation_versions v
		JOIN command_automations a ON a.id = v.automation_id
		WHERE v.definition_crypto_version = 0
		ORDER BY v.automation_id, v.version LIMIT $1`, j.commandDefinitionLegacyProjection("v"))
	if j.engine == EnginePostgres {
		q += ` FOR UPDATE OF a, v`
	}
	rows, err := tx.QueryContext(ctx, j.bind(q), limit+1)
	if err != nil {
		return 0, false, fmt.Errorf("journal: select legacy command definitions: %w", err)
	}
	type legacyDefinition struct {
		tenantID, automationID string
		version                int
		raw                    []byte
		plainBytes             sql.NullInt64
		digest, canonical      sql.NullString
	}
	items := make([]legacyDefinition, 0, limit+1)
	for rows.Next() {
		var item legacyDefinition
		if err := rows.Scan(&item.tenantID, &item.automationID, &item.version, &item.raw,
			&item.plainBytes, &item.digest, &item.canonical); err != nil {
			rows.Close()
			return 0, false, fmt.Errorf("journal: scan legacy command definition: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, false, fmt.Errorf("journal: iterate legacy command definitions: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, false, fmt.Errorf("journal: close legacy command definitions: %w", err)
	}
	more = len(items) > limit
	if more {
		items = items[:limit]
	}
	for _, item := range items {
		if item.tenantID == "" || item.automationID == "" || item.version < 1 ||
			item.plainBytes.Valid || item.digest.Valid || item.canonical.Valid ||
			len(item.raw) == 0 || len(item.raw) > commandautomations.MaxDefinitionBytes || !json.Valid(item.raw) {
			return 0, false, fmt.Errorf("journal: invalid legacy command definition %q version %d: %w",
				item.automationID, item.version, payloadcrypto.ErrInvalidEnvelope)
		}
		sealed, sealErr := j.payloadKey.SealJSON(item.raw,
			commandDefinitionIdentity(item.tenantID, item.automationID, item.version))
		if sealErr != nil {
			return 0, false, fmt.Errorf("journal: seal legacy command definition %q version %d: %w",
				item.automationID, item.version, sealErr)
		}
		rawSum := sha256.Sum256(item.raw)
		res, updateErr := tx.ExecContext(ctx, j.bind(`UPDATE command_automation_versions
			SET definition_json = $1, definition_crypto_version = 1,
				definition_plaintext_bytes = $2, definition_sha256 = $3,
				definition_canonical_sha256 = $4
			WHERE automation_id = $5 AND version = $6 AND definition_crypto_version = 0`),
			outputArg(sealed, j.engine), len(item.raw), hex.EncodeToString(rawSum[:]),
			commandDefinitionReceiptDigest(item.raw), item.automationID, item.version)
		if updateErr != nil {
			return 0, false, fmt.Errorf("journal: persist sealed command definition %q version %d: %w",
				item.automationID, item.version, updateErr)
		}
		n, rowsErr := res.RowsAffected()
		if rowsErr != nil || n != 1 {
			return 0, false, fmt.Errorf("journal: legacy command definition changed during backfill %q version %d: %w",
				item.automationID, item.version, errors.Join(ErrCommandAutomationConflict, rowsErr))
		}
		converted++
	}
	if err := tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("journal: commit command definition backfill: %w", err)
	}
	return converted, more, nil
}
