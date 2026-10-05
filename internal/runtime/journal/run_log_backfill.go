package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

const maxRunLogBackfillBatch = 32

// BackfillLegacyRunLogs seals one bounded, atomic batch of historical log
// lines. It preserves the exact line bytes, order, kind, and created_at. The
// key must already be initialized by a keyed daemon; this operator operation
// does not create a journal key or run automatically at startup.
func (j *Journal) BackfillLegacyRunLogs(ctx context.Context, limit int) (converted int, more bool, err error) {
	if j == nil || j.db == nil || j.payloadKey == nil {
		return 0, false, payloadcrypto.ErrKeyRequired
	}
	if limit < 1 || limit > maxRunLogBackfillBatch {
		return 0, false, fmt.Errorf("journal: run log backfill limit must be 1..%d", maxRunLogBackfillBatch)
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, fmt.Errorf("journal: begin run log backfill: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		// Freeze the candidate set before reading it. A deferred SQLite read
		// transaction cannot later upgrade safely if a writer appends a line.
		if _, err := tx.ExecContext(ctx, `UPDATE schema_meta SET value = value WHERE key = 'engine'`); err != nil {
			return 0, false, fmt.Errorf("journal: lock run log backfill: %w", err)
		}
	}
	rows, err := tx.QueryContext(ctx, j.bind(`SELECT run_id, seq FROM run_logs
		WHERE payload_crypto_version = 0 ORDER BY run_id, seq LIMIT $1`), limit+1)
	if err != nil {
		return 0, false, fmt.Errorf("journal: select legacy run logs: %w", err)
	}
	type logID struct {
		runID string
		seq   int64
	}
	ids := make([]logID, 0, limit+1)
	for rows.Next() {
		var id logID
		if err := rows.Scan(&id.runID, &id.seq); err != nil {
			rows.Close()
			return 0, false, fmt.Errorf("journal: scan legacy run log identity: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, false, fmt.Errorf("journal: iterate legacy run log identities: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, false, fmt.Errorf("journal: close legacy run log identities: %w", err)
	}
	more = len(ids) > limit
	if more {
		ids = ids[:limit]
	}

	storedSize := "octet_length(line)"
	if j.engine == EngineSQLite {
		storedSize = "length(CAST(line AS BLOB))"
	}
	logQ := fmt.Sprintf(`SELECT CASE WHEN %s <= %d THEN line ELSE NULL END,
		%s, kind, plaintext_bytes FROM run_logs
		WHERE run_id = $1 AND seq = $2 AND payload_crypto_version = 0`,
		storedSize, maxRunLogLineBytes, storedSize)
	runQ := `SELECT tenant_id FROM runs WHERE id = $1`
	if j.engine == EnginePostgres {
		// Retention locks the parent run before deleting its logs. Keep that
		// order here so a concurrent purge cannot invert the lock order.
		runQ += ` FOR UPDATE`
		logQ += ` FOR UPDATE`
	}
	for _, id := range ids {
		var tenantID string
		if err := tx.QueryRowContext(ctx, j.bind(runQ), id.runID).Scan(&tenantID); err != nil || tenantID == "" {
			return 0, false, fmt.Errorf("journal: legacy run log %q/%d has no tenant: %w",
				id.runID, id.seq, payloadcrypto.ErrInvalidEnvelope)
		}
		var line sql.NullString
		var size sql.NullInt64
		var kind string
		var plainBytes sql.NullInt64
		if err := tx.QueryRowContext(ctx, j.bind(logQ), id.runID, id.seq).
			Scan(&line, &size, &kind, &plainBytes); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return 0, false, fmt.Errorf("journal: legacy run log changed during backfill %q/%d: %w", id.runID, id.seq, ErrNotFound)
			}
			return 0, false, fmt.Errorf("journal: read legacy run log %q/%d: %w", id.runID, id.seq, err)
		}
		if id.seq < 0 || (kind != runLogKindRuntime && kind != runLogKindArtifactFence) ||
			plainBytes.Valid || !size.Valid || size.Int64 < 0 || size.Int64 > maxRunLogLineBytes ||
			!line.Valid || int64(len(line.String)) != size.Int64 {
			return 0, false, fmt.Errorf("journal: invalid legacy run log %q/%d: %w",
				id.runID, id.seq, payloadcrypto.ErrInvalidEnvelope)
		}
		sealed, err := j.payloadKey.SealBytes([]byte(line.String), runLogIdentity(tenantID, id.runID, id.seq, kind))
		if err != nil {
			return 0, false, fmt.Errorf("journal: seal legacy run log %q/%d: %w", id.runID, id.seq, err)
		}
		res, err := tx.ExecContext(ctx, j.bind(`UPDATE run_logs SET line = $1,
			payload_crypto_version = 1, plaintext_bytes = $2
			WHERE run_id = $3 AND seq = $4 AND payload_crypto_version = 0`),
			string(sealed), size.Int64, id.runID, id.seq)
		if err != nil {
			return 0, false, fmt.Errorf("journal: persist sealed run log %q/%d: %w", id.runID, id.seq, err)
		}
		n, err := res.RowsAffected()
		if err != nil || n != 1 {
			return 0, false, fmt.Errorf("journal: legacy run log changed during backfill %q/%d: %w",
				id.runID, id.seq, errors.Join(ErrNotFound, err))
		}
		converted++
	}
	if err := tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("journal: commit run log backfill: %w", err)
	}
	return converted, more, nil
}
