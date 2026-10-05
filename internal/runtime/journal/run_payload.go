package journal

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
	"github.com/bright-interaction/reactor/internal/vault"
)

const wrappedRunPayloadKeyID = "journal-payload-key/v1"

// HasPayloadKey distinguishes a pre-cutover database from one that already
// requires a master key for execution-data reads and all new run writes.
func (j *Journal) HasPayloadKey(ctx context.Context) (bool, error) {
	var one int
	err := j.db.QueryRowContext(ctx, j.bind(`SELECT 1 FROM journal_payload_keys WHERE id = $1`), "v1").Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("journal payload: inspect key state: %w", err)
	}
	return true, nil
}

// LoadPayloadEncryption is read-only and never creates or rewraps a key. It
// lets replay/CLI/MCP readers open v1 rows without mutating the database.
func (j *Journal) LoadPayloadEncryption(ctx context.Context, master, previousMaster []byte) error {
	if len(master) != 32 || (len(previousMaster) != 0 && len(previousMaster) != 32) {
		return payloadcrypto.ErrKeyRequired
	}
	var wrapped []byte
	err := j.db.QueryRowContext(ctx, j.bind(`SELECT wrapped_key FROM journal_payload_keys WHERE id = $1`), "v1").Scan(&wrapped)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("journal payload: load wrapped data key: %w", err)
	}
	dataKey, err := vault.DecryptForID(master, wrappedRunPayloadKeyID, wrapped)
	if err != nil && len(previousMaster) == 32 {
		dataKey, err = vault.DecryptForID(previousMaster, wrappedRunPayloadKeyID, wrapped)
	}
	if err != nil {
		return fmt.Errorf("journal payload: cannot unwrap data key: %w", err)
	}
	defer clearPayloadKey(dataKey)
	keyring, err := payloadcrypto.New(dataKey, nil)
	if err != nil {
		return err
	}
	j.payloadKey = keyring
	return nil
}

// EnablePayloadEncryption loads one stable, randomly generated journal data
// key from the database. The master key only wraps that key, so rotating the
// vault master does not change the key that opens historical run payloads.
// Call before the Journal is shared with dispatchers/readers. A missing or
// wrong master key fails startup before a new plaintext run can be written.
func (j *Journal) EnablePayloadEncryption(ctx context.Context, master, previousMaster []byte) error {
	if len(master) != 32 || (len(previousMaster) != 0 && len(previousMaster) != 32) {
		return payloadcrypto.ErrKeyRequired
	}
	if j == nil || j.db == nil {
		return errors.New("journal payload: database required")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal payload: begin key load: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EnginePostgres {
		// Serialize first-key creation with the migration's old-writer
		// trigger. SQLite already serializes the write transactions.
		var gate string
		if err := tx.QueryRowContext(ctx, `SELECT id FROM journal_payload_gate WHERE id = 'v1' FOR UPDATE`).Scan(&gate); err != nil {
			return fmt.Errorf("journal payload: lock encryption gate: %w", err)
		}
	}
	generated := make([]byte, 32)
	if _, err := rand.Read(generated); err != nil {
		return fmt.Errorf("journal payload: generate data key: %w", err)
	}
	defer clearPayloadKey(generated)
	wrapped, err := vault.EncryptForID(master, wrappedRunPayloadKeyID, generated)
	if err != nil {
		return fmt.Errorf("journal payload: wrap data key: %w", err)
	}
	if _, err := tx.ExecContext(ctx, j.bind(`INSERT INTO journal_payload_keys (id, wrapped_key)
		VALUES ($1, $2) ON CONFLICT DO NOTHING`), "v1", wrapped); err != nil {
		return fmt.Errorf("journal payload: initialize data key: %w", err)
	}
	query := `SELECT wrapped_key FROM journal_payload_keys WHERE id = $1`
	if j.engine == EnginePostgres {
		query += ` FOR UPDATE`
	}
	var stored []byte
	if err := tx.QueryRowContext(ctx, j.bind(query), "v1").Scan(&stored); err != nil {
		return fmt.Errorf("journal payload: load data key: %w", err)
	}
	dataKey, err := vault.DecryptForID(master, wrappedRunPayloadKeyID, stored)
	if err != nil && len(previousMaster) == 32 {
		dataKey, err = vault.DecryptForID(previousMaster, wrappedRunPayloadKeyID, stored)
		if err == nil {
			// Rewrap the SAME data key while holding the key row lock. New and
			// old nodes can overlap during a controlled rolling rotation; a
			// node using only the retired master must fail its next restart.
			newWrap, wrapErr := vault.EncryptForID(master, wrappedRunPayloadKeyID, dataKey)
			if wrapErr != nil {
				clearPayloadKey(dataKey)
				return fmt.Errorf("journal payload: rewrap data key: %w", wrapErr)
			}
			if _, wrapErr = tx.ExecContext(ctx, j.bind(`UPDATE journal_payload_keys SET wrapped_key = $1 WHERE id = $2`), newWrap, "v1"); wrapErr != nil {
				clearPayloadKey(dataKey)
				return fmt.Errorf("journal payload: persist rewrapped data key: %w", wrapErr)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("journal payload: cannot unwrap data key: %w", err)
	}
	defer clearPayloadKey(dataKey)
	keyring, err := payloadcrypto.New(dataKey, nil)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal payload: commit data key load: %w", err)
	}
	j.payloadKey = keyring
	return nil
}

func clearPayloadKey(key []byte) {
	for i := range key {
		key[i] = 0
	}
}

type runPayloadArgs struct {
	tenantID       string
	meta           any
	input          any
	cryptoVersion  int
	plaintextBytes any
}

type queryRowContext interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// prepareRunPayload stores both original JSON metadata and byte-exact input
// under separate authenticated purposes. The tenant comes from the same
// workflow row used by the INSERT, and callers persist its literal value so
// a concurrent tenant edit cannot make the AAD disagree with the run row.
func (j *Journal) prepareRunPayload(ctx context.Context, q queryRowContext, workflowID, runID string, raw []byte) (runPayloadArgs, error) {
	var tenantID string
	if err := q.QueryRowContext(ctx, j.bind(`SELECT tenant_id FROM workflows WHERE id = $1`), workflowID).Scan(&tenantID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return runPayloadArgs{}, ErrNotFound
		}
		return runPayloadArgs{}, fmt.Errorf("journal payload: resolve workflow tenant: %w", err)
	}
	args := runPayloadArgs{tenantID: tenantID, meta: outputArg(raw, j.engine), input: rawInputArg(raw)}
	if j.payloadKey == nil {
		// Keep unkeyed fixtures and pre-cutover databases readable, but once a
		// database owns an encrypted data key no current unkeyed writer may
		// append a plaintext version-zero row. This does not protect against
		// older binaries; the deployment cutover must quiesce those first.
		var one int
		err := q.QueryRowContext(ctx, j.bind(`SELECT 1 FROM journal_payload_keys WHERE id = $1`), "v1").Scan(&one)
		if err == nil {
			return runPayloadArgs{}, payloadcrypto.ErrKeyRequired
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return runPayloadArgs{}, fmt.Errorf("journal payload: inspect encryption state: %w", err)
		}
		return args, nil
	}
	meta, err := j.payloadKey.SealJSON(raw, payloadcrypto.Identity(tenantID, runID, "trigger_meta"))
	if err != nil {
		return runPayloadArgs{}, fmt.Errorf("journal payload: seal trigger metadata: %w", err)
	}
	input, err := j.payloadKey.SealBytes(raw, payloadcrypto.Identity(tenantID, runID, "trigger_input"))
	if err != nil {
		return runPayloadArgs{}, fmt.Errorf("journal payload: seal trigger input: %w", err)
	}
	args.meta = outputArg(meta, j.engine)
	args.input = rawInputArg(input)
	args.cryptoVersion = 1
	args.plaintextBytes = len(raw)
	return args, nil
}

func (j *Journal) openRunPayload(tenantID, runID string, version int, plainBytes sql.NullInt64, meta, input []byte) ([]byte, []byte, error) {
	switch version {
	case 0:
		return meta, input, nil
	case 1:
		if j.payloadKey == nil {
			return nil, nil, payloadcrypto.ErrKeyRequired
		}
		if !plainBytes.Valid || plainBytes.Int64 < 0 || input == nil || meta == nil {
			return nil, nil, payloadcrypto.ErrInvalidEnvelope
		}
		decodedMeta, sealedMeta, err := j.payloadKey.OpenJSON(meta, payloadcrypto.Identity(tenantID, runID, "trigger_meta"))
		if err != nil || !sealedMeta {
			return nil, nil, payloadReadError(err)
		}
		decodedInput, sealedInput, err := j.payloadKey.OpenBytes(input, payloadcrypto.Identity(tenantID, runID, "trigger_input"))
		if err != nil || !sealedInput {
			return nil, nil, payloadReadError(err)
		}
		if len(decodedMeta) != int(plainBytes.Int64) || len(decodedInput) != int(plainBytes.Int64) || !bytes.Equal(decodedMeta, decodedInput) {
			return nil, nil, payloadcrypto.ErrInvalidEnvelope
		}
		return decodedMeta, decodedInput, nil
	default:
		return nil, nil, payloadcrypto.ErrInvalidEnvelope
	}
}

func payloadReadError(err error) error {
	if err != nil {
		return err
	}
	return payloadcrypto.ErrInvalidEnvelope
}
