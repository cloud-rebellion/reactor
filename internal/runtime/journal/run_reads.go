package journal

// This file contains bounded read variants for MCP/read-model callers. The
// worker and supervisor must continue using GetRun, which returns the exact
// trigger bytes needed for execution. A control-plane read must not
// materialize an arbitrarily large trigger payload merely to render a run
// receipt or check tenant ownership.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

// ErrRunInputTooLarge means the durable input exists but exceeds a caller's
// explicit materialization bound. It is deliberately distinct from
// ErrNotFound so MCP can explain a bounded-data refusal without revealing
// whether a foreign run exists.
var ErrRunInputTooLarge = errors.New("journal: run input exceeds read bound")

// GetRunForTenantMetadata returns a tenant-scoped run receipt without reading
// trigger_input. trigger_meta is returned only when it fits maxMetaBytes;
// TriggerMetaBytes always reports its durable byte length so a caller can
// expose an explicit truncation marker. A non-positive maxMetaBytes omits the
// metadata bytes entirely.
func (j *Journal) GetRunForTenantMetadata(ctx context.Context, runID, tenantID string, maxMetaBytes int) (RunInfo, error) {
	if maxMetaBytes < 0 {
		return RunInfo{}, errors.New("journal: negative run metadata bound")
	}
	if maxMetaBytes > 16<<20 {
		return RunInfo{}, errors.New("journal: run metadata bound exceeds 16 MiB")
	}

	// PostgreSQL JSONB must be rendered as UTF-8 text before its byte length is
	// measured. SQLite stores the legacy column as TEXT; casting to BLOB keeps
	// the length in bytes rather than Unicode code points.
	var sizeExpr, valueExpr, inputSizeExpr, inputPresentExpr, storedMetaSize, storedMetaValue string
	if j.engine == EnginePostgres {
		storedMetaSize = "octet_length(trigger_meta::text)"
		storedMetaValue = "trigger_meta::text"
		inputSizeExpr = "CASE WHEN payload_crypto_version = 1 THEN payload_plaintext_bytes WHEN trigger_input IS NOT NULL THEN octet_length(trigger_input) ELSE " + storedMetaSize + " END"
		inputPresentExpr = "CASE WHEN trigger_input IS NOT NULL THEN TRUE ELSE FALSE END"
	} else {
		storedMetaSize = "length(CAST(trigger_meta AS BLOB))"
		storedMetaValue = "trigger_meta"
		inputSizeExpr = "CASE WHEN payload_crypto_version = 1 THEN payload_plaintext_bytes WHEN trigger_input IS NOT NULL THEN length(CAST(trigger_input AS BLOB)) ELSE " + storedMetaSize + " END"
		inputPresentExpr = "CASE WHEN trigger_input IS NOT NULL THEN 1 ELSE 0 END"
	}
	sizeExpr = "CASE WHEN payload_crypto_version = 1 THEN payload_plaintext_bytes ELSE " + storedMetaSize + " END"
	valueExpr = "NULL"
	if maxMetaBytes > 0 {
		plainLimit := strconv.Itoa(maxMetaBytes)
		cipherLimit := strconv.Itoa(payloadcrypto.JSONCiphertextLimit(maxMetaBytes))
		valueExpr = "CASE WHEN (payload_crypto_version = 1 AND payload_plaintext_bytes <= " + plainLimit + " AND " + storedMetaSize + " <= " + cipherLimit + ") OR (payload_crypto_version = 0 AND " + storedMetaSize + " <= " + plainLimit + ") THEN " + storedMetaValue + " ELSE NULL END"
	}
	q := fmt.Sprintf(`SELECT id, workflow_id, tenant_id, trigger_kind,
		dispatch_payload_sha256, status, cancel_requested,
		%s, %s, %s, %s, workflow_version, workflow_artifact_sha256, started_at, finished_at, payload_crypto_version, payload_plaintext_bytes
		FROM runs WHERE id = $1 AND ($2 = '' OR tenant_id = $2)`, valueExpr, sizeExpr, inputSizeExpr, inputPresentExpr)
	var (
		info         RunInfo
		inputHash    sql.NullString
		cancel       any
		meta         []byte
		metaBytes    sql.NullInt64
		inputBytes   sql.NullInt64
		inputPresent any
		version      sql.NullInt64
		artifact     sql.NullString
		started      sql.NullString
		finished     sql.NullString
		cryptoVer    int
		plainLen     sql.NullInt64
	)
	args := []any{runID, tenantID}
	if j.engine == EngineSQLite {
		// bind rewrites each numbered PostgreSQL placeholder to an anonymous
		// SQLite placeholder; repeated $2 therefore needs a repeated argument.
		args = []any{runID, tenantID, tenantID}
	}
	err := j.db.QueryRowContext(ctx, j.bind(q), args...).Scan(
		&info.ID, &info.WorkflowID, &info.TenantID, &info.TriggerKind,
		&inputHash, &info.Status, &cancel, &meta, &metaBytes, &inputBytes, &inputPresent, &version,
		&artifact, &started, &finished, &cryptoVer, &plainLen,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return RunInfo{}, ErrNotFound
	}
	if err != nil {
		return RunInfo{}, fmt.Errorf("journal: get bounded run metadata: %w", err)
	}
	if cryptoVer == 1 {
		if j.payloadKey == nil {
			return RunInfo{}, payloadcrypto.ErrKeyRequired
		}
		if !plainLen.Valid || plainLen.Int64 < 0 {
			return RunInfo{}, payloadcrypto.ErrInvalidEnvelope
		}
		if len(meta) > 0 {
			decoded, sealed, openErr := j.payloadKey.OpenJSON(meta, payloadcrypto.Identity(info.TenantID, runID, "trigger_meta"))
			if openErr != nil || !sealed || len(decoded) != int(plainLen.Int64) {
				return RunInfo{}, payloadReadError(openErr)
			}
			meta = decoded
		}
	} else if cryptoVer != 0 {
		return RunInfo{}, payloadcrypto.ErrInvalidEnvelope
	}
	info.CancelRequested = parseBool(cancel)
	if inputHash.Valid {
		info.InputSHA256 = inputHash.String
	}
	if metaBytes.Valid && metaBytes.Int64 >= 0 {
		info.TriggerMetaBytes = int(metaBytes.Int64)
	}
	if inputBytes.Valid && inputBytes.Int64 >= 0 {
		info.TriggerInputBytes = int(inputBytes.Int64)
		info.TriggerInputPresent = parseBool(inputPresent)
	}
	if len(meta) > 0 {
		info.TriggerMeta = append([]byte(nil), meta...)
	}
	if version.Valid {
		info.WorkflowVersion = int(version.Int64)
	}
	info.WorkflowArtifactSHA256 = artifact.String
	if started.Valid {
		if t, parseErr := j.parseTime(started.String); parseErr == nil {
			info.StartedAt = t
		}
	}
	if finished.Valid {
		if t, parseErr := j.parseTime(finished.String); parseErr == nil {
			info.FinishedAt = t
		}
	}
	return info, nil
}

// GetRunForTenantInputBounded verifies the durable input size before reading
// the exact bytes. It deliberately does not call GetRun: an imported row may
// have a small trigger_input alongside an unexpectedly large trigger_meta, and
// the general worker reader is allowed to materialize both. Control-plane
// reads must remain bounded even for that malformed state.
func (j *Journal) GetRunForTenantInputBounded(ctx context.Context, runID, tenantID string, maxBytes int) (RunInfo, error) {
	if maxBytes <= 0 || maxBytes > 16<<20 {
		return RunInfo{}, errors.New("journal: run input bound must be between 1 byte and 16 MiB")
	}
	var sizeExpr string
	if j.engine == EnginePostgres {
		sizeExpr = "CASE WHEN payload_crypto_version = 1 THEN payload_plaintext_bytes WHEN trigger_input IS NOT NULL THEN octet_length(trigger_input) ELSE octet_length(trigger_meta::text) END"
	} else {
		sizeExpr = "CASE WHEN payload_crypto_version = 1 THEN payload_plaintext_bytes ELSE length(CASE WHEN trigger_input IS NOT NULL THEN trigger_input ELSE CAST(trigger_meta AS BLOB) END) END"
	}
	q := fmt.Sprintf("SELECT %s FROM runs WHERE id = $1 AND ($2 = '' OR tenant_id = $2)", sizeExpr)
	var size sql.NullInt64
	args := []any{runID, tenantID}
	if j.engine == EngineSQLite {
		args = []any{runID, tenantID, tenantID}
	}
	err := j.db.QueryRowContext(ctx, j.bind(q), args...).Scan(&size)
	if errors.Is(err, sql.ErrNoRows) {
		return RunInfo{}, ErrNotFound
	}
	if err != nil {
		return RunInfo{}, fmt.Errorf("journal: inspect run input size: %w", err)
	}
	if size.Valid && size.Int64 > int64(maxBytes) {
		return RunInfo{}, ErrRunInputTooLarge
	}

	// Read the exact input and a NULL marker separately from trigger_meta. The
	// marker matters because a zero-length retained input is distinct from a
	// legacy row whose trigger_input column is NULL.
	storedInputSize := "octet_length(trigger_input)"
	if j.engine == EngineSQLite {
		storedInputSize = "length(CAST(trigger_input AS BLOB))"
	}
	inputQ := fmt.Sprintf(`SELECT CASE WHEN trigger_input IS NULL THEN 1 ELSE 0 END,
		CASE WHEN payload_crypto_version = 1 AND %s > %d THEN NULL ELSE trigger_input END,
		payload_crypto_version, payload_plaintext_bytes, tenant_id
		FROM runs WHERE id = $1 AND ($2 = '' OR tenant_id = $2)`, storedInputSize, payloadcrypto.CiphertextLimit(maxBytes))
	args = []any{runID, tenantID}
	if j.engine == EngineSQLite {
		args = []any{runID, tenantID, tenantID}
	}
	var (
		missing      int
		input        []byte
		cryptoVer    int
		plainLen     sql.NullInt64
		actualTenant string
	)
	err = j.db.QueryRowContext(ctx, j.bind(inputQ), args...).Scan(&missing, &input, &cryptoVer, &plainLen, &actualTenant)
	if errors.Is(err, sql.ErrNoRows) {
		return RunInfo{}, ErrNotFound
	}
	if err != nil {
		return RunInfo{}, fmt.Errorf("journal: read bounded run input: %w", err)
	}
	if missing == 1 {
		if cryptoVer != 0 {
			return RunInfo{}, payloadcrypto.ErrInvalidEnvelope
		}
		// Legacy rows only have trigger_meta as their input. Bound that column
		// through the metadata helper before exposing it to the MCP caller.
		return j.GetRunForTenantMetadata(ctx, runID, tenantID, maxBytes)
	}
	if cryptoVer == 1 {
		if j.payloadKey == nil {
			return RunInfo{}, payloadcrypto.ErrKeyRequired
		}
		if !plainLen.Valid || plainLen.Int64 < 0 {
			return RunInfo{}, payloadcrypto.ErrInvalidEnvelope
		}
		if input == nil {
			return RunInfo{}, ErrRunInputTooLarge
		}
		decoded, sealed, openErr := j.payloadKey.OpenBytes(input, payloadcrypto.Identity(actualTenant, runID, "trigger_input"))
		if openErr != nil || !sealed || len(decoded) != int(plainLen.Int64) {
			return RunInfo{}, payloadReadError(openErr)
		}
		input = decoded
	} else if cryptoVer != 0 {
		return RunInfo{}, payloadcrypto.ErrInvalidEnvelope
	}
	info, err := j.GetRunForTenantMetadata(ctx, runID, tenantID, 0)
	if err != nil {
		return RunInfo{}, err
	}
	// Allocate explicitly so a present zero-length trigger_input remains a
	// non-nil slice. Nil is the durable marker for legacy rows and must not be
	// collapsed with an exact empty dispatch input during replay.
	info.TriggerInput = make([]byte, len(input))
	copy(info.TriggerInput, input)
	if cryptoVer == 1 && info.InputSHA256 != "" && info.InputSHA256 != inputSHA256(input) {
		return RunInfo{}, payloadcrypto.ErrInvalidEnvelope
	}
	return info, nil
}
