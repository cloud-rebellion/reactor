package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

// The in-memory runlogs ring limits a single line to 8 MiB. Keep the same
// bound for new durable encrypted lines so every authenticated read is bounded.
const maxRunLogLineBytes = 8 << 20

const (
	runLogKindRuntime       = "runtime"
	runLogKindArtifactFence = "artifact_fence"
)

type runLogWriteArgs struct {
	line       string
	version    int
	plainBytes any
}

func (j *Journal) requireRunLogPayloadKey(ctx context.Context, q queryRowContext) error {
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
	return fmt.Errorf("journal payload: inspect run log encryption state: %w", err)
}

func runLogIdentity(tenantID, runID string, seq int64, kind string) []byte {
	identity := payloadcrypto.Identity(tenantID, runID, "run_log")
	return append(identity, payloadcrypto.Identity(strconv.FormatInt(seq, 10), kind, "v1")...)
}

func (j *Journal) prepareRunLogLine(tenantID, runID string, seq int64, kind, line string) (runLogWriteArgs, error) {
	args := runLogWriteArgs{line: line}
	if len(line) > maxRunLogLineBytes {
		return runLogWriteArgs{}, fmt.Errorf("journal payload: run log line exceeds %d-byte limit", maxRunLogLineBytes)
	}
	if j.payloadKey == nil {
		return args, nil
	}
	sealed, err := j.payloadKey.SealBytes([]byte(line), runLogIdentity(tenantID, runID, seq, kind))
	if err != nil {
		return runLogWriteArgs{}, fmt.Errorf("journal payload: seal run log line: %w", err)
	}
	args.line = string(sealed)
	args.version = 1
	args.plainBytes = len(line)
	return args, nil
}

func (j *Journal) openRunLogLine(tenantID, runID string, seq int64, kind string, version int, plainBytes sql.NullInt64, stored sql.NullString) (string, error) {
	if kind != runLogKindRuntime && kind != runLogKindArtifactFence {
		return "", payloadcrypto.ErrInvalidEnvelope
	}
	switch version {
	case 0:
		if plainBytes.Valid || !stored.Valid {
			return "", payloadcrypto.ErrInvalidEnvelope
		}
		return stored.String, nil
	case 1:
		if j.payloadKey == nil {
			return "", payloadcrypto.ErrKeyRequired
		}
		if !plainBytes.Valid || plainBytes.Int64 < 0 || plainBytes.Int64 > maxRunLogLineBytes ||
			!stored.Valid || len(stored.String) > payloadcrypto.CiphertextLimit(int(plainBytes.Int64)) {
			return "", payloadcrypto.ErrInvalidEnvelope
		}
		plain, sealed, err := j.payloadKey.OpenBytes([]byte(stored.String), runLogIdentity(tenantID, runID, seq, kind))
		if err != nil || !sealed {
			return "", payloadReadError(err)
		}
		if len(plain) != int(plainBytes.Int64) {
			return "", payloadcrypto.ErrInvalidEnvelope
		}
		return string(plain), nil
	default:
		return "", payloadcrypto.ErrInvalidEnvelope
	}
}
